import { NextResponse } from "next/server";
import type { EmailCheckResponse } from "@/lib/api-types";
import { getCurrentUser } from "@/lib/auth";
import { getCachedResult, setCachedResult } from "@/lib/check-cache";
import { checkEmailAuth } from "@/lib/email-auth";
import {
  fetchHudsonRock,
  fetchLeakCheck,
  fetchOsintCat,
  type HudsonRockResult,
  type LeakCheckResult,
  type OsintCatResult,
} from "@/lib/email-breach";
import { checkEmailMx } from "@/lib/email-check";
import { searchGitHubCommits, type GitHubExposureResult } from "@/lib/github-exposure";
import { fetchBreachesForEmail, type HibpBreachMeta } from "@/lib/hibp";
import { resolveKeys } from "@/lib/keys";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";
import { normalizeEmail } from "@/lib/validate";

export const runtime = "nodejs";
export const maxDuration = 10;

// POST { email: "user@example.com" }
//
// Runs the free checks in parallel (MX records, SPF/DKIM/DMARC grading,
// LeakCheck breach index, Hudson Rock infostealer exposure) plus the keyed
// checks when their keys are configured (HIBP, OsintCat, GitHub). Keyed
// sources without a key report a needs-key state instead of a fake result.
// Every source is independent: one failing source never fails the check.
export async function POST(req: Request) {
  const ip = getClientIp(req);
  const limit = checkRateLimit(`check:email:${ip}`);
  if (!limit.allowed) {
    return NextResponse.json(
      { error: "Rate limit exceeded. Try again shortly." },
      {
        status: 429,
        headers: { "Retry-After": String(limit.retryAfterSec) },
      },
    );
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const email = normalizeEmail((body as { email?: unknown } | null)?.email);
  if (!email) {
    return NextResponse.json(
      { error: "Invalid email address." },
      { status: 400 },
    );
  }

  const domain = email.split("@")[1];
  // BYOK: a logged-in user's own keys win over the server env keys.
  const user = await getCurrentUser(req);
  const keys = await resolveKeys(user?.id ?? null);
  const hibpKey = keys.hibp;
  const osintCatKey = keys.osintcat;
  const githubToken = keys.github;
  const enumerationAvailable = Boolean(
    process.env.RESEND_API_KEY && process.env.VERIFY_SECRET,
  );

  // Route-level cache (bypassed entirely when a BYOK key is in play).
  if (!keys.usedByok) {
    const cached = await getCachedResult<EmailCheckResponse>("email", email);
    if (cached) {
      return NextResponse.json(cached, { headers: { "X-Cache": "HIT" } });
    }
  }

  try {
    const [mxResult, authResult, leakcheck, hudsonrock, hibp, osintcat, github] =
      await Promise.all([
        checkEmailMx(domain),
        checkEmailAuth(domain),
        fetchLeakCheck(email),
        fetchHudsonRock(email),
        (async (): Promise<
          | {
              available: true;
              rateLimited?: boolean;
              breaches?: HibpBreachMeta[];
              error?: string;
            }
          | { available: false }
        > => {
          if (!hibpKey) return { available: false as const };
          // A bad key (or a HIBP outage) must not fail the whole check:
          // it surfaces as an honest error on the HIBP source instead.
          try {
            const breaches = await fetchBreachesForEmail(email, hibpKey);
            if (breaches.status === "rate_limited") {
              return { available: true as const, rateLimited: true as const };
            }
            return { available: true as const, breaches: breaches.breaches };
          } catch (err) {
            const message =
              err instanceof Error ? err.message : "HIBP lookup failed";
            return {
              available: true as const,
              error: message.includes("401")
                ? "The HIBP API key was rejected. Check the key (or the saved BYOK key) and try again."
                : message,
            };
          }
        })(),
        (async (): Promise<{
          available: boolean;
          result?: OsintCatResult;
        }> => {
          if (!osintCatKey) return { available: false };
          return {
            available: true,
            result: await fetchOsintCat(email, osintCatKey),
          };
        })(),
        (async (): Promise<{
          available: boolean;
          result?: GitHubExposureResult;
        }> => {
          if (!githubToken) return { available: false };
          return {
            available: true,
            result: await searchGitHubCommits(email, githubToken),
          };
        })(),
      ]);

    const responseBody: EmailCheckResponse = {
      email,
      domain,
      checkedAt: new Date().toISOString(),
      mx: mxResult.mx,
      mxOk: mxResult.mxOk,
      mxError: mxResult.mxError,
      disposable: mxResult.disposable,
      hibp,
      auth: authResult,
      leakcheck: leakcheck as LeakCheckResult,
      osintcat,
      hudsonrock: hudsonrock as HudsonRockResult,
      github,
      enumeration: { available: enumerationAvailable },
    };
    if (!keys.usedByok) {
      await setCachedResult("email", email, responseBody);
      return NextResponse.json(responseBody, {
        headers: { "X-Cache": "MISS" },
      });
    }
    return NextResponse.json(responseBody);
  } catch {
    return NextResponse.json(
      { error: "The email check failed unexpectedly. Try again later." },
      { status: 502 },
    );
  }
}
