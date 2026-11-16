import { NextResponse } from "next/server";
import type { EmailCheckResponse } from "@/lib/api-types";
import { getCurrentUser } from "@/lib/auth";
import { getCachedResult, setCachedResult } from "@/lib/check-cache";
import { runFullEmailCheck } from "@/lib/email-check";
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
// The check itself lives in lib/email-check runFullEmailCheck, shared with
// the dossier section runner.
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

  // BYOK: a logged-in user's own keys win over the server env keys.
  const user = await getCurrentUser(req);
  const keys = await resolveKeys(user?.id ?? null);
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
    const responseBody = await runFullEmailCheck(
      email,
      { hibp: keys.hibp, osintcat: keys.osintcat, github: keys.github },
      enumerationAvailable,
    );
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
