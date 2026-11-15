import { NextResponse } from "next/server";
import type { DomainCheckResult } from "@/lib/api-types";
import { getCurrentUser } from "@/lib/auth";
import { getCachedResult, setCachedResult } from "@/lib/check-cache";
import { checkDomain } from "@/lib/domain-check";
import { resolveKeys } from "@/lib/keys";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";
import { normalizeDomain } from "@/lib/validate";

export const runtime = "nodejs";
export const maxDuration = 15;

// POST { domain: "example.com" }
export async function POST(req: Request) {
  const ip = getClientIp(req);
  const limit = checkRateLimit(`check:domain:${ip}`);
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

  const domain = normalizeDomain((body as { domain?: unknown } | null)?.domain);
  if (!domain) {
    return NextResponse.json(
      { error: "Invalid domain. Enter a hostname such as example.com." },
      { status: 400 },
    );
  }

  try {
    // BYOK: a logged-in user's own keys win over the server env keys.
    const user = await getCurrentUser(req);
    const keys = await resolveKeys(user?.id ?? null);

    // Route-level cache (bypassed entirely when a BYOK key is in play).
    if (!keys.usedByok) {
      const cached = await getCachedResult<DomainCheckResult>(
        "domain",
        domain,
      );
      if (cached) {
        return NextResponse.json(cached, { headers: { "X-Cache": "HIT" } });
      }
    }

    const result = await checkDomain(domain, {
      otxApiKey: keys.otx,
    });
    if (!keys.usedByok) {
      await setCachedResult("domain", domain, result);
      return NextResponse.json(result, { headers: { "X-Cache": "MISS" } });
    }
    return NextResponse.json(result);
  } catch {
    return NextResponse.json(
      { error: "The domain check failed unexpectedly. Try again later." },
      { status: 502 },
    );
  }
}
