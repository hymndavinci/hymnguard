import { NextResponse } from "next/server";
import type { HashCheckResult } from "@/lib/api-types";
import { getCurrentUser } from "@/lib/auth";
import { getCachedResult, setCachedResult } from "@/lib/check-cache";
import { checkHash } from "@/lib/hash-check";
import { resolveKeys } from "@/lib/keys";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";
import { normalizeHash } from "@/lib/validate";

export const runtime = "nodejs";
export const maxDuration = 15;

// POST { hash: "275a021b..." }
//
// File hash reputation: CIRCL hashlookup + urlscan.io (free), VirusTotal
// + MalwareBazaar + Hybrid Analysis + OTX (keyed). Only the hash is ever
// sent — never a file. "Not found" in a source means that source has no
// record of the hash; it is not a clean verdict.
export async function POST(req: Request) {
  const ip = getClientIp(req);
  const limit = checkRateLimit(`check:hash:${ip}`);
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

  const parsed = normalizeHash((body as { hash?: unknown } | null)?.hash);
  if (!parsed) {
    return NextResponse.json(
      {
        error:
          "Invalid hash. Enter an MD5 (32 hex chars), SHA-1 (40), or SHA-256 (64) digest.",
      },
      { status: 400 },
    );
  }

  try {
    // BYOK: a logged-in user's own keys win over the server env keys.
    const user = await getCurrentUser(req);
    const keys = await resolveKeys(user?.id ?? null);

    // Route-level cache (bypassed entirely when a BYOK key is in play).
    if (!keys.usedByok) {
      const cached = await getCachedResult<HashCheckResult>("hash", parsed.hash);
      if (cached) {
        return NextResponse.json(cached, { headers: { "X-Cache": "HIT" } });
      }
    }

    const result = await checkHash(parsed.hash, parsed.algorithm, {
      virusTotalKey: keys.virustotal,
      malwareBazaarKey: keys.malwarebazaar,
      hybridAnalysisKey: keys.hybridanalysis,
      otxKey: keys.otx,
    });
    if (!keys.usedByok) {
      await setCachedResult("hash", parsed.hash, result);
      return NextResponse.json(result, { headers: { "X-Cache": "MISS" } });
    }
    return NextResponse.json(result);
  } catch {
    return NextResponse.json(
      { error: "The hash check failed unexpectedly. Try again later." },
      { status: 502 },
    );
  }
}
