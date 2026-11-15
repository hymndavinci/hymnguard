import { NextResponse } from "next/server";
import type { UrlCheckResult } from "@/lib/api-types";
import { getCurrentUser } from "@/lib/auth";
import { getCachedResult, setCachedResult } from "@/lib/check-cache";
import { resolveKeys } from "@/lib/keys";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";
import { checkUrl } from "@/lib/url-check";
import { normalizeUrl } from "@/lib/validate";

export const runtime = "nodejs";
export const maxDuration = 10;

// POST { url: "https://example.com/login" }
//
// URL reputation: urlscan.io (free), VirusTotal + Google Safe Browsing
// (keyed). The URL is only sent to reputation APIs — HymnGuard never
// fetches it, so there is no SSRF surface.
export async function POST(req: Request) {
  const ip = getClientIp(req);
  const limit = checkRateLimit(`check:url:${ip}`);
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

  const target = normalizeUrl((body as { url?: unknown } | null)?.url);
  if (!target) {
    return NextResponse.json(
      {
        error:
          "Invalid URL. Enter a full http or https URL (localhost and private IP hosts cannot be checked).",
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
      const cached = await getCachedResult<UrlCheckResult>("url", target);
      if (cached) {
        return NextResponse.json(cached, { headers: { "X-Cache": "HIT" } });
      }
    }

    const result = await checkUrl(target, {
      virusTotalKey: keys.virustotal,
      safeBrowsingKey: keys.safebrowsing,
    });
    if (!keys.usedByok) {
      await setCachedResult("url", target, result);
      return NextResponse.json(result, { headers: { "X-Cache": "MISS" } });
    }
    return NextResponse.json(result);
  } catch {
    return NextResponse.json(
      { error: "The URL check failed unexpectedly. Try again later." },
      { status: 502 },
    );
  }
}
