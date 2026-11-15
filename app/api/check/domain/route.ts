import { NextResponse } from "next/server";
import { checkDomain } from "@/lib/domain-check";
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
    const result = await checkDomain(domain, {
      otxApiKey: process.env.OTX_API_KEY,
    });
    return NextResponse.json(result);
  } catch {
    return NextResponse.json(
      { error: "The domain check failed unexpectedly. Try again later." },
      { status: 502 },
    );
  }
}
