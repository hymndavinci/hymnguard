import { NextResponse } from "next/server";
import { checkIp } from "@/lib/ip-check";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";
import { normalizeIp } from "@/lib/validate";

export const runtime = "nodejs";
export const maxDuration = 10;

// POST { ip: "8.8.8.8" }
//
// Geolocation + ASN (ip-api.com), Tor exit-node status, reverse DNS, and
// AbuseIPDB reputation when ABUSEIPDB_API_KEY is configured. Passive data
// only — no port scanning. Private/reserved IPs are rejected: public
// sources have nothing to say about them.
export async function POST(req: Request) {
  const ip = getClientIp(req);
  const limit = checkRateLimit(`check:ip:${ip}`);
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

  const target = normalizeIp((body as { ip?: unknown } | null)?.ip);
  if (!target) {
    return NextResponse.json(
      {
        error:
          "Invalid IP address. Enter a public IPv4 or IPv6 address (private, loopback, and reserved ranges cannot be checked).",
      },
      { status: 400 },
    );
  }

  try {
    const result = await checkIp(target, {
      abuseIpDbKey: process.env.ABUSEIPDB_API_KEY,
    });
    return NextResponse.json(result);
  } catch {
    return NextResponse.json(
      { error: "The IP check failed unexpectedly. Try again later." },
      { status: 502 },
    );
  }
}
