import { NextResponse } from "next/server";
import { fetchPwnedRange } from "@/lib/hibp";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";
import { isValidPasswordPrefix } from "@/lib/validate";

export const runtime = "nodejs";

// POST { prefix: "ABC12" } — the first 5 hex chars of the SHA-1 hash.
// The password and the full hash never reach this server: the client hashes
// locally and matches its own suffix against the returned range.
export async function POST(req: Request) {
  const ip = getClientIp(req);
  const limit = checkRateLimit(`check:password:${ip}`);
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

  const rawPrefix = (body as { prefix?: unknown } | null)?.prefix;
  if (!isValidPasswordPrefix(rawPrefix)) {
    return NextResponse.json(
      { error: "Invalid request. Expected a 5-character SHA-1 prefix." },
      { status: 400 },
    );
  }
  // Canonical uppercase form (HIBP returns uppercase suffixes).
  const prefix = rawPrefix.toUpperCase();

  try {
    const entries = await fetchPwnedRange(prefix);
    return NextResponse.json({ prefix, entries });
  } catch {
    return NextResponse.json(
      { error: "Could not reach the Have I Been Pwned service. Try again later." },
      { status: 502 },
    );
  }
}
