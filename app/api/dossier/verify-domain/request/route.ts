import { NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { DB_NOT_CONFIGURED, getDb } from "@/lib/db";
import { createDomainVerifyToken } from "@/lib/dossier";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";
import { normalizeDomain } from "@/lib/validate";

export const runtime = "nodejs";
export const maxDuration = 10;

// POST { domain } — issues a stateless HMAC verification token (24h TTL)
// for a domain. The user adds it as a TXT record at _hymnguard.<domain>,
// then confirms via /api/dossier/verify-domain/confirm. Nothing is stored
// here: the token is self-describing (domain + expiry + HMAC).
export async function POST(req: Request) {
  const ip = getClientIp(req);
  const limit = checkRateLimit(`dossier:verify-domain:request:${ip}`);
  if (!limit.allowed) {
    return NextResponse.json(
      { error: "Rate limit exceeded. Try again shortly." },
      {
        status: 429,
        headers: { "Retry-After": String(limit.retryAfterSec) },
      },
    );
  }

  const user = await getCurrentUser(req);
  if (!user) {
    return NextResponse.json({ error: "Sign in required." }, { status: 401 });
  }
  const db = getDb();
  if (!db) {
    return NextResponse.json(DB_NOT_CONFIGURED, { status: 503 });
  }

  const secret = process.env.VERIFY_SECRET;
  if (!secret) {
    return NextResponse.json(
      {
        error:
          "Domain verification is not configured on this deployment (VERIFY_SECRET is not set).",
      },
      { status: 503 },
    );
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }
  const domain = normalizeDomain(
    (body as { domain?: unknown } | null)?.domain,
  );
  if (!domain) {
    return NextResponse.json(
      { error: "Invalid domain." },
      { status: 400 },
    );
  }

  const token = createDomainVerifyToken(secret, domain);
  return NextResponse.json({
    domain,
    host: token.host,
    value: token.value,
    expiresInSec: Math.floor((token.expiresAt - Date.now()) / 1000),
  });
}
