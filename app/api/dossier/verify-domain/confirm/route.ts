import { NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { DB_NOT_CONFIGURED, getDb } from "@/lib/db";
import {
  addVerifiedIdentifier,
  confirmDomainOwnership,
  resolveDomainOwnership,
} from "@/lib/dossier";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";
import { normalizeDomain } from "@/lib/validate";

export const runtime = "nodejs";
export const maxDuration = 10;

// POST { domain } — looks up the TXT record at _hymnguard.<domain> and
// checks it carries a valid HymnGuard verification token. On success the
// domain is added to the user's verified identifiers. On failure the
// response says exactly what was (not) found — DNS propagation can take a
// few minutes, so a missing record is not an error state.
export async function POST(req: Request) {
  const ip = getClientIp(req);
  const limit = checkRateLimit(`dossier:verify-domain:confirm:${ip}`);
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

  const existing = await resolveDomainOwnership(db, user, domain);
  if (existing.verified) {
    return NextResponse.json({
      alreadyVerified: true,
      method: existing.method,
    });
  }

  const result = await confirmDomainOwnership(domain, secret);
  if (!result.verified) {
    return NextResponse.json(
      { error: result.error ?? "Domain could not be verified." },
      { status: 404 },
    );
  }

  const saved = await addVerifiedIdentifier(db, user.id, {
    type: "domain",
    value: domain,
    method: "domain_txt",
  });
  if (!saved.ok) {
    return NextResponse.json({ error: saved.error }, { status: 400 });
  }
  return NextResponse.json(
    { verified: true, method: "domain_txt", id: saved.id },
    { status: 201 },
  );
}
