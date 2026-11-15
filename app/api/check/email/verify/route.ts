import { NextResponse } from "next/server";
import {
  createVerificationToken,
  VERIFICATION_TTL_MS,
  verifyCodeToken,
} from "@/lib/email-verify";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";
import { normalizeEmail } from "@/lib/validate";

export const runtime = "nodejs";
export const maxDuration = 10;

// POST { email, code, token } — checks the 6-digit code against the HMAC
// token issued by verify-request. On match, returns a verification token
// (HMAC-signed, 30 min) that authorizes enumeration chunks.
//
// Rate-limited to 5 attempts/min/IP: brute-forcing a 6-digit code at that
// rate is infeasible within the code's 10-minute lifetime.
export async function POST(req: Request) {
  const ip = getClientIp(req);
  const secret = process.env.VERIFY_SECRET;
  if (!secret) {
    return NextResponse.json(
      {
        error:
          "Ownership verification is not configured on this deployment.",
        needsKey: true,
      },
      { status: 503 },
    );
  }

  const limit = checkRateLimit(`verify:${ip}`, 5);
  if (!limit.allowed) {
    return NextResponse.json(
      { error: "Too many attempts. Try again shortly." },
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

  const input = (body as { email?: unknown; code?: unknown; token?: unknown } | null) ?? {};
  const email = normalizeEmail(input.email);
  const code = typeof input.code === "string" ? input.code.trim() : "";
  const token = typeof input.token === "string" ? input.token : "";
  if (!email || !/^\d{6}$/.test(code) || !token) {
    return NextResponse.json(
      { error: "Invalid verification request." },
      { status: 400 },
    );
  }

  if (!verifyCodeToken(secret, email, code, token)) {
    return NextResponse.json(
      { error: "Invalid or expired code." },
      { status: 401 },
    );
  }

  return NextResponse.json({
    verified: true,
    verificationToken: createVerificationToken(secret, email),
    expiresInSec: Math.floor(VERIFICATION_TTL_MS / 1000),
  });
}
