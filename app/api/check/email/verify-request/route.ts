import { NextResponse } from "next/server";
import {
  CODE_TTL_MS,
  createCodeToken,
  generateCode,
  sendVerificationCode,
} from "@/lib/email-verify";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";
import { normalizeEmail } from "@/lib/validate";

export const runtime = "nodejs";
export const maxDuration = 10;

// POST { email } — sends a 6-digit ownership-verification code to the
// address and returns an HMAC token binding email + code + expiry.
// The code itself is never inside the token.
//
// Strict rate limits: 5 requests/hour per IP and 3/hour per email, so the
// endpoint cannot be used to spam an address with codes. If Resend or the
// signing secret is not configured, the response says so (needs-key state)
// and no code is sent.
export async function POST(req: Request) {
  const ip = getClientIp(req);
  const secret = process.env.VERIFY_SECRET;
  const resendKey = process.env.RESEND_API_KEY;
  const from =
    process.env.RESEND_FROM ?? "HymnGuard <onboarding@resend.dev>";

  if (!secret || !resendKey) {
    return NextResponse.json(
      {
        error:
          "Ownership verification is not configured on this deployment (RESEND_API_KEY and VERIFY_SECRET are required).",
        needsKey: true,
      },
      { status: 503 },
    );
  }

  const ipLimit = checkRateLimit(`verify-request:ip:${ip}`, 5, 3_600_000);
  if (!ipLimit.allowed) {
    return NextResponse.json(
      { error: "Too many code requests. Try again later." },
      {
        status: 429,
        headers: { "Retry-After": String(ipLimit.retryAfterSec) },
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

  const emailLimit = checkRateLimit(
    `verify-request:email:${email}`,
    3,
    3_600_000,
  );
  if (!emailLimit.allowed) {
    return NextResponse.json(
      { error: "Too many code requests for this email. Try again later." },
      {
        status: 429,
        headers: { "Retry-After": String(emailLimit.retryAfterSec) },
      },
    );
  }

  const code = generateCode();
  const expiresAt = Date.now() + CODE_TTL_MS;
  const token = createCodeToken(secret, email, code, expiresAt);

  const sent = await sendVerificationCode(email, code, resendKey, from);
  if (!sent.ok) {
    return NextResponse.json(
      { error: `Could not send the verification code. ${sent.error ?? ""}`.trim() },
      { status: 502 },
    );
  }

  return NextResponse.json({
    token,
    expiresInSec: Math.floor(CODE_TTL_MS / 1000),
  });
}
