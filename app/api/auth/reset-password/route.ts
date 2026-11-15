import { NextResponse } from "next/server";
import { DB_NOT_CONFIGURED, getDb, isDbConfigured } from "@/lib/db";
import { codeHashMatches } from "@/lib/email-verify";
import { hashPassword, MIN_PASSWORD_LENGTH } from "@/lib/password";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";
import { normalizeEmail } from "@/lib/validate";

export const runtime = "nodejs";
export const maxDuration = 10;

const MAX_ATTEMPTS = 5;

// POST { email, code, newPassword }
//
// Completes a password reset started by POST /api/auth/forgot-password.
// On success the password is replaced, token_version is bumped (all
// existing sessions stop validating), and every reset code for the email
// is deleted. The user signs in again with the new password.
export async function POST(req: Request) {
  const ip = getClientIp(req);
  const limit = checkRateLimit(`auth:reset:${ip}`);
  if (!limit.allowed) {
    return NextResponse.json(
      { error: "Rate limit exceeded. Try again shortly." },
      { status: 429, headers: { "Retry-After": String(limit.retryAfterSec) } },
    );
  }

  if (!isDbConfigured()) {
    return NextResponse.json(DB_NOT_CONFIGURED, { status: 503 });
  }
  const db = getDb();
  if (!db) return NextResponse.json(DB_NOT_CONFIGURED, { status: 503 });

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }
  const input = body as {
    email?: unknown;
    code?: unknown;
    newPassword?: unknown;
  } | null;
  const email = normalizeEmail(input?.email);
  const code = typeof input?.code === "string" ? input.code.trim() : "";
  const newPassword =
    typeof input?.newPassword === "string" ? input.newPassword : "";
  if (!email || !/^\d{6}$/.test(code)) {
    return NextResponse.json(
      { error: "Invalid email or code." },
      { status: 400 },
    );
  }
  if (newPassword.length < MIN_PASSWORD_LENGTH) {
    return NextResponse.json(
      { error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters.` },
      { status: 400 },
    );
  }

  const reset = await db.queryOne<{
    id: string;
    code_hash: string;
    expires_at: string;
    attempts: number;
  }>(
    `SELECT id, code_hash, expires_at::text AS expires_at, attempts
     FROM password_resets WHERE email = $1
     ORDER BY created_at DESC LIMIT 1`,
    [email],
  );
  if (!reset) {
    return NextResponse.json(
      { error: "No reset request for this email. Request a new code." },
      { status: 401 },
    );
  }
  if (reset.attempts >= MAX_ATTEMPTS) {
    await db.exec(`DELETE FROM password_resets WHERE email = $1`, [email]);
    return NextResponse.json(
      { error: "Too many wrong codes. Request a new code." },
      { status: 429 },
    );
  }
  if (new Date(reset.expires_at).getTime() < Date.now()) {
    await db.exec(`DELETE FROM password_resets WHERE email = $1`, [email]);
    return NextResponse.json(
      { error: "The code expired. Request a new code." },
      { status: 401 },
    );
  }
  if (!codeHashMatches(code, reset.code_hash)) {
    await db.exec(
      `UPDATE password_resets SET attempts = attempts + 1 WHERE id = $1`,
      [reset.id],
    );
    return NextResponse.json(
      { error: "Invalid code. Check the email and try again." },
      { status: 401 },
    );
  }

  const passwordHash = await hashPassword(newPassword);
  await db.exec(
    `UPDATE users
     SET password_hash = $1, token_version = token_version + 1,
         updated_at = now()
     WHERE email = $2`,
    [passwordHash, email],
  );
  await db.exec(`DELETE FROM password_resets WHERE email = $1`, [email]);

  return NextResponse.json({
    ok: true,
    message: "Password changed. Sign in with your new password.",
  });
}
