import crypto from "node:crypto";
import { NextResponse } from "next/server";
import { DB_NOT_CONFIGURED, getDb, isDbConfigured } from "@/lib/db";
import { CODE_TTL_MS, generateCode, hashCode } from "@/lib/email-verify";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";
import { sendEmail } from "@/lib/resend";
import { normalizeEmail } from "@/lib/validate";

export const runtime = "nodejs";
export const maxDuration = 10;

// POST { email }
//
// Starts a password reset: emails a 6-digit code when the account exists
// and Resend is configured. Anti-enumeration: always returns 200, whether
// or not the email has an account. Without Resend, resets cannot be sent
// (documented in the README) — the response is still 200.
export async function POST(req: Request) {
  const ip = getClientIp(req);
  const limit = checkRateLimit(`auth:forgot:${ip}`, 5, 60 * 60 * 1000);
  if (!limit.allowed) {
    return NextResponse.json(
      { error: "Too many requests from this address. Try again later." },
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
  const email = normalizeEmail(
    (body as { email?: unknown } | null)?.email,
  );
  if (!email) {
    return NextResponse.json({ error: "Invalid email address." }, { status: 400 });
  }

  const resendKey = process.env.RESEND_API_KEY;
  const resendFrom = process.env.RESEND_FROM;
  const user = await db.queryOne<{ id: string }>(
    `SELECT id FROM users WHERE email = $1`,
    [email],
  );
  if (user && resendKey && resendFrom) {
    const code = generateCode();
    const expiresAt = new Date(Date.now() + CODE_TTL_MS).toISOString();
    await db.exec(`DELETE FROM password_resets WHERE email = $1`, [email]);
    await db.exec(
      `INSERT INTO password_resets (id, email, code_hash, expires_at, attempts)
       VALUES ($1, $2, $3, $4, 0)`,
      [crypto.randomUUID(), email, hashCode(code), expiresAt],
    );
    await sendEmail(
      {
        to: email,
        subject: `Your HymnGuard password reset code: ${code}`,
        text:
          `Your HymnGuard password reset code is: ${code}\n\n` +
          `It expires in 10 minutes. Enter it in HymnGuard with your new password.\n\n` +
          `If you did not request this, ignore this email — your password will not change.`,
        html:
          `<p>Your HymnGuard password reset code is:</p>` +
          `<p style="font-size: 28px; font-weight: 700; letter-spacing: 4px; font-family: monospace;">${code}</p>` +
          `<p>It expires in 10 minutes. Enter it in HymnGuard with your new password.</p>` +
          `<p>If you did not request this, ignore this email — your password will not change.</p>`,
      },
      resendKey,
      resendFrom,
    );
  }

  return NextResponse.json({ ok: true });
}
