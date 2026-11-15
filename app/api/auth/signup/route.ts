import crypto from "node:crypto";
import { NextResponse } from "next/server";
import { DB_NOT_CONFIGURED, getDb, isDbConfigured } from "@/lib/db";
import {
  CODE_TTL_MS,
  generateCode,
  hashCode,
} from "@/lib/email-verify";
import { hashPassword, MIN_PASSWORD_LENGTH } from "@/lib/password";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";
import { sendEmail } from "@/lib/resend";
import {
  createSessionValue,
  getSessionSecret,
  sessionCookieHeader,
} from "@/lib/session";
import { normalizeEmail } from "@/lib/validate";

export const runtime = "nodejs";
export const maxDuration = 10;

// POST { email, password }
//
// Creates an account. When Resend is configured, signup is a two-step
// flow: this route stores a pending signup and emails a 6-digit code;
// POST /api/auth/verify-signup completes it. Without Resend, the account
// is created immediately (unverified) so accounts still work on a
// keyless deployment. Passwords are scrypt-hashed; the code is stored
// as a SHA-256 hash and expires in 10 minutes.
export async function POST(req: Request) {
  const ip = getClientIp(req);
  const limit = checkRateLimit(`auth:signup:${ip}`, 5, 60 * 60 * 1000);
  if (!limit.allowed) {
    return NextResponse.json(
      { error: "Too many signups from this address. Try again later." },
      { status: 429, headers: { "Retry-After": String(limit.retryAfterSec) } },
    );
  }

  if (!isDbConfigured() || !getSessionSecret()) {
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
  const input = body as { email?: unknown; password?: unknown } | null;
  const email = normalizeEmail(input?.email);
  const password = typeof input?.password === "string" ? input.password : "";
  if (!email) {
    return NextResponse.json({ error: "Invalid email address." }, { status: 400 });
  }
  if (password.length < MIN_PASSWORD_LENGTH) {
    return NextResponse.json(
      { error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters.` },
      { status: 400 },
    );
  }

  const existing = await db.queryOne<{ id: string }>(
    `SELECT id FROM users WHERE email = $1`,
    [email],
  );
  if (existing) {
    return NextResponse.json(
      { error: "An account with this email already exists. Try signing in." },
      { status: 409 },
    );
  }

  const passwordHash = await hashPassword(password);
  const resendKey = process.env.RESEND_API_KEY;
  const resendFrom = process.env.RESEND_FROM;

  // Keyless deployment: create the account right away (unverified).
  if (!resendKey || !resendFrom) {
    const id = crypto.randomUUID();
    const row = await db.queryOne<{
      id: string;
      email: string;
      email_verified: boolean;
      created_at: string;
    }>(
      `INSERT INTO users (id, email, password_hash, email_verified)
       VALUES ($1, $2, $3, FALSE)
       RETURNING id, email, email_verified, created_at::text AS created_at`,
      [id, email, passwordHash],
    );
    if (!row) {
      return NextResponse.json(
        { error: "Could not create the account. Try again later." },
        { status: 500 },
      );
    }
    const secret = getSessionSecret();
    if (!secret) {
      return NextResponse.json(DB_NOT_CONFIGURED, { status: 503 });
    }
    const res = NextResponse.json(
      {
        user: {
          id: row.id,
          email: row.email,
          emailVerified: row.email_verified,
          createdAt: row.created_at,
        },
        needsVerification: false,
      },
      { status: 201 },
    );
    res.headers.set(
      "Set-Cookie",
      sessionCookieHeader(createSessionValue(secret, row.id, 0)),
    );
    return res;
  }

  // Resend configured: pending signup + emailed code.
  const code = generateCode();
  const expiresAt = new Date(Date.now() + CODE_TTL_MS).toISOString();
  await db.exec(
    `INSERT INTO pending_signups (id, email, password_hash, code_hash, expires_at, attempts)
     VALUES ($1, $2, $3, $4, $5, 0)
     ON CONFLICT (email) DO UPDATE
       SET password_hash = EXCLUDED.password_hash,
           code_hash = EXCLUDED.code_hash,
           expires_at = EXCLUDED.expires_at,
           attempts = 0, created_at = now()`,
    [crypto.randomUUID(), email, passwordHash, hashCode(code), expiresAt],
  );

  const sent = await sendEmail(
    {
      to: email,
      subject: `Your HymnGuard signup code: ${code}`,
      text:
        `Your HymnGuard signup code is: ${code}\n\n` +
        `It expires in 10 minutes. Enter it in HymnGuard to finish creating your account.\n\n` +
        `If you did not request this, ignore this email — no account will be created.`,
      html:
        `<p>Your HymnGuard signup code is:</p>` +
        `<p style="font-size: 28px; font-weight: 700; letter-spacing: 4px; font-family: monospace;">${code}</p>` +
        `<p>It expires in 10 minutes. Enter it in HymnGuard to finish creating your account.</p>` +
        `<p>If you did not request this, ignore this email — no account will be created.</p>`,
    },
    resendKey,
    resendFrom,
  );
  if (!sent.ok) {
    await db.exec(`DELETE FROM pending_signups WHERE email = $1`, [email]);
    return NextResponse.json(
      { error: "Could not send the verification email. Try again later." },
      { status: 502 },
    );
  }

  return NextResponse.json(
    { needsVerification: true, email },
    { status: 202 },
  );
}
