import crypto from "node:crypto";
import { NextResponse } from "next/server";
import { DB_NOT_CONFIGURED, getDb, isDbConfigured } from "@/lib/db";
import { codeHashMatches } from "@/lib/email-verify";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";
import {
  createSessionValue,
  getSessionSecret,
  sessionCookieHeader,
} from "@/lib/session";
import { normalizeEmail } from "@/lib/validate";

export const runtime = "nodejs";
export const maxDuration = 10;

const MAX_ATTEMPTS = 5;

// POST { email, code }
//
// Completes a signup started by POST /api/auth/signup: checks the emailed
// 6-digit code against the stored hash, creates the verified user, and
// issues a session. Wrong codes are capped at 5 attempts; expired codes
// are rejected and the pending signup is removed.
export async function POST(req: Request) {
  const ip = getClientIp(req);
  const limit = checkRateLimit(`auth:verify-signup:${ip}`);
  if (!limit.allowed) {
    return NextResponse.json(
      { error: "Rate limit exceeded. Try again shortly." },
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
  const input = body as { email?: unknown; code?: unknown } | null;
  const email = normalizeEmail(input?.email);
  const code = typeof input?.code === "string" ? input.code.trim() : "";
  if (!email || !/^\d{6}$/.test(code)) {
    return NextResponse.json(
      { error: "Invalid email or code." },
      { status: 400 },
    );
  }

  const pending = await db.queryOne<{
    id: string;
    password_hash: string;
    code_hash: string;
    expires_at: string;
    attempts: number;
  }>(
    `SELECT id, password_hash, code_hash, expires_at::text AS expires_at,
            attempts
     FROM pending_signups WHERE email = $1`,
    [email],
  );
  if (!pending) {
    return NextResponse.json(
      { error: "No pending signup for this email. Sign up again." },
      { status: 401 },
    );
  }
  if (pending.attempts >= MAX_ATTEMPTS) {
    await db.exec(`DELETE FROM pending_signups WHERE email = $1`, [email]);
    return NextResponse.json(
      { error: "Too many wrong codes. Sign up again for a new code." },
      { status: 429 },
    );
  }
  if (new Date(pending.expires_at).getTime() < Date.now()) {
    await db.exec(`DELETE FROM pending_signups WHERE email = $1`, [email]);
    return NextResponse.json(
      { error: "The code expired. Sign up again for a new code." },
      { status: 401 },
    );
  }
  if (!codeHashMatches(code, pending.code_hash)) {
    await db.exec(
      `UPDATE pending_signups SET attempts = attempts + 1 WHERE email = $1`,
      [email],
    );
    return NextResponse.json(
      { error: "Invalid code. Check the email and try again." },
      { status: 401 },
    );
  }

  const userId = crypto.randomUUID();
  const row = await db.queryOne<{
    id: string;
    email: string;
    email_verified: boolean;
    created_at: string;
  }>(
    `INSERT INTO users (id, email, password_hash, email_verified)
     VALUES ($1, $2, $3, TRUE)
     ON CONFLICT (email) DO NOTHING
     RETURNING id, email, email_verified, created_at::text AS created_at`,
    [userId, email, pending.password_hash],
  );
  await db.exec(`DELETE FROM pending_signups WHERE email = $1`, [email]);
  if (!row) {
    return NextResponse.json(
      { error: "An account with this email already exists. Try signing in." },
      { status: 409 },
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
    },
    { status: 200 },
  );
  res.headers.set(
    "Set-Cookie",
    sessionCookieHeader(createSessionValue(secret, row.id, 0)),
  );
  return res;
}
