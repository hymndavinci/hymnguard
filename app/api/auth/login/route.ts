import { NextResponse } from "next/server";
import { DB_NOT_CONFIGURED, getDb, isDbConfigured } from "@/lib/db";
import {
  dummyPasswordCheck,
  verifyPassword,
} from "@/lib/password";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";
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
// Signs in and issues a session cookie. Anti-enumeration: every failure
// returns the same generic 401, and a missing user still runs a dummy
// scrypt so timing doesn't reveal whether the email exists.
export async function POST(req: Request) {
  const ip = getClientIp(req);
  const limit = checkRateLimit(`auth:login:${ip}`);
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
  const input = body as { email?: unknown; password?: unknown } | null;
  const email = normalizeEmail(input?.email);
  const password = typeof input?.password === "string" ? input.password : "";
  if (!email || !password) {
    return NextResponse.json(
      { error: "Invalid email or password." },
      { status: 401 },
    );
  }

  const user = await db.queryOne<{
    id: string;
    email: string;
    password_hash: string;
    email_verified: boolean;
    token_version: number;
    created_at: string;
  }>(
    `SELECT id, email, password_hash, email_verified, token_version,
            created_at::text AS created_at
     FROM users WHERE email = $1`,
    [email],
  );
  if (!user) {
    await dummyPasswordCheck();
    return NextResponse.json(
      { error: "Invalid email or password." },
      { status: 401 },
    );
  }
  const ok = await verifyPassword(password, user.password_hash);
  if (!ok) {
    return NextResponse.json(
      { error: "Invalid email or password." },
      { status: 401 },
    );
  }

  const secret = getSessionSecret();
  if (!secret) {
    return NextResponse.json(DB_NOT_CONFIGURED, { status: 503 });
  }
  const res = NextResponse.json({
    user: {
      id: user.id,
      email: user.email,
      emailVerified: user.email_verified,
      createdAt: user.created_at,
    },
  });
  res.headers.set(
    "Set-Cookie",
    sessionCookieHeader(
      createSessionValue(secret, user.id, user.token_version),
    ),
  );
  return res;
}
