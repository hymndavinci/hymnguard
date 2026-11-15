// Stateless session cookies (HMAC-signed, no server-side session store).
//
// Cookie value: "<base64url JSON>.<hex HMAC-SHA256>"
// Payload: { uid, exp, v } — user id, expiry (epoch ms), token version.
// The token version is checked against users.token_version on every
// authenticated request, so a password reset (which bumps token_version)
// invalidates all existing sessions.
//
// Requires SESSION_SECRET (any long random string). Without it, auth
// endpoints report a "not configured" state and never issue sessions.

import crypto from "node:crypto";

export const SESSION_COOKIE = "hymnguard_session";
export const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

export interface SessionPayload {
  uid: string;
  exp: number;
  v: number;
}

function b64urlEncode(text: string): string {
  return Buffer.from(text, "utf8").toString("base64url");
}

function b64urlDecode(text: string): string | null {
  try {
    return Buffer.from(text, "base64url").toString("utf8");
  } catch {
    return null;
  }
}

function hmac(secret: string, payload: string): string {
  return crypto.createHmac("sha256", secret).update(payload).digest("hex");
}

function safeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

export function getSessionSecret(): string | null {
  return process.env.SESSION_SECRET || null;
}

export function isAuthConfigured(): boolean {
  return Boolean(process.env.DATABASE_URL && process.env.SESSION_SECRET);
}

export function createSessionValue(
  secret: string,
  userId: string,
  tokenVersion: number,
): string {
  const payload: SessionPayload = {
    uid: userId,
    exp: Date.now() + SESSION_TTL_MS,
    v: tokenVersion,
  };
  const encoded = b64urlEncode(JSON.stringify(payload));
  return `${encoded}.${hmac(secret, encoded)}`;
}

export function parseSessionValue(
  secret: string,
  value: string,
): SessionPayload | null {
  const [encoded, sig] = value.split(".");
  if (!encoded || !sig) return null;
  if (!safeEqual(sig, hmac(secret, encoded))) return null;
  const json = b64urlDecode(encoded);
  if (!json) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) return null;
  const { uid, exp, v } = parsed as Record<string, unknown>;
  if (typeof uid !== "string" || !uid) return null;
  if (typeof exp !== "number" || !Number.isFinite(exp)) return null;
  if (typeof v !== "number" || !Number.isInteger(v)) return null;
  if (Date.now() > exp) return null;
  return { uid, exp, v };
}

export function sessionCookieHeader(value: string): string {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  return (
    `${SESSION_COOKIE}=${value}; Path=/; HttpOnly; SameSite=Lax${secure}; ` +
    `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`
  );
}

export function clearSessionCookieHeader(): string {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
}

/** Reads the session cookie from a Request (works in route handlers, where
 *  next/headers cookies() has proven unreliable). */
export function readSessionCookie(req: Request): string | null {
  const header = req.headers.get("cookie");
  if (!header) return null;
  for (const part of header.split(";")) {
    const [name, ...rest] = part.trim().split("=");
    if (name === SESSION_COOKIE) return rest.join("=") || null;
  }
  return null;
}
