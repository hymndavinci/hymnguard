// Ownership verification for account enumeration.
//
// Enumeration probes third-party signup/forgot-password flows, so it only
// runs for an email the requester proves they own: we send a 6-digit code
// to the address and require it back before any probe runs.
//
// Stateless HMAC design (MVP has no database; in-memory code stores do not
// survive across Vercel instances):
//   1. verify-request: server generates a code, sends it via Resend, and
//      returns a token binding email + code + expiry with HMAC-SHA256.
//      The code itself is never inside the token — only its HMAC.
//   2. verify: server recomputes the HMAC with the user-supplied code and
//      compares in constant time. On match it issues a verification token
//      (HMAC-signed, 30 min) that authorizes enumeration chunks.
//   3. enumerate: each chunk request carries the verification token; the
//      server validates it before running any probe.
//
// Requires VERIFY_SECRET (any long random string) and RESEND_API_KEY.
// Without either, enumeration reports a needs-key state and never runs.

import crypto from "node:crypto";

export const CODE_TTL_MS = 10 * 60 * 1000; // 10 minutes
export const VERIFICATION_TTL_MS = 30 * 60 * 1000; // 30 minutes

export function generateCode(): string {
  return String(crypto.randomInt(100000, 1000000));
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

/** Token returned by verify-request. Binds email + code + expiry. */
export function createCodeToken(
  secret: string,
  email: string,
  code: string,
  expiresAtMs: number,
): string {
  const sig = hmac(secret, `${email}|${code}|${expiresAtMs}`);
  return `${b64urlEncode(email)}.${expiresAtMs}.${sig}`;
}

export function verifyCodeToken(
  secret: string,
  email: string,
  code: string,
  token: string,
): boolean {
  const [encodedEmail, expiresAtRaw, sig] = token.split(".");
  if (!encodedEmail || !expiresAtRaw || !sig) return false;
  if (b64urlDecode(encodedEmail) !== email) return false;
  const expiresAt = Number(expiresAtRaw);
  if (!Number.isFinite(expiresAt) || Date.now() > expiresAt) return false;
  return safeEqual(sig, hmac(secret, `${email}|${code}|${expiresAt}`));
}

/** Token issued by verify. Authorizes enumeration for one email. */
export function createVerificationToken(
  secret: string,
  email: string,
  validMs: number = VERIFICATION_TTL_MS,
): string {
  const expiresAt = Date.now() + validMs;
  const sig = hmac(secret, `${email}|verified|${expiresAt}`);
  return `${b64urlEncode(email)}.${expiresAt}.${sig}`;
}

export function verifyVerificationToken(
  secret: string,
  email: string,
  token: string,
): boolean {
  const [encodedEmail, expiresAtRaw, sig] = token.split(".");
  if (!encodedEmail || !expiresAtRaw || !sig) return false;
  if (b64urlDecode(encodedEmail) !== email) return false;
  const expiresAt = Number(expiresAtRaw);
  if (!Number.isFinite(expiresAt) || Date.now() > expiresAt) return false;
  return safeEqual(sig, hmac(secret, `${email}|verified|${expiresAt}`));
}

// ------------------------------------------------------------------- Resend
// POST https://api.resend.com/emails — documented API shape. The free tier
// only sends from onboarding@resend.dev to the account owner's own address;
// sending verification codes to arbitrary emails requires a verified domain
// (set RESEND_FROM to an address on that domain).

export interface ResendSendResult {
  ok: boolean;
  error?: string;
}

export async function sendVerificationCode(
  email: string,
  code: string,
  apiKey: string,
  from: string,
): Promise<ResendSendResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from,
        to: [email],
        subject: `Your HymnGuard verification code: ${code}`,
        text:
          `Your HymnGuard verification code is: ${code}\n\n` +
          `It expires in 10 minutes. Enter it in HymnGuard to prove you own ` +
          `this email address and unlock the account-enumeration check.\n\n` +
          `If you did not request this, ignore this email — no check will run.`,
        html:
          `<p>Your HymnGuard verification code is:</p>` +
          `<p style="font-size: 28px; font-weight: 700; letter-spacing: 4px; font-family: monospace;">${code}</p>` +
          `<p>It expires in 10 minutes. Enter it in HymnGuard to prove you own this email address and unlock the account-enumeration check.</p>` +
          `<p>If you did not request this, ignore this email — no check will run.</p>`,
      }),
      signal: controller.signal,
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      return {
        ok: false,
        error: `Resend responded with HTTP ${res.status}${body ? `: ${body.slice(0, 200)}` : ""}`,
      };
    }
    return { ok: true };
  } catch (err) {
    return {
      ok: false,
      error:
        err instanceof Error && err.name === "AbortError"
          ? "Resend request timed out"
          : "Could not reach Resend",
    };
  } finally {
    clearTimeout(timer);
  }
}
