// Auth helpers shared by the account routes: loading the current user from
// the session cookie, and identifier hashing/masking for saved history.

import crypto from "node:crypto";
import { getDb } from "./db";
import {
  getSessionSecret,
  parseSessionValue,
  readSessionCookie,
} from "./session";
import type { CheckType } from "./history";

export interface CurrentUser {
  id: string;
  email: string;
  emailVerified: boolean;
  tokenVersion: number;
  createdAt: string;
}

/** Loads the logged-in user from a raw session cookie value (or null).
 *  Validates the session signature, expiry, and token version against the
 *  database — a password reset invalidates every session by bumping
 *  token_version. Used by server components via next/headers cookies(). */
export async function getCurrentUserFromSessionValue(
  value: string | null,
): Promise<CurrentUser | null> {
  const secret = getSessionSecret();
  if (!secret || !value) return null;
  const payload = parseSessionValue(secret, value);
  if (!payload) return null;
  const db = getDb();
  if (!db) return null;
  const row = await db.queryOne<{
    id: string;
    email: string;
    email_verified: boolean;
    token_version: number;
    created_at: string;
  }>(
    `SELECT id, email, email_verified, token_version,
            created_at::text AS created_at
     FROM users WHERE id = $1`,
    [payload.uid],
  );
  if (!row || row.token_version !== payload.v) return null;
  return {
    id: row.id,
    email: row.email,
    emailVerified: row.email_verified,
    tokenVersion: row.token_version,
    createdAt: row.created_at,
  };
}

/** Loads the logged-in user from a Request's session cookie (or null). */
export async function getCurrentUser(req: Request): Promise<CurrentUser | null> {
  return getCurrentUserFromSessionValue(readSessionCookie(req));
}

/** SHA-256 of the normalized identifier — the history key. Passwords are
 *  never hashed here: the caller passes the 5-char hash prefix instead. */
export function hashIdentifier(type: CheckType, input: string): string {
  const normalized =
    type === "email" ||
    type === "domain" ||
    type === "username" ||
    type === "hash" ||
    type === "wallet"
      ? input.trim().toLowerCase()
      : input.trim();
  return crypto.createHash("sha256").update(`${type}:${normalized}`).digest("hex");
}

/** Masked display hint for the history table. Email/phone are masked;
 *  domain/username/IP are public identifiers and shown in full; password
 *  checks store nothing. URLs are stored with the query and fragment
 *  stripped (they can carry tokens); image entries store only the file
 *  name, truncated. */
export function maskIdentifier(type: CheckType, input: string): string {
  const trimmed = input.trim();
  switch (type) {
    case "password":
      return "";
    case "url": {
      try {
        const parsed = new URL(trimmed);
        return `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
      } catch {
        return trimmed.split(/[?#]/)[0];
      }
    }
    case "image":
      return trimmed.length > 60 ? `${trimmed.slice(0, 57)}...` : trimmed;
    case "email": {
      const at = trimmed.indexOf("@");
      if (at <= 0) return "***";
      const local = trimmed.slice(0, at);
      const domain = trimmed.slice(at + 1);
      const head = local.length >= 2 ? local.slice(0, 2) : local.slice(0, 1);
      return `${head}***@${domain}`;
    }
    case "phone": {
      const digits = trimmed.replace(/[\s()-]/g, "");
      if (digits.length <= 8) return `${digits.slice(0, 2)}••••`;
      return `${digits.slice(0, 5)}••••${digits.slice(-4)}`;
    }
    default:
      return trimmed;
  }
}
