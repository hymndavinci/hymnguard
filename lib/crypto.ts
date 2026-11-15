// AES-256-GCM encryption for data that must be stored reversibly:
// user-supplied API keys (BYOK) and monitored email addresses (the cron
// needs the raw email to re-check it).
//
// Format: "v1.<base64url IV (12 bytes)>.<base64url ciphertext+tag>"
// The key comes from ENCRYPTION_KEY: 64 hex characters (32 bytes).
// Generate one with:
//   node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"
//
// Without ENCRYPTION_KEY, BYOK and monitoring report a "not configured"
// state — encrypted data is never written with a fallback key.

import crypto from "node:crypto";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;

export function getEncryptionKey(): Buffer | null {
  const raw = process.env.ENCRYPTION_KEY;
  if (!raw) return null;
  // Accept 64 hex chars, or base64url of 32 bytes.
  if (/^[0-9a-fA-F]{64}$/.test(raw)) return Buffer.from(raw, "hex");
  try {
    const buf = Buffer.from(raw, "base64url");
    if (buf.length === 32) return buf;
  } catch {
    // Fall through to null.
  }
  return null;
}

export function isEncryptionConfigured(): boolean {
  return getEncryptionKey() !== null;
}

export function encryptSecret(key: Buffer, plaintext: string): string {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  const combined = Buffer.concat([ciphertext, tag]);
  return `v1.${iv.toString("base64url")}.${combined.toString("base64url")}`;
}

export function decryptSecret(key: Buffer, blob: string): string | null {
  try {
    const [version, ivB64, dataB64] = blob.split(".");
    if (version !== "v1" || !ivB64 || !dataB64) return null;
    const iv = Buffer.from(ivB64, "base64url");
    const combined = Buffer.from(dataB64, "base64url");
    if (iv.length !== IV_LENGTH || combined.length <= 16) return null;
    const ciphertext = combined.subarray(0, combined.length - 16);
    const tag = combined.subarray(combined.length - 16);
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]).toString("utf8");
  } catch {
    return null;
  }
}
