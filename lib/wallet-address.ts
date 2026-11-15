// Ethereum-style wallet address validation (client-safe: no node imports).
// Used by the wallet check route and by the console for client-side
// feedback before a check runs.
//
// Format: 0x + 40 hex chars. EIP-55 checksum: an all-lowercase or
// all-uppercase address carries no checksum and is accepted as-is; a
// mixed-case address must match the keccak-256 checksum or it is rejected
// (a mistyped character usually breaks the checksum — that is the point).

import { keccak256 } from "js-sha3";

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

/** The EIP-55 checksummed form of a lowercase address. */
export function toChecksumAddress(lowercaseHex: string): string {
  const hash = keccak256(lowercaseHex);
  let out = "0x";
  for (let i = 0; i < 40; i++) {
    const char = lowercaseHex[i];
    const nibble = parseInt(hash[i], 16);
    out += nibble >= 8 ? char.toUpperCase() : char;
  }
  return out;
}

/**
 * Accepts a 0x-prefixed 40-hex-char address. Mixed-case addresses must
 * pass the EIP-55 checksum. Returns the address as entered (trimmed),
 * or null when invalid.
 */
export function normalizeWalletAddress(input: unknown): string | null {
  if (typeof input !== "string") return null;
  const value = input.trim();
  if (!ADDRESS_RE.test(value)) return null;
  const hex = value.slice(2);
  const hasLower = /[a-f]/.test(hex);
  const hasUpper = /[A-F]/.test(hex);
  if (hasLower && hasUpper) {
    // Mixed case claims a checksum — verify it.
    if (toChecksumAddress(hex.toLowerCase()) !== value) return null;
  }
  return value;
}
