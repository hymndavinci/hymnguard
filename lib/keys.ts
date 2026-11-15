// BYOK key resolution: for each keyed provider, the effective key is the
// logged-in user's own key when they saved one, otherwise the server env
// key. Used by the check routes so a user's key unlocks sources the
// deployment hasn't configured.
//
// A request that uses any BYOK key must bypass the result cache (see
// lib/check-cache.ts) — the result may differ from the server-keyed one.

import { decryptSecret, getEncryptionKey } from "./crypto";
import { getDb } from "./db";
import type { KeyProvider } from "./checkers";

export const ENV_KEY_MAP: Record<KeyProvider, string> = {
  hibp: "HIBP_API_KEY",
  osintcat: "OSINTCAT_API_KEY",
  github: "GITHUB_TOKEN",
  otx: "OTX_API_KEY",
  abuseipdb: "ABUSEIPDB_API_KEY",
  ipqs: "IPQS_API_KEY",
  virustotal: "VIRUSTOTAL_API_KEY",
  malwarebazaar: "MALWAREBAZAAR_API_KEY",
  hybridanalysis: "HYBRID_ANALYSIS_API_KEY",
  safebrowsing: "SAFE_BROWSING_API_KEY",
  etherscan: "ETHERSCAN_API_KEY",
};

export type ResolvedKeys = Partial<Record<KeyProvider, string>> & {
  /** True when at least one key came from the user's BYOK store. */
  usedByok: boolean;
};

const PROVIDERS: KeyProvider[] = [
  "hibp",
  "osintcat",
  "github",
  "otx",
  "abuseipdb",
  "ipqs",
  "virustotal",
  "malwarebazaar",
  "hybridanalysis",
  "safebrowsing",
  "etherscan",
];

export async function resolveKeys(userId: string | null): Promise<ResolvedKeys> {
  const resolved: ResolvedKeys = { usedByok: false };
  for (const provider of PROVIDERS) {
    const envKey = process.env[ENV_KEY_MAP[provider]];
    if (envKey) resolved[provider] = envKey;
  }

  if (!userId) return resolved;
  const db = getDb();
  if (!db) return resolved;
  const encKey = getEncryptionKey();
  if (!encKey) return resolved;

  try {
    const rows = await db.query<{
      provider: string;
      encrypted_key: string;
    }>(`SELECT provider, encrypted_key FROM user_keys WHERE user_id = $1`, [
      userId,
    ]);
    for (const row of rows) {
      if (!PROVIDERS.includes(row.provider as KeyProvider)) continue;
      const decrypted = decryptSecret(encKey, row.encrypted_key);
      if (!decrypted) continue;
      resolved[row.provider as KeyProvider] = decrypted;
      resolved.usedByok = true;
    }
  } catch {
    // Key lookup failure falls back to env keys — never breaks a check.
  }
  return resolved;
}
