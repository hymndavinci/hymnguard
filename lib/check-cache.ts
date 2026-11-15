// Route-level result cache, keyed by SHA-256 of checker + normalized input.
//
// - DB-backed (check_cache table) when DATABASE_URL is set, otherwise an
//   in-memory Map (per-instance, best-effort).
// - TTL comes from the checker registry (lib/checkers.ts). Checkers with a
//   TTL of 0 (password, username) are never cached.
// - Only successful, server-keyed results are cached. Requests that use a
//   BYOK key bypass the cache entirely (read and write) — a user's key can
//   produce different results than the server key, and cached BYOK results
//   must never leak to another user.
// - The cache never breaks a check: any error degrades to a miss.

import crypto from "node:crypto";
import { getChecker } from "./checkers";
import { getDb } from "./db";
import type { CheckType } from "./history";

export function cacheKeyFor(checkerId: CheckType, normalizedInput: string): string {
  return crypto
    .createHash("sha256")
    .update(`${checkerId}:${normalizedInput}`)
    .digest("hex");
}

// ------------------------------------------------------------------ memory
// Per-instance fallback when no database is configured. Bounded + cleaned
// opportunistically so it cannot grow without bound.

type MemoryEntry = { value: unknown; expiresAt: number };

const memoryCache = new Map<string, MemoryEntry>();
const MEMORY_MAX_ENTRIES = 1000;

function memoryGet(key: string): unknown | undefined {
  const entry = memoryCache.get(key);
  if (!entry) return undefined;
  if (entry.expiresAt <= Date.now()) {
    memoryCache.delete(key);
    return undefined;
  }
  return entry.value;
}

function memorySet(key: string, value: unknown, ttlMs: number): void {
  if (memoryCache.size >= MEMORY_MAX_ENTRIES) {
    const now = Date.now();
    for (const [k, entry] of memoryCache) {
      if (entry.expiresAt <= now) memoryCache.delete(k);
    }
    if (memoryCache.size >= MEMORY_MAX_ENTRIES) {
      // Still full — drop the oldest entry (Map preserves insertion order).
      const oldest = memoryCache.keys().next().value;
      if (oldest !== undefined) memoryCache.delete(oldest);
    }
  }
  memoryCache.set(key, { value, expiresAt: Date.now() + ttlMs });
}

// --------------------------------------------------------------------- API

export async function getCachedResult<T>(
  checkerId: CheckType,
  normalizedInput: string,
): Promise<T | null> {
  const checker = getChecker(checkerId);
  if (!checker || checker.cacheTtlSec <= 0) return null;
  const key = cacheKeyFor(checkerId, normalizedInput);
  const db = getDb();
  if (db) {
    try {
      const row = await db.queryOne<{ value: T }>(
        `SELECT value FROM check_cache WHERE key = $1 AND expires_at > now()`,
        [key],
      );
      return row?.value ?? null;
    } catch {
      return null;
    }
  }
  return (memoryGet(key) as T | undefined) ?? null;
}

export async function setCachedResult<T>(
  checkerId: CheckType,
  normalizedInput: string,
  value: T,
): Promise<void> {
  const checker = getChecker(checkerId);
  if (!checker || checker.cacheTtlSec <= 0) return;
  const key = cacheKeyFor(checkerId, normalizedInput);
  const ttlMs = checker.cacheTtlSec * 1000;
  const db = getDb();
  if (db) {
    try {
      await db.exec(
        `INSERT INTO check_cache (key, value, expires_at)
         VALUES ($1, $2::jsonb, now() + ($3 || ' seconds')::interval)
         ON CONFLICT (key) DO UPDATE
           SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at,
               created_at = now()`,
        [key, JSON.stringify(value), String(checker.cacheTtlSec)],
      );
    } catch {
      // Cache write failure is never fatal.
    }
    return;
  }
  memorySet(key, value, ttlMs);
}

/** Deletes expired rows. Called opportunistically by the monitor cron. */
export async function pruneExpiredCache(): Promise<number> {
  const db = getDb();
  if (!db) return 0;
  try {
    const rows = await db.query<{ count: string }>(
      `WITH deleted AS (
         DELETE FROM check_cache WHERE expires_at <= now() RETURNING key
       ) SELECT count(*)::text AS count FROM deleted`,
    );
    return Number(rows[0]?.count ?? 0);
  } catch {
    return 0;
  }
}
