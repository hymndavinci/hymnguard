// Database access for HymnGuard Phase 5 (accounts, history, monitoring,
// BYOK, cache).
//
// Two drivers behind one tiny interface:
// - Neon HTTP (@neondatabase/serverless) when DATABASE_URL points at a
//   *.neon.tech host (production).
// - pg Pool when DATABASE_URL points anywhere else (local Postgres).
// - null when DATABASE_URL is unset: every DB-backed feature reports a
//   "not configured" state instead of crashing.
//
// Why raw SQL, not Prisma: the Prisma CLI cannot run in this project's
// build environment — it downloads engine binaries on every invocation
// (generate, db push, migrate) and the egress proxy aborts those
// downloads (ECONNRESET). The schema lives in db/migrations/001_init.sql
// and is applied idempotently by scripts/db-push-if-configured.mjs.

import { neon, type NeonQueryFunction } from "@neondatabase/serverless";
import { Pool, type QueryResultRow } from "pg";

export interface Db {
  /** Run a parameterized query, return the rows. */
  query<T extends QueryResultRow>(text: string, params?: unknown[]): Promise<T[]>;
  /** Run a parameterized query, return the first row or null. */
  queryOne<T extends QueryResultRow>(
    text: string,
    params?: unknown[],
  ): Promise<T | null>;
  /** Run a parameterized statement, ignore the result. */
  exec(text: string, params?: unknown[]): Promise<void>;
}

export function isDbConfigured(): boolean {
  return Boolean(process.env.DATABASE_URL);
}

function isNeonUrl(url: string): boolean {
  try {
    return new URL(url).hostname.endsWith(".neon.tech");
  } catch {
    return false;
  }
}

function neonDb(sql: NeonQueryFunction<false, false>): Db {
  const query = async <T extends QueryResultRow>(
    text: string,
    params?: unknown[],
  ): Promise<T[]> => {
    const rows = (await sql.query(text, (params ?? []) as never[])) as unknown as T[];
    return rows;
  };
  return {
    query,
    queryOne: async <T extends QueryResultRow>(
      text: string,
      params?: unknown[],
    ): Promise<T | null> => {
      const rows = await query<T>(text, params);
      return rows[0] ?? null;
    },
    exec: async (text: string, params?: unknown[]): Promise<void> => {
      await sql.query(text, (params ?? []) as never[]);
    },
  };
}

function pgDb(pool: Pool): Db {
  const query = async <T extends QueryResultRow>(
    text: string,
    params?: unknown[],
  ): Promise<T[]> => {
    const res = await pool.query(text, (params ?? []) as never[]);
    return res.rows as T[];
  };
  return {
    query,
    queryOne: async <T extends QueryResultRow>(
      text: string,
      params?: unknown[],
    ): Promise<T | null> => {
      const rows = await query<T>(text, params);
      return rows[0] ?? null;
    },
    exec: async (text: string, params?: unknown[]): Promise<void> => {
      await pool.query(text, (params ?? []) as never[]);
    },
  };
}

// Cached on globalThis so Next.js dev-mode module reloads don't leak pools.
const globalForDb = globalThis as unknown as {
  __hymnguardDb?: Db | null;
  __hymnguardPool?: Pool;
  __hymnguardDbUrl?: string;
};

/** The database handle, or null when DATABASE_URL is not set. */
export function getDb(): Db | null {
  const url = process.env.DATABASE_URL;
  if (!url) return null;
  if (globalForDb.__hymnguardDb && globalForDb.__hymnguardDbUrl === url) {
    return globalForDb.__hymnguardDb;
  }

  let db: Db;
  if (isNeonUrl(url)) {
    db = neonDb(neon(url));
  } else {
    const pool = new Pool({
      connectionString: url,
      max: 5,
      idleTimeoutMillis: 30_000,
    });
    globalForDb.__hymnguardPool = pool;
    db = pgDb(pool);
  }
  globalForDb.__hymnguardDb = db;
  globalForDb.__hymnguardDbUrl = url;
  return db;
}

/** Standard 503 body for DB-backed endpoints when no database is set. */
export const DB_NOT_CONFIGURED = {
  error:
    "Accounts are not configured on this deployment (DATABASE_URL is not set).",
  needsSetup: true,
} as const;
