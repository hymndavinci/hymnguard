-- HymnGuard Phase 5 schema: accounts, saved history, breach monitoring,
-- BYOK keys, and the result cache.
--
-- Applied idempotently (CREATE TABLE IF NOT EXISTS) by
-- scripts/db-push-if-configured.mjs during the Vercel build when
-- DATABASE_URL is set, or manually with psql for local development:
--   psql "$DATABASE_URL" -f db/migrations/001_init.sql
--
-- Why raw SQL instead of Prisma: the Prisma CLI cannot run in this
-- project's build environment — it downloads engine binaries and the
-- egress proxy aborts those downloads (ECONNRESET). Raw SQL keeps the
-- schema verifiable everywhere. See lib/db.ts.
--
-- Privacy notes:
-- - Passwords are stored as scrypt hashes only (lib/password.ts).
-- - checks stores a SHA-256 hash of the identifier plus a masked display
--   hint — never the raw identifier, and nothing at all for password checks.
-- - monitors.email_encrypted and user_keys.encrypted_key are AES-256-GCM
--   ciphertexts (lib/crypto.ts). Breach contents are never stored anywhere.

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  -- 'email' for email/password accounts. 'google' is reserved for a future
  -- Google OAuth login (google_sub below); no OAuth flow exists yet.
  provider TEXT NOT NULL DEFAULT 'email',
  google_sub TEXT UNIQUE,
  email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  -- Bumped on password reset: sessions carrying an older version stop
  -- validating (see lib/session.ts).
  token_version INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Signup awaiting an email verification code. Created only when Resend is
-- configured; without Resend, signup creates the user immediately.
CREATE TABLE IF NOT EXISTS pending_signups (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Forgot-password code request. One row per request; verified by code hash.
CREATE TABLE IF NOT EXISTS password_resets (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS password_resets_email_idx ON password_resets (email);

-- One saved check, owned by a user. Written by POST /api/history when a
-- logged-in user runs a check in the console.
CREATE TABLE IF NOT EXISTS checks (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  -- email | username | domain | ip | phone | password
  type TEXT NOT NULL,
  -- SHA-256 of the normalized identifier (for password: SHA-256 of the
  -- 5-char hash prefix — the password itself never leaves the browser).
  identifier_hash TEXT NOT NULL,
  -- Masked display hint: email/phone are masked, domain/username/IP are
  -- shown in full (public identifiers), password checks store nothing.
  identifier_hint TEXT,
  summary TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS checks_user_created_idx ON checks (user_id, created_at DESC);

-- A watched email address. Re-checked daily by /api/cron/monitor against
-- LeakCheck + Hudson Rock; an alert email goes out when new exposure
-- appears. The raw email is needed for re-checks, so it is stored
-- AES-256-GCM encrypted; only counts/booleans are kept as status.
CREATE TABLE IF NOT EXISTS monitors (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  email_hash TEXT NOT NULL,
  email_encrypted TEXT NOT NULL,
  verified_at TIMESTAMPTZ NOT NULL,
  last_checked_at TIMESTAMPTZ,
  last_leakcheck_found INTEGER,
  last_hudson_associated BOOLEAN,
  last_alert_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, email_hash)
);
CREATE INDEX IF NOT EXISTS monitors_user_idx ON monitors (user_id);

-- A user-supplied API key (BYOK), encrypted at rest. The key is never
-- returned to the browser in full — only the last-4 hint.
CREATE TABLE IF NOT EXISTS user_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  -- hibp | osintcat | github | otx | abuseipdb | ipqs
  provider TEXT NOT NULL,
  encrypted_key TEXT NOT NULL,
  hint TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, provider)
);

-- Route-level result cache, keyed by SHA-256 of checker + input.
-- Only successful, server-keyed results are cached (see lib/check-cache.ts).
CREATE TABLE IF NOT EXISTS check_cache (
  key TEXT PRIMARY KEY,
  value JSONB NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS check_cache_expires_idx ON check_cache (expires_at);
