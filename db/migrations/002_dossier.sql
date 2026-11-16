-- HymnGuard Phase 7 — Dossier mode.
--
-- verified_identifiers: identifiers a user has PROVEN they own, via one of
-- the ownership methods below. A dossier only ever runs on verified
-- identifiers (plus identifiers derived from the account itself: the user's
-- own verified account email and their monitored emails). Nothing else is
-- ever accepted by the dossier build endpoint.
--
--   email    — method email_code: a Phase 3 verification token (code sent to
--              the address) was presented. The raw email is stored AES-256-GCM
--              encrypted (same envelope as monitors.email_encrypted) so a
--              dossier can re-check it; the display column is masked.
--   username — method username_localpart: the username is the local-part of an
--              email the user has already verified.
--            — method username_github: a public commit by that GitHub login
--              has one of the user's verified emails as its author email.
--   domain   — method domain_txt: a HymnGuard TXT record was found at
--              _hymnguard.<domain> carrying a valid HMAC verification token.
--
-- IP is NOT stored here: the "current IP" identifier is verified per build by
-- matching the request IP, and never persisted as a verified identifier.
--
-- dossier_runs: one consolidated exposure report per build. identifiers holds
-- the snapshot of what the dossier ran on (emails encrypted, username/domain/
-- IP in plaintext — public identifiers, same as the checks table); sections
-- holds one checker result per identifier (emails masked inside results);
-- report holds the computed score, findings, remediations and cross-
-- references once the run completes. status: running | complete | partial
-- (partial = at least one section errored or timed out; the report is still
-- computed from the sections that succeeded).

CREATE TABLE IF NOT EXISTS verified_identifiers (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type TEXT NOT NULL CHECK (type IN ('email', 'username', 'domain')),
  identifier_hash TEXT NOT NULL,
  identifier_display TEXT NOT NULL,
  identifier_encrypted TEXT,
  method TEXT NOT NULL,
  verified_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, type, identifier_hash)
);
CREATE INDEX IF NOT EXISTS verified_identifiers_user_idx
  ON verified_identifiers (user_id);

CREATE TABLE IF NOT EXISTS dossier_runs (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  identifiers JSONB NOT NULL,
  sections JSONB NOT NULL DEFAULT '{}'::jsonb,
  report JSONB,
  score INTEGER,
  status TEXT NOT NULL DEFAULT 'running'
    CHECK (status IN ('running', 'complete', 'partial')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS dossier_runs_user_idx
  ON dossier_runs (user_id, created_at DESC);
