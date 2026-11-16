// Dossier mode (Phase 7): ownership proofs, the verified-identifier
// registry, and dossier-run storage.
//
// THE HARD RULE: a dossier only ever runs on identifiers the user has
// PROVEN they own. Every identifier entering a build is resolved through
// one of these paths, and anything else is rejected with 403:
//
//   Email    — the user's own verified account email, a monitored email
//              (ownership-verified when the monitor was created), or a
//              registry row created by presenting a valid Phase 3
//              verification token (a code sent to the address).
//   Username — the local-part of an already-verified email, or a GitHub
//              login whose public commits carry a verified email as the
//              author email (needs a GitHub token).
//   Domain   — a DNS TXT record at _hymnguard.<domain> carrying a valid
//              HMAC verification token (24h TTL, stateless).
//   IP       — the requester's own current public IP, verified per build by
//              matching the request IP. Never stored as a verified identifier.
//
// Excluded by design: phone (no SMS verification channel), crypto wallet
// (would need message signing), password/hash/URL/image (not identity
// identifiers — they can't be "owned" in any verifiable sense).
//
// Storage: emails are stored AES-256-GCM encrypted (same envelope as
// monitors) and shown masked everywhere; username/domain/IP are public
// identifiers and stored in plaintext, same as the checks table. Run
// payloads sent to the client are stripped of encrypted values via
// toPublicRun() — the server re-decrypts them only while running chunks.

import crypto from "node:crypto";
import { resolveTxt } from "node:dns/promises";
import { hashIdentifier, maskIdentifier, type CurrentUser } from "./auth";
import {
  decryptSecret,
  encryptSecret,
  getEncryptionKey,
} from "./crypto";
import { searchCommitAuthorLogins } from "./github-exposure";
import type { Db } from "./db";
import type {
  DossierIdentifierType,
  DossierReport,
  DossierSection,
} from "./dossier-score";

export type { DossierIdentifierType } from "./dossier-score";

export interface DossierIdentifierInput {
  type: DossierIdentifierType;
  value: string;
}

/** One identifier the user has verified ownership of (registry or derived). */
export interface VerifiedIdentifier {
  id: string;
  type: Exclude<DossierIdentifierType, "ip">;
  display: string;
  method: string;
  verifiedAt: string;
  /** True for entries derived from the account itself (account email /
   *  monitored emails) rather than registry rows. */
  derived: boolean;
}

/** One identifier snapshotted into a dossier run. Emails are encrypted;
 *  username/domain/IP are stored in plaintext (public identifiers). */
export interface DossierRunIdentifier {
  type: DossierIdentifierType;
  display: string;
  hash: string;
  value?: string;
  valueEncrypted?: string;
}

export type DossierRunStatus = "running" | "complete" | "partial";

export interface DossierRun {
  id: string;
  userId: string;
  identifiers: DossierRunIdentifier[];
  sections: Record<string, DossierSection>;
  report: DossierReport | null;
  score: number | null;
  status: DossierRunStatus;
  createdAt: string;
  updatedAt: string;
}

/** The run as returned to the client: no raw values, no encrypted blobs. */
export type PublicDossierRun = Omit<DossierRun, "identifiers" | "userId"> & {
  identifiers: { type: DossierIdentifierType; display: string; hash: string }[];
};

export function toPublicRun(run: DossierRun): PublicDossierRun {
  return {
    id: run.id,
    identifiers: run.identifiers.map(({ type, display, hash }) => ({
      type,
      display,
      hash,
    })),
    sections: run.sections,
    report: run.report,
    score: run.score,
    status: run.status,
    createdAt: run.createdAt,
    updatedAt: run.updatedAt,
  };
}

export const MAX_VERIFIED_IDENTIFIERS = 10;
export const MAX_DOSSIER_IDENTIFIERS = 8;
const DOMAIN_TOKEN_TTL_MS = 24 * 60 * 60 * 1000;

/** AES-256-GCM via the shared crypto module (same envelope as monitors).
 *  Returns null when ENCRYPTION_KEY is not configured — encrypted data is
 *  never written with a fallback key. */
function encryptIdentifier(plaintext: string): string | null {
  const key = getEncryptionKey();
  return key ? encryptSecret(key, plaintext) : null;
}

function decryptIdentifier(blob: string): string | null {
  const key = getEncryptionKey();
  return key ? decryptSecret(key, blob) : null;
}

// ---------------------------------------------------------------------------
// Ownership resolution
// ---------------------------------------------------------------------------

export interface OwnershipResult {
  verified: boolean;
  method?: string;
  reason?: string;
  note?: string;
}

/** All emails the user has verified, as raw values. Decryption needs
 *  ENCRYPTION_KEY; without it only the (plaintext) account email is
 *  available. Used for username local-part / GitHub-link checks. */
export async function getVerifiedEmails(
  db: Db,
  user: CurrentUser,
): Promise<string[]> {
  const emails: string[] = [];
  if (user.emailVerified) emails.push(user.email);

  const rows = await db.query<{
    identifier_encrypted: string | null;
  }>(
    `SELECT identifier_encrypted FROM verified_identifiers
     WHERE user_id = $1 AND type = 'email'`,
    [user.id],
  );
  for (const row of rows) {
    if (!row.identifier_encrypted) continue;
    const decrypted = decryptIdentifier(row.identifier_encrypted);
    if (decrypted) emails.push(decrypted);
  }

  const monitors = await db.query<{ email_encrypted: string }>(
    `SELECT email_encrypted FROM monitors WHERE user_id = $1`,
    [user.id],
  );
  for (const row of monitors) {
    const decrypted = decryptIdentifier(row.email_encrypted);
    if (decrypted) emails.push(decrypted);
  }

  return [...new Set(emails.map((e) => e.trim().toLowerCase()))];
}

export async function resolveEmailOwnership(
  db: Db,
  user: CurrentUser,
  email: string,
): Promise<OwnershipResult> {
  const normalized = email.trim().toLowerCase();
  if (user.emailVerified && user.email === normalized) {
    return { verified: true, method: "account_email" };
  }
  const hash = hashIdentifier("email", normalized);
  const registry = await db.queryOne<{ method: string }>(
    `SELECT method FROM verified_identifiers
     WHERE user_id = $1 AND type = 'email' AND identifier_hash = $2`,
    [user.id, hash],
  );
  if (registry) return { verified: true, method: registry.method };
  const monitor = await db.queryOne<{ id: string }>(
    `SELECT id FROM monitors WHERE user_id = $1 AND email_hash = $2`,
    [user.id, hash],
  );
  if (monitor) return { verified: true, method: "monitor" };
  return {
    verified: false,
    reason:
      "Verify this email first — we send a 6-digit code to the address, and only the inbox owner can complete it.",
  };
}

export async function resolveUsernameOwnership(
  db: Db,
  user: CurrentUser,
  username: string,
  githubToken?: string,
): Promise<OwnershipResult> {
  const normalized = username.trim().toLowerCase();
  const emails = await getVerifiedEmails(db, user);

  for (const email of emails) {
    const localPart = email.split("@")[0];
    if (localPart === normalized) {
      return { verified: true, method: "username_localpart" };
    }
  }

  if (githubToken) {
    for (const email of emails) {
      const result = await searchCommitAuthorLogins(email, githubToken);
      if (result.status === "ok") {
        const logins = result.logins.map((l) => l.toLowerCase());
        if (logins.includes(normalized)) {
          return { verified: true, method: "username_github" };
        }
      }
      // A rate limit or error on one email must not block the others.
    }
    return {
      verified: false,
      reason:
        "This username is not the local-part of any of your verified emails, and no public GitHub commit by this login uses one of your verified emails as its author email.",
    };
  }

  return {
    verified: false,
    reason:
      "This username is not the local-part of any of your verified emails.",
    note: "The GitHub-link check needs a GitHub token — add one in Settings (Bring your own key) or as an environment key, then try again.",
  };
}

export async function resolveDomainOwnership(
  db: Db,
  user: CurrentUser,
  domain: string,
): Promise<OwnershipResult> {
  const normalized = domain.trim().toLowerCase();
  const registry = await db.queryOne<{ method: string }>(
    `SELECT method FROM verified_identifiers
     WHERE user_id = $1 AND type = 'domain' AND identifier_hash = $2`,
    [user.id, hashIdentifier("domain", normalized)],
  );
  if (registry) return { verified: true, method: registry.method };
  return {
    verified: false,
    reason:
      "Verify this domain first by adding a DNS TXT record at _hymnguard.<domain>.",
  };
}

// ---------------------------------------------------------------------------
// Domain TXT verification (stateless HMAC tokens, 24h TTL)
// ---------------------------------------------------------------------------

function domainTokenHmac(secret: string, domain: string, expiresAt: number): string {
  return crypto
    .createHmac("sha256", secret)
    .update(`domain-verify|${domain}|${expiresAt}`)
    .digest("hex");
}

export function createDomainVerifyToken(
  secret: string,
  domain: string,
  ttlMs: number = DOMAIN_TOKEN_TTL_MS,
): { value: string; host: string; expiresAt: number } {
  const normalized = domain.trim().toLowerCase();
  const expiresAt = Date.now() + ttlMs;
  const payload = Buffer.from(normalized, "utf8").toString("base64url");
  const value = `hymnguard-verify=${payload}.${expiresAt}.${domainTokenHmac(secret, normalized, expiresAt)}`;
  return { value, host: `_hymnguard.${normalized}`, expiresAt };
}

/** Validates a TXT value: prefix, embedded domain, expiry, HMAC. */
export function verifyDomainToken(
  secret: string,
  domain: string,
  value: string,
): boolean {
  const normalized = domain.trim().toLowerCase();
  const prefix = "hymnguard-verify=";
  if (!value.startsWith(prefix)) return false;
  const rest = value.slice(prefix.length);
  const parts = rest.split(".");
  if (parts.length !== 3) return false;
  const [payload, expiresAtRaw, hmac] = parts;
  let embedded: string;
  try {
    embedded = Buffer.from(payload, "base64url").toString("utf8");
  } catch {
    return false;
  }
  if (embedded !== normalized) return false;
  const expiresAt = Number(expiresAtRaw);
  if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) return false;
  const expected = domainTokenHmac(secret, normalized, expiresAt);
  const a = Buffer.from(hmac);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export type TxtResolver = (host: string) => Promise<string[][]>;

/** Checks DNS for a valid HymnGuard TXT record at _hymnguard.<domain>.
 *  The resolver is injectable so unit tests can stub DNS (VM DNS is broken). */
export async function confirmDomainOwnership(
  domain: string,
  secret: string,
  resolveTxtFn: TxtResolver = (host) => resolveTxt(host),
): Promise<{ verified: boolean; error?: string }> {
  const normalized = domain.trim().toLowerCase();
  const host = `_hymnguard.${normalized}`;
  let records: string[][];
  try {
    records = await resolveTxtFn(host);
  } catch (err) {
    const code = (err as { code?: string } | null)?.code;
    if (code === "ENOTFOUND" || code === "ENODATA") {
      return {
        verified: false,
        error: `No TXT record found at ${host}. Add the record and try again — DNS changes can take a few minutes to propagate.`,
      };
    }
    return {
      verified: false,
      error: `DNS lookup failed (${code ?? "unknown"}). Try again shortly.`,
    };
  }
  for (const record of records) {
    // TXT records can be split into chunks; join them back.
    if (verifyDomainToken(secret, normalized, record.join("").trim())) {
      return { verified: true };
    }
  }
  return {
    verified: false,
    error: `No valid verification record found at ${host}. Make sure the TXT value is exactly as shown.`,
  };
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

interface RegistryRow {
  id: string;
  type: string;
  identifier_hash: string;
  identifier_display: string;
  identifier_encrypted: string | null;
  method: string;
  verified_at: string;
}

export async function listVerifiedIdentifiers(
  db: Db,
  user: CurrentUser,
): Promise<VerifiedIdentifier[]> {
  const out: VerifiedIdentifier[] = [];

  if (user.emailVerified) {
    out.push({
      id: "account",
      type: "email",
      display: maskIdentifier("email", user.email),
      method: "account_email",
      verifiedAt: user.createdAt,
      derived: true,
    });
  }

  const monitors = await db.query<{
    id: string;
    email_encrypted: string;
    created_at: string;
  }>(
    `SELECT id, email_encrypted, created_at::text AS created_at
     FROM monitors WHERE user_id = $1 ORDER BY created_at`,
    [user.id],
  );
  for (const row of monitors) {
    const email = decryptIdentifier(row.email_encrypted);
    if (!email) continue; // Needs ENCRYPTION_KEY; can't display or use it.
    if (user.emailVerified && email === user.email) continue; // Already listed.
    out.push({
      id: `monitor:${row.id}`,
      type: "email",
      display: maskIdentifier("email", email),
      method: "monitor",
      verifiedAt: row.created_at,
      derived: true,
    });
  }

  const rows = await db.query<RegistryRow>(
    `SELECT id, type, identifier_hash, identifier_display,
            identifier_encrypted, method, verified_at::text AS verified_at
     FROM verified_identifiers WHERE user_id = $1 ORDER BY created_at`,
    [user.id],
  );
  for (const row of rows) {
    if (
      row.type === "email" &&
      out.some((v) => v.type === "email" && v.display === row.identifier_display)
    ) {
      continue; // Same email already listed via account/monitor.
    }
    out.push({
      id: row.id,
      type: row.type as VerifiedIdentifier["type"],
      display: row.identifier_display,
      method: row.method,
      verifiedAt: row.verified_at,
      derived: false,
    });
  }

  return out;
}

/** Resolves a verified-identifier id (registry row, "account", or
 *  "monitor:<id>") back to its raw value. Returns null when the id does not
 *  exist, belongs to another user, or can't be decrypted. */
export async function resolveVerifiedId(
  db: Db,
  user: CurrentUser,
  id: string,
): Promise<{ type: Exclude<DossierIdentifierType, "ip">; value: string } | null> {
  if (id === "account") {
    if (!user.emailVerified) return null;
    return { type: "email", value: user.email };
  }
  if (id.startsWith("monitor:")) {
    const monitorId = id.slice("monitor:".length);
    const row = await db.queryOne<{ email_encrypted: string }>(
      `SELECT email_encrypted FROM monitors WHERE id = $1 AND user_id = $2`,
      [monitorId, user.id],
    );
    if (!row) return null;
    const email = decryptIdentifier(row.email_encrypted);
    return email ? { type: "email", value: email } : null;
  }
  const row = await db.queryOne<RegistryRow>(
    `SELECT type, identifier_display, identifier_encrypted
     FROM verified_identifiers WHERE id = $1 AND user_id = $2`,
    [id, user.id],
  );
  if (!row) return null;
  if (row.type === "email") {
    if (!row.identifier_encrypted) return null;
    const email = decryptIdentifier(row.identifier_encrypted);
    return email ? { type: "email", value: email } : null;
  }
  return {
    type: row.type as Exclude<DossierIdentifierType, "ip">,
    value: row.identifier_display,
  };
}

export async function addVerifiedIdentifier(
  db: Db,
  userId: string,
  input: { type: Exclude<DossierIdentifierType, "ip">; value: string; method: string },
): Promise<{ ok: true; id: string } | { ok: false; error: string }> {
  const count = await db.queryOne<{ n: string }>(
    `SELECT COUNT(*)::text AS n FROM verified_identifiers WHERE user_id = $1`,
    [userId],
  );
  if (count && Number(count.n) >= MAX_VERIFIED_IDENTIFIERS) {
    return {
      ok: false,
      error: `You can verify up to ${MAX_VERIFIED_IDENTIFIERS} identifiers. Remove one first.`,
    };
  }

  const encrypted =
    input.type === "email" ? encryptIdentifier(input.value) : null;
  if (input.type === "email" && encrypted === null) {
    return {
      ok: false,
      error:
        "Email verification needs server-side encryption (ENCRYPTION_KEY) to be configured. Ask the instance owner to set it.",
    };
  }

  const row = await db.queryOne<{ id: string }>(
    `INSERT INTO verified_identifiers
       (id, user_id, type, identifier_hash, identifier_display,
        identifier_encrypted, method)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     ON CONFLICT (user_id, type, identifier_hash)
       DO UPDATE SET method = EXCLUDED.method, verified_at = now()
     RETURNING id`,
    [
      crypto.randomUUID(),
      userId,
      input.type,
      hashIdentifier(input.type, input.value),
      input.type === "email"
        ? maskIdentifier("email", input.value)
        : input.value,
      encrypted,
      input.method,
    ],
  );
  if (!row) return { ok: false, error: "Could not save the identifier." };
  return { ok: true, id: row.id };
}

export async function removeVerifiedIdentifier(
  db: Db,
  userId: string,
  id: string,
): Promise<boolean> {
  const row = await db.queryOne<{ id: string }>(
    `DELETE FROM verified_identifiers WHERE id = $1 AND user_id = $2
     RETURNING id`,
    [id, userId],
  );
  return row !== null;
}

// ---------------------------------------------------------------------------
// Runs
// ---------------------------------------------------------------------------

/** Builds the stored run identifier for a verified raw value. Emails are
 *  encrypted; anything else is stored in plaintext (public identifiers). */
export function toRunIdentifier(
  input: DossierIdentifierInput,
): DossierRunIdentifier | { error: string } {
  if (input.type === "email") {
    const encrypted = encryptIdentifier(input.value);
    if (encrypted === null) {
      return {
        error:
          "Email dossiers need server-side encryption (ENCRYPTION_KEY) to be configured.",
      };
    }
    return {
      type: "email",
      display: maskIdentifier("email", input.value),
      hash: hashIdentifier("email", input.value),
      valueEncrypted: encrypted,
    };
  }
  return {
    type: input.type,
    display: input.value,
    hash: hashIdentifier(input.type, input.value),
    value: input.value,
  };
}

/** Decrypts a run identifier back to its raw value for checking. */
export function runIdentifierValue(
  identifier: DossierRunIdentifier,
): string | null {
  if (identifier.type === "email") {
    if (!identifier.valueEncrypted) return null;
    return decryptIdentifier(identifier.valueEncrypted);
  }
  return identifier.value ?? null;
}

function rowToRun(row: {
  id: string;
  user_id: string;
  identifiers: DossierRunIdentifier[] | string;
  sections: Record<string, DossierSection> | string;
  report: DossierReport | string | null;
  score: number | null;
  status: string;
  created_at: string;
  updated_at: string;
}): DossierRun {
  const parse = <T,>(v: T | string, fallback: T): T =>
    typeof v === "string" ? (JSON.parse(v) as T) : (v ?? fallback);
  return {
    id: row.id,
    userId: row.user_id,
    identifiers: parse(row.identifiers, []),
    sections: parse(row.sections, {}),
    report: row.report === null ? null : parse(row.report, null),
    score: row.score,
    status: row.status as DossierRunStatus,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

type RunRow = {
  id: string;
  user_id: string;
  identifiers: DossierRunIdentifier[] | string;
  sections: Record<string, DossierSection> | string;
  report: DossierReport | string | null;
  score: number | null;
  status: string;
  created_at: string;
  updated_at: string;
};

const RUN_COLUMNS = `id, user_id, identifiers, sections, report, score,
  status, created_at::text AS created_at, updated_at::text AS updated_at`;

export async function createDossierRun(
  db: Db,
  userId: string,
  identifiers: DossierRunIdentifier[],
): Promise<DossierRun> {
  const id = crypto.randomUUID();
  const row = await db.queryOne<RunRow>(
    `INSERT INTO dossier_runs (id, user_id, identifiers)
     VALUES ($1, $2, $3::jsonb)
     RETURNING ${RUN_COLUMNS}`,
    [id, userId, JSON.stringify(identifiers)],
  );
  if (!row) throw new Error("Failed to create dossier run.");
  return rowToRun(row);
}

export async function getDossierRun(
  db: Db,
  userId: string,
  runId: string,
): Promise<DossierRun | null> {
  const row = await db.queryOne<RunRow>(
    `SELECT ${RUN_COLUMNS} FROM dossier_runs WHERE id = $1 AND user_id = $2`,
    [runId, userId],
  );
  return row ? rowToRun(row) : null;
}

export async function getLatestDossierRun(
  db: Db,
  userId: string,
): Promise<DossierRun | null> {
  const row = await db.queryOne<RunRow>(
    `SELECT ${RUN_COLUMNS} FROM dossier_runs
     WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1`,
    [userId],
  );
  return row ? rowToRun(row) : null;
}

/** Stores one section atomically (jsonb_set) so concurrent chunk requests
 *  can't clobber each other's sections. */
export async function saveDossierSection(
  db: Db,
  runId: string,
  index: number,
  section: DossierSection,
): Promise<void> {
  await db.exec(
    `UPDATE dossier_runs
     SET sections = jsonb_set(sections, $2::text[], $3::jsonb, true),
         updated_at = now()
     WHERE id = $1`,
    [runId, `{${index}}`, JSON.stringify(section)],
  );
}

export async function finalizeDossierRun(
  db: Db,
  runId: string,
  report: DossierReport,
  status: "complete" | "partial",
): Promise<void> {
  await db.exec(
    `UPDATE dossier_runs
     SET report = $2::jsonb, score = $3, status = $4, updated_at = now()
     WHERE id = $1`,
    [runId, JSON.stringify(report), report.score, status],
  );
}
