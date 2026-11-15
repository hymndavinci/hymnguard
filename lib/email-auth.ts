// Email authentication grading (SpoofCheck-style): SPF, DMARC, DKIM.
// DNS-only, no key required.
//
// SHARED MODULE: Phase 2 (domain/IP expansion) reuses this in the domain
// checker — import checkEmailAuth from here, do not duplicate the logic.

import dns from "node:dns/promises";
import { friendlyDnsError } from "./domain-check";

const DNS_TIMEOUT_MS = 5000;

// Common DKIM selectors. A domain only needs one published selector to
// count as "DKIM present" — the list is a best-effort probe, not a
// guarantee that no other selector exists. Google uses date-based
// selectors for gmail.com (20230601 is current; 20161025 is still
// published), while Google Workspace customer domains use `google`.
const DKIM_SELECTORS = [
  "default",
  "google",
  "20230601",
  "20161025",
  "selector1",
  "selector2",
  "k1",
  "mail",
  "smtp",
  "dkim",
];

export type SpfPolicy = "hardfail" | "softfail" | "neutral" | "pass" | "unknown";
export type DmarcPolicy = "reject" | "quarantine" | "none" | "unknown";

export interface SpfResult {
  present: boolean;
  record?: string;
  policy?: SpfPolicy;
  /** When the SPF record redirects, the domain the policy was resolved from. */
  redirect?: string;
}

export interface DmarcResult {
  present: boolean;
  record?: string;
  policy?: DmarcPolicy;
}

export interface DkimResult {
  present: boolean;
  /** Selectors that published a DKIM record. */
  selectors: string[];
}

export interface EmailAuthResult {
  domain: string;
  spf: SpfResult;
  dmarc: DmarcResult;
  dkim: DkimResult;
  score: number;
  grade: string;
  /** Set only when the DNS lookups themselves failed. */
  error?: string;
}

function withTimeout<T>(
  promise: Promise<T>,
  ms: number,
  label: string,
): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_resolve, reject) =>
      setTimeout(() => reject(new Error(`${label} timed out`)), ms),
    ),
  ]);
}

function flattenTxt(records: string[][]): string[] {
  return records.map((parts) => parts.join(""));
}

export function parseSpf(records: string[]): SpfResult {
  const record = records.find((r) => r.startsWith("v=spf1"));
  if (!record) return { present: false };
  let policy: SpfPolicy = "unknown";
  if (record.includes("-all")) policy = "hardfail";
  else if (record.includes("~all")) policy = "softfail";
  else if (record.includes("?all")) policy = "neutral";
  else if (record.includes("+all")) policy = "pass";
  return { present: true, record, policy };
}

function parseDmarc(records: string[]): DmarcResult {
  const record = records.find((r) => r.startsWith("v=DMARC1"));
  if (!record) return { present: false };
  const match = record.match(/p=(reject|quarantine|none)/);
  return {
    present: true,
    record,
    policy: match ? (match[1] as DmarcPolicy) : "unknown",
  };
}

export function gradeFor(score: number): string {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

/** Pure scoring, exported for unit testing. Start at 100, deduct for
 * missing or weak mechanisms. */
export function scoreEmailAuth(
  spf: SpfResult,
  dmarc: DmarcResult,
  dkim: DkimResult,
): number {
  let score = 100;
  if (!spf.present) score -= 35;
  else if (spf.policy === "softfail") score -= 15;
  else if (spf.policy === "neutral") score -= 25;
  else if (spf.policy === "pass" || spf.policy === "unknown") score -= 30;
  if (!dmarc.present) score -= 35;
  else if (dmarc.policy === "none") score -= 20;
  else if (dmarc.policy === "quarantine") score -= 10;
  else if (dmarc.policy === "unknown") score -= 15;
  if (!dkim.present) score -= 30;
  return Math.max(0, score);
}

async function resolveTxtSafe(name: string): Promise<string[]> {
  try {
    const records = await withTimeout(
      dns.resolveTxt(name),
      DNS_TIMEOUT_MS,
      `TXT ${name}`,
    );
    return flattenTxt(records);
  } catch (err) {
    // ENOTFOUND / ENODATA mean "no records" — a result, not an error.
    if (friendlyDnsError(err) === null) return [];
    throw err;
  }
}

/** Resolve SPF, following `redirect=` chains (e.g. gmail.com redirects to
 * _spf.google.com). The policy comes from the final record in the chain;
 * `record` stays the domain's own record. Loops and chains longer than 3
 * hops resolve to policy "unknown" instead of failing. */
async function resolveSpf(domain: string): Promise<SpfResult> {
  const seen = new Set<string>([domain]);
  let current = domain;
  let originalRecord: string | undefined;
  let redirect: string | undefined;
  for (let hop = 0; hop < 4; hop++) {
    const records = await resolveTxtSafe(current);
    const record = records.find((r) => r.startsWith("v=spf1"));
    if (!record) {
      // No SPF record at this hop. If we arrived here via a redirect, the
      // chain is broken — the domain still publishes an SPF record, but
      // its policy cannot be determined.
      return originalRecord
        ? { present: true, record: originalRecord, policy: "unknown", redirect }
        : { present: false };
    }
    if (hop === 0) originalRecord = record;
    const target = record.match(/redirect=([A-Za-z0-9._-]+)/)?.[1];
    if (!target || seen.has(target)) {
      const parsed = parseSpf([record]);
      return { ...parsed, record: originalRecord ?? record, redirect };
    }
    seen.add(target);
    redirect = target;
    current = target;
  }
  return { present: true, record: originalRecord, policy: "unknown", redirect };
}

/** A TXT record at a `._domainkey` name is a DKIM key when it carries the
 * version tag — or, for publishers that omit it (Google's older selectors
 * do), when it carries a public key (`p=`) with a key type. Either way the
 * public key must be non-empty: RFC 6376 treats an empty `p=` as a revoked
 * key (example.com publishes a wildcard `v=DKIM1; p=` record, which must
 * not count as a real key). */
export function isDkimRecord(record: string): boolean {
  const hasKey = /p=\s*[A-Za-z0-9+/=]+/.test(record);
  if (!hasKey) return false;
  if (record.includes("v=DKIM1")) return true;
  return record.includes("k=rsa") || record.includes("k=ed25519");
}

export async function checkEmailAuth(domain: string): Promise<EmailAuthResult> {
  const [spfResult, dmarcRecords, dkimResults] = await Promise.allSettled([
    resolveSpf(domain),
    resolveTxtSafe(`_dmarc.${domain}`),
    Promise.all(
      DKIM_SELECTORS.map(async (selector) => {
        const records = await resolveTxtSafe(
          `${selector}._domainkey.${domain}`,
        );
        const found = records.some(isDkimRecord);
        return { selector, found };
      }),
    ),
  ]);

  // If every lookup failed with a real DNS error, report it instead of
  // pretending all three mechanisms are absent.
  const failures = [spfResult, dmarcRecords, dkimResults].filter(
    (r) => r.status === "rejected",
  );
  if (failures.length === 3) {
    const reason = (failures[0] as PromiseRejectedResult).reason;
    const message = friendlyDnsError(reason) ?? "DNS lookups failed";
    return {
      domain,
      spf: { present: false },
      dmarc: { present: false },
      dkim: { present: false, selectors: [] },
      score: 0,
      grade: "F",
      error: message,
    };
  }

  const spf =
    spfResult.status === "fulfilled"
      ? spfResult.value
      : { present: false };
  const dmarc =
    dmarcRecords.status === "fulfilled"
      ? parseDmarc(dmarcRecords.value ?? [])
      : { present: false };
  const dkimFound =
    dkimResults.status === "fulfilled"
      ? dkimResults.value.filter((r) => r.found).map((r) => r.selector)
      : [];
  const dkim: DkimResult = { present: dkimFound.length > 0, selectors: dkimFound };

  const score = scoreEmailAuth(spf, dmarc, dkim);
  return { domain, spf, dmarc, dkim, score, grade: gradeFor(score) };
}
