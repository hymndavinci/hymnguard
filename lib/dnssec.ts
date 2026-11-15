// DNSSEC status, from two independent signals:
//  1. RDAP `secureDNS.delegationSigned` — a DS record at the parent zone,
//     which anchors the chain of trust.
//  2. DNSKEY records published at the domain itself (the zone is signed).
// A domain counts as signed when either signal is positive. When both are
// unavailable the result is inconclusive (signed: null), never "unsigned".

import dns from "node:dns/promises";
import { friendlyDnsError } from "./domain-check";

const DNSKEY_TIMEOUT_MS = 5000;

export interface DnssecResult {
  /** True = signed, false = not signed, null = could not determine. */
  signed: boolean | null;
  /** DS record at the parent (from RDAP). Null when RDAP gave no answer. */
  delegationSigned: boolean | null;
  /** DNSKEY records published at the domain. Null when the lookup failed. */
  dnskeyPresent: boolean | null;
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

export async function lookupDnskey(domain: string): Promise<boolean | null> {
  try {
    const records = await withTimeout(
      dns.resolve(domain, "DNSKEY"),
      DNSKEY_TIMEOUT_MS,
      "DNSKEY",
    );
    return Array.isArray(records) && records.length > 0;
  } catch (err) {
    // ENOTFOUND / ENODATA mean "no DNSKEY records" — the zone is unsigned.
    if (friendlyDnsError(err) === null) return false;
    return null;
  }
}

export function combineDnssec(
  delegationSigned: boolean | null | undefined,
  dnskeyPresent: boolean | null,
): DnssecResult {
  const ds = delegationSigned ?? null;
  if (ds === true || dnskeyPresent === true) {
    return { signed: true, delegationSigned: ds, dnskeyPresent };
  }
  if (ds === false && dnskeyPresent === false) {
    return { signed: false, delegationSigned: ds, dnskeyPresent };
  }
  if (ds === false && dnskeyPresent === null) {
    // No DS record at the parent: even if the zone published keys, no
    // validator can anchor trust — effectively unsigned.
    return { signed: false, delegationSigned: ds, dnskeyPresent };
  }
  return {
    signed: null,
    delegationSigned: ds,
    dnskeyPresent,
    error: "Could not determine DNSSEC status — the lookups failed.",
  };
}

export async function checkDnssec(
  domain: string,
  delegationSigned?: boolean | null,
): Promise<DnssecResult> {
  const dnskeyPresent = await lookupDnskey(domain);
  return combineDnssec(delegationSigned, dnskeyPresent);
}
