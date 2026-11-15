// DNSSEC status, from two independent signals:
//  1. RDAP `secureDNS.delegationSigned` — a DS record at the parent zone,
//     which anchors the chain of trust.
//  2. DNSKEY records published at the domain itself (the zone is signed).
// A domain counts as signed when either signal is positive. When both are
// unavailable the result is inconclusive (signed: null), never "unsigned".

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

export async function lookupDnskey(domain: string): Promise<boolean | null> {
  // Node's dns.resolve() rejects "DNSKEY" as an rrtype, so ask a
  // DNS-over-HTTPS resolver instead (Google Public DNS JSON API).
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DNSKEY_TIMEOUT_MS);
  try {
    const res = await fetch(
      `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=DNSKEY`,
      { signal: controller.signal },
    );
    if (!res.ok) return null;
    const data = (await res.json()) as {
      Status?: number;
      Answer?: unknown[];
    };
    if (data.Status === 3) return false; // NXDOMAIN: no DNSKEY records.
    if (data.Status !== 0) return null;
    return Array.isArray(data.Answer) && data.Answer.length > 0;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
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
