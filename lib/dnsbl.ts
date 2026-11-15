// DNS-based blocklist (DNSBL) checks, via the server's own resolver.
// Lists queried:
//  - Spamhaus ZEN (IP-based: SBL + XBL + PBL combined) for each A record.
//  - Spamhaus DBL (domain-based) for the domain itself.
//  - SpamCop (IP-based) for each A record.
// A listing answer is a 127.0.0.x A record. 127.255.255.255 from Spamhaus
// means the resolver is blocked or over the free query limit — reported as
// "could not check", never as a listing. NXDOMAIN means "not listed".
// NOTE: Spamhaus refuses queries from high-volume public resolvers, so
// these checks depend on the deployment's resolver being allowed.

import dns from "node:dns/promises";

const DNSBL_TIMEOUT_MS = 4000;
const MAX_IPS = 4;

export interface DnsblListResult {
  name: string;
  /** What the list covers. */
  scope: string;
  /** True = listed, false = not listed, null = could not check. */
  listed: boolean | null;
  /** IPs (or the domain) that came back listed. */
  listedOn: string[];
  error?: string;
}

export interface DnsblResult {
  lists: DnsblListResult[];
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

function reverseIpv4(ip: string): string | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  if (parts.some((p) => !/^\d{1,3}$/.test(p) || Number(p) > 255)) return null;
  return [...parts].reverse().join(".");
}

type QueryOutcome =
  | { kind: "listed"; code: string }
  | { kind: "not_listed" }
  | { kind: "blocked" }
  | { kind: "error"; message: string };

async function queryDnsbl(name: string): Promise<QueryOutcome> {
  try {
    const answers = await withTimeout(
      dns.resolve4(name),
      DNSBL_TIMEOUT_MS,
      `DNSBL ${name}`,
    );
    for (const answer of answers) {
      if (answer === "127.255.255.255") return { kind: "blocked" };
    }
    const listed = answers.find((a) => a.startsWith("127.0."));
    if (listed) return { kind: "listed", code: listed };
    return { kind: "not_listed" };
  } catch (err) {
    const code = err instanceof Error && "code" in err ? err.code : undefined;
    if (code === "ENOTFOUND" || code === "ENODATA") {
      return { kind: "not_listed" };
    }
    if (err instanceof Error && err.message.includes("timed out")) {
      return { kind: "error", message: "Query timed out" };
    }
    return { kind: "error", message: "Lookup failed" };
  }
}

async function checkIpList(
  name: string,
  scope: string,
  zone: string,
  ips: string[],
): Promise<DnsblListResult> {
  const targets = ips.slice(0, MAX_IPS);
  if (targets.length === 0) {
    return {
      name,
      scope,
      listed: null,
      listedOn: [],
      error: "No IPv4 addresses to check",
    };
  }
  const outcomes = await Promise.all(
    targets.map(async (ip) => {
      const reversed = reverseIpv4(ip);
      if (!reversed) return { ip, outcome: { kind: "error", message: "Invalid IP" } as QueryOutcome };
      return { ip, outcome: await queryDnsbl(`${reversed}.${zone}`) };
    }),
  );
  const listedOn = outcomes
    .filter((o) => o.outcome.kind === "listed")
    .map((o) => o.ip);
  const blocked = outcomes.some((o) => o.outcome.kind === "blocked");
  const errors = outcomes.filter((o) => o.outcome.kind === "error");
  if (listedOn.length > 0) {
    return { name, scope, listed: true, listedOn };
  }
  if (blocked) {
    return {
      name,
      scope,
      listed: null,
      listedOn: [],
      error:
        "Spamhaus is not answering this deployment's resolver (query limit or resolver block) — the list could not be checked.",
    };
  }
  if (errors.length === outcomes.length) {
    return {
      name,
      scope,
      listed: null,
      listedOn: [],
      error: "All blocklist queries failed.",
    };
  }
  return { name, scope, listed: false, listedOn: [] };
}

async function checkDomainList(
  name: string,
  scope: string,
  zone: string,
  domain: string,
): Promise<DnsblListResult> {
  const outcome = await queryDnsbl(`${domain}.${zone}`);
  if (outcome.kind === "listed") {
    return { name, scope, listed: true, listedOn: [domain] };
  }
  if (outcome.kind === "blocked") {
    return {
      name,
      scope,
      listed: null,
      listedOn: [],
      error:
        "Spamhaus is not answering this deployment's resolver (query limit or resolver block) — the list could not be checked.",
    };
  }
  if (outcome.kind === "error") {
    return { name, scope, listed: null, listedOn: [], error: outcome.message };
  }
  return { name, scope, listed: false, listedOn: [] };
}

export async function checkDnsbl(
  domain: string,
  ips: string[],
): Promise<DnsblResult> {
  const lists = await Promise.all([
    checkIpList(
      "Spamhaus ZEN",
      "IP reputation (spam sources, exploits, policy)",
      "zen.spamhaus.org",
      ips,
    ),
    checkDomainList(
      "Spamhaus DBL",
      "Domain reputation (spam / phishing / malware)",
      "dbl.spamhaus.org",
      domain,
    ),
    checkIpList(
      "SpamCop",
      "IP reputation (reported spam sources)",
      "bl.spamcop.net",
      ips,
    ),
  ]);
  return { lists };
}
