// Domain checks: DNS, TLS certificate, security headers, passive subdomains,
// registration (RDAP), Wayback history, email-auth grading, DNSSEC,
// blocklists, tech fingerprinting, OTX passive DNS, urlscan activity.
// All sources are free; OTX needs a free API key (needs-key state otherwise).

import dns from "node:dns/promises";
import tls from "node:tls";
import { checkDnsbl, type DnsblResult } from "./dnsbl";
import { combineDnssec, lookupDnskey, type DnssecResult } from "./dnssec";
import { checkEmailAuth, type EmailAuthResult } from "./email-auth";
import { fetchOtxPassiveDns, type OtxResult } from "./otx";
import { fetchRdap, type RdapResult } from "./rdap";
import { fingerprintTech, type TechResult } from "./tech-fingerprint";
import { fetchUrlscan, type UrlscanResult } from "./urlscan";
import { fetchWayback, type WaybackResult } from "./wayback";

export type {
  DnsblResult,
  DnssecResult,
  EmailAuthResult,
  OtxResult,
  RdapResult,
  TechResult,
  UrlscanResult,
  WaybackResult,
};

export interface DnsResult {
  a: string[];
  aaaa: string[];
  mx: { exchange: string; priority: number }[];
  txt: string[][];
  ns: string[];
  errors: Record<string, string>;
}

export interface TlsResult {
  ok: boolean;
  error?: string;
  subjectCN?: string;
  issuer?: string;
  validFrom?: string;
  validTo?: string;
  daysUntilExpiry?: number;
  authorized?: boolean;
  authorizationError?: string;
}

export interface HeaderCheck {
  name: string;
  present: boolean;
  value: string | null;
  description: string;
}

export interface HeadersResult {
  ok: boolean;
  error?: string;
  url?: string;
  status?: number;
  headers: HeaderCheck[];
  score: number;
  grade: string;
}

export interface SubdomainResult {
  ok: boolean;
  error?: string;
  total: number;
  subdomains: string[];
  truncated: boolean;
}

export interface DomainCheckResult {
  domain: string;
  checkedAt: string;
  dns: DnsResult;
  tls: TlsResult;
  headers: HeadersResult;
  subdomains: SubdomainResult;
  /** Registration data from RDAP (rdap.org bootstrap). */
  rdap: RdapResult;
  /** Wayback Machine history (Internet Archive CDX API). */
  wayback: WaybackResult;
  /** SPF / DMARC / DKIM grading (shared module, also used by email checks). */
  emailAuth: EmailAuthResult;
  /** DNSSEC status (RDAP delegation + DNSKEY records). */
  dnssec: DnssecResult;
  /** DNS blocklists (Spamhaus ZEN + DBL, SpamCop). */
  dnsbl: DnsblResult;
  /** Detected server / CDN / CMS / framework technologies. */
  tech: TechResult;
  /** AlienVault OTX passive DNS (keyed). */
  otx: { available: boolean; result?: OtxResult };
  /** Recent public urlscan.io scans. */
  urlscan: UrlscanResult;
}

const USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

const DNS_TIMEOUT_MS = 5000;
const TLS_TIMEOUT_MS = 5000;
const FETCH_TIMEOUT_MS = 8000;
const CRT_TIMEOUT_MS = 10000;
const SUBDOMAIN_CAP = 100;

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

/** Human-readable DNS error text. Returns null when the error only means
 * "no records of this type" — that is a result, not an error to display. */
export function friendlyDnsError(reason: unknown): string | null {
  if (reason instanceof Error && "code" in reason) {
    switch (reason.code) {
      case "ENOTFOUND":
      case "ENODATA":
        return null;
      case "EREFUSED":
        return "DNS server refused the query";
      case "ESERVFAIL":
        return "DNS lookup failed (server error)";
      case "ETIMEOUT":
        return "DNS lookup timed out";
      case "ECONNREFUSED":
        return "Could not reach the DNS server";
    }
  }
  return reason instanceof Error ? reason.message : "Lookup failed";
}

function friendlyTlsError(err: Error): string {
  const code = "code" in err ? (err as { code?: unknown }).code : undefined;
  if (code === "ENOTFOUND") return "Domain does not resolve";
  if (code === "ECONNREFUSED") return "Connection refused on port 443";
  if (code === "ETIMEDOUT" || code === "ESOCKETTIMEDOUT")
    return "Connection timed out";
  if (code === "EHOSTUNREACH") return "Host unreachable";
  if (err.message.includes("wrong version number")) {
    return "The server did not speak TLS on port 443";
  }
  if (err.message.includes("self-signed certificate")) {
    return "Self-signed certificate";
  }
  return err.message;
}

function recordError(
  errors: Record<string, string>,
  type: string,
  reason: unknown,
): void {
  const message = friendlyDnsError(reason);
  if (message) errors[type] = message;
}

async function resolveDns(domain: string): Promise<DnsResult> {
  const [a, aaaa, mx, txt, ns] = await Promise.allSettled([
    withTimeout(dns.resolve4(domain), DNS_TIMEOUT_MS, "A"),
    withTimeout(dns.resolve6(domain), DNS_TIMEOUT_MS, "AAAA"),
    withTimeout(dns.resolveMx(domain), DNS_TIMEOUT_MS, "MX"),
    withTimeout(dns.resolveTxt(domain), DNS_TIMEOUT_MS, "TXT"),
    withTimeout(dns.resolveNs(domain), DNS_TIMEOUT_MS, "NS"),
  ]);

  const errors: Record<string, string> = {};
  const value = <T>(result: PromiseSettledResult<T>, type: string): T | [] => {
    if (result.status === "fulfilled") return result.value;
    recordError(errors, type, result.reason);
    return [];
  };

  return {
    a: value(a, "A") as string[],
    aaaa: value(aaaa, "AAAA") as string[],
    mx: value(mx, "MX") as { exchange: string; priority: number }[],
    txt: value(txt, "TXT") as string[][],
    ns: value(ns, "NS") as string[],
    errors,
  };
}

function checkTls(domain: string): Promise<TlsResult> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (result: TlsResult) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    const socket = tls.connect(
      {
        host: domain,
        port: 443,
        servername: domain,
        // We want the certificate even when it does not validate, so we can
        // report expiry and issuer; the `authorized` flag reports validity.
        rejectUnauthorized: false,
      },
      () => {
        const cert = socket.getPeerCertificate();
        const authorized = socket.authorized;
        const authError = socket.authorizationError;
        socket.end();
        if (!cert || !cert.valid_to) {
          done({ ok: false, error: "No certificate presented" });
          return;
        }
        const validTo = new Date(cert.valid_to);
        done({
          ok: true,
          subjectCN:
            typeof cert.subject?.CN === "string" ? cert.subject.CN : undefined,
          issuer:
            (typeof cert.issuer?.O === "string" ? cert.issuer.O : undefined) ??
            (typeof cert.issuer?.CN === "string" ? cert.issuer.CN : undefined),
          validFrom: cert.valid_from,
          validTo: cert.valid_to,
          daysUntilExpiry: Math.ceil(
            (validTo.getTime() - Date.now()) / 86_400_000,
          ),
          authorized,
          authorizationError:
            authError instanceof Error ? authError.message : undefined,
        });
      },
    );

    socket.setTimeout(TLS_TIMEOUT_MS, () => {
      socket.destroy();
      done({ ok: false, error: "TLS handshake timed out" });
    });
    socket.on("error", (err) =>
      done({ ok: false, error: friendlyTlsError(err) }),
    );
  });
}

const HEADER_DEFS = [
  {
    key: "strict-transport-security",
    label: "Strict-Transport-Security",
    weight: 20,
    description: "Forces HTTPS (HSTS)",
  },
  {
    key: "content-security-policy",
    label: "Content-Security-Policy",
    weight: 25,
    description: "Restricts which resources the page may load",
  },
  {
    key: "x-frame-options",
    label: "X-Frame-Options",
    weight: 15,
    description: "Blocks clickjacking",
  },
  {
    key: "x-content-type-options",
    label: "X-Content-Type-Options",
    weight: 15,
    description: "Prevents MIME sniffing",
  },
  {
    key: "referrer-policy",
    label: "Referrer-Policy",
    weight: 10,
    description: "Controls referrer leakage",
  },
  {
    key: "permissions-policy",
    label: "Permissions-Policy",
    weight: 10,
    description: "Restricts browser features",
  },
  {
    key: "cross-origin-opener-policy",
    label: "Cross-Origin-Opener-Policy",
    weight: 5,
    description: "Isolates the browsing context",
  },
] as const;

function gradeFor(score: number): string {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

async function checkHeaders(domain: string): Promise<HeadersResult> {
  for (const scheme of ["https", "http"] as const) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
      const res = await fetch(`${scheme}://${domain}/`, {
        method: "GET",
        redirect: "follow",
        signal: controller.signal,
        headers: { "User-Agent": USER_AGENT },
      });
      // Headers are all we need; stop the body download.
      await res.body?.cancel().catch(() => undefined);
      const headers: HeaderCheck[] = HEADER_DEFS.map((def) => {
        const value = res.headers.get(def.key);
        return {
          name: def.label,
          present: value !== null,
          value,
          description: def.description,
        };
      });
      const score = HEADER_DEFS.reduce(
        (acc, def, i) => acc + (headers[i].present ? def.weight : 0),
        0,
      );
      return {
        ok: true,
        url: res.url,
        status: res.status,
        headers,
        score,
        grade: gradeFor(score),
      };
    } catch {
      // Fall through to the next scheme.
    } finally {
      clearTimeout(timer);
    }
  }
  return {
    ok: false,
    error: "Could not reach the site over HTTP or HTTPS",
    headers: [],
    score: 0,
    grade: "F",
  };
}

async function checkSubdomains(domain: string): Promise<SubdomainResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CRT_TIMEOUT_MS);
  try {
    const res = await fetch(
      `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`,
      { headers: { "User-Agent": USER_AGENT }, signal: controller.signal },
    );
    if (!res.ok) {
      return {
        ok: false,
        error: `crt.sh responded with HTTP ${res.status}`,
        total: 0,
        subdomains: [],
        truncated: false,
      };
    }
    const data = (await res.json()) as { name_value?: string }[];
    const names = new Set<string>();
    for (const row of data) {
      for (const part of (row.name_value ?? "").split("\n")) {
        const name = part.trim().toLowerCase();
        if (!name) continue;
        if (name === domain || name.endsWith(`.${domain}`)) names.add(name);
      }
    }
    const all = [...names].sort();
    return {
      ok: true,
      total: all.length,
      subdomains: all.slice(0, SUBDOMAIN_CAP),
      truncated: all.length > SUBDOMAIN_CAP,
    };
  } catch (err) {
    return {
      ok: false,
      error:
        err instanceof Error && err.name === "AbortError"
          ? "crt.sh request timed out"
          : "Could not reach crt.sh",
      total: 0,
      subdomains: [],
      truncated: false,
    };
  } finally {
    clearTimeout(timer);
  }
}

export async function checkDomain(
  domain: string,
  opts: { otxApiKey?: string } = {},
): Promise<DomainCheckResult> {
  // DNS runs first: the blocklist check needs the domain's A records.
  const dnsResult = await resolveDns(domain);

  const [
    tlsResult,
    headersResult,
    subdomainResult,
    rdapResult,
    dnskeyPresent,
    waybackResult,
    emailAuthResult,
    dnsblResult,
    techResult,
    otx,
    urlscanResult,
  ] = await Promise.all([
    checkTls(domain),
    checkHeaders(domain),
    checkSubdomains(domain),
    fetchRdap(domain),
    lookupDnskey(domain),
    fetchWayback(domain),
    checkEmailAuth(domain),
    checkDnsbl(domain, dnsResult.a),
    fingerprintTech(domain),
    (async (): Promise<{ available: boolean; result?: OtxResult }> => {
      if (!opts.otxApiKey) return { available: false };
      return {
        available: true,
        result: await fetchOtxPassiveDns(domain, opts.otxApiKey),
      };
    })(),
    fetchUrlscan(domain),
  ]);

  return {
    domain,
    checkedAt: new Date().toISOString(),
    dns: dnsResult,
    tls: tlsResult,
    headers: headersResult,
    subdomains: subdomainResult,
    rdap: rdapResult,
    wayback: waybackResult,
    emailAuth: emailAuthResult,
    dnssec: combineDnssec(rdapResult.delegationSigned, dnskeyPresent),
    dnsbl: dnsblResult,
    tech: techResult,
    otx,
    urlscan: urlscanResult,
  };
}
