// Checker registry (Phase 5 plugin architecture).
//
// Each checker declares its metadata in one place: label, input hints,
// API route, sources (name, cost, key, confidence), and cache TTL.
// New identifier types (Phase 6) plug in by adding one entry here plus
// their route and result component.
//
// Client-safe: pure data, no server imports. The console derives its tabs
// from CHECKERS; the cache and key-resolution helpers read the TTLs and
// key requirements from here.

import type { CheckType } from "./history";

export type KeyProvider =
  | "hibp"
  | "osintcat"
  | "github"
  | "otx"
  | "abuseipdb"
  | "ipqs";

export interface KeyProviderMeta {
  id: KeyProvider;
  label: string;
  envVar: string;
  /** Where a user gets their own key. */
  where: string;
}

export const KEY_PROVIDERS: KeyProviderMeta[] = [
  {
    id: "hibp",
    label: "Have I Been Pwned",
    envVar: "HIBP_API_KEY",
    where: "haveibeenpwned.com/API/Key (paid, from $4/mo)",
  },
  {
    id: "osintcat",
    label: "OsintCat",
    envVar: "OSINTCAT_API_KEY",
    where: "osintcat.net (free tier on sign-up)",
  },
  {
    id: "github",
    label: "GitHub",
    envVar: "GITHUB_TOKEN",
    where: "github.com/settings/tokens (no scopes needed)",
  },
  {
    id: "otx",
    label: "AlienVault OTX",
    envVar: "OTX_API_KEY",
    where: "otx.alienvault.com (free, on your profile page)",
  },
  {
    id: "abuseipdb",
    label: "AbuseIPDB",
    envVar: "ABUSEIPDB_API_KEY",
    where: "abuseipdb.com (free tier, 1,000 checks/day)",
  },
  {
    id: "ipqs",
    label: "IPQualityScore",
    envVar: "IPQS_API_KEY",
    where: "ipqualityscore.com (free tier, 1,000 lookups/mo)",
  },
];

export function isKeyProvider(value: string): value is KeyProvider {
  return KEY_PROVIDERS.some((p) => p.id === value);
}

export interface SourceDef {
  name: string;
  cost: "free" | "keyed";
  key?: KeyProvider;
  /** How much the result can be trusted (see README for the labels). */
  confidence: "high" | "medium" | "low";
}

export interface CheckerDef {
  id: CheckType;
  label: string;
  placeholder: string;
  hint: string;
  privacy: string;
  route: string;
  sources: SourceDef[];
  /** Route-level cache TTL in seconds. 0 = never cached. */
  cacheTtlSec: number;
  /** Chunked (multi-request) check — the console streams partial results. */
  chunked?: boolean;
}

export const CHECKERS: CheckerDef[] = [
  {
    id: "email",
    label: "Email",
    placeholder: "you@example.com",
    hint: "Mail records, breach lookups, email authentication, infostealer exposure, and optional account enumeration after ownership verification.",
    privacy: "Checked and discarded — never stored.",
    route: "/api/check/email",
    cacheTtlSec: 3600,
    sources: [
      { name: "MX records", cost: "free", confidence: "high" },
      { name: "SPF / DKIM / DMARC", cost: "free", confidence: "high" },
      { name: "LeakCheck", cost: "free", confidence: "medium" },
      { name: "Hudson Rock", cost: "free", confidence: "medium" },
      { name: "Have I Been Pwned", cost: "keyed", key: "hibp", confidence: "high" },
      { name: "OsintCat", cost: "keyed", key: "osintcat", confidence: "medium" },
      { name: "GitHub commits", cost: "keyed", key: "github", confidence: "high" },
      { name: "Account enumeration", cost: "free", confidence: "medium" },
    ],
  },
  {
    id: "username",
    label: "Username",
    placeholder: "username",
    hint: "Probed across 256 sites, in chunks — results stream in as each chunk finishes.",
    privacy: "Checked and discarded — never stored.",
    route: "/api/check/username",
    cacheTtlSec: 0,
    chunked: true,
    sources: [
      { name: "Live probing (256 sites)", cost: "free", confidence: "medium" },
    ],
  },
  {
    id: "domain",
    label: "Domain",
    placeholder: "example.com",
    hint: "DNS records, TLS certificate, security headers, subdomains, registration, email authentication, blocklists, and more.",
    privacy: "Checked and discarded — never stored.",
    route: "/api/check/domain",
    cacheTtlSec: 21600,
    sources: [
      { name: "DNS records", cost: "free", confidence: "high" },
      { name: "TLS certificate", cost: "free", confidence: "high" },
      { name: "Security headers", cost: "free", confidence: "high" },
      { name: "crt.sh subdomains", cost: "free", confidence: "high" },
      { name: "RDAP registration", cost: "free", confidence: "high" },
      { name: "Wayback Machine", cost: "free", confidence: "high" },
      { name: "DNSSEC", cost: "free", confidence: "high" },
      { name: "DNSBL blocklists", cost: "free", confidence: "medium" },
      { name: "Tech fingerprint", cost: "free", confidence: "medium" },
      { name: "AlienVault OTX", cost: "keyed", key: "otx", confidence: "high" },
      { name: "urlscan.io", cost: "free", confidence: "medium" },
    ],
  },
  {
    id: "ip",
    label: "IP",
    placeholder: "8.8.8.8",
    hint: "Location, network, reputation, and VPN/proxy/Tor signals. Public IPs only.",
    privacy: "Checked and discarded — never stored.",
    route: "/api/check/ip",
    cacheTtlSec: 86400,
    sources: [
      { name: "ip-api.com", cost: "free", confidence: "high" },
      { name: "Tor exit list", cost: "free", confidence: "high" },
      { name: "AbuseIPDB", cost: "keyed", key: "abuseipdb", confidence: "high" },
    ],
  },
  {
    id: "phone",
    label: "Phone",
    placeholder: "+6281234567890",
    hint: "Format, carrier, and community spam reports. Not a breach lookup.",
    privacy: "Checked and discarded — never stored.",
    route: "/api/check/phone",
    cacheTtlSec: 86400,
    sources: [
      { name: "libphonenumber", cost: "free", confidence: "high" },
      { name: "ID prefix table", cost: "free", confidence: "high" },
      { name: "IPQualityScore", cost: "keyed", key: "ipqs", confidence: "high" },
      { name: "GetContact", cost: "free", confidence: "medium" },
      { name: "Should I Answer", cost: "free", confidence: "medium" },
    ],
  },
  {
    id: "password",
    label: "Password",
    placeholder: "Enter a password to check",
    hint: "Checked against Have I Been Pwned with k-anonymity.",
    privacy: "Hashed in your browser. Only the first 5 characters of the hash leave this page.",
    route: "/api/check/password",
    cacheTtlSec: 0,
    sources: [
      { name: "HIBP Pwned Passwords", cost: "free", confidence: "high" },
    ],
  },
];

export function getChecker(id: string): CheckerDef | undefined {
  return CHECKERS.find((c) => c.id === id);
}
