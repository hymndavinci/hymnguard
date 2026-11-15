// Strict input validation for every check route.
// Each normalizer returns the cleaned value or null when invalid.
// Nothing here logs or stores the input.

import net from "node:net";

const DOMAIN_RE =
  /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/;

export function normalizeDomain(input: unknown): string | null {
  if (typeof input !== "string") return null;
  let value = input.trim().toLowerCase();
  if (!value) return null;

  // Tolerate a pasted URL: strip scheme, path, query, fragment, port.
  value = value.replace(/^https?:\/\//, "");
  value = value.split("/")[0].split("?")[0].split("#")[0].split(":")[0];
  if (value.endsWith(".")) value = value.slice(0, -1);

  if (value === "localhost") return null;
  if (!DOMAIN_RE.test(value)) return null;
  return value;
}

export function normalizeEmail(input: unknown): string | null {
  if (typeof input !== "string") return null;
  const value = input.trim().toLowerCase();
  if (value.length < 3 || value.length > 254) return null;
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(value)) return null;
  return value;
}

export function normalizeUsername(input: unknown): string | null {
  if (typeof input !== "string") return null;
  let value = input.trim();
  if (value.startsWith("@")) value = value.slice(1);
  if (value.length < 1 || value.length > 50) return null;
  if (!/^[a-zA-Z0-9._-]+$/.test(value)) return null;
  if (
    value.startsWith(".") ||
    value.startsWith("-") ||
    value.endsWith(".") ||
    value.includes("..")
  ) {
    return null;
  }
  return value;
}

export function normalizePhone(input: unknown): string | null {
  if (typeof input !== "string") return null;
  const value = input.trim();
  if (!value.startsWith("+")) return null;
  if (value.length < 8 || value.length > 20) return null;
  if (!/^\+[0-9 ]+$/.test(value)) return null;
  return value.replace(/ /g, "");
}

export function isValidPasswordPrefix(input: unknown): input is string {
  return typeof input === "string" && /^[0-9a-fA-F]{5}$/.test(input);
}

/** IPv4 ranges that are not publicly checkable (private, loopback,
 * link-local, CGNAT, documentation, benchmarking, multicast, reserved). */
const IPV4_PRIVATE: [number, number][] = [
  [0x00000000, 0x00ffffff], // 0.0.0.0/8 ("this network")
  [0x0a000000, 0x0affffff], // 10.0.0.0/8
  [0x64400000, 0x647fffff], // 100.64.0.0/10 CGNAT
  [0x7f000000, 0x7fffffff], // 127.0.0.0/8 loopback
  [0xa9fe0000, 0xa9feffff], // 169.254.0.0/16 link-local
  [0xac100000, 0xac1fffff], // 172.16.0.0/12
  [0xc0000000, 0xc00000ff], // 192.0.0.0/24 IANA special
  [0xc0000200, 0xc00002ff], // 192.0.2.0/24 TEST-NET-1
  [0xc0a80000, 0xc0a8ffff], // 192.168.0.0/16
  [0xc6120000, 0xc613ffff], // 198.18.0.0/15 benchmarking
  [0xc6336400, 0xc63364ff], // 198.51.100.0/24 TEST-NET-2
  [0xcb007100, 0xcb0071ff], // 203.0.113.0/24 TEST-NET-3
  [0xe0000000, 0xefffffff], // 224.0.0.0/4 multicast
  [0xf0000000, 0xffffffff], // 240.0.0.0/4 reserved + broadcast
];

function ipv4ToInt(ip: string): number {
  return ip
    .split(".")
    .reduce((acc, part) => (acc << 8) + Number(part), 0) >>> 0;
}

/** Expand an IPv6 address to 8 groups of 4 hex digits for prefix checks. */
function expandIpv6(ip: string): string | null {
  const [head, tail] = ip.split("::");
  if (tail === undefined) {
    const groups = ip.split(":");
    if (groups.length !== 8) return null;
    return groups.map((g) => g.padStart(4, "0")).join(":");
  }
  const headGroups = head ? head.split(":") : [];
  const tailGroups = tail ? tail.split(":") : [];
  if (headGroups.length + tailGroups.length > 7) return null;
  const missing = 8 - headGroups.length - tailGroups.length;
  const groups = [
    ...headGroups,
    ...Array<string>(missing).fill("0"),
    ...tailGroups,
  ];
  return groups.map((g) => g.padStart(4, "0")).join(":");
}

function isPrivateIpv6(expanded: string): boolean {
  const first = expanded.slice(0, 4);
  // ::1, :: (unspecified), fe80::/10 link-local, fc00::/7 unique-local,
  // ff00::/8 multicast, 2001:db8::/32 documentation.
  if (expanded === "0000:0000:0000:0000:0000:0000:0000:0001") return true;
  if (expanded === "0000:0000:0000:0000:0000:0000:0000:0000") return true;
  if (/^fe[89ab]/.test(first)) return true;
  if (/^f[c-d]/.test(first)) return true;
  if (first.startsWith("ff")) return true;
  if (expanded.startsWith("2001:0db8:")) return true;
  return false;
}

/** Accepts a public IPv4 or IPv6 address; rejects private, reserved,
 * loopback, and other non-public ranges (public sources have nothing to
 * say about them). Returns the cleaned address or null. */
export function normalizeIp(input: unknown): string | null {
  if (typeof input !== "string") return null;
  const value = input.trim().toLowerCase();
  if (!value) return null;
  const version = net.isIP(value);
  if (version === 4) {
    const num = ipv4ToInt(value);
    if (IPV4_PRIVATE.some(([lo, hi]) => num >= lo && num <= hi)) return null;
    return value;
  }
  if (version === 6) {
    // Reject IPv4-mapped IPv6 (::ffff:1.2.3.4) — check the v4 form instead.
    if (value.includes(".")) return null;
    const expanded = expandIpv6(value);
    if (!expanded) return null;
    if (isPrivateIpv6(expanded)) return null;
    return value;
  }
  return null;
}

export function isValidPasswordSuffix(input: unknown): input is string {
  return typeof input === "string" && /^[0-9a-fA-F]{35}$/.test(input);
}
