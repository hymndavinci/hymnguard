// IP address checks: geolocation + ASN (ip-api.com, free, no key),
// reputation (AbuseIPDB, keyed), VPN/proxy/hosting signals (ip-api),
// Tor exit-node status (dan.me.uk DNS exit list, free, no key), and
// reverse DNS. Passive data only — no port scanning, no probing.
// Private/reserved IPs are rejected by the validator before this runs.

import dns from "node:dns/promises";

const IP_API_TIMEOUT_MS = 6000;
const ABUSEIPDB_TIMEOUT_MS = 8000;
const DNS_TIMEOUT_MS = 4000;

export interface IpGeoResult {
  ok: boolean;
  error?: string;
  country?: string;
  countryCode?: string;
  region?: string;
  city?: string;
  zip?: string;
  lat?: number;
  lon?: number;
  timezone?: string;
  isp?: string;
  org?: string;
  as?: string;
  asname?: string;
  reverse?: string;
  /** ip-api's own flags: datacenter/VPN-like infrastructure. */
  mobile?: boolean;
  proxy?: boolean;
  hosting?: boolean;
}

export interface AbuseIpDbResult {
  ok: boolean;
  error?: string;
  rateLimited?: boolean;
  /** 0–100; higher means more confident the IP is abusive. */
  abuseConfidenceScore?: number;
  totalReports?: number;
  lastReportedAt?: string;
  countryCode?: string;
  isp?: string;
  domain?: string;
  isTor?: boolean;
  isWhitelisted?: boolean;
}

export interface TorResult {
  /** True = exit node, false = not an exit node, null = could not check. */
  isExitNode: boolean | null;
  error?: string;
}

export interface IpCheckResult {
  ip: string;
  checkedAt: string;
  geo: IpGeoResult;
  /** Reverse DNS (PTR). Null when the IP has no PTR record. */
  ptr: string | null;
  ptrError?: string;
  tor: TorResult;
  /** AbuseIPDB reputation (keyed). */
  abuseipdb: { available: boolean; result?: AbuseIpDbResult };
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

async function fetchGeo(ip: string): Promise<IpGeoResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), IP_API_TIMEOUT_MS);
  try {
    // ip-api.com's free tier is HTTP-only (HTTPS needs the pro plan).
    const res = await fetch(
      `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query`,
      { signal: controller.signal },
    );
    if (!res.ok) {
      return { ok: false, error: `ip-api.com responded with HTTP ${res.status}` };
    }
    const data = (await res.json()) as Record<string, unknown>;
    if (data.status !== "success") {
      const message =
        typeof data.message === "string" ? data.message : "Lookup failed";
      return {
        ok: false,
        error:
          message === "rate limited"
            ? "ip-api.com is rate-limiting lookups right now."
            : message,
      };
    }
    const str = (key: string): string | undefined =>
      typeof data[key] === "string" ? (data[key] as string) : undefined;
    const num = (key: string): number | undefined =>
      typeof data[key] === "number" ? (data[key] as number) : undefined;
    const bool = (key: string): boolean | undefined =>
      typeof data[key] === "boolean" ? (data[key] as boolean) : undefined;
    return {
      ok: true,
      country: str("country"),
      countryCode: str("countryCode"),
      region: str("regionName"),
      city: str("city"),
      zip: str("zip"),
      lat: num("lat"),
      lon: num("lon"),
      timezone: str("timezone"),
      isp: str("isp"),
      org: str("org"),
      as: str("as"),
      asname: str("asname"),
      reverse: str("reverse"),
      mobile: bool("mobile"),
      proxy: bool("proxy"),
      hosting: bool("hosting"),
    };
  } catch (err) {
    return {
      ok: false,
      error:
        err instanceof Error && err.name === "AbortError"
          ? "ip-api.com request timed out"
          : "Could not reach ip-api.com",
    };
  } finally {
    clearTimeout(timer);
  }
}

export async function fetchAbuseIpDb(
  ip: string,
  apiKey: string,
): Promise<AbuseIpDbResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ABUSEIPDB_TIMEOUT_MS);
  try {
    const res = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`,
      { headers: { Key: apiKey, Accept: "application/json" }, signal: controller.signal },
    );
    if (res.status === 401) {
      return { ok: false, error: "AbuseIPDB rejected the API key." };
    }
    if (res.status === 429) {
      return {
        ok: false,
        error: "AbuseIPDB daily allowance is used up.",
        rateLimited: true,
      };
    }
    if (!res.ok) {
      return {
        ok: false,
        error: `AbuseIPDB responded with HTTP ${res.status}`,
      };
    }
    const data = (await res.json()) as {
      data?: Record<string, unknown>;
    };
    const d = data.data ?? {};
    const num = (key: string): number | undefined =>
      typeof d[key] === "number" ? (d[key] as number) : undefined;
    const str = (key: string): string | undefined =>
      typeof d[key] === "string" ? (d[key] as string) : undefined;
    const bool = (key: string): boolean | undefined =>
      typeof d[key] === "boolean" ? (d[key] as boolean) : undefined;
    return {
      ok: true,
      abuseConfidenceScore: num("abuseConfidenceScore"),
      totalReports: num("totalReports"),
      lastReportedAt: str("lastReportedAt") ?? undefined,
      countryCode: str("countryCode"),
      isp: str("isp"),
      domain: str("domain"),
      isTor: bool("isTor"),
      isWhitelisted: bool("isWhitelisted"),
    };
  } catch (err) {
    return {
      ok: false,
      error:
        err instanceof Error && err.name === "AbortError"
          ? "AbuseIPDB request timed out"
          : "Could not reach AbuseIPDB",
    };
  } finally {
    clearTimeout(timer);
  }
}

function reverseIpv4(ip: string): string | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  if (parts.some((p) => !/^\d{1,3}$/.test(p) || Number(p) > 255)) return null;
  return [...parts].reverse().join(".");
}

/** Tor exit-node check via the dan.me.uk DNS exit list (IPv4 only).
 * 127.0.0.100 = exit node; NXDOMAIN = not an exit node. */
async function checkTor(ip: string): Promise<TorResult> {
  const reversed = reverseIpv4(ip);
  if (!reversed) {
    return {
      isExitNode: null,
      error: "Tor exit-node check only supports IPv4 addresses.",
    };
  }
  try {
    const answers = await withTimeout(
      dns.resolve4(`${reversed}.tor.dan.me.uk`),
      DNS_TIMEOUT_MS,
      "Tor exit list",
    );
    return { isExitNode: answers.includes("127.0.0.100") };
  } catch (err) {
    const code = err instanceof Error && "code" in err ? err.code : undefined;
    if (code === "ENOTFOUND" || code === "ENODATA") {
      return { isExitNode: false };
    }
    return { isExitNode: null, error: "Tor exit-node lookup failed." };
  }
}

async function reverseDns(
  ip: string,
): Promise<{ ptr: string | null; error?: string }> {
  try {
    const names = await withTimeout(
      dns.reverse(ip),
      DNS_TIMEOUT_MS,
      "Reverse DNS",
    );
    return { ptr: names[0] ?? null };
  } catch (err) {
    const code = err instanceof Error && "code" in err ? err.code : undefined;
    if (code === "ENOTFOUND" || code === "ENODATA") {
      return { ptr: null };
    }
    return { ptr: null, error: "Reverse DNS lookup failed." };
  }
}

export async function checkIp(
  ip: string,
  opts: { abuseIpDbKey?: string } = {},
): Promise<IpCheckResult> {
  const [geo, ptrResult, tor, abuseipdb] = await Promise.all([
    fetchGeo(ip),
    reverseDns(ip),
    checkTor(ip),
    (async (): Promise<{
      available: boolean;
      result?: AbuseIpDbResult;
    }> => {
      if (!opts.abuseIpDbKey) return { available: false };
      return {
        available: true,
        result: await fetchAbuseIpDb(ip, opts.abuseIpDbKey),
      };
    })(),
  ]);

  return {
    ip,
    checkedAt: new Date().toISOString(),
    geo,
    ptr: ptrResult.ptr,
    ptrError: ptrResult.error,
    tor,
    abuseipdb,
  };
}
