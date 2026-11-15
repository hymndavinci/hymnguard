// URL reputation: VirusTotal URL report, Google Safe Browsing, and
// urlscan.io scan activity. Only the URL string is sent to reputation
// APIs — HymnGuard never fetches the URL itself (no SSRF surface).
//
// Free source (verified live 2026-11-15, known-positive + control):
// - urlscan.io — public scans of the exact URL in the last 30 days.
//   https://example.com/ returns scans; a never-scanned URL returns none.
//
// Keyed sources (implemented from the public docs; not yet tested live —
// no keys have been available):
// - VirusTotal v3 — engine verdicts for previously scanned URLs. A URL
//   VirusTotal has never seen reports "not previously scanned", not
//   "clean". Free tier: 500 req/day, 4/min.
// - Google Safe Browsing v4 — MALWARE / SOCIAL_ENGINEERING /
//   UNWANTED_SOFTWARE / POTENTIALLY_HARMFUL_APPLICATION lists.
//   Free tier: 10,000 req/day. Google's own test URL
//   (http://malware.testing.google.test/testing/malware/) always matches.

import { fetchUrlscanForUrl, type UrlscanResult } from "./urlscan";

const API_TIMEOUT_MS = 10000;

export interface VirusTotalUrlResult {
  ok: boolean;
  error?: string;
  rateLimited?: boolean;
  /** True when VirusTotal has never scanned the URL (not an error). */
  notFound?: boolean;
  malicious?: number;
  suspicious?: number;
  undetected?: number;
  harmless?: number;
  timeout?: number;
  lastAnalysisDate?: number;
}

export interface SafeBrowsingMatch {
  threatType: string;
  platformType: string;
}

export interface SafeBrowsingResult {
  ok: boolean;
  error?: string;
  rateLimited?: boolean;
  matches: SafeBrowsingMatch[];
}

export interface UrlCheckResult {
  url: string;
  checkedAt: string;
  /** urlscan.io scan activity (free, no key). */
  urlscan: UrlscanResult;
  /** VirusTotal URL report (keyed). */
  virustotal: { available: boolean; result?: VirusTotalUrlResult };
  /** Google Safe Browsing (keyed). */
  safebrowsing: { available: boolean; result?: SafeBrowsingResult };
}

/** VirusTotal identifies a URL by its base64url encoding, no padding. */
function virusTotalUrlId(url: string): string {
  return Buffer.from(url, "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export async function fetchVirusTotalUrl(
  url: string,
  apiKey: string,
): Promise<VirusTotalUrlResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), API_TIMEOUT_MS);
  try {
    const res = await fetch(
      `https://www.virustotal.com/api/v3/urls/${virusTotalUrlId(url)}`,
      { headers: { "x-apikey": apiKey }, signal: controller.signal },
    );
    if (res.status === 401 || res.status === 403) {
      return { ok: false, error: "VirusTotal rejected the API key." };
    }
    if (res.status === 429) {
      return {
        ok: false,
        error: "VirusTotal rate limit reached (free tier: 4/min, 500/day).",
        rateLimited: true,
      };
    }
    if (res.status === 404) {
      return { ok: true, notFound: true };
    }
    if (!res.ok) {
      return {
        ok: false,
        error: `VirusTotal responded with HTTP ${res.status}`,
      };
    }
    const data = (await res.json()) as {
      data?: { attributes?: Record<string, unknown> };
    };
    const attrs = data.data?.attributes ?? {};
    const stats = (attrs.last_analysis_stats ?? {}) as Record<string, unknown>;
    const num = (obj: Record<string, unknown>, key: string): number | undefined =>
      typeof obj[key] === "number" ? (obj[key] as number) : undefined;
    return {
      ok: true,
      malicious: num(stats, "malicious"),
      suspicious: num(stats, "suspicious"),
      undetected: num(stats, "undetected"),
      harmless: num(stats, "harmless"),
      timeout: num(stats, "timeout"),
      lastAnalysisDate: num(attrs, "last_analysis_date"),
    };
  } catch (err) {
    return {
      ok: false,
      error:
        err instanceof Error && err.name === "AbortError"
          ? "VirusTotal request timed out"
          : "Could not reach VirusTotal",
    };
  } finally {
    clearTimeout(timer);
  }
}

export async function fetchSafeBrowsing(
  url: string,
  apiKey: string,
): Promise<SafeBrowsingResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), API_TIMEOUT_MS);
  try {
    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "hymnguard", clientVersion: "1.0.0" },
          threatInfo: {
            threatTypes: [
              "MALWARE",
              "SOCIAL_ENGINEERING",
              "UNWANTED_SOFTWARE",
              "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url }],
          },
        }),
        signal: controller.signal,
      },
    );
    if (res.status === 400) {
      return {
        ok: false,
        error: "Safe Browsing rejected the request (check the API key).",
        matches: [],
      };
    }
    if (res.status === 403) {
      return {
        ok: false,
        error: "Safe Browsing rejected the API key.",
        matches: [],
      };
    }
    if (res.status === 429) {
      return {
        ok: false,
        error: "Safe Browsing rate limit reached.",
        rateLimited: true,
        matches: [],
      };
    }
    if (!res.ok) {
      return {
        ok: false,
        error: `Safe Browsing responded with HTTP ${res.status}`,
        matches: [],
      };
    }
    const data = (await res.json()) as {
      matches?: {
        threatType?: string;
        platformType?: string;
      }[];
    };
    return {
      ok: true,
      matches: (data.matches ?? []).map((m) => ({
        threatType: m.threatType ?? "UNKNOWN",
        platformType: m.platformType ?? "UNKNOWN",
      })),
    };
  } catch (err) {
    return {
      ok: false,
      error:
        err instanceof Error && err.name === "AbortError"
          ? "Safe Browsing request timed out"
          : "Could not reach Safe Browsing",
      matches: [],
    };
  } finally {
    clearTimeout(timer);
  }
}

export async function checkUrl(
  url: string,
  opts: { virusTotalKey?: string; safeBrowsingKey?: string } = {},
): Promise<UrlCheckResult> {
  const [urlscan, virustotal, safebrowsing] = await Promise.all([
    fetchUrlscanForUrl(url),
    (async (): Promise<{
      available: boolean;
      result?: VirusTotalUrlResult;
    }> => {
      if (!opts.virusTotalKey) return { available: false };
      return {
        available: true,
        result: await fetchVirusTotalUrl(url, opts.virusTotalKey),
      };
    })(),
    (async (): Promise<{
      available: boolean;
      result?: SafeBrowsingResult;
    }> => {
      if (!opts.safeBrowsingKey) return { available: false };
      return {
        available: true,
        result: await fetchSafeBrowsing(url, opts.safeBrowsingKey),
      };
    })(),
  ]);

  return {
    url,
    checkedAt: new Date().toISOString(),
    urlscan,
    virustotal,
    safebrowsing,
  };
}
