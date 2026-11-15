// File hash reputation: MD5 / SHA-1 / SHA-256 lookups across six sources.
// Only the hash is ever sent — never a file. "Not found" in a source means
// that source has no record of the hash; it is not a clean verdict, and
// the UI says so.
//
// Free sources (verified live 2026-11-15, known-positive + control):
// - CIRCL hashlookup — known-file corpus (NSRL et al.), incl. a
//   KnownMalicious flag. Empty-file hash and the EICAR test hash return
//   records; a random hash returns 404.
// - urlscan.io — public scans where a file with this hash was downloaded.
//   The EICAR hash returns scans; an all-zero hash returns none.
//
// Keyed sources (implemented from the public docs; not yet tested live —
// no keys have been available):
// - VirusTotal v3 — 70+ engine verdicts (free tier: 500 req/day, 4/min).
// - MalwareBazaar — abuse.ch sample database. NOTE: since 2025 the
//   Community API requires a free Auth-Key (auth.abuse.ch), sent as the
//   `Auth-Key` header; it is no longer keyless.
// - Hybrid Analysis v2 — Falcon Sandbox verdicts (free Public API key).
// - AlienVault OTX file indicator — threat-intel pulses (reuses OTX key).

import { fetchOtxFile, type OtxFileResult } from "./otx";
import { fetchUrlscanForHash, type UrlscanResult } from "./urlscan";
import type { HashAlgorithm } from "./validate";

const API_TIMEOUT_MS = 10000;

export interface CirclResult {
  ok: boolean;
  error?: string;
  /** True when CIRCL has no record of the hash (not an error). */
  notFound?: boolean;
  fileName?: string;
  fileSize?: string;
  /** Present when CIRCL flags the file as known malicious. */
  knownMalicious?: string;
  productName?: string;
  /** The file's other hashes, when CIRCL returns them. */
  md5?: string;
  sha1?: string;
  sha256?: string;
}

export interface VirusTotalFileResult {
  ok: boolean;
  error?: string;
  rateLimited?: boolean;
  /** True when VirusTotal has never seen the hash (not an error). */
  notFound?: boolean;
  malicious?: number;
  suspicious?: number;
  undetected?: number;
  harmless?: number;
  timeout?: number;
  meaningfulName?: string;
  typeDescription?: string;
  firstSeen?: number;
  lastAnalysisDate?: number;
}

export interface MalwareBazaarResult {
  ok: boolean;
  error?: string;
  /** True when MalwareBazaar has no record of the hash (not an error). */
  notFound?: boolean;
  signature?: string;
  fileName?: string;
  fileType?: string;
  fileSize?: number;
  firstSeen?: string;
  tags: string[];
}

export interface HybridAnalysisResult {
  ok: boolean;
  error?: string;
  rateLimited?: boolean;
  /** True when Hybrid Analysis has no report for the hash (not an error). */
  notFound?: boolean;
  /** 0–100 threat score of the worst matching report. */
  threatScore?: number;
  verdict?: string;
  vxFamily?: string;
  submitName?: string;
  reportCount: number;
}

export interface HashCheckResult {
  hash: string;
  algorithm: HashAlgorithm;
  checkedAt: string;
  /** CIRCL hashlookup (free, no key). */
  circl: CirclResult;
  /** urlscan.io hash search (free, no key). */
  urlscan: UrlscanResult;
  /** VirusTotal file report (keyed). */
  virustotal: { available: boolean; result?: VirusTotalFileResult };
  /** MalwareBazaar sample lookup (keyed). */
  malwarebazaar: { available: boolean; result?: MalwareBazaarResult };
  /** Hybrid Analysis verdict (keyed). */
  hybridanalysis: { available: boolean; result?: HybridAnalysisResult };
  /** OTX threat-intel pulses (keyed, reuses OTX key). */
  otx: { available: boolean; result?: OtxFileResult };
}

async function fetchCircl(
  hash: string,
  algorithm: HashAlgorithm,
): Promise<CirclResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), API_TIMEOUT_MS);
  try {
    const res = await fetch(
      `https://hashlookup.circl.lu/lookup/${algorithm}/${encodeURIComponent(hash)}`,
      { signal: controller.signal },
    );
    if (res.status === 404) {
      return { ok: true, notFound: true };
    }
    if (!res.ok) {
      return {
        ok: false,
        error: `CIRCL hashlookup responded with HTTP ${res.status}`,
      };
    }
    const data = (await res.json()) as Record<string, unknown>;
    const str = (key: string): string | undefined =>
      typeof data[key] === "string" ? (data[key] as string) : undefined;
    const product = data.ProductCode as Record<string, unknown> | undefined;
    return {
      ok: true,
      fileName: str("FileName"),
      fileSize: str("FileSize"),
      knownMalicious: str("KnownMalicious"),
      productName:
        typeof product?.ProductName === "string"
          ? product.ProductName
          : undefined,
      md5: str("MD5"),
      sha1: str("SHA-1"),
      sha256: str("SHA-256"),
    };
  } catch (err) {
    return {
      ok: false,
      error:
        err instanceof Error && err.name === "AbortError"
          ? "CIRCL hashlookup request timed out"
          : "Could not reach CIRCL hashlookup",
    };
  } finally {
    clearTimeout(timer);
  }
}

export async function fetchVirusTotalFile(
  hash: string,
  apiKey: string,
): Promise<VirusTotalFileResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), API_TIMEOUT_MS);
  try {
    const res = await fetch(
      `https://www.virustotal.com/api/v3/files/${encodeURIComponent(hash)}`,
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
    const str = (key: string): string | undefined =>
      typeof attrs[key] === "string" ? (attrs[key] as string) : undefined;
    return {
      ok: true,
      malicious: num(stats, "malicious"),
      suspicious: num(stats, "suspicious"),
      undetected: num(stats, "undetected"),
      harmless: num(stats, "harmless"),
      timeout: num(stats, "timeout"),
      meaningfulName: str("meaningful_name"),
      typeDescription: str("type_description"),
      firstSeen: num(attrs, "first_submission_date"),
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

export async function fetchMalwareBazaar(
  hash: string,
  apiKey: string,
): Promise<MalwareBazaarResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), API_TIMEOUT_MS);
  try {
    const res = await fetch("https://mb-api.abuse.ch/api/v1/", {
      method: "POST",
      headers: {
        "Auth-Key": apiKey,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: `query=get_info&hash=${encodeURIComponent(hash)}`,
      signal: controller.signal,
    });
    if (!res.ok) {
      return {
        ok: false,
        error: `MalwareBazaar responded with HTTP ${res.status}`,
        tags: [],
      };
    }
    const data = (await res.json()) as {
      query_status?: string;
      data?: Record<string, unknown>[];
    };
    if (data.query_status === "hash_not_found") {
      return { ok: true, notFound: true, tags: [] };
    }
    if (data.query_status === "no_api_key" || data.query_status === "user_blacklisted") {
      return {
        ok: false,
        error: "MalwareBazaar rejected the Auth-Key.",
        tags: [],
      };
    }
    if (data.query_status !== "ok" || !data.data?.[0]) {
      return {
        ok: false,
        error: `MalwareBazaar returned an unexpected status (${data.query_status ?? "unknown"}).`,
        tags: [],
      };
    }
    const row = data.data[0];
    const str = (key: string): string | undefined =>
      typeof row[key] === "string" ? (row[key] as string) : undefined;
    const tags = Array.isArray(row.tags)
      ? (row.tags as unknown[]).filter((t): t is string => typeof t === "string").slice(0, 5)
      : [];
    return {
      ok: true,
      signature: str("signature"),
      fileName: str("file_name"),
      fileType: str("file_type"),
      fileSize: typeof row.file_size === "number" ? row.file_size : undefined,
      firstSeen: str("first_seen"),
      tags,
    };
  } catch (err) {
    return {
      ok: false,
      error:
        err instanceof Error && err.name === "AbortError"
          ? "MalwareBazaar request timed out"
          : "Could not reach MalwareBazaar",
      tags: [],
    };
  } finally {
    clearTimeout(timer);
  }
}

export async function fetchHybridAnalysis(
  hash: string,
  apiKey: string,
): Promise<HybridAnalysisResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), API_TIMEOUT_MS);
  try {
    const res = await fetch("https://www.hybrid-analysis.com/api/v2/search/hash", {
      method: "POST",
      headers: {
        "api-key": apiKey,
        "User-Agent": "HymnGuard/1.0",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: `hash=${encodeURIComponent(hash)}`,
      signal: controller.signal,
    });
    if (res.status === 401 || res.status === 403) {
      return {
        ok: false,
        error: "Hybrid Analysis rejected the API key.",
        reportCount: 0,
      };
    }
    if (res.status === 429) {
      return {
        ok: false,
        error: "Hybrid Analysis rate limit reached.",
        rateLimited: true,
        reportCount: 0,
      };
    }
    if (!res.ok) {
      return {
        ok: false,
        error: `Hybrid Analysis responded with HTTP ${res.status}`,
        reportCount: 0,
      };
    }
    const data = (await res.json()) as unknown;
    const reports = Array.isArray(data)
      ? (data as Record<string, unknown>[])
      : [];
    if (reports.length === 0) {
      return { ok: true, notFound: true, reportCount: 0 };
    }
    // Show the worst report (highest threat score).
    const worst = reports.reduce((best, row) => {
      const score = typeof row.threat_score === "number" ? row.threat_score : 0;
      const bestScore =
        typeof best.threat_score === "number" ? best.threat_score : 0;
      return score > bestScore ? row : best;
    }, reports[0]);
    const str = (key: string): string | undefined =>
      typeof worst[key] === "string" ? (worst[key] as string) : undefined;
    return {
      ok: true,
      threatScore:
        typeof worst.threat_score === "number" ? worst.threat_score : undefined,
      verdict: str("verdict"),
      vxFamily: str("vx_family"),
      submitName: str("submit_name"),
      reportCount: reports.length,
    };
  } catch (err) {
    return {
      ok: false,
      error:
        err instanceof Error && err.name === "AbortError"
          ? "Hybrid Analysis request timed out"
          : "Could not reach Hybrid Analysis",
      reportCount: 0,
    };
  } finally {
    clearTimeout(timer);
  }
}

export async function checkHash(
  hash: string,
  algorithm: HashAlgorithm,
  opts: {
    virusTotalKey?: string;
    malwareBazaarKey?: string;
    hybridAnalysisKey?: string;
    otxKey?: string;
  } = {},
): Promise<HashCheckResult> {
  const [circl, urlscan, virustotal, malwarebazaar, hybridanalysis, otx] =
    await Promise.all([
      fetchCircl(hash, algorithm),
      fetchUrlscanForHash(hash),
      (async (): Promise<{
        available: boolean;
        result?: VirusTotalFileResult;
      }> => {
        if (!opts.virusTotalKey) return { available: false };
        return {
          available: true,
          result: await fetchVirusTotalFile(hash, opts.virusTotalKey),
        };
      })(),
      (async (): Promise<{
        available: boolean;
        result?: MalwareBazaarResult;
      }> => {
        if (!opts.malwareBazaarKey) return { available: false };
        return {
          available: true,
          result: await fetchMalwareBazaar(hash, opts.malwareBazaarKey),
        };
      })(),
      (async (): Promise<{
        available: boolean;
        result?: HybridAnalysisResult;
      }> => {
        if (!opts.hybridAnalysisKey) return { available: false };
        return {
          available: true,
          result: await fetchHybridAnalysis(hash, opts.hybridAnalysisKey),
        };
      })(),
      (async (): Promise<{ available: boolean; result?: OtxFileResult }> => {
        if (!opts.otxKey) return { available: false };
        return {
          available: true,
          result: await fetchOtxFile(hash, opts.otxKey),
        };
      })(),
    ]);

  return {
    hash,
    algorithm,
    checkedAt: new Date().toISOString(),
    circl,
    urlscan,
    virustotal,
    malwarebazaar,
    hybridanalysis,
    otx,
  };
}
