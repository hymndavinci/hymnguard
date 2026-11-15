// urlscan.io search API (free, no key for search).
// Counts public scans submitted for the domain in the last 30 days
// (urlscan's unauthenticated search window) and links the most recent one.
// Scan verdicts live behind the result-detail endpoint, which requires a
// login — so this source reports scan activity only, never verdicts.

const URLSCAN_TIMEOUT_MS = 10000;

export interface UrlscanResult {
  ok: boolean;
  error?: string;
  /** Public scans submitted for this domain in the last 30 days. */
  total: number;
  /** True when urlscan capped the count at 10,000 (the real total is higher). */
  totalCapped?: boolean;
  latestScanAt?: string;
  latestScanUrl?: string;
  /** Link to the urlscan search for this domain. */
  searchUrl: string;
}

export async function fetchUrlscan(domain: string): Promise<UrlscanResult> {
  const searchUrl = `https://urlscan.io/search/#task.domain%3A${encodeURIComponent(domain)}`;
  return fetchUrlscanQuery(
    `task.domain:${domain}`,
    searchUrl,
    "urlscan.io responded with HTTP",
  );
}

/** Shared search-query runner: urlscan's unauthenticated search API
 * (30-day window, totals capped at 10,000). */
async function fetchUrlscanQuery(
  query: string,
  searchUrl: string,
  httpErrorPrefix: string,
): Promise<UrlscanResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), URLSCAN_TIMEOUT_MS);
  try {
    const res = await fetch(
      `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(query)}`,
      { signal: controller.signal },
    );
    if (res.status === 429) {
      return {
        ok: false,
        error: "urlscan.io is rate-limiting searches right now.",
        total: 0,
        searchUrl,
      };
    }
    if (!res.ok) {
      return {
        ok: false,
        error: `${httpErrorPrefix} ${res.status}`,
        total: 0,
        searchUrl,
      };
    }
    const data = (await res.json()) as {
      total?: number;
      results?: { task?: { time?: string; uuid?: string } }[];
    };
    const latest = data.results?.[0]?.task;
    const total = typeof data.total === "number" ? data.total : 0;
    return {
      ok: true,
      total,
      // urlscan caps unauthenticated search totals at 10,000.
      totalCapped: total >= 10000,
      latestScanAt: latest?.time,
      latestScanUrl: latest?.uuid
        ? `https://urlscan.io/result/${latest.uuid}/`
        : undefined,
      searchUrl,
    };
  } catch (err) {
    return {
      ok: false,
      error:
        err instanceof Error && err.name === "AbortError"
          ? "urlscan.io request timed out"
          : "Could not reach urlscan.io",
      total: 0,
      searchUrl,
    };
  } finally {
    clearTimeout(timer);
  }
}

/** Public scans in the last 30 days where a file with this hash was
 * downloaded. Verified live 2026-11-15: the EICAR test hash returns
 * scans, an all-zero hash returns none. */
export async function fetchUrlscanForHash(hash: string): Promise<UrlscanResult> {
  const searchUrl = `https://urlscan.io/search/#hash%3A${encodeURIComponent(hash)}`;
  return fetchUrlscanQuery(
    `hash:${hash}`,
    searchUrl,
    "urlscan.io responded with HTTP",
  );
}

/** Public scans of this exact URL in the last 30 days. Verified live
 * 2026-11-15: https://example.com/ returns scans, a never-scanned URL
 * returns none. */
export async function fetchUrlscanForUrl(url: string): Promise<UrlscanResult> {
  const searchUrl = `https://urlscan.io/search/#page.url%3A%22${encodeURIComponent(url)}%22`;
  return fetchUrlscanQuery(
    `page.url:"${url}"`,
    searchUrl,
    "urlscan.io responded with HTTP",
  );
}
