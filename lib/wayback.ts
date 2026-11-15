// Wayback Machine (Internet Archive CDX API, free, no key).
// First snapshot of the homepage + snapshot count. The count comes from the
// CDX index page count (15,000 records per page): exact when the domain has
// few snapshots, approximate above that.

const CDX_BASE = "https://web.archive.org/cdx/search/cdx";
const CDX_TIMEOUT_MS = 8000;
const BLOCK_SIZE = 15000;
const EXACT_COUNT_LIMIT = 500;

export interface WaybackResult {
  ok: boolean;
  error?: string;
  /** ISO timestamp of the earliest capture, if any. */
  firstSnapshotAt?: string;
  /** Original URL of the earliest capture. */
  firstSnapshotUrl?: string;
  firstSnapshotStatus?: number;
  /** Number of captures. Approximate when totalApproximate is true. */
  totalSnapshots?: number;
  totalApproximate?: boolean;
}

async function fetchCdx(
  params: Record<string, string>,
): Promise<unknown> {
  const url = new URL(CDX_BASE);
  for (const [key, value] of Object.entries(params)) {
    url.searchParams.set(key, value);
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CDX_TIMEOUT_MS);
  try {
    const res = await fetch(url.toString(), { signal: controller.signal });
    if (!res.ok) throw new Error(`Wayback responded with HTTP ${res.status}`);
    return (await res.json()) as unknown;
  } finally {
    clearTimeout(timer);
  }
}

/** CDX timestamps look like 20020120142510 — convert to ISO. */
function cdxToIso(timestamp: string): string | undefined {
  if (!/^\d{14}$/.test(timestamp)) return undefined;
  const iso = `${timestamp.slice(0, 4)}-${timestamp.slice(4, 6)}-${timestamp.slice(6, 8)}T${timestamp.slice(8, 10)}:${timestamp.slice(10, 12)}:${timestamp.slice(12, 14)}Z`;
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

export async function fetchWayback(domain: string): Promise<WaybackResult> {
  // First capture + page count in parallel. The sample query only runs
  // when the page count says the total is small — for large domains the
  // count is approximate anyway, so fetching a sample would waste a
  // request and add peak concurrency. The two queries are settled
  // independently: the CDX API blocks data queries for some domains
  // (gmail.com returns 403) while still answering the page count, so a
  // failed first-capture query must not discard a usable count.
  const [firstSettled, pagesSettled] = await Promise.allSettled([
    // Earliest capture of the homepage (any status code).
    fetchCdx({
      url: domain,
      output: "json",
      fl: "timestamp,original,statuscode",
      limit: "1",
    }),
    // Index page count (15,000 records per page).
    fetchCdx({ url: domain, output: "json", showNumPages: "true" }),
  ]);

  if (firstSettled.status === "rejected" && pagesSettled.status === "rejected") {
    return { ok: false, error: describeError(firstSettled.reason) };
  }

  const result: WaybackResult = { ok: true };
  let firstRow: string[] | undefined;
  if (firstSettled.status === "fulfilled") {
    const firstRows = firstSettled.value as string[][];
    firstRow = firstRows[1]; // Row 0 is the header.
    if (firstRow) {
      result.firstSnapshotAt = cdxToIso(firstRow[0]);
      result.firstSnapshotUrl = firstRow[1];
      const status = Number(firstRow[2]);
      if (Number.isFinite(status)) result.firstSnapshotStatus = status;
    }
  }

  if (pagesSettled.status === "fulfilled") {
    const pageRows = pagesSettled.value as string[][];
    const numPages = Number(pageRows[1]?.[0] ?? 0);
    if (Number.isFinite(numPages) && numPages > 1) {
      result.totalSnapshots = numPages * BLOCK_SIZE;
      result.totalApproximate = true;
    } else if (Number.isFinite(numPages) && numPages === 1) {
      // One page or less: fetch a sample for an exact count.
      try {
        const sample = await fetchCdx({
          url: domain,
          output: "json",
          fl: "timestamp",
          limit: String(EXACT_COUNT_LIMIT),
        });
        const sampleRows = sample as string[][];
        // Sample rows include the header row; subtract it.
        const sampleCount = Math.max(0, sampleRows.length - 1);
        if (sampleCount < EXACT_COUNT_LIMIT) {
          result.totalSnapshots = sampleCount;
          result.totalApproximate = false;
        } else {
          // The sample hit its cap: at least the cap.
          result.totalSnapshots = EXACT_COUNT_LIMIT;
          result.totalApproximate = true;
        }
      } catch {
        // Count stays unknown; the first snapshot (if any) is still shown.
      }
    } else if (!firstRow) {
      result.totalSnapshots = 0;
      result.totalApproximate = false;
    }
  }
  return result;
}

function describeError(err: unknown): string {
  return err instanceof Error && err.name === "AbortError"
    ? "Wayback Machine request timed out"
    : err instanceof Error
      ? err.message
      : "Could not reach the Wayback Machine";
}
