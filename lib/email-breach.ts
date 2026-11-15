// Breach and infostealer sources beyond HIBP.
//
// Metadata only, always: breach/source names, dates, and data categories.
// Leaked passwords, hashes, tokens, or any other breach contents are never
// requested, stored, or displayed.
//
// Confidence labels (shown in the UI):
//   HIBP       — gold standard (verified, curated breach corpus)
//   LeakCheck  — aggregator (large index, includes stealer logs)
//   OsintCat   — aggregator (keyed, untested without a key)
//   Hudson Rock — infostealer-specific (malware infection records)

const USER_AGENT = "HymnGuard";
const FETCH_TIMEOUT_MS = 8000;

// ---------------------------------------------------------------- LeakCheck
// Public API: GET https://leakcheck.io/api/public?check={email}
// Free, no key, 1 req/sec. Requires a "Powered by LeakCheck" attribution
// link on the website (rendered in the UI next to these results).

export interface LeakCheckSource {
  name: string;
  date: string;
}

export type LeakCheckResult =
  | {
      status: "ok";
      found: number;
      fields: string[];
      sources: LeakCheckSource[];
    }
  | { status: "not_found" }
  | { status: "error"; error: string };

export async function fetchLeakCheck(email: string): Promise<LeakCheckResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(
      `https://leakcheck.io/api/public?check=${encodeURIComponent(email)}`,
      { headers: { "User-Agent": USER_AGENT }, signal: controller.signal },
    );
    if (!res.ok) {
      return { status: "error", error: `LeakCheck responded with HTTP ${res.status}` };
    }
    const data = (await res.json()) as {
      success?: boolean;
      error?: string;
      found?: number;
      fields?: string[];
      sources?: { name?: string; date?: string }[];
    };
    if (!data.success) {
      if (data.error === "Not found") return { status: "not_found" };
      return {
        status: "error",
        error: data.error ? `LeakCheck: ${data.error}` : "LeakCheck returned an error",
      };
    }
    return {
      status: "ok",
      found: typeof data.found === "number" ? data.found : 0,
      fields: Array.isArray(data.fields) ? data.fields : [],
      sources: Array.isArray(data.sources)
        ? data.sources
            .filter((s) => typeof s.name === "string")
            .map((s) => ({ name: s.name as string, date: s.date ?? "" }))
        : [],
    };
  } catch (err) {
    return {
      status: "error",
      error:
        err instanceof Error && err.name === "AbortError"
          ? "LeakCheck request timed out"
          : "Could not reach LeakCheck",
    };
  } finally {
    clearTimeout(timer);
  }
}

// ----------------------------------------------------------------- OsintCat
// Breach Lookup: GET https://www.osintcat.net/api/breach?query={email}&type=email
// Header: X-API-KEY. Keyed source — the caller checks for OSINTCAT_API_KEY
// first and reports a needs-key state when unset.
//
// NOTE: implemented from the public docs (docs.osintcat.net) and NOT yet
// tested live — no key is available. Parsing is defensive: only source_db
// names and the count are extracted; passwords, hashes, IPs and every other
// PII field in breach_data are dropped. A shape mismatch surfaces as an
// error, never as "not found".

export interface OsintCatSource {
  name: string;
  count: number;
}

export type OsintCatResult =
  | { status: "ok"; sources: OsintCatSource[]; total: number }
  | { status: "not_found" }
  | { status: "rate_limited" }
  | { status: "error"; error: string };

export async function fetchOsintCat(
  email: string,
  apiKey: string,
): Promise<OsintCatResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(
      `https://www.osintcat.net/api/breach?query=${encodeURIComponent(email)}&type=email`,
      {
        headers: { "X-API-KEY": apiKey, "User-Agent": USER_AGENT },
        signal: controller.signal,
      },
    );
    if (res.status === 429) return { status: "rate_limited" };
    if (res.status === 402) {
      return { status: "error", error: "OsintCat balance insufficient" };
    }
    if (res.status === 403) {
      return {
        status: "error",
        error: "OsintCat key rejected or plan does not include breach lookup",
      };
    }
    if (res.status === 424) {
      return { status: "error", error: "OsintCat upstream source failed" };
    }
    if (!res.ok) {
      return { status: "error", error: `OsintCat responded with HTTP ${res.status}` };
    }
    const data = (await res.json()) as {
      breach_data?: { source_db?: string }[];
      results_count?: number;
    };
    if (!Array.isArray(data.breach_data)) {
      return { status: "error", error: "OsintCat returned an unexpected response shape" };
    }
    if (data.breach_data.length === 0) return { status: "not_found" };
    const bySource = new Map<string, number>();
    for (const record of data.breach_data) {
      const name =
        typeof record.source_db === "string" && record.source_db
          ? record.source_db
          : "Unknown source";
      bySource.set(name, (bySource.get(name) ?? 0) + 1);
    }
    const sources = [...bySource.entries()]
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 20);
    return {
      status: "ok",
      sources,
      total:
        typeof data.results_count === "number"
          ? data.results_count
          : data.breach_data.length,
    };
  } catch (err) {
    return {
      status: "error",
      error:
        err instanceof Error && err.name === "AbortError"
          ? "OsintCat request timed out"
          : "Could not reach OsintCat",
    };
  } finally {
    clearTimeout(timer);
  }
}

// -------------------------------------------------------------- Hudson Rock
// Cavalier free API: GET
// https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=...
// Free, no key, ~1 req/sec/IP. Checks whether the email is tied to a
// computer infected by an info-stealing malware.
//
// NEVER surfaced: top_passwords, top_logins, ip (even masked), malware_path.
// Only infection metadata: dates, machine name, OS, antivirus products,
// and how many corporate/user services were compromised.

export interface HudsonRockStealer {
  dateCompromised?: string;
  computerName?: string;
  operatingSystem?: string;
  antiviruses?: string[];
  totalCorporateServices: number;
  totalUserServices: number;
}

export type HudsonRockResult =
  | {
      status: "ok";
      associated: boolean;
      stealers: HudsonRockStealer[];
    }
  | { status: "error"; error: string };

export async function fetchHudsonRock(email: string): Promise<HudsonRockResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(
      `https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=${encodeURIComponent(email)}`,
      { headers: { "User-Agent": USER_AGENT }, signal: controller.signal },
    );
    if (!res.ok) {
      return {
        status: "error",
        error: `Hudson Rock responded with HTTP ${res.status}`,
      };
    }
    const data = (await res.json()) as {
      stealers?: {
        date_compromised?: string;
        computer_name?: string;
        operating_system?: string;
        antiviruses?: string[];
        total_corporate_services?: number;
        total_user_services?: number;
      }[];
    };
    if (!Array.isArray(data.stealers)) {
      return {
        status: "error",
        error: "Hudson Rock returned an unexpected response shape",
      };
    }
    const stealers: HudsonRockStealer[] = data.stealers.map((s) => ({
      ...(typeof s.date_compromised === "string"
        ? { dateCompromised: s.date_compromised }
        : {}),
      ...(typeof s.computer_name === "string"
        ? { computerName: s.computer_name }
        : {}),
      ...(typeof s.operating_system === "string"
        ? { operatingSystem: s.operating_system }
        : {}),
      ...(Array.isArray(s.antiviruses)
        ? { antiviruses: s.antiviruses.filter((a) => typeof a === "string") }
        : {}),
      totalCorporateServices:
        typeof s.total_corporate_services === "number"
          ? s.total_corporate_services
          : 0,
      totalUserServices:
        typeof s.total_user_services === "number" ? s.total_user_services : 0,
    }));
    return { status: "ok", associated: stealers.length > 0, stealers };
  } catch (err) {
    return {
      status: "error",
      error:
        err instanceof Error && err.name === "AbortError"
          ? "Hudson Rock request timed out"
          : "Could not reach Hudson Rock",
    };
  } finally {
    clearTimeout(timer);
  }
}
