// AlienVault OTX passive DNS (keyed — OTX_API_KEY, free tier).
// Returns hostnames historically resolved for the domain: a second,
// independent subdomain source next to crt.sh.
// Implemented from the public OTX API docs; not yet tested live — no key
// has been available. Without a key the route reports a needs-key state.

const OTX_TIMEOUT_MS = 10000;
const HOSTNAME_CAP = 100;

export interface OtxResult {
  ok: boolean;
  error?: string;
  rateLimited?: boolean;
  total: number;
  hostnames: string[];
  truncated: boolean;
}

export async function fetchOtxPassiveDns(
  domain: string,
  apiKey: string,
): Promise<OtxResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), OTX_TIMEOUT_MS);
  try {
    const res = await fetch(
      `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/passive_dns`,
      {
        headers: { "X-OTX-API-KEY": apiKey },
        signal: controller.signal,
      },
    );
    if (res.status === 401 || res.status === 403) {
      return {
        ok: false,
        error: "OTX rejected the API key.",
        total: 0,
        hostnames: [],
        truncated: false,
      };
    }
    if (res.status === 429) {
      return {
        ok: false,
        error: "OTX rate limit reached.",
        rateLimited: true,
        total: 0,
        hostnames: [],
        truncated: false,
      };
    }
    if (!res.ok) {
      return {
        ok: false,
        error: `OTX responded with HTTP ${res.status}`,
        total: 0,
        hostnames: [],
        truncated: false,
      };
    }
    const data = (await res.json()) as {
      passive_dns?: { hostname?: string }[];
    };
    const names = new Set<string>();
    for (const row of data.passive_dns ?? []) {
      const name = (row.hostname ?? "").trim().toLowerCase();
      if (!name) continue;
      if (name === domain || name.endsWith(`.${domain}`)) names.add(name);
    }
    const all = [...names].sort();
    return {
      ok: true,
      total: all.length,
      hostnames: all.slice(0, HOSTNAME_CAP),
      truncated: all.length > HOSTNAME_CAP,
    };
  } catch (err) {
    return {
      ok: false,
      error:
        err instanceof Error && err.name === "AbortError"
          ? "OTX request timed out"
          : "Could not reach OTX",
      total: 0,
      hostnames: [],
      truncated: false,
    };
  } finally {
    clearTimeout(timer);
  }
}

export interface OtxFileResult {
  ok: boolean;
  error?: string;
  rateLimited?: boolean;
  /** True when OTX has no pulses referencing this hash (not an error). */
  notFound?: boolean;
  /** Threat-intel pulses referencing this file hash. */
  pulseCount: number;
  /** Names of the top pulses (capped). */
  pulses: string[];
}

const PULSE_CAP = 5;

/** OTX file indicator (keyed — reuses OTX_API_KEY). Counts threat-intel
 * pulses referencing the file hash. Implemented from the public OTX API
 * docs; not yet tested live — no key has been available. */
export async function fetchOtxFile(
  hash: string,
  apiKey: string,
): Promise<OtxFileResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), OTX_TIMEOUT_MS);
  try {
    const res = await fetch(
      `https://otx.alienvault.com/api/v1/indicators/file/${encodeURIComponent(hash)}/general`,
      {
        headers: { "X-OTX-API-KEY": apiKey },
        signal: controller.signal,
      },
    );
    if (res.status === 401 || res.status === 403) {
      return {
        ok: false,
        error: "OTX rejected the API key.",
        pulseCount: 0,
        pulses: [],
      };
    }
    if (res.status === 429) {
      return {
        ok: false,
        error: "OTX rate limit reached.",
        rateLimited: true,
        pulseCount: 0,
        pulses: [],
      };
    }
    if (res.status === 404) {
      return { ok: true, notFound: true, pulseCount: 0, pulses: [] };
    }
    if (!res.ok) {
      return {
        ok: false,
        error: `OTX responded with HTTP ${res.status}`,
        pulseCount: 0,
        pulses: [],
      };
    }
    const data = (await res.json()) as {
      pulse_info?: {
        count?: number;
        pulses?: { name?: string }[];
      };
    };
    const pulses = (data.pulse_info?.pulses ?? [])
      .map((p) => (p.name ?? "").trim())
      .filter(Boolean)
      .slice(0, PULSE_CAP);
    return {
      ok: true,
      pulseCount:
        typeof data.pulse_info?.count === "number"
          ? data.pulse_info.count
          : pulses.length,
      pulses,
    };
  } catch (err) {
    return {
      ok: false,
      error:
        err instanceof Error && err.name === "AbortError"
          ? "OTX request timed out"
          : "Could not reach OTX",
      pulseCount: 0,
      pulses: [],
    };
  } finally {
    clearTimeout(timer);
  }
}
