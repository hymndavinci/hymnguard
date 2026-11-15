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
