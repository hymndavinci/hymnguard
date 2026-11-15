// Have I Been Pwned clients.
//
// Pwned Passwords (free, no key): k-anonymity range API. The caller sends
// only the first 5 hex characters of the SHA-1 hash; the full hash and the
// password itself must never reach this server.
//
// Breached Account (paid key): breach metadata only. The HIBP API never
// returns breach contents, and this module passes through metadata fields
// only (name, date, data classes, counts).

const USER_AGENT = "HymnGuard";
const FETCH_TIMEOUT_MS = 8000;

export interface PwnedRangeEntry {
  suffix: string;
  count: number;
}

export async function fetchPwnedRange(
  prefix: string,
): Promise<PwnedRangeEntry[]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(
      `https://api.pwnedpasswords.com/range/${prefix}`,
      {
        headers: { "User-Agent": USER_AGENT, "Add-Padding": "true" },
        signal: controller.signal,
      },
    );
    if (!res.ok) {
      throw new Error(`HIBP responded with HTTP ${res.status}`);
    }
    const text = await res.text();
    const entries: PwnedRangeEntry[] = [];
    for (const line of text.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const [suffix, count] = trimmed.split(":");
      if (!suffix || count === undefined) continue;
      entries.push({ suffix, count: Number.parseInt(count, 10) || 0 });
    }
    return entries;
  } finally {
    clearTimeout(timer);
  }
}

export interface HibpBreachMeta {
  name: string;
  title: string;
  domain: string | null;
  breachDate: string;
  pwnCount: number;
  dataClasses: string[];
  isVerified: boolean;
  isSensitive: boolean;
}

type HibpBreachResponse = {
  Name: string;
  Title: string;
  Domain: string | null;
  BreachDate: string;
  PwnCount: number;
  DataClasses: string[];
  IsVerified: boolean;
  IsSensitive: boolean;
};

export type BreachLookupResult =
  | { status: "ok"; breaches: HibpBreachMeta[] }
  | { status: "rate_limited" };

export async function fetchBreachesForEmail(
  email: string,
  apiKey: string,
): Promise<BreachLookupResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(
      `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,
      {
        headers: {
          "hibp-api-key": apiKey,
          "User-Agent": USER_AGENT,
        },
        signal: controller.signal,
      },
    );

    // 404 means the account appears in no known breach.
    if (res.status === 404) return { status: "ok", breaches: [] };
    if (res.status === 429) return { status: "rate_limited" };
    if (!res.ok) {
      throw new Error(`HIBP responded with HTTP ${res.status}`);
    }

    const data = (await res.json()) as HibpBreachResponse[];
    return {
      status: "ok",
      breaches: data.map((b) => ({
        name: b.Name,
        title: b.Title,
        domain: b.Domain,
        breachDate: b.BreachDate,
        pwnCount: b.PwnCount,
        dataClasses: b.DataClasses,
        isVerified: b.IsVerified,
        isSensitive: b.IsSensitive,
      })),
    };
  } finally {
    clearTimeout(timer);
  }
}
