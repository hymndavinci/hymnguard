// IPQualityScore Phone Number Validation API (keyed).
// Docs: https://www.ipqualityscore.com/documentation/phone-number-validation-api/overview
// Endpoint: GET https://www.ipqualityscore.com/api/json/phone/{API_KEY}/{PHONE}
//   Optional params: country[] (ISO code), strictness (0|1), fast=true.
// Free tier: sign up for a free API key at ipqualityscore.com (phone
// validation free tier reported at 1,000 lookups/month).
//
// Implemented from the public docs; NOT tested live — no key has been
// available (same precedent as OTX / AbuseIPDB / OsintCat).
//
// Privacy: IPQS can return an owner name and associated email addresses.
// Those fields are deliberately NOT read or surfaced — HymnGuard shows
// carrier, line type, and risk signals only, never identity data.

const IPQS_TIMEOUT_MS = 8000;

export interface IpqsPhoneResult {
  ok: boolean;
  error?: string;
  rateLimited?: boolean;
  /** IPQS's own validity verdict (format + carrier assignment). */
  valid?: boolean;
  /** 0–100 fraud score. 85+ is high risk per IPQS guidance. */
  fraudScore?: number;
  recentAbuse?: boolean;
  /** Flagged as a spammer by IPQS. */
  spammer?: boolean;
  /** Number appeared in a known data leak (boolean only, no contents). */
  leaked?: boolean;
  active?: boolean;
  activeStatus?: string;
  carrier?: string;
  lineType?: string;
  voip?: boolean;
  prepaid?: boolean;
  risky?: boolean;
  country?: string;
  region?: string;
  city?: string;
}

function asBool(v: unknown): boolean | undefined {
  return typeof v === "boolean" ? v : undefined;
}

function asNum(v: unknown): number | undefined {
  return typeof v === "number" ? v : undefined;
}

function asStr(v: unknown): string | undefined {
  return typeof v === "string" && v !== "" && v !== "N/A" ? v : undefined;
}

export async function fetchIpqsPhone(
  e164: string,
  apiKey: string,
  countryCode?: string,
): Promise<IpqsPhoneResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), IPQS_TIMEOUT_MS);
  try {
    const params = new URLSearchParams({ strictness: "0", fast: "true" });
    if (countryCode) params.append("country[]", countryCode);
    const url =
      `https://www.ipqualityscore.com/api/json/phone/${encodeURIComponent(apiKey)}/${encodeURIComponent(e164)}` +
      `?${params.toString()}`;
    const res = await fetch(url, { signal: controller.signal });
    if (res.status === 401 || res.status === 403) {
      return { ok: false, error: "IPQS rejected the API key." };
    }
    if (res.status === 429) {
      return {
        ok: false,
        error: "IPQS rate limit reached.",
        rateLimited: true,
      };
    }
    if (!res.ok) {
      return { ok: false, error: `IPQS responded with HTTP ${res.status}` };
    }
    const data = (await res.json()) as Record<string, unknown>;
    if (data.success === false) {
      const message =
        typeof data.message === "string" ? data.message : "Lookup failed";
      const exhausted = /insufficient credits/i.test(message);
      return {
        ok: false,
        error: exhausted
          ? "IPQS credit balance is used up."
          : message,
        rateLimited: exhausted ? true : undefined,
      };
    }
    return {
      ok: true,
      valid: asBool(data.valid),
      fraudScore: asNum(data.fraud_score),
      recentAbuse: asBool(data.recent_abuse),
      spammer: asBool(data.spammer),
      leaked: asBool(data.leaked),
      active: asBool(data.active),
      activeStatus: asStr(data.active_status),
      carrier: asStr(data.carrier),
      lineType: asStr(data.line_type),
      voip: asBool(data.VOIP),
      prepaid: asBool(data.prepaid),
      risky: asBool(data.risky),
      country: asStr(data.country),
      region: asStr(data.region),
      city: asStr(data.city),
    };
  } catch (err) {
    return {
      ok: false,
      error:
        err instanceof Error && err.name === "AbortError"
          ? "IPQS request timed out"
          : "Could not reach IPQS",
    };
  } finally {
    clearTimeout(timer);
  }
}
