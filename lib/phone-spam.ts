// Community spam / scam reports for phone numbers. Best-effort, public
// data only — both sources are read from their public web pages, one fetch
// per check, and both allow general crawling in robots.txt (GetContact
// only opts out AI *training* crawlers from /number-lookup/).
//
// Only AGGREGATE signals are extracted (report counts, risk level,
// community verdict). Name tags, comment text, and anything identifying
// the number's owner are never read or shown.
//
// Sources (verified live 2026-11-15, both directions):
// - GetContact (getcontact.com) — community reports, strong in Indonesia.
//   HTTP 200 = number in their database, stat cards parsed from the page.
//   HTTP 404 = number not in their database = no reports on GetContact.
//   Verified: +62 817 7636 3485 (610 reports, High risk, Negative) vs
//   +62 812 3456 7890 (404, not in database).
// - Should I Answer (shouldianswer.com) — NANP (+1) numbers only.
//   Rating comes from the page's schema.org AggregateRating JSON-LD.
//   Verified: 1-800-555-1234 (rating 1, 5 reviews) and 1-800-555-0000
//   (rating 1, 7 reviews) vs 1-212-555-0147 (no rating data).
//   The Indonesian subdomain (id.shouldianswer.net) is deliberately NOT
//   used: its database is empty — numbers with 600+ GetContact reports
//   show 0 reviews there, so it would only produce false "no reports".
//
// Excluded (verified): tellows (403 bot-block from server networks),
// whocalld (unreachable), spamcalls.net (redirects unknown numbers to a
// sample page — unreliable signal), Truecaller (account/login required).

const USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
const FETCH_TIMEOUT_MS = 8000;
const MAX_BODY_BYTES = 1_000_000;

export interface GetContactResult {
  ok: boolean;
  error?: string;
  /** False when GetContact returns 404 (number not in their database). */
  inDatabase: boolean;
  /** User reports on GetContact. */
  reports?: number;
  totalCalls?: number;
  risk?: string;
  feedback?: string;
  /** GetContact marks the number as blocked. */
  blocked?: boolean;
  region?: string;
  url: string;
}

export interface ShouldIAnswerResult {
  ok: boolean;
  error?: string;
  /** Only NANP (+1) numbers are covered. */
  covered: boolean;
  /** Community reviews on Should I Answer. */
  reports?: number;
  /** Mean community rating, 1 (negative) to 5 (positive). */
  rating?: number;
  url?: string;
}

/** Read a response body with a byte cap. Null when over the cap. */
async function readCapped(res: Response): Promise<string | null> {
  const reader = res.body?.getReader();
  if (!reader) return null;
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel().catch(() => undefined);
      return null;
    }
    chunks.push(value);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.length;
  }
  return new TextDecoder().decode(merged);
}

function parseCount(raw: string): number | undefined {
  const n = Number(raw.replace(/[.,\s]/g, ""));
  return Number.isFinite(n) ? n : undefined;
}

function normalizeRisk(raw: string): string {
  const v = raw.trim().toLowerCase();
  if (v.includes("tinggi") || v.includes("high")) return "High risk";
  if (v.includes("sedang") || v.includes("medium")) return "Medium risk";
  if (v.includes("rendah") || v.includes("low")) return "Low risk";
  return raw.trim();
}

function normalizeFeedback(raw: string): string {
  const v = raw.trim().toLowerCase();
  if (v.includes("negatif") || v.includes("negative")) return "Negative";
  if (v.includes("positif") || v.includes("positive")) return "Positive";
  if (v.includes("netral") || v.includes("neutral")) return "Neutral";
  return raw.trim();
}

/** Stat card: <p>VALUE</p><p>LABEL</p> (GetContact renders value first). */
function statCard(html: string, labels: string[]): string | undefined {
  for (const label of labels) {
    const m = html.match(
      new RegExp(
        `<p[^>]*>([^<]{1,40})</p>\\s*<p[^>]*>${label}</p>`,
        "i",
      ),
    );
    if (m) return m[1].trim();
  }
  return undefined;
}

/** Labeled row: LABEL</p><p>VALUE</p> (risk, feedback, status rows). */
function labeledValue(html: string, labels: string[]): string | undefined {
  for (const label of labels) {
    const m = html.match(
      new RegExp(`${label}</p>\\s*<p[^>]*>([^<]{1,40})</p>`, "i"),
    );
    if (m) return m[1].trim();
  }
  return undefined;
}

export async function fetchGetContact(
  e164: string,
  countryCode: string | undefined,
): Promise<GetContactResult> {
  const digits = e164.replace(/^\+/, "");
  const cc = (countryCode ?? "id").toLowerCase();
  const url = `https://getcontact.com/number-lookup/${cc}/p/${digits}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      headers: { "User-Agent": USER_AGENT },
      signal: controller.signal,
      redirect: "follow",
    });
    if (res.status === 404) {
      return { ok: true, inDatabase: false, url };
    }
    if (res.status === 403 || res.status === 429) {
      return {
        ok: false,
        inDatabase: false,
        error: "GetContact is blocking automated checks right now.",
        url,
      };
    }
    if (!res.ok) {
      return {
        ok: false,
        inDatabase: false,
        error: `GetContact responded with HTTP ${res.status}`,
        url,
      };
    }
    const html = await readCapped(res);
    if (html === null) {
      return {
        ok: false,
        inDatabase: false,
        error: "GetContact's response was too large to read.",
        url,
      };
    }
    const reportsRaw = statCard(html, ["LAPORAN PENGGUNA", "USER REPORTS"]);
    const callsRaw = statCard(html, ["TOTAL PANGGILAN", "TOTAL CALLS"]);
    const region = statCard(html, ["REGION"]);
    const riskRaw = labeledValue(html, ["SKOR RISIKO", "RISK SCORE"]);
    const feedbackRaw = labeledValue(html, [
      "UMPAN BALIK KOMUNITAS",
      "COMMUNITY FEEDBACK",
    ]);
    const statusRaw = labeledValue(html, [
      "STATUS GETCONTACT",
      "GETCONTACT STATUS",
    ]);
    // A 200 page without any of the known stat markers means the layout
    // changed — report an error, never a fabricated "no reports".
    if (
      reportsRaw === undefined &&
      riskRaw === undefined &&
      feedbackRaw === undefined
    ) {
      return {
        ok: false,
        inDatabase: false,
        error: "Could not read GetContact's response (their page layout may have changed).",
        url,
      };
    }
    return {
      ok: true,
      inDatabase: true,
      reports: reportsRaw ? parseCount(reportsRaw) : undefined,
      totalCalls: callsRaw ? parseCount(callsRaw) : undefined,
      risk: riskRaw ? normalizeRisk(riskRaw) : undefined,
      feedback: feedbackRaw ? normalizeFeedback(feedbackRaw) : undefined,
      blocked: statusRaw
        ? /diblokir|blocked/i.test(statusRaw)
        : undefined,
      region,
      url,
    };
  } catch (err) {
    return {
      ok: false,
      inDatabase: false,
      error:
        err instanceof Error && err.name === "AbortError"
          ? "GetContact request timed out"
          : "Could not reach GetContact",
      url,
    };
  } finally {
    clearTimeout(timer);
  }
}

export async function fetchShouldIAnswer(
  e164: string,
  countryCallingCode: string | undefined,
): Promise<ShouldIAnswerResult> {
  // Should I Answer's US site only covers NANP numbers. Other countries
  // have their own subdomains, but coverage is thin (Indonesia's is
  // empty — see the header note), so only +1 is attempted.
  if (countryCallingCode !== "1") {
    return { ok: true, covered: false };
  }
  const digits = e164.replace(/^\+/, "");
  const url = `https://www.shouldianswer.com/phone-number/${digits}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      headers: { "User-Agent": USER_AGENT },
      signal: controller.signal,
    });
    if (!res.ok) {
      return {
        ok: false,
        covered: true,
        error: `Should I Answer responded with HTTP ${res.status}`,
        url,
      };
    }
    const html = await readCapped(res);
    if (html === null) {
      return {
        ok: false,
        covered: true,
        error: "Should I Answer's response was too large to read.",
        url,
      };
    }
    const ld = html.match(
      /<script[^>]*type="application\/ld\+json"[^>]*>([\s\S]*?)<\/script>/,
    );
    if (!ld) {
      // A full number page with no rating data = never rated. A short
      // page means the site served an error/unsupported page instead.
      if (html.length > 20000) {
        return { ok: true, covered: true, reports: 0, url };
      }
      return {
        ok: false,
        covered: true,
        error: "Should I Answer did not return a number page.",
        url,
      };
    }
    let parsed: { aggregateRating?: Record<string, unknown> };
    try {
      parsed = JSON.parse(ld[1]) as {
        aggregateRating?: Record<string, unknown>;
      };
    } catch {
      return {
        ok: false,
        covered: true,
        error: "Could not read Should I Answer's rating data.",
        url,
      };
    }
    const agg = parsed.aggregateRating;
    if (!agg) {
      return { ok: true, covered: true, reports: 0, url };
    }
    const reports = Number(agg.reviewCount ?? agg.ratingCount ?? 0);
    const rating = Number(agg.ratingValue);
    return {
      ok: true,
      covered: true,
      reports: Number.isFinite(reports) ? reports : 0,
      rating: Number.isFinite(rating) ? rating : undefined,
      url,
    };
  } catch (err) {
    return {
      ok: false,
      covered: true,
      error:
        err instanceof Error && err.name === "AbortError"
          ? "Should I Answer request timed out"
          : "Could not reach Should I Answer",
      url,
    };
  } finally {
    clearTimeout(timer);
  }
}
