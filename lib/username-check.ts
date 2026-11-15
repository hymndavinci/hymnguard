// Sherlock-style username probing, implemented in TypeScript.
// One HTTP request per site, all run concurrently. A per-site failure
// (timeout, block, rate limit) is reported as an error for that site only
// and never fails the whole check.

import { USERNAME_SITES, type UsernameSite } from "./username-sites";

export type SiteStatus = "found" | "not_found" | "error";

export interface SiteResult {
  id: string;
  name: string;
  url: string;
  status: SiteStatus;
  detail?: string;
  /** Adult site (Sherlock's isNSFW). */
  isNSFW?: boolean;
}

export interface UsernameCheckResult {
  username: string;
  checkedAt: string;
  sites: SiteResult[];
  summary: { found: number; notFound: number; errors: number };
}

/** Detail string used when a site's own username regex rejects the input. */
export const REGEX_SKIP_DETAIL = "Username format not supported by this site";

const USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

const DEFAULT_ACCEPT =
  "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

const SITE_TIMEOUT_MS = 5000;

// Markers for bot-challenge / interstitial pages. A 200 that serves one of
// these is not evidence the user exists — it means the check was blocked.
// Includes Sherlock's WAF fingerprints (Cloudflare / AWS / PerimeterX).
const CHALLENGE_MARKERS = [
  "Checking your browser before accessing",
  "Just a moment...",
  "Attention Required! | Cloudflare",
  "Verify you are human",
  '<span id="challenge-error-text">',
  "AwsWafIntegration.forceRefreshToken",
  "perimeterxIdentifiers",
];

const BODY_READ_LIMIT_BYTES = 128 * 1024;
// Message-detection markers can sit near the end of a large page
// (TikTok's statusCode sits at ~365KB), so read up to 1MB there.
const MESSAGE_BODY_LIMIT_BYTES = 1024 * 1024;

function profileUrl(site: UsernameSite, username: string): string {
  return site.urlTemplate.replaceAll("{}", encodeURIComponent(username));
}

function probeUrl(site: UsernameSite, username: string): string {
  const template = site.probeUrlTemplate ?? site.urlTemplate;
  return template.replaceAll("{}", encodeURIComponent(username));
}

/** Deep-substitute `{}` with the username inside a POST payload. */
function substitutePayload(payload: unknown, username: string): unknown {
  if (typeof payload === "string") {
    return payload.replaceAll("{}", username);
  }
  if (Array.isArray(payload)) {
    return payload.map((item) => substitutePayload(item, username));
  }
  if (payload !== null && typeof payload === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(payload)) {
      out[key] = substitutePayload(value, username);
    }
    return out;
  }
  return payload;
}

/** Sherlock's `regexCheck`: the site is skipped when the username cannot exist there. */
function usernameAllowed(site: UsernameSite, username: string): boolean {
  if (!site.usernameRegex) return true;
  try {
    return new RegExp(site.usernameRegex).test(username);
  } catch {
    return true;
  }
}

/** Read at most `limit` bytes of a response body (enough for markers). */
async function readBodyUpTo(res: Response, limit: number): Promise<string> {
  const reader = res.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done || !value) break;
      chunks.push(value);
      total += value.length;
      if (total >= limit) break;
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.length;
  }
  return new TextDecoder().decode(merged.subarray(0, limit));
}

function isChallengePage(text: string): boolean {
  return CHALLENGE_MARKERS.some((marker) => text.includes(marker));
}

async function probeSite(
  site: UsernameSite,
  username: string,
): Promise<SiteResult> {
  const url = profileUrl(site, username);
  const requestUrl = probeUrl(site, username);
  const base = {
    id: site.id,
    name: site.name,
    url,
    ...(site.isNSFW ? { isNSFW: true as const } : {}),
  };

  // Sherlock's ILLEGAL: this username cannot exist on this site, so there
  // is nothing to probe. Reported as an error (inconclusive), never as
  // "not found".
  if (!usernameAllowed(site, username)) {
    return { ...base, status: "error", detail: REGEX_SKIP_DETAIL };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), SITE_TIMEOUT_MS);

  try {
    const method = site.method ?? "GET";
    const headers: Record<string, string> = {
      "User-Agent": USER_AGENT,
      Accept: site.accept ?? DEFAULT_ACCEPT,
      "Accept-Language": "en-US,en;q=0.9",
      ...(site.headers ?? {}),
    };
    const init: RequestInit = {
      method,
      headers,
      redirect: site.noRedirect ? "manual" : "follow",
      signal: controller.signal,
    };
    if (method === "POST") {
      init.body = JSON.stringify(
        substitutePayload(site.requestPayload ?? {}, username),
      );
      if (!headers["Content-Type"] && !headers["content-type"]) {
        headers["Content-Type"] = "application/json";
      }
    }
    const res = await fetch(requestUrl, init);

    // A block or rate limit is not evidence either way.
    if (res.status === 429 || res.status === 403 || res.status === 401) {
      return {
        ...base,
        status: "error",
        detail: `HTTP ${res.status} (blocked or rate-limited)`,
      };
    }

    // A 404 (or a site-specific not-found status) means "not here" under
    // every detection method.
    if (res.status === 404 || site.notFoundStatuses?.includes(res.status)) {
      return { ...base, status: "not_found" };
    }

    if (site.detection === "status") {
      if (res.status !== 200) {
        return { ...base, status: "error", detail: `HTTP ${res.status}` };
      }
      // A 200 can still be a bot-challenge interstitial, which is a block,
      // not a found account.
      const text = await readBodyUpTo(res, BODY_READ_LIMIT_BYTES);
      if (isChallengePage(text)) {
        return {
          ...base,
          status: "error",
          detail: "Blocked (bot challenge page)",
        };
      }
      return { ...base, status: "found" };
    }

    if (site.detection === "response_url") {
      if (site.noRedirect) {
        // Sherlock's own `response_url` semantics: redirects were disabled,
        // so a 2xx means the profile exists and a redirect (3xx) means the
        // site bounced the missing username elsewhere.
        if (res.status >= 200 && res.status < 300) {
          const text = await readBodyUpTo(res, BODY_READ_LIMIT_BYTES);
          if (isChallengePage(text)) {
            return {
              ...base,
              status: "error",
              detail: "Blocked (bot challenge page)",
            };
          }
          return { ...base, status: "found" };
        }
        if (res.status >= 300 && res.status < 400) {
          return { ...base, status: "not_found" };
        }
        return { ...base, status: "error", detail: `HTTP ${res.status}` };
      }
      const finalUrl = res.url.replace(/\/$/, "");
      if (
        site.errorUrlExact &&
        finalUrl === site.errorUrlExact.replace(/\/$/, "")
      ) {
        return { ...base, status: "not_found" };
      }
      if (site.errorUrlContains && res.url.includes(site.errorUrlContains)) {
        return { ...base, status: "not_found" };
      }
      if (res.status !== 200) {
        return { ...base, status: "error", detail: `HTTP ${res.status}` };
      }
      const text = await readBodyUpTo(res, BODY_READ_LIMIT_BYTES);
      if (isChallengePage(text)) {
        return {
          ...base,
          status: "error",
          detail: "Blocked (bot challenge page)",
        };
      }
      return { ...base, status: "found" };
    }

    // Message detection: the profile page returns 200 either way, so look
    // for the site's own "this user does not exist" marker in the body.
    const text = await readBodyUpTo(res, MESSAGE_BODY_LIMIT_BYTES);
    if (isChallengePage(text)) {
      return {
        ...base,
        status: "error",
        detail: "Blocked (bot challenge page)",
      };
    }
    const markers = site.errorMarkers ?? [];
    if (markers.some((marker) => text.includes(marker))) {
      return { ...base, status: "not_found" };
    }
    return { ...base, status: "found" };
  } catch (err) {
    const detail =
      err instanceof Error && err.name === "AbortError"
        ? "Request timed out"
        : "Request failed";
    return { ...base, status: "error", detail };
  } finally {
    clearTimeout(timer);
  }
}

export async function checkUsername(
  username: string,
  sitesToCheck: UsernameSite[] = USERNAME_SITES,
): Promise<UsernameCheckResult> {
  const settled = await Promise.allSettled(
    sitesToCheck.map((site) => probeSite(site, username)),
  );

  const sites = settled.map((result, i) => {
    if (result.status === "fulfilled") return result.value;
    const site = sitesToCheck[i];
    return {
      id: site.id,
      name: site.name,
      url: profileUrl(site, username),
      status: "error" as const,
      detail: "Check failed",
      ...(site.isNSFW ? { isNSFW: true as const } : {}),
    };
  });

  return {
    username,
    checkedAt: new Date().toISOString(),
    sites,
    summary: {
      found: sites.filter((s) => s.status === "found").length,
      notFound: sites.filter((s) => s.status === "not_found").length,
      errors: sites.filter((s) => s.status === "error").length,
    },
  };
}
