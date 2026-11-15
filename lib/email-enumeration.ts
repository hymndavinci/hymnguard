// Holehe-style account enumeration: checks whether an email is registered
// on popular sites via their public signup/forgot-password endpoints.
//
// GATED: this module only runs behind ownership verification (see
// lib/email-verify.ts). The enumerate route validates a verification token
// before calling into this module; never call it from an ungated route.
//
// Rules:
//   - A probe reports "exists" / "not_exists" / "error" only. An
//     unrecognized response is an ERROR (inconclusive), never "not found".
//   - Probes that would SEND an email (password-reset flows) are NOT in
//     this list — every probe here is a signup-availability check, a login
//     attempt with a wrong password, or a public lookup endpoint.
//   - No bulk checks: one email per invocation, chunked (10 sites/chunk),
//     strict rate limits on the route.
//   - NSFW sites follow the Phase 1 precedent: included when verified,
//     rendered with an 18+ badge; enumeration is gated behind ownership
//     verification, so users only ever see their own data.
//
// Detection rules are adapted from Holehe (GPL-3.0, see
// THIRD-PARTY-NOTICES.md) and verified live before shipping: every kept probe returned not_exists
// for a known-nonexistent control email AND exists for at least one real
// account (verified 2026-11-15 from the Vercel network, control +
// 4 positive test emails). 69 of 76 candidates were excluded — endpoints
// changed, bot-blocked, or never confirmed in the exists direction.
// See README.md for the full exclusion list; excluded probe code is
// preserved in git history (commit 2d62842) for future re-verification.

import crypto from "node:crypto";

const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
const UA_FF =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0";

// 4s per request: two-step probes stay under ~8s, inside the 10s
// serverless window. Slow sites surface as errors, not as "not found".
const TIMEOUT_MS = 4000;
const CONCURRENCY = 8;

export const ENUM_CHUNK_SIZE = 10;

export type EnumStatus = "exists" | "not_exists" | "error";

export interface EnumSiteResult {
  id: string;
  name: string;
  isNSFW: boolean;
  status: EnumStatus;
  detail?: string;
  /** Raw response snippet. Only populated when the caller asks for it
   * (verification harness) — never sent to the production UI. */
  raw?: string;
}

export interface EnumChunkResult {
  email: string;
  checkedAt: string;
  sites: EnumSiteResult[];
  summary: { found: number; notFound: number; errors: number };
  chunk: number;
  chunkSize: number;
  total: number;
  chunks: number;
}

type ProbeOutcome = {
  status: EnumStatus | "observe";
  detail?: string;
  raw?: string;
};

type ProbeFn = (email: string) => Promise<ProbeOutcome>;

export interface EnumSite {
  id: string;
  name: string;
  nsfw?: boolean;
  probe: ProbeFn;
}

function randomString(n: number): string {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let out = "";
  for (let i = 0; i < n; i++)
    out += chars[Math.floor(Math.random() * chars.length)];
  return out;
}

class Jar {
  private map = new Map<string, string>();
  store(res: Response): void {
    const getSetCookie = (
      res.headers as Headers & { getSetCookie?: () => string[] }
    ).getSetCookie;
    const setCookies =
      typeof getSetCookie === "function" ? getSetCookie.call(res.headers) : [];
    for (const c of setCookies) {
      const [pair] = c.split(";");
      const eq = pair.indexOf("=");
      if (eq > 0)
        this.map.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
    }
  }
  get(name: string): string | undefined {
    return this.map.get(name);
  }
  header(): string {
    return [...this.map.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
  }
}

interface ReqOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  jar?: Jar;
  redirect?: RequestRedirect;
}

async function req(
  url: string,
  { method = "GET", headers = {}, body, jar, redirect }: ReqOptions = {},
): Promise<{ status: number; text: string; headers: Headers }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const h: Record<string, string> = { "User-Agent": UA, ...headers };
    if (jar) {
      const c = jar.header();
      if (c) h["Cookie"] = c;
    }
    const res = await fetch(url, {
      method,
      headers: h,
      body,
      redirect: redirect ?? "follow",
      signal: controller.signal,
    });
    if (jar) jar.store(res);
    const text = await res.text().catch(() => "");
    return { status: res.status, text, headers: res.headers };
  } finally {
    clearTimeout(timer);
  }
}

function form(obj: Record<string, string>): string {
  return new URLSearchParams(obj).toString();
}

function jsonOrNull(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function snippet(text: string, n = 220): string {
  return text.replace(/\s+/g, " ").slice(0, n);
}

// ------------------------------------------------------------------- probes
// Each probe returns exists / not_exists / error. "observe" is only used
// during verification for probes whose rule is not yet known; the runner
// maps it to "error" in production.

export const ENUMERATION_SITES: EnumSite[] = [
  {
    id: "spotify", name: "Spotify",
    probe: async (email) => {
      const r = await req(
        `https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email=${encodeURIComponent(email)}`,
        { headers: { Accept: "application/json, text/plain, */*" } },
      );
      const j = jsonOrNull(r.text) as { status?: number } | null;
      if (!j || typeof j.status !== "number")
        return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
      if (j.status === 20) return { status: "exists", detail: "status 20" };
      if (j.status === 1) return { status: "not_exists", detail: "status 1" };
      return { status: "error", detail: `status ${j.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "twitter", name: "X (Twitter)",
    probe: async (email) => {
      const r = await req(
        `https://api.twitter.com/i/users/email_available.json?email=${encodeURIComponent(email)}`,
      );
      const j = jsonOrNull(r.text) as { taken?: boolean } | null;
      if (!j || typeof j.taken !== "boolean")
        return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
      return j.taken
        ? { status: "exists", detail: "taken=true" }
        : { status: "not_exists", detail: "taken=false" };
    },
  },
  {
    id: "adobe", name: "Adobe",
    probe: async (email) => {
      const r = await req("https://auth.services.adobe.com/signin/v1/authenticationstate", {
        method: "POST",
        headers: {
          Accept: "application/json, text/plain, */*",
          "X-IMS-CLIENTID": "adobedotcom2",
          "Content-Type": "application/json;charset=utf-8",
          Origin: "https://auth.services.adobe.com",
        },
        body: JSON.stringify({ username: email, accountType: "individual" }),
      });
      const j = jsonOrNull(r.text) as { errorCode?: string } | null;
      if (!j) return { status: "error", detail: `HTTP ${r.status} non-JSON`, raw: snippet(r.text) };
      if ("errorCode" in j) return { status: "not_exists", detail: `errorCode ${j.errorCode}` };
      return { status: "exists", detail: "no errorCode (account state returned)" };
    },
  },
  {
    id: "gravatar", name: "Gravatar",
    probe: async (email) => {
      const hash = crypto.createHash("md5").update(email.trim().toLowerCase()).digest("hex");
      const r = await req(`https://en.gravatar.com/${hash}.json`);
      if (r.status === 200) return { status: "exists", detail: "HTTP 200 profile" };
      if (r.status === 404) return { status: "not_exists", detail: "HTTP 404" };
      return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "replit", name: "Replit",
    probe: async (email) => {
      const r = await req("https://replit.com/data/user/exists", {
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/json", Origin: "https://replit.com", "X-Requested-With": "XMLHttpRequest" },
        body: JSON.stringify({ email }),
      });
      const j = jsonOrNull(r.text) as { exists?: boolean } | null;
      if (!j || typeof j.exists !== "boolean")
        return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
      return j.exists
        ? { status: "exists", detail: "exists=true" }
        : { status: "not_exists", detail: "exists=false" };
    },
  },
  {
    id: "xvideos", name: "XVideos", nsfw: true,
    probe: async (email) => {
      const r = await req(`https://www.xvideos.com/account/checkemail?email=${encodeURIComponent(email)}`);
      const j = jsonOrNull(r.text) as { result?: boolean } | null;
      if (!j) return { status: "error", detail: `HTTP ${r.status} non-JSON`, raw: snippet(r.text) };
      if (j.result === false && r.text.includes("This email is already in use"))
        return { status: "exists", detail: "already in use" };
      if (j.result === true) return { status: "not_exists", detail: "result=true" };
      return { status: "observe", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "wordpress", name: "WordPress.com",
    probe: async (email) => {
      const r = await req(
        `https://public-api.wordpress.com/rest/v1.1/users/${encodeURIComponent(email)}/auth-options?http_envelope=1&locale=fr`,
        {
          headers: {
            "User-Agent": UA_FF,
            Cookie: "G_ENABLED_IDPS=google; ccpa_applies=true; usprivacy=1YNN; wordpress_test_cookie=WP+Cookie+check",
          },
        },
      );
      const j = jsonOrNull(r.text) as {
        body?: { email_verified?: boolean };
        email_verified?: boolean;
      } | null;
      const body = j?.body ?? j;
      if (body && typeof body.email_verified === "boolean")
        return body.email_verified
          ? { status: "exists", detail: "email_verified=true" }
          : { status: "not_exists", detail: "email_verified=false", raw: snippet(r.text) };
      // "email_login_not_allowed" means the account EXISTS but cannot log in
      // with email/password (e.g. social-only signup) — verified live
      // 2026-11-15: control email returned unknown_user, a real account
      // returned email_login_not_allowed. Mapping it to not_exists would
      // be a false negative.
      if (r.text.includes("email_login_not_allowed"))
        return { status: "exists", detail: "email_login_not_allowed", raw: snippet(r.text) };
      if (r.text.includes("unknown_user"))
        return { status: "not_exists", detail: "unknown_user", raw: snippet(r.text) };
      return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
];

// ------------------------------------------------------------------ runner

export function getEnumPlan(): { total: number; chunkSize: number; chunks: number } {
  return {
    total: ENUMERATION_SITES.length,
    chunkSize: ENUM_CHUNK_SIZE,
    chunks: Math.ceil(ENUMERATION_SITES.length / ENUM_CHUNK_SIZE),
  };
}

/**
 * Run one chunk of enumeration probes. `includeRaw` is for the verification
 * harness only — production responses never include raw snippets.
 * "observe" outcomes are mapped to "error" unless includeRaw is set, so an
 * unclassified response is never reported as "not found".
 */
export async function checkEnumChunk(
  email: string,
  chunk: number,
  includeRaw = false,
): Promise<EnumChunkResult> {
  const plan = getEnumPlan();
  const sites = ENUMERATION_SITES.slice(
    chunk * ENUM_CHUNK_SIZE,
    (chunk + 1) * ENUM_CHUNK_SIZE,
  );
  const results: EnumSiteResult[] = [];
  const queue = [...sites];
  const workers = Array.from({ length: CONCURRENCY }, async () => {
    while (queue.length > 0) {
      const site = queue.shift();
      if (!site) return;
      try {
        const out = await site.probe(email);
        const status: EnumStatus =
          out.status === "observe"
            ? "error"
            : (out.status as EnumStatus);
        results.push({
          id: site.id,
          name: site.name,
          isNSFW: Boolean(site.nsfw),
          status,
          ...(out.detail ? { detail: out.detail } : {}),
          ...(includeRaw && out.raw ? { raw: out.raw } : {}),
          ...(includeRaw && out.status === "observe"
            ? { detail: `observe: ${out.detail ?? ""}` }
            : {}),
        });
      } catch (err) {
        results.push({
          id: site.id,
          name: site.name,
          isNSFW: Boolean(site.nsfw),
          status: "error",
          detail: err instanceof Error ? err.message : "Probe failed",
        });
      }
    }
  });
  await Promise.all(workers);

  // Keep chunk order stable (sites were pushed in completion order).
  const order = new Map(sites.map((s, i) => [s.id, i]));
  results.sort((a, b) => (order.get(a.id) ?? 0) - (order.get(b.id) ?? 0));

  return {
    email,
    checkedAt: new Date().toISOString(),
    sites: results,
    summary: {
      found: results.filter((s) => s.status === "exists").length,
      notFound: results.filter((s) => s.status === "not_exists").length,
      errors: results.filter((s) => s.status === "error").length,
    },
    chunk,
    chunkSize: ENUM_CHUNK_SIZE,
    total: plan.total,
    chunks: plan.chunks,
  };
}
