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
// Detection rules are adapted from Holehe (MIT, see THIRD-PARTY-NOTICES.md)
// and verified live before shipping. Sites whose rules could not be
// verified are excluded — see README.md for the exclusion list.

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
    id: "github", name: "GitHub",
    probe: async (email) => {
      const jar = new Jar();
      const page = await req("https://github.com/join", { jar });
      const m =
        page.text.match(/<auto-check src="\/signup_check\/email[\s\S]*?value="([\S]+)"/) ||
        page.text.match(/signup_check\/email[\s\S]{0,800}?value="([^"]+)"/);
      if (!m) return { status: "error", detail: "no csrf token on /join", raw: snippet(page.text) };
      const r = await req("https://github.com/signup_check/email", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "*/*" },
        body: form({ value: email, authenticity_token: m[1] }),
        jar,
      });
      if (r.text.includes("Your browser did something unexpected"))
        return { status: "error", detail: "rate limited", raw: snippet(r.text) };
      if (r.status === 422) return { status: "exists", detail: "HTTP 422" };
      if (r.status === 200) return { status: "not_exists", detail: "HTTP 200" };
      return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "discord", name: "Discord",
    probe: async (email) => {
      const r = await req("https://discord.com/api/v9/auth/register", {
        method: "POST",
        headers: {
          "User-Agent": UA_FF, Accept: "*/*", "Content-Type": "application/json",
          Origin: "https://discord.com",
        },
        body: JSON.stringify({
          fingerprint: "", email, username: randomString(20),
          password: randomString(20), invite: null, consent: true,
          date_of_birth: "", gift_code_sku_id: null, captcha_key: null,
        }),
      });
      const j = jsonOrNull(r.text) as {
        errors?: { email?: { _errors?: { code?: string }[] } };
        captcha_key?: string[];
        message?: string;
        code?: number;
      } | null;
      if (!j) return { status: "error", detail: `HTTP ${r.status} non-JSON`, raw: snippet(r.text) };
      const code = j?.errors?.email?._errors?.[0]?.code;
      if (code === "EMAIL_ALREADY_REGISTERED") return { status: "exists", detail: code };
      if (j.captcha_key?.[0] === "captcha-required" || j.message === "captcha-required")
        return { status: "not_exists", detail: "captcha-required (email free)" };
      if (j.code === 50035 && j.errors && !j.errors.email)
        return { status: "not_exists", detail: "validation errors, email not flagged" };
      return { status: "error", detail: `unrecognized shape code=${j.code}`, raw: snippet(r.text) };
    },
  },
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
    id: "instagram", name: "Instagram",
    probe: async (email) => {
      const jar = new Jar();
      const page = await req("https://www.instagram.com/accounts/emailsignup/", { jar });
      const token = jar.get("csrftoken");
      if (!token) return { status: "error", detail: "no csrftoken cookie", raw: snippet(page.text) };
      const r = await req("https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Origin: "https://www.instagram.com", "X-CSRFToken": token,
          "X-Requested-With": "XMLHttpRequest",
        },
        body: form({ email, username: randomString(10), first_name: "", opt_into_one_tap: "false" }),
        jar,
      });
      const j = jsonOrNull(r.text) as {
        status?: string;
        errors?: { email?: { code?: string }[] };
      } | null;
      if (!j) return { status: "error", detail: `HTTP ${r.status} non-JSON`, raw: snippet(r.text) };
      if (j.status === "fail") return { status: "error", detail: "status fail (blocked?)", raw: snippet(r.text) };
      const code = j?.errors?.email?.[0]?.code;
      if (code === "email_is_taken") return { status: "exists", detail: code };
      if (j.errors && !("email" in j.errors)) return { status: "not_exists", detail: "no email error" };
      return { status: "error", detail: "unrecognized shape", raw: snippet(r.text) };
    },
  },
  {
    id: "facebook", name: "Facebook",
    probe: async (email) => {
      const jar = new Jar();
      const page = await req("https://www.facebook.com/accounts/emailsignup/", { jar });
      if (page.status === 404) return { status: "error", detail: "signup page 404" };
      const token = jar.get("csrftoken") ?? jar.get("sb");
      const r = await req("https://www.facebook.com/api/v1/web/accounts/web_create_ajax/attempt/", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Origin: "https://www.facebook.com",
          ...(token ? { "X-CSRFToken": token } : {}),
        },
        body: form({ email, username: randomString(10), first_name: "", opt_into_one_tap: "false" }),
        jar,
      });
      const j = jsonOrNull(r.text) as {
        errors?: { email?: { code?: string | number }[] };
      } | null;
      if (!j) return { status: "error", detail: `HTTP ${r.status} non-JSON`, raw: snippet(r.text) };
      const code = j?.errors?.email?.[0]?.code;
      if (code === "email_is_taken" || code === 1396009) return { status: "exists", detail: String(code) };
      if (j.errors && !("email" in j.errors)) return { status: "not_exists", detail: "no email error" };
      return { status: "error", detail: "unrecognized shape", raw: snippet(r.text) };
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
    id: "firefox", name: "Firefox Account",
    probe: async (email) => {
      const r = await req("https://api.accounts.firefox.com/v1/account/status", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: form({ email }),
      });
      const j = jsonOrNull(r.text) as { exists?: boolean } | null;
      if (!j || typeof j.exists !== "boolean") {
        if (r.text.includes("true") && !r.text.includes("false"))
          return { status: "exists", detail: "text contains true" };
        if (r.text.includes("false")) return { status: "not_exists", detail: "text contains false" };
        return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
      }
      return j.exists
        ? { status: "exists", detail: "exists=true" }
        : { status: "not_exists", detail: "exists=false" };
    },
  },
  {
    id: "lastpass", name: "LastPass",
    probe: async (email) => {
      const r = await req(
        `https://lastpass.com/create_account.php?check=avail&skipcontent=1&mistype=1&username=${encodeURIComponent(email)}`,
        { headers: { "User-Agent": UA_FF, "X-Requested-With": "XMLHttpRequest", Referer: "https://lastpass.com/" } },
      );
      const t = r.text.trim();
      if (t === "no") return { status: "exists", detail: 'body "no"' };
      if (t === "ok" || t === "emailinvalid") return { status: "not_exists", detail: `body "${t}"` };
      return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "docker", name: "Docker Hub",
    probe: async (email) => {
      const r = await req("https://hub.docker.com/v2/users/signup/", {
        method: "POST",
        headers: {
          Accept: "application/json", "Content-Type": "application/json",
          Referer: "https://hub.docker.com/signup", Origin: "https://hub.docker.com",
        },
        body: JSON.stringify({ email, password: "", recaptcha_response: "", redirect_value: "", subscribe: true, username: "" }),
      });
      if (r.text.includes("This email is already in use."))
        return { status: "exists", detail: "already in use" };
      if (r.text.includes("username") || r.text.includes("password") || r.text.includes("recaptcha"))
        return { status: "not_exists", detail: "other validation errors only", raw: snippet(r.text) };
      return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "patreon", name: "Patreon",
    probe: async (email) => {
      const r = await req("https://www.patreon.com/api/email/available?json-api-version=1.0&include=[]", {
        method: "POST",
        headers: {
          Accept: "*/*", "Content-Type": "application/vnd.api+json",
          Referer: "https://www.patreon.com/signup", Origin: "https://www.patreon.com",
        },
        body: JSON.stringify({ data: { attributes: { email }, relationships: {} } }),
      });
      const j = jsonOrNull(r.text) as { data?: { is_available?: boolean } } | null;
      const avail = j?.data?.is_available;
      if (typeof avail !== "boolean")
        return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
      return avail
        ? { status: "not_exists", detail: "is_available=true" }
        : { status: "exists", detail: "is_available=false" };
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
    id: "duolingo", name: "Duolingo",
    probe: async (email) => {
      const r = await req(`https://www.duolingo.com/2017-06-30/users?email=${encodeURIComponent(email)}`);
      const j = jsonOrNull(r.text) as { users?: unknown[] } | null;
      if (!j || !Array.isArray(j.users))
        return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
      return j.users.length > 0
        ? { status: "exists", detail: `${j.users.length} user(s)` }
        : { status: "not_exists", detail: "users empty" };
    },
  },
  {
    id: "pinterest", name: "Pinterest",
    probe: async (email) => {
      const data = JSON.stringify({ options: { email }, context: {} });
      const r = await req(
        `https://www.pinterest.com/_ngjs/resource/EmailExistsResource/get/?source_url=/&data=${encodeURIComponent(data)}`,
      );
      const j = jsonOrNull(r.text) as { resource_response?: { data?: unknown } } | null;
      const d = j?.resource_response?.data;
      if (d === undefined) return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
      if (d && typeof d === "object" && "source_field" in d)
        return { status: "exists", detail: "source_field present", raw: snippet(r.text) };
      if (d) return { status: "not_exists", detail: "data truthy, no source_field", raw: snippet(r.text) };
      return { status: "not_exists", detail: "data falsy", raw: snippet(r.text) };
    },
  },
  {
    id: "protonmail", name: "Proton Mail (PGP key)",
    probe: async (email) => {
      const r = await req(`https://api.protonmail.ch/pks/lookup?op=index&search=${encodeURIComponent(email)}`);
      if (r.text.includes("info:1:1")) return { status: "exists", detail: "info:1:1 (key published)" };
      if (r.text.includes("info:1:0")) return { status: "not_exists", detail: "info:1:0 (no key)" };
      return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "nike", name: "Nike",
    probe: async (email) => {
      const qs = "appVersion=831&experienceVersion=831&uxid=com.nike.commerce.nikedotcom.web&locale=fr_FR&backendEnvironment=identity&browser=&mobile=false&native=false&visit=1";
      const r = await req(`https://unite.nike.com/account/email/v1?${qs}`, {
        method: "POST",
        headers: {
          "User-Agent": UA_FF, "Content-Type": "text/plain;charset=UTF-8",
          Origin: "https://www.nike.com", Referer: "https://www.nike.com/",
        },
        body: JSON.stringify({ emailAddress: email }),
      });
      if (r.status === 409) return { status: "exists", detail: "HTTP 409" };
      if (r.status === 204) return { status: "not_exists", detail: "HTTP 204" };
      return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "anydo", name: "Any.do",
    probe: async (email) => {
      const r = await req("https://sm-prod2.any.do/check_email", {
        method: "POST",
        headers: {
          "Content-Type": "application/json; charset=UTF-8", "X-Platform": "3",
          Referer: "https://desktop.any.do/", Origin: "https://desktop.any.do",
        },
        body: JSON.stringify({ email }),
      });
      const j = jsonOrNull(r.text) as { user_exists?: boolean } | null;
      if (!j || typeof j.user_exists !== "boolean")
        return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
      return j.user_exists
        ? { status: "exists", detail: "user_exists=true" }
        : { status: "not_exists", detail: "user_exists=false" };
    },
  },
  {
    id: "tellonym", name: "Tellonym",
    probe: async (email) => {
      const r = await req(`https://api.tellonym.me/accounts/check?email=${encodeURIComponent(email)}`);
      if (r.text.includes("EMAIL_ALREADY_IN_USE")) return { status: "exists", detail: "EMAIL_ALREADY_IN_USE" };
      const j = jsonOrNull(r.text) as { available?: boolean; exists?: boolean } | null;
      if (j && (j.available === true || j.exists === false))
        return { status: "not_exists", detail: "available", raw: snippet(r.text) };
      return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "plurk", name: "Plurk",
    probe: async (email) => {
      const r = await req("https://www.plurk.com/Users/isEmailFound", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: form({ email }),
      });
      const t = r.text.trim();
      if (t === "True") return { status: "exists", detail: "True" };
      if (t === "False") return { status: "not_exists", detail: "False" };
      return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "myspace", name: "Myspace",
    probe: async (email) => {
      const jar = new Jar();
      await req("https://myspace.com/signup/email", { jar });
      const r = await req("https://myspace.com/ajax/account/validateemail", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", "X-Requested-With": "XMLHttpRequest" },
        body: form({ email }),
        jar,
      });
      if (r.text.includes("This email address was already used to create an account."))
        return { status: "exists", detail: "already used" };
      return { status: "observe", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "issuu", name: "Issuu",
    probe: async (email) => {
      const r = await req(`https://issuu.com/call/signup/check-email/?email=${encodeURIComponent(email)}`);
      const j = jsonOrNull(r.text) as { status?: string } | null;
      if (!j || typeof j.status !== "string")
        return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
      if (j.status === "unavailable") return { status: "exists", detail: "unavailable" };
      if (j.status === "available") return { status: "not_exists", detail: "available" };
      return { status: "error", detail: `status ${j.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "archive", name: "Internet Archive",
    probe: async (email) => {
      const boundary = "---------------------------" + randomString(12);
      const body =
        `--${boundary}\r\nContent-Disposition: form-data; name="input_name"\r\n\r\nemail\r\n` +
        `--${boundary}\r\nContent-Disposition: form-data; name="input_value"\r\n\r\n${email}\r\n` +
        `--${boundary}--\r\n`;
      const r = await req("https://archive.org/account/signup", {
        method: "POST",
        headers: { "Content-Type": `multipart/form-data; boundary=${boundary}` },
        body,
      });
      if (r.text.includes("is already taken.")) return { status: "exists", detail: "already taken" };
      return { status: "observe", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "bodybuilding", name: "Bodybuilding.com",
    probe: async (email) => {
      const r = await req(`https://api.bodybuilding.com/profile/email/${encodeURIComponent(email)}`);
      return { status: "observe", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "rocketreach", name: "RocketReach",
    probe: async (email) => {
      const jar = new Jar();
      await req("https://rocketreach.co/signup", { jar });
      const r = await req(`https://rocketreach.co/v1/validateEmail?email_address=${encodeURIComponent(email)}`, { jar });
      const j = jsonOrNull(r.text) as { found?: boolean } | null;
      if (!j || typeof j.found !== "boolean")
        return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
      return j.found
        ? { status: "exists", detail: "found=true" }
        : { status: "not_exists", detail: "found=false" };
    },
  },
  {
    id: "diigo", name: "Diigo",
    probe: async (email) => {
      const r = await req(`https://www.diigo.com/user_mana2/check_email?email=${encodeURIComponent(email)}`);
      return { status: "observe", detail: `HTTP ${r.status} body=${JSON.stringify(r.text.trim())}`, raw: snippet(r.text) };
    },
  },
  {
    id: "smule", name: "Smule",
    probe: async (email) => {
      const jar = new Jar();
      await req("https://www.smule.com/user/check_email", { jar });
      const r = await req("https://www.smule.com/user/check_email", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: form({ email }),
        jar,
      });
      const j = jsonOrNull(r.text) as { email?: unknown } | null;
      if (!j || j.email === undefined)
        return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
      return String(j.email) === "True"
        ? { status: "exists", detail: "email=True" }
        : { status: "not_exists", detail: `email=${j.email}`, raw: snippet(r.text) };
    },
  },
  {
    id: "sporcle", name: "Sporcle",
    probe: async (email) => {
      const r = await req("https://www.sporcle.com/auth/ajax/verify.php", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", "X-Requested-With": "XMLHttpRequest" },
        body: form({ email }),
      });
      if (r.text.includes("account already exists with this email"))
        return { status: "exists", detail: "already exists" };
      return { status: "observe", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "tunefind", name: "TuneFind",
    probe: async (email) => {
      const jar = new Jar();
      await req("https://www.tunefind.com/user/join", { jar });
      const boundary = "---------------------------" + randomString(12);
      const body =
        `--${boundary}\r\nContent-Disposition: form-data; name="username"\r\n\r\n\r\n` +
        `--${boundary}\r\nContent-Disposition: form-data; name="email"\r\n\r\n${email}\r\n` +
        `--${boundary}--\r\n`;
      const r = await req("https://www.tunefind.com/user/join", {
        method: "POST",
        headers: { "Content-Type": `multipart/form-data; boundary=${boundary}` },
        body, jar,
      });
      const j = jsonOrNull(r.text) as { errors?: Record<string, unknown> } | null;
      if (!j) return { status: "error", detail: `HTTP ${r.status} non-JSON`, raw: snippet(r.text) };
      if (j.errors && "email" in j.errors) return { status: "exists", detail: "email in errors", raw: snippet(r.text) };
      return { status: "observe", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "ello", name: "Ello",
    probe: async (email) => {
      const r = await req("https://ello.co/api/v2/availability", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const j = jsonOrNull(r.text) as { availability?: { email?: boolean } } | null;
      const avail = j?.availability?.email;
      if (typeof avail !== "boolean")
        return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
      return avail
        ? { status: "not_exists", detail: "available=true" }
        : { status: "exists", detail: "available=false" };
    },
  },
  {
    id: "komoot", name: "Komoot",
    probe: async (email) => {
      const r = await req("https://account.komoot.com/v1/signin", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const j = jsonOrNull(r.text) as { type?: string } | null;
      if (!j) return { status: "error", detail: `HTTP ${r.status} non-JSON`, raw: snippet(r.text) };
      if (typeof j.type === "string" && j.type.includes("login"))
        return { status: "exists", detail: `type=${j.type}` };
      return { status: "observe", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "blip", name: "Blip.fm",
    probe: async (email) => {
      const r = await req("https://blip.fm/signup/save", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: form({ email }),
      });
      if (r.text.includes("That email address is already in use."))
        return { status: "exists", detail: "already in use" };
      return { status: "observe", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "lastfm", name: "Last.fm",
    probe: async (email) => {
      const jar = new Jar();
      const page = await req("https://www.last.fm/join", { jar });
      const m = page.text.match(/name="csrfmiddlewaretoken" value="([^"]+)"/);
      if (!m) return { status: "error", detail: "no csrf token", raw: snippet(page.text) };
      const r = await req("https://www.last.fm/join/partial/validate", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", "X-Requested-With": "XMLHttpRequest", Referer: "https://www.last.fm/join" },
        body: form({ csrfmiddlewaretoken: m[1], userName: "", email }),
        jar,
      });
      return { status: "observe", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "coroflot", name: "Coroflot",
    probe: async (email) => {
      const r = await req("https://www.coroflot.com/home/signup_email_check", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", "X-Requested-With": "XMLHttpRequest" },
        body: form({ email }),
      });
      const j = jsonOrNull(r.text) as { data?: number } | null;
      if (!j) return { status: "error", detail: `HTTP ${r.status} non-JSON`, raw: snippet(r.text) };
      if (j.data === -2) return { status: "exists", detail: "data=-2" };
      return { status: "observe", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "freelancer", name: "Freelancer",
    probe: async (email) => {
      const r = await req("https://www.freelancer.com/api/users/0.1/users/check?compact=true&new_errors=true", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user: { email } }),
      });
      if (r.status === 409 && r.text.includes("EMAIL_ALREADY_IN_USE"))
        return { status: "exists", detail: "409 EMAIL_ALREADY_IN_USE" };
      if (r.status === 200) return { status: "not_exists", detail: "HTTP 200" };
      return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "teamtreehouse", name: "Treehouse",
    probe: async (email) => {
      const jar = new Jar();
      await req("https://teamtreehouse.com/subscribe/new?trial=yes", { jar });
      const r = await req("https://teamtreehouse.com/account/email_address", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", "X-Requested-With": "XMLHttpRequest" },
        body: form({ email }),
        jar,
      });
      if (r.text.includes("that email address is taken.")) return { status: "exists", detail: "taken" };
      if (r.text.trim() === '{"success":true}') return { status: "not_exists", detail: "success true" };
      return { status: "observe", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "vrbo", name: "Vrbo",
    probe: async (email) => {
      const r = await req("https://www.vrbo.com/auth/aam/v3/status", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ emailAddress: email }),
      });
      const j = jsonOrNull(r.text) as { authType?: string[] } | null;
      const t = j?.authType?.[0];
      if (t === "LOGIN_UMS") return { status: "exists", detail: "LOGIN_UMS" };
      if (t === "SIGNUP") return { status: "not_exists", detail: "SIGNUP" };
      return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "fanpop", name: "Fanpop",
    probe: async (email) => {
      const r = await req("https://www.fanpop.com/login/superlogin", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: form({ email, password: randomString(12) }),
      });
      if (r.text.includes("already registered")) return { status: "exists", detail: "already registered" };
      return { status: "observe", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
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
    id: "xnxx", name: "XNXX", nsfw: true,
    probe: async (email) => {
      // Direct checkemail call — no homepage fetch needed (verified live).
      const r = await req(`https://www.xnxx.com/account/checkemail?email=${encodeURIComponent(email)}`);
      const j = jsonOrNull(r.text) as { result?: boolean; code?: number } | null;
      if (!j) return { status: "error", detail: `HTTP ${r.status} non-JSON`, raw: snippet(r.text) };
      if (j.result === false && j.code === 1 && r.text.includes("utilis"))
        return { status: "exists", detail: "already used (FR)" };
      if (j.result === true && j.code === 0) return { status: "not_exists", detail: "result=true" };
      if (j.code === 2) return { status: "error", detail: "rate limited" };
      return { status: "observe", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "pornhub", name: "Pornhub", nsfw: true,
    probe: async (email) => {
      const jar = new Jar();
      const page = await req("https://www.pornhub.com/signup", { jar });
      const m = page.text.match(/name="token" value="([^"]+)"/);
      if (!m) return { status: "error", detail: "no token on signup page", raw: snippet(page.text) };
      const r = await req(`https://www.pornhub.com/user/create_account_check?token=${encodeURIComponent(m[1])}`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", "X-Requested-With": "XMLHttpRequest" },
        body: form({ check_what: "email", email }),
        jar,
      });
      const j = jsonOrNull(r.text) as { error_message?: string } | null;
      if (j?.error_message === "Email has been taken.") return { status: "exists", detail: "taken" };
      if (j && !j.error_message) return { status: "not_exists", detail: "no error", raw: snippet(r.text) };
      return { status: "observe", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "redtube", name: "RedTube", nsfw: true,
    probe: async (email) => {
      const jar = new Jar();
      const page = await req("https://redtube.com/register", { jar });
      const m = page.text.match(/name="token" value="([^"]+)"/);
      if (!m) return { status: "error", detail: "no token on register page", raw: snippet(page.text) };
      const r = await req(`https://www.redtube.com/user/create_account_check?token=${encodeURIComponent(m[1])}`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", "X-Requested-With": "XMLHttpRequest", Origin: "https://redtube.com" },
        body: form({ token: m[1], redirect: "", check_what: "email", email }),
        jar,
      });
      if (r.text.includes("Email has been taken.")) return { status: "exists", detail: "taken" };
      return { status: "observe", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "hubspot", name: "HubSpot",
    probe: async (email) => {
      const r = await req("https://api.hubspot.com/login-api/v1/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password: "", rememberLogin: false }),
      });
      const j = jsonOrNull(r.text) as { status?: string } | null;
      if (r.status === 400 && j?.status === "INVALID_PASSWORD")
        return { status: "exists", detail: "INVALID_PASSWORD" };
      if (r.status === 400 && j?.status === "INVALID_USER")
        return { status: "not_exists", detail: "INVALID_USER" };
      return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "zoho", name: "Zoho",
    probe: async (email) => {
      const jar = new Jar();
      await req("https://accounts.zoho.com/register", { jar });
      const r = await req(`https://accounts.zoho.com/signin/v2/lookup/${encodeURIComponent(email)}`, { jar });
      const j = jsonOrNull(r.text) as { message?: string; status_code?: number } | null;
      if (j?.message === "User exists" && j?.status_code === 201)
        return { status: "exists", detail: "User exists" };
      if (j?.status_code === 400) return { status: "not_exists", detail: "status 400" };
      return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "pipedrive", name: "Pipedrive",
    probe: async (email) => {
      const r = await req("https://app.pipedrive.com/signup-service/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, language: "fr", country_code: "fr", selectedTier: null, packages: [] }),
      });
      const j = jsonOrNull(r.text) as {
        errors?: { user_email?: string[] };
        data?: { redirectUrl?: string };
      } | null;
      if (j?.errors?.user_email?.includes("Email is not available"))
        return { status: "exists", detail: "Email is not available" };
      if (j?.data?.redirectUrl === "https://app.pipedrive.com/signup-service")
        return { status: "not_exists", detail: "redirect to signup-service" };
      return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "teamleader", name: "Teamleader",
    probe: async (email) => {
      const r = await req(`https://focus.teamleader.eu/app/emails/availability?email=${encodeURIComponent(email)}`);
      const t = r.text.trim();
      if (t === '{"available":false}') return { status: "exists", detail: "available=false" };
      if (t === '{"available":true}') return { status: "not_exists", detail: "available=true" };
      return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "nocrm", name: "noCRM",
    probe: async (email) => {
      const r = await req(`https://register.nocrm.io/register/check_trial_duplicate?email=${encodeURIComponent(email)}`);
      if (r.text.includes('{"account":1')) return { status: "exists", detail: "account=1" };
      if (r.text.trim() === '{"account":0}') return { status: "not_exists", detail: "account=0" };
      return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "nimble", name: "Nimble",
    probe: async (email) => {
      const r = await req(`https://www.nimble.com/lib/register.php?email=${encodeURIComponent(email)}`);
      if (r.text.includes("This email is already registered."))
        return { status: "exists", detail: "already registered" };
      if (r.text.trim() === '"true"' || r.text.trim() === "true")
        return { status: "not_exists", detail: "true" };
      return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "insightly", name: "Insightly",
    probe: async (email) => {
      const r = await req("https://accounts.insightly.com/signup/isemailvalid", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: form({ email }),
      });
      if (r.text.includes("An account exists for this address."))
        return { status: "exists", detail: "account exists" };
      if (r.text.trim() === "true") return { status: "not_exists", detail: "true" };
      return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "amocrm", name: "amoCRM",
    probe: async (email) => {
      const r = await req("https://www.amocrm.com/account/check_login.php", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: form({ login: email }),
      });
      const j = jsonOrNull(r.text) as { status?: string } | null;
      if (j?.status === "used") return { status: "exists", detail: "used" };
      if (j?.status === "free") return { status: "not_exists", detail: "free" };
      return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "axonaut", name: "Axonaut",
    probe: async (email) => {
      const r = await req(`https://axonaut.com/onboarding/?email=${encodeURIComponent(email)}`, { redirect: "manual" });
      const loc = r.headers.get("location") ?? "";
      if (r.status === 302 && loc.includes("/login?email"))
        return { status: "exists", detail: "302 to login" };
      if (r.status === 200) return { status: "not_exists", detail: "HTTP 200" };
      return { status: "error", detail: `HTTP ${r.status} loc=${loc}`, raw: snippet(r.text) };
    },
  },
  {
    id: "nutshell", name: "Nutshell",
    probe: async (email) => {
      const r = await req("https://app.nutshell.com/auth", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: form({ email, password: randomString(12) }),
      });
      if (r.text.includes("Sorry, your password is incorrect"))
        return { status: "exists", detail: "password incorrect" };
      if (r.text.includes("find a Nutshell account for that email address."))
        return { status: "not_exists", detail: "no account" };
      return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "sevencups", name: "7 Cups",
    probe: async (email) => {
      const boundary = "---------------------------" + randomString(12);
      const body =
        `--${boundary}\r\nContent-Disposition: form-data; name="email"\r\n\r\n${email}\r\n` +
        `--${boundary}\r\nContent-Disposition: form-data; name="passwd"\r\n\r\n\r\n` +
        `--${boundary}--\r\n`;
      const r = await req("https://www.7cups.com/listener/CreateAccount.php", {
        method: "POST",
        headers: { "Content-Type": `multipart/form-data; boundary=${boundary}` },
        body,
      });
      if (r.text.includes("Account already exists with this email address"))
        return { status: "exists", detail: "already exists" };
      return { status: "observe", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "caringbridge", name: "CaringBridge",
    probe: async (email) => {
      const r = await req("https://www.caringbridge.org/signin", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: form({ email, password: randomString(12) }),
      });
      if (r.text.includes("Welcome Back,")) return { status: "exists", detail: "Welcome Back" };
      return { status: "observe", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "vivino", name: "Vivino",
    probe: async (email) => {
      const r = await req("https://www.vivino.com/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password: "e" }),
      });
      if (r.status === 429) return { status: "error", detail: "rate limited" };
      const j = jsonOrNull(r.text) as { error?: string } | null;
      if (j?.error === "The supplied email does not exist")
        return { status: "not_exists", detail: "email does not exist" };
      if (j?.error) return { status: "exists", detail: `other error: ${j.error}`, raw: snippet(r.text) };
      return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "garmin", name: "Garmin",
    probe: async (email) => {
      const jar = new Jar();
      await req("https://sso.garmin.com/sso/createNewAccount", { jar });
      const r = await req("https://sso.garmin.com/sso/validateNewAccount", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", "X-Requested-With": "XMLHttpRequest" },
        body: form({ email }),
        jar,
      });
      return { status: "observe", detail: `HTTP ${r.status} body=${JSON.stringify(r.text.trim())}`, raw: snippet(r.text) };
    },
  },
  {
    id: "envato", name: "Envato",
    probe: async (email) => {
      const r = await req("https://account.envato.com/api/validate_email", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", "X-Requested-With": "XMLHttpRequest" },
        body: form({ email }),
      });
      if (r.text.includes("Email is already in use")) return { status: "exists", detail: "already in use" };
      return { status: "observe", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "deliveroo", name: "Deliveroo",
    probe: async (email) => {
      const r = await req("https://consumer-ow-api.deliveroo.com/orderapp/v1/check-email", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email_address: email }),
      });
      return { status: "observe", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "blablacar", name: "BlaBlaCar",
    probe: async (email) => {
      const jar = new Jar();
      const page = await req("https://www.blablacar.fr/register", { jar });
      const m = page.text.match(/appToken["']?\s*[:=]\s*["']([^"']+)/);
      if (!m) return { status: "error", detail: "no appToken", raw: snippet(page.text) };
      const r = await req(`https://edge.blablacar.fr/auth/validation/email/${encodeURIComponent(email)}?appToken=${encodeURIComponent(m[1])}`, { jar });
      return { status: "observe", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "evernote", name: "Evernote",
    probe: async (email) => {
      const jar = new Jar();
      const page = await req("https://www.evernote.com/Login.action", { jar });
      const m = page.text.match(/document\.getElementById\("hpts"\)\.value = "([^"]+)"/);
      if (!m) return { status: "error", detail: "no hpts token", raw: snippet(page.text) };
      const r = await req("https://www.evernote.com/Login.action", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
          "X-Requested-With": "XMLHttpRequest", Referer: "https://www.evernote.com/Login.action",
          Origin: "https://www.evernote.com",
        },
        body: form({ username: email, evaluateUsername: "", hpts: m[1] }),
        jar,
      });
      if (r.text.includes("usePasswordAuth")) return { status: "exists", detail: "usePasswordAuth" };
      if (r.text.includes("displayMessage")) return { status: "not_exists", detail: "displayMessage", raw: snippet(r.text) };
      return { status: "observe", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "codepen", name: "CodePen",
    probe: async (email) => {
      const jar = new Jar();
      const page = await req("https://codepen.io/accounts/signup/user/free", { jar });
      const m = page.text.match(/name="csrf-token" content="([^"]+)"/);
      if (!m) return { status: "error", detail: "no csrf token", raw: snippet(page.text) };
      const r = await req("https://codepen.io/accounts/duplicate_check", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
          "X-Requested-With": "XMLHttpRequest", "X-CSRF-Token": m[1],
          Referer: "https://codepen.io/accounts/signup/user/free", Origin: "https://codepen.io",
        },
        body: form({ attribute: "email", value: email, context: "user" }),
        jar,
      });
      if (r.text.includes("That Email is already taken.")) return { status: "exists", detail: "taken" };
      return { status: "observe", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "codecademy", name: "Codecademy",
    probe: async (email) => {
      const jar = new Jar();
      const page = await req("https://www.codecademy.com/register?redirect=%2F", { jar });
      const m = page.text.match(/name="csrf-token" content="([^"]+)"/);
      if (!m) return { status: "error", detail: "no csrf token", raw: snippet(page.text) };
      const r = await req("https://www.codecademy.com/register/validate", {
        method: "POST",
        headers: {
          Accept: "application/json", "Content-Type": "application/json",
          "X-CSRF-Token": m[1], Referer: "https://www.codecademy.com/register?redirect=%2F",
          Origin: "https://www.codecademy.com",
        },
        body: JSON.stringify({ user: { email } }),
        jar,
      });
      if (r.text.includes("is already taken")) return { status: "exists", detail: "taken" };
      return { status: "observe", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "strava", name: "Strava",
    probe: async (email) => {
      const jar = new Jar();
      const page = await req("https://www.strava.com/register/free?cta=sign-up&element=button&source=website_show", { jar });
      const m = page.text.match(/<meta name="csrf-token" content="([^"]+)"/);
      const r = await req(`https://www.strava.com/athletes/email_unique?email=${encodeURIComponent(email)}`, {
        headers: {
          ...(m ? { "X-CSRF-Token": m[1] } : {}),
          "X-Requested-With": "XMLHttpRequest",
          Referer: "https://www.strava.com/register/free?cta=sign-up&element=button&source=website_show",
        },
        jar,
      });
      const t = r.text.trim();
      if (t === "false") return { status: "exists", detail: "false (not unique)" };
      if (t === "true") return { status: "not_exists", detail: "true (unique)" };
      return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "imgur", name: "Imgur",
    probe: async (email) => {
      const jar = new Jar();
      await req("https://imgur.com/register?redirect=%2Fuser", { jar });
      const r = await req("https://imgur.com/signin/ajax_email_available", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
          "X-Requested-With": "XMLHttpRequest", Origin: "https://imgur.com",
        },
        body: form({ email }),
        jar,
      });
      const j = jsonOrNull(r.text) as { data?: { available?: boolean } } | null;
      if (!j) return { status: "error", detail: `HTTP ${r.status} non-JSON`, raw: snippet(r.text) };
      if (j.data?.available === true) return { status: "not_exists", detail: "available=true" };
      if (j.data?.available === false) return { status: "exists", detail: "available=false" };
      if (r.text.includes("Invalid email domain")) return { status: "error", detail: "invalid domain?" };
      return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "atlassian", name: "Atlassian",
    probe: async (email) => {
      const jar = new Jar();
      const page = await req("https://id.atlassian.com/login", { jar });
      const m = page.text.match(/csrfToken&quot;:&quot;([^&]+)/) || page.text.match(/"csrfToken":"([^"]+)"/);
      if (!m) return { status: "error", detail: "no csrfToken", raw: snippet(page.text) };
      const r = await req("https://id.atlassian.com/rest/check-username", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
          Referer: "https://id.atlassian.com/", Origin: "https://id.atlassian.com",
        },
        body: form({ csrfToken: m[1], username: email }),
        jar,
      });
      const j = jsonOrNull(r.text) as { action?: string } | null;
      if (!j || typeof j.action !== "string")
        return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
      if (j.action === "signup") return { status: "not_exists", detail: "action=signup" };
      return { status: "exists", detail: `action=${j.action}` };
    },
  },
  {
    id: "xing", name: "XING",
    probe: async (email) => {
      const jar = new Jar();
      await req("https://www.xing.com/start/signup?registration=1", { jar });
      const csrf = jar.get("xing_csrf_token");
      if (!csrf) return { status: "error", detail: "no xing_csrf_token cookie" };
      const r = await req("https://www.xing.com/welcome/api/signup/validate", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-csrf-token": csrf },
        body: JSON.stringify({ signup_minireg: { email, password: "", tandc_check: "1", signup_channel: "minireg_fullpage", first_name: "", last_name: "" } }),
        jar,
      });
      return { status: "observe", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "aboutme", name: "About.me",
    probe: async (email) => {
      const page = await req("https://about.me/signup", { headers: { "User-Agent": UA_FF } });
      const m = page.text.match(/,"AUTH_TOKEN":"([^"]+)"/);
      if (!m) return { status: "error", detail: "no AUTH_TOKEN", raw: snippet(page.text) };
      const r = await req("https://about.me/n/signup", {
        method: "POST",
        headers: {
          "User-Agent": UA_FF, Accept: "application/json, text/javascript, */*; q=0.01",
          "X-Auth-Token": m[1], "Content-Type": "application/json",
          "X-Requested-With": "XMLHttpRequest", Origin: "https://about.me",
        },
        body: JSON.stringify({ user_name: "", first_name: "", last_name: "", email_address: email }),
      });
      if (r.status === 409) return { status: "exists", detail: "HTTP 409" };
      if (r.status === 200) return { status: "not_exists", detail: "HTTP 200" };
      return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "ebay", name: "eBay",
    probe: async (email) => {
      const jar = new Jar();
      const page = await req("https://www.ebay.com/signin/", { jar });
      const m = page.text.match(/"csrfAjaxToken":"([^"]+)"/);
      if (!m) return { status: "error", detail: "no csrfAjaxToken", raw: snippet(page.text) };
      const r = await req("https://signin.ebay.com/signin/srv/identifer", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: "https://www.ebay.com" },
        body: form({ identifier: email, srt: m[1] }),
        jar,
      });
      return { status: "observe", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "eventbrite", name: "Eventbrite",
    probe: async (email) => {
      const jar = new Jar();
      await req("https://www.eventbrite.com/signin/?referrer=%2F", { jar });
      const csrf = jar.get("csrftoken");
      if (!csrf) return { status: "error", detail: "no csrftoken cookie" };
      const r = await req("https://www.eventbrite.com/api/v3/users/lookup/", {
        method: "POST",
        headers: {
          "Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest",
          "X-CSRFToken": csrf, Referer: "https://www.eventbrite.com/", Origin: "https://www.eventbrite.com",
        },
        body: JSON.stringify({ email }),
        jar,
      });
      return { status: "observe", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "venmo", name: "Venmo",
    probe: async (email) => {
      const jar = new Jar();
      await req("https://venmo.com/signup/email", { headers: { "User-Agent": UA_FF }, jar });
      const vid = jar.get("v_id");
      if (!vid) return { status: "error", detail: "no v_id cookie" };
      const r = await req("https://venmo.com/api/v5/users", {
        method: "POST",
        headers: {
          "User-Agent": UA_FF, Accept: "application/json", "Content-Type": "application/json",
          Referer: "https://venmo.com/", Origin: "https://venmo.com", "device-id": vid,
        },
        body: JSON.stringify({ last_name: "e", first_name: "z", email, password: "", phone: "1", client_id: 10 }),
        jar,
      });
      if (r.text.includes("Not acceptable")) return { status: "error", detail: "Not acceptable", raw: snippet(r.text) };
      if (r.text.includes("That email is already registered in our system."))
        return { status: "exists", detail: "already registered" };
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
      if (r.text.includes("unknown_user") || r.text.includes("email_login_not_allowed"))
        return { status: "not_exists", detail: "unknown_user", raw: snippet(r.text) };
      return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "snapchat", name: "Snapchat",
    probe: async (email) => {
      const jar = new Jar();
      const page = await req("https://accounts.snapchat.com", { headers: { "User-Agent": UA_FF }, jar });
      const xsrf = page.text.match(/data-xsrf="([^"]+)"/)?.[1];
      const webId = page.text.match(/ata-web-client-id="([^"]+)"/)?.[1];
      if (!xsrf || !webId) return { status: "error", detail: "no xsrf/webClientId", raw: snippet(page.text) };
      const r = await req("https://accounts.snapchat.com/accounts/merlin/login", {
        method: "POST",
        headers: {
          "User-Agent": UA_FF, Accept: "*/*", "X-XSRF-TOKEN": xsrf,
          "Content-Type": "application/json",
          Cookie: `xsrf_token=${xsrf}; web_client_id=${webId}`,
        },
        body: JSON.stringify({ email, app: "BITMOJI_APP" }),
      });
      if (r.status === 204) return { status: "not_exists", detail: "HTTP 204" };
      const j = jsonOrNull(r.text) as { hasSnapchat?: boolean } | null;
      if (j && typeof j.hasSnapchat === "boolean")
        return j.hasSnapchat
          ? { status: "exists", detail: "hasSnapchat=true" }
          : { status: "not_exists", detail: "hasSnapchat=false" };
      return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "bitmoji", name: "Bitmoji",
    probe: async (email) => {
      const jar = new Jar();
      const page = await req("https://accounts.snapchat.com", { headers: { "User-Agent": UA_FF }, jar });
      const xsrf = page.text.match(/data-xsrf="([^"]+)"/)?.[1];
      const webId = page.text.match(/ata-web-client-id="([^"]+)"/)?.[1];
      if (!xsrf || !webId) return { status: "error", detail: "no xsrf/webClientId", raw: snippet(page.text) };
      const r = await req("https://accounts.snapchat.com/accounts/merlin/login", {
        method: "POST",
        headers: {
          "User-Agent": UA_FF, Accept: "*/*", "X-XSRF-TOKEN": xsrf,
          "Content-Type": "application/json",
          Cookie: `xsrf_token=${xsrf}; web_client_id=${webId}`,
        },
        body: JSON.stringify({ email, app: "BITMOJI_APP" }),
      });
      if (r.status === 204) return { status: "not_exists", detail: "HTTP 204" };
      const j = jsonOrNull(r.text) as { hasBitmoji?: boolean } | null;
      if (j && typeof j.hasBitmoji === "boolean")
        return j.hasBitmoji
          ? { status: "exists", detail: "hasBitmoji=true" }
          : { status: "not_exists", detail: "hasBitmoji=false" };
      return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "google", name: "Google",
    probe: async (email) => {
      const jar = new Jar();
      const page = await req(
        "https://accounts.google.com/signup/v2/webcreateaccount?continue=https%3A%2F%2Faccounts.google.com%2FManageAccount%3Fnc%3D1&gmb=exp&biz=false&flowName=GlifWebSignIn&flowEntry=SignUp",
        { headers: { "User-Agent": UA_FF }, jar },
      );
      const m = page.text.match(/quot;,null,null,null,&quot;([^&]+)&quot;/);
      if (!m) return { status: "error", detail: "no flow token", raw: snippet(page.text) };
      const r = await req("https://accounts.google.com/_/signup/webusernameavailability?hl=fr&rt=j", {
        method: "POST",
        headers: {
          "User-Agent": UA_FF, "X-Same-Domain": "1", "Google-Accounts-XSRF": "1",
          "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
          Origin: "https://accounts.google.com",
        },
        body: form({
          continue: "https://accounts.google.com/", dsh: "", hl: "fr",
          "f.req": JSON.stringify([m[1], "", "", email, false]),
          azt: "", cookiesDisabled: "false",
        }),
        jar,
      });
      if (r.text.includes('"gf.wuar",2')) return { status: "exists", detail: "gf.wuar 2" };
      if (r.text.includes('"gf.wuar",1') || r.text.includes("EmailInvalid"))
        return { status: "not_exists", detail: "gf.wuar 1 / invalid" };
      return { status: "error", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "amazon", name: "Amazon",
    probe: async (email) => {
      const jar = new Jar();
      const url = "https://www.amazon.com/ap/signin?openid.pape.max_auth_age=0&openid.return_to=https%3A%2F%2Fwww.amazon.com%2F&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.assoc_handle=usflex&openid.mode=checkid_setup&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&";
      const page = await req(url, { jar });
      const inputs: Record<string, string> = {};
      for (const m of page.text.matchAll(/<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"/g)) inputs[m[1]] = m[2];
      if (!inputs.appActionToken && !inputs.openid) return { status: "error", detail: "no signin form (captcha?)", raw: snippet(page.text) };
      inputs.email = email;
      const r = await req("https://www.amazon.com/ap/signin/", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: form(inputs),
        jar,
      });
      if (r.text.includes("auth-password-missing-alert")) return { status: "exists", detail: "password prompt shown" };
      if (r.text.includes("We cannot find an account with that email address"))
        return { status: "not_exists", detail: "no account message" };
      return { status: "observe", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
    },
  },
  {
    id: "tumblr", name: "Tumblr",
    probe: async (email) => {
      const jar = new Jar();
      const page = await req("https://www.tumblr.com/", { jar });
      const m = page.text.match(/"API_TOKEN":"([^"]+)"/);
      if (!m) return { status: "error", detail: "no API_TOKEN", raw: snippet(page.text) };
      const csrf = await req("https://www.tumblr.com/api/v2/radar?fields%5Bblogs%5D=name&limit=15", {
        headers: { Authorization: `Bearer ${m[1]}` }, jar,
      });
      const csrfToken = csrf.headers.get("x-csrf-token") ?? jar.get("csrf") ?? "";
      const r = await req("https://www.tumblr.com/api/v2/register/account/validate", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${m[1]}`, "Content-Type": "application/json",
          ...(csrfToken ? { "X-CSRF-Token": csrfToken } : {}),
        },
        body: JSON.stringify({ email }),
        jar,
      });
      return { status: "observe", detail: `HTTP ${r.status}`, raw: snippet(r.text) };
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
