// Free email checks: MX records (does the domain accept mail?) and a
// disposable-domain note. runFullEmailCheck runs the whole email check
// (free sources + keyed sources when their keys are passed in) and is
// shared by the email route and the dossier section runner — one
// implementation, so a dossier email section is exactly the console check.

import dns from "node:dns/promises";
import type { EmailCheckResponse } from "./api-types";
import { friendlyDnsError } from "./domain-check";
import { checkEmailAuth } from "./email-auth";
import {
  fetchHudsonRock,
  fetchLeakCheck,
  fetchOsintCat,
  type HudsonRockResult,
  type LeakCheckResult,
  type OsintCatResult,
} from "./email-breach";
import {
  searchGitHubCommits,
  type GitHubExposureResult,
} from "./github-exposure";
import { fetchBreachesForEmail, type HibpBreachMeta } from "./hibp";

// Small built-in list of well-known disposable providers. This is a limited
// list, not a comprehensive blocklist — the UI says so.
const DISPOSABLE_DOMAINS = new Set([
  "mailinator.com",
  "guerrillamail.com",
  "10minutemail.com",
  "tempmail.com",
  "temp-mail.org",
  "yopmail.com",
  "throwawaymail.com",
  "fakeinbox.com",
  "trashmail.com",
  "sharklasers.com",
  "getnada.com",
  "maildrop.cc",
  "mohmal.com",
  "mintemail.com",
  "mytemp.email",
  "tempail.com",
  "dispostable.com",
  "emailondeck.com",
  "spamgourmet.com",
  "anonymbox.com",
]);

export interface EmailMxResult {
  mx: { exchange: string; priority: number }[];
  mxOk: boolean;
  mxError?: string;
  disposable: boolean;
}

export async function checkEmailMx(domain: string): Promise<EmailMxResult> {
  const disposable = DISPOSABLE_DOMAINS.has(domain);
  try {
    const mx = await Promise.race([
      dns.resolveMx(domain),
      new Promise<never>((_resolve, reject) =>
        setTimeout(() => reject(new Error("MX lookup timed out")), 5000),
      ),
    ]);
    const sorted = [...mx].sort((a, b) => a.priority - b.priority);
    return { mx: sorted, mxOk: sorted.length > 0, disposable };
  } catch (err) {
    const message = friendlyDnsError(err);
    return {
      mx: [],
      mxOk: false,
      ...(message ? { mxError: message } : {}),
      disposable,
    };
  }
}

export interface EmailCheckKeys {
  hibp?: string;
  osintcat?: string;
  github?: string;
}

/** The full email check: MX records, SPF/DKIM/DMARC grading, LeakCheck
 *  breach index, Hudson Rock infostealer exposure, plus the keyed checks
 *  (HIBP, OsintCat, GitHub) when their keys are passed in. Keyed sources
 *  without a key report a needs-key state instead of a fake result. Every
 *  source is independent: one failing source never fails the check. */
export async function runFullEmailCheck(
  email: string,
  keys: EmailCheckKeys,
  enumerationAvailable: boolean,
): Promise<EmailCheckResponse> {
  const domain = email.split("@")[1];
  const [mxResult, authResult, leakcheck, hudsonrock, hibp, osintcat, github] =
    await Promise.all([
      checkEmailMx(domain),
      checkEmailAuth(domain),
      fetchLeakCheck(email),
      fetchHudsonRock(email),
      (async (): Promise<
        | {
            available: true;
            rateLimited?: boolean;
            breaches?: HibpBreachMeta[];
            error?: string;
          }
        | { available: false }
      > => {
        if (!keys.hibp) return { available: false as const };
        // A bad key (or a HIBP outage) must not fail the whole check:
        // it surfaces as an honest error on the HIBP source instead.
        try {
          const breaches = await fetchBreachesForEmail(email, keys.hibp);
          if (breaches.status === "rate_limited") {
            return { available: true as const, rateLimited: true as const };
          }
          return { available: true as const, breaches: breaches.breaches };
        } catch (err) {
          const message =
            err instanceof Error ? err.message : "HIBP lookup failed";
          return {
            available: true as const,
            error: message.includes("401")
              ? "The HIBP API key was rejected. Check the key (or the saved BYOK key) and try again."
              : message,
          };
        }
      })(),
      (async (): Promise<{
        available: boolean;
        result?: OsintCatResult;
      }> => {
        if (!keys.osintcat) return { available: false };
        return {
          available: true,
          result: await fetchOsintCat(email, keys.osintcat),
        };
      })(),
      (async (): Promise<{
        available: boolean;
        result?: GitHubExposureResult;
      }> => {
        if (!keys.github) return { available: false };
        return {
          available: true,
          result: await searchGitHubCommits(email, keys.github),
        };
      })(),
    ]);

  return {
    email,
    domain,
    checkedAt: new Date().toISOString(),
    mx: mxResult.mx,
    mxOk: mxResult.mxOk,
    mxError: mxResult.mxError,
    disposable: mxResult.disposable,
    hibp,
    auth: authResult,
    leakcheck: leakcheck as LeakCheckResult,
    osintcat,
    hudsonrock: hudsonrock as HudsonRockResult,
    github,
    enumeration: { available: enumerationAvailable },
  };
}
