// Free email checks: MX records (does the domain accept mail?) and a
// disposable-domain note. The HIBP breach lookup lives in the email route
// and only runs when HIBP_API_KEY is configured.

import dns from "node:dns/promises";
import { friendlyDnsError } from "./domain-check";

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
