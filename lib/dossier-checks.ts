// Dossier section runners (Phase 7): one function per identifier type that
// runs the EXISTING checker modules and wraps the result in a DossierSection
// with a one-line summary and honest partial-error reporting. No check is
// re-implemented here — a dossier email section IS the console email check,
// a dossier domain section IS the console domain check (minus the slow
// subdomain enumeration), and so on.
//
// Dossier checks always run fresh — the route cache is deliberately not
// used, because a dossier is a point-in-time exposure report, not a
// repeated lookup. Emails are masked in the stored result before it is
// saved to the run.

import { maskIdentifier } from "./auth";
import { checkDomain } from "./domain-check";
import type { DossierSection } from "./dossier-score";
import { runFullEmailCheck } from "./email-check";
import { checkEnumChunk } from "./email-enumeration";
import { verifyVerificationToken } from "./email-verify";
import { checkIp } from "./ip-check";
import type { ResolvedKeys } from "./keys";
import { checkUsername } from "./username-check";
import { USERNAME_SITES } from "./username-sites";

export async function runEmailSection(
  email: string,
  keys: ResolvedKeys,
  enumToken?: string,
): Promise<DossierSection> {
  const enumerationAvailable = Boolean(
    process.env.RESEND_API_KEY && process.env.VERIFY_SECRET,
  );
  const base = await runFullEmailCheck(
    email,
    { hibp: keys.hibp, osintcat: keys.osintcat, github: keys.github },
    enumerationAvailable,
  );

  const partialErrors: string[] = [];
  if (base.leakcheck.status === "error") {
    partialErrors.push(`LeakCheck: ${base.leakcheck.error}`);
  }
  if (base.hudsonrock.status === "error") {
    partialErrors.push(`Hudson Rock: ${base.hudsonrock.error}`);
  }
  if (base.hibp.error) partialErrors.push(`HIBP: ${base.hibp.error}`);
  if (base.osintcat.result?.status === "error") {
    partialErrors.push(`OsintCat: ${base.osintcat.result.error}`);
  }
  if (base.github.result?.status === "error") {
    partialErrors.push(`GitHub: ${base.github.result.error}`);
  }
  if (base.mxError) partialErrors.push(`MX: ${base.mxError}`);
  if (base.auth.error) partialErrors.push(`Email auth: ${base.auth.error}`);

  // Optional enumeration (7 probes, 1 chunk) — only with a valid
  // ownership token for this email. An invalid token skips enumeration
  // honestly; it never runs probes without proof of ownership.
  let enumResults;
  if (enumToken) {
    const secret = process.env.VERIFY_SECRET;
    if (secret && verifyVerificationToken(secret, email, enumToken)) {
      enumResults = await checkEnumChunk(email, 0);
    } else {
      partialErrors.push(
        "The enumeration token was invalid or expired — enumeration was skipped.",
      );
    }
  }

  const githubLogins =
    base.github.result?.status === "ok"
      ? base.github.result.logins
      : undefined;

  const parts: string[] = [];
  if (base.leakcheck.status === "ok" && base.leakcheck.found > 0) {
    parts.push(
      `${base.leakcheck.found} breach record${base.leakcheck.found === 1 ? "" : "s"}`,
    );
  }
  if (base.hudsonrock.status === "ok" && base.hudsonrock.associated) {
    parts.push("infostealer exposed");
  }
  if (base.github.result?.status === "ok" && base.github.result.total > 0) {
    parts.push(`${base.github.result.total} public commits`);
  }
  if (enumResults) {
    const exists = enumResults.sites.filter(
      (r) => r.status === "exists",
    ).length;
    if (exists > 0) parts.push(`on ${exists} probed sites`);
  }
  // The auth grade is notable on its own when it is weak; a clean email
  // with a strong grade just says so.
  const weakAuth = ["F", "D", "C"].includes(base.auth.grade);
  const summary =
    parts.length > 0 || weakAuth
      ? [...parts, `Auth ${base.auth.grade}`].join(" · ")
      : "No exposure found";

  return {
    type: "email",
    display: maskIdentifier("email", email),
    status: partialErrors.length > 0 ? "partial" : "ok",
    checkedAt: new Date().toISOString(),
    summary,
    result: {
      ...base,
      email: maskIdentifier("email", email),
      ...(enumResults ? { enumResults } : {}),
      ...(githubLogins ? { githubLogins } : {}),
    },
    ...(partialErrors.length > 0 ? { partialErrors } : {}),
  };
}

export async function runUsernameSection(
  username: string,
): Promise<DossierSection> {
  // All 256 sites, in the same two slices the console uses (150 + 106),
  // run in parallel in this one invocation.
  const [first, second] = await Promise.all([
    checkUsername(username, USERNAME_SITES.slice(0, 150)),
    checkUsername(username, USERNAME_SITES.slice(150)),
  ]);
  const sites = [...first.sites, ...second.sites];
  const found = sites.filter((s) => s.status === "found").length;
  const notFound = sites.filter((s) => s.status === "not_found").length;
  const errors = sites.filter((s) => s.status === "error").length;

  const parts = [`Found on ${found} of ${sites.length} sites`];
  if (errors > 0) parts.push(`${errors} checks failed`);
  return {
    type: "username",
    display: username,
    status: errors > 0 ? "partial" : "ok",
    checkedAt: new Date().toISOString(),
    summary: parts.join(" · "),
    result: {
      username,
      checkedAt: first.checkedAt,
      sites,
      summary: { found, notFound, errors },
    },
    ...(errors > 0
      ? { partialErrors: [`${errors} site checks failed (network errors).`] }
      : {}),
  };
}

export async function runDomainSection(
  domain: string,
  keys: ResolvedKeys,
): Promise<DossierSection> {
  const result = await checkDomain(domain, {
    otxApiKey: keys.otx,
    includeSubdomains: false,
  });

  const partialErrors: string[] = [];
  if (!result.tls.ok && result.tls.error) {
    partialErrors.push(`TLS: ${result.tls.error}`);
  }
  if (!result.headers.ok && result.headers.error) {
    partialErrors.push(`Headers: ${result.headers.error}`);
  }
  if (!result.rdap.ok && result.rdap.error) {
    partialErrors.push(`RDAP: ${result.rdap.error}`);
  }
  const dnsErrors = Object.entries(result.dns.errors);
  if (dnsErrors.length > 0) {
    partialErrors.push(
      `DNS: ${dnsErrors.map(([k, v]) => `${k} (${v})`).join(", ")}`,
    );
  }

  const parts: string[] = [`Auth ${result.emailAuth.grade}`];
  const daysLeft = result.tls.daysUntilExpiry;
  if (daysLeft !== undefined) {
    parts.push(
      daysLeft < 0 ? "TLS expired" : `TLS ${daysLeft}d left`,
    );
  }
  const listed = result.dnsbl.lists.filter((l) => l.listed === true).length;
  if (listed > 0) parts.push(`Listed on ${listed} blocklists`);
  parts.push(`Headers ${result.headers.grade}`);

  return {
    type: "domain",
    display: domain,
    status: partialErrors.length > 0 ? "partial" : "ok",
    checkedAt: new Date().toISOString(),
    summary: parts.join(" · "),
    result,
    ...(partialErrors.length > 0 ? { partialErrors } : {}),
  };
}

export async function runIpSection(
  ip: string,
  keys: ResolvedKeys,
): Promise<DossierSection> {
  const result = await checkIp(ip, { abuseIpDbKey: keys.abuseipdb });

  const partialErrors: string[] = [];
  if (!result.geo.ok && result.geo.error) {
    partialErrors.push(`Geo: ${result.geo.error}`);
  }
  if (result.tor.error) partialErrors.push(`Tor: ${result.tor.error}`);
  if (result.abuseipdb.result?.error) {
    partialErrors.push(`AbuseIPDB: ${result.abuseipdb.result.error}`);
  }

  const parts: string[] = [];
  if (result.geo.country) parts.push(result.geo.country);
  const org = result.geo.org ?? result.geo.isp;
  if (org) parts.push(org);
  const abuse = result.abuseipdb.result?.abuseConfidenceScore;
  if (abuse !== undefined) parts.push(`AbuseIPDB ${abuse}%`);
  if (result.tor.isExitNode === true) parts.push("Tor exit node");

  return {
    type: "ip",
    display: ip,
    status: partialErrors.length > 0 ? "partial" : "ok",
    checkedAt: new Date().toISOString(),
    summary: parts.length > 0 ? parts.join(" · ") : "Checked",
    result,
    ...(partialErrors.length > 0 ? { partialErrors } : {}),
  };
}
