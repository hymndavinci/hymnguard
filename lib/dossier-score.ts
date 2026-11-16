// Dossier scoring (Phase 7): pure functions that turn completed dossier
// sections into an exposure score (0–100), findings, prioritized
// remediation steps, and cross-references between the user's identifiers.
//
// The score is a weighted exposure measure, not a vulnerability rating:
// breach records and infostealer exposure weigh heaviest; surface (sites
// where a username is registered, headers) weighs least. Every finding
// carries its points so the score is explainable — nothing is a black box.
// Each domain's email-auth grade is counted once per dossier (an email
// section and a domain section grading the same domain would otherwise
// double-count).

import type {
  DomainCheckResult,
  EmailCheckResponse,
  EnumChunkResult,
  IpCheckResult,
  UsernameCheckResult,
} from "./api-types";

export type DossierIdentifierType = "email" | "username" | "domain" | "ip";

/** One identifier's completed (or failed) checker run inside a dossier. */
export interface DossierSection {
  type: DossierIdentifierType;
  /** Masked for emails, raw for username/domain/IP. */
  display: string;
  status: "ok" | "partial" | "error";
  checkedAt: string;
  /** One-line human summary, e.g. "6 breach records · Auth C". */
  summary: string;
  result:
    | (EmailCheckResponse & {
        enumResults?: EnumChunkResult;
        githubLogins?: string[];
      })
    | UsernameCheckResult
    | DomainCheckResult
    | IpCheckResult
    | null;
  error?: string;
  /** Sub-checks that errored while the rest succeeded (honest partials). */
  partialErrors?: string[];
}

export interface DossierFinding {
  id: string;
  identifier: string;
  identifierType: DossierIdentifierType;
  severity: "high" | "medium" | "low" | "info";
  points: number;
  title: string;
  detail: string;
  remediation?: string;
  remediationPriority?: 1 | 2 | 3;
}

export interface DossierRemediation {
  action: string;
  priority: 1 | 2 | 3;
  findingIds: string[];
}

export type DossierBand = "Low" | "Moderate" | "High" | "Critical";

export interface DossierReport {
  score: number;
  band: DossierBand;
  findings: DossierFinding[];
  remediations: DossierRemediation[];
  crossRefs: string[];
  computedAt: string;
}

const RESET_PASSWORD =
  "Change the password for this email — and anywhere you reused it — then turn on two-factor authentication.";
const INFOSTEALER =
  "This email appears in infostealer logs: change its passwords from a clean device, review active sessions, and scan for malware.";
const DORMANT_ACCOUNTS =
  "Review accounts on sites you no longer use and close dormant ones.";

function bandFor(score: number): DossierBand {
  if (score >= 65) return "Critical";
  if (score >= 40) return "High";
  if (score >= 20) return "Moderate";
  return "Low";
}

function authGradePoints(grade: string): number {
  switch (grade) {
    case "F":
      return 10;
    case "D":
      return 8;
    case "C":
      return 5;
    case "B":
      return 2;
    default:
      return 0;
  }
}

function authGradeSeverity(grade: string): DossierFinding["severity"] {
  if (grade === "F" || grade === "D") return "high";
  if (grade === "C") return "medium";
  if (grade === "B") return "low";
  return "info";
}

/**
 * Computes the dossier report from completed sections plus the raw
 * identifier values (server-only — needed to cross-reference, e.g. a
 * username against an email's local-part; only display strings ever land
 * in the stored report).
 */
export function computeDossierReport(
  sections: DossierSection[],
  identifiers: { type: DossierIdentifierType; value: string }[],
): DossierReport {
  const findings: DossierFinding[] = [];
  const add = (f: Omit<DossierFinding, "id">) => {
    findings.push({ ...f, id: `finding-${findings.length}` });
  };

  // Email-auth grades are deduped by domain: an email section and a domain
  // section grading the same domain must not double-count. Collect first,
  // score each unique domain once (from the first section that has it).
  const authGrades = new Map<
    string,
    {
      grade: string;
      score: number;
      detail: string;
      identifier: string;
      identifierType: DossierIdentifierType;
    }
  >();
  const collectAuth = (
    section: DossierSection,
    auth: {
      grade: string;
      score: number;
      domain: string;
      spf: { present: boolean };
      dmarc: { present: boolean; policy?: string };
      dkim: { present: boolean };
    },
  ) => {
    if (authGrades.has(auth.domain)) return;
    const missing = [
      !auth.spf.present && "SPF",
      !auth.dmarc.present && "DMARC",
      !auth.dkim.present && "DKIM",
    ].filter((x): x is string => Boolean(x));
    let detail = `Score ${auth.score}/100.`;
    if (missing.length > 0) detail += ` Missing: ${missing.join(", ")}.`;
    else if (auth.dmarc.policy === "none") {
      detail += " DMARC policy is p=none (monitor-only).";
    }
    authGrades.set(auth.domain, {
      grade: auth.grade,
      score: auth.score,
      detail,
      identifier: section.display,
      identifierType: section.type,
    });
  };

  for (const section of sections) {
    if (!section.result || section.status === "error") continue;

    if (section.type === "email") {
      const r = section.result as EmailCheckResponse & {
        enumResults?: EnumChunkResult;
        githubLogins?: string[];
      };

      if (r.leakcheck.status === "ok" && r.leakcheck.found > 0) {
        const sources = [...new Set(r.leakcheck.sources.map((s) => s.name))]
          .slice(0, 5)
          .join(", ");
        add({
          identifier: section.display,
          identifierType: "email",
          severity: "high",
          points: Math.min(5 * r.leakcheck.found, 30),
          title: `${r.leakcheck.found} breach record${r.leakcheck.found === 1 ? "" : "s"} (LeakCheck)`,
          detail: sources
            ? `Sources: ${sources}${r.leakcheck.sources.length > 5 ? ", and more" : ""}.`
            : "Found in breach data.",
          remediation: RESET_PASSWORD,
          remediationPriority: 1,
        });
      }

      const hibpBreaches = r.hibp.breaches ?? [];
      if (hibpBreaches.length > 0) {
        const names = hibpBreaches
          .map((b) => b.name)
          .slice(0, 5)
          .join(", ");
        add({
          identifier: section.display,
          identifierType: "email",
          severity: "high",
          points: Math.min(5 * hibpBreaches.length, 25),
          title: `${hibpBreaches.length} breach${hibpBreaches.length === 1 ? "" : "es"} (Have I Been Pwned)`,
          detail: `Breaches: ${names}.`,
          remediation: RESET_PASSWORD,
          remediationPriority: 1,
        });
      }

      if (
        r.osintcat.result?.status === "ok" &&
        r.osintcat.result.total > 0
      ) {
        add({
          identifier: section.display,
          identifierType: "email",
          severity: "high",
          points: Math.min(3 * r.osintcat.result.total, 15),
          title: `${r.osintcat.result.total} infostealer record${r.osintcat.result.total === 1 ? "" : "s"} (OsintCat)`,
          detail: "This email appears in stealer-log data.",
          remediation: INFOSTEALER,
          remediationPriority: 1,
        });
      }

      if (r.hudsonrock.status === "ok" && r.hudsonrock.associated) {
        const count = r.hudsonrock.stealers.length;
        add({
          identifier: section.display,
          identifierType: "email",
          severity: "high",
          points: 20,
          title: "Exposed in infostealer logs (Hudson Rock)",
          detail:
            count > 0
              ? `Associated with ${count} infected computer${count === 1 ? "" : "s"}.`
              : "Associated with infected computers.",
          remediation: INFOSTEALER,
          remediationPriority: 1,
        });
      }

      if (
        r.github.result?.status === "ok" &&
        r.github.result.total > 0
      ) {
        const repos = [
          ...new Set(r.github.result.commits.map((c) => c.repo)),
        ]
          .slice(0, 5)
          .join(", ");
        add({
          identifier: section.display,
          identifierType: "email",
          severity: "medium",
          points: Math.min(2 * r.github.result.total, 10),
          title: `Email in ${r.github.result.total} public commit${r.github.result.total === 1 ? "" : "s"}`,
          detail: repos ? `Repositories: ${repos}.` : "",
          remediation:
            "Remove this email from public git history — rewrite the history or switch to a GitHub noreply address.",
          remediationPriority: 2,
        });
      }

      if (r.enumResults) {
        const found = r.enumResults.sites.filter(
          (x) => x.status === "exists",
        );
        if (found.length > 0) {
          add({
            identifier: section.display,
            identifierType: "email",
            severity: "low",
            points: Math.min(found.length, 7),
            title: `Registered on ${found.length} of ${r.enumResults.sites.length} probed sites`,
            detail: found.map((x) => x.name).join(", "),
            remediation: DORMANT_ACCOUNTS,
            remediationPriority: 3,
          });
        }
      }

      if (!r.mxOk) {
        add({
          identifier: section.display,
          identifierType: "email",
          severity: "low",
          points: 3,
          title: "No MX records",
          detail: "This domain cannot receive email.",
        });
      }

      collectAuth(section, r.auth);
    }

    if (section.type === "username") {
      const r = section.result as UsernameCheckResult;
      const found = r.summary.found;
      if (found > 0) {
        add({
          identifier: section.display,
          identifierType: "username",
          severity: "low",
          points: Math.min(found, 10),
          title: `Found on ${found} of ${r.sites.length} sites`,
          detail: r.sites
            .filter((s) => s.status === "found")
            .map((s) => s.name)
            .slice(0, 8)
            .join(", "),
          remediation: DORMANT_ACCOUNTS,
          remediationPriority: 3,
        });
      }
    }

    if (section.type === "domain") {
      const r = section.result as DomainCheckResult;

      const listed = r.dnsbl.lists.filter((x) => x.listed === true);
      if (listed.length > 0) {
        add({
          identifier: section.display,
          identifierType: "domain",
          severity: "high",
          points: 15,
          title: `Listed on ${listed.length} blocklist${listed.length === 1 ? "" : "s"}`,
          detail: listed.map((x) => x.name).join(", "),
          remediation:
            "Find out why this domain is listed, fix the cause, then request delisting.",
          remediationPriority: 2,
        });
      }

      const daysLeft = r.tls.daysUntilExpiry;
      if (daysLeft !== undefined && daysLeft < 0) {
        add({
          identifier: section.display,
          identifierType: "domain",
          severity: "high",
          points: 15,
          title: "TLS certificate expired",
          detail: r.tls.issuer ? `Issuer: ${r.tls.issuer}.` : "",
          remediation: "Renew the TLS certificate.",
          remediationPriority: 2,
        });
      } else if (
        daysLeft !== undefined &&
        daysLeft >= 0 &&
        daysLeft < 30
      ) {
        add({
          identifier: section.display,
          identifierType: "domain",
          severity: "medium",
          points: 5,
          title: `TLS certificate expires in ${daysLeft} day${daysLeft === 1 ? "" : "s"}`,
          detail: r.tls.issuer ? `Issuer: ${r.tls.issuer}.` : "",
          remediation: "Renew the TLS certificate.",
          remediationPriority: 2,
        });
      }

      if (r.headers.grade === "F" || r.headers.grade === "D") {
        const missing = r.headers.headers
          .filter((h) => !h.present)
          .map((h) => h.name);
        add({
          identifier: section.display,
          identifierType: "domain",
          severity: "low",
          points: r.headers.grade === "F" ? 5 : 3,
          title: `Security headers grade ${r.headers.grade}`,
          detail:
            missing.length > 0
              ? `Missing: ${missing.slice(0, 6).join(", ")}.`
              : "",
          remediation:
            "Add the missing security headers (Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, and the rest).",
          remediationPriority: 3,
        });
      }

      if (r.rdap.ok && r.rdap.expiresAt) {
        const days = Math.ceil(
          (new Date(r.rdap.expiresAt).getTime() - Date.now()) / 86_400_000,
        );
        if (days < 30) {
          add({
            identifier: section.display,
            identifierType: "domain",
            severity: "medium",
            points: 5,
            title:
              days < 0
                ? "Domain registration expired"
                : `Domain expires in ${days} day${days === 1 ? "" : "s"}`,
            detail: `Registered until ${r.rdap.expiresAt.slice(0, 10)}.`,
            remediation: "Renew the domain registration.",
            remediationPriority: 2,
          });
        }
      }

      collectAuth(section, r.emailAuth);
    }

    if (section.type === "ip") {
      const r = section.result as IpCheckResult;
      const abuse = r.abuseipdb.result;
      const score = abuse?.abuseConfidenceScore;
      if (abuse?.ok && score !== undefined && score > 0) {
        add({
          identifier: section.display,
          identifierType: "ip",
          severity: score >= 50 ? "high" : score >= 25 ? "medium" : "low",
          points: score >= 50 ? 15 : score >= 25 ? 10 : 5,
          title: `AbuseIPDB score ${score}%`,
          detail:
            abuse.totalReports !== undefined
              ? `${abuse.totalReports} report${abuse.totalReports === 1 ? "" : "s"}.`
              : "",
          remediation:
            "Check why this IP is reported — shared and VPN IPs inherit other users' reports.",
          remediationPriority: 2,
        });
      }
      if (r.tor.isExitNode === true) {
        add({
          identifier: section.display,
          identifierType: "ip",
          severity: "low",
          points: 5,
          title: "Tor exit node",
          detail: "This IP is currently a Tor exit node.",
        });
      }
    }
  }

  // Auth-grade findings (deduped by domain, scored once each).
  for (const [domain, a] of authGrades) {
    const points = authGradePoints(a.grade);
    if (points === 0) continue;
    add({
      identifier: a.identifier,
      identifierType: a.identifierType,
      severity: authGradeSeverity(a.grade),
      points,
      title: `Email authentication grade ${a.grade} (${domain})`,
      detail: a.detail,
      remediation:
        a.grade === "F" || a.grade === "D"
          ? `Strengthen email authentication for ${domain} (SPF + DKIM + a DMARC policy).`
          : undefined,
      remediationPriority:
        a.grade === "F" || a.grade === "D" ? 2 : undefined,
    });
  }

  // Cross-references between the user's own identifiers.
  const crossRefs: string[] = [];
  const emails = identifiers.filter((i) => i.type === "email");
  const usernames = identifiers.filter((i) => i.type === "username");
  const domains = identifiers.filter((i) => i.type === "domain");
  for (const email of emails) {
    const localPart = email.value.split("@")[0].toLowerCase();
    const mailDomain = email.value.split("@")[1]?.toLowerCase();
    for (const u of usernames) {
      if (u.value.toLowerCase() === localPart) {
        crossRefs.push(
          `Username ${u.value} is the local-part of ${maskEmail(email.value)}.`,
        );
      }
    }
    for (const d of domains) {
      if (mailDomain && d.value.toLowerCase() === mailDomain) {
        crossRefs.push(
          `Domain ${d.value} is the mail domain of ${maskEmail(email.value)}.`,
        );
      }
    }
    const section = sections.find(
      (s) =>
        s.type === "email" && s.display === maskEmail(email.value),
    );
    if (section?.result && section.type === "email") {
      const logins = (
        section.result as { githubLogins?: string[] }
      ).githubLogins;
      if (logins) {
        for (const login of logins) {
          const match = usernames.find(
            (u) => u.value.toLowerCase() === login.toLowerCase(),
          );
          if (match) {
            crossRefs.push(
              `${maskEmail(email.value)} appears in public commits by GitHub user ${login}.`,
            );
          }
        }
      }
    }
  }

  const score = Math.min(
    100,
    findings.reduce((sum, f) => sum + f.points, 0),
  );

  const severityOrder = { high: 0, medium: 1, low: 2, info: 3 };
  findings.sort(
    (a, b) =>
      severityOrder[a.severity] - severityOrder[b.severity] ||
      b.points - a.points,
  );
  // Re-number ids after sorting so they stay stable and readable.
  findings.forEach((f, i) => {
    f.id = `finding-${i}`;
  });

  // Remediation steps, deduplicated by action text (e.g. LeakCheck and
  // HIBP both say "change the password"), sorted by priority then by the
  // points of the findings they address.
  const byAction = new Map<
    string,
    { priority: 1 | 2 | 3; findingIds: string[]; points: number }
  >();
  for (const f of findings) {
    if (!f.remediation || !f.remediationPriority) continue;
    const existing = byAction.get(f.remediation);
    if (existing) {
      existing.findingIds.push(f.id);
      existing.points += f.points;
      existing.priority = Math.min(
        existing.priority,
        f.remediationPriority,
      ) as 1 | 2 | 3;
    } else {
      byAction.set(f.remediation, {
        priority: f.remediationPriority,
        findingIds: [f.id],
        points: f.points,
      });
    }
  }
  const remediations: DossierRemediation[] = [...byAction.entries()]
    .map(([action, v]) => ({
      action,
      priority: v.priority,
      findingIds: v.findingIds,
      points: v.points,
    }))
    .sort((a, b) => a.priority - b.priority || b.points - a.points)
    .map(({ action, priority, findingIds }) => ({
      action,
      priority,
      findingIds,
    }));

  return {
    score,
    band: bandFor(score),
    findings,
    remediations,
    crossRefs: [...new Set(crossRefs)],
    computedAt: new Date().toISOString(),
  };
}

/** Masks an email the same way lib/auth maskIdentifier does, kept local so
 *  this module stays dependency-free (pure, unit-testable). */
function maskEmail(email: string): string {
  const at = email.indexOf("@");
  if (at <= 0) return "***";
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  const head = local.length >= 2 ? local.slice(0, 2) : local.slice(0, 1);
  return `${head}***@${domain}`;
}
