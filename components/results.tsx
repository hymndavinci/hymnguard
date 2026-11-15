// Result renderers for each check type. Pure presentational components.
// Client component: the username result has interactive search/filter state.

"use client";

import { useMemo, useState } from "react";
import type {
  DomainCheckResult,
  EmailCheckResponse,
  HashCheckResult,
  IpCheckResult,
  PhoneCheckResult,
  UrlCheckResult,
  UsernameCheckResult,
  WalletCheckResult,
} from "@/lib/api-types";
import type { ImageExifResult } from "@/lib/image-exif";
import EmailEnumeration from "./email-enumeration";

function formatNumber(value: number): string {
  return value.toLocaleString("en-US");
}

function formatDate(iso?: string): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function CheckIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M20 6L9 17l-5-5" />
    </svg>
  );
}

function XIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" aria-hidden="true">
      <path d="M18 6L6 18M6 6l12 12" />
    </svg>
  );
}

function ExternalIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
      <path d="M15 3h6v6" />
      <path d="M10 14L21 3" />
    </svg>
  );
}

type Tone = "ok" | "danger" | "warning" | "info";

const TONE_STYLES: Record<Tone, { box: string; dot: string }> = {
  ok: { box: "border-green-200 bg-green-50 text-green-900", dot: "bg-green-500" },
  danger: { box: "border-red-200 bg-red-50 text-red-900", dot: "bg-red-500" },
  warning: { box: "border-amber-200 bg-amber-50 text-amber-900", dot: "bg-amber-500" },
  info: { box: "border-gray-200 bg-gray-50 text-gray-900", dot: "bg-gray-400" },
};

export function Verdict({
  tone,
  title,
  children,
}: {
  tone: Tone;
  title: string;
  children?: React.ReactNode;
}) {
  const styles = TONE_STYLES[tone];
  return (
    <div className={`rounded-lg border px-4 py-3.5 ${styles.box}`}>
      <div className="flex items-center gap-2">
        <span className={`h-2 w-2 shrink-0 rounded-full ${styles.dot}`} />
        <p className="text-sm font-semibold">{title}</p>
      </div>
      {children ? (
        <div className="mt-1.5 pl-4 text-[13px] leading-relaxed opacity-90">
          {children}
        </div>
      ) : null}
    </div>
  );
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <h3 className="text-sm font-semibold tracking-tight">{children}</h3>
  );
}

function StatGrid({ items }: { items: { label: string; value: string }[] }) {
  return (
    <div className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-gray-200 bg-gray-200 sm:grid-cols-3">
      {items.map((item) => (
        <div key={item.label} className="bg-white px-3.5 py-3">
          <p className="text-xs text-gray-500">{item.label}</p>
          <p className="mt-0.5 truncate font-mono text-sm font-medium" title={item.value}>
            {item.value}
          </p>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------- password

export function PasswordResult({ count }: { count: number }) {
  if (count > 0) {
    return (
      <Verdict
        tone="danger"
        title={`Pwned — seen ${formatNumber(count)} time${count === 1 ? "" : "s"} in data breaches`}
      >
        <p>
          This password has appeared in known data breaches. Do not use it
          anywhere — change it on every account that shares it, and use a
          unique password per account.
        </p>
        <p className="mt-1.5 text-xs opacity-75">
          Checked against Have I Been Pwned (Pwned Passwords) using
          k-anonymity: the password was hashed in your browser and only the
          first 5 characters of the hash were sent.
        </p>
      </Verdict>
    );
  }
  return (
    <Verdict tone="ok" title="Not found in known data breaches">
      <p>
        This password does not appear in the Have I Been Pwned breach corpus.
        That means it has not leaked — it does not mean it is strong. Long,
        unique passwords per account are still the rule.
      </p>
      <p className="mt-1.5 text-xs opacity-75">
        Checked against Have I Been Pwned (Pwned Passwords) using
        k-anonymity: the password was hashed in your browser and only the
        first 5 characters of the hash were sent.
      </p>
    </Verdict>
  );
}

// ---------------------------------------------------------------- username

type UsernameFilter = "all" | "found" | "not_found" | "error";

const FILTER_LABELS: Record<UsernameFilter, string> = {
  all: "All",
  found: "Found",
  not_found: "Not found",
  error: "Errors",
};

export function UsernameResult({
  data,
  progress,
}: {
  data: UsernameCheckResult;
  progress?: { checked: number; total: number };
}) {
  const [filter, setFilter] = useState<UsernameFilter>("all");
  const [query, setQuery] = useState("");

  const ordered = useMemo(
    () =>
      [...data.sites].sort((a, b) => {
        const rank = (s: string) =>
          s === "found" ? 0 : s === "not_found" ? 1 : 2;
        return rank(a.status) - rank(b.status) || a.name.localeCompare(b.name);
      }),
    [data.sites],
  );

  const counts = useMemo(
    () => ({
      all: ordered.length,
      found: ordered.filter((s) => s.status === "found").length,
      not_found: ordered.filter((s) => s.status === "not_found").length,
      error: ordered.filter((s) => s.status === "error").length,
    }),
    [ordered],
  );

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return ordered.filter((site) => {
      if (filter !== "all" && site.status !== filter) return false;
      if (q && !site.name.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [ordered, filter, query]);

  const totalSites = progress?.total ?? data.sites.length;

  return (
    <div className="space-y-5">
      {progress ? (
        <div className="space-y-2">
          <div className="flex items-baseline justify-between gap-2">
            <p className="text-[13px] text-gray-600">
              Checking… {progress.checked} of {progress.total} sites
            </p>
            <p className="font-mono text-xs text-gray-500">
              {Math.round((progress.checked / progress.total) * 100)}%
            </p>
          </div>
          <div className="h-1.5 overflow-hidden rounded-full bg-gray-100">
            <div
              className="h-full rounded-full bg-black transition-all duration-300"
              style={{ width: `${(progress.checked / progress.total) * 100}%` }}
            />
          </div>
        </div>
      ) : null}

      <StatGrid
        items={[
          { label: "Accounts found", value: String(data.summary.found) },
          { label: "Not found", value: String(data.summary.notFound) },
          { label: "Errors", value: String(data.summary.errors) },
        ]}
      />

      <div>
        <SectionTitle>
          {data.summary.found > 0
            ? `“${data.username}” exists on ${data.summary.found} of ${totalSites} checked sites`
            : progress
              ? `Checking “${data.username}” across ${totalSites} sites…`
              : `“${data.username}” was not found on any checked site`}
        </SectionTitle>
        <p className="mt-1 text-[13px] text-gray-500">
          {data.summary.errors > 0
            ? `${data.summary.errors} site${data.summary.errors === 1 ? "" : "s"} could not be checked (blocked or rate-limited) — those are inconclusive, not “not found”.`
            : "Every site responded."}
        </p>
      </div>

      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="inline-flex max-w-full gap-1 overflow-x-auto rounded-lg bg-gray-100 p-1">
          {(Object.keys(FILTER_LABELS) as UsernameFilter[]).map((key) => (
            <button
              key={key}
              onClick={() => setFilter(key)}
              aria-pressed={filter === key}
              className={`whitespace-nowrap rounded-md px-3 py-1.5 text-[13px] font-medium transition-all ${
                filter === key
                  ? "bg-white text-black shadow-sm ring-1 ring-gray-200"
                  : "text-gray-500 hover:text-black"
              }`}
            >
              {FILTER_LABELS[key]}{" "}
              <span className="font-mono text-xs text-gray-400">
                {counts[key]}
              </span>
            </button>
          ))}
        </div>
        <input
          type="text"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Search sites…"
          aria-label="Search sites by name"
          autoComplete="off"
          spellCheck={false}
          className="h-9 w-full rounded-md border border-gray-300 bg-white px-3 text-sm text-black outline-none transition-colors placeholder:text-gray-500 focus:border-black sm:w-56"
        />
      </div>

      <div className="overflow-hidden rounded-lg border border-gray-200">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-200 bg-gray-50 text-left">
              <th className="px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500">
                Site
              </th>
              <th className="px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500">
                Status
              </th>
              <th className="px-4 py-2.5 text-right text-xs font-medium uppercase tracking-wider text-gray-500">
                Profile
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {visible.map((site) => (
              <tr key={site.id}>
                <td className="px-4 py-2.5 font-medium">
                  {site.name}
                  {site.isNSFW ? (
                    <span className="ml-2 rounded border border-gray-200 bg-gray-50 px-1.5 py-0.5 font-mono text-[10px] font-medium text-gray-500">
                      18+
                    </span>
                  ) : null}
                </td>
                <td className="px-4 py-2.5">
                  {site.status === "found" ? (
                    <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-green-700">
                      <span className="h-1.5 w-1.5 rounded-full bg-green-500" />
                      Found
                    </span>
                  ) : site.status === "not_found" ? (
                    <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-gray-500">
                      <span className="h-1.5 w-1.5 rounded-full bg-gray-300" />
                      Not found
                    </span>
                  ) : (
                    <span
                      className="inline-flex items-center gap-1.5 whitespace-nowrap text-amber-700"
                      title={site.detail ?? "Check failed"}
                    >
                      <span className="h-1.5 w-1.5 rounded-full bg-amber-500" />
                      Error
                    </span>
                  )}
                </td>
                <td className="px-4 py-2.5 text-right">
                  {site.status === "found" ? (
                    <a
                      href={site.url}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1 font-mono text-xs text-gray-500 transition-colors hover:text-black"
                    >
                      Open
                      <ExternalIcon />
                    </a>
                  ) : (
                    <span className="font-mono text-xs text-gray-500">—</span>
                  )}
                </td>
              </tr>
            ))}
            {visible.length === 0 ? (
              <tr>
                <td colSpan={3} className="px-4 py-6 text-center text-[13px] text-gray-500">
                  No sites match this filter.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
      <p className="text-xs text-gray-500">
        Showing {visible.length} of {ordered.length} checked sites.
        {progress ? " More results are still arriving." : ""}
      </p>
    </div>
  );
}

// ------------------------------------------------------------------- domain

function DnsRows({ data }: { data: DomainCheckResult["dns"] }) {
  const rows: { type: string; values: string[] }[] = [
    { type: "A", values: data.a },
    { type: "AAAA", values: data.aaaa },
    {
      type: "MX",
      values: data.mx.map((m) => `${m.priority} ${m.exchange}`),
    },
    { type: "TXT", values: data.txt.map((parts) => parts.join("")) },
    { type: "NS", values: data.ns },
  ];
  return (
    <div className="overflow-hidden rounded-lg border border-gray-200">
      <table className="w-full text-sm">
        <tbody className="divide-y divide-gray-100">
          {rows.map((row) => (
            <tr key={row.type}>
              <td className="w-20 px-4 py-2.5 align-top font-mono text-xs font-semibold text-gray-500">
                {row.type}
              </td>
              <td className="px-4 py-2.5 font-mono text-[13px] leading-relaxed">
                {row.values.length > 0 ? (
                  row.values.map((value) => (
                    <div key={value} className="break-all">
                      {value}
                    </div>
                  ))
                ) : (
                  <span className="text-gray-500">No records</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function DomainResult({ data }: { data: DomainCheckResult }) {
  const tls = data.tls;
  const tlsTone: Tone =
    !tls.ok || (tls.daysUntilExpiry !== undefined && tls.daysUntilExpiry <= 0)
      ? "danger"
      : tls.daysUntilExpiry !== undefined && tls.daysUntilExpiry <= 30
        ? "warning"
        : "ok";

  return (
    <div className="space-y-6">
      <div className="space-y-3">
        <SectionTitle>DNS records</SectionTitle>
        <DnsRows data={data.dns} />
        {Object.keys(data.dns.errors).length > 0 ? (
          <p className="text-xs text-amber-700">
            Some lookups failed:{" "}
            {Object.entries(data.dns.errors)
              .map(([type, message]) => `${type} (${message})`)
              .join(", ")}
          </p>
        ) : null}
      </div>

      <div className="space-y-3 border-t border-gray-100 pt-6">
        <SectionTitle>TLS certificate</SectionTitle>
        {tls.ok ? (
          <>
            <Verdict
              tone={tlsTone}
              title={
                tls.daysUntilExpiry !== undefined && tls.daysUntilExpiry <= 0
                  ? "Certificate expired"
                  : tls.daysUntilExpiry !== undefined && tls.daysUntilExpiry <= 30
                    ? `Certificate expires in ${tls.daysUntilExpiry} days`
                    : `Certificate valid for ${tls.daysUntilExpiry ?? "?"} more days`
              }
            >
              <p>
                Issued by {tls.issuer ?? "unknown issuer"}
                {tls.authorized === false
                  ? ` — chain validation failed${tls.authorizationError ? `: ${tls.authorizationError}` : ""}.`
                  : " — chain validates."}
              </p>
            </Verdict>
            <StatGrid
              items={[
                { label: "Subject", value: tls.subjectCN ?? "—" },
                { label: "Issuer", value: tls.issuer ?? "—" },
                { label: "Valid from", value: tls.validFrom ?? "—" },
                { label: "Valid to", value: tls.validTo ?? "—" },
                {
                  label: "Days left",
                  value:
                    tls.daysUntilExpiry !== undefined
                      ? String(tls.daysUntilExpiry)
                      : "—",
                },
                {
                  label: "Chain",
                  value: tls.authorized ? "Trusted" : "Not trusted",
                },
              ]}
            />
          </>
        ) : (
          <Verdict tone="danger" title="No TLS certificate">
            <p>{tls.error ?? "The site did not present a certificate."}</p>
          </Verdict>
        )}
      </div>

      <div className="space-y-3 border-t border-gray-100 pt-6">
        <SectionTitle>Security headers</SectionTitle>
        {data.headers.ok ? (
          <>
            <div className="flex items-center gap-4">
              <div className="flex h-12 w-12 items-center justify-center rounded-lg border border-gray-200 bg-gray-50 font-mono text-xl font-semibold">
                {data.headers.grade}
              </div>
              <div>
                <p className="text-sm font-medium">
                  {data.headers.score} / 100
                </p>
                <p className="font-mono text-xs text-gray-500">
                  {data.headers.url} (HTTP {data.headers.status})
                </p>
              </div>
            </div>
            <div className="overflow-hidden rounded-lg border border-gray-200">
              <table className="w-full text-sm">
                <tbody className="divide-y divide-gray-100">
                  {data.headers.headers.map((header) => (
                    <tr key={header.name}>
                      <td className="px-4 py-2.5 font-mono text-[13px] font-medium">
                        {header.name}
                      </td>
                      <td className="hidden px-4 py-2.5 text-[13px] text-gray-500 sm:table-cell">
                        {header.description}
                      </td>
                      <td className="px-4 py-2.5 text-right">
                        {header.present ? (
                          <span className="inline-flex items-center gap-1.5 text-green-700">
                            <CheckIcon />
                            <span className="hidden sm:inline">Present</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1.5 text-gray-500">
                            <XIcon />
                            <span className="hidden sm:inline">Missing</span>
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        ) : (
          <Verdict tone="warning" title="Headers could not be checked">
            <p>{data.headers.error}</p>
          </Verdict>
        )}
      </div>

      <div className="space-y-3 border-t border-gray-100 pt-6">
        <SectionTitle>
          Subdomains from certificate transparency
          <span className="ml-2 font-mono text-xs font-normal text-gray-500">
            {data.subdomains.ok
              ? `${formatNumber(data.subdomains.total)} found`
              : ""}
          </span>
        </SectionTitle>
        {data.subdomains.ok ? (
          data.subdomains.total > 0 ? (
            <>
              <div className="grid grid-cols-1 gap-x-6 gap-y-1 rounded-lg border border-gray-200 p-4 font-mono text-[13px] sm:grid-cols-2">
                {data.subdomains.subdomains.map((name) => (
                  <span key={name} className="truncate" title={name}>
                    {name}
                  </span>
                ))}
              </div>
              {data.subdomains.truncated ? (
                <p className="text-xs text-gray-500">
                  Showing the first {data.subdomains.subdomains.length} of{" "}
                  {formatNumber(data.subdomains.total)} subdomains. Source:
                  crt.sh.
                </p>
              ) : (
                <p className="text-xs text-gray-500">Source: crt.sh.</p>
              )}
            </>
          ) : (
            <p className="text-sm text-gray-500">
              No subdomains found in certificate transparency logs.
            </p>
          )
        ) : (
          <Verdict tone="warning" title="Subdomain lookup failed">
            <p>{data.subdomains.error}</p>
          </Verdict>
        )}
      </div>

      <div className="space-y-3 border-t border-gray-100 pt-6">
        <SectionTitle>Registration</SectionTitle>
        {!data.rdap.ok ? (
          <Verdict tone="warning" title="Registration lookup failed">
            <p>{data.rdap.error}</p>
          </Verdict>
        ) : data.rdap.registered === false ? (
          <Verdict tone="info" title="Domain is not registered">
            <p>
              No RDAP record exists for this domain — it appears to be
              available for registration.
            </p>
          </Verdict>
        ) : (
          <>
            <StatGrid
              items={[
                {
                  label: "Registrar",
                  value:
                    data.rdap.registrar ?? data.rdap.registrarUrl ?? "—",
                },
                { label: "Registered", value: formatDate(data.rdap.createdAt) },
                { label: "Expires", value: formatDate(data.rdap.expiresAt) },
                {
                  label: "Last changed",
                  value: formatDate(data.rdap.updatedAt),
                },
                {
                  label: "IANA registrar ID",
                  value: data.rdap.registrarIanaId ?? "—",
                },
                {
                  label: "Nameservers",
                  value: data.rdap.nameservers?.length
                    ? String(data.rdap.nameservers.length)
                    : "—",
                },
              ]}
            />
            {data.rdap.nameservers && data.rdap.nameservers.length > 0 ? (
              <p className="break-all font-mono text-xs leading-relaxed text-gray-500">
                {data.rdap.nameservers.join(", ")}
              </p>
            ) : null}
            <p className="text-xs text-gray-500">Source: RDAP (rdap.org).</p>
          </>
        )}
      </div>

      <div className="space-y-3 border-t border-gray-100 pt-6">
        <SectionTitle>Email authentication</SectionTitle>
        {data.emailAuth.error ? (
          <Verdict
            tone="warning"
            title="Authentication records could not be checked"
          >
            <p>{data.emailAuth.error}</p>
          </Verdict>
        ) : (
          <>
            <div className="flex items-center gap-4">
              <div className="flex h-12 w-12 items-center justify-center rounded-lg border border-gray-200 bg-gray-50 font-mono text-xl font-semibold">
                {data.emailAuth.grade}
              </div>
              <div>
                <p className="text-sm font-medium">
                  {data.emailAuth.score} / 100
                </p>
                <p className="text-[13px] text-gray-500">
                  {data.emailAuth.grade === "A" || data.emailAuth.grade === "B"
                    ? "This domain is well protected against email spoofing."
                    : "This domain can be spoofed more easily — senders should publish SPF, DKIM, and DMARC."}
                </p>
              </div>
            </div>
            <div className="overflow-hidden rounded-lg border border-gray-200">
              <table className="w-full text-sm">
                <tbody className="divide-y divide-gray-100">
                  <AuthRow
                    name="SPF"
                    present={data.emailAuth.spf.present}
                    detail={
                      data.emailAuth.spf.policy === "hardfail"
                        ? "-all (strict)"
                        : data.emailAuth.spf.policy === "softfail"
                          ? "~all (soft)"
                          : data.emailAuth.spf.policy === "neutral"
                            ? "?all (neutral)"
                            : data.emailAuth.spf.policy === "pass"
                              ? "+all (weak)"
                              : "present"
                    }
                    hint="Authorizes which servers may send mail for this domain"
                  />
                  <AuthRow
                    name="DKIM"
                    present={data.emailAuth.dkim.present}
                    detail={
                      data.emailAuth.dkim.selectors.length > 0
                        ? data.emailAuth.dkim.selectors.join(", ")
                        : "present"
                    }
                    hint="Cryptographic signature proving the mail is genuine"
                  />
                  <AuthRow
                    name="DMARC"
                    present={data.emailAuth.dmarc.present}
                    detail={
                      data.emailAuth.dmarc.policy
                        ? `p=${data.emailAuth.dmarc.policy}`
                        : "present"
                    }
                    hint="Tells receivers what to do with mail that fails SPF/DKIM"
                  />
                </tbody>
              </table>
            </div>
            {data.emailAuth.spf.redirect ? (
              <p className="text-xs text-gray-500">
                SPF policy resolved via redirect to{" "}
                <span className="font-mono">{data.emailAuth.spf.redirect}</span>
                .
              </p>
            ) : null}
          </>
        )}
      </div>

      <div className="space-y-3 border-t border-gray-100 pt-6">
        <SectionTitle>DNSSEC</SectionTitle>
        {data.dnssec.signed === true ? (
          <Verdict tone="ok" title="DNSSEC is enabled">
            <p>
              DNS responses for this domain are cryptographically signed, so
              resolvers can verify they have not been tampered with.
            </p>
          </Verdict>
        ) : data.dnssec.signed === false ? (
          <Verdict tone="warning" title="DNSSEC is not enabled">
            <p>
              Nothing signs this domain&apos;s DNS responses, so a network
              attacker could more easily forge them. This is common — most
              domains are still unsigned.
            </p>
          </Verdict>
        ) : (
          <Verdict tone="info" title="DNSSEC status could not be determined">
            <p>
              {data.dnssec.error ?? "The DNSSEC lookups failed."}
            </p>
          </Verdict>
        )}
        <div className="overflow-hidden rounded-lg border border-gray-200">
          <table className="w-full text-sm">
            <tbody className="divide-y divide-gray-100">
              <tr>
                <td className="px-4 py-2.5 font-mono text-[13px] font-medium">
                  DS record at parent
                </td>
                <td className="hidden px-4 py-2.5 text-[13px] text-gray-500 sm:table-cell">
                  Anchors the chain of trust (from RDAP)
                </td>
                <td className="px-4 py-2.5 text-right text-[13px]">
                  {data.dnssec.delegationSigned === true
                    ? "Published"
                    : data.dnssec.delegationSigned === false
                      ? "Not published"
                      : "Unknown"}
                </td>
              </tr>
              <tr>
                <td className="px-4 py-2.5 font-mono text-[13px] font-medium">
                  DNSKEY records
                </td>
                <td className="hidden px-4 py-2.5 text-[13px] text-gray-500 sm:table-cell">
                  Signing keys published at the domain
                </td>
                <td className="px-4 py-2.5 text-right text-[13px]">
                  {data.dnssec.dnskeyPresent === true
                    ? "Published"
                    : data.dnssec.dnskeyPresent === false
                      ? "Not published"
                      : "Unknown"}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <div className="space-y-3 border-t border-gray-100 pt-6">
        <SectionTitle>Blocklists</SectionTitle>
        <div className="overflow-hidden rounded-lg border border-gray-200">
          <table className="w-full text-sm">
            <tbody className="divide-y divide-gray-100">
              {data.dnsbl.lists.map((list) => (
                <tr key={list.name}>
                  <td className="px-4 py-2.5 font-medium">{list.name}</td>
                  <td className="hidden px-4 py-2.5 text-[13px] text-gray-500 sm:table-cell">
                    {list.scope}
                  </td>
                  <td className="px-4 py-2.5 text-right">
                    {list.listed === true ? (
                      <span className="inline-flex items-center gap-1.5 text-red-700">
                        <span className="h-1.5 w-1.5 rounded-full bg-red-500" />
                        Listed
                        {list.listedOn.length > 0
                          ? ` (${list.listedOn.join(", ")})`
                          : ""}
                      </span>
                    ) : list.listed === false ? (
                      <span className="inline-flex items-center gap-1.5 text-green-700">
                        <span className="h-1.5 w-1.5 rounded-full bg-green-500" />
                        Not listed
                      </span>
                    ) : (
                      <span
                        className="inline-flex items-center gap-1.5 text-amber-700"
                        title={list.error ?? "Check failed"}
                      >
                        <span className="h-1.5 w-1.5 rounded-full bg-amber-500" />
                        Could not check
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="text-xs leading-relaxed text-gray-500">
          A listing means the domain or its IPs appear on a spam/malware
          blocklist — mail from it is more likely to be filtered. Sources:
          Spamhaus, SpamCop.
        </p>
      </div>

      <div className="space-y-3 border-t border-gray-100 pt-6">
        <SectionTitle>Technology</SectionTitle>
        {!data.tech.ok ? (
          <Verdict tone="warning" title="Technology detection failed">
            <p>{data.tech.error}</p>
          </Verdict>
        ) : data.tech.technologies.length === 0 ? (
          <p className="text-sm text-gray-500">
            No recognizable technologies detected on the homepage.
          </p>
        ) : (
          <div className="overflow-hidden rounded-lg border border-gray-200">
            <table className="w-full text-sm">
              <tbody className="divide-y divide-gray-100">
                {data.tech.technologies.map((tech) => (
                  <tr key={tech.name}>
                    <td className="px-4 py-2.5 font-medium">{tech.name}</td>
                    <td className="px-4 py-2.5 text-[13px] text-gray-500">
                      {tech.category}
                    </td>
                    <td className="hidden max-w-[280px] truncate px-4 py-2.5 text-right font-mono text-xs text-gray-500 sm:table-cell">
                      {tech.evidence}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="space-y-3 border-t border-gray-100 pt-6">
        <SectionTitle>Wayback Machine history</SectionTitle>
        {!data.wayback.ok ? (
          <Verdict tone="warning" title="Archive lookup failed">
            <p>{data.wayback.error}</p>
          </Verdict>
        ) : !data.wayback.firstSnapshotAt &&
          !data.wayback.totalSnapshots ? (
          <p className="text-sm text-gray-500">
            No snapshots of this domain in the Internet Archive.
          </p>
        ) : (
          <>
            <StatGrid
              items={[
                {
                  label: "First snapshot",
                  value: formatDate(data.wayback.firstSnapshotAt),
                },
                {
                  label: "Snapshots",
                  value:
                    data.wayback.totalSnapshots !== undefined
                      ? `${data.wayback.totalApproximate ? "≈" : ""}${formatNumber(data.wayback.totalSnapshots)}`
                      : "—",
                },
                {
                  label: "First status",
                  value:
                    data.wayback.firstSnapshotStatus !== undefined
                      ? `HTTP ${data.wayback.firstSnapshotStatus}`
                      : "—",
                },
              ]}
            />
            <p className="text-xs text-gray-500">
              Source: Internet Archive Wayback Machine (CDX API).
              {data.wayback.totalApproximate
                ? " Snapshot count is approximate."
                : ""}
            </p>
          </>
        )}
      </div>

      <div className="space-y-3 border-t border-gray-100 pt-6">
        <SectionTitle>
          Passive DNS
          <span className="ml-2 font-mono text-xs font-normal text-gray-500">
            {data.otx.available && data.otx.result?.ok
              ? `${formatNumber(data.otx.result.total)} hostnames`
              : ""}
          </span>
        </SectionTitle>
        {!data.otx.available ? (
          <Verdict
            tone="info"
            title="Passive DNS lookup is not configured on this deployment"
          >
            <p>
              AlienVault OTX passive DNS needs an API key (OTX_API_KEY, free
              tier). No key is configured, so no result is shown.
            </p>
          </Verdict>
        ) : data.otx.result?.ok ? (
          data.otx.result.total > 0 ? (
            <>
              <div className="grid grid-cols-1 gap-x-6 gap-y-1 rounded-lg border border-gray-200 p-4 font-mono text-[13px] sm:grid-cols-2">
                {data.otx.result.hostnames.map((name) => (
                  <span key={name} className="truncate" title={name}>
                    {name}
                  </span>
                ))}
              </div>
              <p className="text-xs text-gray-500">
                {data.otx.result.truncated
                  ? `Showing the first ${data.otx.result.hostnames.length} of ${formatNumber(data.otx.result.total)} hostnames. `
                  : ""}
                Source: AlienVault OTX.
              </p>
            </>
          ) : (
            <p className="text-sm text-gray-500">
              No hostnames in OTX passive DNS for this domain.
            </p>
          )
        ) : (
          <Verdict tone="warning" title="Passive DNS lookup failed">
            <p>{data.otx.result?.error}</p>
          </Verdict>
        )}
      </div>

      <div className="space-y-3 border-t border-gray-100 pt-6">
        <SectionTitle>Recent scans (urlscan.io)</SectionTitle>
        {!data.urlscan.ok ? (
          <Verdict tone="warning" title="urlscan.io lookup failed">
            <p>{data.urlscan.error}</p>
          </Verdict>
        ) : data.urlscan.total === 0 ? (
          <p className="text-sm text-gray-500">
            No public urlscan.io scans submitted for this domain in the last
            30 days.
          </p>
        ) : (
          <>
            <p className="text-sm text-gray-700">
              <span className="font-mono font-semibold">
                {data.urlscan.totalCapped
                  ? `${formatNumber(data.urlscan.total)}+`
                  : formatNumber(data.urlscan.total)}
              </span>{" "}
              public scan{data.urlscan.total === 1 ? "" : "s"} submitted in
              the last 30 days
              {data.urlscan.latestScanAt
                ? `, latest on ${formatDate(data.urlscan.latestScanAt)}`
                : ""}
              {data.urlscan.totalCapped
                ? " (urlscan.io caps the count at 10,000)"
                : ""}
              .
            </p>
            <p className="text-xs text-gray-500">
              {data.urlscan.latestScanUrl ? (
                <>
                  <a
                    href={data.urlscan.latestScanUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="font-medium text-gray-700 underline-offset-2 hover:text-black hover:underline"
                  >
                    Latest scan
                  </a>{" "}
                  ·{" "}
                </>
              ) : null}
              <a
                href={data.urlscan.searchUrl}
                target="_blank"
                rel="noreferrer"
                className="font-medium text-gray-700 underline-offset-2 hover:text-black hover:underline"
              >
                All scans on urlscan.io
              </a>
            </p>
          </>
        )}
      </div>
    </div>
  );
}

// ----------------------------------------------------------------------- ip

function SignalRow({
  name,
  value,
  hint,
}: {
  name: string;
  value: boolean | null | undefined;
  hint: string;
}) {
  return (
    <tr>
      <td className="px-4 py-2.5 font-medium">{name}</td>
      <td className="hidden px-4 py-2.5 text-[13px] text-gray-500 sm:table-cell">
        {hint}
      </td>
      <td className="px-4 py-2.5 text-right text-[13px]">
        {value === true ? (
          <span className="text-amber-700">Yes</span>
        ) : value === false ? (
          <span className="text-gray-700">No</span>
        ) : (
          <span className="text-gray-500">Unknown</span>
        )}
      </td>
    </tr>
  );
}

export function IpResult({ data }: { data: IpCheckResult }) {
  const abuse = data.abuseipdb.result;
  const score =
    abuse?.ok && typeof abuse.abuseConfidenceScore === "number"
      ? abuse.abuseConfidenceScore
      : undefined;
  const reports = abuse?.ok ? abuse.totalReports : undefined;

  const verdictTone: Tone =
    score !== undefined && score >= 50
      ? "danger"
      : score !== undefined && score > 0
        ? "warning"
        : "ok";
  const verdictTitle =
    score === undefined
      ? data.abuseipdb.available
        ? "Reputation could not be checked"
        : "No reputation data on this deployment"
      : score === 0 && (reports ?? 0) === 0
        ? "No abuse reports for this IP"
        : score < 50
          ? `Low abuse confidence (${score}%)`
          : `High abuse confidence (${score}%)`;

  return (
    <div className="space-y-6">
      <Verdict tone={verdictTone} title={verdictTitle}>
        <p>
          {score === undefined ? (
            data.abuseipdb.available ? (
              abuse?.error ?? "The AbuseIPDB lookup failed."
            ) : (
              "AbuseIPDB reputation needs an API key (ABUSEIPDB_API_KEY, free tier). No key is configured, so no reputation result is shown."
            )
          ) : score === 0 && (reports ?? 0) === 0 ? (
            "AbuseIPDB has no abuse reports for this address in the last 90 days."
          ) : (
            <>
              AbuseIPDB reports {reports ?? "?"} report
              {reports === 1 ? "" : "s"} in the last 90 days
              {abuse?.lastReportedAt
                ? `, most recently on ${formatDate(abuse.lastReportedAt)}`
                : ""}
              .
            </>
          )}
        </p>
        {data.tor.isExitNode ? (
          <p className="mt-1.5">
            This IP is a Tor exit node. Exit nodes relay other people&apos;s
            traffic, so they are often flagged by services — that alone does
            not make the address malicious.
          </p>
        ) : null}
      </Verdict>

      <div className="space-y-3">
        <SectionTitle>Location &amp; network</SectionTitle>
        {data.geo.ok ? (
          <StatGrid
            items={[
              { label: "Country", value: data.geo.country ?? "—" },
              { label: "City", value: data.geo.city ?? "—" },
              { label: "Region", value: data.geo.region ?? "—" },
              { label: "ISP", value: data.geo.isp ?? "—" },
              { label: "Organization", value: data.geo.org ?? "—" },
              { label: "ASN", value: data.geo.as ?? "—" },
              { label: "Timezone", value: data.geo.timezone ?? "—" },
              { label: "Reverse DNS", value: data.ptr ?? data.geo.reverse ?? "—" },
              {
                label: "Coordinates",
                value:
                  data.geo.lat !== undefined && data.geo.lon !== undefined
                    ? `${data.geo.lat}, ${data.geo.lon}`
                    : "—",
              },
            ]}
          />
        ) : (
          <Verdict tone="warning" title="Location lookup failed">
            <p>{data.geo.error}</p>
          </Verdict>
        )}
        <p className="text-xs leading-relaxed text-gray-500">
          IP geolocation is approximate — city-level at best, and often just
          the ISP&apos;s point of presence. Source: ip-api.com.
        </p>
      </div>

      <div className="space-y-3 border-t border-gray-100 pt-6">
        <SectionTitle>Network signals</SectionTitle>
        <div className="overflow-hidden rounded-lg border border-gray-200">
          <table className="w-full text-sm">
            <tbody className="divide-y divide-gray-100">
              <SignalRow
                name="VPN / proxy"
                value={data.geo.ok ? data.geo.proxy : null}
                hint="Traffic looks like it comes from a VPN or proxy (ip-api.com)"
              />
              <SignalRow
                name="Hosting / datacenter"
                value={data.geo.ok ? data.geo.hosting : null}
                hint="Address belongs to a hosting provider, not a home ISP (ip-api.com)"
              />
              <SignalRow
                name="Mobile network"
                value={data.geo.ok ? data.geo.mobile : null}
                hint="Address belongs to a mobile carrier (ip-api.com)"
              />
              <SignalRow
                name="Tor exit node"
                value={data.tor.isExitNode}
                hint="Listed as a Tor exit relay (dan.me.uk exit list)"
              />
            </tbody>
          </table>
        </div>
        <p className="text-xs leading-relaxed text-gray-500">
          These flags describe the kind of network, not intent — datacenter
          and VPN addresses are common and usually legitimate.
        </p>
      </div>

      {data.abuseipdb.available && abuse?.ok ? (
        <div className="space-y-3 border-t border-gray-100 pt-6">
          <SectionTitle>AbuseIPDB details</SectionTitle>
          <StatGrid
            items={[
              {
                label: "Abuse confidence",
                value: score !== undefined ? `${score}%` : "—",
              },
              {
                label: "Reports (90 days)",
                value: reports !== undefined ? String(reports) : "—",
              },
              {
                label: "Last reported",
                value: formatDate(abuse.lastReportedAt),
              },
              { label: "ISP", value: abuse.isp ?? "—" },
              { label: "Domain", value: abuse.domain ?? "—" },
              {
                label: "Whitelisted",
                value: abuse.isWhitelisted ? "Yes" : "No",
              },
            ]}
          />
          <p className="text-xs text-gray-500">Source: AbuseIPDB.</p>
        </div>
      ) : null}
    </div>
  );
}

// -------------------------------------------------------------------- phone

export function PhoneResult({ data }: { data: PhoneCheckResult }) {
  const ipqs = data.ipqs.result;
  const gc = data.spam.getcontact;
  const sia = data.spam.shouldianswer;
  const fraudScore = ipqs?.ok ? ipqs.fraudScore : undefined;
  const fraudHigh = fraudScore !== undefined && fraudScore >= 85;
  const ipqsFlagged =
    ipqs?.ok === true && (ipqs.spammer === true || ipqs.recentAbuse === true);
  const gcFlagged =
    gc.ok &&
    gc.inDatabase &&
    (gc.risk === "High risk" || gc.feedback === "Negative");
  const siaFlagged =
    sia.ok &&
    sia.covered &&
    (sia.reports ?? 0) > 0 &&
    (sia.rating ?? 5) <= 2;
  const spamFlagged = gcFlagged || siaFlagged;

  const statItems: { label: string; value: string }[] = [
    { label: "E.164", value: data.e164 ?? "—" },
    { label: "Country", value: data.country ?? "—" },
    {
      label: "Calling code",
      value: data.countryCallingCode ? `+${data.countryCallingCode}` : "—",
    },
    { label: "Type", value: data.type ?? "—" },
    { label: "International", value: data.international ?? "—" },
    { label: "National", value: data.national ?? "—" },
  ];
  if (data.idOperator) {
    statItems.push({
      label: "Operator (prefix)",
      value: data.idOperator.parent
        ? `${data.idOperator.operator} · ${data.idOperator.parent}`
        : data.idOperator.operator,
    });
  }

  return (
    <div className="space-y-4">
      <Verdict
        tone={data.valid ? "ok" : "danger"}
        title={
          data.valid
            ? "Valid phone number"
            : "Not a valid phone number for its region"
        }
      >
        <p>
          {data.valid
            ? "The number parses and is valid for its detected country."
            : "The number could not be validated. Check the country code and the digits."}
        </p>
      </Verdict>
      <StatGrid items={statItems} />
      {data.idOperator ? (
        <p className="text-xs leading-relaxed text-gray-500">
          Prefix {data.idOperator.prefix} was allocated to{" "}
          {data.idOperator.operator}. The current operator can differ if the
          number was ported.
        </p>
      ) : null}

      {data.valid ? (
        <>
          <div className="space-y-3 border-t border-gray-100 pt-4">
            <SectionTitle>Carrier &amp; risk</SectionTitle>
            {!data.ipqs.available ? (
              <p className="text-[13px] leading-relaxed text-gray-500">
                Carrier and risk lookup needs an API key (IPQS_API_KEY, free
                tier). No key is configured, so no carrier or risk result is
                shown.
              </p>
            ) : !ipqs?.ok ? (
              <p className="text-[13px] leading-relaxed text-gray-500">
                {ipqs?.error ?? "The IPQS lookup failed."}
              </p>
            ) : (
              <>
                {fraudHigh || ipqsFlagged ? (
                  <p className="text-[13px] font-medium leading-relaxed text-amber-800">
                    {fraudHigh
                      ? `High fraud score (${fraudScore}/100).`
                      : ""}
                    {ipqs.spammer ? " Flagged as a spammer by IPQS." : ""}
                    {ipqs.recentAbuse
                      ? " Associated with recent abuse."
                      : ""}
                  </p>
                ) : null}
                <StatGrid
                  items={[
                    { label: "Carrier", value: ipqs.carrier ?? "—" },
                    { label: "Line type", value: ipqs.lineType ?? "—" },
                    {
                      label: "Fraud score",
                      value:
                        fraudScore !== undefined ? `${fraudScore}/100` : "—",
                    },
                    {
                      label: "Active",
                      value: ipqs.activeStatus ?? (ipqs.active === undefined ? "—" : ipqs.active ? "Yes" : "No"),
                    },
                    {
                      label: "Recent abuse",
                      value:
                        ipqs.recentAbuse === undefined
                          ? "—"
                          : ipqs.recentAbuse
                            ? "Yes"
                            : "No",
                    },
                    {
                      label: "In a data leak",
                      value:
                        ipqs.leaked === undefined
                          ? "—"
                          : ipqs.leaked
                            ? "Yes"
                            : "No",
                    },
                    {
                      label: "VoIP",
                      value:
                        ipqs.voip === undefined
                          ? "—"
                          : ipqs.voip
                            ? "Yes"
                            : "No",
                    },
                    {
                      label: "Prepaid",
                      value:
                        ipqs.prepaid === undefined
                          ? "—"
                          : ipqs.prepaid
                            ? "Yes"
                            : "No",
                    },
                  ]}
                />
                <p className="text-xs text-gray-500">Source: IPQualityScore.</p>
              </>
            )}
          </div>

          <div className="space-y-3 border-t border-gray-100 pt-4">
            <SectionTitle>Spam reports</SectionTitle>
            {spamFlagged ? (
              <Verdict tone="warning" title="Reported as spam or scam">
                <p>
                  Community reports flag this number. Do not answer unknown
                  calls from it, and never share codes or transfer money to
                  callers you did not expect.
                </p>
              </Verdict>
            ) : null}
            {!gc.ok ? (
              <p className="text-[13px] leading-relaxed text-gray-500">
                GetContact: {gc.error ?? "The lookup failed."}
              </p>
            ) : !gc.inDatabase ? (
              <p className="text-[13px] leading-relaxed text-gray-500">
                No reports on GetContact — this number is not in their
                community database.
              </p>
            ) : (
              <>
                <StatGrid
                  items={[
                    {
                      label: "User reports",
                      value:
                        gc.reports !== undefined
                          ? formatNumber(gc.reports)
                          : "—",
                    },
                    { label: "Risk", value: gc.risk ?? "—" },
                    { label: "Community", value: gc.feedback ?? "—" },
                    {
                      label: "Total calls",
                      value:
                        gc.totalCalls !== undefined
                          ? formatNumber(gc.totalCalls)
                          : "—",
                    },
                    {
                      label: "Blocked",
                      value:
                        gc.blocked === undefined
                          ? "—"
                          : gc.blocked
                            ? "Yes"
                            : "No",
                    },
                    { label: "Region", value: gc.region ?? "—" },
                  ]}
                />
                <p className="text-xs text-gray-500">
                  Source:{" "}
                  <a
                    href={gc.url}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 text-gray-700 underline underline-offset-2"
                  >
                    Getcontact
                    <ExternalIcon />
                  </a>
                  .
                </p>
              </>
            )}
            {sia.covered ? (
              !sia.ok ? (
                <p className="text-[13px] leading-relaxed text-gray-500">
                  Should I Answer: {sia.error ?? "The lookup failed."}
                </p>
              ) : (sia.reports ?? 0) === 0 ? (
                <p className="text-[13px] leading-relaxed text-gray-500">
                  No community reports on Should I Answer.
                </p>
              ) : (
                <p className="text-[13px] leading-relaxed text-gray-700">
                  Should I Answer: rated {sia.rating ?? "?"}/5 from{" "}
                  {formatNumber(sia.reports ?? 0)} community review
                  {sia.reports === 1 ? "" : "s"}
                  {sia.url ? (
                    <>
                      {" — "}
                      <a
                        href={sia.url}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 underline underline-offset-2"
                      >
                        view reports
                        <ExternalIcon />
                      </a>
                    </>
                  ) : null}
                  .
                </p>
              )
            ) : (
              <p className="text-xs leading-relaxed text-gray-500">
                Should I Answer only covers +1 (US/CA) numbers.
              </p>
            )}
            <p className="text-xs leading-relaxed text-gray-500">
              Community reports are best-effort signals, not proof — a number
              with no reports here may still be unwanted, and reports can be
              wrong.
            </p>
          </div>
        </>
      ) : null}

      <p className="text-xs leading-relaxed text-gray-500">
        Format, country, carrier, and community reports only. No free,
        legitimate source exists for phone-number breach lookups, so this
        check does not claim to find breaches.
      </p>
    </div>
  );
}

// -------------------------------------------------------------------- email

function ConfidenceTag({ label }: { label: string }) {
  return (
    <span className="ml-2 rounded border border-gray-200 bg-gray-50 px-1.5 py-0.5 font-mono text-[10px] font-medium text-gray-500">
      {label}
    </span>
  );
}

function AuthRow({
  name,
  present,
  detail,
  hint,
}: {
  name: string;
  present: boolean;
  detail: string;
  hint: string;
}) {
  return (
    <tr>
      <td className="px-4 py-2.5 font-mono text-[13px] font-medium">{name}</td>
      <td className="hidden px-4 py-2.5 text-[13px] text-gray-500 sm:table-cell">
        {hint}
      </td>
      <td className="px-4 py-2.5 text-right">
        {present ? (
          <span className="inline-flex items-center gap-1.5 text-green-700">
            <CheckIcon />
            <span className="font-mono text-[13px]">{detail}</span>
          </span>
        ) : (
          <span className="inline-flex items-center gap-1.5 text-gray-500">
            <XIcon />
            <span className="text-[13px]">Missing</span>
          </span>
        )}
      </td>
    </tr>
  );
}

export function EmailResult({ data }: { data: EmailCheckResponse }) {
  const hibp = data.hibp;
  const auth = data.auth;
  const leakcheck = data.leakcheck;
  const osintcat = data.osintcat;
  const hudsonrock = data.hudsonrock;
  const github = data.github;

  return (
    <div className="space-y-6">
      <div className="space-y-3">
        <SectionTitle>Mail records</SectionTitle>
        {data.mxOk ? (
          <div className="overflow-hidden rounded-lg border border-gray-200">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-200 bg-gray-50 text-left">
                  <th className="px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500">
                    Priority
                  </th>
                  <th className="px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500">
                    Mail server
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {data.mx.map((record) => (
                  <tr key={record.exchange}>
                    <td className="px-4 py-2.5 font-mono text-[13px]">
                      {record.priority}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-[13px]">
                      {record.exchange}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Verdict tone="warning" title="No MX records found">
            <p>
              {data.mxError ??
                `The domain ${data.domain} has no mail servers configured — it cannot receive email.`}
            </p>
          </Verdict>
        )}
        {data.disposable ? (
          <p className="text-xs leading-relaxed text-amber-700">
            {data.domain} is on a small built-in list of well-known disposable
            email providers. The list is limited, not comprehensive.
          </p>
        ) : null}
      </div>

      <div className="space-y-3 border-t border-gray-100 pt-6">
        <SectionTitle>
          Email authentication
          <span className="ml-2 font-mono text-xs font-normal text-gray-500">
            {data.domain}
          </span>
        </SectionTitle>
        {auth.error ? (
          <Verdict tone="warning" title="Authentication records could not be checked">
            <p>{auth.error}</p>
          </Verdict>
        ) : (
          <>
            <div className="flex items-center gap-4">
              <div className="flex h-12 w-12 items-center justify-center rounded-lg border border-gray-200 bg-gray-50 font-mono text-xl font-semibold">
                {auth.grade}
              </div>
              <div>
                <p className="text-sm font-medium">{auth.score} / 100</p>
                <p className="text-[13px] text-gray-500">
                  {auth.grade === "A" || auth.grade === "B"
                    ? "This domain is well protected against email spoofing."
                    : "This domain can be spoofed more easily — senders should publish SPF, DKIM, and DMARC."}
                </p>
              </div>
            </div>
            <div className="overflow-hidden rounded-lg border border-gray-200">
              <table className="w-full text-sm">
                <tbody className="divide-y divide-gray-100">
                  <AuthRow
                    name="SPF"
                    present={auth.spf.present}
                    detail={
                      auth.spf.policy === "hardfail"
                        ? "-all (strict)"
                        : auth.spf.policy === "softfail"
                          ? "~all (soft)"
                          : auth.spf.policy === "neutral"
                            ? "?all (neutral)"
                            : auth.spf.policy === "pass"
                              ? "+all (weak)"
                              : "present"
                    }
                    hint="Authorizes which servers may send mail for this domain"
                  />
                  <AuthRow
                    name="DKIM"
                    present={auth.dkim.present}
                    detail={
                      auth.dkim.selectors.length > 0
                        ? auth.dkim.selectors.join(", ")
                        : "present"
                    }
                    hint="Cryptographic signature proving the mail is genuine"
                  />
                  <AuthRow
                    name="DMARC"
                    present={auth.dmarc.present}
                    detail={
                      auth.dmarc.policy ? `p=${auth.dmarc.policy}` : "present"
                    }
                    hint="Tells receivers what to do with mail that fails SPF/DKIM"
                  />
                </tbody>
              </table>
            </div>
            <p className="text-xs leading-relaxed text-gray-500">
              This grades the domain&apos;s anti-spoofing setup, not the
              mailbox itself. A weak grade means anyone can more easily forge
              mail that looks like it comes from @{data.domain}.
            </p>
          </>
        )}
      </div>

      <div className="space-y-3 border-t border-gray-100 pt-6">
        <SectionTitle>Data breaches</SectionTitle>
        <p className="text-[13px] text-gray-500">
          Checked against several breach indexes. Only breach metadata is
          shown — never breach contents.
        </p>

        {/* HIBP — gold standard */}
        <div className="space-y-3 rounded-lg border border-gray-200 p-4">
          <p className="text-sm font-semibold">
            Have I Been Pwned
            <ConfidenceTag label="gold standard" />
          </p>
          {!hibp.available ? (
            <Verdict
              tone="warning"
              title="Breach lookup is not configured on this deployment"
            >
              <p>
                Email breach lookup needs a Have I Been Pwned API key (paid,
                from $4/month). No key is configured, so no breach result is
                shown — rather than a fake one.
              </p>
            </Verdict>
          ) : hibp.rateLimited ? (
            <Verdict tone="warning" title="Breach lookup is rate-limited">
              <p>
                Have I Been Pwned is throttling requests right now. Try again
                in a few minutes.
              </p>
            </Verdict>
          ) : hibp.error ? (
            <Verdict tone="warning" title="Breach lookup failed">
              <p>{hibp.error}</p>
            </Verdict>
          ) : hibp.breaches && hibp.breaches.length > 0 ? (
            <>
              <Verdict
                tone="danger"
                title={`Found in ${hibp.breaches.length} data breach${hibp.breaches.length === 1 ? "" : "es"}`}
              >
                <p>
                  This email appears in known breaches. Change the password on
                  every affected account, and enable two-factor authentication
                  where it is offered.
                </p>
              </Verdict>
              <div className="overflow-hidden rounded-lg border border-gray-200">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-200 bg-gray-50 text-left">
                      <th className="px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500">
                        Breach
                      </th>
                      <th className="px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500">
                        Date
                      </th>
                      <th className="hidden px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500 sm:table-cell">
                        Accounts
                      </th>
                      <th className="px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500">
                        Data exposed
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {hibp.breaches.map((breach) => (
                      <tr key={breach.name}>
                        <td className="px-4 py-2.5 font-medium">{breach.title}</td>
                        <td className="px-4 py-2.5 font-mono text-[13px]">
                          {breach.breachDate}
                        </td>
                        <td className="hidden px-4 py-2.5 font-mono text-[13px] sm:table-cell">
                          {formatNumber(breach.pwnCount)}
                        </td>
                        <td className="px-4 py-2.5 text-[13px] text-gray-600">
                          {breach.dataClasses.join(", ")}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          ) : (
            <Verdict tone="ok" title="No breaches found for this email">
              <p>
                This email does not appear in any breach known to Have I Been
                Pwned. New breaches surface over time, so this is a
                point-in-time result.
              </p>
            </Verdict>
          )}
        </div>

        {/* LeakCheck — aggregator */}
        <div className="space-y-3 rounded-lg border border-gray-200 p-4">
          <p className="text-sm font-semibold">
            LeakCheck
            <ConfidenceTag label="aggregator" />
          </p>
          {leakcheck.status === "error" ? (
            <Verdict tone="warning" title="LeakCheck lookup failed">
              <p>{leakcheck.error}</p>
            </Verdict>
          ) : leakcheck.status === "not_found" ? (
            <Verdict tone="ok" title="Not found in the LeakCheck index">
              <p>
                This email does not appear in LeakCheck&apos;s breach index.
              </p>
            </Verdict>
          ) : (
            <>
              <Verdict
                tone="danger"
                title={`Found in ${formatNumber(leakcheck.found)} breach record${leakcheck.found === 1 ? "" : "s"}`}
              >
                <p>
                  This email appears in LeakCheck&apos;s index, which includes
                  stealer logs. Change the password on every affected account
                  and enable two-factor authentication.
                </p>
              </Verdict>
              {leakcheck.sources.length > 0 ? (
                <div className="overflow-hidden rounded-lg border border-gray-200">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-gray-200 bg-gray-50 text-left">
                        <th className="px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500">
                          Source
                        </th>
                        <th className="px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500">
                          Date
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100">
                      {leakcheck.sources.map((source) => (
                        <tr key={`${source.name}-${source.date}`}>
                          <td className="px-4 py-2.5 font-medium">{source.name}</td>
                          <td className="px-4 py-2.5 font-mono text-[13px]">
                            {source.date || "—"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : null}
              {leakcheck.fields.length > 0 ? (
                <p className="text-[13px] text-gray-600">
                  Data categories seen: {leakcheck.fields.join(", ")}.
                </p>
              ) : null}
            </>
          )}
          <p className="text-xs text-gray-500">
            Powered by{" "}
            <a
              href="https://leakcheck.io"
              target="_blank"
              rel="noreferrer"
              className="font-medium text-gray-700 underline-offset-2 hover:text-black hover:underline"
            >
              LeakCheck
            </a>
            .
          </p>
        </div>

        {/* OsintCat — aggregator, keyed */}
        <div className="space-y-3 rounded-lg border border-gray-200 p-4">
          <p className="text-sm font-semibold">
            OsintCat
            <ConfidenceTag label="aggregator" />
          </p>
          {!osintcat.available ? (
            <Verdict
              tone="info"
              title="OsintCat lookup is not configured on this deployment"
            >
              <p>
                OsintCat breach lookup needs an API key (OSINTCAT_API_KEY).
                No key is configured, so no result is shown.
              </p>
            </Verdict>
          ) : osintcat.result?.status === "error" ? (
            <Verdict tone="warning" title="OsintCat lookup failed">
              <p>{osintcat.result.error}</p>
            </Verdict>
          ) : osintcat.result?.status === "rate_limited" ? (
            <Verdict tone="warning" title="OsintCat lookup is rate-limited">
              <p>The daily OsintCat allowance is used up. Try again tomorrow.</p>
            </Verdict>
          ) : osintcat.result?.status === "not_found" ? (
            <Verdict tone="ok" title="Not found in the OsintCat index">
              <p>This email does not appear in OsintCat&apos;s breach index.</p>
            </Verdict>
          ) : osintcat.result?.status === "ok" ? (
            <>
              <Verdict
                tone="danger"
                title={`Found in ${formatNumber(osintcat.result.total)} breach record${osintcat.result.total === 1 ? "" : "s"}`}
              >
                <p>
                  This email appears in OsintCat&apos;s breach index. Change
                  the password on every affected account.
                </p>
              </Verdict>
              <div className="overflow-hidden rounded-lg border border-gray-200">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-200 bg-gray-50 text-left">
                      <th className="px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500">
                        Source
                      </th>
                      <th className="px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500">
                        Records
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {osintcat.result.sources.map((source) => (
                      <tr key={source.name}>
                        <td className="px-4 py-2.5 font-medium">{source.name}</td>
                        <td className="px-4 py-2.5 font-mono text-[13px]">
                          {formatNumber(source.count)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          ) : null}
        </div>
      </div>

      <div className="space-y-3 border-t border-gray-100 pt-6">
        <SectionTitle>
          Infostealer exposure
          <ConfidenceTag label="Hudson Rock" />
        </SectionTitle>
        {hudsonrock.status === "error" ? (
          <Verdict tone="warning" title="Infostealer lookup failed">
            <p>{hudsonrock.error}</p>
          </Verdict>
        ) : !hudsonrock.associated ? (
          <Verdict tone="ok" title="No infostealer infection found">
            <p>
              This email is not associated with any computer infected by
              info-stealing malware in Hudson Rock&apos;s database.
            </p>
          </Verdict>
        ) : (
          <>
            <Verdict
              tone="danger"
              title={`Associated with ${hudsonrock.stealers.length} infected computer${hudsonrock.stealers.length === 1 ? "" : "s"}`}
            >
              <p>
                This email was found on a computer infected by info-stealing
                malware. Credentials saved on that machine should be treated
                as compromised: change passwords from a clean device, revoke
                sessions, and enable two-factor authentication everywhere.
              </p>
            </Verdict>
            <div className="overflow-hidden rounded-lg border border-gray-200">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-200 bg-gray-50 text-left">
                    <th className="px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500">
                      Compromised
                    </th>
                    <th className="px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500">
                      Machine
                    </th>
                    <th className="hidden px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500 sm:table-cell">
                      OS
                    </th>
                    <th className="px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500">
                      Services hit
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {hudsonrock.stealers.map((stealer, i) => (
                    <tr key={`${stealer.computerName ?? "machine"}-${i}`}>
                      <td className="px-4 py-2.5 font-mono text-[13px]">
                        {stealer.dateCompromised
                          ? new Date(stealer.dateCompromised).toLocaleDateString("en-US", {
                              year: "numeric",
                              month: "short",
                              day: "numeric",
                            })
                          : "—"}
                      </td>
                      <td className="px-4 py-2.5 font-mono text-[13px]">
                        {stealer.computerName ?? "—"}
                      </td>
                      <td className="hidden px-4 py-2.5 text-[13px] text-gray-600 sm:table-cell">
                        {stealer.operatingSystem ?? "—"}
                      </td>
                      <td className="px-4 py-2.5 font-mono text-[13px]">
                        {stealer.totalCorporateServices + stealer.totalUserServices}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="text-xs leading-relaxed text-gray-500">
              Only infection metadata is shown — never stolen passwords,
              logins, or IP addresses. Source: Hudson Rock Cavalier.
            </p>
          </>
        )}
      </div>

      <div className="space-y-3 border-t border-gray-100 pt-6">
        <SectionTitle>GitHub exposure</SectionTitle>
        {!github.available ? (
          <Verdict
            tone="info"
            title="GitHub exposure lookup is not configured on this deployment"
          >
            <p>
              Searching public commits for this email needs a GitHub token
              (GITHUB_TOKEN). No token is configured, so no result is shown.
            </p>
          </Verdict>
        ) : github.result?.status === "error" ? (
          <Verdict tone="warning" title="GitHub lookup failed">
            <p>{github.result.error}</p>
          </Verdict>
        ) : github.result?.status === "rate_limited" ? (
          <Verdict tone="warning" title="GitHub lookup is rate-limited">
            <p>GitHub is throttling search requests. Try again in a minute.</p>
          </Verdict>
        ) : github.result?.status === "ok" && github.result.total === 0 ? (
          <Verdict tone="ok" title="No public commits found with this email">
            <p>
              This email does not appear as an author address in any public
              GitHub commit.
            </p>
          </Verdict>
        ) : github.result?.status === "ok" ? (
          <>
            <Verdict
              tone="warning"
              title={`Exposed in ${formatNumber(github.result.total)} public commit${github.result.total === 1 ? "" : "s"}`}
            >
              <p>
                This email appears as an author address in public GitHub
                commits, linking it to a GitHub identity. Consider using
                GitHub&apos;s private noreply email for future commits; past
                commits stay in git history unless rewritten.
              </p>
            </Verdict>
            <div className="overflow-hidden rounded-lg border border-gray-200">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-200 bg-gray-50 text-left">
                    <th className="px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500">
                      Repository
                    </th>
                    <th className="hidden px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500 sm:table-cell">
                      Author
                    </th>
                    <th className="px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500">
                      Commit
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {github.result.commits.map((commit) => (
                    <tr key={`${commit.repo}-${commit.url}`}>
                      <td className="px-4 py-2.5 font-mono text-[13px]">
                        {commit.url ? (
                          <a
                            href={commit.url}
                            target="_blank"
                            rel="noreferrer"
                            className="text-gray-700 underline-offset-2 hover:text-black hover:underline"
                          >
                            {commit.repo}
                          </a>
                        ) : (
                          commit.repo
                        )}
                      </td>
                      <td className="hidden px-4 py-2.5 text-[13px] text-gray-600 sm:table-cell">
                        {commit.authorName}
                      </td>
                      <td className="px-4 py-2.5 text-[13px] text-gray-600">
                        <span className="block truncate" title={commit.message}>
                          {commit.message}
                        </span>
                        {commit.date ? (
                          <span className="font-mono text-xs text-gray-500">
                            {new Date(commit.date).toLocaleDateString("en-US", {
                              year: "numeric",
                              month: "short",
                              day: "numeric",
                            })}
                          </span>
                        ) : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        ) : null}
      </div>

      <div className="space-y-3 border-t border-gray-100 pt-6">
        <SectionTitle>Account enumeration</SectionTitle>
        <EmailEnumeration
          email={data.email}
          available={data.enumeration.available}
        />
      </div>
    </div>
  );
}

// --------------------------------------------------------------------- hash

function formatEpoch(seconds?: number): string {
  if (seconds === undefined) return "—";
  const date = new Date(seconds * 1000);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function formatBytes(bytes?: number): string {
  if (bytes === undefined) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** Shared "this source needs an API key" block. */
function NeedsKeyNote({ provider, envVar, where }: { provider: string; envVar: string; where: string }) {
  return (
    <p className="text-[13px] leading-relaxed text-gray-500">
      {provider} needs an API key ({envVar}, {where}). No key is configured,
      so no result is shown — add one in your dashboard (bring your own key)
      or ask the operator to set it.
    </p>
  );
}

export function HashResult({ data }: { data: HashCheckResult }) {
  const vt = data.virustotal.result;
  const mb = data.malwarebazaar.result;
  const ha = data.hybridanalysis.result;
  const otx = data.otx.result;

  const vtMalicious = vt?.ok && !vt.notFound ? vt.malicious : undefined;
  const knownMalicious = data.circl.ok && !!data.circl.knownMalicious;
  const haScore = ha?.ok && !ha.notFound ? ha.threatScore : undefined;

  const anySourceErrored =
    !data.circl.ok ||
    !data.urlscan.ok ||
    (data.virustotal.available && !vt?.ok) ||
    (data.malwarebazaar.available && !mb?.ok) ||
    (data.hybridanalysis.available && !ha?.ok) ||
    (data.otx.available && !otx?.ok);

  const anyFound =
    (data.circl.ok && !data.circl.notFound) ||
    (data.urlscan.ok && data.urlscan.total > 0) ||
    (vt?.ok && !vt.notFound) ||
    (mb?.ok && !mb.notFound) ||
    (ha?.ok && !ha.notFound) ||
    (otx?.ok && !otx.notFound);

  const verdictTone: Tone =
    knownMalicious || (vtMalicious !== undefined && vtMalicious > 0) || (haScore !== undefined && haScore >= 50)
      ? "danger"
      : vtMalicious !== undefined && vtMalicious === 0
        ? "ok"
        : anyFound
          ? "info"
          : anySourceErrored
            ? "warning"
            : "info";
  const verdictTitle =
    knownMalicious
      ? "Known malicious — CIRCL flags this file"
      : vtMalicious !== undefined && vtMalicious > 0
        ? `${vtMalicious} VirusTotal engine${vtMalicious === 1 ? "" : "s"} flag this file`
        : haScore !== undefined && haScore >= 50
          ? `High threat score on Hybrid Analysis (${haScore}/100)`
          : vtMalicious !== undefined && vtMalicious === 0
            ? "No VirusTotal engine flags this file"
            : anyFound
              ? "This hash is known to at least one source"
              : "Not found in any source";

  return (
    <div className="space-y-6">
      <Verdict tone={verdictTone} title={verdictTitle}>
        <p>
          {vtMalicious !== undefined
            ? `VirusTotal: ${vtMalicious} malicious, ${vt?.suspicious ?? 0} suspicious, ${vt?.undetected ?? 0} undetected, ${vt?.harmless ?? 0} harmless.`
            : knownMalicious
              ? `CIRCL lists this file as known malicious (${data.circl.knownMalicious}).`
              : anyFound
                ? "The hash appears in at least one reputation source, but no source flags it as malicious."
                : "No reputation source has a record of this hash. That is not a clean verdict — it may simply be a file nobody has scanned yet."}
        </p>
        {anySourceErrored ? (
          <p className="mt-1.5">
            At least one source failed to answer — its section below shows the error.
          </p>
        ) : null}
      </Verdict>

      <div className="space-y-3">
        <SectionTitle>Hash</SectionTitle>
        <StatGrid
          items={[
            { label: "Algorithm", value: data.algorithm.toUpperCase() },
            {
              label: "Value",
              value: `${data.hash.slice(0, 16)}…${data.hash.slice(-8)}`,
            },
          ]}
        />
      </div>

      <div className="space-y-3 border-t border-gray-100 pt-6">
        <SectionTitle>CIRCL hashlookup</SectionTitle>
        {data.circl.ok ? (
          data.circl.notFound ? (
            <p className="text-[13px] text-gray-500">
              No record of this hash in CIRCL&apos;s known-file corpus.
            </p>
          ) : (
            <StatGrid
              items={[
                { label: "File name", value: data.circl.fileName ?? "—" },
                {
                  label: "File size",
                  value: data.circl.fileSize
                    ? formatBytes(Number(data.circl.fileSize))
                    : "—",
                },
                { label: "Product", value: data.circl.productName ?? "—" },
                {
                  label: "Known malicious",
                  value: data.circl.knownMalicious ?? "No",
                },
              ]}
            />
          )
        ) : (
          <Verdict tone="warning" title="CIRCL lookup failed">
            <p>{data.circl.error}</p>
          </Verdict>
        )}
        <p className="text-xs text-gray-500">
          Source: hashlookup.circl.lu (known-file corpus, incl. NSRL).
        </p>
      </div>

      <div className="space-y-3 border-t border-gray-100 pt-6">
        <SectionTitle>urlscan.io</SectionTitle>
        {data.urlscan.ok ? (
          <p className="text-[13px] leading-relaxed text-gray-700">
            {data.urlscan.total === 0
              ? "No public scan in the last 30 days downloaded a file with this hash."
              : `${formatNumber(data.urlscan.total)} public scan${data.urlscan.total === 1 ? "" : "s"} in the last 30 days downloaded a file with this hash${data.urlscan.totalCapped ? " (total capped at 10,000)" : ""}.`}
            {data.urlscan.searchUrl ? (
              <>
                {" "}
                <a
                  href={data.urlscan.searchUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 font-medium text-black underline underline-offset-2"
                >
                  View on urlscan.io <ExternalIcon />
                </a>
              </>
            ) : null}
          </p>
        ) : (
          <Verdict tone="warning" title="urlscan.io lookup failed">
            <p>{data.urlscan.error}</p>
          </Verdict>
        )}
      </div>

      <div className="space-y-3 border-t border-gray-100 pt-6">
        <SectionTitle>VirusTotal</SectionTitle>
        {!data.virustotal.available ? (
          <NeedsKeyNote provider="VirusTotal" envVar="VIRUSTOTAL_API_KEY" where="free tier, 500 req/day" />
        ) : vt && !vt.ok ? (
          <Verdict tone="warning" title="VirusTotal lookup failed">
            <p>{vt.error}</p>
          </Verdict>
        ) : vt?.notFound ? (
          <p className="text-[13px] text-gray-500">
            VirusTotal has never seen this hash.
          </p>
        ) : (
          <StatGrid
            items={[
              { label: "Malicious", value: String(vt?.malicious ?? "—") },
              { label: "Suspicious", value: String(vt?.suspicious ?? "—") },
              { label: "Undetected", value: String(vt?.undetected ?? "—") },
              { label: "Harmless", value: String(vt?.harmless ?? "—") },
              { label: "Name", value: vt?.meaningfulName ?? "—" },
              { label: "Type", value: vt?.typeDescription ?? "—" },
              { label: "First seen", value: formatEpoch(vt?.firstSeen) },
              { label: "Last analysis", value: formatEpoch(vt?.lastAnalysisDate) },
            ]}
          />
        )}
      </div>

      <div className="space-y-3 border-t border-gray-100 pt-6">
        <SectionTitle>MalwareBazaar</SectionTitle>
        {!data.malwarebazaar.available ? (
          <NeedsKeyNote provider="MalwareBazaar" envVar="MALWAREBAZAAR_API_KEY" where="free Auth-Key from auth.abuse.ch" />
        ) : mb && !mb.ok ? (
          <Verdict tone="warning" title="MalwareBazaar lookup failed">
            <p>{mb.error}</p>
          </Verdict>
        ) : mb?.notFound ? (
          <p className="text-[13px] text-gray-500">
            No sample with this hash in the MalwareBazaar database.
          </p>
        ) : (
          <StatGrid
            items={[
              { label: "Signature", value: mb?.signature ?? "—" },
              { label: "File name", value: mb?.fileName ?? "—" },
              { label: "File type", value: mb?.fileType ?? "—" },
              { label: "File size", value: formatBytes(mb?.fileSize) },
              { label: "First seen", value: formatDate(mb?.firstSeen) },
              {
                label: "Tags",
                value: mb?.tags && mb.tags.length > 0 ? mb.tags.join(", ") : "—",
              },
            ]}
          />
        )}
      </div>

      <div className="space-y-3 border-t border-gray-100 pt-6">
        <SectionTitle>Hybrid Analysis</SectionTitle>
        {!data.hybridanalysis.available ? (
          <NeedsKeyNote provider="Hybrid Analysis" envVar="HYBRID_ANALYSIS_API_KEY" where="free Public API key" />
        ) : ha && !ha.ok ? (
          <Verdict tone="warning" title="Hybrid Analysis lookup failed">
            <p>{ha.error}</p>
          </Verdict>
        ) : ha?.notFound ? (
          <p className="text-[13px] text-gray-500">
            No sandbox report for this hash.
          </p>
        ) : (
          <StatGrid
            items={[
              {
                label: "Threat score",
                value: ha?.threatScore !== undefined ? `${ha.threatScore}/100` : "—",
              },
              { label: "Verdict", value: ha?.verdict ?? "—" },
              { label: "Family", value: ha?.vxFamily ?? "—" },
              { label: "Submitted as", value: ha?.submitName ?? "—" },
              {
                label: "Reports",
                value: String(ha?.reportCount ?? "—"),
              },
            ]}
          />
        )}
      </div>

      <div className="space-y-3 border-t border-gray-100 pt-6">
        <SectionTitle>AlienVault OTX</SectionTitle>
        {!data.otx.available ? (
          <NeedsKeyNote provider="OTX" envVar="OTX_API_KEY" where="free, on your OTX profile page" />
        ) : otx && !otx.ok ? (
          <Verdict tone="warning" title="OTX lookup failed">
            <p>{otx.error}</p>
          </Verdict>
        ) : otx?.notFound ? (
          <p className="text-[13px] text-gray-500">
            No threat-intel pulse references this hash.
          </p>
        ) : (
          <div className="space-y-2">
            <p className="text-[13px] leading-relaxed text-gray-700">
              {otx?.pulseCount ?? 0} threat-intel pulse{(otx?.pulseCount ?? 0) === 1 ? "" : "s"} reference
              this hash.
            </p>
            {otx?.pulses && otx.pulses.length > 0 ? (
              <ul className="list-disc space-y-1 pl-5 text-[13px] text-gray-600">
                {otx.pulses.map((name) => (
                  <li key={name}>{name}</li>
                ))}
              </ul>
            ) : null}
          </div>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------- url

export function UrlResult({ data }: { data: UrlCheckResult }) {
  const vt = data.virustotal.result;
  const sb = data.safebrowsing.result;

  const vtMalicious = vt?.ok && !vt.notFound ? vt.malicious : undefined;
  const flagged = sb?.ok && sb.matches.length > 0;

  const verdictTone: Tone =
    flagged || (vtMalicious !== undefined && vtMalicious > 0)
      ? "danger"
      : vtMalicious !== undefined && vtMalicious === 0 && sb?.ok && sb.matches.length === 0
        ? "ok"
        : "info";
  const verdictTitle = flagged
    ? `Flagged by Safe Browsing: ${sb?.matches.map((m) => m.threatType).join(", ")}`
    : vtMalicious !== undefined && vtMalicious > 0
      ? `${vtMalicious} VirusTotal engine${vtMalicious === 1 ? "" : "s"} flag this URL`
      : vtMalicious !== undefined && vtMalicious === 0 && sb?.ok
        ? "No source flags this URL"
        : "No verdict available from keyed sources";

  return (
    <div className="space-y-6">
      <Verdict tone={verdictTone} title={verdictTitle}>
        <p>
          {flagged
            ? "Google Safe Browsing lists this URL as a threat. Do not visit it."
            : vtMalicious !== undefined && vtMalicious > 0
              ? `VirusTotal: ${vtMalicious} malicious, ${vt?.suspicious ?? 0} suspicious, ${vt?.undetected ?? 0} undetected, ${vt?.harmless ?? 0} harmless.`
              : vtMalicious !== undefined && vtMalicious === 0 && sb?.ok
                ? "VirusTotal and Safe Browsing both report no threat for this URL."
                : "The keyed sources (VirusTotal, Safe Browsing) are not configured on this deployment, so no verdict is shown. urlscan.io activity below is the only signal."}
        </p>
      </Verdict>

      <div className="space-y-3">
        <SectionTitle>urlscan.io</SectionTitle>
        {data.urlscan.ok ? (
          <p className="text-[13px] leading-relaxed text-gray-700">
            {data.urlscan.total === 0
              ? "No public scan of this exact URL in the last 30 days."
              : `${formatNumber(data.urlscan.total)} public scan${data.urlscan.total === 1 ? "" : "s"} of this exact URL in the last 30 days${data.urlscan.totalCapped ? " (total capped at 10,000)" : ""}.`}
            {data.urlscan.latestScanAt ? (
              <> Most recent: {formatDate(data.urlscan.latestScanAt)}.</>
            ) : null}
            {data.urlscan.searchUrl ? (
              <>
                {" "}
                <a
                  href={data.urlscan.searchUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 font-medium text-black underline underline-offset-2"
                >
                  View on urlscan.io <ExternalIcon />
                </a>
              </>
            ) : null}
          </p>
        ) : (
          <Verdict tone="warning" title="urlscan.io lookup failed">
            <p>{data.urlscan.error}</p>
          </Verdict>
        )}
        <p className="text-xs leading-relaxed text-gray-500">
          Scan activity is not a verdict — popular legitimate sites are scanned
          often, and a never-scanned URL can still be malicious.
        </p>
      </div>

      <div className="space-y-3 border-t border-gray-100 pt-6">
        <SectionTitle>VirusTotal</SectionTitle>
        {!data.virustotal.available ? (
          <NeedsKeyNote provider="VirusTotal" envVar="VIRUSTOTAL_API_KEY" where="free tier, 500 req/day" />
        ) : vt && !vt.ok ? (
          <Verdict tone="warning" title="VirusTotal lookup failed">
            <p>{vt.error}</p>
          </Verdict>
        ) : vt?.notFound ? (
          <p className="text-[13px] text-gray-500">
            VirusTotal has never scanned this URL. That is not a clean verdict.
          </p>
        ) : (
          <StatGrid
            items={[
              { label: "Malicious", value: String(vt?.malicious ?? "—") },
              { label: "Suspicious", value: String(vt?.suspicious ?? "—") },
              { label: "Undetected", value: String(vt?.undetected ?? "—") },
              { label: "Harmless", value: String(vt?.harmless ?? "—") },
              { label: "Last analysis", value: formatEpoch(vt?.lastAnalysisDate) },
            ]}
          />
        )}
      </div>

      <div className="space-y-3 border-t border-gray-100 pt-6">
        <SectionTitle>Google Safe Browsing</SectionTitle>
        {!data.safebrowsing.available ? (
          <NeedsKeyNote provider="Safe Browsing" envVar="SAFE_BROWSING_API_KEY" where="free tier, 10,000 req/day" />
        ) : sb && !sb.ok ? (
          <Verdict tone="warning" title="Safe Browsing lookup failed">
            <p>{sb.error}</p>
          </Verdict>
        ) : sb?.matches.length === 0 ? (
          <p className="text-[13px] text-gray-500">
            No match on Google&apos;s malware / social-engineering / unwanted-software lists.
          </p>
        ) : (
          <div className="space-y-2">
            {sb?.matches.map((match) => (
              <p key={`${match.threatType}-${match.platformType}`} className="text-[13px] text-gray-700">
                <span className="font-medium">{match.threatType}</span>
                {" — "}platform {match.platformType}
              </p>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// -------------------------------------------------------------------- image

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function ImageResult({ data }: { data: ImageExifResult }) {
  const verdictTone: Tone = data.gps
    ? "danger"
    : data.hasExif
      ? "warning"
      : "ok";
  const verdictTitle = data.gps
    ? "This photo carries its GPS location"
    : data.hasExif
      ? `Metadata found — ${data.fields.length} field${data.fields.length === 1 ? "" : "s"} embedded in the file`
      : "No metadata found in this image";

  return (
    <div className="space-y-6">
      <Verdict tone={verdictTone} title={verdictTitle}>
        <p>
          {data.gps
            ? "Anyone who receives this photo can read exactly where it was taken. Strip location data before sharing photos publicly."
            : data.hasExif
              ? "The photo reveals device and timing details (below). That is normal for unedited phone photos — it becomes an exposure when shared publicly."
              : "No EXIF, XMP, or IPTC metadata was found. The image was likely stripped by an editor or a sharing service."}
        </p>
        <p className="mt-1.5">
          Analyzed entirely in your browser — the file was never uploaded.
        </p>
      </Verdict>

      <div className="space-y-3">
        <SectionTitle>File</SectionTitle>
        <StatGrid
          items={[
            { label: "Name", value: data.fileName },
            { label: "Size", value: formatFileSize(data.fileSize) },
            { label: "Type", value: data.fileType },
          ]}
        />
      </div>

      {data.hasExif ? (
        <div className="space-y-3 border-t border-gray-100 pt-6">
          <SectionTitle>Embedded metadata</SectionTitle>
          <div className="overflow-hidden rounded-lg border border-gray-200">
            <table className="w-full text-sm">
              <tbody className="divide-y divide-gray-100">
                {data.fields.map((field) => (
                  <tr key={field.label}>
                    <td className="w-40 px-4 py-2.5 align-top text-xs font-medium uppercase tracking-wider text-gray-500">
                      {field.label}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-[13px] break-words">
                      {field.value}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {data.gps ? (
            <p className="text-[13px] leading-relaxed text-gray-700">
              <a
                href={`https://www.google.com/maps/search/?api=1&query=${data.gps.latitude},${data.gps.longitude}`}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 font-medium text-black underline underline-offset-2"
              >
                Open this location on Google Maps <ExternalIcon />
              </a>
            </p>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

// ------------------------------------------------------------------- wallet

function shortAddress(address: string): string {
  return `${address.slice(0, 8)}…${address.slice(-6)}`;
}

function formatTxTime(epochSeconds: number): string {
  const date = new Date(epochSeconds * 1000);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function WalletChainSection({
  title,
  chain,
  explorer,
}: {
  title: string;
  chain: WalletCheckResult["ethereum"];
  explorer: string;
}) {
  return (
    <div className="space-y-3 border-t border-gray-100 pt-6">
      <SectionTitle>{title}</SectionTitle>
      {!chain.ok ? (
        <Verdict tone="warning" title={`${title} lookup failed`}>
          <p>{chain.error}</p>
        </Verdict>
      ) : (
        <>
          <StatGrid
            items={[
              { label: "Balance", value: chain.balanceDisplay ?? "—" },
              {
                label: "Transactions",
                value:
                  chain.txCount !== undefined
                    ? `${formatNumber(chain.txCount)}${chain.txCountCapped ? "+" : ""}`
                    : "—",
              },
              {
                label: "First activity",
                value: chain.firstTx ? formatTxTime(chain.firstTx.timeStamp) : "—",
              },
              {
                label: "Last activity",
                value: chain.lastTx ? formatTxTime(chain.lastTx.timeStamp) : "—",
              },
            ]}
          />
          {chain.txCount === 0 ? (
            <p className="text-[13px] text-gray-500">
              This address has no transactions on {title} — it has never been used.
            </p>
          ) : null}
          {chain.txCountCapped ? (
            <p className="text-[13px] text-gray-500">
              More than 1,000 transactions — the count is capped at the first 1,000.
            </p>
          ) : null}
          {chain.lastTx ? (
            <p className="text-[13px] leading-relaxed text-gray-700">
              Latest transaction:{" "}
              <a
                href={`${explorer}/tx/${chain.lastTx.hash}`}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 font-mono font-medium text-black underline underline-offset-2"
              >
                {shortAddress(chain.lastTx.hash)} <ExternalIcon />
              </a>
            </p>
          ) : null}
        </>
      )}
    </div>
  );
}

export function WalletResult({ data }: { data: WalletCheckResult }) {
  const eth = data.ethereum;
  const bsc = data.bsc;
  const bothFailed = !eth.ok && !bsc.ok;
  const anyActivity =
    (eth.ok && (eth.txCount ?? 0) > 0) || (bsc.ok && (bsc.txCount ?? 0) > 0);

  const verdictTone: Tone = bothFailed ? "warning" : "info";
  const verdictTitle = bothFailed
    ? "The wallet lookup failed"
    : anyActivity
      ? "This address has on-chain activity"
      : "This address has no on-chain activity";

  return (
    <div className="space-y-6">
      <Verdict tone={verdictTone} title={verdictTitle}>
        <p>
          {bothFailed
            ? "Both chain lookups failed — the sections below show the errors."
            : anyActivity
              ? "Balances and activity below are public chain data. Anyone with this address can see the same."
              : "No transactions and no balance on either chain. The address exists as a string, but nothing has ever used it."}
        </p>
      </Verdict>

      <div className="space-y-3">
        <SectionTitle>Address</SectionTitle>
        <p className="break-all font-mono text-sm">{data.address}</p>
        <p className="text-[13px] leading-relaxed text-gray-500">
          <a
            href={`https://etherscan.io/address/${data.address}`}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1 font-medium text-black underline underline-offset-2"
          >
            View on Etherscan <ExternalIcon />
          </a>{" "}
          ·{" "}
          <a
            href={`https://bscscan.com/address/${data.address}`}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1 font-medium text-black underline underline-offset-2"
          >
            View on BscScan <ExternalIcon />
          </a>
        </p>
      </div>

      <WalletChainSection
        title="Ethereum"
        chain={eth}
        explorer="https://etherscan.io"
      />
      <WalletChainSection
        title="BNB Chain"
        chain={bsc}
        explorer="https://bscscan.com"
      />
    </div>
  );
}
