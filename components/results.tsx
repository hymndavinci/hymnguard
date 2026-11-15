// Result renderers for each check type. Pure presentational components.
// Client component: the username result has interactive search/filter state.

"use client";

import { useMemo, useState } from "react";
import type {
  DomainCheckResult,
  EmailCheckResponse,
  PhoneCheckResult,
  UsernameCheckResult,
} from "@/lib/api-types";
import EmailEnumeration from "./email-enumeration";

function formatNumber(value: number): string {
  return value.toLocaleString("en-US");
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
    </div>
  );
}

// -------------------------------------------------------------------- phone

export function PhoneResult({ data }: { data: PhoneCheckResult }) {
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
      <StatGrid
        items={[
          { label: "E.164", value: data.e164 ?? "—" },
          { label: "Country", value: data.country ?? "—" },
          {
            label: "Calling code",
            value: data.countryCallingCode
              ? `+${data.countryCallingCode}`
              : "—",
          },
          { label: "Type", value: data.type ?? "—" },
          { label: "International", value: data.international ?? "—" },
          { label: "National", value: data.national ?? "—" },
        ]}
      />
      <p className="text-xs leading-relaxed text-gray-500">
        Format, country, and validity only. No free, legitimate source exists
        for phone-number breach lookups, so this check does not claim to find
        breaches.
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
