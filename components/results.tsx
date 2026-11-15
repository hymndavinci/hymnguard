// Result renderers for each check type. Pure presentational components.

import type {
  DomainCheckResult,
  EmailCheckResponse,
  PhoneCheckResult,
  UsernameCheckResult,
} from "@/lib/api-types";

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

export function UsernameResult({ data }: { data: UsernameCheckResult }) {
  const ordered = [...data.sites].sort((a, b) => {
    const rank = (s: string) =>
      s === "found" ? 0 : s === "not_found" ? 1 : 2;
    return rank(a.status) - rank(b.status) || a.name.localeCompare(b.name);
  });

  return (
    <div className="space-y-5">
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
            ? `“${data.username}” exists on ${data.summary.found} of ${data.sites.length} checked sites`
            : `“${data.username}” was not found on any checked site`}
        </SectionTitle>
        <p className="mt-1 text-[13px] text-gray-500">
          {data.summary.errors > 0
            ? `${data.summary.errors} site${data.summary.errors === 1 ? "" : "s"} could not be checked (blocked or rate-limited) — those are inconclusive, not “not found”.`
            : "Every site responded."}
        </p>
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
            {ordered.map((site) => (
              <tr key={site.id}>
                <td className="px-4 py-2.5 font-medium">{site.name}</td>
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
          </tbody>
        </table>
      </div>
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

export function EmailResult({ data }: { data: EmailCheckResponse }) {
  const hibp = data.hibp;
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
        <SectionTitle>Data breaches</SectionTitle>
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
              Have I Been Pwned is throttling requests right now. Try again in
              a few minutes.
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
                where it is offered. Only breach metadata is shown here —
                never breach contents.
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
              Pwned. New breaches surface over time, so this is a point-in-time
              result.
            </p>
          </Verdict>
        )}
      </div>
    </div>
  );
}
