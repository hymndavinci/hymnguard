// Dossier mode (Phase 7): verify ownership of identifiers, build a
// consolidated exposure report from them, and view/export the latest run.
//
// The hard rule is visible in the UI as well as the API: the build picker
// only lists identifiers the user has already verified. Nothing else can
// be added to a dossier.

"use client";

import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type Dispatch,
  type SetStateAction,
} from "react";
import type {
  DomainCheckResult,
  EmailCheckResponse,
  EnumChunkResult,
  IpCheckResult,
  UsernameCheckResult,
} from "@/lib/api-types";
import {
  DomainResult,
  EmailResult,
  IpResult,
  UsernameResult,
} from "@/components/results";

// ------------------------------------------------------------------ shared

async function fetchJson(path: string, init?: RequestInit) {
  const res = await fetch(path, init);
  const json = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  return { res, json };
}

function maskEmail(email: string): string {
  const at = email.indexOf("@");
  if (at <= 0) return "***";
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  const head = local.length >= 2 ? local.slice(0, 2) : local.slice(0, 1);
  return `${head}***@${domain}`;
}

function Section({
  title,
  description,
  children,
  className,
}: {
  title: string;
  description: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`mt-10 border-t border-gray-200 pt-8 first:mt-0 first:border-t-0 first:pt-0 ${className ?? ""}`}
    >
      <h2 className="text-lg font-semibold tracking-tight">{title}</h2>
      <p className="mt-1 max-w-2xl text-sm leading-relaxed text-gray-500">
        {description}
      </p>
      <div className="mt-5">{children}</div>
    </section>
  );
}

const METHOD_LABELS: Record<string, string> = {
  account_email: "Your account email",
  monitor: "Monitored email",
  email_code: "Verified by email code",
  username_localpart: "Local-part of a verified email",
  username_github: "Linked via GitHub commits",
  domain_txt: "DNS TXT record",
};

interface VerifiedIdentifier {
  id: string;
  type: "email" | "username" | "domain";
  display: string;
  method: string;
  verifiedAt: string;
  derived: boolean;
}

interface DossierFinding {
  id: string;
  identifier: string;
  identifierType: string;
  severity: "high" | "medium" | "low" | "info";
  points: number;
  title: string;
  detail: string;
  remediation?: string;
  remediationPriority?: 1 | 2 | 3;
}

interface DossierRemediation {
  action: string;
  priority: 1 | 2 | 3;
  findingIds: string[];
}

interface DossierReport {
  score: number;
  band: string;
  findings: DossierFinding[];
  remediations: DossierRemediation[];
  crossRefs: string[];
  computedAt: string;
}

interface DossierSectionData {
  type: string;
  display: string;
  status: "ok" | "partial" | "error";
  checkedAt: string;
  summary: string;
  result: unknown;
  error?: string;
  partialErrors?: string[];
}

interface PublicRun {
  id: string;
  identifiers: { type: string; display: string; hash: string }[];
  sections: Record<string, DossierSectionData>;
  report: DossierReport | null;
  score: number | null;
  status: "running" | "complete" | "partial";
  createdAt: string;
  updatedAt: string;
}

// ------------------------------------------------------- identifier forms

function EmailAddForm({
  onVerified,
  onToken,
}: {
  onVerified: () => void;
  /** Called with a fresh verification token (keyed by masked display) so
   *  the next dossier build can include account enumeration for it. */
  onToken: (maskedDisplay: string, token: string) => void;
}) {
  const [email, setEmail] = useState("");
  const [phase, setPhase] = useState<"idle" | "code-sent">("idle");
  const [code, setCode] = useState("");
  const [codeToken, setCodeToken] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function addEmail(verificationToken?: string) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const { res, json } = await fetchJson("/api/dossier/identifiers", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          type: "email",
          value: email,
          ...(verificationToken ? { token: verificationToken } : {}),
        }),
      });
      if (res.status === 401 && json.needsVerification) {
        const codeRes = await fetchJson("/api/check/email/verify-request", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email }),
        });
        if (!codeRes.res.ok || typeof codeRes.json.token !== "string") {
          throw new Error(
            typeof codeRes.json.error === "string"
              ? codeRes.json.error
              : "Could not send the verification code.",
          );
        }
        setCodeToken(codeRes.json.token as string);
        setPhase("code-sent");
        setNotice(`A 6-digit code was sent to ${email}.`);
        return;
      }
      if (!res.ok) {
        throw new Error(
          typeof json.error === "string"
            ? json.error
            : "Could not verify this email.",
        );
      }
      if (verificationToken) onToken(maskEmail(email), verificationToken);
      setEmail("");
      setPhase("idle");
      setCode("");
      setCodeToken(null);
      setNotice(
        json.alreadyVerified
          ? "This email is already verified — it is in your list below."
          : "Email verified. It is now in your list below.",
      );
      onVerified();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not verify this email.");
    } finally {
      setBusy(false);
    }
  }

  async function submitCode() {
    if (!/^\d{6}$/.test(code) || !codeToken) return;
    setBusy(true);
    setError(null);
    try {
      const { res, json } = await fetchJson("/api/check/email/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, code, token: codeToken }),
      });
      if (!res.ok || !json.verified || typeof json.verificationToken !== "string") {
        throw new Error(
          typeof json.error === "string" ? json.error : "Invalid or expired code.",
        );
      }
      await addEmail(json.verificationToken as string);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-3">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (email.trim()) void addEmail();
        }}
        className="flex flex-col gap-3 sm:flex-row"
      >
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="you@example.com"
          aria-label="Email address to verify"
          autoComplete="off"
          spellCheck={false}
          required
          className="h-11 flex-1 rounded-md border border-gray-300 bg-white px-3.5 font-mono text-[15px] text-black outline-none transition-colors placeholder:text-gray-500 focus:border-black"
        />
        <button
          type="submit"
          disabled={busy || !email.trim()}
          className="h-11 shrink-0 rounded-md bg-black px-6 text-sm font-medium text-white transition-colors hover:bg-gray-800 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {busy ? "Verifying…" : "Verify this email"}
        </button>
      </form>
      {phase === "code-sent" ? (
        <div className="space-y-3 rounded-lg border border-gray-200 bg-gray-50 p-4">
          <p className="text-[13px] text-gray-600">
            Enter the code sent to{" "}
            <span className="font-mono">{email}</span>.
          </p>
          <div className="flex flex-col gap-3 sm:flex-row">
            <input
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              value={code}
              onChange={(e) =>
                setCode(e.target.value.replace(/\D/g, "").slice(0, 6))
              }
              placeholder="123456"
              aria-label="Verification code"
              className="h-10 w-full rounded-md border border-gray-300 bg-white px-3 font-mono text-[15px] tracking-[0.3em] text-black outline-none transition-colors placeholder:text-gray-500 focus:border-black sm:w-48"
            />
            <button
              onClick={submitCode}
              disabled={busy || !/^\d{6}$/.test(code)}
              className="h-10 shrink-0 rounded-md bg-black px-5 text-sm font-medium text-white transition-colors hover:bg-gray-800 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {busy ? "Checking…" : "Confirm code"}
            </button>
          </div>
        </div>
      ) : null}
      {error ? <p className="text-sm text-red-700">{error}</p> : null}
      {notice ? <p className="text-sm text-green-700">{notice}</p> : null}
      <p className="text-[13px] leading-relaxed text-gray-500">
        A 6-digit code is sent to the address — only the inbox owner can
        complete it. The token is also kept for this session, so a dossier
        built now can include account enumeration for this email.
      </p>
    </div>
  );
}

function UsernameAddForm({ onVerified }: { onVerified: () => void }) {
  const [username, setUsername] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function addUsername() {
    setBusy(true);
    setError(null);
    setNote(null);
    setNotice(null);
    try {
      const { res, json } = await fetchJson("/api/dossier/identifiers", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type: "username", value: username }),
      });
      if (!res.ok) {
        setError(
          typeof json.error === "string"
            ? json.error
            : "Could not verify this username.",
        );
        if (typeof json.note === "string") setNote(json.note);
        return;
      }
      setUsername("");
      setNotice(
        `Username verified (${METHOD_LABELS[String(json.method)] ?? "verified"}).`,
      );
      onVerified();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not verify this username.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-3">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (username.trim()) void addUsername();
        }}
        className="flex flex-col gap-3 sm:flex-row"
      >
        <input
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder="your-username"
          aria-label="Username to verify"
          autoComplete="off"
          spellCheck={false}
          required
          className="h-11 flex-1 rounded-md border border-gray-300 bg-white px-3.5 font-mono text-[15px] text-black outline-none transition-colors placeholder:text-gray-500 focus:border-black"
        />
        <button
          type="submit"
          disabled={busy || !username.trim()}
          className="h-11 shrink-0 rounded-md bg-black px-6 text-sm font-medium text-white transition-colors hover:bg-gray-800 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {busy ? "Verifying…" : "Verify this username"}
        </button>
      </form>
      {error ? <p className="text-sm text-red-700">{error}</p> : null}
      {note ? <p className="text-sm text-amber-700">{note}</p> : null}
      {notice ? <p className="text-sm text-green-700">{notice}</p> : null}
      <p className="text-[13px] leading-relaxed text-gray-500">
        A username is verified when it is the local-part of one of your
        verified emails, or when a public GitHub commit by that login uses
        one of your verified emails as its author email (needs a GitHub
        token — add one in Settings).
      </p>
    </div>
  );
}

function DomainAddForm({ onVerified }: { onVerified: () => void }) {
  const [domain, setDomain] = useState("");
  const [record, setRecord] = useState<{
    host: string;
    value: string;
    expiresInSec: number;
  } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  async function requestRecord() {
    setBusy(true);
    setError(null);
    setNotice(null);
    setRecord(null);
    try {
      const { res, json } = await fetchJson(
        "/api/dossier/verify-domain/request",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ domain }),
        },
      );
      if (!res.ok || typeof json.value !== "string") {
        throw new Error(
          typeof json.error === "string"
            ? json.error
            : "Could not create a verification record.",
        );
      }
      setRecord({
        host: String(json.host),
        value: String(json.value),
        expiresInSec: Number(json.expiresInSec),
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create a verification record.");
    } finally {
      setBusy(false);
    }
  }

  async function confirmRecord() {
    setBusy(true);
    setError(null);
    try {
      const { res, json } = await fetchJson(
        "/api/dossier/verify-domain/confirm",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ domain }),
        },
      );
      if (!res.ok) {
        throw new Error(
          typeof json.error === "string"
            ? json.error
            : "Domain could not be verified.",
        );
      }
      setDomain("");
      setRecord(null);
      setNotice(
        json.alreadyVerified
          ? "This domain is already verified."
          : "Domain verified. It is now in your list below.",
      );
      onVerified();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Domain could not be verified.");
    } finally {
      setBusy(false);
    }
  }

  async function copyValue() {
    if (!record) return;
    try {
      await navigator.clipboard.writeText(record.value);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard unavailable; the value is selectable in the box.
    }
  }

  return (
    <div className="space-y-3">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (domain.trim()) void requestRecord();
        }}
        className="flex flex-col gap-3 sm:flex-row"
      >
        <input
          type="text"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="example.com"
          aria-label="Domain to verify"
          autoComplete="off"
          spellCheck={false}
          required
          className="h-11 flex-1 rounded-md border border-gray-300 bg-white px-3.5 font-mono text-[15px] text-black outline-none transition-colors placeholder:text-gray-500 focus:border-black"
        />
        <button
          type="submit"
          disabled={busy || !domain.trim()}
          className="h-11 shrink-0 rounded-md bg-black px-6 text-sm font-medium text-white transition-colors hover:bg-gray-800 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {busy ? "Creating…" : "Get verification record"}
        </button>
      </form>
      {record ? (
        <div className="space-y-3 rounded-lg border border-gray-200 bg-gray-50 p-4">
          <p className="text-[13px] leading-relaxed text-gray-600">
            Add this TXT record at your DNS provider, then confirm. The
            token is valid for{" "}
            {Math.round(record.expiresInSec / 3600)} hours.
          </p>
          <div className="space-y-2 font-mono text-[13px]">
            <div className="flex flex-col gap-1 sm:flex-row sm:items-center">
              <span className="w-20 shrink-0 text-gray-500">Host</span>
              <span className="break-all">{record.host}</span>
            </div>
            <div className="flex flex-col gap-1 sm:flex-row sm:items-start">
              <span className="w-20 shrink-0 pt-0.5 text-gray-500">Value</span>
              <span className="break-all">{record.value}</span>
            </div>
          </div>
          <div className="flex flex-wrap gap-3">
            <button
              onClick={copyValue}
              className="h-10 rounded-md border border-gray-300 bg-white px-4 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-50"
            >
              {copied ? "Copied" : "Copy value"}
            </button>
            <button
              onClick={confirmRecord}
              disabled={busy}
              className="h-10 rounded-md bg-black px-5 text-sm font-medium text-white transition-colors hover:bg-gray-800 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {busy ? "Checking DNS…" : "I added the record — confirm"}
            </button>
          </div>
        </div>
      ) : null}
      {error ? <p className="text-sm text-red-700">{error}</p> : null}
      {notice ? <p className="text-sm text-green-700">{notice}</p> : null}
      <p className="text-[13px] leading-relaxed text-gray-500">
        Only someone who controls the domain&apos;s DNS can add the record.
        DNS changes can take a few minutes to propagate — if confirmation
        says the record is missing, wait and try again.
      </p>
    </div>
  );
}

// ---------------------------------------------------------- identifiers

function IdentifiersSection({
  identifiers,
  onChanged,
  onToken,
}: {
  identifiers: VerifiedIdentifier[] | null;
  onChanged: () => void;
  onToken: (maskedDisplay: string, token: string) => void;
}) {
  const [addType, setAddType] = useState<"email" | "username" | "domain">(
    "email",
  );
  const [removing, setRemoving] = useState<string | null>(null);

  async function remove(id: string) {
    setRemoving(id);
    try {
      await fetchJson(`/api/dossier/identifiers?id=${encodeURIComponent(id)}`, {
        method: "DELETE",
      });
      onChanged();
    } finally {
      setRemoving(null);
    }
  }

  return (
    <div className="space-y-6">
      {identifiers === null ? (
        <p className="text-sm text-gray-500">Loading…</p>
      ) : identifiers.length === 0 ? (
        <p className="text-sm text-gray-500">
          No verified identifiers yet. Verify one below to start — a dossier
          can only be built from identifiers you own.
        </p>
      ) : (
        <div className="overflow-hidden rounded-lg border border-gray-200">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 bg-gray-50 text-left">
                <th className="px-3 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500 sm:px-4">
                  Type
                </th>
                <th className="px-3 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500 sm:px-4">
                  Identifier
                </th>
                <th className="hidden px-3 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500 sm:table-cell sm:px-4">
                  How it was verified
                </th>
                <th className="px-3 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500 sm:px-4" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {identifiers.map((row) => (
                <tr key={row.id}>
                  <td className="px-3 py-2.5 sm:px-4">
                    <span className="rounded-md border border-gray-200 bg-gray-50 px-2 py-0.5 text-xs font-medium capitalize">
                      {row.type}
                    </span>
                  </td>
                  <td className="max-w-[140px] truncate px-3 py-2.5 font-mono text-[13px] sm:max-w-[220px] sm:px-4">
                    {row.display}
                  </td>
                  <td className="hidden px-3 py-2.5 text-[13px] text-gray-600 sm:table-cell sm:px-4">
                    {METHOD_LABELS[row.method] ?? row.method}
                  </td>
                  <td className="px-3 py-2.5 text-right sm:px-4">
                    {row.derived ? (
                      <span
                        className="text-xs text-gray-400"
                        title="This identifier comes from your account or a monitor."
                      >
                        —
                      </span>
                    ) : (
                      <button
                        onClick={() => void remove(row.id)}
                        disabled={removing === row.id}
                        className="rounded-md border border-gray-200 bg-white px-2.5 py-1 text-xs font-medium text-gray-600 transition-colors hover:bg-gray-50 hover:text-black disabled:opacity-40"
                      >
                        {removing === row.id ? "Removing…" : "Remove"}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div>
        <div className="mb-4 flex flex-wrap gap-2" role="tablist" aria-label="Add an identifier">
          {(
            [
              ["email", "Email"],
              ["username", "Username"],
              ["domain", "Domain"],
            ] as const
          ).map(([type, label]) => (
            <button
              key={type}
              role="tab"
              aria-selected={addType === type}
              onClick={() => setAddType(type)}
              className={`rounded-md border px-3.5 py-1.5 text-sm font-medium transition-colors ${
                addType === type
                  ? "border-black bg-black text-white"
                  : "border-gray-200 bg-white text-gray-600 hover:bg-gray-50 hover:text-black"
              }`}
            >
              {label}
            </button>
          ))}
        </div>
        {addType === "email" ? (
          <EmailAddForm onVerified={onChanged} onToken={onToken} />
        ) : addType === "username" ? (
          <UsernameAddForm onVerified={onChanged} />
        ) : (
          <DomainAddForm onVerified={onChanged} />
        )}
      </div>

      <p className="text-[13px] leading-relaxed text-gray-500">
        Phone numbers and crypto wallets can&apos;t be verified here — there
        is no SMS channel and no message signing. Passwords, file hashes,
        URLs, and images are not identity identifiers and never appear in a
        dossier. Your current IP can be added at build time.
      </p>
    </div>
  );
}

// --------------------------------------------------------------- builder

function BuildSection({
  identifiers,
  enumTokens,
  onBuilt,
}: {
  identifiers: VerifiedIdentifier[];
  enumTokens: Record<string, string>;
  onBuilt: Dispatch<SetStateAction<PublicRun | null>>;
}) {
  const [selected, setSelected] = useState<Set<string>>(
    () => new Set(identifiers.map((i) => i.id)),
  );
  const [includeIp, setIncludeIp] = useState(false);
  const [includeEnum, setIncludeEnum] = useState(true);
  const [building, setBuilding] = useState(false);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(
    null,
  );
  const [error, setError] = useState<string | null>(null);

  // Keep the selection in sync when identifiers are added/removed:
  // new ones join the selection, removed ones drop out, and deliberate
  // deselections are preserved.
  const prevIdsRef = useRef<Set<string>>(new Set());
  useEffect(() => {
    const currentIds = new Set(identifiers.map((i) => i.id));
    // Capture the previous ids first: the setState updater below runs
    // during the next render, after this ref has already been updated.
    const prevIds = prevIdsRef.current;
    prevIdsRef.current = currentIds;
    setSelected((prev) => {
      const next = new Set<string>();
      for (const id of prev) if (currentIds.has(id)) next.add(id);
      for (const id of currentIds) if (!prevIds.has(id)) next.add(id);
      return next;
    });
  }, [identifiers]);

  const selectedEmails = identifiers.filter(
    (i) => i.type === "email" && selected.has(i.id),
  );
  const enumReady = selectedEmails.filter((i) => enumTokens[i.display]);
  const total = selected.size + (includeIp ? 1 : 0);

  async function build() {
    const verifiedIds = identifiers
      .filter((i) => selected.has(i.id))
      .map((i) => i.id);
    setBuilding(true);
    setError(null);
    setProgress({ done: 0, total: verifiedIds.length + (includeIp ? 1 : 0) });
    try {
      const { res, json } = await fetchJson("/api/dossier/build", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          verifiedIds,
          includeCurrentIp: includeIp,
        }),
      });
      if (!res.ok) {
        throw new Error(
          typeof json.error === "string"
            ? json.error
            : "Could not start the dossier.",
        );
      }
      const created = json as unknown as PublicRun;
      onBuilt(created);

      // Chunks run two at a time (same discipline as the username console).
      const count = created.identifiers.length;
      let done = 0;
      const runChunk = async (index: number) => {
        const ident = created.identifiers[index];
        const token =
          ident.type === "email" && includeEnum
            ? enumTokens[ident.display]
            : undefined;
        const chunk = await fetchJson("/api/dossier/build/chunk", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            runId: created.id,
            index,
            ...(token ? { token } : {}),
          }),
        });
        done += 1;
        setProgress({ done, total: count });
        if (chunk.json.run) {
          onBuilt(chunk.json.run as PublicRun);
        } else if (chunk.json.section) {
          const section = chunk.json.section as DossierSectionData;
          onBuilt((prev) => {
            const base = prev ?? created;
            return {
              ...base,
              sections: { ...base.sections, [String(index)]: section },
            };
          });
        }
      };
      await Promise.all(
        [0, 1].map(async (worker) => {
          for (let i = worker; i < count; i += 2) {
            await runChunk(i);
          }
        }),
      );
      // Final refresh so the report is the stored one, not a merge.
      const latest = await fetchJson("/api/dossier");
      if (latest.res.ok && latest.json.run) {
        onBuilt(latest.json.run as PublicRun);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not build the dossier.");
    } finally {
      setBuilding(false);
      setProgress(null);
    }
  }

  return (
    <div className="space-y-4">
      {identifiers.length === 0 ? (
        <p className="text-sm text-gray-500">
          Verify an identifier above first — there is nothing to build a
          dossier from yet.
        </p>
      ) : (
        <>
          <div className="space-y-2">
            {identifiers.map((i) => (
              <label
                key={i.id}
                className="flex cursor-pointer items-center gap-3 rounded-lg border border-gray-200 bg-white px-4 py-3 transition-colors hover:bg-gray-50"
              >
                <input
                  type="checkbox"
                  checked={selected.has(i.id)}
                  onChange={(e) => {
                    setSelected((prev) => {
                      const next = new Set(prev);
                      if (e.target.checked) next.add(i.id);
                      else next.delete(i.id);
                      return next;
                    });
                  }}
                  disabled={building}
                  className="h-4 w-4 accent-black"
                />
                <span className="rounded-md border border-gray-200 bg-gray-50 px-2 py-0.5 text-xs font-medium capitalize">
                  {i.type}
                </span>
                <span className="truncate font-mono text-[13px]">{i.display}</span>
                {i.type === "email" && enumTokens[i.display] ? (
                  <span className="ml-auto shrink-0 rounded-full border border-green-200 bg-green-50 px-2 py-0.5 text-[11px] font-medium text-green-700">
                    Enumeration ready
                  </span>
                ) : null}
              </label>
            ))}
            <label className="flex cursor-pointer items-center gap-3 rounded-lg border border-gray-200 bg-white px-4 py-3 transition-colors hover:bg-gray-50">
              <input
                type="checkbox"
                checked={includeIp}
                onChange={(e) => setIncludeIp(e.target.checked)}
                disabled={building}
                className="h-4 w-4 accent-black"
              />
              <span className="rounded-md border border-gray-200 bg-gray-50 px-2 py-0.5 text-xs font-medium">
                IP
              </span>
              <span className="text-[13px] text-gray-600">
                My current IP address
              </span>
              <span className="ml-auto shrink-0 text-xs text-gray-400">
                Verified by your connection
              </span>
            </label>
          </div>

          {selectedEmails.length > 0 ? (
            <label className="flex cursor-pointer items-start gap-3 rounded-lg border border-gray-200 bg-gray-50 px-4 py-3">
              <input
                type="checkbox"
                checked={includeEnum && enumReady.length > 0}
                onChange={(e) => setIncludeEnum(e.target.checked)}
                disabled={building || enumReady.length === 0}
                className="mt-0.5 h-4 w-4 accent-black"
              />
              <span className="text-[13px] leading-relaxed text-gray-600">
                Include account enumeration for emails with a fresh
                verification token (
                {enumReady.length} of {selectedEmails.length} ready
                {enumReady.length === 0
                  ? " — verify an email with a code in this session to enable it"
                  : ""}
                ).
              </span>
            </label>
          ) : null}

          {progress ? (
            <div className="space-y-2">
              <div className="h-1.5 overflow-hidden rounded-full bg-gray-100">
                <div
                  className="h-full bg-black transition-all"
                  style={{
                    width: `${progress.total === 0 ? 0 : Math.round((progress.done / progress.total) * 100)}%`,
                  }}
                />
              </div>
              <p className="text-[13px] text-gray-500">
                Checking {progress.done} of {progress.total}…
              </p>
            </div>
          ) : null}

          {error ? <p className="text-sm text-red-700">{error}</p> : null}

          <button
            onClick={() => void build()}
            disabled={building || total === 0}
            className="h-11 rounded-md bg-black px-6 text-sm font-medium text-white transition-colors hover:bg-gray-800 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {building
              ? "Building…"
              : total === 0
                ? "Pick at least one identifier"
                : `Build dossier (${total} identifier${total === 1 ? "" : "s"})`}
          </button>
          <p className="text-[13px] leading-relaxed text-gray-500">
            Each identifier is checked live (breaches, exposure, reputation)
            and the results are saved as your latest dossier. Building again
            replaces it.
          </p>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- report

const SEVERITY_STYLE: Record<string, string> = {
  high: "bg-red-500",
  medium: "bg-amber-500",
  low: "bg-gray-400",
  info: "bg-gray-300",
};

const BAND_STYLE: Record<string, string> = {
  Low: "border-green-200 bg-green-50 text-green-700",
  Moderate: "border-amber-200 bg-amber-50 text-amber-700",
  High: "border-red-200 bg-red-50 text-red-700",
  Critical: "border-red-500 bg-red-50 text-red-900",
};

function openInConsole(type: string, input: string) {
  try {
    localStorage.setItem(
      "hymnguard:console-prefill",
      JSON.stringify({ tab: type, input }),
    );
  } catch {
    // Storage unavailable; the console still opens.
  }
  window.location.href = "/#console";
}

function EnumBlock({ data }: { data: EnumChunkResult }) {
  return (
    <div className="mt-4 rounded-lg border border-gray-200 p-4">
      <h4 className="text-sm font-semibold">Account enumeration</h4>
      <p className="mt-1 text-[13px] text-gray-500">
        {data.summary.found} of {data.sites.length} probed sites have an
        account with this email.
      </p>
      <ul className="mt-3 space-y-1.5">
        {data.sites.map((site) => (
          <li
            key={site.id}
            className="flex items-center justify-between gap-3 text-[13px]"
          >
            <span className="font-medium">
              {site.name}
              {site.isNSFW ? (
                <span className="ml-2 rounded border border-red-200 bg-red-50 px-1.5 py-0.5 text-[10px] font-medium text-red-700">
                  18+
                </span>
              ) : null}
            </span>
            <span
              className={
                site.status === "exists"
                  ? "text-red-700"
                  : site.status === "error"
                    ? "text-amber-700"
                    : "text-gray-500"
              }
            >
              {site.status === "exists"
                ? "Registered"
                : site.status === "error"
                  ? `Could not check${site.detail ? ` — ${site.detail}` : ""}`
                  : "Not registered"}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function SectionCard({ section }: { section: DossierSectionData }) {
  const result = section.result as
    | (EmailCheckResponse & { enumResults?: EnumChunkResult })
    | UsernameCheckResult
    | DomainCheckResult
    | IpCheckResult
    | null;
  return (
    <div className="rounded-lg border border-gray-200">
      <div className="flex flex-wrap items-center gap-3 px-4 py-3.5">
        <span className="rounded-md border border-gray-200 bg-gray-50 px-2 py-0.5 text-xs font-medium capitalize">
          {section.type}
        </span>
        <span className="truncate font-mono text-[13px] font-medium">
          {section.display}
        </span>
        <span
          className={`ml-auto shrink-0 rounded-full border px-2 py-0.5 text-[11px] font-medium ${
            section.status === "ok"
              ? "border-green-200 bg-green-50 text-green-700"
              : section.status === "partial"
                ? "border-amber-200 bg-amber-50 text-amber-700"
                : "border-red-200 bg-red-50 text-red-700"
          }`}
        >
          {section.status === "ok"
            ? "Checked"
            : section.status === "partial"
              ? "Partial"
              : "Failed"}
        </span>
      </div>
      <div className="border-t border-gray-100 px-4 py-3">
        <p className="text-[13px] leading-relaxed text-gray-600">
          {section.summary}
        </p>
        {section.error ? (
          <p className="mt-1.5 text-[13px] text-red-700">{section.error}</p>
        ) : null}
        {section.partialErrors && section.partialErrors.length > 0 ? (
          <ul className="mt-1.5 space-y-1">
            {section.partialErrors.map((e) => (
              <li key={e} className="text-[13px] text-amber-700">
                {e}
              </li>
            ))}
          </ul>
        ) : null}
        {result ? (
          <details className="mt-3">
            <summary className="no-print cursor-pointer text-[13px] font-medium text-gray-700 hover:text-black">
              Full check details
            </summary>
            <div className="mt-3">
              {section.type === "email" ? (
                <>
                  <EmailResult
                    data={result as EmailCheckResponse}
                  />
                  {(result as { enumResults?: EnumChunkResult }).enumResults ? (
                    <EnumBlock
                      data={
                        (result as { enumResults: EnumChunkResult })
                          .enumResults
                      }
                    />
                  ) : null}
                </>
              ) : section.type === "username" ? (
                <UsernameResult data={result as UsernameCheckResult} />
              ) : section.type === "domain" ? (
                <DomainResult data={result as DomainCheckResult} />
              ) : section.type === "ip" ? (
                <IpResult data={result as IpCheckResult} />
              ) : null}
            </div>
          </details>
        ) : null}
        <div className="no-print mt-3">
          {section.type === "email" ? (
            <button
              onClick={() => openInConsole("email", "")}
              className="rounded-md border border-gray-200 bg-white px-3 py-1.5 text-[13px] font-medium text-gray-600 transition-colors hover:bg-gray-50 hover:text-black"
            >
              Open the email checker
            </button>
          ) : (
            <button
              onClick={() => openInConsole(section.type, section.display)}
              className="rounded-md border border-gray-200 bg-white px-3 py-1.5 text-[13px] font-medium text-gray-600 transition-colors hover:bg-gray-50 hover:text-black"
            >
              Re-run in console
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

function ReportView({ run }: { run: PublicRun }) {
  const report = run.report;
  const sections = run.identifiers.map((_, i) => run.sections[String(i)]);
  const failed = sections.filter((s) => s?.status === "error");
  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of report?.findings ?? []) counts[f.severity] += 1;

  function downloadJson() {
    const blob = new Blob([JSON.stringify(run, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `hymnguard-dossier-${run.createdAt.slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function printReport() {
    // Expand every section so the printed report is complete.
    document.querySelectorAll("details").forEach((d) => {
      (d as HTMLDetailsElement).open = true;
    });
    window.print();
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-3">
        <p className="text-sm text-gray-500">
          Built{" "}
          {new Date(run.createdAt).toLocaleString("en-US", {
            month: "short",
            day: "numeric",
            hour: "2-digit",
            minute: "2-digit",
          })}{" "}
          · {run.identifiers.length} identifier
          {run.identifiers.length === 1 ? "" : "s"}
        </p>
        <span
          className={`rounded-full border px-2 py-0.5 text-[11px] font-medium ${
            run.status === "complete"
              ? "border-green-200 bg-green-50 text-green-700"
              : run.status === "partial"
                ? "border-amber-200 bg-amber-50 text-amber-700"
                : "border-gray-200 bg-gray-50 text-gray-500"
          }`}
        >
          {run.status === "complete"
            ? "Complete"
            : run.status === "partial"
              ? "Partial"
              : "Running"}
        </span>
        <div className="no-print ml-auto flex flex-wrap gap-2">
          <button
            onClick={downloadJson}
            className="rounded-md border border-gray-200 bg-white px-3 py-1.5 text-[13px] font-medium text-gray-600 transition-colors hover:bg-gray-50 hover:text-black"
          >
            Download JSON
          </button>
          <button
            onClick={printReport}
            className="rounded-md border border-gray-200 bg-white px-3 py-1.5 text-[13px] font-medium text-gray-600 transition-colors hover:bg-gray-50 hover:text-black"
          >
            Print / Save as PDF
          </button>
        </div>
      </div>

      {run.status === "partial" && failed.length > 0 ? (
        <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3.5 text-[13px] leading-relaxed text-amber-900">
          {failed.length} section{failed.length === 1 ? "" : "s"} failed
          ({failed.map((s) => s.display).join(", ")}). The score below only
          reflects what was checked — build the dossier again to retry them.
        </div>
      ) : null}

      {report ? (
        <>
          <div className="flex flex-wrap items-center gap-6 rounded-lg border border-gray-200 px-5 py-4">
            <div>
              <div className="text-4xl font-semibold tracking-tight tabular-nums">
                {report.score}
                <span className="text-lg text-gray-400">/100</span>
              </div>
              <div className="mt-1 text-[13px] text-gray-500">
                Exposure score
              </div>
            </div>
            <span
              className={`rounded-full border px-3 py-1 text-sm font-medium ${BAND_STYLE[report.band] ?? "border-gray-200 bg-gray-50 text-gray-600"}`}
            >
              {report.band}
            </span>
            <div className="ml-auto flex flex-wrap gap-x-5 gap-y-1 text-[13px] text-gray-600">
              <span>
                <span className="mr-1.5 inline-block h-2 w-2 rounded-full bg-red-500 align-middle" />
                {counts.high} high
              </span>
              <span>
                <span className="mr-1.5 inline-block h-2 w-2 rounded-full bg-amber-500 align-middle" />
                {counts.medium} medium
              </span>
              <span>
                <span className="mr-1.5 inline-block h-2 w-2 rounded-full bg-gray-400 align-middle" />
                {counts.low} low
              </span>
            </div>
          </div>

          {report.crossRefs.length > 0 ? (
            <div>
              <h3 className="text-sm font-semibold">How your identifiers connect</h3>
              <ul className="mt-2 space-y-1.5">
                {report.crossRefs.map((ref) => (
                  <li
                    key={ref}
                    className="text-[13px] leading-relaxed text-gray-600"
                  >
                    {ref}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}

          {report.remediations.length > 0 ? (
            <div>
              <h3 className="text-sm font-semibold">What to fix first</h3>
              <ol className="mt-2 space-y-2">
                {report.remediations.map((step, i) => (
                  <li
                    key={step.action}
                    className="flex items-start gap-3 rounded-lg border border-gray-200 px-4 py-3"
                  >
                    <span className="mt-0.5 shrink-0 font-mono text-[13px] text-gray-400">
                      {String(i + 1).padStart(2, "0")}
                    </span>
                    <span className="text-[13px] leading-relaxed">
                      {step.action}
                    </span>
                    <span
                      className={`ml-auto shrink-0 rounded-full border px-2 py-0.5 text-[11px] font-medium ${
                        step.priority === 1
                          ? "border-red-200 bg-red-50 text-red-700"
                          : step.priority === 2
                            ? "border-amber-200 bg-amber-50 text-amber-700"
                            : "border-gray-200 bg-gray-50 text-gray-500"
                      }`}
                    >
                      P{step.priority}
                    </span>
                  </li>
                ))}
              </ol>
            </div>
          ) : (
            <p className="text-sm text-gray-500">
              No exposure found — nothing to fix right now.
            </p>
          )}

          {report.findings.length > 0 ? (
            <div>
              <h3 className="text-sm font-semibold">Findings</h3>
              <ul className="mt-2 space-y-2">
                {report.findings.map((f) => (
                  <li
                    key={f.id}
                    className="rounded-lg border border-gray-200 px-4 py-3"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`h-2 w-2 shrink-0 rounded-full ${SEVERITY_STYLE[f.severity]}`}
                      />
                      <span className="text-[13px] font-medium">{f.title}</span>
                      <span className="ml-auto shrink-0 font-mono text-xs text-gray-400">
                        +{f.points}
                      </span>
                    </div>
                    <p className="mt-1 pl-4 font-mono text-xs text-gray-500">
                      {f.identifier}
                    </p>
                    {f.detail ? (
                      <p className="mt-1 pl-4 text-[13px] leading-relaxed text-gray-600">
                        {f.detail}
                      </p>
                    ) : null}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </>
      ) : (
        <p className="text-sm text-gray-500">
          This dossier is still building — its sections appear below as they
          finish.
        </p>
      )}

      <div className="space-y-3">
        {run.identifiers.map((ident, i) => {
          const section = run.sections[String(i)];
          if (!section) {
            return (
              <div
                key={ident.hash}
                className="rounded-lg border border-gray-200 px-4 py-3.5"
              >
                <span className="rounded-md border border-gray-200 bg-gray-50 px-2 py-0.5 text-xs font-medium capitalize">
                  {ident.type}
                </span>
                <span className="ml-3 font-mono text-[13px]">
                  {ident.display}
                </span>
                <span className="ml-3 text-[13px] text-gray-500">
                  Checking…
                </span>
              </div>
            );
          }
          return <SectionCard key={ident.hash} section={section} />;
        })}
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ main

export default function DossierClient({
  userEmail,
}: {
  userEmail: string;
}) {
  const [identifiers, setIdentifiers] = useState<VerifiedIdentifier[] | null>(
    null,
  );
  const [run, setRun] = useState<PublicRun | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  // Fresh verification tokens, keyed by masked email display, kept in
  // memory only (never stored) so a dossier built this session can include
  // account enumeration for those emails.
  const [enumTokens, setEnumTokens] = useState<Record<string, string>>({});

  const loadIdentifiers = useCallback(async () => {
    const { res, json } = await fetchJson("/api/dossier/identifiers");
    if (!res.ok) {
      setLoadError(
        typeof json.error === "string"
          ? json.error
          : "Could not load your verified identifiers.",
      );
      return;
    }
    setIdentifiers(
      Array.isArray(json.identifiers)
        ? (json.identifiers as VerifiedIdentifier[])
        : [],
    );
  }, []);

  const loadRun = useCallback(async () => {
    const { res, json } = await fetchJson("/api/dossier");
    if (res.ok && json.run) setRun(json.run as PublicRun);
  }, []);

  useEffect(() => {
    void loadIdentifiers();
    void loadRun();
  }, [loadIdentifiers, loadRun]);

  const handleToken = useCallback((maskedDisplay: string, token: string) => {
    setEnumTokens((prev) => ({ ...prev, [maskedDisplay]: token }));
  }, []);

  return (
    <div className="pb-16">
      {loadError ? (
        <p className="mb-6 text-sm text-red-700">{loadError}</p>
      ) : null}
      <Section
        title="Your verified identifiers"
        description={`Signed in as ${userEmail}. A dossier only runs on identifiers listed here — your verified account email, monitored emails, and anything else you prove you own below.`}
      >
        <IdentifiersSection
          identifiers={identifiers}
          onChanged={loadIdentifiers}
          onToken={handleToken}
        />
      </Section>

      <Section
        title="Build your dossier"
        description="Pick the identifiers to include. Each one is checked live and the results are combined into one report with an exposure score and prioritized fixes."
        className="no-print"
      >
        <BuildSection
          identifiers={identifiers ?? []}
          enumTokens={enumTokens}
          onBuilt={setRun}
        />
      </Section>

      {run ? (
        <Section
          title="Latest dossier"
          description="Your most recent report. Building again replaces it."
        >
          <ReportView run={run} />
        </Section>
      ) : (
        <Section
          title="Latest dossier"
          description="Your most recent report. Building again replaces it."
        >
          <p className="text-sm text-gray-500">
            No dossier yet. Verify an identifier above, then build one.
          </p>
        </Section>
      )}
    </div>
  );
}
