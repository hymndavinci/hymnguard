// Account enumeration UI: ownership verification flow + chunked results.
//
// Flow: request code (sent to the email) → enter code → verified → run
// enumeration in chunks, streaming results like the username check.
// If the deployment has no Resend key / signing secret, the section shows
// a needs-key state and nothing runs.

"use client";

import { useMemo, useState } from "react";
import type {
  EnumChunkResult,
  EnumPlanResponse,
  EnumSiteResult,
  VerifyRequestResponse,
  VerifyResponse,
} from "@/lib/api-types";

type Phase = "idle" | "code-sent" | "verified" | "running" | "done";

type EnumFilter = "all" | "exists" | "not_exists" | "error";

const FILTER_LABELS: Record<EnumFilter, string> = {
  all: "All",
  exists: "Found",
  not_exists: "Not found",
  error: "Errors",
};

export default function EmailEnumeration({
  email,
  available,
}: {
  email: string;
  available: boolean;
}) {
  const [phase, setPhase] = useState<Phase>("idle");
  const [code, setCode] = useState("");
  const [codeToken, setCodeToken] = useState<string | null>(null);
  const [verificationToken, setVerificationToken] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sites, setSites] = useState<EnumSiteResult[]>([]);
  const [progress, setProgress] = useState<{ checked: number; total: number } | null>(null);
  const [filter, setFilter] = useState<EnumFilter>("all");
  const [query, setQuery] = useState("");

  async function requestCode() {
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/check/email/verify-request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const json = (await res.json().catch(() => ({}))) as {
        error?: string;
      } & Partial<VerifyRequestResponse>;
      if (!res.ok || !json.token) {
        throw new Error(json.error ?? "Could not send the verification code.");
      }
      setCodeToken(json.token);
      setPhase("code-sent");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not send the code.");
    } finally {
      setBusy(false);
    }
  }

  async function submitCode() {
    if (!/^\d{6}$/.test(code) || !codeToken) return;
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/check/email/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, code, token: codeToken }),
      });
      const json = (await res.json().catch(() => ({}))) as {
        error?: string;
      } & Partial<VerifyResponse>;
      if (!res.ok || !json.verified || !json.verificationToken) {
        throw new Error(json.error ?? "Invalid or expired code.");
      }
      setVerificationToken(json.verificationToken);
      setPhase("verified");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification failed.");
    } finally {
      setBusy(false);
    }
  }

  async function runEnumeration() {
    if (!verificationToken) return;
    setBusy(true);
    setError(null);
    setSites([]);
    setPhase("running");
    try {
      const planRes = await fetch("/api/check/email/enumerate");
      const plan = (await planRes.json().catch(() => ({}))) as Partial<EnumPlanResponse>;
      if (!planRes.ok || !plan.total || !plan.chunks) {
        throw new Error("Could not start enumeration.");
      }
      const total = plan.total;
      const accumulated: EnumSiteResult[] = [];
      setProgress({ checked: 0, total });
      const fetchChunk = async (chunk: number) => {
        const res = await fetch("/api/check/email/enumerate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, verificationToken, chunk }),
        });
        const json = (await res.json().catch(() => ({}))) as {
          error?: string;
        } & Partial<EnumChunkResult>;
        if (!res.ok || !json.sites) {
          throw new Error(json.error ?? "Enumeration failed.");
        }
        accumulated.push(...json.sites);
        setSites([...accumulated]);
        setProgress({ checked: accumulated.length, total });
      };
      const queue = Array.from({ length: plan.chunks }, (_, i) => i);
      const workers = Array.from({ length: Math.min(4, queue.length) }, async () => {
        while (queue.length > 0) {
          const chunk = queue.shift();
          if (chunk === undefined) return;
          await fetchChunk(chunk);
        }
      });
      await Promise.all(workers);
      setProgress(null);
      setPhase("done");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Enumeration failed.");
      setPhase("verified");
      setProgress(null);
    } finally {
      setBusy(false);
    }
  }

  const ordered = useMemo(
    () =>
      [...sites].sort((a, b) => {
        const rank = (s: string) =>
          s === "exists" ? 0 : s === "not_exists" ? 1 : 2;
        return rank(a.status) - rank(b.status) || a.name.localeCompare(b.name);
      }),
    [sites],
  );

  const counts = useMemo(
    () => ({
      all: ordered.length,
      exists: ordered.filter((s) => s.status === "exists").length,
      not_exists: ordered.filter((s) => s.status === "not_exists").length,
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

  if (!available) {
    return (
      <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3.5 text-amber-900">
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 shrink-0 rounded-full bg-amber-500" />
          <p className="text-sm font-semibold">Account enumeration is not configured on this deployment</p>
        </div>
        <p className="mt-1.5 pl-4 text-[13px] leading-relaxed opacity-90">
          Enumeration checks whether this email is registered on popular sites.
          It requires ownership verification by email code, which needs a
          Resend API key and a signing secret (RESEND_API_KEY, VERIFY_SECRET)
          — neither is configured here, so enumeration cannot run.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <p className="text-[13px] leading-relaxed text-gray-600">
        Enumeration checks whether this email is registered on popular sites
        via their public signup checks. It only runs after you prove you own
        the address — a code is sent to it first. Some checks may trigger a
        password-reset email from the checked site; run this only on your own
        email address.
      </p>

      {phase === "idle" ? (
        <button
          onClick={requestCode}
          disabled={busy}
          className="h-10 rounded-md bg-black px-5 text-sm font-medium text-white transition-colors hover:bg-gray-800 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {busy ? "Sending code…" : "Send verification code"}
        </button>
      ) : null}

      {phase === "code-sent" ? (
        <div className="space-y-3">
          <p className="text-[13px] text-gray-600">
            A 6-digit code was sent to{" "}
            <span className="font-mono">{email}</span>. It expires in 10
            minutes.
          </p>
          <div className="flex flex-col gap-3 sm:flex-row">
            <input
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              value={code}
              onChange={(event) =>
                setCode(event.target.value.replace(/\D/g, "").slice(0, 6))
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
              {busy ? "Verifying…" : "Verify code"}
            </button>
          </div>
          <button
            onClick={requestCode}
            disabled={busy}
            className="text-[13px] font-medium text-gray-600 underline-offset-2 hover:text-black hover:underline disabled:opacity-40"
          >
            Resend code
          </button>
        </div>
      ) : null}

      {phase === "verified" ? (
        <div className="space-y-3">
          <div className="flex items-center gap-2 rounded-lg border border-green-200 bg-green-50 px-4 py-3 text-sm text-green-900">
            <span className="h-2 w-2 shrink-0 rounded-full bg-green-500" />
            <p className="font-medium">
              Ownership verified for {email}. Enumeration is unlocked for 30
              minutes.
            </p>
          </div>
          <button
            onClick={runEnumeration}
            disabled={busy}
            className="h-10 rounded-md bg-black px-5 text-sm font-medium text-white transition-colors hover:bg-gray-800 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {busy ? "Running…" : "Run enumeration"}
          </button>
        </div>
      ) : null}

      {error ? (
        <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-900">
          {error}
        </div>
      ) : null}

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

      {sites.length > 0 ? (
        <>
          <div className="grid grid-cols-3 gap-px overflow-hidden rounded-lg border border-gray-200 bg-gray-200">
            {[
              { label: "Accounts found", value: String(counts.exists) },
              { label: "Not found", value: String(counts.not_exists) },
              { label: "Errors", value: String(counts.error) },
            ].map((item) => (
              <div key={item.label} className="bg-white px-3.5 py-3">
                <p className="text-xs text-gray-500">{item.label}</p>
                <p className="mt-0.5 truncate font-mono text-sm font-medium">
                  {item.value}
                </p>
              </div>
            ))}
          </div>

          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="inline-flex max-w-full gap-1 overflow-x-auto rounded-lg bg-gray-100 p-1">
              {(Object.keys(FILTER_LABELS) as EnumFilter[]).map((key) => (
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
                      {site.status === "exists" ? (
                        <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-green-700">
                          <span className="h-1.5 w-1.5 rounded-full bg-green-500" />
                          Registered
                        </span>
                      ) : site.status === "not_exists" ? (
                        <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-gray-500">
                          <span className="h-1.5 w-1.5 rounded-full bg-gray-300" />
                          Not registered
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
                  </tr>
                ))}
                {visible.length === 0 ? (
                  <tr>
                    <td colSpan={2} className="px-4 py-6 text-center text-[13px] text-gray-500">
                      No sites match this filter.
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
          <p className="text-xs text-gray-500">
            Showing {visible.length} of {ordered.length} checked sites.
            {counts.error > 0
              ? ` ${counts.error} site${counts.error === 1 ? "" : "s"} could not be checked — those are inconclusive, not “not registered”.`
              : ""}
          </p>
        </>
      ) : null}
    </div>
  );
}
