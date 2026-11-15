"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type {
  DomainCheckResult,
  EmailCheckResponse,
  PasswordCheckResponse,
  PhoneCheckResult,
  UsernameCheckResult,
  UsernameChunkResponse,
  UsernamePlanResponse,
} from "@/lib/api-types";
import {
  addHistoryEntry,
  clearHistory,
  loadHistory,
  type CheckType,
  type HistoryEntry,
} from "@/lib/history";
import { sha1Hex } from "@/lib/sha1";
import {
  DomainResult,
  EmailResult,
  PasswordResult,
  PhoneResult,
  UsernameResult,
} from "./results";

interface TabConfig {
  id: CheckType;
  label: string;
  placeholder: string;
  hint: string;
  privacy: string;
}

const TABS: TabConfig[] = [
  {
    id: "email",
    label: "Email",
    placeholder: "you@example.com",
    hint: "Mail records, plus a breach lookup when a HIBP key is configured.",
    privacy: "Checked and discarded — never stored.",
  },
  {
    id: "username",
    label: "Username",
    placeholder: "username",
    hint: "Probed across 256 sites, in chunks — results stream in as each chunk finishes.",
    privacy: "Checked and discarded — never stored.",
  },
  {
    id: "domain",
    label: "Domain",
    placeholder: "example.com",
    hint: "DNS records, TLS certificate, security headers, subdomains.",
    privacy: "Checked and discarded — never stored.",
  },
  {
    id: "phone",
    label: "Phone",
    placeholder: "+6281234567890",
    hint: "Format, country, and validity. Not a breach lookup.",
    privacy: "Checked and discarded — never stored.",
  },
  {
    id: "password",
    label: "Password",
    placeholder: "Enter a password to check",
    hint: "Checked against Have I Been Pwned with k-anonymity.",
    privacy: "Hashed in your browser. Only the first 5 characters of the hash leave this page.",
  },
];

type CheckResultState =
  | { type: "email"; input: string; data: EmailCheckResponse; durationMs: number }
  | {
      type: "username";
      input: string;
      data: UsernameCheckResult;
      durationMs: number;
      /** Present while chunks are still arriving. */
      progress?: { checked: number; total: number };
    }
  | { type: "domain"; input: string; data: DomainCheckResult; durationMs: number }
  | { type: "phone"; input: string; data: PhoneCheckResult; durationMs: number }
  | { type: "password"; data: { count: number }; durationMs: number };

const EMPTY_INPUTS: Record<CheckType, string> = {
  email: "",
  username: "",
  domain: "",
  phone: "",
  password: "",
};

function summaryFor(result: CheckResultState): string {
  switch (result.type) {
    case "email": {
      if (!result.data.mxOk) return "No MX records";
      if (!result.data.hibp.available) return "MX ok · Breach lookup not configured";
      if (result.data.hibp.rateLimited) return "MX ok · Breach lookup rate-limited";
      const count = result.data.hibp.breaches?.length ?? 0;
      return count > 0 ? `Found in ${count} breach${count === 1 ? "" : "es"}` : "No breaches found";
    }
    case "username":
      return `Found on ${result.data.summary.found} of ${result.data.sites.length} sites`;
    case "domain": {
      const days = result.data.tls.daysUntilExpiry;
      const tls =
        result.data.tls.ok && days !== undefined
          ? `TLS ${days}d left`
          : "TLS unavailable";
      return `Headers ${result.data.headers.grade} · ${result.data.subdomains.total} subdomains · ${tls}`;
    }
    case "phone":
      return result.data.valid
        ? `Valid${result.data.country ? ` · ${result.data.country}` : ""}`
        : "Invalid number";
    case "password":
      return result.data.count > 0
        ? `Pwned — seen ${result.data.count.toLocaleString("en-US")} times`
        : "Not found in known breaches";
  }
}

function Spinner() {
  return (
    <span
      className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-gray-300 border-t-black"
      aria-hidden="true"
    />
  );
}

export default function CheckConsole() {
  const [activeTab, setActiveTab] = useState<CheckType>("email");
  const [inputs, setInputs] = useState<Record<CheckType, string>>(EMPTY_INPUTS);
  const [showPassword, setShowPassword] = useState(false);
  const [running, setRunning] = useState(false);
  const [elapsedMs, setElapsedMs] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<CheckResultState | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [historyLoaded, setHistoryLoaded] = useState(false);
  const elapsedTimer = useRef<ReturnType<typeof setInterval> | null>(null);

  const tab = TABS.find((t) => t.id === activeTab) ?? TABS[0];

  useEffect(() => {
    setHistory(loadHistory());
    setHistoryLoaded(true);
  }, []);

  useEffect(() => {
    if (!running) return;
    const started = Date.now();
    setElapsedMs(0);
    elapsedTimer.current = setInterval(() => {
      setElapsedMs(Date.now() - started);
    }, 100);
    return () => {
      if (elapsedTimer.current) clearInterval(elapsedTimer.current);
    };
  }, [running]);

  const runCheck = useCallback(
    async (type: CheckType, value: string) => {
      const started = performance.now();
      setRunning(true);
      setError(null);
      setResult(null);
      try {
        if (type === "password") {
          if (!window.crypto?.subtle) {
            throw new Error(
              "This browser cannot hash locally (a secure context is required).",
            );
          }
          const hash = await sha1Hex(value);
          const prefix = hash.slice(0, 5);
          const suffix = hash.slice(5);
          const res = await fetch("/api/check/password", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ prefix }),
          });
          const json = (await res.json().catch(() => ({}))) as {
            error?: string;
          } & Partial<PasswordCheckResponse>;
          if (!res.ok || !json.entries) {
            throw new Error(json.error ?? "The password check failed.");
          }
          const match = json.entries.find((entry) => entry.suffix === suffix);
          const count = match ? match.count : 0;
          const state: CheckResultState = {
            type: "password",
            data: { count },
            durationMs: performance.now() - started,
          };
          setResult(state);
          setHistory(
            addHistoryEntry({ type, input: "", summary: summaryFor(state) }),
          );
          return;
        }

        if (type === "username") {
          // Chunked check: fetch the plan, then POST one chunk at a time
          // (up to 4 in flight) and stream partial results into the UI.
          const planRes = await fetch("/api/check/username");
          const plan = (await planRes.json().catch(() => ({}))) as Partial<UsernamePlanResponse>;
          if (!planRes.ok || !plan.total || !plan.chunks) {
            throw new Error("Could not start the username check.");
          }
          const total = plan.total;
          const chunkCount = plan.chunks;
          const accumulated: UsernameCheckResult["sites"] = [];
          const pushPartial = () => {
            const data: UsernameCheckResult = {
              username: value,
              checkedAt: new Date().toISOString(),
              sites: [...accumulated],
              summary: {
                found: accumulated.filter((s) => s.status === "found").length,
                notFound: accumulated.filter((s) => s.status === "not_found").length,
                errors: accumulated.filter((s) => s.status === "error").length,
              },
            };
            setResult({
              type: "username",
              input: value,
              data,
              durationMs: performance.now() - started,
              progress: { checked: accumulated.length, total },
            });
          };
          const fetchChunk = async (chunk: number) => {
            const res = await fetch("/api/check/username", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ username: value, chunk }),
            });
            const json = (await res.json().catch(() => ({}))) as {
              error?: string;
            } & Partial<UsernameChunkResponse>;
            if (!res.ok || !json.sites) {
              throw new Error(json.error ?? "The username check failed.");
            }
            accumulated.push(...json.sites);
            pushPartial();
          };
          const queue = Array.from({ length: chunkCount }, (_, i) => i);
          const workers = Array.from({ length: Math.min(4, queue.length) }, async () => {
            while (queue.length > 0) {
              const chunk = queue.shift();
              if (chunk === undefined) return;
              await fetchChunk(chunk);
            }
          });
          await Promise.all(workers);
          const finalState: CheckResultState = {
            type: "username",
            input: value,
            data: {
              username: value,
              checkedAt: new Date().toISOString(),
              sites: [...accumulated],
              summary: {
                found: accumulated.filter((s) => s.status === "found").length,
                notFound: accumulated.filter((s) => s.status === "not_found").length,
                errors: accumulated.filter((s) => s.status === "error").length,
              },
            },
            durationMs: performance.now() - started,
          };
          setResult(finalState);
          setHistory(
            addHistoryEntry({ type, input: value, summary: summaryFor(finalState) }),
          );
          return;
        }

        const res = await fetch(`/api/check/${type}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ [type]: value }),
        });
        const json = (await res.json().catch(() => ({}))) as {
          error?: string;
        };
        if (!res.ok) {
          throw new Error(json.error ?? "The check failed.");
        }
        const durationMs = performance.now() - started;
        const state = {
          type,
          input: value,
          data: json,
          durationMs,
        } as CheckResultState;
        setResult(state);
        setHistory(
          addHistoryEntry({ type, input: value, summary: summaryFor(state) }),
        );
      } catch (err) {
        setError(
          err instanceof Error ? err.message : "The check failed. Try again.",
        );
      } finally {
        setRunning(false);
      }
    },
    [],
  );

  function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    const value = inputs[activeTab].trim();
    if (!value || running) return;
    void runCheck(activeTab, value);
  }

  function handleRerun(entry: HistoryEntry) {
    if (entry.type === "password" || !entry.input) return;
    setActiveTab(entry.type);
    setInputs((prev) => ({ ...prev, [entry.type]: entry.input }));
    void runCheck(entry.type, entry.input);
    document
      .getElementById("console")
      ?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function handleClearHistory() {
    clearHistory();
    setHistory([]);
  }

  return (
    <>
      <section
        id="console"
        className="scroll-mt-20 overflow-hidden rounded-xl border border-gray-200 bg-white shadow-[0_1px_2px_rgba(0,0,0,0.04)]"
      >
        <div className="border-b border-gray-200 px-4 pt-4 sm:px-5">
          <div
            role="tablist"
            aria-label="Check type"
            className="no-scrollbar inline-flex max-w-full gap-1 overflow-x-auto rounded-lg bg-gray-100 p-1"
          >
            {TABS.map((item) => (
              <button
                key={item.id}
                role="tab"
                aria-selected={activeTab === item.id}
                onClick={() => setActiveTab(item.id)}
                className={`whitespace-nowrap rounded-md px-3.5 py-1.5 text-sm font-medium transition-all ${
                  activeTab === item.id
                    ? "bg-white text-black shadow-sm ring-1 ring-gray-200"
                    : "text-gray-500 hover:text-black"
                }`}
              >
                {item.label}
              </button>
            ))}
          </div>
          <p className="py-3 text-[13px] text-gray-500">{tab.hint}</p>
        </div>

        <form onSubmit={handleSubmit} className="p-4 sm:p-5">
          <label
            htmlFor="check-input"
            className="mb-2 block text-xs font-medium text-gray-700"
          >
            {tab.label}
          </label>
          <div className="flex flex-col gap-3 sm:flex-row">
            <div className="relative flex-1">
              <input
                id="check-input"
                type={
                  activeTab === "password"
                    ? showPassword
                      ? "text"
                      : "password"
                    : activeTab === "email"
                      ? "email"
                      : "text"
                }
                value={inputs[activeTab]}
                onChange={(event) =>
                  setInputs((prev) => ({
                    ...prev,
                    [activeTab]: event.target.value,
                  }))
                }
                placeholder={tab.placeholder}
                aria-label={`${tab.label} to check`}
                autoComplete="off"
                spellCheck={false}
                className="h-11 w-full rounded-md border border-gray-300 bg-white px-3.5 font-mono text-[15px] text-black outline-none transition-colors placeholder:font-sans placeholder:text-gray-500 focus:border-black"
              />
              {activeTab === "password" ? (
                <button
                  type="button"
                  onClick={() => setShowPassword((prev) => !prev)}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 rounded px-1.5 py-1 text-xs font-medium text-gray-500 hover:text-black"
                >
                  {showPassword ? "Hide" : "Show"}
                </button>
              ) : null}
            </div>
            <button
              type="submit"
              disabled={running || !inputs[activeTab].trim()}
              className="h-11 shrink-0 rounded-md bg-black px-6 text-sm font-medium text-white transition-colors hover:bg-gray-800 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {running ? "Running…" : "Run check"}
            </button>
          </div>
          <p className="mt-2.5 flex items-start gap-1.5 text-[13px] leading-relaxed text-gray-500">
            <svg
              width="14"
              height="14"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              className="mt-0.5 shrink-0"
              aria-hidden="true"
            >
              <path d="M12 3l7 3v5c0 4.5-3 7.6-7 9-4-1.4-7-4.5-7-9V6l7-3z" />
            </svg>
            {tab.privacy}
          </p>
        </form>

        {running ? (
          <div className="flex items-center gap-3 border-t border-gray-200 px-4 py-4 sm:px-5">
            <Spinner />
            <p className="text-sm text-gray-600">
              Running checks…{" "}
              <span className="font-mono text-xs text-gray-500">
                {(elapsedMs / 1000).toFixed(1)}s
              </span>
            </p>
          </div>
        ) : null}

        {error ? (
          <div className="border-t border-gray-200 px-4 py-4 sm:px-5">
            <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-900">
              {error}
            </div>
          </div>
        ) : null}

        {result ? (
          <div className="border-t border-gray-200 p-4 sm:p-5">
            <div className="mb-5 flex flex-wrap items-baseline justify-between gap-2">
              <h2 className="text-base font-semibold tracking-tight">
                {result.type === "password" ? (
                  "Password result"
                ) : (
                  <>
                    Results for{" "}
                    <span className="font-mono text-[15px]">
                      {result.input}
                    </span>
                  </>
                )}
              </h2>
              <p className="font-mono text-xs text-gray-500">
                {result.type === "username" && result.progress
                  ? `Checking… ${result.progress.checked} of ${result.progress.total} sites`
                  : `Completed in ${(result.durationMs / 1000).toFixed(1)}s`}
              </p>
            </div>
            {result.type === "email" ? (
              <EmailResult data={result.data} />
            ) : result.type === "username" ? (
              <UsernameResult data={result.data} progress={result.progress} />
            ) : result.type === "domain" ? (
              <DomainResult data={result.data} />
            ) : result.type === "phone" ? (
              <PhoneResult data={result.data} />
            ) : (
              <PasswordResult count={result.data.count} />
            )}
          </div>
        ) : null}

        {!running && !error && !result ? (
          <div className="border-t border-gray-200 px-4 py-10 sm:px-5">
            <div className="rounded-lg border border-dashed border-gray-200 px-4 py-8 text-center">
              <p className="text-sm font-medium text-gray-700">
                Results will appear here
              </p>
              <p className="mt-1 text-[13px] text-gray-500">
                Enter a {tab.label.toLowerCase()} above and run the check.
              </p>
            </div>
          </div>
        ) : null}
      </section>

      <section id="history" className="mt-12 scroll-mt-20">
        <div className="flex items-baseline justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold tracking-tight">
              Recent checks
            </h2>
            <p className="mt-1 text-sm text-gray-500">
              Stored only in this browser. Passwords are never stored — not
              even here.
            </p>
          </div>
          {historyLoaded && history.length > 0 ? (
            <button
              onClick={handleClearHistory}
              className="shrink-0 rounded-md border border-gray-200 bg-white px-3 py-1.5 text-[13px] font-medium text-gray-600 transition-colors hover:bg-gray-50 hover:text-black"
            >
              Clear history
            </button>
          ) : null}
        </div>

        <div className="mt-4 overflow-hidden rounded-lg border border-gray-200">
          {!historyLoaded ? (
            <p className="px-4 py-6 text-sm text-gray-500">Loading…</p>
          ) : history.length === 0 ? (
            <p className="px-4 py-6 text-sm text-gray-500">
              No checks yet. Run your first check above.
            </p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-200 bg-gray-50 text-left">
                  <th className="px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500">
                    Type
                  </th>
                  <th className="px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500">
                    Input
                  </th>
                  <th className="px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500">
                    Result
                  </th>
                  <th className="hidden px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500 sm:table-cell">
                    When
                  </th>
                  <th className="px-4 py-2.5 text-right text-xs font-medium uppercase tracking-wider text-gray-500" />
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {history.map((entry) => (
                  <tr key={entry.id}>
                    <td className="px-4 py-2.5">
                      <span className="rounded-md border border-gray-200 bg-gray-50 px-2 py-0.5 text-xs font-medium capitalize">
                        {entry.type}
                      </span>
                    </td>
                    <td className="max-w-[180px] truncate px-4 py-2.5 font-mono text-[13px]">
                      {entry.input || "••••••••"}
                    </td>
                    <td className="px-4 py-2.5 text-[13px] text-gray-600">
                      {entry.summary}
                    </td>
                    <td className="hidden whitespace-nowrap px-4 py-2.5 text-[13px] text-gray-500 sm:table-cell">
                      {new Date(entry.at).toLocaleString("en-US", {
                        month: "short",
                        day: "numeric",
                        hour: "2-digit",
                        minute: "2-digit",
                      })}
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      {entry.type !== "password" && entry.input ? (
                        <button
                          onClick={() => handleRerun(entry)}
                          disabled={running}
                          className="whitespace-nowrap rounded-md px-2 py-1 text-[13px] font-medium text-gray-600 transition-colors hover:bg-gray-100 hover:text-black disabled:opacity-40"
                        >
                          Re-run
                        </button>
                      ) : (
                        <span className="text-xs text-gray-500">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </section>
    </>
  );
}
