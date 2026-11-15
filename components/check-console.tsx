"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type {
  DomainCheckResult,
  EmailCheckResponse,
  HashCheckResult,
  IpCheckResult,
  PasswordCheckResponse,
  PhoneCheckResult,
  UrlCheckResult,
  UsernameCheckResult,
  UsernameChunkResponse,
  UsernamePlanResponse,
  WalletCheckResult,
} from "@/lib/api-types";
import { CHECKERS } from "@/lib/checkers";
import {
  addHistoryEntry,
  clearHistory,
  loadHistory,
  type CheckType,
  type HistoryEntry,
} from "@/lib/history";
import {
  analyzeImage,
  type ImageExifResult,
} from "@/lib/image-exif";
import { sha1Hex } from "@/lib/sha1";
import { normalizeWalletAddress } from "@/lib/wallet-address";
import {
  DomainResult,
  EmailResult,
  HashResult,
  ImageResult,
  IpResult,
  PasswordResult,
  PhoneResult,
  UrlResult,
  UsernameResult,
  WalletResult,
} from "./results";

// Tabs come from the checker registry (lib/checkers.ts) — adding a
// checker there adds its tab here.
const TABS = CHECKERS;

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
  | { type: "ip"; input: string; data: IpCheckResult; durationMs: number }
  | { type: "phone"; input: string; data: PhoneCheckResult; durationMs: number }
  | { type: "hash"; input: string; data: HashCheckResult; durationMs: number }
  | { type: "url"; input: string; data: UrlCheckResult; durationMs: number }
  | { type: "image"; input: string; data: ImageExifResult; durationMs: number }
  | { type: "wallet"; input: string; data: WalletCheckResult; durationMs: number }
  | { type: "password"; data: { count: number }; durationMs: number };

const EMPTY_INPUTS: Record<CheckType, string> = {
  email: "",
  username: "",
  domain: "",
  ip: "",
  phone: "",
  password: "",
  hash: "",
  url: "",
  image: "",
  wallet: "",
};

function summaryFor(result: CheckResultState): string {
  switch (result.type) {
    case "email": {
      if (!result.data.mxOk) return "No MX records";
      const parts: string[] = [];
      if (result.data.hibp.available) {
        if (result.data.hibp.error) {
          parts.push("HIBP: lookup failed");
        } else {
          const count = result.data.hibp.breaches?.length ?? 0;
          parts.push(count > 0 ? `HIBP: ${count} breach${count === 1 ? "" : "es"}` : "HIBP: clean");
        }
      }
      if (result.data.leakcheck.status === "ok") {
        parts.push(`LeakCheck: ${result.data.leakcheck.found} records`);
      }
      if (
        result.data.hudsonrock.status === "ok" &&
        result.data.hudsonrock.associated
      ) {
        parts.push("Infostealer: exposed");
      }
      if (result.data.github.available && result.data.github.result?.status === "ok") {
        const total = result.data.github.result.total;
        if (total > 0) parts.push(`GitHub: ${total} commits`);
      }
      parts.push(`Auth ${result.data.auth.grade}`);
      return parts.length > 0 ? parts.join(" · ") : "MX ok";
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
    case "ip": {
      const parts: string[] = [];
      if (result.data.geo.ok) {
        if (result.data.geo.country) parts.push(result.data.geo.country);
        if (result.data.geo.isp) parts.push(result.data.geo.isp);
      }
      const abuse = result.data.abuseipdb.result;
      if (abuse?.ok && abuse.abuseConfidenceScore !== undefined) {
        parts.push(`AbuseIPDB ${abuse.abuseConfidenceScore}%`);
      }
      if (result.data.tor.isExitNode) parts.push("Tor exit node");
      return parts.length > 0 ? parts.join(" · ") : "Checked";
    }
    case "phone":
      return result.data.valid
        ? `Valid${result.data.country ? ` · ${result.data.country}` : ""}`
        : "Invalid number";
    case "hash": {
      const vt = result.data.virustotal.result;
      if (vt?.ok && !vt.notFound && vt.malicious !== undefined) {
        return `VirusTotal: ${vt.malicious} malicious / ${vt.harmless ?? 0} harmless`;
      }
      if (result.data.circl.ok && result.data.circl.knownMalicious) {
        return "Known malicious (CIRCL)";
      }
      if (result.data.circl.ok && !result.data.circl.notFound) {
        return `Known file${result.data.circl.fileName ? `: ${result.data.circl.fileName}` : ""}`;
      }
      return "Not found in any source";
    }
    case "url": {
      const vt = result.data.virustotal.result;
      if (vt?.ok && !vt.notFound && vt.malicious !== undefined) {
        return `VirusTotal: ${vt.malicious} malicious`;
      }
      const sb = result.data.safebrowsing.result;
      if (sb?.ok && sb.matches.length > 0) {
        return `Flagged: ${sb.matches.map((m) => m.threatType).join(", ")}`;
      }
      if (result.data.urlscan.ok) {
        return `${result.data.urlscan.total} urlscan scans (30d)`;
      }
      return "Checked";
    }
    case "image":
      return result.data.hasExif
        ? result.data.gps
          ? "Metadata found — GPS location present"
          : `Metadata found (${result.data.fields.length} fields)`
        : "No metadata found";
    case "wallet": {
      const parts: string[] = [];
      if (result.data.ethereum.ok && result.data.ethereum.balanceDisplay) {
        parts.push(`ETH ${result.data.ethereum.balanceDisplay}`);
      }
      if (result.data.bsc.ok && result.data.bsc.balanceDisplay) {
        parts.push(`BNB ${result.data.bsc.balanceDisplay}`);
      }
      return parts.length > 0 ? parts.join(" · ") : "Checked";
    }
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
  const [loggedIn, setLoggedIn] = useState(false);
  const loggedInRef = useRef(false);
  const imageFileRef = useRef<File | null>(null);
  const [imageFileName, setImageFileName] = useState<string | null>(null);
  const elapsedTimer = useRef<ReturnType<typeof setInterval> | null>(null);

  const tab = TABS.find((t) => t.id === activeTab) ?? TABS[0];

  useEffect(() => {
    setHistory(loadHistory());
    setHistoryLoaded(true);
    // Signed-in users also get server-side history (hashed identifiers,
    // masked hints — see POST /api/history). Best-effort: a failed check
    // here just means local-only history.
    fetch("/api/auth/me")
      .then((res) => {
        loggedInRef.current = res.ok;
        setLoggedIn(res.ok);
      })
      .catch(() => {});
  }, []);

  // Fire-and-forget: server history must never block or break a check.
  const logToServerHistory = useCallback(
    (type: CheckType, input: string, summary: string) => {
      if (!loggedInRef.current) return;
      fetch("/api/history", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type, input, summary }),
      }).catch(() => {});
    },
    [],
  );

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
        if (type === "image") {
          // Client-side only: the file is parsed in the browser and never
          // leaves the device. `value` is the file name; the File itself
          // comes from the picker ref.
          const file = imageFileRef.current;
          if (!file) {
            throw new Error("Choose an image file first.");
          }
          const data = await analyzeImage(file);
          const state: CheckResultState = {
            type: "image",
            input: file.name,
            data,
            durationMs: performance.now() - started,
          };
          setResult(state);
          setHistory(
            addHistoryEntry({ type, input: file.name, summary: summaryFor(state) }),
          );
          logToServerHistory(type, file.name, summaryFor(state));
          return;
        }

        if (type === "wallet" && !normalizeWalletAddress(value)) {
          throw new Error(
            "Invalid address. Enter an Ethereum-style address (0x + 40 hex characters); mixed-case addresses must pass the EIP-55 checksum.",
          );
        }

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
          logToServerHistory(type, "", summaryFor(state));
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
          logToServerHistory(type, value, summaryFor(finalState));
          return;
        }

        const res = await fetch(`/api/check/${type}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          // The wallet route reads `address`, not `wallet`.
          body: JSON.stringify({
            [type === "wallet" ? "address" : type]: value,
          }),
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
        logToServerHistory(type, value, summaryFor(state));
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
    if (running) return;
    if (activeTab === "image") {
      if (!imageFileRef.current) return;
      void runCheck("image", imageFileRef.current.name);
      return;
    }
    const value = inputs[activeTab].trim();
    if (!value) return;
    void runCheck(activeTab, value);
  }

  function handleImageFile(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0] ?? null;
    imageFileRef.current = file;
    setImageFileName(file ? file.name : null);
    setError(null);
    setResult(null);
  }

  function handleRerun(entry: HistoryEntry) {
    if (entry.type === "password" || entry.type === "image" || !entry.input) return;
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
            htmlFor={activeTab === "image" ? "image-file" : "check-input"}
            className="mb-2 block text-xs font-medium text-gray-700"
          >
            {tab.label}
          </label>
          {activeTab === "image" ? (
            <div className="flex flex-col gap-3 sm:flex-row">
              <label
                htmlFor="image-file"
                className="flex h-11 flex-1 cursor-pointer items-center gap-2.5 rounded-md border border-gray-300 bg-white px-3.5 text-[15px] text-gray-700 transition-colors hover:border-black"
              >
                <svg
                  width="16"
                  height="16"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  className="shrink-0 text-gray-500"
                  aria-hidden="true"
                >
                  <rect x="3" y="3" width="18" height="18" rx="2" />
                  <circle cx="9" cy="9" r="2" />
                  <path d="M21 15l-3.1-3.1a2 2 0 0 0-2.8 0L6 21" />
                </svg>
                <span className="truncate">
                  {imageFileName ?? "Choose an image file (max 20 MB)"}
                </span>
              </label>
              <input
                id="image-file"
                type="file"
                accept="image/*"
                onChange={handleImageFile}
                className="sr-only"
              />
              <button
                type="submit"
                disabled={running || !imageFileName}
                className="h-11 shrink-0 rounded-md bg-black px-6 text-sm font-medium text-white transition-colors hover:bg-gray-800 disabled:cursor-not-allowed disabled:opacity-40"
              >
                {running ? "Analyzing…" : "Analyze"}
              </button>
            </div>
          ) : (
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
          )}
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
            ) : result.type === "ip" ? (
              <IpResult data={result.data} />
            ) : result.type === "phone" ? (
              <PhoneResult data={result.data} />
            ) : result.type === "hash" ? (
              <HashResult data={result.data} />
            ) : result.type === "url" ? (
              <UrlResult data={result.data} />
            ) : result.type === "image" ? (
              <ImageResult data={result.data} />
            ) : result.type === "wallet" ? (
              <WalletResult data={result.data} />
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
                {activeTab === "image"
                  ? "Choose an image file above and analyze it."
                  : `Enter a ${tab.label.toLowerCase()} above and run the check.`}
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
              {loggedIn
                ? " Signed in — checks are also saved to your account (hashed identifiers, masked hints)."
                : ""}
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
                      {entry.type !== "password" &&
                      entry.type !== "image" &&
                      entry.input ? (
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
