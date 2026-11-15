// Dashboard sections: saved history, breach monitoring, BYOK keys.
// Each section fetches its own API and degrades to a needs-key state when
// the deployment lacks the required configuration.

"use client";

import { useCallback, useEffect, useState } from "react";
import { KEY_PROVIDERS, type KeyProvider } from "@/lib/checkers";

// ------------------------------------------------------------------ shared

async function fetchJson(path: string, init?: RequestInit) {
  const res = await fetch(path, init);
  const json = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  return { res, json };
}

function NeedsSetupBox({ text }: { text: string }) {
  return (
    <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3.5 text-amber-900">
      <div className="flex items-center gap-2">
        <span className="h-2 w-2 shrink-0 rounded-full bg-amber-500" />
        <p className="text-sm font-semibold">Not configured on this deployment</p>
      </div>
      <p className="mt-1.5 pl-4 text-[13px] leading-relaxed opacity-90">{text}</p>
    </div>
  );
}

function Section({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  return (
    <section className="mt-10 border-t border-gray-200 pt-8 first:mt-0 first:border-t-0 first:pt-0">
      <h2 className="text-lg font-semibold tracking-tight">{title}</h2>
      <p className="mt-1 max-w-2xl text-sm leading-relaxed text-gray-500">
        {description}
      </p>
      <div className="mt-5">{children}</div>
    </section>
  );
}

// ----------------------------------------------------------------- history

interface HistoryRow {
  id: string;
  type: string;
  identifierHint: string | null;
  summary: string;
  createdAt: string;
}

function HistorySection() {
  const [rows, setRows] = useState<HistoryRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [clearing, setClearing] = useState(false);

  const load = useCallback(async () => {
    const { res, json } = await fetchJson("/api/history");
    if (!res.ok) {
      setError(
        typeof json.error === "string"
          ? json.error
          : "Could not load history.",
      );
      return;
    }
    setRows(Array.isArray(json.checks) ? (json.checks as HistoryRow[]) : []);
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function clearAll() {
    setClearing(true);
    try {
      const { res } = await fetchJson("/api/history", { method: "DELETE" });
      if (res.ok) setRows([]);
    } finally {
      setClearing(false);
    }
  }

  if (error) {
    return <p className="text-sm text-red-700">{error}</p>;
  }
  if (rows === null) {
    return <p className="text-sm text-gray-500">Loading…</p>;
  }
  if (rows.length === 0) {
    return (
      <p className="text-sm text-gray-500">
        No saved checks yet. Run a check in the console and it appears here.
      </p>
    );
  }
  return (
    <div>
      <div className="overflow-hidden rounded-lg border border-gray-200">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-200 bg-gray-50 text-left">
              <th className="px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500">
                Type
              </th>
              <th className="px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500">
                Checked
              </th>
              <th className="px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500">
                Result
              </th>
              <th className="hidden px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500 sm:table-cell">
                When
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {rows.map((row) => (
              <tr key={row.id}>
                <td className="px-4 py-2.5">
                  <span className="rounded-md border border-gray-200 bg-gray-50 px-2 py-0.5 text-xs font-medium capitalize">
                    {row.type}
                  </span>
                </td>
                <td className="max-w-[200px] truncate px-4 py-2.5 font-mono text-[13px]">
                  {row.identifierHint || "••••••••"}
                </td>
                <td className="px-4 py-2.5 text-[13px] text-gray-600">
                  {row.summary}
                </td>
                <td className="hidden whitespace-nowrap px-4 py-2.5 text-[13px] text-gray-500 sm:table-cell">
                  {new Date(row.createdAt).toLocaleString("en-US", {
                    month: "short",
                    day: "numeric",
                    hour: "2-digit",
                    minute: "2-digit",
                  })}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <button
        onClick={clearAll}
        disabled={clearing}
        className="mt-4 rounded-md border border-gray-200 bg-white px-3 py-1.5 text-[13px] font-medium text-gray-600 transition-colors hover:bg-gray-50 hover:text-black disabled:opacity-40"
      >
        {clearing ? "Clearing…" : "Clear all history"}
      </button>
    </div>
  );
}

// --------------------------------------------------------------- monitors

interface MonitorRow {
  id: string;
  emailMasked: string;
  verifiedAt: string;
  lastCheckedAt: string | null;
  lastLeakCheckFound: number | null;
  lastHudsonAssociated: boolean | null;
  lastAlertAt: string | null;
  createdAt: string;
}

type MonitorPhase = "idle" | "code-sent";

function MonitorsSection({ userEmail }: { userEmail: string }) {
  const [rows, setRows] = useState<MonitorRow[] | null>(null);
  const [notConfigured, setNotConfigured] = useState<string | null>(null);
  const [email, setEmail] = useState("");
  const [phase, setPhase] = useState<MonitorPhase>("idle");
  const [code, setCode] = useState("");
  const [codeToken, setCodeToken] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async () => {
    const { res, json } = await fetchJson("/api/monitors");
    if (!res.ok) {
      if (json.needsSetup) {
        setNotConfigured(
          typeof json.error === "string"
            ? json.error
            : "Monitoring is not configured on this deployment.",
        );
      } else {
        setError(
          typeof json.error === "string"
            ? json.error
            : "Could not load monitors.",
        );
      }
      return;
    }
    setRows(Array.isArray(json.monitors) ? (json.monitors as MonitorRow[]) : []);
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function addMonitor(verificationToken?: string) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const { res, json } = await fetchJson("/api/monitors", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, token: verificationToken }),
      });
      if (json.needsSetup) {
        setNotConfigured(
          typeof json.error === "string"
            ? json.error
            : "Monitoring is not configured on this deployment.",
        );
        return;
      }
      if (res.status === 401 && json.needsVerification) {
        // Ownership proof needed: send a code to the address.
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
          typeof json.error === "string" ? json.error : "Could not add the monitor.",
        );
      }
      setEmail("");
      setPhase("idle");
      setCode("");
      setCodeToken(null);
      setNotice("Watching this email. It is re-checked daily; you will get an email alert if new exposure appears.");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not add the monitor.");
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
      await addMonitor(json.verificationToken as string);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification failed.");
    } finally {
      setBusy(false);
    }
  }

  async function removeMonitor(id: string) {
    setBusy(true);
    try {
      const { res } = await fetchJson(
        `/api/monitors?id=${encodeURIComponent(id)}`,
        { method: "DELETE" },
      );
      if (res.ok) await load();
    } finally {
      setBusy(false);
    }
  }

  if (notConfigured) return <NeedsSetupBox text={notConfigured} />;
  if (error && rows === null) {
    return <p className="text-sm text-red-700">{error}</p>;
  }

  return (
    <div className="space-y-5">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (email.trim()) void addMonitor();
        }}
        className="flex flex-col gap-3 sm:flex-row"
      >
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder={userEmail}
          aria-label="Email address to watch"
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
          {busy ? "Adding…" : "Watch this email"}
        </button>
      </form>

      {phase === "code-sent" ? (
        <div className="space-y-3 rounded-lg border border-gray-200 bg-gray-50 p-4">
          <p className="text-[13px] text-gray-600">
            This address needs ownership verification first. Enter the code
            sent to <span className="font-mono">{email}</span>.
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
              {busy ? "Verifying…" : "Verify and watch"}
            </button>
          </div>
        </div>
      ) : null}

      {notice ? (
        <div className="rounded-lg border border-green-200 bg-green-50 px-4 py-3 text-sm text-green-900">
          {notice}
        </div>
      ) : null}
      {error ? (
        <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-900">
          {error}
        </div>
      ) : null}

      {rows === null ? (
        <p className="text-sm text-gray-500">Loading…</p>
      ) : rows.length === 0 ? (
        <p className="text-sm text-gray-500">
          No watched emails yet. Add one above — it is re-checked daily
          against LeakCheck and Hudson Rock, and you get an email alert when
          new exposure appears.
        </p>
      ) : (
        <div className="overflow-hidden rounded-lg border border-gray-200">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 bg-gray-50 text-left">
                <th className="px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500">
                  Email
                </th>
                <th className="px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500">
                  Last check
                </th>
                <th className="px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500">
                  Exposure
                </th>
                <th className="px-4 py-2.5 text-right text-xs font-medium uppercase tracking-wider text-gray-500" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {rows.map((row) => (
                <tr key={row.id}>
                  <td className="px-4 py-2.5 font-mono text-[13px]">
                    {row.emailMasked}
                  </td>
                  <td className="whitespace-nowrap px-4 py-2.5 text-[13px] text-gray-500">
                    {row.lastCheckedAt
                      ? new Date(row.lastCheckedAt).toLocaleString("en-US", {
                          month: "short",
                          day: "numeric",
                          hour: "2-digit",
                          minute: "2-digit",
                        })
                      : "Not checked yet"}
                  </td>
                  <td className="px-4 py-2.5 text-[13px] text-gray-600">
                    {row.lastLeakCheckFound === null &&
                    row.lastHudsonAssociated === null
                      ? "Unknown"
                      : [
                          row.lastLeakCheckFound !== null
                            ? `${row.lastLeakCheckFound} breach records`
                            : null,
                          row.lastHudsonAssociated
                            ? "infostealer exposed"
                            : row.lastHudsonAssociated === false
                              ? "no stealer exposure"
                              : null,
                        ]
                          .filter(Boolean)
                          .join(" · ")}
                  </td>
                  <td className="px-4 py-2.5 text-right">
                    <button
                      onClick={() => void removeMonitor(row.id)}
                      disabled={busy}
                      className="whitespace-nowrap rounded-md px-2 py-1 text-[13px] font-medium text-gray-600 transition-colors hover:bg-gray-100 hover:text-black disabled:opacity-40"
                    >
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// -------------------------------------------------------------------- keys

interface SavedKey {
  provider: string;
  label: string;
  hint: string;
  updatedAt: string;
}

function KeysSection() {
  const [saved, setSaved] = useState<SavedKey[] | null>(null);
  const [notConfigured, setNotConfigured] = useState<string | null>(null);
  const [drafts, setDrafts] = useState<Partial<Record<KeyProvider, string>>>({});
  const [busyProvider, setBusyProvider] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async () => {
    const { res, json } = await fetchJson("/api/keys");
    if (!res.ok) {
      if (json.needsSetup) {
        setNotConfigured(
          typeof json.error === "string"
            ? json.error
            : "API keys are not configured on this deployment.",
        );
      } else {
        setError(
          typeof json.error === "string" ? json.error : "Could not load keys.",
        );
      }
      return;
    }
    setSaved(Array.isArray(json.keys) ? (json.keys as SavedKey[]) : []);
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function saveKey(provider: KeyProvider) {
    const key = (drafts[provider] ?? "").trim();
    if (!key) return;
    setBusyProvider(provider);
    setError(null);
    setNotice(null);
    try {
      const { res, json } = await fetchJson("/api/keys", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider, key }),
      });
      if (!res.ok) {
        throw new Error(
          typeof json.error === "string" ? json.error : "Could not save the key.",
        );
      }
      setDrafts((prev) => ({ ...prev, [provider]: "" }));
      setNotice("Key saved. Checks now use it instead of the server key.");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save the key.");
    } finally {
      setBusyProvider(null);
    }
  }

  async function deleteKey(provider: KeyProvider) {
    setBusyProvider(provider);
    setError(null);
    try {
      const { res } = await fetchJson(
        `/api/keys?provider=${encodeURIComponent(provider)}`,
        { method: "DELETE" },
      );
      if (res.ok) await load();
    } finally {
      setBusyProvider(null);
    }
  }

  if (notConfigured) return <NeedsSetupBox text={notConfigured} />;
  if (error && saved === null) {
    return <p className="text-sm text-red-700">{error}</p>;
  }

  const savedByProvider = new Map((saved ?? []).map((k) => [k.provider, k]));

  return (
    <div className="space-y-4">
      {notice ? (
        <div className="rounded-lg border border-green-200 bg-green-50 px-4 py-3 text-sm text-green-900">
          {notice}
        </div>
      ) : null}
      {error ? (
        <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-900">
          {error}
        </div>
      ) : null}
      <div className="overflow-hidden rounded-lg border border-gray-200">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-200 bg-gray-50 text-left">
              <th className="px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500">
                Provider
              </th>
              <th className="px-4 py-2.5 text-xs font-medium uppercase tracking-wider text-gray-500">
                Your key
              </th>
              <th className="px-4 py-2.5 text-right text-xs font-medium uppercase tracking-wider text-gray-500" />
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {KEY_PROVIDERS.map((provider) => {
              const existing = savedByProvider.get(provider.id);
              const busy = busyProvider === provider.id;
              return (
                <tr key={provider.id}>
                  <td className="px-4 py-3 align-top">
                    <p className="font-medium">{provider.label}</p>
                    <p className="mt-0.5 text-xs leading-relaxed text-gray-500">
                      {provider.where}
                    </p>
                  </td>
                  <td className="px-4 py-3">
                    {existing ? (
                      <p className="font-mono text-[13px] text-gray-600">
                        Saved · ends {existing.hint}
                      </p>
                    ) : (
                      <p className="text-[13px] text-gray-500">
                        Not set — the server key is used, if one is configured.
                      </p>
                    )}
                    <div className="mt-2 flex flex-col gap-2 sm:flex-row">
                      <input
                        type="password"
                        value={drafts[provider.id] ?? ""}
                        onChange={(e) =>
                          setDrafts((prev) => ({
                            ...prev,
                            [provider.id]: e.target.value,
                          }))
                        }
                        placeholder={existing ? "Replace key…" : "Paste your key…"}
                        autoComplete="off"
                        spellCheck={false}
                        aria-label={`${provider.label} API key`}
                        className="h-9 flex-1 rounded-md border border-gray-300 bg-white px-3 font-mono text-[13px] text-black outline-none transition-colors placeholder:font-sans placeholder:text-gray-500 focus:border-black"
                      />
                      <button
                        onClick={() => void saveKey(provider.id)}
                        disabled={busy || !(drafts[provider.id] ?? "").trim()}
                        className="h-9 shrink-0 rounded-md bg-black px-4 text-[13px] font-medium text-white transition-colors hover:bg-gray-800 disabled:cursor-not-allowed disabled:opacity-40"
                      >
                        {busy ? "Saving…" : existing ? "Replace" : "Save"}
                      </button>
                      {existing ? (
                        <button
                          onClick={() => void deleteKey(provider.id)}
                          disabled={busy}
                          className="h-9 shrink-0 rounded-md border border-gray-200 bg-white px-3 text-[13px] font-medium text-gray-600 transition-colors hover:bg-gray-50 hover:text-black disabled:opacity-40"
                        >
                          Delete
                        </button>
                      ) : null}
                    </div>
                  </td>
                  <td />
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <p className="text-xs leading-relaxed text-gray-500">
        Keys are encrypted at rest with a server-side key, used server-side
        only, and never shown back in full. Saving a key here overrides the
        server key for your checks.
      </p>
    </div>
  );
}

// -------------------------------------------------------------------- page

export default function DashboardClient({ userEmail }: { userEmail: string }) {
  return (
    <div className="pb-20">
      <Section
        title="Saved history"
        description="Checks you run while signed in are saved here — identifiers are stored as hashes with masked hints, never in full. Passwords are never stored at all."
      >
        <HistorySection />
      </Section>

      <Section
        title="Breach monitoring"
        description="Watch up to 5 email addresses. Each is re-checked daily against LeakCheck and Hudson Rock; if new exposure appears, you get an email alert. Only addresses you prove you own can be watched."
      >
        <MonitorsSection userEmail={userEmail} />
      </Section>

      <Section
        title="Your API keys"
        description="Bring your own keys to unlock sources this deployment hasn't configured — HIBP, OTX, AbuseIPDB, and more. Your key is used for your checks only."
      >
        <KeysSection />
      </Section>
    </div>
  );
}
