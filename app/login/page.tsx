// Sign-in / sign-up / forgot-password / reset-password.
// Accounts are optional — every check works without one. An account adds
// saved history, breach monitoring, and BYOK (your own API keys).

"use client";

import { useState } from "react";

type Mode = "login" | "signup" | "signup-code" | "forgot" | "reset";

async function postJson(path: string, body: unknown) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = (await res.json().catch(() => ({}))) as {
    error?: string;
    needsVerification?: boolean;
    needsSetup?: boolean;
    user?: { email: string };
    message?: string;
  };
  return { res, json };
}

export default function LoginPage() {
  const [mode, setMode] = useState<Mode>("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [notConfigured, setNotConfigured] = useState(false);

  function switchMode(next: Mode) {
    setMode(next);
    setError(null);
    setNotice(null);
    setCode("");
  }

  async function handleLogin(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { res, json } = await postJson("/api/auth/login", {
        email,
        password,
      });
      if (json.needsSetup) {
        setNotConfigured(true);
        return;
      }
      if (!res.ok) throw new Error(json.error ?? "Sign-in failed.");
      window.location.href = "/dashboard";
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign-in failed.");
    } finally {
      setBusy(false);
    }
  }

  async function handleSignup(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { res, json } = await postJson("/api/auth/signup", {
        email,
        password,
      });
      if (json.needsSetup) {
        setNotConfigured(true);
        return;
      }
      if (!res.ok) throw new Error(json.error ?? "Sign-up failed.");
      if (json.needsVerification) {
        setMode("signup-code");
        setNotice(`A 6-digit code was sent to ${email}. It expires in 10 minutes.`);
      } else {
        window.location.href = "/dashboard";
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign-up failed.");
    } finally {
      setBusy(false);
    }
  }

  async function handleSignupCode(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { res, json } = await postJson("/api/auth/verify-signup", {
        email,
        code,
      });
      if (!res.ok) throw new Error(json.error ?? "Verification failed.");
      window.location.href = "/dashboard";
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification failed.");
    } finally {
      setBusy(false);
    }
  }

  async function handleForgot(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { res, json } = await postJson("/api/auth/forgot-password", {
        email,
      });
      if (json.needsSetup) {
        setNotConfigured(true);
        return;
      }
      if (!res.ok) throw new Error(json.error ?? "Request failed.");
      setMode("reset");
      setNotice(
        "If an account exists for this email, a 6-digit reset code was sent to it.",
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Request failed.");
    } finally {
      setBusy(false);
    }
  }

  async function handleReset(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { res, json } = await postJson("/api/auth/reset-password", {
        email,
        code,
        newPassword,
      });
      if (!res.ok) throw new Error(json.error ?? "Reset failed.");
      setMode("login");
      setPassword("");
      setNewPassword("");
      setNotice("Password changed. Sign in with your new password.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Reset failed.");
    } finally {
      setBusy(false);
    }
  }

  const inputClass =
    "h-11 w-full rounded-md border border-gray-300 bg-white px-3.5 text-[15px] text-black outline-none transition-colors placeholder:text-gray-500 focus:border-black";
  const buttonClass =
    "h-11 w-full rounded-md bg-black px-6 text-sm font-medium text-white transition-colors hover:bg-gray-800 disabled:cursor-not-allowed disabled:opacity-40";

  if (notConfigured) {
    return (
      <main className="wrap">
        <div className="mx-auto max-w-md pb-20 pt-14 sm:pt-20">
          <h1 className="text-2xl font-semibold tracking-tight">
            Accounts are not configured
          </h1>
          <p className="mt-3 text-sm leading-relaxed text-gray-600">
            This deployment has no database configured, so sign-in is
            unavailable. The checks themselves work fine without an account —
            head back to the console.
          </p>
          <a
            href="/"
            className="mt-6 inline-block rounded-md bg-black px-5 py-2.5 text-sm font-medium text-white hover:bg-gray-800"
          >
            Back to checks
          </a>
        </div>
      </main>
    );
  }

  return (
    <main className="wrap">
      <div className="mx-auto max-w-md pb-20 pt-14 sm:pt-20">
        <h1 className="text-2xl font-semibold tracking-tight">
          {mode === "login" && "Sign in to HymnGuard"}
          {mode === "signup" && "Create your account"}
          {mode === "signup-code" && "Check your email"}
          {mode === "forgot" && "Reset your password"}
          {mode === "reset" && "Enter your reset code"}
        </h1>
        <p className="mt-2 text-sm leading-relaxed text-gray-500">
          {mode === "login" &&
            "An account adds saved history, breach monitoring, and your own API keys. Checks work without one."}
          {mode === "signup" &&
            "Email and password only — no tracking, no marketing. Your password is stored as a scrypt hash."}
          {mode === "signup-code" &&
            "Enter the code we sent to finish creating your account."}
          {mode === "forgot" &&
            "We'll email a 6-digit code to reset your password."}
          {mode === "reset" &&
            "Enter the code from the email, then choose a new password."}
        </p>

        {notice ? (
          <div className="mt-6 rounded-lg border border-green-200 bg-green-50 px-4 py-3 text-sm text-green-900">
            {notice}
          </div>
        ) : null}
        {error ? (
          <div className="mt-6 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-900">
            {error}
          </div>
        ) : null}

        <div className="mt-6 rounded-xl border border-gray-200 bg-white p-5 shadow-[0_1px_2px_rgba(0,0,0,0.04)] sm:p-6">
          {mode === "login" ? (
            <form onSubmit={handleLogin} className="space-y-4">
              <div>
                <label htmlFor="email" className="mb-2 block text-xs font-medium text-gray-700">
                  Email
                </label>
                <input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  autoComplete="email"
                  required
                  className={inputClass}
                />
              </div>
              <div>
                <label htmlFor="password" className="mb-2 block text-xs font-medium text-gray-700">
                  Password
                </label>
                <input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                  required
                  className={inputClass}
                />
              </div>
              <button type="submit" disabled={busy} className={buttonClass}>
                {busy ? "Signing in…" : "Sign in"}
              </button>
              <div className="flex items-center justify-between text-[13px]">
                <button
                  type="button"
                  onClick={() => switchMode("forgot")}
                  className="font-medium text-gray-600 hover:text-black hover:underline underline-offset-2"
                >
                  Forgot password?
                </button>
                <button
                  type="button"
                  onClick={() => switchMode("signup")}
                  className="font-medium text-gray-600 hover:text-black hover:underline underline-offset-2"
                >
                  Create an account
                </button>
              </div>
            </form>
          ) : null}

          {mode === "signup" ? (
            <form onSubmit={handleSignup} className="space-y-4">
              <div>
                <label htmlFor="email" className="mb-2 block text-xs font-medium text-gray-700">
                  Email
                </label>
                <input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  autoComplete="email"
                  required
                  className={inputClass}
                />
              </div>
              <div>
                <label htmlFor="password" className="mb-2 block text-xs font-medium text-gray-700">
                  Password
                </label>
                <input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="new-password"
                  required
                  minLength={10}
                  className={inputClass}
                />
                <p className="mt-1.5 text-xs text-gray-500">
                  At least 10 characters.
                </p>
              </div>
              <button type="submit" disabled={busy} className={buttonClass}>
                {busy ? "Creating account…" : "Create account"}
              </button>
              <p className="text-center text-[13px] text-gray-500">
                Already have an account?{" "}
                <button
                  type="button"
                  onClick={() => switchMode("login")}
                  className="font-medium text-gray-700 hover:text-black hover:underline underline-offset-2"
                >
                  Sign in
                </button>
              </p>
            </form>
          ) : null}

          {mode === "signup-code" ? (
            <form onSubmit={handleSignupCode} className="space-y-4">
              <div>
                <label htmlFor="code" className="mb-2 block text-xs font-medium text-gray-700">
                  Verification code
                </label>
                <input
                  id="code"
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  value={code}
                  onChange={(e) =>
                    setCode(e.target.value.replace(/\D/g, "").slice(0, 6))
                  }
                  placeholder="123456"
                  required
                  className="h-11 w-full rounded-md border border-gray-300 bg-white px-3.5 font-mono text-[15px] tracking-[0.3em] text-black outline-none transition-colors placeholder:text-gray-500 focus:border-black"
                />
              </div>
              <button
                type="submit"
                disabled={busy || !/^\d{6}$/.test(code)}
                className={buttonClass}
              >
                {busy ? "Verifying…" : "Verify and create account"}
              </button>
              <p className="text-center text-[13px] text-gray-500">
                Wrong email?{" "}
                <button
                  type="button"
                  onClick={() => switchMode("signup")}
                  className="font-medium text-gray-700 hover:text-black hover:underline underline-offset-2"
                >
                  Start over
                </button>
              </p>
            </form>
          ) : null}

          {mode === "forgot" ? (
            <form onSubmit={handleForgot} className="space-y-4">
              <div>
                <label htmlFor="email" className="mb-2 block text-xs font-medium text-gray-700">
                  Email
                </label>
                <input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  autoComplete="email"
                  required
                  className={inputClass}
                />
              </div>
              <button type="submit" disabled={busy} className={buttonClass}>
                {busy ? "Sending code…" : "Send reset code"}
              </button>
              <p className="text-center text-[13px] text-gray-500">
                Remembered it?{" "}
                <button
                  type="button"
                  onClick={() => switchMode("login")}
                  className="font-medium text-gray-700 hover:text-black hover:underline underline-offset-2"
                >
                  Sign in
                </button>
              </p>
            </form>
          ) : null}

          {mode === "reset" ? (
            <form onSubmit={handleReset} className="space-y-4">
              <div>
                <label htmlFor="code" className="mb-2 block text-xs font-medium text-gray-700">
                  Reset code
                </label>
                <input
                  id="code"
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  value={code}
                  onChange={(e) =>
                    setCode(e.target.value.replace(/\D/g, "").slice(0, 6))
                  }
                  placeholder="123456"
                  required
                  className="h-11 w-full rounded-md border border-gray-300 bg-white px-3.5 font-mono text-[15px] tracking-[0.3em] text-black outline-none transition-colors placeholder:text-gray-500 focus:border-black"
                />
              </div>
              <div>
                <label htmlFor="new-password" className="mb-2 block text-xs font-medium text-gray-700">
                  New password
                </label>
                <input
                  id="new-password"
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  autoComplete="new-password"
                  required
                  minLength={10}
                  className={inputClass}
                />
                <p className="mt-1.5 text-xs text-gray-500">
                  At least 10 characters.
                </p>
              </div>
              <button
                type="submit"
                disabled={busy || !/^\d{6}$/.test(code)}
                className={buttonClass}
              >
                {busy ? "Resetting…" : "Reset password"}
              </button>
            </form>
          ) : null}
        </div>
      </div>
    </main>
  );
}
