// Header auth state: "Sign in" for anonymous visitors, Dashboard +
// Sign out for logged-in users. Fetched client-side from /api/auth/me
// (the layout is a server component and the session cookie is httpOnly).

"use client";

import { useEffect, useState } from "react";

interface MeUser {
  id: string;
  email: string;
  emailVerified: boolean;
  createdAt: string;
}

export default function AuthNav() {
  const [user, setUser] = useState<MeUser | null>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/auth/me")
      .then(async (res) => {
        if (cancelled) return;
        if (res.ok) {
          const json = (await res.json().catch(() => ({}))) as {
            user?: MeUser;
          };
          setUser(json.user ?? null);
        }
        setLoaded(true);
      })
      .catch(() => {
        if (!cancelled) setLoaded(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function signOut() {
    await fetch("/api/auth/logout", { method: "POST" }).catch(() => {});
    setUser(null);
    window.location.href = "/";
  }

  if (!loaded) return null;

  if (!user) {
    return (
      <a
        href="/login"
        className="rounded-md bg-black px-3.5 py-1.5 text-sm font-medium text-white transition-colors hover:bg-gray-800"
      >
        Sign in
      </a>
    );
  }

  return (
    <>
      <a
        href="/dashboard"
        className="transition-colors hover:text-black"
      >
        Dashboard
      </a>
      <a
        href="/dossier"
        className="transition-colors hover:text-black"
      >
        Dossier
      </a>
      <span
        className="hidden max-w-[160px] truncate font-mono text-xs text-gray-500 lg:inline"
        title={user.email}
      >
        {user.email}
      </span>
      <button
        onClick={signOut}
        className="transition-colors hover:text-black"
      >
        Sign out
      </button>
    </>
  );
}
