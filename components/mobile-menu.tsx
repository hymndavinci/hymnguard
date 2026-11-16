// Mobile header menu (hamburger). On narrow screens the header shows
// only the logo, the theme toggle, and this button — everything else
// (Checks / Privacy / History / GitHub / Sign in) lives in the panel,
// so signing in is reachable on a phone.

"use client";

import { useEffect, useRef, useState } from "react";
import AuthNav from "./auth-nav";

const LINKS = [
  { href: "#console", label: "Checks" },
  { href: "#privacy", label: "Privacy" },
  { href: "#history", label: "History" },
  {
    href: "https://github.com/hymndavinci/hymnguard",
    label: "GitHub",
    external: true,
  },
];

function MenuIcon() {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M4 7h16M4 12h16M4 17h16" />
    </svg>
  );
}

function CloseIcon() {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M18 6L6 18M6 6l12 12" />
    </svg>
  );
}

export default function MobileMenu() {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    const onClick = (event: MouseEvent) => {
      if (
        rootRef.current &&
        !rootRef.current.contains(event.target as Node)
      ) {
        setOpen(false);
      }
    };
    document.addEventListener("keydown", onKey);
    document.addEventListener("mousedown", onClick);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("mousedown", onClick);
    };
  }, [open ]);

  return (
    <div ref={rootRef} className="relative sm:hidden">
      <button
        type="button"
        onClick={() => setOpen((prev) => !prev)}
        aria-expanded={open}
        aria-label="Menu"
        className="flex h-8 w-8 items-center justify-center rounded-md border border-gray-200 bg-white text-gray-700 transition-colors hover:text-black"
      >
        {open ? <CloseIcon /> : <MenuIcon />}
      </button>
      {open ? (
        <div className="absolute right-0 top-10 z-50 w-56 rounded-lg border border-gray-200 bg-white py-2 shadow-lg">
          {LINKS.map((link) => (
            <a
              key={link.href}
              href={link.href}
              {...(link.external
                ? { target: "_blank", rel: "noreferrer" }
                : {})}
              onClick={() => setOpen(false)}
              className="block px-4 py-2 text-sm text-gray-600 transition-colors hover:bg-gray-50 hover:text-black"
            >
              {link.label}
            </a>
          ))}
          <div className="mt-2 flex flex-col items-start gap-2 border-t border-gray-100 px-4 py-2.5 text-sm text-gray-500">
            <AuthNav />
          </div>
        </div>
      ) : null}
    </div>
  );
}
