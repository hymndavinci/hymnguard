import type { Metadata } from "next";
import { GeistMono } from "geist/font/mono";
import { GeistSans } from "geist/font/sans";
import AuthNav from "@/components/auth-nav";
import MobileMenu from "@/components/mobile-menu";
import ThemeToggle from "@/components/theme-toggle";
import "./globals.css";

// Dark mode is the default. This script runs before first paint so the
// theme is right from the start: stored "light" removes the class,
// anything else (stored "dark" or nothing) keeps it.
const THEME_SCRIPT = `(function(){try{var t=localStorage.getItem('hymnguard-theme');document.documentElement.classList.toggle('dark',t!=='light')}catch(e){document.documentElement.classList.add('dark')}})();`;

export const metadata: Metadata = {
  title: "HymnGuard — Free Security Exposure Checker",
  description:
    "Check a password, username, email, domain, or phone number against public breach data and live records. Free. Checks need no sign-up and store nothing; an optional account adds history, monitoring, and your own API keys.",
  metadataBase: new URL("https://hymnguard.vercel.app"),
  openGraph: {
    title: "HymnGuard — Free Security Exposure Checker",
    description:
      "Check a password, username, email, domain, or phone number against public breach data and live records.",
    type: "website",
  },
};

function ShieldMark() {
  return (
    <span className="flex h-7 w-7 items-center justify-center rounded-md bg-black text-white">
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
        <path d="M12 3l7 3v5c0 4.5-3 7.6-7 9-4-1.4-7-4.5-7-9V6l7-3z" />
        <path d="M9 12l2 2 4-4" />
      </svg>
    </span>
  );
}

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html
      lang="en"
      className={`dark ${GeistSans.variable} ${GeistMono.variable}`}
      suppressHydrationWarning
    >
      <body className="min-h-screen bg-white font-sans text-gray-900 antialiased">
        <script dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} />
        <header className="sticky top-0 z-40 border-b border-gray-200 bg-white">
          <div className="wrap flex h-14 items-center justify-between">
            <a href="/" className="flex items-center gap-2.5">
              <ShieldMark />
              <span className="text-[15px] font-semibold tracking-tight">
                HymnGuard
              </span>
              <span className="rounded-full border border-gray-200 bg-gray-50 px-2 py-0.5 text-[11px] font-medium text-gray-500">
                MVP
              </span>
            </a>
            <nav className="flex items-center gap-4 text-sm text-gray-500 sm:gap-6">
              <a href="#console" className="hidden transition-colors hover:text-black sm:block">
                Checks
              </a>
              <a href="#privacy" className="hidden transition-colors hover:text-black sm:block">
                Privacy
              </a>
              <a href="#history" className="hidden transition-colors hover:text-black sm:block">
                History
              </a>
              <a
                href="https://github.com/hymndavinci/hymnguard"
                target="_blank"
                rel="noreferrer"
                className="hidden items-center gap-1.5 transition-colors hover:text-black sm:flex"
              >
                <svg
                  width="16"
                  height="16"
                  viewBox="0 0 16 16"
                  fill="currentColor"
                  aria-hidden="true"
                >
                  <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
                </svg>
                <span>GitHub</span>
              </a>
              <span className="hidden items-center gap-6 sm:flex">
                <AuthNav />
              </span>
              <ThemeToggle />
              <MobileMenu />
            </nav>
          </div>
        </header>

        {children}

        <footer className="border-t border-gray-200">
          <div className="wrap flex flex-col gap-3 py-6 text-[13px] text-gray-500 sm:flex-row sm:items-center sm:justify-between">
            <p>
              HymnGuard — free security exposure checks. Data sources: Have I
              Been Pwned, LeakCheck, Hudson Rock, crt.sh, RDAP, Wayback
              Machine, OTX, urlscan.io, CIRCL, VirusTotal, MalwareBazaar,
              Hybrid Analysis, Safe Browsing, Etherscan, and public DNS
              records.
            </p>
            <p className="font-mono text-xs">
              Anonymous checks store nothing on the server. Accounts are
              optional.
            </p>
          </div>
        </footer>
      </body>
    </html>
  );
}
