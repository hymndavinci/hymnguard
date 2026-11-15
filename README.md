# HymnGuard

Free, universal security exposure checker. Check a password, username, email,
domain, or phone number against public breach data and live records.

**Live:** https://hymnguard.vercel.app

No sign-up. No database in MVP. Nothing is stored on the server — check
history lives only in the visitor's browser (localStorage).

## Checkers

| Check | Source | Notes |
| --- | --- | --- |
| **Password** | Have I Been Pwned — Pwned Passwords (free, no key) | k-anonymity: the password is SHA-1 hashed in the browser; only the first 5 hex chars of the hash are sent. The password and full hash never reach the server. |
| **Username** | Live HTTP probing, Sherlock-style (free) | 256 sites — 30 hand-verified plus 226 verified live from the Sherlock site list (each kept site was confirmed with a known-existing username and a known-nonexistent control username, on both the verification network and production; 225 candidates were excluded — 35 false positives, 26 unverified rules, 164 blocked/unreachable from the verification network). Detection by status code, "not found" body markers, or final URL. Blocks/rate limits are reported as errors, never as "not found". Instagram, Spotify, and Reddit are excluded — no reliable free probe exists for them (login walls / JS shells that return the same page for real and missing accounts). |
| **Domain** | Node DNS + TLS + HTTPS + crt.sh (free, no key) | DNS records (A/AAAA/MX/TXT/NS), TLS certificate (issuer, expiry, chain validity), security-header grade, passive subdomains from certificate transparency logs. |
| **Phone** | libphonenumber-js (free, offline) | Format, country, calling code, type, validity. Honest scope: no breach lookup — no free, legitimate source exists for that. |
| **Email** | DNS MX (free) + HIBP Breached Account (paid key) | MX records and a disposable-domain note always run. The breach lookup only runs when `HIBP_API_KEY` is set; without a key the UI shows a clear "not configured" state instead of a fake result. Breach metadata only — never breach contents. |

## Privacy rules

- Passwords are hashed client-side (Web Crypto SHA-1). The server only ever
  sees a 5-character hash prefix.
- Identifiers are validated, checked, and discarded within the request. They
  are never logged and never stored server-side.
- History is localStorage-only (`hymnguard:history:v1`, 20 entries max).
  Password checks store no input at all.
- Every check route is rate-limited (10 requests/minute/IP per route) to
  prevent bulk enumeration.
- All upstream calls have timeouts (5s per site, 8s per API call, 10s for
  crt.sh) so no single slow source can hang a check.

## Environment variables

| Variable | Required | Purpose |
| --- | --- | --- |
| `HIBP_API_KEY` | No | Have I Been Pwned API key for the email breach lookup. Paid, from $4/mo at https://haveibeenpwned.com/API/Key. Without it, email checks still run MX + disposable checks and show a "not configured" state for breaches. |

## Run locally

```bash
npm install
npm run dev      # http://localhost:3000
npm run build    # production build
npm start        # serve the production build
```

Node 20+ required.

## Deploy

The repo is linked to Vercel; every push to `main` deploys to production.
To set the optional HIBP key: Vercel project → Settings → Environment
Variables → `HIBP_API_KEY`, then redeploy.

## Tech

- Next.js 16 (App Router) + TypeScript + Tailwind CSS 4
- Geist Sans / Geist Mono
- All checks run server-side in Next.js API routes (`app/api/check/*`)
- No database, no auth in MVP (phase 2: accounts, saved history, breach
  monitoring alerts)

## Attribution

- Username detection approach: [sherlock-project/sherlock](https://github.com/sherlock-project/sherlock) (re-implemented in TypeScript; no Sherlock code is used)
- Breach data: [Have I Been Pwned](https://haveibeenpwned.com)
- Subdomains: [crt.sh](https://crt.sh)
