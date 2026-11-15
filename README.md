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
| **Email** | DNS MX + email-auth grading + breach sources + GitHub exposure + account enumeration | MX records, disposable-domain note, and SPF/DKIM/DMARC grading (A–F) always run. Breach metadata from HIBP (paid key), LeakCheck (free, no key), OsintCat (keyed), and Hudson Rock infostealer records (free, no key) — metadata only, never breach contents. GitHub exposure searches public commits for the email (needs `GITHUB_TOKEN`). Account enumeration checks 7 verified sites (see below) and only runs after ownership verification. Any source without its key shows a clear "not configured" state instead of a fake result. |

## Email enumeration

Holehe-style account enumeration: checks whether an email is registered
on popular sites via their public signup-availability and login endpoints.
Detection rules were adapted from Holehe (GPL-3.0, see
THIRD-PARTY-NOTICES.md) and re-implemented in TypeScript; no Holehe code
is used.

**Gated behind ownership verification.** Enumeration only runs for an
email the requester proves they own: HymnGuard sends a 6-digit code to
the address (via Resend) and requires it back before any probe runs.
No bulk checks: one email per invocation, chunked, strict rate limits.
No probe sends an email — every probe is a signup-availability check, a
login attempt with a wrong password, or a public lookup endpoint.

**Verified live 2026-11-15** (from the Vercel network, control email +
4 positive test emails). Kept probes — control returned `not_exists`
and at least one real account returned `exists`:

Adobe, Gravatar, Replit, Spotify, X (Twitter), WordPress.com, XVideos
(7 sites; XVideos carries an 18+ badge).

**Excluded (69 of 76 candidates):**

- Endpoint gone or changed (20): About.me, Docker Hub, Facebook,
  Nocrm, Patreon, RocketReach, Strava, TuneFind, XING, Komoot (all 404);
  amoCRM, CaringBridge (405); Teamtreehouse (500); Sporcle, Tumblr
  (400 — endpoint now requires more fields); Insightly, Teamleader
  (unrecognized response shape); Zoho (400); Evernote (login flow
  rebuilt, token gone); Freelancer (control email rejected as invalid,
  exists direction unconfirmed).
- Bot-blocked, rate-limited, or captcha (21): Amazon (captcha),
  CodePen (Cloudflare challenge), Imgur (412 security check),
  Instagram (429), Nimble, Pipedrive, Pinterest, Smule, Tellonym,
  Envato, 7 Cups (403), Nutshell (bot challenge), Atlassian, eBay,
  GitHub, Last.fm (no CSRF token found), Bitmoji, Snapchat (no XSRF
  token), BlaBlaCar (no app token), Google (no flow token), RedTube
  (no token).
- Unreachable or upstream error (7): Blip, Venmo (timeouts), Deliveroo,
  Nike (fetch failed), Ello (520), Issuu (503), Myspace (401).
- No signal — identical response for every email (7): Archive.org,
  Bodybuilding.com, Codecademy (empty `{}`), Diigo (body `"1"`),
  Fanpop (redirect page), Garmin (empty body), Pornhub (HTML shell).
- Rule responds but no positive confirmation — no test email has an
  account there, so the exists direction is unverified (14): Any.do,
  Axonaut, Discord, Duolingo, Firefox, HubSpot, LastPass, Plurk,
  Proton Mail, Vivino, Vrbo, XNXX. Coroflot and Eventbrite have
  inferable rules (Corofloat `data: 0` vs `-2`; Eventbrite's `exists`
  boolean) but also lack a positive confirmation.

Excluded probe code is preserved in git history (commit `2d62842`) for
future re-verification. CheckLeaked was evaluated and excluded (paid-only,
redundant with LeakCheck). SMTP deep verification was skipped (outbound
SMTP is blocked on Vercel, so it cannot be verified there).

## Privacy rules

- Passwords are hashed client-side (Web Crypto SHA-1). The server only ever
  sees a 5-character hash prefix.
- Identifiers are validated, checked, and discarded within the request. They
  are never logged and never stored server-side.
- History is localStorage-only (`hymnguard:history:v1`, 20 entries max).
  Password checks store no input at all.
- Every check route is rate-limited (10 requests/minute/IP per route) to
  prevent bulk enumeration.
- Account enumeration only runs after ownership verification (a code sent
  to the email). Verification tokens are stateless HMAC-signed tokens;
  no codes or emails are stored server-side.
- All upstream calls have timeouts (5s per site, 8s per API call, 10s for
  crt.sh) so no single slow source can hang a check.

## Environment variables

| Variable | Required | Purpose |
| --- | --- | --- |
| `HIBP_API_KEY` | No | Have I Been Pwned API key for the email breach lookup. Paid, from $4/mo at https://haveibeenpwned.com/API/Key. Without it, email checks still run MX + disposable checks and show a "not configured" state for breaches. |
| `OSINTCAT_API_KEY` | No | OsintCat API key for the OsintCat breach lookup. Get one at https://www.osintcat.net. Without it, that source shows a "not configured" state. (Implemented from the public docs; not yet tested live — no key has been available.) |
| `GITHUB_TOKEN` | No | GitHub personal access token (no scopes needed) for the GitHub exposure check. Without it, that source shows a "not configured" state. |
| `VERIFY_SECRET` | No* | Random secret for signing ownership-verification tokens. Required together with `RESEND_API_KEY` to enable account enumeration. Generate with `node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"`. |
| `RESEND_API_KEY` | No* | Resend API key for sending ownership-verification codes. Get one at https://resend.com (free tier available). Required together with `VERIFY_SECRET` to enable account enumeration. |
| `RESEND_FROM` | No* | Sender address for verification codes. Resend's free tier only sends from `onboarding@resend.dev` to the account owner's own address — to send codes to arbitrary emails, verify a domain you own in Resend and set this to an address on it (e.g. `noreply@yourdomain.com`). |

\* Without `VERIFY_SECRET` + `RESEND_API_KEY`, enumeration reports a
"not configured" state and never runs.

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
- Email enumeration approach: [megadose/holehe](https://github.com/megadose/holehe) (rules adapted; re-implemented in TypeScript; no Holehe code is used)
- Breach data: [Have I Been Pwned](https://haveibeenpwned.com), [LeakCheck](https://leakcheck.io) (public API; attribution link shown in the UI), [OsintCat](https://www.osintcat.net)
- Infostealer data: [Hudson Rock](https://hudsonrock.com) (Cavalier free API)
- Subdomains: [crt.sh](https://crt.sh)
