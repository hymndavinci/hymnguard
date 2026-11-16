# HymnGuard

Free, universal security exposure checker. Check a password, username, email,
domain, IP address, phone number, file hash, URL, image, or crypto wallet
against public breach data and live records.

**Live:** https://hymnguard.vercel.app

No sign-up is needed for checks — every checker works anonymously, and
anonymous checks store nothing on the server (history lives only in the
visitor's browser, localStorage). An optional account adds saved history,
breach monitoring, and bring-your-own API keys (see "Accounts" below).

## Checkers

| Check | Source | Notes |
| --- | --- | --- |
| **Password** | Have I Been Pwned — Pwned Passwords (free, no key) | k-anonymity: the password is SHA-1 hashed in the browser; only the first 5 hex chars of the hash are sent. The password and full hash never reach the server. |
| **Username** | Live HTTP probing, Sherlock-style (free) | 256 sites — 30 hand-verified plus 226 verified live from the Sherlock site list (each kept site was confirmed with a known-existing username and a known-nonexistent control username, on both the verification network and production; 225 candidates were excluded — 35 false positives, 26 unverified rules, 164 blocked/unreachable from the verification network). Detection by status code, "not found" body markers, or final URL. Blocks/rate limits are reported as errors, never as "not found". Instagram, Spotify, and Reddit are excluded — no reliable free probe exists for them (login walls / JS shells that return the same page for real and missing accounts). |
| **Domain** | Node DNS + TLS + HTTPS + crt.sh + RDAP + Wayback + urlscan.io + Spamhaus/SpamCop DNSBL + OTX (free, no key except OTX) | DNS records (A/AAAA/MX/TXT/NS), TLS certificate (issuer, expiry, chain validity), security-header grade, passive subdomains from certificate transparency logs, RDAP registration (registrar, created/expires, nameservers), SPF/DKIM/DMARC grading (A–F, shared with the email checker), DNSSEC status (DS record + DNSKEY), blocklist status (Spamhaus ZEN/DBL, SpamCop), tech fingerprinting from headers + homepage HTML, Wayback Machine first snapshot + snapshot count, OTX passive DNS hostnames (needs `OTX_API_KEY`), and urlscan.io public-scan activity (last 30 days; verdicts need a urlscan login, so only activity is reported). |
| **IP** | ip-api.com + AbuseIPDB + Tor exit list (free; AbuseIPDB needs a free key) | Geolocation (country/city/region, approximate), ASN + ISP + organization, reverse DNS, VPN/proxy/hosting/mobile flags (ip-api.com), Tor exit-node status (dan.me.uk exit list), and AbuseIPDB reputation (abuse confidence score, report count, last reported — needs `ABUSEIPDB_API_KEY`). Public IPs only; private/loopback/reserved ranges are rejected. |
| **Phone** | libphonenumber-js + offline ID prefix table + IPQS (keyed) + GetContact + Should I Answer (free) | Format, country, calling code, type, validity, plus Indonesian operator from the offline prefix table (42 prefixes, verified against Wikipedia's Indonesia numbering list — prefix shows the allocated operator; porting can change it). Carrier, line type, fraud score, active status, and leak flag via IPQS (needs `IPQS_API_KEY`, free tier; owner name and associated emails are never read or shown). Community spam reports from GetContact (report count, risk level, community verdict — aggregate signals only, no name tags or comments) and Should I Answer (NANP/+1 numbers only; the Indonesian subdomain's database is empty, so it is not used). Honest scope: no breach lookup — no free, legitimate source exists for that. Excluded after live verification: tellows (bot-blocked), whocalld (unreachable), spamcalls.net (unreliable redirects), Truecaller (account required). |
| **Email** | DNS MX + email-auth grading + breach sources + GitHub exposure + account enumeration | MX records, disposable-domain note, and SPF/DKIM/DMARC grading (A–F) always run. Breach metadata from HIBP (paid key), LeakCheck (free, no key), OsintCat (keyed), and Hudson Rock infostealer records (free, no key) — metadata only, never breach contents. GitHub exposure searches public commits for the email (needs `GITHUB_TOKEN`). Account enumeration checks 7 verified sites (see below) and only runs after ownership verification. Any source without its key shows a clear "not configured" state instead of a fake result. |
| **File hash** | CIRCL hashlookup + urlscan.io (free) + VirusTotal + MalwareBazaar + Hybrid Analysis + OTX (keyed) | MD5, SHA-1, or SHA-256 reputation. Only the hash is sent — never a file. CIRCL's known-file corpus (incl. a KnownMalicious flag) and urlscan.io's hash search were verified live both directions (EICAR test hash = known malicious; random hash = not found). VirusTotal (70+ engine verdicts), MalwareBazaar (abuse.ch sample database — needs a free Auth-Key since 2025), Hybrid Analysis (sandbox verdicts), and OTX file pulses are implemented from the public docs and show needs-key states until a key is configured. "Not found" in a source is reported as such — never as "clean". |
| **URL** | urlscan.io (free) + VirusTotal + Google Safe Browsing (keyed) | The URL is only sent to reputation APIs — HymnGuard never fetches it (no SSRF surface). urlscan.io scan activity was verified live both directions (example.com = scans; never-scanned URL = none). VirusTotal URL report and Safe Browsing threat lists are implemented from the public docs and show needs-key states until a key is configured. A URL VirusTotal has never scanned reports "not previously scanned", not "clean". |
| **Image** | exifr (client-side, free, no key) | EXIF/XMP/IPTC metadata read entirely in the browser — the file NEVER leaves the device; there is no API route for this checker. Shows camera/device, software, timestamps, exposure settings, and GPS coordinates when present (with a Maps link and a privacy warning — location data in photos is a real exposure vector). A stripped image gets a clear "no metadata found" verdict. 20 MB file cap. |
| **Wallet** | Etherscan API v2 (keyed, free tier) | Balance, first/last activity, and transaction count for an Ethereum-style address, on Ethereum and BNB Chain — one Etherscan key covers both chains (the v2 API is unified; the old per-chain v1 endpoints were deprecated in August 2025). Addresses are validated client- and server-side, including the EIP-55 checksum for mixed-case addresses. Without a key the check reports "needs an Etherscan API key" — never an empty "clean" result. Only public chain data is shown: no token holdings, no identity data. (Implemented from the public docs; not yet tested live — no key has been available.) |

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

## Accounts

Optional email/password accounts (Phase 5). Without a database configured
(`DATABASE_URL` unset), sign-in reports "not configured" and the app runs
exactly as before — all ten checkers work anonymously.

- **Saved history** — checks run while signed in are stored as a SHA-256
  hash of the identifier plus a masked display hint (email/phone masked;
  domain/username/IP shown in full, they are public). Password checks
  store no input at all. Newest 50 shown, 200 kept per user, clearable.
- **Breach monitoring** — watch up to 5 email addresses. Each is re-checked
  daily by a Vercel Cron job against LeakCheck + Hudson Rock; if new
  exposure appears, an alert email goes out via Resend. Only addresses
  you prove you own can be watched (your verified account email, or a
  Phase 3 ownership-verification code for another address). Monitored
  emails are stored AES-256-GCM encrypted — the cron needs the raw email
  to re-check it.
- **BYOK** — save your own API keys (HIBP, OsintCat, GitHub, OTX,
  AbuseIPDB, IPQS), encrypted at rest with AES-256-GCM. Your key is used
  for your checks instead of the server key, unlocking sources the
  deployment hasn't configured. Keys are never shown back in full —
  masked hints only. Requests that use a BYOK key bypass the result
  cache.
- **Sessions** — HMAC-signed stateless cookies (7 days, httpOnly,
  SameSite=Lax, Secure in production). Passwords are scrypt-hashed
  (N=16384, r=8, p=1). A password reset bumps `token_version` and
  invalidates all sessions. Login failures return a generic 401 so
  timing and messages don't reveal whether an email has an account.
- **Result caching** — successful server-keyed results are cached per
  identifier hash (email 1h, domain 6h, IP/phone 24h; password and
  username never). The cache lives in the database when one is
  configured, otherwise in memory. Responses carry an `X-Cache: HIT|MISS`
  header when the cache was consulted.

### Setting up accounts

1. Create a free Postgres database. Neon is the recommended host:
   sign up at https://neon.tech, create a project, and copy the
   **pooled** connection string.
2. Set the env vars in Vercel (Settings → Environment Variables,
   Production): `DATABASE_URL` (the pooled connection string),
   `SESSION_SECRET`, `ENCRYPTION_KEY`, `CRON_SECRET` (generate with the
   commands in `.env.example`).
3. Redeploy (or push). The build applies every `db/migrations/*.sql`
   file in filename order automatically when `DATABASE_URL` is set.
4. Optionally set `RESEND_API_KEY` + `RESEND_FROM` so signup and
   password-reset codes can be emailed (without Resend, signup creates
   the account immediately, unverified; monitoring alerts can't be
   sent). Note Resend's free tier only sends to the account owner's own
   address — sending to arbitrary emails needs a verified domain.

Google OAuth is not implemented: creating an OAuth client needs the
owner's Google Cloud Console. The schema reserves `users.provider` and
`users.google_sub` for it.

## Dossier mode

A consolidated exposure report built from your **own verified
identifiers only** (Phase 7, authenticated). Pick emails, usernames,
domains, and your current IP; each is checked live with the existing
checkers, and the results are combined into one report: an exposure
score (0–100), findings with points, prioritized remediation steps,
and cross-references between your identifiers (e.g. a username that is
the local-part of your email). The latest dossier is saved per user
and re-runnable; export it as JSON or print it (Print / Save as PDF).

**Ownership is enforced server-side, not just in the UI.** A dossier
build only accepts identifiers from the user's verified set — anything
else is rejected with 403 and no run is created. The proofs:

- **Email** — a Phase 3 verification token (a 6-digit code sent to the
  address), or the user's own verified account email, or a monitored
  email (ownership-verified when the monitor was created).
- **Username** — the local-part of an already-verified email, or a
  GitHub login whose public commits use a verified email as the author
  email (needs a GitHub token).
- **Domain** — a DNS TXT record at `_hymnguard.<domain>` carrying a
  valid HMAC verification token (24h TTL, stateless).
- **IP** — the requester's own current public IP, verified per build by
  matching the request IP. Typed IP values are never accepted.

**Excluded by design:** phone numbers (no SMS verification channel),
crypto wallets (would need message signing), and password/hash/URL/
image (not identity identifiers — they can't be "owned" in any
verifiable sense). There is no "check someone else" path: no
third-party dossiers, no people-search.

**How it runs:** a build creates a run, then the client drives one
chunk request per identifier (a full dossier can't fit in one 10-second
serverless invocation). Each section runs the real checker modules — a
dossier email section *is* the console email check — except the domain
section skips the slow subdomain enumeration (crt.sh, ~10s worst case)
and says so honestly. Dossier checks always run fresh, never from the
result cache. Each section has a 9-second budget; a section that runs
longer is recorded as an honest timeout and the run finalizes as
partial. Emails are stored AES-256-GCM encrypted in the run and shown
masked everywhere; the API never returns raw values or encrypted blobs
to the client.

**Scoring:** breach records and infostealer exposure weigh heaviest
(LeakCheck +5/record capped at 30, HIBP +5/breach capped at 25, Hudson
Rock +20); surface (username registrations, headers) weighs least.
Each domain's email-auth grade is counted once per dossier. Bands:
0–19 Low, 20–39 Moderate, 40–64 High, 65–100 Critical. Every finding
carries its points, so the score is explainable.

## Privacy rules

- Passwords are hashed client-side (Web Crypto SHA-1). The server only ever
  sees a 5-character hash prefix.
- Identifiers are validated, checked, and discarded within the request. They
  are never logged and never stored server-side — except for signed-in
  users' saved history (hashed identifiers + masked hints only) and
  monitored emails (encrypted, see "Accounts").
- History is localStorage-only for anonymous users
  (`hymnguard:history:v1`, 20 entries max). Password checks store no
  input at all, anywhere.
- Every check route is rate-limited (10 requests/minute/IP per route) to
  prevent bulk enumeration.
- Account enumeration only runs after ownership verification (a code sent
  to the email). Verification tokens are stateless HMAC-signed tokens;
  no codes or emails are stored server-side.
- Account passwords are stored as scrypt hashes; API keys and monitored
  emails as AES-256-GCM ciphertexts. Breach contents are never stored
  anywhere.
- All upstream calls have timeouts (5s per site, 8s per API call, 10s for
  crt.sh) so no single slow source can hang a check.

## Environment variables

| Variable | Required | Purpose |
| --- | --- | --- |
| `HIBP_API_KEY` | No | Have I Been Pwned API key for the email breach lookup. Paid, from $4/mo at https://haveibeenpwned.com/API/Key. Without it, email checks still run MX + disposable checks and show a "not configured" state for breaches. |
| `OSINTCAT_API_KEY` | No | OsintCat API key for the OsintCat breach lookup. Get one at https://www.osintcat.net. Without it, that source shows a "not configured" state. (Implemented from the public docs; not yet tested live — no key has been available.) |
| `GITHUB_TOKEN` | No | GitHub personal access token (no scopes needed) for the GitHub exposure check. Without it, that source shows a "not configured" state. |
| `OTX_API_KEY` | No | AlienVault OTX API key for the OTX passive DNS source in the domain checker. Free tier at https://otx.alienvault.com (sign up, then copy the key from your profile page). Without it, that source shows a "not configured" state. (Implemented from the public docs; not yet tested live — no key has been available.) |
| `ABUSEIPDB_API_KEY` | No | AbuseIPDB API key for the IP reputation check. Free tier (1,000 checks/day) at https://www.abuseipdb.com (sign up, then create a key under API). Without it, IP checks still run geolocation + network signals and show a "not configured" state for reputation. (Implemented from the public docs; not yet tested live — no key has been available.) |
| `IPQS_API_KEY` | No | IPQualityScore API key for the phone carrier + risk check (carrier, line type, fraud score, active status, leak flag). Free tier at https://www.ipqualityscore.com (sign up for a free API key; phone validation free tier reported at 1,000 lookups/month). Without it, phone checks still run format + prefix + spam reports and show a "not configured" state for carrier/risk. (Implemented from the public docs; not yet tested live — no key has been available.) |
| `VIRUSTOTAL_API_KEY` | No | VirusTotal API key for the hash and URL reputation checks (70+ engine verdicts). Free tier (500 req/day, 4/min) at https://www.virustotal.com. Without it, both checkers still run their free sources and show a "not configured" state for VirusTotal. (Implemented from the public docs; not yet tested live — no key has been available.) |
| `MALWAREBAZAAR_API_KEY` | No | MalwareBazaar Auth-Key for the hash checker (abuse.ch sample database). Free at https://auth.abuse.ch. Without it, the hash checker shows a "not configured" state for MalwareBazaar. (Implemented from the public docs; not yet tested live — no key has been available.) |
| `HYBRID_ANALYSIS_API_KEY` | No | Hybrid Analysis API key for the hash checker (Falcon Sandbox verdicts). Free Public API key at https://www.hybrid-analysis.com. Without it, the hash checker shows a "not configured" state for Hybrid Analysis. (Implemented from the public docs; not yet tested live — no key has been available.) |
| `SAFE_BROWSING_API_KEY` | No | Google Safe Browsing API key for the URL checker (malware / social-engineering / unwanted-software lists). Free tier (10,000 req/day) from Google Cloud Console. Without it, the URL checker shows a "not configured" state for Safe Browsing. (Implemented from the public docs; not yet tested live — no key has been available.) |
| `ETHERSCAN_API_KEY` | No | Etherscan API key for the wallet checker (one key covers Ethereum + BNB Chain via the unified v2 API). Free tier at https://etherscan.io. Without it, the wallet check has no source at all and reports "needs an Etherscan API key". (Implemented from the public docs; not yet tested live — no key has been available.) |
| `VERIFY_SECRET` | No* | Random secret for signing ownership-verification tokens. Required together with `RESEND_API_KEY` to enable account enumeration, and required on its own for dossier email verification and the domain TXT verification flow. Generate with `node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"`. |
| `RESEND_API_KEY` | No* | Resend API key for sending ownership-verification codes. Get one at https://resend.com (free tier available). Required together with `VERIFY_SECRET` to enable account enumeration. |
| `RESEND_FROM` | No* | Sender address for verification codes. Resend's free tier only sends from `onboarding@resend.dev` to the account owner's own address — to send codes to arbitrary emails, verify a domain you own in Resend and set this to an address on it (e.g. `noreply@yourdomain.com`). |
| `DATABASE_URL` | No† | Postgres connection string (Neon pooled URL recommended). Enables accounts: saved history, breach monitoring, BYOK, and the DB-backed cache. The schema is applied automatically on the next build. |
| `SESSION_SECRET` | No† | Random secret for signing session cookies. Generate with `node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"`. |
| `ENCRYPTION_KEY` | No† | 64 hex characters (32 bytes) for AES-256-GCM encryption of saved API keys and monitored emails. Generate with `node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"`. Changing it makes previously stored keys and monitored emails undecryptable. |
| `CRON_SECRET` | No† | Random secret the monitor cron must present as a Bearer token. Vercel Cron sends it automatically when set. Generate like `SESSION_SECRET`. |

\* Without `VERIFY_SECRET` + `RESEND_API_KEY`, enumeration reports a
"not configured" state and never runs. Without `VERIFY_SECRET` alone,
dossier email verification and domain TXT verification report "not
configured" (the domain flow needs only the secret; the email code flow
also needs Resend to send the code).

† Without `DATABASE_URL` (+ `SESSION_SECRET` for sign-in,
`ENCRYPTION_KEY` for BYOK/monitoring, `CRON_SECRET` for the cron), the
account features report "not configured" and the checkers keep working
anonymously.

## Run locally

```bash
npm install
npm run dev      # http://localhost:3000
npm run build    # production build
npm start        # serve the production build
```

Node 20+ required.

For local account features, run a Postgres (e.g. `postgresql://user:pass@127.0.0.1:5432/hymnguard`),
apply the schema (`psql "$DATABASE_URL" -f db/migrations/001_init.sql`
or `DATABASE_URL=... node scripts/db-push-if-configured.mjs`), and set
`DATABASE_URL`, `SESSION_SECRET`, `ENCRYPTION_KEY`, `CRON_SECRET` in
`.env.local` (see `.env.example`). Without them, the checkers still work
anonymously.

## Deploy

The repo is linked to Vercel; every push to `main` deploys to production.
To set the optional HIBP key: Vercel project → Settings → Environment
Variables → `HIBP_API_KEY`, then redeploy. For accounts, set
`DATABASE_URL`, `SESSION_SECRET`, `ENCRYPTION_KEY`, and `CRON_SECRET`
the same way (see "Setting up accounts" above); the build applies the
database schema automatically.

## Tech

- Next.js 16 (App Router) + TypeScript + Tailwind CSS 4
- Geist Sans / Geist Mono
- All checks run server-side in Next.js API routes (`app/api/check/*`),
  except the image check, which is parsed client-side with exifr and has
  no API route (the file never leaves the browser).
- Accounts: Postgres (Neon) + raw SQL (`db/migrations/001_init.sql`).
  No ORM — the Prisma CLI cannot run in this project's build environment
  (it downloads engine binaries and the egress proxy aborts those
  downloads), so the schema is plain SQL applied by
  `scripts/db-push-if-configured.mjs` at build time. The runtime uses
  the Neon HTTP driver for `*.neon.tech` URLs and `pg` otherwise.
- Checkers are registered in `lib/checkers.ts` (id, label, route,
  sources, cache TTL) — new identifier types plug in there.

## Attribution

- Username detection approach: [sherlock-project/sherlock](https://github.com/sherlock-project/sherlock) (re-implemented in TypeScript; no Sherlock code is used)
- Email enumeration approach: [megadose/holehe](https://github.com/megadose/holehe) (rules adapted; re-implemented in TypeScript; no Holehe code is used)
- Breach data: [Have I Been Pwned](https://haveibeenpwned.com), [LeakCheck](https://leakcheck.io) (public API; attribution link shown in the UI), [OsintCat](https://www.osintcat.net)
- Infostealer data: [Hudson Rock](https://hudsonrock.com) (Cavalier free API)
- Subdomains: [crt.sh](https://crt.sh), [AlienVault OTX](https://otx.alienvault.com)
- Registration: [RDAP](https://rdap.org)
- History: [Wayback Machine](https://web.archive.org)
- Scan activity: [urlscan.io](https://urlscan.io)
- Blocklists: [Spamhaus](https://www.spamhaus.org), [SpamCop](https://www.spamcop.net)
- IP data: [ip-api.com](https://ip-api.com), [AbuseIPDB](https://www.abuseipdb.com), [Tor exit list](https://www.dan.me.uk/torlist/)
- Phone data: [IPQualityScore](https://www.ipqualityscore.com) (carrier + risk, keyed), [GetContact](https://getcontact.com) (community spam reports), [Should I Answer](https://www.shouldianswer.com) (NANP community reports); Indonesian prefix data: [Wikipedia — Daftar kode telepon di Indonesia](https://id.wikipedia.org/wiki/Daftar_kode_telepon_di_Indonesia)
- Hash reputation: [CIRCL hashlookup](https://hashlookup.circl.lu), [VirusTotal](https://www.virustotal.com), [MalwareBazaar](https://bazaar.abuse.ch), [Hybrid Analysis](https://www.hybrid-analysis.com), [AlienVault OTX](https://otx.alienvault.com)
- URL reputation: [Google Safe Browsing](https://developers.google.com/safe-browsing), [VirusTotal](https://www.virustotal.com)
- Wallet data: [Etherscan](https://etherscan.io) (unified v2 API, Ethereum + BNB Chain)
- Image metadata: [exifr](https://github.com/MikeKovarik/exifr) (MIT, client-side only)
