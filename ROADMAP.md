# HymnGuard Roadmap

**Vision:** the universal security exposure checker. Enter any identifier — email, username, domain, phone, password, IP, file hash — and get a complete, honest exposure report.

**Source of truth for completeness:** [jivoi/awesome-osint](https://github.com/jivoi/awesome-osint) — the curated OSINT list. This roadmap maps its relevant categories onto HymnGuard, phase by phase.

## Principles (non-negotiable)

1. **Free-first.** Every checker works without paid keys. Paid sources are optional upgrades, never requirements.
2. **Privacy-first.** No raw identifiers stored server-side beyond the request. Passwords are hashed in the browser (k-anonymity). Enumeration checks require proof of ownership.
3. **Honest results.** Errors are never reported as "not found". No mock data, no invented findings. Every result names its source.
4. **Passive only, by default.** No active scanning of arbitrary targets. Active checks only with verified ownership.
5. **Metadata, never contents.** Breach results show breach name, date, and data classes — never leaked passwords or PII.

## Current state — v0.1 (live 15 Nov 2026)

| Identifier | Sources |
|---|---|
| Password | HIBP Pwned Passwords (k-anonymity, free, no key) |
| Username | 30 sites, Sherlock-style (status / body-marker / probe-URL rules) |
| Domain | DNS, TLS certificate, security headers, crt.sh subdomains |
| Phone | libphonenumber parse (format, country, validity) |
| Email | MX records, disposable-domain check; HIBP breach check needs paid key |

No auth, no database. History in localStorage (max 20). Rate limit 10/min/IP per route.

---

## Execution order

Phases run sequentially, each verified and deployed before the next starts. Current order (Bintang, 2026-11-15): Phase 1 → Phase 3 (email) → Phase 2 (domain & IP) → Phase 4 → Phase 5 → Phase 6 → Phase 7. Email was pulled ahead of domain/IP at Bintang's direction ("email dlu").

## Phase 1 — Username: full coverage (DONE — live 2026-11-15)

- Port Sherlock's full site list (`data.json`, 400+ sites) into `lib/username-sites.ts`.
- Live-verify every detection rule with a known-existing username and a known-nonexistent control username. Exclude anything unreliable (documented, same precedent as Instagram / Spotify / Reddit).
- Evaluate merging unique sites from Blackbird (600+), WhatsMyName, and Maigret — same verification bar, no exceptions.
- UI: found-first ordering, filter by status, search by site name.
- **Done when:** control username yields 0 false positives; full sweep completes in reasonable time.
- **Outcome:** 256 sites live (30 curated + 226 Sherlock-verified of 451 candidates; 225 excluded — 35 false positives, 26 unverified rules, 164 blocked/unreachable from the verification network). Control username probes 0 found on production.

## Phase 2 — Domain & IP expansion (DONE — live 2026-11-15)

Domain additions:
- **RDAP / WHOIS** — registrar, registration + expiry dates (rdap.org, free, no key).
- **Wayback Machine** — first-seen date, snapshot count, history (free API).
- **Email-auth grading** — SPF / DKIM / DMARC posture, A–F grade (SpoofCheck-style, DNS-only, free).
- **DNSSEC** validation status.
- **Blacklist / DNSBL check** — Spamhaus, MultiRBL (free lookups).
- **Tech fingerprinting** — Wappalyzer-style detection from HTML + headers (no key).
- **Passive subdomain expansion** — AlienVault OTX passive DNS (free key), urlscan.io (free tier).

New identifier: **IP address**
- Geolocation + ASN (ip-api.com, free).
- Reputation: AbuseIPDB (free tier, 1,000 checks/day, free key).
- VPN / proxy / Tor / bot detection (free tiers).
- No active port scanning of arbitrary IPs — passive data only (Shodan / Censys summaries only via user-provided key, see Phase 5).
- **Outcome:** all domain additions live + new IP checker live (6 checkers total). RDAP, Wayback, urlscan, tech fingerprinting, DNSBL, DNSSEC, and ip-api verified live on production with known-positive + known-negative cases. OTX + AbuseIPDB implemented from public docs with needs-key states (no keys set yet — untested live). Email-auth grader fixes shipped: SPF redirect following, DKIM records without the `v=DKIM1` prefix, non-empty `p=` required (empty `p=` = revoked key), gmail.com's current DKIM selector 20251104 added (20230601/20161025 are revoked). gmail.com now grades an honest 65/C (was a misleading F). DNSSEC uses RDAP DS + DNSKEY via DoH (Node's `dns.resolve` rejects the DNSKEY type). Excluded: SORBS (stale/unreliable); urlscan verdicts (need a urlscan login — activity only); MultiRBL (Spamhaus + SpamCop cover the need). Reliability fixes from production verification: crt.sh retry (flaky 502/404/timeout), Wayback partial results (CDX data queries 403 for gmail.com but the page count still answers). DNSBL positive path untested on production (no known-listed public IP handy).

## Phase 3 — Email expansion (DONE — live 2026-11-15)

- **Holehe-style account enumeration** — check whether the email is registered on popular sites via their forgot-password flows. **Gated:** only after ownership verification (code sent to the email) + strict rate limits. No bulk checks, ever.
- **Breach sources beyond HIBP** — LeakCheck, CheckLeaked, OsintCat (free tiers). Label each source's confidence; HIBP remains the gold standard.
- **Infostealer exposure** — Hudson Rock free check (is the email in stealer logs?).
- **GitHub exposure** — search public commits for the email address (Gitrecon-style; needs a GitHub token server-side or via BYOK).
- **Deep verification** — Reacher-style SMTP checks. Optional and heavily rate-limited (SMTP probing can look like spam); skip if it proves abusive.
- Shared with Phase 2: SPF / DKIM / DMARC grading for the email's domain.
- **Outcome:** enumeration pruned to 7 verified probes (Adobe, Gravatar, Replit, Spotify, X, WordPress.com, XVideos) of 76 candidates — 69 excluded (endpoints changed, bot-blocked, no signal, or no positive confirmation; see README). Breach sources live: LeakCheck + Hudson Rock (free, verified), HIBP + OsintCat + GitHub exposure (keyed, needs-key states until keys are set). CheckLeaked excluded (paid-only, redundant); SMTP deep verification skipped (outbound SMTP blocked on Vercel). Ownership verification needs `RESEND_API_KEY` + `RESEND_FROM` (verified domain) + `VERIFY_SECRET` — until those are set, enumeration reports needs-key and never runs.

## Phase 4 — Phone expansion (DONE — live 2026-11-15)

- **PhoneInfoga-style aggregation** — carrier lookup from free sources, prefix databases (including Indonesia prefix data), line-type detection.
- **Spam / scam reports** — presence in public complaint boards (fragile, scraping-dependent — treat as best-effort).
- **Honest scope:** format, country, carrier, line type, spam-report presence. Truecaller / Twilio-class identity data stays behind BYOK (Phase 5).
- Phone remains the hardest category for free sources. No overpromising.
- **Outcome:** offline ID prefix table (42 prefixes, Wikipedia-verified); IPQS carrier + risk (keyed, from docs, untested live — no key); GetContact spam reports (aggregate signals only, verified both directions: 610-report spam number vs 404 clean number); Should I Answer for NANP only (verified both directions). Excluded: tellows (403), whocalld (unreachable), spamcalls.net (unreliable redirects), shouldianswer ID subdomain (empty database — known spam numbers show 0 reviews), Truecaller (account required), phone breach lookup (no free legitimate source). IPQS owner name / associated emails deliberately never read or shown.

## Phase 5 — Platform: accounts, history, monitoring, BYOK (DONE — live 2026-11-15)

The biggest architectural step. Turns HymnGuard from a tool into a service.

- **Auth** — email/password (scrypt hashing, HMAC-signed stateless session cookies, token-version revocation on password reset). Google OAuth NOT built: creating an OAuth client needs the owner's Google Cloud Console; the schema reserves `users.provider` + `users.google_sub` for it.
- **Database** — Postgres (Neon) + **raw SQL, not Prisma**: the Prisma CLI cannot run in this project's build environment (it downloads engine binaries and the egress proxy aborts those downloads with ECONNRESET). Schema in `db/migrations/001_init.sql`, applied idempotently by `scripts/db-push-if-configured.mjs` at build time when `DATABASE_URL` is set. Runtime uses the Neon HTTP driver for `*.neon.tech` URLs, `pg` otherwise. Saved check history per account (hashed identifiers + masked hints; passwords never stored).
- **Breach monitoring** — watch up to 5 emails (ownership-verified only), re-checked daily by Vercel Cron against LeakCheck + Hudson Rock, alert email via Resend when new exposure appears. Monitored emails stored AES-256-GCM encrypted.
- **Bring Your Own Key (BYOK)** — users add their own API keys (HIBP, OsintCat, GitHub, OTX, AbuseIPDB, IPQS). Keys encrypted at rest (AES-256-GCM), used server-side only, never shown back in full (masked hints only). BYOK requests bypass the result cache.
- **Plugin architecture** — `lib/checkers.ts` registry: each checker declares id, label, route, sources (name, cost, key, confidence), and cache TTL. Console tabs derive from it; Phase 6 types plug in by adding one entry + their route.
- **Caching** — route-level results cached by identifier hash (email 1h, domain 6h, IP/phone 24h; password and username never), DB-backed when a database is configured, in-memory otherwise. `X-Cache: HIT|MISS` header.
- **Also fixed in this phase:** a bad HIBP key (server or BYOK) used to fail the whole email check with a 502; it now surfaces as an honest per-source error.
- **Verified live locally (61/61 E2E assertions against a local Postgres)** and on production for the no-DB states. The Neon-driver path is untested live until `DATABASE_URL` is set — see the deployment note below.
- **Deployment note:** accounts need Bintang to create the Neon project and set `DATABASE_URL` (plus `SESSION_SECRET`, `ENCRYPTION_KEY`, `CRON_SECRET` — set by the agent in Vercel). Until then the app runs as before: all checkers work anonymously and sign-in reports "not configured".

## Phase 6 — New identifier types (DONE — live 2026-11-15)

Four new checkers, ten total. Each plugs into the `lib/checkers.ts`
registry with one entry + one route (the image checker has no route —
it is client-side only, so `route` is optional on the registry now).

- **File hash** — MD5/SHA-1/SHA-256 reputation via CIRCL hashlookup
  (keyless, verified live both directions: EICAR test hash returns
  KnownMalicious, a random hash returns 404) + urlscan.io hash search
  (keyless, verified both directions) + VirusTotal, MalwareBazaar,
  Hybrid Analysis, OTX file pulses (all keyed, implemented from the
  public docs, needs-key states until a key is configured). **Two brief
  corrections:** MalwareBazaar is NOT keyless anymore — its Community
  API has required a free Auth-Key (auth.abuse.ch) since 2025; and
  the brief's "EICAR hash" had to be recomputed from the test string
  (the remembered value was 63 chars and wrong). Cache TTL 24h.
- **URL reputation** — urlscan.io page.url search (keyless, verified
  live both directions) + VirusTotal URL report + Google Safe Browsing
  (both keyed, from docs, needs-key states). The URL is only sent to
  reputation APIs — HymnGuard never fetches it (no SSRF surface).
  Cache TTL 1h.
- **Image** — EXIF/XMP/IPTC analysis with exifr, fully client-side: the
  file NEVER leaves the browser (no API route, no upload, no key).
  Shows camera/device, software, timestamps, exposure, and GPS
  coordinates when present (with a Maps link and a privacy warning).
  Verified locally with crafted test JPEGs (GPS + device present vs
  stripped). 20 MB cap.
- **Crypto wallet** — Etherscan API v2 unified (one key covers Ethereum
  + BNB Chain; the brief's "Etherscan + BSCScan (separate keys)" is
  outdated — v1 was deprecated in August 2025). Balance, tx count,
  first/last activity per chain. EIP-55 checksum validation
  client- and server-side (js-sha3). Without a key the check reports
  "needs an Etherscan API key" — never an empty result. Implemented
  from the docs; untested live (no key). Cache TTL 1h.
- **New BYOK providers:** virustotal, malwarebazaar, hybridanalysis,
  safebrowsing, etherscan (11 total). Server history masking extended:
  URLs stored with query + fragment stripped, image entries store only
  the file name.
- **Excluded:** reverse image search (TinEye paid, Google Lens has no
  official API — still a research item, not built); MalwareBazaar CSV
  export (410 Gone); token holdings / identity linking for wallets
  (out of scope — public chain data only).

## Phase 7 — Dossier mode (opt-in, authenticated only) — DONE (2026-11-16)

- Combine identifiers into one dossier (Maigret-style): username + email + domain + current IP cross-referenced into an identity graph.
- **Strictly opt-in, own identifiers only** — every identifier must be ownership-verified. No third-party dossiers, no people-search.
- **Ownership proofs (server-enforced, 403 otherwise):** email via Phase 3 verification token / own verified account email / monitored email; username via local-part of a verified email or GitHub commits by that login using a verified email (needs a GitHub token); domain via DNS TXT record `_hymnguard.<domain>` carrying a stateless HMAC token (24h TTL); IP via request-IP match at build time (typed IPs never accepted).
- **Excluded (by design, documented in the README):** phone (no SMS channel), wallet (would need message signing), password/hash/URL/image (not identity identifiers).
- **Architecture:** migration `002_dossier.sql` (`verified_identifiers` + `dossier_runs`); the build script now applies all migrations in order. Chunked, client-driven build (POST `/api/dossier/build` creates the run, POST `/api/dossier/build/chunk` runs one identifier's section, ~9s budget each) because a full dossier can't fit in one 10s invocation. Sections call the checker lib functions directly — the email check was extracted into `runFullEmailCheck` (shared by the route and the dossier) and `checkDomain` gained an `includeSubdomains` option (dossier skips crt.sh, says so honestly). Scoring is pure (`lib/dossier-score.ts`): 0–100, capped, auth grade deduped per domain, bands Low/Moderate/High/Critical, remediations deduped and sorted P1→P3.
- **UI:** `/dossier` page (dense OpenRouter-style, dark default): verified-identifiers management (email code flow, username, domain TXT flow), build picker (verified identifiers + current IP + optional enumeration with a fresh token), report view (score, cross-refs, remediations, findings, per-identifier sections with the full result components expandable), JSON download + print (light palette forced in print CSS). Dossier link in the header nav and a card on the dashboard. "Re-run in console" prefills the console via localStorage.
- **Verified:** 47 unit tests (scoring + domain tokens, incl. injected-resolver confirm tests); 70-assertion local E2E (signup → verify → build → chunks → report → 403/400/401 negatives → cleanup); visual QA 0px overflow at 1440/768/390; production E2E with a throwaway account (signup → verify → build → chunks → report, plus the 403 rejection test) — see the phase report. Domain TXT positive path implemented from docs + unit-tested (no domain available to add a record to — same precedent as OTX/AbuseIPDB/IPQS).
- **Two bugs found by QA and fixed before shipping:** (1) the build picker auto-select effect read a ref inside a setState updater — the ref was already updated by the time the updater ran, so nothing was ever selected (captured the previous ids first); (2) the `no-print` wrapper div made the build section a `:first-child`, killing its top divider (className prop instead).

---

## Explicitly out of scope

| Excluded | Why |
|---|---|
| People-investigation directories | Paid, US-centric, and a doxxing risk in a public tool |
| Dark-web search | Needs Tor; doesn't run on Vercel serverless |
| Active port / vulnerability scanning of arbitrary targets | No consent — legal risk (UU ITE / CFAA). Only with verified ownership |
| Displaying breach contents | Passwords and PII are never shown — metadata only, always |
| Scraping-gated sources requiring accounts or ToS violations | Fragile and not defensible in a public tool |
| Manual research workflows (Google dorks, company research) | Human research, not a checker — out of scope by design |

## Source evaluation checklist (for every new source)

1. Is it free, or does it have a usable free tier?
2. Does it have an API, or is it scrapable without violating ToS?
3. Can its results be verified live (known-positive + known-negative)?
4. Does it need a key? If yes, can it work under BYOK?
5. Does it create an abuse vector? If yes, what gate neutralizes it?
6. What is its rate limit, and does HymnGuard's caching keep us under it?

A source joins the roadmap only when all six have answers.
