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

## Phase 1 — Username: full coverage (IN PROGRESS)

- Port Sherlock's full site list (`data.json`, 400+ sites) into `lib/username-sites.ts`.
- Live-verify every detection rule with a known-existing username and a known-nonexistent control username. Exclude anything unreliable (documented, same precedent as Instagram / Spotify / Reddit).
- Evaluate merging unique sites from Blackbird (600+), WhatsMyName, and Maigret — same verification bar, no exceptions.
- UI: found-first ordering, filter by status, search by site name.
- **Done when:** control username yields 0 false positives; full sweep completes in reasonable time.

## Phase 2 — Domain & IP expansion (NEXT — mostly free)

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

## Phase 3 — Email expansion

- **Holehe-style account enumeration** — check whether the email is registered on popular sites via their forgot-password flows. **Gated:** only after ownership verification (code sent to the email) + strict rate limits. No bulk checks, ever.
- **Breach sources beyond HIBP** — LeakCheck, CheckLeaked, OsintCat (free tiers). Label each source's confidence; HIBP remains the gold standard.
- **Infostealer exposure** — Hudson Rock free check (is the email in stealer logs?).
- **GitHub exposure** — search public commits for the email address (Gitrecon-style; needs a GitHub token server-side or via BYOK).
- **Deep verification** — Reacher-style SMTP checks. Optional and heavily rate-limited (SMTP probing can look like spam); skip if it proves abusive.
- Shared with Phase 2: SPF / DKIM / DMARC grading for the email's domain.

## Phase 4 — Phone expansion (limited by free sources)

- **PhoneInfoga-style aggregation** — carrier lookup from free sources, prefix databases (including Indonesia prefix data), line-type detection.
- **Spam / scam reports** — presence in public complaint boards (fragile, scraping-dependent — treat as best-effort).
- **Honest scope:** format, country, carrier, line type, spam-report presence. Truecaller / Twilio-class identity data stays behind BYOK (Phase 5).
- Phone remains the hardest category for free sources. No overpromising.

## Phase 5 — Platform: accounts, history, monitoring, BYOK

The biggest architectural step. Turns HymnGuard from a tool into a service.

- **Auth** — email/password + Google (same pattern as Hymn Router).
- **Database** — Postgres (Neon) + Prisma. Saved check history per account.
- **Breach monitoring** — watch identifiers, re-check on schedule, email alerts (Resend) when a new breach hits a watched identifier.
- **Bring Your Own Key (BYOK)** — users add their own API keys (HIBP, Shodan, Censys, AbuseIPDB, Hunter). Keys encrypted at rest, used server-side only, never exposed to the browser.
- **Plugin architecture** — each source becomes a module declaring: name, cost (free/paid), key required?, rate limit, confidence. New sources become additive instead of rewrites.
- **Caching** — results cached by identifier hash (breach data changes slowly; re-checks are cheap).

## Phase 6 — New identifier types

- **File hash / URL reputation** — VirusTotal (free tier), MalwareBazaar (free API), Hybrid Analysis (free tier). Easiest new type.
- **Image** — EXIF / metadata analysis (free, client-side — easy win). Reverse image search is a research item: TinEye is paid, Google Lens has no official API.
- **Crypto wallet** — public chain data via Etherscan / BSCScan free APIs (exposure, scam labels).

## Phase 7 — Dossier mode (opt-in, authenticated only)

- Combine identifiers into one dossier (Maigret-style): username + email + phone cross-referenced into an identity graph.
- **Strictly opt-in, own identifiers only** — every identifier must be ownership-verified. No third-party dossiers, no people-search.
- Mostly product + safety design work; the checkers already exist by then.

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
