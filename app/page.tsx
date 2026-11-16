import CheckConsole from "@/components/check-console";
import { CHECKERS, KEY_PROVIDERS } from "@/lib/checkers";

const PRIVACY_POINTS = [
  {
    title: "Passwords stay in your browser",
    body: "A password is hashed locally with SHA-1. Only the first 5 characters of the hash are sent, and the match is done back in your browser.",
  },
  {
    title: "Anonymous checks store nothing",
    body: "Every check runs per request. Without an account, identifiers are never logged, never written to a database, and never leave the request.",
  },
  {
    title: "Accounts are optional",
    body: "Sign up to save history, watch emails for new breaches, and use your own API keys. Saved history stores hashed identifiers and masked hints — never raw passwords.",
  },
  {
    title: "Your keys stay yours",
    body: "API keys you save (BYOK) are encrypted at rest, used server-side only, and never shown back in full.",
  },
  {
    title: "Free public sources only",
    body: "Have I Been Pwned, crt.sh, public DNS records, and live HTTP probing. No paid data brokers, no leaked databases.",
  },
  {
    title: "Rate-limited by design",
    body: "Each check type is limited to 10 requests per minute per address, so the tool cannot be used for bulk enumeration.",
  },
];

const CHECK_TYPES = [
  {
    name: "Email",
    what: "Mail server records, disposable-domain note, and breach lookup when a HIBP key is configured.",
    source: "DNS MX · Have I Been Pwned",
  },
  {
    name: "Username",
    what: "Checks whether the name exists on 256 sites, from GitHub and X to LeetCode and Kaggle.",
    source: "Live HTTP probing · Sherlock-style detection",
  },
  {
    name: "Domain",
    what: "DNS records, TLS certificate, security headers, subdomains, registration, email-auth grade, DNSSEC, blocklists, detected technology, and archive history.",
    source: "DNS · TLS · HTTP · crt.sh · RDAP · Wayback · OTX · urlscan.io",
  },
  {
    name: "IP",
    what: "Geolocation, network, and reverse DNS, plus VPN/proxy/Tor signals and AbuseIPDB reputation when a key is configured.",
    source: "ip-api.com · AbuseIPDB · Tor exit list",
  },
  {
    name: "Phone",
    what: "Validates the number, identifies the Indonesian operator from its prefix, and checks carrier/risk plus community spam reports.",
    source: "libphonenumber · prefix table · IPQS · GetContact",
  },
  {
    name: "Password",
    what: "Checks whether the password appears in known data breaches, and how many times.",
    source: "HIBP Pwned Passwords · k-anonymity",
  },
  {
    name: "File hash",
    what: "Reputation of an MD5, SHA-1, or SHA-256 hash across known-file, malware, and threat-intel sources. Only the hash is sent — never the file.",
    source: "CIRCL · urlscan.io · VirusTotal · MalwareBazaar · Hybrid Analysis · OTX",
  },
  {
    name: "URL",
    what: "Whether a URL is flagged by malware/phishing lists or has been scanned publicly. The URL is only sent to reputation APIs — never fetched.",
    source: "urlscan.io · VirusTotal · Google Safe Browsing",
  },
  {
    name: "Image",
    what: "EXIF metadata inside a photo — camera, timestamps, and GPS location when present. Analyzed in the browser; the file never leaves the device.",
    source: "exifr (local, client-side)",
  },
  {
    name: "Wallet",
    what: "Balance, first/last activity, and transaction count for an Ethereum-style address, on Ethereum and BNB Chain. Needs an Etherscan API key.",
    source: "Etherscan API v2",
  },
];

export default function Home() {
  return (
    <main className="wrap">
      <section className="pb-6 pt-8">
        <p className="font-mono text-xs font-medium uppercase tracking-[0.2em] text-gray-500">
          Free security exposure checker
        </p>
        <h1 className="mt-3 max-w-2xl text-3xl font-semibold leading-[1.1] tracking-tight sm:text-4xl">
          Know where you&rsquo;re exposed.
        </h1>
        <p className="mt-3 max-w-2xl text-[15px] leading-relaxed text-gray-500">
          Check a password, username, email, domain, IP address, phone
          number, file hash, URL, image, or crypto wallet against public
          breach data and live records. Free, no sign-up needed — and an
          optional account adds saved history, breach monitoring, your own
          API keys, and a consolidated dossier of your verified identifiers.
        </p>
        <div className="mt-4 flex flex-wrap gap-2">
          {["Free forever", "No sign-up needed", "Private by design"].map((badge) => (
            <span
              key={badge}
              className="inline-flex items-center gap-1.5 rounded-full border border-gray-200 bg-gray-50 px-2.5 py-1 text-xs font-medium text-gray-600"
            >
              <span className="h-1.5 w-1.5 rounded-full bg-green-500" />
              {badge}
            </span>
          ))}
        </div>
        <dl className="mt-6 grid grid-cols-2 overflow-hidden rounded-lg border border-gray-200 sm:grid-cols-4">
          {[
            { value: String(CHECKERS.length), label: "checkers" },
            { value: "256", label: "username sites probed" },
            { value: String(KEY_PROVIDERS.length), label: "BYOK key providers" },
            { value: "10/min", label: "rate limit per check" },
          ].map((stat, index) => (
            <div
              key={stat.label}
              className={`border-gray-200 px-4 py-3 ${index > 0 ? "border-l" : ""} ${index >= 2 ? "max-sm:border-t" : ""} ${index === 2 ? "max-sm:border-l-0" : ""}`}
            >
              <dt className="sr-only">{stat.label}</dt>
              <dd className="font-mono text-xl font-semibold leading-none tracking-tight">
                {stat.value}
              </dd>
              <dd className="mt-1 text-xs text-gray-500">{stat.label}</dd>
            </div>
          ))}
        </dl>
      </section>

      <CheckConsole />

      <section id="privacy" className="mt-10 scroll-mt-20 border-t border-gray-200 pb-10 pt-8">
        <h2 className="text-lg font-semibold tracking-tight">
          How privacy works
        </h2>
        <p className="mt-1 max-w-2xl text-sm leading-relaxed text-gray-500">
          A security tool should not become another place your data leaks.
          These are the rules the whole app is built on.
        </p>
        <div className="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {PRIVACY_POINTS.map((point) => (
            <div
              key={point.title}
              className="rounded-lg border border-gray-200 bg-white p-4"
            >
              <h3 className="text-sm font-semibold">{point.title}</h3>
              <p className="mt-1.5 text-[13px] leading-relaxed text-gray-500">
                {point.body}
              </p>
            </div>
          ))}
        </div>
      </section>

      <section id="checks" className="scroll-mt-20 border-t border-gray-200 pb-12 pt-8">
        <h2 className="text-lg font-semibold tracking-tight">
          What each check does
        </h2>
        <p className="mt-1 max-w-2xl text-sm leading-relaxed text-gray-500">
          Ten checkers, each against the best free source for its kind. No
          check invents a result when its source is unavailable — it says so.
        </p>
        <div className="mt-6 overflow-hidden rounded-lg border border-gray-200">
          <table className="w-full text-sm">
            <tbody className="divide-y divide-gray-100">
              {CHECK_TYPES.map((check) => (
                <tr key={check.name}>
                  <td className="w-24 px-4 py-2.5 align-top font-semibold sm:px-5">
                    {check.name}
                  </td>
                  <td className="px-4 py-2.5 align-top text-[13px] leading-relaxed text-gray-600 sm:px-5">
                    {check.what}
                  </td>
                  <td className="hidden px-4 py-2.5 align-top font-mono text-xs leading-relaxed text-gray-500 sm:table-cell sm:px-5">
                    {check.source}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-4 text-xs leading-relaxed text-gray-500">
          Username detection follows the approach of the open-source Sherlock
          project (sherlock-project/sherlock), re-implemented here in
          TypeScript. Breach data: Have I Been Pwned. Subdomains: crt.sh and
          AlienVault OTX. Registration: RDAP. History: Wayback Machine. IP
          data: ip-api.com and AbuseIPDB. Phone data: IPQualityScore,
          GetContact, and Should I Answer. Hash and URL reputation: CIRCL,
          urlscan.io, VirusTotal, MalwareBazaar, Hybrid Analysis, and Google
          Safe Browsing. Wallet data: Etherscan. Image metadata: exifr,
          entirely in the browser.
        </p>
      </section>
    </main>
  );
}
