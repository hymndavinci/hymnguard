import CheckConsole from "@/components/check-console";

const PRIVACY_POINTS = [
  {
    title: "Passwords stay in your browser",
    body: "A password is hashed locally with SHA-1. Only the first 5 characters of the hash are sent, and the match is done back in your browser.",
  },
  {
    title: "Nothing is stored on the server",
    body: "Every check runs per request. Identifiers are never logged, never written to a database, and never leave the request.",
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
];

export default function Home() {
  return (
    <main className="wrap">
      <section className="pb-10 pt-14 sm:pt-20">
        <p className="font-mono text-xs font-medium uppercase tracking-[0.2em] text-gray-500">
          Free security exposure checker
        </p>
        <h1 className="mt-4 max-w-2xl text-4xl font-semibold leading-[1.1] tracking-tight sm:text-5xl">
          Know where you&rsquo;re exposed.
        </h1>
        <p className="mt-4 max-w-2xl text-lg leading-relaxed text-gray-500">
          Check a password, username, email, domain, IP address, or phone
          number against public breach data and live records. Free, no
          sign-up, and nothing is stored on the server.
        </p>
        <div className="mt-6 flex flex-wrap gap-2">
          {["Free forever", "No sign-up", "No data stored"].map((badge) => (
            <span
              key={badge}
              className="inline-flex items-center gap-1.5 rounded-full border border-gray-200 bg-gray-50 px-2.5 py-1 text-xs font-medium text-gray-600"
            >
              <span className="h-1.5 w-1.5 rounded-full bg-green-500" />
              {badge}
            </span>
          ))}
        </div>
      </section>

      <CheckConsole />

      <section id="privacy" className="mt-16 scroll-mt-20 border-t border-gray-200 pb-16 pt-12">
        <h2 className="text-lg font-semibold tracking-tight">
          How privacy works
        </h2>
        <p className="mt-1 max-w-2xl text-sm leading-relaxed text-gray-500">
          A security tool should not become another place your data leaks.
          These are the rules the whole app is built on.
        </p>
        <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2">
          {PRIVACY_POINTS.map((point) => (
            <div
              key={point.title}
              className="rounded-lg border border-gray-200 bg-white p-5"
            >
              <h3 className="text-sm font-semibold">{point.title}</h3>
              <p className="mt-1.5 text-[13px] leading-relaxed text-gray-500">
                {point.body}
              </p>
            </div>
          ))}
        </div>
      </section>

      <section id="checks" className="scroll-mt-20 border-t border-gray-200 pb-20 pt-12">
        <h2 className="text-lg font-semibold tracking-tight">
          What each check does
        </h2>
        <p className="mt-1 max-w-2xl text-sm leading-relaxed text-gray-500">
          Six checkers, each against the best free source for its kind. No
          check invents a result when its source is unavailable — it says so.
        </p>
        <div className="mt-6 overflow-hidden rounded-lg border border-gray-200">
          <table className="w-full text-sm">
            <tbody className="divide-y divide-gray-100">
              {CHECK_TYPES.map((check) => (
                <tr key={check.name}>
                  <td className="w-28 px-4 py-4 align-top font-semibold sm:px-5">
                    {check.name}
                  </td>
                  <td className="px-4 py-4 align-top text-[13px] leading-relaxed text-gray-600 sm:px-5">
                    {check.what}
                  </td>
                  <td className="hidden px-4 py-4 align-top font-mono text-xs leading-relaxed text-gray-500 sm:table-cell sm:px-5">
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
          GetContact, and Should I Answer.
        </p>
      </section>
    </main>
  );
}
