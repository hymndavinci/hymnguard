// Domain registration data via RDAP (rdap.org bootstrap, free, no key).
// Follows the redirect to the authoritative RDAP server, then follows the
// `related` link to the registrar's RDAP record for the registrar name.

const RDAP_TIMEOUT_MS = 6000;
const REGISTRAR_TIMEOUT_MS = 4000;
const USER_AGENT =
  "HymnGuard/1.0 (+https://hymnguard.vercel.app) RDAP lookup";

export interface RdapResult {
  ok: boolean;
  error?: string;
  /** False when the registry answers 404 — the domain is not registered. */
  registered?: boolean;
  registrar?: string;
  registrarIanaId?: string;
  registrarUrl?: string;
  createdAt?: string;
  expiresAt?: string;
  updatedAt?: string;
  status?: string[];
  nameservers?: string[];
  /** DS record published at the parent — the DNSSEC chain-of-trust signal. */
  delegationSigned?: boolean;
}

interface RdapEvent {
  eventAction?: string;
  eventDate?: string;
}

interface RdapEntity {
  roles?: string[];
  handle?: string | number;
  links?: { href?: string; rel?: string; type?: string }[];
  publicIds?: { type?: string; identifier?: string }[];
  vCardArray?: unknown;
  vcardArray?: unknown;
  [key: string]: unknown;
}

interface RdapResponse {
  events?: RdapEvent[];
  entities?: RdapEntity[];
  links?: { href?: string; rel?: string; type?: string }[];
  status?: string[];
  nameservers?: { ldhName?: string }[];
  secureDNS?: { delegationSigned?: boolean };
  [key: string]: unknown;
}

async function fetchRdapJson(
  url: string,
  timeoutMs: number,
): Promise<{ status: number; json: RdapResponse | null }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      headers: { Accept: "application/rdap+json", "User-Agent": USER_AGENT },
      signal: controller.signal,
      redirect: "follow",
    });
    if (res.status === 404) return { status: 404, json: null };
    if (!res.ok) return { status: res.status, json: null };
    const text = await res.text();
    if (!text.trim()) return { status: res.status, json: null };
    try {
      return { status: res.status, json: JSON.parse(text) as RdapResponse };
    } catch {
      return { status: res.status, json: null };
    }
  } finally {
    clearTimeout(timer);
  }
}

function eventDate(
  events: RdapEvent[] | undefined,
  actions: string[],
): string | undefined {
  for (const action of actions) {
    const event = events?.find((e) => e.eventAction === action);
    if (event?.eventDate) return event.eventDate;
  }
  return undefined;
}

/** vCard property lookup. RDAP servers disagree on the key casing
 * (`vCardArray` vs `vcardArray`) and on which properties exist. */
function vcardValue(entity: RdapEntity, property: string): string | undefined {
  const vcard = (entity.vCardArray ?? entity.vcardArray) as
    | [string, unknown[][]]
    | undefined;
  const rows = vcard?.[1];
  if (!Array.isArray(rows)) return undefined;
  for (const row of rows) {
    if (Array.isArray(row) && row[0] === property && typeof row[3] === "string") {
      return row[3];
    }
  }
  return undefined;
}

function registrarEntity(
  entities: RdapEntity[] | undefined,
): RdapEntity | undefined {
  return entities?.find((e) => (e.roles ?? []).includes("registrar"));
}

function ianaId(entity: RdapEntity | undefined): string | undefined {
  return entity?.publicIds?.find((id) => id.type === "IANA Registrar ID")
    ?.identifier;
}

function linkHostname(entity: RdapEntity | undefined): string | undefined {
  const href = entity?.links?.[0]?.href;
  if (!href) return undefined;
  try {
    return new URL(href).hostname.replace(/^www\./, "");
  } catch {
    return undefined;
  }
}

export async function fetchRdap(domain: string): Promise<RdapResult> {
  // One retry: RDAP endpoints occasionally return an empty body.
  let thin: { status: number; json: RdapResponse | null } = {
    status: 0,
    json: null,
  };
  for (let attempt = 0; attempt < 2; attempt++) {
    thin = await fetchRdapJson(
      `https://rdap.org/domain/${encodeURIComponent(domain)}`,
      RDAP_TIMEOUT_MS,
    );
    if (thin.json || thin.status === 404) break;
  }

  if (thin.status === 404) {
    return { ok: true, registered: false };
  }
  if (!thin.json) {
    return {
      ok: false,
      error:
        thin.status > 0
          ? `RDAP lookup failed (HTTP ${thin.status})`
          : "RDAP lookup timed out or returned no data",
    };
  }

  const data = thin.json;
  const thinRegistrar = registrarEntity(data.entities);
  let registrar = vcardValue(thinRegistrar ?? {}, "fn");
  let registrarIanaId = ianaId(thinRegistrar);
  let registrarUrl = linkHostname(thinRegistrar);

  // The thin (registry) record rarely names the registrar. Follow the
  // `related` link to the registrar's RDAP record when one is advertised.
  const related = data.links?.find(
    (l) => l.rel === "related" && l.type === "application/rdap+json" && l.href,
  );
  if (related?.href) {
    try {
      const full = await fetchRdapJson(related.href, REGISTRAR_TIMEOUT_MS);
      if (full.json) {
        const reg = registrarEntity(full.json.entities);
        registrar =
          vcardValue(reg ?? {}, "fn") ??
          vcardValue(reg ?? {}, "org") ??
          registrar;
        registrarIanaId = ianaId(reg) ?? registrarIanaId;
        registrarUrl = linkHostname(reg) ?? registrarUrl;
      }
    } catch {
      // Fall through to the thin record's data.
    }
  }

  return {
    ok: true,
    registered: true,
    registrar,
    registrarIanaId,
    registrarUrl,
    createdAt: eventDate(data.events, ["registration"]),
    expiresAt: eventDate(data.events, ["expiration", "registrar expiration"]),
    updatedAt: eventDate(data.events, ["last changed"]),
    status: data.status,
    nameservers: data.nameservers
      ?.map((ns) => ns.ldhName)
      .filter((name): name is string => Boolean(name)),
    delegationSigned: data.secureDNS?.delegationSigned,
  };
}
