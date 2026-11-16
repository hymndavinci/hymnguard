import { NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { DB_NOT_CONFIGURED, getDb } from "@/lib/db";
import {
  createDossierRun,
  MAX_DOSSIER_IDENTIFIERS,
  resolveDomainOwnership,
  resolveEmailOwnership,
  resolveUsernameOwnership,
  resolveVerifiedId,
  toPublicRun,
  toRunIdentifier,
  type DossierIdentifierInput,
  type DossierRunIdentifier,
} from "@/lib/dossier";
import { resolveKeys } from "@/lib/keys";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";
import {
  normalizeDomain,
  normalizeEmail,
  normalizeIp,
  normalizeUsername,
} from "@/lib/validate";

export const runtime = "nodejs";
export const maxDuration = 10;

// POST { identifiers?: [{ type, value }], verifiedIds?: string[],
//       includeCurrentIp?: boolean } — creates a dossier run.
//
// THE HARD RULE, enforced here: every identifier is checked against the
// user's verified set before the run exists. Anything unverified is
// rejected with 403 and no run is created. IPs are only ever accepted via
// includeCurrentIp (the request's own public IP) — a user-supplied IP
// value is never trusted, since any IP could be anyone's.
//
// The run is then built chunk by chunk via /api/dossier/build/chunk (one
// identifier per chunk), because a full dossier cannot fit in one
// 10-second serverless invocation.
export async function POST(req: Request) {
  const ip = getClientIp(req);
  const limit = checkRateLimit(`dossier:build:${ip}`);
  if (!limit.allowed) {
    return NextResponse.json(
      { error: "Rate limit exceeded. Try again shortly." },
      {
        status: 429,
        headers: { "Retry-After": String(limit.retryAfterSec) },
      },
    );
  }

  const user = await getCurrentUser(req);
  if (!user) {
    return NextResponse.json({ error: "Sign in required." }, { status: 401 });
  }
  const db = getDb();
  if (!db) {
    return NextResponse.json(DB_NOT_CONFIGURED, { status: 503 });
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }
  const input = (body as {
    identifiers?: unknown;
    verifiedIds?: unknown;
    includeCurrentIp?: unknown;
  } | null) ?? {};

  const raw: DossierIdentifierInput[] = [];
  const reject = (message: string, status = 400) =>
    NextResponse.json({ error: message }, { status });

  if (Array.isArray(input.identifiers)) {
    for (const item of input.identifiers) {
      const entry = item as { type?: unknown; value?: unknown } | null;
      const type = typeof entry?.type === "string" ? entry.type : "";
      if (type === "email") {
        const value = normalizeEmail(entry?.value);
        if (!value) return reject("Invalid email address.");
        raw.push({ type: "email", value });
      } else if (type === "username") {
        const value = normalizeUsername(entry?.value);
        if (!value) return reject("Invalid username.");
        raw.push({ type: "username", value });
      } else if (type === "domain") {
        const value = normalizeDomain(entry?.value);
        if (!value) return reject("Invalid domain.");
        raw.push({ type: "domain", value });
      } else if (type === "ip") {
        return reject(
          "IP addresses are only accepted as your current IP (includeCurrentIp) — a typed IP could be anyone's.",
        );
      } else {
        return reject(
          "Dossiers only cover email, username, domain, and your current IP.",
        );
      }
    }
  }

  if (Array.isArray(input.verifiedIds)) {
    for (const id of input.verifiedIds) {
      if (typeof id !== "string") {
        return reject("Invalid verified identifier id.");
      }
      const resolved = await resolveVerifiedId(db, user, id);
      if (!resolved) {
        return NextResponse.json(
          { error: "Unknown verified identifier." },
          { status: 404 },
        );
      }
      raw.push({ type: resolved.type, value: resolved.value });
    }
  }

  if (input.includeCurrentIp === true) {
    const currentIp = normalizeIp(ip);
    if (!currentIp) {
      return reject(
        "Could not determine your public IP address from this connection.",
      );
    }
    raw.push({ type: "ip", value: currentIp });
  }

  // Dedupe (case-insensitive for email/username/domain).
  const seen = new Set<string>();
  const identifiers: DossierIdentifierInput[] = [];
  for (const item of raw) {
    const key = `${item.type}:${item.value.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    identifiers.push(item);
  }

  if (identifiers.length === 0) {
    return reject("Pick at least one verified identifier.");
  }
  if (identifiers.length > MAX_DOSSIER_IDENTIFIERS) {
    return reject(
      `A dossier can cover at most ${MAX_DOSSIER_IDENTIFIERS} identifiers.`,
    );
  }

  // Ownership enforcement: every identifier must be in the user's verified
  // set. The first unverified identifier fails the whole build — no partial
  // runs on someone else's identifiers.
  const keys = await resolveKeys(user.id);
  for (const item of identifiers) {
    if (item.type === "ip") continue; // Verified by request-IP match above.
    const ownership =
      item.type === "email"
        ? await resolveEmailOwnership(db, user, item.value)
        : item.type === "username"
          ? await resolveUsernameOwnership(db, user, item.value, keys.github)
          : await resolveDomainOwnership(db, user, item.value);
    if (!ownership.verified) {
      return NextResponse.json(
        {
          error: `Not verified: ${item.value}. ${ownership.reason ?? "Verify ownership of this identifier first."}`,
          identifier: item.value,
          type: item.type,
        },
        { status: 403 },
      );
    }
  }

  const runIdentifiers: DossierRunIdentifier[] = [];
  for (const item of identifiers) {
    const runIdentifier = toRunIdentifier(item);
    if ("error" in runIdentifier) {
      return NextResponse.json({ error: runIdentifier.error }, { status: 503 });
    }
    runIdentifiers.push(runIdentifier);
  }

  const run = await createDossierRun(db, user.id, runIdentifiers);
  return NextResponse.json(toPublicRun(run), { status: 201 });
}
