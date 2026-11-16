import { NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { DB_NOT_CONFIGURED, getDb } from "@/lib/db";
import {
  addVerifiedIdentifier,
  listVerifiedIdentifiers,
  removeVerifiedIdentifier,
  resolveEmailOwnership,
  resolveUsernameOwnership,
} from "@/lib/dossier";
import { verifyVerificationToken } from "@/lib/email-verify";
import { resolveKeys } from "@/lib/keys";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";
import {
  normalizeEmail,
  normalizeUsername,
} from "@/lib/validate";

export const runtime = "nodejs";
export const maxDuration = 10;

// GET — the user's verified identifiers (registry rows + derived entries:
// the own verified account email and monitored emails).
//
// POST { type, value, token? } — verify ownership of an identifier and add
// it to the registry:
//   email    — needs a valid Phase 3 verification token (code sent to the
//              address). Already-verified emails return alreadyVerified.
//   username — the local-part of a verified email, or a GitHub login whose
//              public commits use a verified email (needs a GitHub token).
//   domain   — rejected here; use /api/dossier/verify-domain/* (DNS TXT).
//   ip       — rejected here; verified per build from the request IP.
//   anything else — rejected; dossiers only cover identity identifiers.
//
// DELETE ?id= — removes a registry row. Derived entries can't be removed
// here (remove the monitor, or change the account email).
export async function GET(req: Request) {
  const ip = getClientIp(req);
  const limit = checkRateLimit(`dossier:identifiers:list:${ip}`);
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

  const identifiers = await listVerifiedIdentifiers(db, user);
  return NextResponse.json({ identifiers });
}

export async function POST(req: Request) {
  const ip = getClientIp(req);
  const limit = checkRateLimit(`dossier:identifiers:add:${ip}`);
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
  const input = (body as { type?: unknown; value?: unknown; token?: unknown } | null) ?? {};
  const type = typeof input.type === "string" ? input.type : "";
  const token = typeof input.token === "string" ? input.token : "";

  if (type === "email") {
    const email = normalizeEmail(input.value);
    if (!email) {
      return NextResponse.json(
        { error: "Invalid email address." },
        { status: 400 },
      );
    }
    const existing = await resolveEmailOwnership(db, user, email);
    if (existing.verified) {
      return NextResponse.json({
        alreadyVerified: true,
        method: existing.method,
      });
    }
    if (!token) {
      return NextResponse.json(
        {
          error:
            "Ownership verification required. Verify this email first — we send a 6-digit code to the address.",
          needsVerification: true,
        },
        { status: 401 },
      );
    }
    const secret = process.env.VERIFY_SECRET;
    if (!secret) {
      return NextResponse.json(
        {
          error:
            "Email verification is not configured on this deployment (VERIFY_SECRET is not set).",
        },
        { status: 503 },
      );
    }
    if (!verifyVerificationToken(secret, email, token)) {
      return NextResponse.json(
        {
          error:
            "The verification token is invalid or expired. Request a new code.",
          needsVerification: true,
        },
        { status: 401 },
      );
    }
    const saved = await addVerifiedIdentifier(db, user.id, {
      type: "email",
      value: email,
      method: "email_code",
    });
    if (!saved.ok) {
      return NextResponse.json({ error: saved.error }, { status: 400 });
    }
    return NextResponse.json(
      { verified: true, method: "email_code", id: saved.id },
      { status: 201 },
    );
  }

  if (type === "username") {
    const username = normalizeUsername(input.value);
    if (!username) {
      return NextResponse.json(
        { error: "Invalid username." },
        { status: 400 },
      );
    }
    const keys = await resolveKeys(user.id);
    const ownership = await resolveUsernameOwnership(
      db,
      user,
      username,
      keys.github,
    );
    if (!ownership.verified) {
      return NextResponse.json(
        {
          error:
            ownership.reason ??
            "Could not verify ownership of this username.",
          ...(ownership.note ? { note: ownership.note } : {}),
        },
        { status: 403 },
      );
    }
    const saved = await addVerifiedIdentifier(db, user.id, {
      type: "username",
      value: username,
      method: ownership.method ?? "username_localpart",
    });
    if (!saved.ok) {
      return NextResponse.json({ error: saved.error }, { status: 400 });
    }
    return NextResponse.json(
      { verified: true, method: ownership.method, id: saved.id },
      { status: 201 },
    );
  }

  if (type === "domain") {
    return NextResponse.json(
      {
        error:
          "Domains are verified with a DNS TXT record. Request a verification record first.",
        useVerifyDomain: true,
      },
      { status: 400 },
    );
  }

  if (type === "ip") {
    return NextResponse.json(
      {
        error:
          "IP addresses are verified per build from your current connection — add 'Current IP' when building a dossier.",
      },
      { status: 400 },
    );
  }

  const reasons: Record<string, string> = {
    phone:
      "Phone numbers can't be verified — HymnGuard has no SMS verification channel.",
    wallet:
      "Crypto wallets can't be verified — that would need message signing, which HymnGuard doesn't do.",
    password:
      "Passwords are not identity identifiers and are never stored or checked in a dossier.",
    hash: "File hashes are not identity identifiers and can't be owned.",
    url: "URLs are not identity identifiers and can't be owned.",
    image: "Images are not identity identifiers and can't be owned.",
  };
  return NextResponse.json(
    {
      error:
        reasons[type] ??
        "Only email, username, domain, and your current IP can be verified for dossiers.",
    },
    { status: 400 },
  );
}

export async function DELETE(req: Request) {
  const ip = getClientIp(req);
  const limit = checkRateLimit(`dossier:identifiers:delete:${ip}`);
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

  const id = new URL(req.url).searchParams.get("id") ?? "";
  if (!id) {
    return NextResponse.json(
      { error: "Missing identifier id." },
      { status: 400 },
    );
  }
  if (id === "account" || id.startsWith("monitor:")) {
    return NextResponse.json(
      {
        error:
          "This identifier comes from your account or a monitor — remove the monitor, or change your account email, to remove it.",
      },
      { status: 400 },
    );
  }
  const removed = await removeVerifiedIdentifier(db, user.id, id);
  if (!removed) {
    return NextResponse.json(
      { error: "Identifier not found." },
      { status: 404 },
    );
  }
  return NextResponse.json({ removed: true });
}
