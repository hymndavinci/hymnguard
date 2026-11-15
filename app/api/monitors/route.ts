import crypto from "node:crypto";
import { NextResponse } from "next/server";
import { getCurrentUser, maskIdentifier } from "@/lib/auth";
import { decryptSecret, encryptSecret, getEncryptionKey } from "@/lib/crypto";
import { DB_NOT_CONFIGURED, getDb, isDbConfigured } from "@/lib/db";
import { verifyVerificationToken } from "@/lib/email-verify";
import { checkMonitoredEmail } from "@/lib/monitor";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";
import { normalizeEmail } from "@/lib/validate";

export const runtime = "nodejs";
export const maxDuration = 15;

const MAX_MONITORS_PER_USER = 5;

const ENCRYPTION_NOT_CONFIGURED = {
  error:
    "Monitoring is not configured on this deployment (ENCRYPTION_KEY is not set).",
  needsSetup: true,
} as const;

// Breach monitoring (logged-in users only).
//
// POST { email, token? } — watches an email address. Ownership is
// required: either the email is the user's own verified account email,
// or the caller passes a Phase 3 ownership-verification token for it
// (obtained via /api/check/email/verify). The email is stored
// AES-256-GCM encrypted; the daily cron re-checks it and alerts on new
// exposure. A first check runs inline so the dashboard shows status
// immediately.
// GET — the user's monitors (masked emails + last status).
// DELETE ?id= — removes a monitor.
export async function GET(req: Request) {
  if (!isDbConfigured()) {
    return NextResponse.json(DB_NOT_CONFIGURED, { status: 503 });
  }
  const user = await getCurrentUser(req);
  if (!user) {
    return NextResponse.json({ error: "Not signed in." }, { status: 401 });
  }
  const db = getDb();
  if (!db) return NextResponse.json(DB_NOT_CONFIGURED, { status: 503 });

  const rows = await db.query<{
    id: string;
    email_encrypted: string;
    verified_at: string;
    last_checked_at: string | null;
    last_leakcheck_found: number | null;
    last_hudson_associated: boolean | null;
    last_alert_at: string | null;
    created_at: string;
  }>(
    `SELECT id, email_encrypted,
            verified_at::text AS verified_at,
            last_checked_at::text AS last_checked_at,
            last_leakcheck_found, last_hudson_associated,
            last_alert_at::text AS last_alert_at,
            created_at::text AS created_at
     FROM monitors WHERE user_id = $1 ORDER BY created_at DESC`,
    [user.id],
  );
  const encKey = getEncryptionKey();
  return NextResponse.json({
    monitors: rows.map((row) => {
      const email = encKey
        ? decryptSecret(encKey, row.email_encrypted)
        : null;
      return {
        id: row.id,
        emailMasked: email ? maskIdentifier("email", email) : "***",
        verifiedAt: row.verified_at,
        lastCheckedAt: row.last_checked_at,
        lastLeakCheckFound: row.last_leakcheck_found,
        lastHudsonAssociated: row.last_hudson_associated,
        lastAlertAt: row.last_alert_at,
        createdAt: row.created_at,
      };
    }),
  });
}

export async function POST(req: Request) {
  const ip = getClientIp(req);
  const limit = checkRateLimit(`monitors:add:${ip}`);
  if (!limit.allowed) {
    return NextResponse.json(
      { error: "Rate limit exceeded. Try again shortly." },
      { status: 429, headers: { "Retry-After": String(limit.retryAfterSec) } },
    );
  }
  if (!isDbConfigured()) {
    return NextResponse.json(DB_NOT_CONFIGURED, { status: 503 });
  }
  const encKey = getEncryptionKey();
  if (!encKey) {
    return NextResponse.json(ENCRYPTION_NOT_CONFIGURED, { status: 503 });
  }
  const user = await getCurrentUser(req);
  if (!user) {
    return NextResponse.json({ error: "Not signed in." }, { status: 401 });
  }
  const db = getDb();
  if (!db) return NextResponse.json(DB_NOT_CONFIGURED, { status: 503 });

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }
  const input = body as { email?: unknown; token?: unknown } | null;
  const email = normalizeEmail(input?.email);
  if (!email) {
    return NextResponse.json({ error: "Invalid email address." }, { status: 400 });
  }

  // Ownership: the user's own verified account email needs no token;
  // any other address needs a Phase 3 verification token for it.
  const isOwnVerifiedEmail =
    email === user.email.toLowerCase() && user.emailVerified;
  if (!isOwnVerifiedEmail) {
    const verifySecret = process.env.VERIFY_SECRET;
    const token = typeof input?.token === "string" ? input.token : "";
    if (
      !verifySecret ||
      !token ||
      !verifyVerificationToken(verifySecret, email, token)
    ) {
      return NextResponse.json(
        {
          error:
            "Ownership verification is required for this email. Verify it first with the code sent to the address.",
          needsVerification: true,
        },
        { status: 401 },
      );
    }
  }

  const count = await db.queryOne<{ count: string }>(
    `SELECT count(*)::text AS count FROM monitors WHERE user_id = $1`,
    [user.id],
  );
  if (Number(count?.count ?? 0) >= MAX_MONITORS_PER_USER) {
    return NextResponse.json(
      { error: `You can watch up to ${MAX_MONITORS_PER_USER} email addresses.` },
      { status: 409 },
    );
  }

  const emailHash = crypto
    .createHash("sha256")
    .update(`email:${email}`)
    .digest("hex");
  const id = crypto.randomUUID();
  const inserted = await db.queryOne<{ id: string }>(
    `INSERT INTO monitors (id, user_id, email_hash, email_encrypted, verified_at)
     VALUES ($1, $2, $3, $4, now())
     ON CONFLICT (user_id, email_hash) DO NOTHING
     RETURNING id`,
    [id, user.id, emailHash, encryptSecret(encKey, email)],
  );
  if (!inserted) {
    return NextResponse.json(
      { error: "You are already watching this email address." },
      { status: 409 },
    );
  }

  // First check inline so the dashboard shows status right away. Errors
  // are fine — the cron retries daily.
  const status = await checkMonitoredEmail(email);
  await db.exec(
    `UPDATE monitors
     SET last_checked_at = now(),
         last_leakcheck_found = $1, last_hudson_associated = $2
     WHERE id = $3`,
    [status.leakcheckFound, status.hudsonAssociated, inserted.id],
  );

  return NextResponse.json(
    {
      monitor: {
        id: inserted.id,
        emailMasked: maskIdentifier("email", email),
        lastLeakCheckFound: status.leakcheckFound,
        lastHudsonAssociated: status.hudsonAssociated,
      },
    },
    { status: 201 },
  );
}

export async function DELETE(req: Request) {
  if (!isDbConfigured()) {
    return NextResponse.json(DB_NOT_CONFIGURED, { status: 503 });
  }
  const user = await getCurrentUser(req);
  if (!user) {
    return NextResponse.json({ error: "Not signed in." }, { status: 401 });
  }
  const db = getDb();
  if (!db) return NextResponse.json(DB_NOT_CONFIGURED, { status: 503 });
  const id = new URL(req.url).searchParams.get("id");
  if (!id) {
    return NextResponse.json({ error: "Missing monitor id." }, { status: 400 });
  }
  const deleted = await db.queryOne<{ id: string }>(
    `DELETE FROM monitors WHERE id = $1 AND user_id = $2 RETURNING id`,
    [id, user.id],
  );
  if (!deleted) {
    return NextResponse.json({ error: "Monitor not found." }, { status: 404 });
  }
  return NextResponse.json({ ok: true });
}
