import crypto from "node:crypto";
import { NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { isKeyProvider, KEY_PROVIDERS, type KeyProvider } from "@/lib/checkers";
import { encryptSecret, getEncryptionKey } from "@/lib/crypto";
import { DB_NOT_CONFIGURED, getDb, isDbConfigured } from "@/lib/db";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";

export const runtime = "nodejs";
export const maxDuration = 10;

const ENCRYPTION_NOT_CONFIGURED = {
  error:
    "API keys are not configured on this deployment (ENCRYPTION_KEY is not set).",
  needsSetup: true,
} as const;

// Bring Your Own Key (logged-in users only).
//
// POST { provider, key } — saves (or replaces) the user's key for one
// provider, AES-256-GCM encrypted at rest. The key is never returned in
// full afterwards — GET lists providers with last-4 hints only.
// DELETE ?provider= — removes a saved key.
// Checks use the user's key when one is saved, else the server env key
// (see lib/keys.ts).
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
    provider: string;
    hint: string;
    updated_at: string;
  }>(
    `SELECT provider, hint, updated_at::text AS updated_at
     FROM user_keys WHERE user_id = $1 ORDER BY provider`,
    [user.id],
  );
  const labelById = new Map(KEY_PROVIDERS.map((p) => [p.id, p.label]));
  return NextResponse.json({
    keys: rows.map((row) => ({
      provider: row.provider,
      label: labelById.get(row.provider as KeyProvider) ?? row.provider,
      hint: row.hint,
      updatedAt: row.updated_at,
    })),
  });
}

export async function POST(req: Request) {
  const ip = getClientIp(req);
  const limit = checkRateLimit(`keys:save:${ip}`);
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
  const input = body as { provider?: unknown; key?: unknown } | null;
  const provider = typeof input?.provider === "string" ? input.provider : "";
  const key = typeof input?.key === "string" ? input.key.trim() : "";
  if (!isKeyProvider(provider)) {
    return NextResponse.json({ error: "Unknown provider." }, { status: 400 });
  }
  if (key.length < 8 || key.length > 500 || /\s/.test(key)) {
    return NextResponse.json(
      { error: "Invalid API key." },
      { status: 400 },
    );
  }

  const hint = `••••${key.slice(-4)}`;
  await db.exec(
    `INSERT INTO user_keys (id, user_id, provider, encrypted_key, hint)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (user_id, provider) DO UPDATE
       SET encrypted_key = EXCLUDED.encrypted_key,
           hint = EXCLUDED.hint, updated_at = now()`,
    [crypto.randomUUID(), user.id, provider, encryptSecret(encKey, key), hint],
  );
  return NextResponse.json({ provider, hint });
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
  const provider = new URL(req.url).searchParams.get("provider") ?? "";
  if (!isKeyProvider(provider)) {
    return NextResponse.json({ error: "Unknown provider." }, { status: 400 });
  }
  const deleted = await db.queryOne<{ id: string }>(
    `DELETE FROM user_keys WHERE user_id = $1 AND provider = $2 RETURNING id`,
    [user.id, provider],
  );
  if (!deleted) {
    return NextResponse.json({ error: "No saved key for this provider." }, { status: 404 });
  }
  return NextResponse.json({ ok: true });
}
