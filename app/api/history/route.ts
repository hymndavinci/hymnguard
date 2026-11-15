import crypto from "node:crypto";
import { NextResponse } from "next/server";
import { getCurrentUser, hashIdentifier, maskIdentifier } from "@/lib/auth";
import { getChecker } from "@/lib/checkers";
import { DB_NOT_CONFIGURED, getDb, isDbConfigured } from "@/lib/db";
import type { CheckType } from "@/lib/history";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";

export const runtime = "nodejs";
export const maxDuration = 10;

const MAX_ENTRIES_PER_USER = 200;
const LIST_LIMIT = 50;

// Saved check history (logged-in users only). Anonymous users keep the
// localStorage history in the browser; this endpoint is the server side.
//
// POST { type, input, summary } — called by the console after a check
// completes. Only a SHA-256 hash of the identifier and a masked display
// hint are stored; for password checks the input is ignored entirely.
// GET — the user's own history, newest first. DELETE — clears it all.
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
    type: string;
    identifier_hint: string | null;
    summary: string;
    created_at: string;
  }>(
    `SELECT id, type, identifier_hint, summary,
            created_at::text AS created_at
     FROM checks WHERE user_id = $1
     ORDER BY created_at DESC LIMIT $2`,
    [user.id, LIST_LIMIT],
  );
  return NextResponse.json({
    checks: rows.map((row) => ({
      id: row.id,
      type: row.type,
      identifierHint: row.identifier_hint,
      summary: row.summary,
      createdAt: row.created_at,
    })),
  });
}

export async function POST(req: Request) {
  const ip = getClientIp(req);
  const limit = checkRateLimit(`history:log:${ip}`, 30);
  if (!limit.allowed) {
    return NextResponse.json(
      { error: "Rate limit exceeded. Try again shortly." },
      { status: 429, headers: { "Retry-After": String(limit.retryAfterSec) } },
    );
  }
  if (!isDbConfigured()) {
    return NextResponse.json(DB_NOT_CONFIGURED, { status: 503 });
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
  const input = body as {
    type?: unknown;
    input?: unknown;
    summary?: unknown;
  } | null;
  const type = typeof input?.type === "string" ? input.type : "";
  const checker = getChecker(type);
  if (!checker) {
    return NextResponse.json({ error: "Invalid check type." }, { status: 400 });
  }
  const summary =
    typeof input?.summary === "string" ? input.summary.trim() : "";
  if (!summary || summary.length > 500) {
    return NextResponse.json(
      { error: "Invalid summary." },
      { status: 400 },
    );
  }
  // Password checks store no input at all — ignore whatever was sent.
  const rawInput =
    type === "password"
      ? ""
      : typeof input?.input === "string"
        ? input.input
        : "";
  if (type !== "password" && !rawInput) {
    return NextResponse.json({ error: "Invalid input." }, { status: 400 });
  }

  const checkType = type as CheckType;
  await db.exec(
    `INSERT INTO checks (id, user_id, type, identifier_hash, identifier_hint, summary)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [
      crypto.randomUUID(),
      user.id,
      type,
      hashIdentifier(checkType, rawInput),
      maskIdentifier(checkType, rawInput) || null,
      summary,
    ],
  );
  // Opportunistic cap: keep the newest 200 rows per user.
  await db.exec(
    `DELETE FROM checks
     WHERE user_id = $1 AND id NOT IN (
       SELECT id FROM checks WHERE user_id = $1
       ORDER BY created_at DESC LIMIT $2
     )`,
    [user.id, MAX_ENTRIES_PER_USER],
  );
  return NextResponse.json({ ok: true }, { status: 201 });
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
  await db.exec(`DELETE FROM checks WHERE user_id = $1`, [user.id]);
  return NextResponse.json({ ok: true });
}
