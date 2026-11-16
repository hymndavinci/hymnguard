import { NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { DB_NOT_CONFIGURED, getDb } from "@/lib/db";
import { getLatestDossierRun, toPublicRun } from "@/lib/dossier";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";

export const runtime = "nodejs";
export const maxDuration = 10;

// GET — the user's latest dossier run (or { run: null } when they have
// never built one). The response is the public run: no raw values, no
// encrypted blobs — only display strings and the stored report.
export async function GET(req: Request) {
  const ip = getClientIp(req);
  const limit = checkRateLimit(`dossier:latest:${ip}`);
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

  const run = await getLatestDossierRun(db, user.id);
  if (!run) return NextResponse.json({ run: null });
  return NextResponse.json({ run: toPublicRun(run) });
}
