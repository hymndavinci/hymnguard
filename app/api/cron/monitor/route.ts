import { NextResponse } from "next/server";
import { pruneExpiredCache } from "@/lib/check-cache";
import { decryptSecret, getEncryptionKey } from "@/lib/crypto";
import { DB_NOT_CONFIGURED, getDb, isDbConfigured } from "@/lib/db";
import {
  checkMonitoredEmail,
  isNewExposure,
  sendBreachAlertEmail,
} from "@/lib/monitor";

export const runtime = "nodejs";
export const maxDuration = 60;

// Daily breach-monitoring cron (Vercel Cron, see vercel.json).
//
// Re-checks each watched email against LeakCheck + Hudson Rock and emails
// an alert when new exposure appears. Auth: Vercel sends
// `Authorization: Bearer <CRON_SECRET>` when CRON_SECRET is set — the
// route requires it, and refuses to run without it.
//
// Throttling: LeakCheck and Hudson Rock each allow ~1 req/sec, so
// monitors are processed one at a time with a 1.1s gap. At most 20
// monitors per run (oldest-checked first) to stay inside the 60s
// function limit. Also prunes expired cache rows.
const MAX_MONITORS_PER_RUN = 20;
const GAP_BETWEEN_MONITORS_MS = 1100;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function GET(req: Request) {
  const cronSecret = process.env.CRON_SECRET;
  if (!cronSecret) {
    return NextResponse.json(
      {
        error: "The monitor cron is not configured (CRON_SECRET is not set).",
        needsSetup: true,
      },
      { status: 503 },
    );
  }
  const auth = req.headers.get("authorization") ?? "";
  if (auth !== `Bearer ${cronSecret}`) {
    return NextResponse.json({ error: "Unauthorized." }, { status: 401 });
  }
  if (!isDbConfigured()) {
    return NextResponse.json(DB_NOT_CONFIGURED, { status: 503 });
  }
  const encKey = getEncryptionKey();
  if (!encKey) {
    return NextResponse.json(
      {
        error: "The monitor cron is not configured (ENCRYPTION_KEY is not set).",
        needsSetup: true,
      },
      { status: 503 },
    );
  }
  const db = getDb();
  if (!db) return NextResponse.json(DB_NOT_CONFIGURED, { status: 503 });

  const monitors = await db.query<{
    id: string;
    user_id: string;
    email_encrypted: string;
    last_leakcheck_found: number | null;
    last_hudson_associated: boolean | null;
  }>(
    `SELECT id, user_id, email_encrypted,
            last_leakcheck_found, last_hudson_associated
     FROM monitors
     ORDER BY last_checked_at ASC NULLS FIRST
     LIMIT $1`,
    [MAX_MONITORS_PER_RUN],
  );

  let checked = 0;
  let alertsSent = 0;
  let alertsSkipped = 0;
  let errors = 0;

  for (const monitor of monitors) {
    const email = decryptSecret(encKey, monitor.email_encrypted);
    if (!email) {
      errors += 1;
      continue;
    }
    const prev = {
      leakcheckFound: monitor.last_leakcheck_found,
      hudsonAssociated: monitor.last_hudson_associated,
    };
    const next = await checkMonitoredEmail(email);
    checked += 1;

    let alertAt: string | null = null;
    if (isNewExposure(prev, next)) {
      const alert = await sendBreachAlertEmail(email, prev, next);
      if (alert.sent) {
        alertsSent += 1;
        alertAt = new Date().toISOString();
      } else {
        // New exposure found but no alert sent (Resend not configured or
        // the send failed). The status is still updated so the dashboard
        // shows it — the alert is retried only if exposure grows again.
        alertsSkipped += 1;
      }
    }

    await db.exec(
      `UPDATE monitors
       SET last_checked_at = now(),
           last_leakcheck_found = $1, last_hudson_associated = $2,
           last_alert_at = COALESCE($3::timestamptz, last_alert_at)
       WHERE id = $4`,
      [next.leakcheckFound, next.hudsonAssociated, alertAt, monitor.id],
    );

    if (checked < monitors.length) await sleep(GAP_BETWEEN_MONITORS_MS);
  }

  const pruned = await pruneExpiredCache();

  return NextResponse.json({
    checked,
    alertsSent,
    alertsSkipped,
    errors,
    prunedExpiredCacheRows: pruned,
  });
}
