// Breach monitoring: re-check a watched email against LeakCheck + Hudson
// Rock, compare with the previous status, and alert when new exposure
// appears. Used by /api/cron/monitor (daily Vercel Cron).
//
// Only counts/booleans are compared and stored — breach contents are never
// requested, stored, or emailed. Alert emails name breach sources (metadata
// the UI already shows) and link back to the dashboard.

import { fetchHudsonRock, fetchLeakCheck } from "./email-breach";
import { sendEmail } from "./resend";

export interface MonitorStatus {
  /** LeakCheck record count, or null when the source errored. */
  leakcheckFound: number | null;
  /** Hudson Rock association, or null when the source errored. */
  hudsonAssociated: boolean | null;
}

export async function checkMonitoredEmail(email: string): Promise<MonitorStatus> {
  const [leakcheck, hudsonrock] = await Promise.all([
    fetchLeakCheck(email),
    fetchHudsonRock(email),
  ]);
  return {
    leakcheckFound:
      leakcheck.status === "ok"
        ? leakcheck.found
        : leakcheck.status === "not_found"
          ? 0
          : null,
    hudsonAssociated:
      hudsonrock.status === "ok" ? hudsonrock.associated : null,
  };
}

/** True when the new status shows exposure the previous status didn't:
 *  LeakCheck's record count grew, or Hudson Rock newly associates the
 *  email with a stealer infection. Unknown (errored) sources never count
 *  as new exposure. */
export function isNewExposure(
  prev: { leakcheckFound: number | null; hudsonAssociated: boolean | null },
  next: MonitorStatus,
): boolean {
  if (
    prev.leakcheckFound !== null &&
    next.leakcheckFound !== null &&
    next.leakcheckFound > prev.leakcheckFound
  ) {
    return true;
  }
  if (prev.hudsonAssociated === false && next.hudsonAssociated === true) {
    return true;
  }
  return false;
}

export interface BreachAlertResult {
  sent: boolean;
  /** "not_configured" when Resend isn't set up; otherwise the send error. */
  reason?: string;
}

export async function sendBreachAlertEmail(
  email: string,
  prev: { leakcheckFound: number | null; hudsonAssociated: boolean | null },
  next: MonitorStatus,
): Promise<BreachAlertResult> {
  const apiKey = process.env.RESEND_API_KEY;
  const from = process.env.RESEND_FROM;
  if (!apiKey || !from) return { sent: false, reason: "not_configured" };

  const changes: string[] = [];
  if (
    prev.leakcheckFound !== null &&
    next.leakcheckFound !== null &&
    next.leakcheckFound > prev.leakcheckFound
  ) {
    changes.push(
      `LeakCheck now shows ${next.leakcheckFound} breach records for this address (was ${prev.leakcheckFound}).`,
    );
  }
  if (prev.hudsonAssociated === false && next.hudsonAssociated === true) {
    changes.push(
      `Hudson Rock now associates this address with a computer infected by info-stealing malware.`,
    );
  }
  if (changes.length === 0) return { sent: false, reason: "no_changes" };

  const dashboardUrl = "https://hymnguard.vercel.app/dashboard";
  const result = await sendEmail(
    {
      to: email,
      subject: "HymnGuard: new exposure found for a watched email",
      text:
        `HymnGuard detected new exposure for ${email}:\n\n` +
        changes.map((c) => `- ${c}`).join("\n") +
        `\n\nReview the details and recommended steps in your dashboard: ${dashboardUrl}\n\n` +
        `You are receiving this because you watch this address in HymnGuard. Remove the monitor in your dashboard to stop these alerts.`,
      html:
        `<p>HymnGuard detected new exposure for <strong>${email}</strong>:</p>` +
        `<ul>${changes.map((c) => `<li>${c}</li>`).join("")}</ul>` +
        `<p><a href="${dashboardUrl}">Review it in your dashboard</a>.</p>` +
        `<p>You are receiving this because you watch this address in HymnGuard. Remove the monitor in your dashboard to stop these alerts.</p>`,
    },
    apiKey,
    from,
  );
  return result.ok
    ? { sent: true }
    : { sent: false, reason: result.error ?? "send_failed" };
}
