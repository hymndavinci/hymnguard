import { NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { DB_NOT_CONFIGURED, getDb } from "@/lib/db";
import {
  finalizeDossierRun,
  getDossierRun,
  runIdentifierValue,
  saveDossierSection,
  toPublicRun,
} from "@/lib/dossier";
import {
  runDomainSection,
  runEmailSection,
  runIpSection,
  runUsernameSection,
} from "@/lib/dossier-checks";
import { computeDossierReport, type DossierSection } from "@/lib/dossier-score";
import { resolveKeys } from "@/lib/keys";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";

export const runtime = "nodejs";
export const maxDuration = 10;

// One identifier's check takes up to ~9s of the 10s invocation budget; a
// section that runs longer is recorded as an honest timeout, not a hang.
const SECTION_TIMEOUT_MS = 9000;

// POST { runId, index, token? } — runs ONE identifier's section of a
// dossier run (created by /api/dossier/build) and stores it. `token` is an
// optional Phase 3 verification token for email sections: when present and
// valid it also runs the 7-probe account enumeration for that email.
// Idempotent: asking for an already-run section returns the stored result.
// When the last section lands, the report (score, findings, remediations,
// cross-references) is computed and the run is finalized.
export async function POST(req: Request) {
  const ip = getClientIp(req);
  const limit = checkRateLimit(`dossier:build:chunk:${ip}`);
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
    runId?: unknown;
    index?: unknown;
    token?: unknown;
  } | null) ?? {};
  const runId = typeof input.runId === "string" ? input.runId : "";
  const index =
    typeof input.index === "number" && Number.isInteger(input.index)
      ? input.index
      : -1;
  const token = typeof input.token === "string" ? input.token : undefined;

  const run = runId ? await getDossierRun(db, user.id, runId) : null;
  if (!run) {
    return NextResponse.json(
      { error: "Dossier run not found." },
      { status: 404 },
    );
  }
  if (index < 0 || index >= run.identifiers.length) {
    return NextResponse.json(
      { error: "Section index out of range." },
      { status: 400 },
    );
  }

  const existing = run.sections[String(index)];
  if (existing) {
    return NextResponse.json({
      section: existing,
      progress: progressOf(run),
      complete: run.status !== "running",
      ...(run.report ? { report: run.report } : {}),
    });
  }
  if (run.status !== "running") {
    return NextResponse.json(
      { error: "This dossier run is already finished." },
      { status: 409 },
    );
  }

  const identifier = run.identifiers[index];
  const value = runIdentifierValue(identifier);
  let section: DossierSection;

  if (value === null) {
    section = {
      type: identifier.type,
      display: identifier.display,
      status: "error",
      checkedAt: new Date().toISOString(),
      summary: "Could not read this identifier",
      result: null,
      error:
        "The stored identifier could not be decrypted (ENCRYPTION_KEY may have changed). Remove and re-verify it.",
    };
  } else {
    const keys = await resolveKeys(user.id);
    const runner =
      identifier.type === "email"
        ? runEmailSection(value, keys, token)
        : identifier.type === "username"
          ? runUsernameSection(value)
          : identifier.type === "domain"
            ? runDomainSection(value, keys)
            : runIpSection(value, keys);
    try {
      section = await Promise.race([
        runner,
        new Promise<DossierSection>((_resolve, reject) =>
          setTimeout(
            () => reject(new Error("section-timeout")),
            SECTION_TIMEOUT_MS,
          ),
        ),
      ]);
    } catch (err) {
      const timedOut = err instanceof Error && err.message === "section-timeout";
      section = {
        type: identifier.type,
        display: identifier.display,
        status: "error",
        checkedAt: new Date().toISOString(),
        summary: timedOut ? "Timed out" : "Check failed",
        result: null,
        error: timedOut
          ? "The check took longer than 9 seconds. Re-run the dossier to try again."
          : "The check failed unexpectedly. Re-run the dossier to try again.",
      };
    }
  }

  await saveDossierSection(db, run.id, index, section);

  // Re-read: concurrent chunks may have landed other sections meanwhile.
  const updated = await getDossierRun(db, user.id, run.id);
  if (!updated) {
    return NextResponse.json({
      section,
      progress: progressOf(run),
      complete: false,
    });
  }

  const allDone = updated.identifiers.every(
    (_, i) => Boolean(updated.sections[String(i)]),
  );
  if (allDone && updated.status === "running") {
    const sections = updated.identifiers.map(
      (_, i) => updated.sections[String(i)],
    );
    // Raw values are needed to cross-reference (e.g. a username against an
    // email's local-part); only display strings land in the stored report.
    const rawValues = updated.identifiers.map((entry) => ({
      type: entry.type,
      value: runIdentifierValue(entry) ?? entry.display,
    }));
    const report = computeDossierReport(sections, rawValues);
    const status = sections.some((s) => s.status === "error")
      ? "partial"
      : "complete";
    await finalizeDossierRun(db, updated.id, report, status);
    return NextResponse.json({
      section,
      progress: progressOf(updated),
      complete: true,
      report,
      run: toPublicRun({ ...updated, report, score: report.score, status }),
    });
  }

  return NextResponse.json({
    section,
    progress: progressOf(updated),
    complete: updated.status !== "running",
    ...(updated.report ? { report: updated.report } : {}),
  });
}

function progressOf(run: {
  identifiers: unknown[];
  sections: Record<string, unknown>;
}): { done: number; total: number } {
  const total = run.identifiers.length;
  let done = 0;
  for (let i = 0; i < total; i++) {
    if (run.sections[String(i)]) done += 1;
  }
  return { done, total };
}
