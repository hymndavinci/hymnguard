import { NextResponse } from "next/server";
import { checkEnumChunk, getEnumPlan } from "@/lib/email-enumeration";
import { normalizeEmail } from "@/lib/validate";

export const runtime = "nodejs";
export const maxDuration = 10;

// TEMPORARY VERIFICATION HARNESS — DELETE AFTER VERIFICATION.
//
// Runs enumeration chunks WITHOUT ownership verification, gated instead by
// a secret in the HARNESS_SECRET env var (header x-verify-secret). Exists
// only because the build VM cannot POST to third-party hosts (egress
// policy), so probe rules must be verified from the Vercel network.
// No fallback: if the env var is unset, every request gets 503.
// The secret value lives only in Vercel env vars and in the local driver
// script (~/workspace/hymnguard-build/email/run-harness.cjs) — never in
// this repo.
//
// POST { email, chunk? } — same chunk shape as the real enumerate route,
// plus raw response snippets (includeRaw) for rule-setting.
// GET — the enumeration plan.
function checkSecret(req: Request): NextResponse | null {
  const secret = process.env.HARNESS_SECRET;
  if (!secret) {
    return NextResponse.json({ error: "Harness not configured." }, { status: 503 });
  }
  if (req.headers.get("x-verify-secret") !== secret) {
    return NextResponse.json({ error: "Forbidden." }, { status: 403 });
  }
  return null;
}

export async function GET(req: Request) {
  const denied = checkSecret(req);
  if (denied) return denied;
  return NextResponse.json(getEnumPlan());
}

export async function POST(req: Request) {
  const denied = checkSecret(req);
  if (denied) return denied;

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const input = (body as { email?: unknown; chunk?: unknown } | null) ?? {};
  const email = normalizeEmail(input.email);
  const chunk =
    typeof input.chunk === "number" && Number.isInteger(input.chunk) && input.chunk >= 0
      ? input.chunk
      : 0;
  if (!email) {
    return NextResponse.json({ error: "Invalid email address." }, { status: 400 });
  }

  const plan = getEnumPlan();
  if (chunk >= plan.chunks) {
    return NextResponse.json(
      { error: `Chunk out of range (0–${plan.chunks - 1}).` },
      { status: 400 },
    );
  }

  const result = await checkEnumChunk(email, chunk, true);
  return NextResponse.json(result);
}
