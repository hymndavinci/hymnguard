import { NextResponse } from "next/server";
import {
  checkEnumChunk,
  getEnumPlan,
} from "@/lib/email-enumeration";
import { verifyVerificationToken } from "@/lib/email-verify";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";
import { normalizeEmail } from "@/lib/validate";

export const runtime = "nodejs";
export const maxDuration = 10;

// GET — the enumeration plan ({ total, chunkSize, chunks }).
// POST { email, verificationToken, chunk? } — one chunk of probes.
//
// GATED: every chunk request must carry a valid verification token proving
// the requester owns the email (issued by /verify after a code sent to the
// address). Without it, no probe runs — ever.
export async function GET() {
  return NextResponse.json(getEnumPlan());
}

export async function POST(req: Request) {
  const ip = getClientIp(req);
  const limit = checkRateLimit(`enumerate:${ip}`);
  if (!limit.allowed) {
    return NextResponse.json(
      { error: "Rate limit exceeded. Try again shortly." },
      {
        status: 429,
        headers: { "Retry-After": String(limit.retryAfterSec) },
      },
    );
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const input = (body as {
    email?: unknown;
    verificationToken?: unknown;
    chunk?: unknown;
  } | null) ?? {};
  const email = normalizeEmail(input.email);
  const verificationToken =
    typeof input.verificationToken === "string" ? input.verificationToken : "";
  const chunk =
    typeof input.chunk === "number" && Number.isInteger(input.chunk) && input.chunk >= 0
      ? input.chunk
      : 0;

  if (!email || !verificationToken) {
    return NextResponse.json(
      { error: "Email and verification token are required." },
      { status: 400 },
    );
  }

  const secret = process.env.VERIFY_SECRET;
  if (!secret || !verifyVerificationToken(secret, email, verificationToken)) {
    return NextResponse.json(
      { error: "Ownership verification required. Verify this email first." },
      { status: 401 },
    );
  }

  const plan = getEnumPlan();
  if (chunk >= plan.chunks) {
    return NextResponse.json(
      { error: `Chunk out of range (0–${plan.chunks - 1}).` },
      { status: 400 },
    );
  }

  const result = await checkEnumChunk(email, chunk);
  return NextResponse.json(result);
}
