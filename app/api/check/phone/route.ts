import { NextResponse } from "next/server";
import type { PhoneCheckResult } from "@/lib/api-types";
import { getCurrentUser } from "@/lib/auth";
import { getCachedResult, setCachedResult } from "@/lib/check-cache";
import { resolveKeys } from "@/lib/keys";
import { checkPhone } from "@/lib/phone-check";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";
import { normalizePhone } from "@/lib/validate";

export const runtime = "nodejs";
export const maxDuration = 10;

// POST { phone: "+6281234567890" }
// Format / country / validity + ID operator prefix + carrier/risk (IPQS,
// keyed) + community spam reports (GetContact, Should I Answer). No
// breach lookup exists for phone numbers from a free, legitimate source.
export async function POST(req: Request) {
  const ip = getClientIp(req);
  const limit = checkRateLimit(`check:phone:${ip}`);
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

  const phone = normalizePhone((body as { phone?: unknown } | null)?.phone);
  if (!phone) {
    return NextResponse.json(
      { error: "Invalid phone number. Use international format, e.g. +6281234567890." },
      { status: 400 },
    );
  }

  // BYOK: a logged-in user's own keys win over the server env keys.
  const user = await getCurrentUser(req);
  const keys = await resolveKeys(user?.id ?? null);

  // Route-level cache (bypassed entirely when a BYOK key is in play).
  if (!keys.usedByok) {
    const cached = await getCachedResult<PhoneCheckResult>("phone", phone);
    if (cached) {
      return NextResponse.json(cached, { headers: { "X-Cache": "HIT" } });
    }
  }

  const result = await checkPhone(phone, { ipqsKey: keys.ipqs });
  if (!keys.usedByok) {
    await setCachedResult("phone", phone, result);
    return NextResponse.json(result, { headers: { "X-Cache": "MISS" } });
  }
  return NextResponse.json(result);
}
