import { NextResponse } from "next/server";
import { checkEmailMx } from "@/lib/email-check";
import { fetchBreachesForEmail } from "@/lib/hibp";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";
import { normalizeEmail } from "@/lib/validate";

export const runtime = "nodejs";
export const maxDuration = 10;

// POST { email: "user@example.com" }
//
// Always runs the free checks (MX records, disposable-domain note).
// The HIBP breach lookup only runs when HIBP_API_KEY is configured; without
// a key the response says so explicitly instead of returning a fake result.
export async function POST(req: Request) {
  const ip = getClientIp(req);
  const limit = checkRateLimit(`check:email:${ip}`);
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

  const email = normalizeEmail((body as { email?: unknown } | null)?.email);
  if (!email) {
    return NextResponse.json(
      { error: "Invalid email address." },
      { status: 400 },
    );
  }

  const domain = email.split("@")[1];
  const apiKey = process.env.HIBP_API_KEY;

  try {
    const mxResult = await checkEmailMx(domain);

    if (!apiKey) {
      return NextResponse.json({
        email,
        domain,
        checkedAt: new Date().toISOString(),
        mx: mxResult.mx,
        mxOk: mxResult.mxOk,
        mxError: mxResult.mxError,
        disposable: mxResult.disposable,
        hibp: { available: false as const },
      });
    }

    const breaches = await fetchBreachesForEmail(email, apiKey);
    if (breaches.status === "rate_limited") {
      return NextResponse.json({
        email,
        domain,
        checkedAt: new Date().toISOString(),
        mx: mxResult.mx,
        mxOk: mxResult.mxOk,
        mxError: mxResult.mxError,
        disposable: mxResult.disposable,
        hibp: { available: true as const, rateLimited: true as const },
      });
    }

    return NextResponse.json({
      email,
      domain,
      checkedAt: new Date().toISOString(),
      mx: mxResult.mx,
      mxOk: mxResult.mxOk,
      mxError: mxResult.mxError,
      disposable: mxResult.disposable,
      hibp: {
        available: true as const,
        breaches: breaches.breaches,
      },
    });
  } catch {
    return NextResponse.json(
      { error: "The email check failed unexpectedly. Try again later." },
      { status: 502 },
    );
  }
}
