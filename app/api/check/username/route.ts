import { NextResponse } from "next/server";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";
import { checkUsername } from "@/lib/username-check";
import { normalizeUsername } from "@/lib/validate";

export const runtime = "nodejs";
export const maxDuration = 10;

// POST { username: "someone" }
export async function POST(req: Request) {
  const ip = getClientIp(req);
  const limit = checkRateLimit(`check:username:${ip}`);
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

  const username = normalizeUsername((body as { username?: unknown } | null)?.username);
  if (!username) {
    return NextResponse.json(
      {
        error:
          "Invalid username. Use 1–50 characters: letters, numbers, dots, underscores, hyphens.",
      },
      { status: 400 },
    );
  }

  try {
    const result = await checkUsername(username);
    return NextResponse.json(result);
  } catch {
    return NextResponse.json(
      { error: "The username check failed unexpectedly. Try again later." },
      { status: 502 },
    );
  }
}
