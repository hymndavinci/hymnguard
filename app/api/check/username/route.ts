import { NextResponse } from "next/server";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";
import { checkUsername } from "@/lib/username-check";
import { USERNAME_SITES } from "@/lib/username-sites";
import { normalizeUsername } from "@/lib/validate";

export const runtime = "nodejs";
export const maxDuration = 10;

/**
 * The full username check covers hundreds of sites, so it runs in chunks:
 * the client fetches the chunk plan from GET, then POSTs one chunk at a
 * time (in parallel) and aggregates the results. Each chunk stays well
 * inside the function timeout, and results stream in progressively.
 */
export const USERNAME_CHUNK_SIZE = 150;

export function usernameChunkPlan() {
  return {
    total: USERNAME_SITES.length,
    chunkSize: USERNAME_CHUNK_SIZE,
    chunks: Math.ceil(USERNAME_SITES.length / USERNAME_CHUNK_SIZE),
  };
}

// GET -> { total, chunkSize, chunks }. Static metadata, no outbound calls,
// so it is not rate-limited.
export async function GET() {
  return NextResponse.json(usernameChunkPlan());
}

// POST { username: "someone", chunk?: number, chunkSize?: number }
// Checks one slice of the site list and returns that slice's results plus
// the chunk plan, so the client can aggregate across chunks.
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

  const username = normalizeUsername(
    (body as { username?: unknown } | null)?.username,
  );
  if (!username) {
    return NextResponse.json(
      {
        error:
          "Invalid username. Use 1–50 characters: letters, numbers, dots, underscores, hyphens.",
      },
      { status: 400 },
    );
  }

  const plan = usernameChunkPlan();
  const rawChunk = (body as { chunk?: unknown } | null)?.chunk;
  const rawChunkSize = (body as { chunkSize?: unknown } | null)?.chunkSize;
  const chunk =
    typeof rawChunk === "number" && Number.isInteger(rawChunk) ? rawChunk : 0;
  const chunkSize =
    typeof rawChunkSize === "number" &&
    Number.isInteger(rawChunkSize) &&
    rawChunkSize >= 1
      ? Math.min(rawChunkSize, USERNAME_CHUNK_SIZE)
      : USERNAME_CHUNK_SIZE;
  const chunks = Math.ceil(plan.total / chunkSize);
  if (chunk < 0 || chunk >= chunks) {
    return NextResponse.json(
      { error: `Invalid chunk. This check has ${chunks} chunks (0–${chunks - 1}).` },
      { status: 400 },
    );
  }

  const sites = USERNAME_SITES.slice(chunk * chunkSize, (chunk + 1) * chunkSize);
  try {
    const result = await checkUsername(username, sites);
    return NextResponse.json({ ...result, chunk, chunkSize, total: plan.total, chunks });
  } catch {
    return NextResponse.json(
      { error: "The username check failed unexpectedly. Try again later." },
      { status: 502 },
    );
  }
}
