import { NextResponse } from "next/server";
import type { WalletCheckResult } from "@/lib/api-types";
import { getCurrentUser } from "@/lib/auth";
import { getCachedResult, setCachedResult } from "@/lib/check-cache";
import { resolveKeys } from "@/lib/keys";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";
import { normalizeWalletAddress } from "@/lib/wallet-address";
import { checkWallet } from "@/lib/wallet-check";

export const runtime = "nodejs";
export const maxDuration = 15;

// POST { address: "0x..." }
//
// Crypto wallet exposure: native balance + first/last activity +
// transaction count, on Ethereum and BNB Chain, via the Etherscan v2
// unified API (one key covers both chains). Without an Etherscan key
// (server env or BYOK) the check has no source at all and returns
// 503 needsKey — never an empty "clean" result.
export async function POST(req: Request) {
  const ip = getClientIp(req);
  const limit = checkRateLimit(`check:wallet:${ip}`);
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

  const address = normalizeWalletAddress(
    (body as { address?: unknown } | null)?.address,
  );
  if (!address) {
    return NextResponse.json(
      {
        error:
          "Invalid address. Enter an Ethereum-style address (0x + 40 hex characters); mixed-case addresses must pass the EIP-55 checksum.",
      },
      { status: 400 },
    );
  }

  try {
    // BYOK: a logged-in user's own keys win over the server env keys.
    const user = await getCurrentUser(req);
    const keys = await resolveKeys(user?.id ?? null);

    if (!keys.etherscan) {
      return NextResponse.json(
        {
          error:
            "The wallet check needs an Etherscan API key. Add one in your dashboard (bring your own key) or ask the operator to set ETHERSCAN_API_KEY.",
          needsKey: true,
          provider: "etherscan",
        },
        { status: 503 },
      );
    }

    // Route-level cache (bypassed entirely when a BYOK key is in play).
    if (!keys.usedByok) {
      const cached = await getCachedResult<WalletCheckResult>(
        "wallet",
        address,
      );
      if (cached) {
        return NextResponse.json(cached, { headers: { "X-Cache": "HIT" } });
      }
    }

    const result = await checkWallet(address, keys.etherscan);
    if (!keys.usedByok) {
      await setCachedResult("wallet", address, result);
      return NextResponse.json(result, { headers: { "X-Cache": "MISS" } });
    }
    return NextResponse.json(result);
  } catch {
    return NextResponse.json(
      { error: "The wallet check failed unexpectedly. Try again later." },
      { status: 502 },
    );
  }
}
