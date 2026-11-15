// Crypto wallet exposure: native balance + first/last activity +
// transaction count for an address, on Ethereum and BNB Chain.
//
// One key covers both chains: Etherscan API v2 is unified
// (https://api.etherscan.io/v2/api, `chainid` selects the chain; the old
// per-chain v1 endpoints were deprecated in August 2025). Free tier:
// 5 calls/second. Implemented from the public docs; not yet tested live
// — no key has been available.
//
// Only public chain data is shown: balances and transaction metadata
// (hash, timestamp, counterparties, value). No token holdings, no
// identity data, nothing that links the address to a person.

const API_TIMEOUT_MS = 10000;
const TX_PAGE_SIZE = 1000;

export interface WalletTx {
  hash: string;
  timeStamp: number;
  from: string;
  to: string;
  /** Value in wei, as a decimal string. */
  valueWei: string;
}

export interface WalletChainResult {
  ok: boolean;
  error?: string;
  rateLimited?: boolean;
  /** Native balance in wei, as a decimal string. */
  balanceWei?: string;
  /** Human-readable balance (e.g. "1.2345 ETH"). */
  balanceDisplay?: string;
  /** Transactions seen (capped at TX_PAGE_SIZE). */
  txCount?: number;
  /** True when the address has more than TX_PAGE_SIZE transactions. */
  txCountCapped?: boolean;
  firstTx?: WalletTx;
  lastTx?: WalletTx;
}

export interface WalletCheckResult {
  address: string;
  checkedAt: string;
  /** Ethereum (chainid 1). */
  ethereum: WalletChainResult;
  /** BNB Chain (chainid 56). */
  bsc: WalletChainResult;
}

const WEI_PER_COIN = 10n ** 18n;

function formatCoin(wei: string, symbol: string): string {
  try {
    const value = BigInt(wei);
    const whole = value / WEI_PER_COIN;
    const frac = value % WEI_PER_COIN;
    if (frac === 0n) return `${whole.toString()} ${symbol}`;
    const fracStr = frac.toString().padStart(18, "0").slice(0, 6);
    const trimmed = fracStr.replace(/0+$/, "");
    return trimmed
      ? `${whole.toString()}.${trimmed} ${symbol}`
      : `${whole.toString()} ${symbol}`;
  } catch {
    return `${wei} wei`;
  }
}

interface EtherscanEnvelope {
  status?: string;
  message?: string;
  result?: unknown;
}

async function etherscanGet(
  params: Record<string, string>,
  apiKey: string,
): Promise<EtherscanEnvelope> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), API_TIMEOUT_MS);
  try {
    const query = new URLSearchParams({ ...params, apikey: apiKey });
    const res = await fetch(`https://api.etherscan.io/v2/api?${query}`, {
      signal: controller.signal,
    });
    if (!res.ok) {
      throw new Error(`Etherscan responded with HTTP ${res.status}`);
    }
    return (await res.json()) as EtherscanEnvelope;
  } finally {
    clearTimeout(timer);
  }
}

function parseTx(row: Record<string, unknown>): WalletTx | null {
  const hash = typeof row.hash === "string" ? row.hash : "";
  const from = typeof row.from === "string" ? row.from : "";
  const to = typeof row.to === "string" ? row.to : "";
  const valueWei = typeof row.value === "string" ? row.value : "";
  const timeStamp = Number(row.timeStamp);
  if (!hash || !from || !valueWei || !Number.isFinite(timeStamp)) return null;
  return { hash, timeStamp, from, to, valueWei };
}

async function checkChain(
  chainId: string,
  symbol: string,
  address: string,
  apiKey: string,
): Promise<WalletChainResult> {
  try {
    const [balanceRes, txRes] = await Promise.all([
      etherscanGet(
        {
          chainid: chainId,
          module: "account",
          action: "balance",
          address,
          tag: "latest",
        },
        apiKey,
      ),
      etherscanGet(
        {
          chainid: chainId,
          module: "account",
          action: "txlist",
          address,
          startblock: "0",
          endblock: "99999999",
          page: "1",
          offset: String(TX_PAGE_SIZE),
          sort: "asc",
        },
        apiKey,
      ),
    ]);

    // Etherscan reports key problems in the envelope, not HTTP status.
    for (const envelope of [balanceRes, txRes]) {
      const result = envelope.result;
      if (
        typeof result === "string" &&
        /invalid api key|api key.*required|rate limit/i.test(result)
      ) {
        const rateLimited = /rate limit/i.test(result);
        return {
          ok: false,
          error: rateLimited
            ? "Etherscan rate limit reached."
            : "Etherscan rejected the API key.",
          rateLimited,
        };
      }
    }

    const balanceWei =
      typeof balanceRes.result === "string" ? balanceRes.result : undefined;

    // status "0" + "No transactions found" is a real answer: empty wallet.
    const txRows =
      txRes.status === "1" && Array.isArray(txRes.result)
        ? (txRes.result as Record<string, unknown>[])
        : [];
    const txs = txRows
      .map(parseTx)
      .filter((tx): tx is WalletTx => tx !== null);
    return {
      ok: true,
      balanceWei,
      balanceDisplay:
        balanceWei !== undefined ? formatCoin(balanceWei, symbol) : undefined,
      txCount: txs.length,
      txCountCapped: txs.length >= TX_PAGE_SIZE,
      firstTx: txs[0],
      lastTx: txs.length > 0 ? txs[txs.length - 1] : undefined,
    };
  } catch (err) {
    return {
      ok: false,
      error:
        err instanceof Error && err.name === "AbortError"
          ? "Etherscan request timed out"
          : err instanceof Error
            ? err.message
            : "Could not reach Etherscan",
    };
  }
}

export async function checkWallet(
  address: string,
  apiKey: string,
): Promise<WalletCheckResult> {
  const [ethereum, bsc] = await Promise.all([
    checkChain("1", "ETH", address, apiKey),
    checkChain("56", "BNB", address, apiKey),
  ]);
  return {
    address,
    checkedAt: new Date().toISOString(),
    ethereum,
    bsc,
  };
}
