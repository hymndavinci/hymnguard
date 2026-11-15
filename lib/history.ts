// Client-side history, stored in localStorage only. Nothing is sent to the
// server. Password checks store no input at all — only the summary.

export type CheckType = "email" | "username" | "domain" | "phone" | "password";

export interface HistoryEntry {
  id: string;
  type: CheckType;
  /** Empty for password checks: the password is never stored. */
  input: string;
  summary: string;
  at: number;
}

const STORAGE_KEY = "hymnguard:history:v1";
const MAX_ENTRIES = 20;

function isValidEntry(value: unknown): value is HistoryEntry {
  if (typeof value !== "object" || value === null) return false;
  const entry = value as Record<string, unknown>;
  return (
    typeof entry.id === "string" &&
    typeof entry.type === "string" &&
    ["email", "username", "domain", "phone", "password"].includes(entry.type) &&
    typeof entry.input === "string" &&
    typeof entry.summary === "string" &&
    typeof entry.at === "number"
  );
}

export function loadHistory(): HistoryEntry[] {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(isValidEntry).slice(0, MAX_ENTRIES);
  } catch {
    return [];
  }
}

export function saveHistory(entries: HistoryEntry[]): void {
  try {
    window.localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify(entries.slice(0, MAX_ENTRIES)),
    );
  } catch {
    // Storage unavailable (private mode, quota) — history is best-effort.
  }
}

export function addHistoryEntry(
  entry: Omit<HistoryEntry, "id" | "at">,
): HistoryEntry[] {
  const next: HistoryEntry[] = [
    {
      ...entry,
      id:
        typeof crypto !== "undefined" && "randomUUID" in crypto
          ? crypto.randomUUID()
          : `${Date.now()}-${Math.random().toString(36).slice(2)}`,
      at: Date.now(),
    },
    ...loadHistory(),
  ].slice(0, MAX_ENTRIES);
  saveHistory(next);
  return next;
}

export function clearHistory(): void {
  try {
    window.localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Ignore.
  }
}
