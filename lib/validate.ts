// Strict input validation for every check route.
// Each normalizer returns the cleaned value or null when invalid.
// Nothing here logs or stores the input.

const DOMAIN_RE =
  /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/;

export function normalizeDomain(input: unknown): string | null {
  if (typeof input !== "string") return null;
  let value = input.trim().toLowerCase();
  if (!value) return null;

  // Tolerate a pasted URL: strip scheme, path, query, fragment, port.
  value = value.replace(/^https?:\/\//, "");
  value = value.split("/")[0].split("?")[0].split("#")[0].split(":")[0];
  if (value.endsWith(".")) value = value.slice(0, -1);

  if (value === "localhost") return null;
  if (!DOMAIN_RE.test(value)) return null;
  return value;
}

export function normalizeEmail(input: unknown): string | null {
  if (typeof input !== "string") return null;
  const value = input.trim().toLowerCase();
  if (value.length < 3 || value.length > 254) return null;
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(value)) return null;
  return value;
}

export function normalizeUsername(input: unknown): string | null {
  if (typeof input !== "string") return null;
  let value = input.trim();
  if (value.startsWith("@")) value = value.slice(1);
  if (value.length < 1 || value.length > 50) return null;
  if (!/^[a-zA-Z0-9._-]+$/.test(value)) return null;
  if (
    value.startsWith(".") ||
    value.startsWith("-") ||
    value.endsWith(".") ||
    value.includes("..")
  ) {
    return null;
  }
  return value;
}

export function normalizePhone(input: unknown): string | null {
  if (typeof input !== "string") return null;
  const value = input.trim();
  if (!value.startsWith("+")) return null;
  if (value.length < 8 || value.length > 20) return null;
  if (!/^\+[0-9 ]+$/.test(value)) return null;
  return value.replace(/ /g, "");
}

export function isValidPasswordPrefix(input: unknown): input is string {
  return typeof input === "string" && /^[0-9a-fA-F]{5}$/.test(input);
}

export function isValidPasswordSuffix(input: unknown): input is string {
  return typeof input === "string" && /^[0-9a-fA-F]{35}$/.test(input);
}
