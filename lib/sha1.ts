// SHA-1 hashing in the browser via Web Crypto. The password is hashed
// locally; only the first 5 hex characters of the hash are ever sent to
// the server (Have I Been Pwned k-anonymity model).

export async function sha1Hex(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-1", data);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}
