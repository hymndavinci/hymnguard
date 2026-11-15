import { NextResponse } from "next/server";
import { clearSessionCookieHeader } from "@/lib/session";

export const runtime = "nodejs";

// POST — clears the session cookie. Stateless sessions need no server
// state to revoke; the cookie is simply expired.
export async function POST() {
  const res = NextResponse.json({ ok: true });
  res.headers.set("Set-Cookie", clearSessionCookieHeader());
  return res;
}
