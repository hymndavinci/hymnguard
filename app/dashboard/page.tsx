import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import DashboardClient from "@/components/dashboard-client";
import { getCurrentUserFromSessionValue } from "@/lib/auth";
import { SESSION_COOKIE } from "@/lib/session";

// Signed-in dashboard: saved history, breach monitoring, and BYOK keys.
// Redirects to /login without a valid session.
export default async function DashboardPage() {
  const cookieStore = await cookies();
  const user = await getCurrentUserFromSessionValue(
    cookieStore.get(SESSION_COOKIE)?.value ?? null,
  );
  if (!user) redirect("/login");

  return (
    <main className="wrap">
      <section className="pb-8 pt-14 sm:pt-16">
        <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
        <p className="mt-2 text-sm leading-relaxed text-gray-500">
          Signed in as <span className="font-mono">{user.email}</span>
          {user.emailVerified ? null : (
            <> · email not verified (monitoring your own address needs a verified email or a code)</>
          )}
        </p>
      </section>

      <DashboardClient userEmail={user.email} />
    </main>
  );
}
