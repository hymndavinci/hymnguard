import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import DossierClient from "@/components/dossier-client";
import { getCurrentUserFromSessionValue } from "@/lib/auth";
import { SESSION_COOKIE } from "@/lib/session";

// Dossier mode (Phase 7): a consolidated exposure report built from the
// user's OWN verified identifiers only. Redirects to /login without a
// valid session.
export default async function DossierPage() {
  const cookieStore = await cookies();
  const user = await getCurrentUserFromSessionValue(
    cookieStore.get(SESSION_COOKIE)?.value ?? null,
  );
  if (!user) redirect("/login");

  return (
    <main className="wrap">
      <section className="no-print pb-8 pt-14 sm:pt-16">
        <h1 className="text-2xl font-semibold tracking-tight">Dossier</h1>
        <p className="mt-2 max-w-2xl text-sm leading-relaxed text-gray-500">
          One consolidated exposure report for your own identifiers — emails,
          usernames, domains, and your current IP. A dossier only ever runs
          on identifiers you have proven you own.
        </p>
      </section>

      <DossierClient userEmail={user.email} />
    </main>
  );
}
