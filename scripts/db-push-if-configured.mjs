// Applies db/migrations/001_init.sql when DATABASE_URL is set; no-op
// otherwise. Run from the build script so a fresh database gets its
// tables on deploy. The migration is idempotent (CREATE TABLE/INDEX IF
// NOT EXISTS), so re-running it is safe.
//
// On failure the script exits non-zero and fails the build — a database
// that can't take the schema should block the deploy loudly, not ship a
// half-working app.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { Client } from "pg";

const url = process.env.DATABASE_URL;
if (!url) {
  console.log("[db-push] DATABASE_URL is not set — skipping schema setup.");
  process.exit(0);
}

const dir = path.dirname(fileURLToPath(import.meta.url));
const sql = readFileSync(
  path.join(dir, "..", "db", "migrations", "001_init.sql"),
  "utf8",
);

const client = new Client({ connectionString: url });
try {
  await client.connect();
  await client.query(sql);
  console.log("[db-push] Schema is up to date.");
} catch (err) {
  console.error(
    "[db-push] Failed to apply schema:",
    err instanceof Error ? err.message : err,
  );
  process.exit(1);
} finally {
  await client.end().catch(() => {});
}
