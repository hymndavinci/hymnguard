// Applies every db/migrations/*.sql file in filename order when
// DATABASE_URL is set; no-op otherwise. Run from the build script so a
// fresh database gets its tables on deploy. Migrations are idempotent
// (CREATE TABLE/INDEX IF NOT EXISTS), so re-running them is safe.
//
// On failure the script exits non-zero and fails the build — a database
// that can't take the schema should block the deploy loudly, not ship a
// half-working app.

import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { Client } from "pg";

const url = process.env.DATABASE_URL;
if (!url) {
  console.log("[db-push] DATABASE_URL is not set — skipping schema setup.");
  process.exit(0);
}

const dir = path.dirname(fileURLToPath(import.meta.url));
const migrationsDir = path.join(dir, "..", "db", "migrations");
const files = readdirSync(migrationsDir)
  .filter((f) => f.endsWith(".sql"))
  .sort();

if (files.length === 0) {
  console.log("[db-push] No migration files found — skipping.");
  process.exit(0);
}

const client = new Client({ connectionString: url });
try {
  await client.connect();
  for (const file of files) {
    const sql = readFileSync(path.join(migrationsDir, file), "utf8");
    await client.query(sql);
    console.log(`[db-push] Applied ${file}.`);
  }
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
