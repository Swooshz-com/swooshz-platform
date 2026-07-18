import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationTag = "0007_remove_legacy_kqag_tables";
const migrationPath = `drizzle/migrations/${migrationTag}.sql`;
const snapshotPath = "drizzle/migrations/meta/0007_snapshot.json";
const legacyTables = [
  "kqag_object_artifacts",
  "kqag_quote_sessions",
  "kqag_pricing_references",
  "kqag_profiles",
];
const platformTables = [
  "app_entitlements",
  "app_launch_tokens",
  "apps",
  "audit_events",
  "auth_states",
  "csrf_tokens",
  "invitations",
  "memberships",
  "provider_identities",
  "sessions",
  "users",
  "workspace_membership_approvals",
  "workspaces",
];

test("current Platform schema contains no legacy kqag tables", async () => {
  const schemaSource = await readFile("src/db/schema.ts", "utf8");

  assert.doesNotMatch(schemaSource, /pgTable\(\s*["']kqag_/i);
  for (const tableName of legacyTables) {
    assert.doesNotMatch(schemaSource, new RegExp(tableName, "i"));
  }
});

test("legacy KQAG migration drops exactly the four approved tables without CASCADE", async () => {
  const migrationSql = await readFile(migrationPath, "utf8");
  const dropTargets = [
    ...migrationSql.matchAll(
      /DROP\s+TABLE\s+IF\s+EXISTS\s+"public"\."([^"]+)"\s*;/gi,
    ),
  ].map((match) => match[1]);

  assert.deepEqual(dropTargets, legacyTables);
  assert.doesNotMatch(migrationSql, /\bCASCADE\b/i);
  assert.equal(
    migrationSql
      .split("--> statement-breakpoint")
      .map((statement) => statement.trim())
      .filter(Boolean).length,
    legacyTables.length,
  );

  for (const tableName of platformTables) {
    assert.doesNotMatch(
      migrationSql,
      new RegExp(`DROP\\s+TABLE[^;]*["']${tableName}["']`, "i"),
    );
  }
});

test("migration journal and generated snapshot remain consistent", async () => {
  const journal = JSON.parse(
    await readFile("drizzle/migrations/meta/_journal.json", "utf8"),
  );
  const previousSnapshot = JSON.parse(
    await readFile("drizzle/migrations/meta/0006_snapshot.json", "utf8"),
  );
  const currentSnapshot = JSON.parse(await readFile(snapshotPath, "utf8"));
  const latestEntry = journal.entries.at(-1);

  assert.equal(journal.version, "7");
  assert.equal(journal.dialect, "postgresql");
  assert.deepEqual(
    journal.entries.map((entry) => entry.idx),
    journal.entries.map((_, index) => index),
  );
  assert.equal(latestEntry.idx, 7);
  assert.equal(latestEntry.tag, migrationTag);
  assert.equal(latestEntry.breakpoints, true);
  assert.equal(currentSnapshot.prevId, previousSnapshot.id);
  assert.deepEqual(currentSnapshot.tables, previousSnapshot.tables);
  assert.deepEqual(currentSnapshot.enums, previousSnapshot.enums);

  for (const tableName of legacyTables) {
    assert.equal(currentSnapshot.tables[`public.${tableName}`], undefined);
  }
});
