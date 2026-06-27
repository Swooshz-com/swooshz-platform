import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import * as schema from "../dist/db/schema.js";

const expectedTableExports = [
  "users",
  "providerIdentities",
  "workspaces",
  "memberships",
  "invitations",
  "sessions",
  "csrfTokens",
  "auditEvents",
  "apps",
  "appEntitlements",
];

test("database schema exports the platform-owned tables", () => {
  for (const tableName of expectedTableExports) {
    assert.ok(schema[tableName], `expected ${tableName} to be exported`);
  }
});

test("database schema exports status enums used by persistence records", () => {
  for (const enumName of [
    "userStatusEnum",
    "workspaceStatusEnum",
    "membershipStatusEnum",
    "roleEnum",
    "invitationStatusEnum",
    "appStatusEnum",
    "entitlementStatusEnum",
    "csrfTokenPurposeEnum",
  ]) {
    assert.ok(schema[enumName], `expected ${enumName} to be exported`);
  }
});

test("database schema and migrations include csrf_tokens without raw token storage", async () => {
  assert.ok(schema.csrfTokens, "expected csrfTokens table to be exported");

  const migrationSql = await readMigrationSql();

  assert.match(migrationSql, /CREATE TYPE "public"\."csrf_token_purpose"/);
  assert.match(migrationSql, /CREATE TABLE "csrf_tokens"/);
  assert.match(migrationSql, /"token_hash" text NOT NULL/);
  assert.match(migrationSql, /"session_id" text NOT NULL/);
  assert.match(migrationSql, /"purpose" "csrf_token_purpose" NOT NULL/);
  assert.match(migrationSql, /"csrf_tokens_session_id_idx"/);
  assert.match(migrationSql, /"csrf_tokens_session_hash_purpose_unique"/);
  assert.match(migrationSql, /FOREIGN KEY \("session_id"\) REFERENCES "public"\."sessions"\("id"\)/);
  assert.doesNotMatch(migrationSql, /raw_token|csrf_token_value|token_value/i);
});

test("pure domain modules do not import database implementation details", async () => {
  const domainFiles = [
    "src/accounts/types.ts",
    "src/accounts/normalization.ts",
    "src/apps/types.ts",
    "src/access/decide-app-access.ts",
  ];

  for (const filePath of domainFiles) {
    const contents = await readFile(filePath, "utf8");

    assert.doesNotMatch(contents, /drizzle-orm/);
    assert.doesNotMatch(contents, /src\/db|\.{1,2}\/db|\.{1,2}\/\.{1,2}\/db/);
    assert.doesNotMatch(contents, /schema\.js|schema\.ts/);
  }
});

async function readMigrationSql() {
  const migrationDirectory = "drizzle/migrations";
  const entries = await readdir(migrationDirectory, { withFileTypes: true });
  const sqlFiles = entries
    .filter((entry) => entry.isFile() && entry.name.endsWith(".sql"))
    .map((entry) => join(migrationDirectory, entry.name));
  const contents = await Promise.all(
    sqlFiles.map((filePath) => readFile(filePath, "utf8")),
  );

  return contents.join("\n");
}
