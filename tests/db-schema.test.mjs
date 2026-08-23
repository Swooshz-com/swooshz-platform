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
  "workspaceMembershipApprovals",
  "invitations",
  "sessions",
  "csrfTokens",
  "authStates",
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
    "workspaceMembershipApprovalStatusEnum",
    "roleEnum",
    "invitationStatusEnum",
    "appStatusEnum",
    "entitlementStatusEnum",
    "csrfTokenPurposeEnum",
  ]) {
    assert.ok(schema[enumName], `expected ${enumName} to be exported`);
  }
});

test("database schema and migrations include pending workspace membership approvals", async () => {
  assert.ok(
    schema.workspaceMembershipApprovals,
    "expected workspaceMembershipApprovals table to be exported",
  );

  const migrationSql = await readMigrationSql();
  const approvalMigrationSql = migrationSql
    .split("--> statement-breakpoint")
    .filter((statement) =>
      /workspace_membership_approval/i.test(statement),
    )
    .join("\n");

  assert.match(migrationSql, /CREATE TYPE "public"\."workspace_membership_approval_status"/);
  assert.match(migrationSql, /CREATE TABLE "workspace_membership_approvals"/);
  assert.match(migrationSql, /"workspace_id" text NOT NULL/);
  assert.match(migrationSql, /"email" text NOT NULL/);
  assert.match(migrationSql, /"role" "role" NOT NULL/);
  assert.match(migrationSql, /"status" "workspace_membership_approval_status" NOT NULL/);
  assert.match(migrationSql, /"requested_by_user_id" text NOT NULL/);
  assert.match(migrationSql, /ALTER COLUMN "requested_by_user_id" DROP NOT NULL/);
  assert.match(migrationSql, /"accepted_user_id" text/);
  assert.match(migrationSql, /"revoked_by_user_id" text/);
  assert.match(migrationSql, /"workspace_membership_approvals_pending_unique"/);
  assert.match(migrationSql, /WHERE .*"status" = 'pending'/);
  assert.match(migrationSql, /"workspace_membership_approvals_email_status_idx"/);
  assert.match(migrationSql, /"workspace_membership_approvals_workspace_status_idx"/);
  assert.doesNotMatch(approvalMigrationSql, /approval_token|token_hash|expires_at/i);
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

test("database schema and migrations include auth_states without raw state or nonce storage", async () => {
  assert.ok(schema.authStates, "expected authStates table to be exported");

  const migrationSql = await readMigrationSql();

  assert.match(migrationSql, /CREATE TABLE "auth_states"/);
  assert.match(migrationSql, /"provider_key" text NOT NULL/);
  assert.match(migrationSql, /"state_hash" text NOT NULL/);
  assert.match(migrationSql, /"nonce_hash" text NOT NULL/);
  assert.match(migrationSql, /"redirect_uri" text NOT NULL/);
  assert.match(migrationSql, /"auth_states_provider_state_unique"/);
  assert.match(migrationSql, /"auth_states_expires_at_idx"/);
  assert.doesNotMatch(migrationSql, /raw_state|raw_nonce|state_value|nonce_value/i);
});

test("database migrations include one-way SQAG app-key data migration", async () => {
  const migrationSql = await readMigrationSql();
  const appKeyMigrationSql = migrationSql
    .split("--> statement-breakpoint")
    .filter((statement) => /app_sqag|app_entitlements|app_launch_tokens/i.test(statement))
    .join("\n");

  assert.match(appKeyMigrationSql, /INSERT INTO "apps"/);
  assert.match(appKeyMigrationSql, /'app_sqag'/);
  assert.match(appKeyMigrationSql, /'sqag'/);
  assert.match(appKeyMigrationSql, /UPDATE "app_entitlements"/);
  assert.match(appKeyMigrationSql, /UPDATE "app_launch_tokens"/);
  assert.match(migrationSql, /DELETE FROM "apps"\s+WHERE "key" = 'kqag'/);
});

test("role-collapse migration maps every current role column to the exact new vocabulary", async () => {
  const migration = await readFile(
    "drizzle/migrations/0010_admin_operator_viewer_role_collapse.sql",
    "utf8",
  );
  const mapping = "'owner' THEN 'admin'";
  assert.equal(
    migration.split(mapping).length - 1,
    3,
    "owner mapping must cover invitations, memberships, and approvals",
  );

  for (const tableName of [
    "invitations",
    "memberships",
    "workspace_membership_approvals",
  ]) {
    assert.match(
      migration,
      new RegExp('UPDATE "' + tableName + '"\\s+SET "role" = CASE "role"'),
    );
    assert.match(migration, new RegExp('ALTER TABLE "' + tableName + '"'));
  }

  assert.match(
    migration,
    /CREATE TYPE "public"\."role" AS ENUM\('admin', 'operator', 'viewer'\)/,
  );
  assert.doesNotMatch(migration, /UPDATE "audit_events"/i);
  assert.doesNotMatch(migration, /ALTER TABLE "audit_events"/i);
});

test("role-collapse migration fails closed on invalid bootstrap and admin state", async () => {
  const migration = await readFile(
    "drizzle/migrations/0010_admin_operator_viewer_role_collapse.sql",
    "utf8",
  );

  for (const phrase of [
    "invalid nullable requester state",
    "duplicate or missing first-admin bootstrap approval",
    "active zero-member workspace lacks first-admin bootstrap approval",
    "active workspace would have no active admin after role collapse",
  ]) {
    assert.match(migration, new RegExp(phrase));
  }

  assert.match(migration, /DO \$\$/);
  assert.match(migration, /RAISE EXCEPTION/);
  assert.match(migration, /statement-breakpoint/);
  assert.match(migration, /role_old/);
  assert.doesNotMatch(migration, /down migration/i);
});

test("role-collapse generated metadata follows the 0009 snapshot and appends journal entry 0010", async () => {
  const journal = JSON.parse(
    await readFile("drizzle/migrations/meta/_journal.json", "utf8"),
  );
  const previousSnapshot = JSON.parse(
    await readFile("drizzle/migrations/meta/0009_snapshot.json", "utf8"),
  );
  const currentSnapshot = JSON.parse(
    await readFile("drizzle/migrations/meta/0010_snapshot.json", "utf8"),
  );
  const entry = journal.entries.find(
    (candidate) => candidate.tag === "0010_admin_operator_viewer_role_collapse",
  );

  assert.equal(entry.idx, 9);
  assert.equal(entry.breakpoints, true);
  assert.equal(currentSnapshot.prevId, previousSnapshot.id);
  assert.deepEqual(currentSnapshot.enums["public.role"].values, [
    "admin",
    "operator",
    "viewer",
  ]);
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
