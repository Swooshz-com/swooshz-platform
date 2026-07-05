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
