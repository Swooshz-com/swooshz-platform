import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import * as schema from "../dist/db/schema.js";

const expectedTableExports = [
  "users",
  "providerIdentities",
  "workspaces",
  "memberships",
  "invitations",
  "sessions",
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
  ]) {
    assert.ok(schema[enumName], `expected ${enumName} to be exported`);
  }
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
