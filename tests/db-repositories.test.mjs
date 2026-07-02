import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import * as schema from "../dist/db/schema.js";
import {
  mapAppEntitlementRow,
  mapAppRow,
  mapAuditEventRow,
  mapInvitationRow,
  mapMembershipRow,
  mapProviderIdentityRow,
  mapSessionRow,
  mapUserRow,
  mapWorkspaceRow,
} from "../dist/db/mappers.js";
import { createDrizzlePlatformRepositories } from "../dist/db/repositories.js";

const createdAt = new Date("2026-06-26T00:00:00.000Z");
const updatedAt = new Date("2026-06-26T01:00:00.000Z");
const expiresAt = new Date("2026-06-27T00:00:00.000Z");
const acceptedAt = new Date("2026-06-26T02:00:00.000Z");

const userRow = {
  id: "user_owner_example",
  email: "owner@example.com",
  displayName: "Owner Example",
  status: "active",
  createdAt,
  updatedAt,
  lastLoginAt: null,
};

const providerIdentityRow = {
  id: "provider_identity_owner_example",
  userId: userRow.id,
  providerKey: "example_oidc",
  providerSubject: "provider-subject-owner-example",
  createdAt,
  updatedAt,
};

const workspaceRow = {
  id: "workspace_koncept_images",
  slug: "koncept-images-pte-ltd",
  displayName: "Koncept Images Pte Ltd",
  status: "active",
  createdAt,
  updatedAt,
};

const membershipRow = {
  id: "membership_owner_example",
  workspaceId: workspaceRow.id,
  userId: userRow.id,
  role: "owner",
  status: "active",
  createdAt,
  updatedAt,
};

const invitationRow = {
  id: "invitation_owner_example",
  workspaceId: workspaceRow.id,
  email: "invitee@example.com",
  role: "member",
  status: "pending",
  tokenHash: "sha256:synthetic-token-hash",
  invitedByUserId: userRow.id,
  createdAt,
  expiresAt,
  acceptedAt,
  revokedAt: null,
};

const sessionRow = {
  id: "session_owner_example",
  userId: userRow.id,
  createdAt,
  expiresAt,
  lastSeenAt: updatedAt,
  revokedAt: null,
  metadata: { userAgentFamily: "synthetic" },
};
const revokedSessionRow = {
  ...sessionRow,
  revokedAt: updatedAt,
};

const auditEventRow = {
  id: "audit_event_example",
  workspaceId: workspaceRow.id,
  actorUserId: userRow.id,
  eventType: "app.access.decided",
  targetType: "app",
  targetId: "app_kqag",
  createdAt,
  metadata: { appKey: "kqag", result: "allowed" },
};

const appRow = {
  id: "app_kqag",
  key: "kqag",
  name: "KQAG / SAQG",
  status: "private_preview",
  launchUrl: null,
  createdAt,
  updatedAt,
};

const entitlementRow = {
  id: "entitlement_koncept_kqag",
  workspaceId: workspaceRow.id,
  appId: appRow.id,
  status: "enabled",
  grantedByUserId: userRow.id,
  createdAt,
  updatedAt,
};

test("maps platform database rows to plain domain records", () => {
  assert.deepEqual(mapUserRow(userRow), {
    ...userRow,
    createdAt: createdAt.toISOString(),
    updatedAt: updatedAt.toISOString(),
  });

  assert.deepEqual(mapSessionRow(sessionRow), {
    id: sessionRow.id,
    userId: sessionRow.userId,
    createdAt: createdAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    lastSeenAt: updatedAt.toISOString(),
    revokedAt: null,
  });

  assert.deepEqual(mapWorkspaceRow(workspaceRow), {
    ...workspaceRow,
    createdAt: createdAt.toISOString(),
    updatedAt: updatedAt.toISOString(),
  });

  assert.deepEqual(mapMembershipRow(membershipRow), {
    ...membershipRow,
    createdAt: createdAt.toISOString(),
    updatedAt: updatedAt.toISOString(),
  });

  assert.deepEqual(mapAppRow(appRow), {
    ...appRow,
    createdAt: createdAt.toISOString(),
    updatedAt: updatedAt.toISOString(),
  });

  assert.deepEqual(mapAppEntitlementRow(entitlementRow), {
    ...entitlementRow,
    createdAt: createdAt.toISOString(),
    updatedAt: updatedAt.toISOString(),
  });
});

test("maps provider identity, invitation, and audit rows without raw secrets", () => {
  assert.deepEqual(mapProviderIdentityRow(providerIdentityRow), {
    ...providerIdentityRow,
    createdAt: createdAt.toISOString(),
    updatedAt: updatedAt.toISOString(),
  });

  assert.deepEqual(mapInvitationRow(invitationRow), {
    id: invitationRow.id,
    workspaceId: invitationRow.workspaceId,
    email: invitationRow.email,
    role: invitationRow.role,
    status: invitationRow.status,
    tokenHash: invitationRow.tokenHash,
    invitedByUserId: invitationRow.invitedByUserId,
    createdAt: createdAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    acceptedAt: acceptedAt.toISOString(),
    revokedAt: null,
  });
  assert.equal("token" in mapInvitationRow(invitationRow), false);

  assert.deepEqual(mapAuditEventRow(auditEventRow), {
    ...auditEventRow,
    createdAt: createdAt.toISOString(),
  });
});

test("Drizzle repository adapters map find results and use expected tables", async () => {
  const fakeDb = createFakeDrizzleDb({
    selectRows: new Map([
      [schema.users, [userRow]],
      [schema.providerIdentities, [providerIdentityRow]],
      [schema.sessions, [sessionRow]],
      [schema.workspaces, [workspaceRow]],
      [schema.memberships, [membershipRow]],
      [schema.invitations, [invitationRow]],
      [schema.apps, [appRow]],
      [schema.appEntitlements, [entitlementRow]],
    ]),
  });
  const repositories = createDrizzlePlatformRepositories(fakeDb);

  assert.deepEqual(await repositories.users.findById(userRow.id), mapUserRow(userRow));
  assert.deepEqual(
    await repositories.users.findByNormalizedEmail(userRow.email),
    mapUserRow(userRow),
  );
  assert.deepEqual(
    await repositories.providerIdentities.findByProviderSubject(
      providerIdentityRow.providerKey,
      providerIdentityRow.providerSubject,
    ),
    mapProviderIdentityRow(providerIdentityRow),
  );
  assert.deepEqual(await repositories.sessions.findById(sessionRow.id), mapSessionRow(sessionRow));
  assert.deepEqual(
    await repositories.workspaces.findById(workspaceRow.id),
    mapWorkspaceRow(workspaceRow),
  );
  assert.deepEqual(
    await repositories.workspaces.findBySlug(workspaceRow.slug),
    mapWorkspaceRow(workspaceRow),
  );
  assert.deepEqual(
    await repositories.memberships.findForUserInWorkspace(userRow.id, workspaceRow.id),
    mapMembershipRow(membershipRow),
  );
  assert.deepEqual(
    await repositories.invitations.findById(invitationRow.id),
    mapInvitationRow(invitationRow),
  );
  assert.deepEqual(await repositories.apps.findByKey(appRow.key), mapAppRow(appRow));
  assert.deepEqual(await repositories.apps.findById(appRow.id), mapAppRow(appRow));
  assert.deepEqual(
    await repositories.appEntitlements.findForWorkspaceApp(workspaceRow.id, appRow.id),
    mapAppEntitlementRow(entitlementRow),
  );

  assertTablesWereSelected(fakeDb, [
    schema.users,
    schema.users,
    schema.providerIdentities,
    schema.sessions,
    schema.workspaces,
    schema.workspaces,
    schema.memberships,
    schema.invitations,
    schema.apps,
    schema.apps,
    schema.appEntitlements,
  ]);
});

test("Drizzle repository adapters return null for missing find results", async () => {
  const repositories = createDrizzlePlatformRepositories(createFakeDrizzleDb());

  assert.equal(await repositories.users.findById("missing_user"), null);
  assert.equal(await repositories.users.findByNormalizedEmail("missing@example.com"), null);
  assert.equal(
    await repositories.providerIdentities.findByProviderSubject("example_oidc", "missing"),
    null,
  );
  assert.equal(await repositories.sessions.findById("missing_session"), null);
  assert.equal(await repositories.workspaces.findById("missing_workspace"), null);
  assert.equal(await repositories.workspaces.findBySlug("missing-workspace"), null);
  assert.equal(
    await repositories.memberships.findForUserInWorkspace("missing_user", "missing_workspace"),
    null,
  );
  assert.equal(await repositories.invitations.findById("missing_invitation"), null);
  assert.equal(await repositories.apps.findByKey("missing_app"), null);
  assert.equal(await repositories.apps.findById("missing_app"), null);
  assert.equal(
    await repositories.appEntitlements.findForWorkspaceApp("missing_workspace", "missing_app"),
    null,
  );
});

test("Drizzle repository list methods return arrays", async () => {
  const repositories = createDrizzlePlatformRepositories(
    createFakeDrizzleDb({
      selectRows: new Map([
        [schema.providerIdentities, [providerIdentityRow]],
        [schema.memberships, [membershipRow]],
        [schema.apps, [appRow]],
        [schema.appEntitlements, [entitlementRow]],
      ]),
    }),
  );

  assert.deepEqual(await repositories.providerIdentities.listForUser(userRow.id), [
    mapProviderIdentityRow(providerIdentityRow),
  ]);
  assert.deepEqual(await repositories.memberships.listForUser(userRow.id), [
    mapMembershipRow(membershipRow),
  ]);
  assert.deepEqual(await repositories.memberships.listForWorkspace(workspaceRow.id), [
    mapMembershipRow(membershipRow),
  ]);
  assert.deepEqual(await repositories.apps.listAll(), [mapAppRow(appRow)]);
  assert.deepEqual(await repositories.appEntitlements.listForWorkspace(workspaceRow.id), [
    mapAppEntitlementRow(entitlementRow),
  ]);
});

test("Drizzle repository create, update, and append methods return mapped records", async () => {
  const fakeDb = createFakeDrizzleDb({
    insertRows: new Map([
      [schema.users, [userRow]],
      [schema.providerIdentities, [providerIdentityRow]],
      [schema.sessions, [sessionRow]],
      [schema.workspaces, [workspaceRow]],
      [schema.memberships, [membershipRow]],
      [schema.invitations, [invitationRow]],
      [schema.apps, [appRow]],
      [schema.appEntitlements, [entitlementRow]],
      [schema.auditEvents, [auditEventRow]],
    ]),
    updateRows: new Map([
      [schema.invitations, [{ ...invitationRow, status: "accepted" }]],
      [schema.sessions, [revokedSessionRow]],
      [schema.memberships, [{ ...membershipRow, role: "admin", updatedAt }]],
      [schema.appEntitlements, [{ ...entitlementRow, status: "disabled", updatedAt }]],
    ]),
  });
  const repositories = createDrizzlePlatformRepositories(fakeDb);

  assert.deepEqual(await repositories.users.create(mapUserRow(userRow)), mapUserRow(userRow));
  assert.deepEqual(
    await repositories.providerIdentities.create(mapProviderIdentityRow(providerIdentityRow)),
    mapProviderIdentityRow(providerIdentityRow),
  );
  assert.deepEqual(
    await repositories.sessions.create(mapSessionRow(sessionRow)),
    mapSessionRow(sessionRow),
  );
  assert.deepEqual(
    await repositories.workspaces.create(mapWorkspaceRow(workspaceRow)),
    mapWorkspaceRow(workspaceRow),
  );
  assert.deepEqual(
    await repositories.memberships.create(mapMembershipRow(membershipRow)),
    mapMembershipRow(membershipRow),
  );
  assert.deepEqual(await repositories.apps.create(mapAppRow(appRow)), mapAppRow(appRow));
  assert.deepEqual(
    await repositories.appEntitlements.create(mapAppEntitlementRow(entitlementRow)),
    mapAppEntitlementRow(entitlementRow),
  );
  assert.deepEqual(
    await repositories.sessions.revoke(sessionRow.id, updatedAt.toISOString()),
    mapSessionRow(revokedSessionRow),
  );
  assert.deepEqual(
    await repositories.memberships.updateRole(
      membershipRow.id,
      "admin",
      updatedAt.toISOString(),
    ),
    mapMembershipRow({ ...membershipRow, role: "admin", updatedAt }),
  );
  assert.deepEqual(
    await repositories.memberships.updateStatus(
      membershipRow.id,
      "disabled",
      updatedAt.toISOString(),
    ),
    mapMembershipRow({ ...membershipRow, role: "admin", updatedAt }),
  );
  assert.deepEqual(
    await repositories.invitations.create(mapInvitationRow(invitationRow)),
    mapInvitationRow(invitationRow),
  );
  assert.deepEqual(
    await repositories.invitations.updateStatus(invitationRow.id, "accepted", {
      acceptedAt: acceptedAt.toISOString(),
    }),
    mapInvitationRow({ ...invitationRow, status: "accepted" }),
  );
  assert.deepEqual(
    await repositories.auditEvents.append(mapAuditEventRow(auditEventRow)),
    mapAuditEventRow(auditEventRow),
  );
  assert.deepEqual(
    await repositories.appEntitlements.updateStatus(
      entitlementRow.id,
      "disabled",
      userRow.id,
      updatedAt.toISOString(),
    ),
    mapAppEntitlementRow({ ...entitlementRow, status: "disabled", updatedAt }),
  );

  const invitationInsert = fakeDb.calls.find(
    (call) => call.operation === "insert.values" && call.table === schema.invitations,
  );
  const sessionInsert = fakeDb.calls.find(
    (call) => call.operation === "insert.values" && call.table === schema.sessions,
  );
  assert.ok(invitationInsert);
  assert.equal("token" in invitationInsert.values, false);
  assert.equal(invitationInsert.values.tokenHash, invitationRow.tokenHash);
  assert.ok(sessionInsert);
  assert.equal("token" in sessionInsert.values, false);
  assert.equal("sessionSecret" in sessionInsert.values, false);
  const workspaceInsert = fakeDb.calls.find(
    (call) => call.operation === "insert.values" && call.table === schema.workspaces,
  );
  const membershipInsert = fakeDb.calls.find(
    (call) => call.operation === "insert.values" && call.table === schema.memberships,
  );
  const appInsert = fakeDb.calls.find(
    (call) => call.operation === "insert.values" && call.table === schema.apps,
  );
  const entitlementInsert = fakeDb.calls.find(
    (call) => call.operation === "insert.values" && call.table === schema.appEntitlements,
  );
  assert.ok(workspaceInsert);
  assert.equal(workspaceInsert.values.slug, workspaceRow.slug);
  assert.equal(workspaceInsert.values.status, workspaceRow.status);
  assert.ok(membershipInsert);
  assert.equal(membershipInsert.values.role, membershipRow.role);
  assert.equal(membershipInsert.values.status, membershipRow.status);
  assert.ok(appInsert);
  assert.equal(appInsert.values.key, appRow.key);
  assert.equal(appInsert.values.status, appRow.status);
  assert.ok(entitlementInsert);
  assert.equal(entitlementInsert.values.status, entitlementRow.status);
  assert.equal(entitlementInsert.values.grantedByUserId, entitlementRow.grantedByUserId);
  const sessionUpdate = fakeDb.calls.find(
    (call) => call.operation === "update.set" && call.table === schema.sessions,
  );
  assert.ok(sessionUpdate);
  assert.deepEqual(Object.keys(sessionUpdate.values), ["revokedAt"]);
  const membershipUpdates = fakeDb.calls.filter(
    (call) => call.operation === "update.set" && call.table === schema.memberships,
  );
  assert.equal(membershipUpdates.length, 2);
  assert.deepEqual(membershipUpdates[0].values, {
    role: "admin",
    updatedAt,
  });
  assert.deepEqual(membershipUpdates[1].values, {
    status: "disabled",
    updatedAt,
  });
  const entitlementUpdate = fakeDb.calls.find(
    (call) => call.operation === "update.set" && call.table === schema.appEntitlements,
  );
  assert.ok(entitlementUpdate);
  assert.deepEqual(entitlementUpdate.values, {
    status: "disabled",
    grantedByUserId: userRow.id,
    updatedAt,
  });
});

test("Drizzle repositories expose a transaction runner for admin mutations", async () => {
  const fakeDb = createFakeDrizzleDb();
  let transactionCalled = false;
  fakeDb.transaction = async (operation) => {
    transactionCalled = true;
    return operation(fakeDb);
  };

  const repositories = createDrizzlePlatformRepositories(fakeDb);

  assert.equal(typeof repositories.workspaceAdminTransactions?.run, "function");
  const result = await repositories.workspaceAdminTransactions.run(async (transactionRepositories) => {
    assert.notEqual(transactionRepositories, repositories);
    return "committed";
  });

  assert.equal(result, "committed");
  assert.equal(transactionCalled, true);
});

test("pure domain and platform port modules do not import database adapter details", async () => {
  const storageAgnosticFiles = [
    "src/accounts/types.ts",
    "src/accounts/normalization.ts",
    "src/apps/types.ts",
    "src/access/decide-app-access.ts",
    "src/platform/repositories.ts",
    "src/platform/app-access-service.ts",
  ];

  for (const filePath of storageAgnosticFiles) {
    const contents = await readFile(filePath, "utf8");

    assert.doesNotMatch(contents, /drizzle-orm/);
    assert.doesNotMatch(contents, /src\/db|\.{1,2}\/db|\.{1,2}\/\.{1,2}\/db/);
    assert.doesNotMatch(contents, /schema\.js|schema\.ts/);
    assert.doesNotMatch(contents, /\bsql\b/i);
    assert.doesNotMatch(contents, /migrations?/i);
  }
});

function createFakeDrizzleDb({ selectRows, insertRows, updateRows } = {}) {
  const calls = [];

  return {
    calls,
    select() {
      return {
        from(table) {
          calls.push({ operation: "select.from", table });

          return new FakeSelectResult(selectRows?.get(table) ?? [], calls, table);
        },
      };
    },
    insert(table) {
      calls.push({ operation: "insert", table });

      return {
        values(values) {
          calls.push({ operation: "insert.values", table, values });

          return {
            returning() {
              calls.push({ operation: "insert.returning", table });
              return Promise.resolve(insertRows?.get(table) ?? []);
            },
          };
        },
      };
    },
    update(table) {
      calls.push({ operation: "update", table });

      return {
        set(values) {
          calls.push({ operation: "update.set", table, values });

          return {
            where(condition) {
              calls.push({ operation: "update.where", table, condition });

              return {
                returning() {
                  calls.push({ operation: "update.returning", table });
                  return Promise.resolve(updateRows?.get(table) ?? []);
                },
              };
            },
          };
        },
      };
    },
  };
}

function assertTablesWereSelected(fakeDb, expectedTables) {
  assert.deepEqual(
    fakeDb.calls
      .filter((call) => call.operation === "select.from")
      .map((call) => call.table),
    expectedTables,
  );
}

class FakeSelectResult {
  constructor(rows, calls, table) {
    this.rows = rows;
    this.calls = calls;
    this.table = table;
  }

  limit(limit) {
    this.calls.push({ operation: "select.limit", table: this.table, limit });
    return Promise.resolve(this.rows.slice(0, limit));
  }

  where(condition) {
    this.calls.push({ operation: "select.where", table: this.table, condition });
    return this;
  }

  then(onFulfilled, onRejected) {
    return Promise.resolve(this.rows).then(onFulfilled, onRejected);
  }

  catch(onRejected) {
    return Promise.resolve(this.rows).catch(onRejected);
  }

  finally(onFinally) {
    return Promise.resolve(this.rows).finally(onFinally);
  }
}
