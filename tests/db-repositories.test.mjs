import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { DrizzleQueryError } from "drizzle-orm";
import { DatabaseError } from "pg";

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
  mapWorkspaceMembershipApprovalRow,
  mapWorkspaceRow,
} from "../dist/db/mappers.js";
import { createDrizzlePlatformRepositories } from "../dist/db/repositories.js";

const createdAt = new Date("2026-06-26T00:00:00.000Z");
const updatedAt = new Date("2026-06-26T01:00:00.000Z");
const expiresAt = new Date("2026-06-27T00:00:00.000Z");
const acceptedAt = new Date("2026-06-26T02:00:00.000Z");
const revokedAt = new Date("2026-06-26T03:00:00.000Z");

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
  role: "admin",
  status: "active",
  createdAt,
  updatedAt,
};

const invitationRow = {
  id: "invitation_owner_example",
  workspaceId: workspaceRow.id,
  email: "invitee@example.com",
  role: "operator",
  status: "pending",
  tokenHash: "sha256:synthetic-token-hash",
  invitedByUserId: userRow.id,
  createdAt,
  expiresAt,
  acceptedAt,
  revokedAt: null,
};

const workspaceMembershipApprovalRow = {
  id: "approval_teammate_example",
  workspaceId: workspaceRow.id,
  email: "teammate@example.com",
  role: "viewer",
  status: "pending",
  requestedByUserId: userRow.id,
  createdAt,
  updatedAt,
  acceptedAt: null,
  revokedAt: null,
  acceptedUserId: null,
  revokedByUserId: null,
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
  targetId: "app_sqag",
  createdAt,
  metadata: { appKey: "sqag", result: "allowed" },
};

const appRow = {
  id: "app_sqag",
  key: "sqag",
  name: "SQAG",
  status: "private_preview",
  launchUrl: null,
  createdAt,
  updatedAt,
};

const entitlementRow = {
  id: "entitlement_koncept_sqag",
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

test("maps workspace membership approval rows without token material", () => {
  assert.deepEqual(mapWorkspaceMembershipApprovalRow(workspaceMembershipApprovalRow), {
    id: workspaceMembershipApprovalRow.id,
    workspaceId: workspaceMembershipApprovalRow.workspaceId,
    email: workspaceMembershipApprovalRow.email,
    role: workspaceMembershipApprovalRow.role,
    status: workspaceMembershipApprovalRow.status,
    requestedByUserId: workspaceMembershipApprovalRow.requestedByUserId,
    createdAt: createdAt.toISOString(),
    updatedAt: updatedAt.toISOString(),
    acceptedAt: null,
    revokedAt: null,
    acceptedUserId: null,
    revokedByUserId: null,
  });
  assert.equal("token" in mapWorkspaceMembershipApprovalRow(workspaceMembershipApprovalRow), false);
  assert.equal("tokenHash" in mapWorkspaceMembershipApprovalRow(workspaceMembershipApprovalRow), false);
});

test("Drizzle repository adapters map find results and use expected tables", async () => {
  const fakeDb = createFakeDrizzleDb({
    selectRows: new Map([
      [schema.users, [userRow]],
      [schema.providerIdentities, [providerIdentityRow]],
      [schema.sessions, [sessionRow]],
      [schema.workspaces, [workspaceRow]],
      [schema.memberships, [membershipRow]],
      [schema.workspaceMembershipApprovals, [workspaceMembershipApprovalRow]],
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
    await repositories.membershipApprovals.findById(workspaceMembershipApprovalRow.id),
    mapWorkspaceMembershipApprovalRow(workspaceMembershipApprovalRow),
  );
  assert.deepEqual(
    await repositories.membershipApprovals.findPendingForWorkspaceEmail(
      workspaceRow.id,
      workspaceMembershipApprovalRow.email,
    ),
    mapWorkspaceMembershipApprovalRow(workspaceMembershipApprovalRow),
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
    schema.workspaceMembershipApprovals,
    schema.workspaceMembershipApprovals,
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
  assert.equal(await repositories.membershipApprovals.findById("missing_approval"), null);
  assert.equal(
    await repositories.membershipApprovals.findPendingForWorkspaceEmail(
      "missing_workspace",
      "missing@example.com",
    ),
    null,
  );
  assert.equal(
    await repositories.membershipApprovals.updatePendingStatus(
      "missing_approval",
      "revoked",
      {
        updatedAt: updatedAt.toISOString(),
        revokedAt: revokedAt.toISOString(),
        revokedByUserId: userRow.id,
      },
    ),
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
        [schema.workspaceMembershipApprovals, [workspaceMembershipApprovalRow]],
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
  assert.deepEqual(
    await repositories.membershipApprovals.listPendingForEmail(
      workspaceMembershipApprovalRow.email,
    ),
    [mapWorkspaceMembershipApprovalRow(workspaceMembershipApprovalRow)],
  );
  assert.deepEqual(
    await repositories.membershipApprovals.listPendingForWorkspace(workspaceRow.id),
    [mapWorkspaceMembershipApprovalRow(workspaceMembershipApprovalRow)],
  );
  assert.deepEqual(await repositories.apps.listAll(), [mapAppRow(appRow)]);
  assert.deepEqual(await repositories.appEntitlements.listForWorkspace(workspaceRow.id), [
    mapAppEntitlementRow(entitlementRow),
  ]);
});

test("Drizzle repository create, update, append, and remove methods return mapped records", async () => {
  const fakeDb = createFakeDrizzleDb({
    insertRows: new Map([
      [schema.users, [userRow]],
      [schema.providerIdentities, [providerIdentityRow]],
      [schema.sessions, [sessionRow]],
      [schema.workspaces, [workspaceRow]],
      [schema.memberships, [membershipRow]],
      [schema.workspaceMembershipApprovals, [workspaceMembershipApprovalRow]],
      [schema.invitations, [invitationRow]],
      [schema.apps, [appRow]],
      [schema.appEntitlements, [entitlementRow]],
      [schema.auditEvents, [auditEventRow]],
    ]),
    updateRows: new Map([
      [schema.invitations, [{ ...invitationRow, status: "accepted" }]],
      [schema.sessions, [revokedSessionRow]],
      [schema.memberships, [{ ...membershipRow, role: "admin", updatedAt }]],
      [
        schema.workspaceMembershipApprovals,
        [
          {
            ...workspaceMembershipApprovalRow,
            status: "revoked",
            updatedAt,
            revokedAt,
            revokedByUserId: userRow.id,
          },
        ],
      ],
      [schema.appEntitlements, [{ ...entitlementRow, status: "disabled", updatedAt }]],
    ]),
    deleteRows: new Map([[schema.memberships, [membershipRow]]]),
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
  assert.deepEqual(
    await repositories.membershipApprovals.create(
      mapWorkspaceMembershipApprovalRow(workspaceMembershipApprovalRow),
    ),
    mapWorkspaceMembershipApprovalRow(workspaceMembershipApprovalRow),
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
    await repositories.sessions.revokeActiveForUser(userRow.id, updatedAt.toISOString()),
    [mapSessionRow(revokedSessionRow)],
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
    await repositories.memberships.removeIfCurrentTarget(mapMembershipRow(membershipRow)),
    mapMembershipRow(membershipRow),
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
    await repositories.membershipApprovals.updatePendingStatus(
      workspaceMembershipApprovalRow.id,
      "revoked",
      {
        updatedAt: updatedAt.toISOString(),
        revokedAt: revokedAt.toISOString(),
        revokedByUserId: userRow.id,
      },
    ),
    mapWorkspaceMembershipApprovalRow({
      ...workspaceMembershipApprovalRow,
      status: "revoked",
      updatedAt,
      revokedAt,
      revokedByUserId: userRow.id,
    }),
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
  const approvalInsert = fakeDb.calls.find(
    (call) =>
      call.operation === "insert.values" &&
      call.table === schema.workspaceMembershipApprovals,
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
  assert.ok(approvalInsert);
  assert.equal(approvalInsert.values.email, workspaceMembershipApprovalRow.email);
  assert.equal(approvalInsert.values.role, workspaceMembershipApprovalRow.role);
  assert.equal(approvalInsert.values.status, workspaceMembershipApprovalRow.status);
  assert.equal("token" in approvalInsert.values, false);
  assert.equal("tokenHash" in approvalInsert.values, false);
  assert.ok(appInsert);
  assert.equal(appInsert.values.key, appRow.key);
  assert.equal(appInsert.values.status, appRow.status);
  assert.ok(entitlementInsert);
  assert.equal(entitlementInsert.values.status, entitlementRow.status);
  assert.equal(entitlementInsert.values.grantedByUserId, entitlementRow.grantedByUserId);
  const sessionUpdates = fakeDb.calls.filter(
    (call) => call.operation === "update.set" && call.table === schema.sessions,
  );
  assert.equal(sessionUpdates.length, 2);
  assert.deepEqual(Object.keys(sessionUpdates[0].values), ["revokedAt"]);
  assert.deepEqual(Object.keys(sessionUpdates[1].values), ["revokedAt"]);
  const sessionUpdateWhereConditions = fakeDb.calls
    .filter((call) => call.operation === "update.where" && call.table === schema.sessions)
    .map((call) => collectSqlConditionFacts(call.condition));
  assert.ok(sessionUpdateWhereConditions[0].columns.includes("id"));
  assert.ok(sessionUpdateWhereConditions[0].params.includes(sessionRow.id));
  assert.ok(sessionUpdateWhereConditions[1].columns.includes("user_id"));
  assert.ok(sessionUpdateWhereConditions[1].columns.includes("revoked_at"));
  assert.ok(sessionUpdateWhereConditions[1].params.includes(userRow.id));
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
  const membershipDeleteWhere = fakeDb.calls.find(
    (call) => call.operation === "delete.where" && call.table === schema.memberships,
  );
  assert.ok(membershipDeleteWhere);
  const membershipDeleteCondition = collectSqlConditionFacts(
    membershipDeleteWhere.condition,
  );
  for (const column of ["id", "workspace_id", "user_id", "role", "status"]) {
    assert.ok(
      membershipDeleteCondition.columns.includes(column),
      `delete condition should include ${column}`,
    );
  }
  for (const value of [
    membershipRow.id,
    membershipRow.workspaceId,
    membershipRow.userId,
    membershipRow.role,
    membershipRow.status,
  ]) {
    assert.ok(
      membershipDeleteCondition.params.includes(value),
      `delete condition should include ${value}`,
    );
  }
  const approvalUpdate = fakeDb.calls.find(
    (call) =>
      call.operation === "update.set" &&
      call.table === schema.workspaceMembershipApprovals,
  );
  assert.ok(approvalUpdate);
  assert.deepEqual(approvalUpdate.values, {
    status: "revoked",
    updatedAt,
    revokedAt,
    revokedByUserId: userRow.id,
  });
  const approvalUpdateWhere = fakeDb.calls.find(
    (call) =>
      call.operation === "update.where" &&
      call.table === schema.workspaceMembershipApprovals,
  );
  assert.ok(approvalUpdateWhere);
  const approvalUpdateCondition = collectSqlConditionFacts(
    approvalUpdateWhere.condition,
  );
  assert.ok(approvalUpdateCondition.columns.includes("id"));
  assert.ok(approvalUpdateCondition.columns.includes("status"));
  assert.ok(approvalUpdateCondition.params.includes(workspaceMembershipApprovalRow.id));
  assert.ok(approvalUpdateCondition.params.includes("pending"));
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

test("Drizzle audit repository lists workspace events newest first with a safe limit", async () => {
  const otherWorkspaceRow = {
    ...auditEventRow,
    id: "audit_other_workspace",
    workspaceId: "workspace_other_example",
    createdAt: new Date("2026-06-26T05:00:00.000Z"),
  };
  const olderAuditRow = {
    ...auditEventRow,
    id: "audit_older",
    eventType: "workspace.membership.added",
    targetType: "membership",
    targetId: "membership_http_1",
    createdAt: new Date("2026-06-26T03:00:00.000Z"),
  };
  const newerAuditRow = {
    ...auditEventRow,
    id: "audit_newer",
    eventType: "workspace.app_entitlement.enabled",
    targetType: "app_entitlement",
    targetId: "entitlement_koncept_sqag",
    createdAt: new Date("2026-06-26T04:00:00.000Z"),
  };
  const repositories = createDrizzlePlatformRepositories(
    createFakeDrizzleDb({
      selectRows: new Map([
        [schema.auditEvents, [olderAuditRow, otherWorkspaceRow, newerAuditRow]],
      ]),
    }),
  );

  assert.deepEqual(
    await repositories.auditEvents.listForWorkspace(workspaceRow.id, 1),
    [mapAuditEventRow(newerAuditRow)],
  );
});

test("Drizzle repositories expose a transaction runner for admin mutations", async () => {
  const fakeDb = createFakeDrizzleDb();
  let transactionCalled = false;
  let transactionConfig;
  fakeDb.transaction = async (operation, config) => {
    transactionCalled = true;
    transactionConfig = config;
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
  assert.deepEqual(transactionConfig, { isolationLevel: "serializable" });
});

test("Drizzle admin transactions admit only direct pg or one ESM Drizzle 40001 signal", async () => {
  const directSerializationError = createPgDatabaseError("40001");
  const wrappedSerializationError = new DrizzleQueryError(
    "delete from memberships",
    [],
    directSerializationError,
  );
  const require = createRequire(import.meta.url);
  const cjsDrizzleQueryError = require("drizzle-orm").DrizzleQueryError;
  assert.equal(typeof cjsDrizzleQueryError, "function");
  assert.notEqual(cjsDrizzleQueryError.prototype, DrizzleQueryError.prototype);
  const cjsWrappedSerializationError = new cjsDrizzleQueryError(
    "delete from memberships",
    [],
    createPgDatabaseError("40001"),
  );

  const directCodeAccessorError = createPgDatabaseError("40001");
  const causeAccessorError = new DrizzleQueryError(
    "delete from memberships",
    [],
    createPgDatabaseError("40001"),
  );
  let prohibitedEffects = 0;
  Object.defineProperty(directCodeAccessorError, "code", {
    configurable: true,
    get() {
      prohibitedEffects += 1;
      return "40001";
    },
  });
  Object.defineProperty(causeAccessorError, "cause", {
    configurable: true,
    get() {
      prohibitedEffects += 1;
      return createPgDatabaseError("40001");
    },
  });

  const proxyHandler = {
    get() {
      prohibitedEffects += 1;
      throw new Error("proxy get trap executed");
    },
    getOwnPropertyDescriptor() {
      prohibitedEffects += 1;
      throw new Error("proxy descriptor trap executed");
    },
    getPrototypeOf() {
      prohibitedEffects += 1;
      throw new Error("proxy prototype trap executed");
    },
  };
  const proxiedSerializationError = new Proxy(
    createPgDatabaseError("40001"),
    proxyHandler,
  );
  const revokedProxy = Proxy.revocable(
    createPgDatabaseError("40001"),
    proxyHandler,
  );
  revokedProxy.revoke();

  const selfWrapped = new DrizzleQueryError("delete from memberships", []);
  Object.defineProperty(selfWrapped, "cause", {
    configurable: true,
    value: selfWrapped,
  });
  const twoWrapperFirst = new DrizzleQueryError("delete from memberships", []);
  const twoWrapperSecond = new DrizzleQueryError(
    "delete from memberships",
    [],
    twoWrapperFirst,
  );
  Object.defineProperty(twoWrapperFirst, "cause", {
    configurable: true,
    value: twoWrapperSecond,
  });

  const ordinaryErrorWithCode = new Error("ordinary error");
  Object.defineProperty(ordinaryErrorWithCode, "code", { value: "40001" });
  const ordinaryErrorWithPgCause = new Error("ordinary wrapper");
  Object.defineProperty(ordinaryErrorWithPgCause, "cause", {
    value: createPgDatabaseError("40001"),
  });

  const unsupportedDrizzleSubclass = new (class extends DrizzleQueryError {})(
    "delete from memberships",
    [],
    createPgDatabaseError("40001"),
  );
  const unsupportedPgSubclass = new (class extends DatabaseError {})(
    "serialization failure",
    0,
    "ErrorResponse",
  );
  Object.defineProperty(unsupportedPgSubclass, "code", { value: "40001" });

  const signalCases = [
    { error: directSerializationError, admitted: true },
    { error: wrappedSerializationError, admitted: true },
    { error: createPgDatabaseError("40P01"), admitted: false },
    { error: { code: "40001" }, admitted: false },
    { error: ordinaryErrorWithCode, admitted: false },
    { error: ordinaryErrorWithPgCause, admitted: false },
    {
      error: new DrizzleQueryError("delete from memberships", [], {
        code: "40001",
      }),
      admitted: false,
    },
    { error: directCodeAccessorError, admitted: false },
    { error: causeAccessorError, admitted: false },
    { error: proxiedSerializationError, admitted: false },
    { error: revokedProxy.proxy, admitted: false },
    { error: selfWrapped, admitted: false },
    { error: twoWrapperSecond, admitted: false },
    { error: cjsWrappedSerializationError, admitted: false },
    { error: unsupportedDrizzleSubclass, admitted: false },
    { error: unsupportedPgSubclass, admitted: false },
  ];

  for (const { error, admitted } of signalCases) {
    const outcome = await exerciseSerializationRetrySignal(error);
    if (admitted) {
      assert.equal(outcome.error, undefined);
      assert.equal(outcome.result, "committed");
      assert.equal(outcome.transactionAttempts, 2);
      assert.equal(outcome.operationCalls, 2);
      assert.notEqual(
        outcome.transactionRepositories[0],
        outcome.transactionRepositories[1],
      );
    } else {
      assert.equal(outcome.error, error);
      assert.equal(outcome.transactionAttempts, 1);
      assert.equal(outcome.operationCalls, 1);
    }
  }

  assert.equal(prohibitedEffects, 0);
});

test("Drizzle admin transactions replay the whole operation and stop after three total attempts", async () => {
  for (const successAtAttempt of [2, 3]) {
    const outcome = await exerciseSerializationSequence({
      failures: Array.from(
        { length: successAtAttempt - 1 },
        () => createPgDatabaseError("40001"),
      ),
      successAtAttempt,
    });

    assert.equal(outcome.error, undefined);
    assert.equal(outcome.result, "committed");
    assert.equal(outcome.transactionAttempts, successAtAttempt);
    assert.equal(outcome.operationCalls, successAtAttempt);
    for (let index = 1; index < successAtAttempt; index += 1) {
      assert.notEqual(
        outcome.transactionRepositories[index - 1],
        outcome.transactionRepositories[index],
      );
    }
  }

  const exhaustionErrors = [
    createPgDatabaseError("40001"),
    new DrizzleQueryError(
      "delete from memberships",
      [],
      createPgDatabaseError("40001"),
    ),
    createPgDatabaseError("40001"),
  ];
  const exhausted = await exerciseSerializationSequence({
    failures: exhaustionErrors,
    successAtAttempt: Infinity,
  });

  assert.equal(exhausted.error, exhaustionErrors[2]);
  assert.equal(exhausted.transactionAttempts, 3);
  assert.equal(exhausted.operationCalls, 3);
  assert.notEqual(
    exhausted.transactionRepositories[0],
    exhausted.transactionRepositories[1],
  );
  assert.notEqual(
    exhausted.transactionRepositories[1],
    exhausted.transactionRepositories[2],
  );
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

async function exerciseSerializationRetrySignal(error) {
  const fakeDb = createFakeDrizzleDb();
  let transactionAttempts = 0;
  let operationCalls = 0;
  const transactionRepositories = [];
  fakeDb.transaction = async (operation, config) => {
    transactionAttempts += 1;
    assert.deepEqual(config, { isolationLevel: "serializable" });
    await operation(fakeDb);
    if (transactionAttempts === 1) {
      throw error;
    }
    return "committed";
  };

  let result;
  let caughtError;
  try {
    result = await createDrizzlePlatformRepositories(fakeDb).workspaceAdminTransactions.run(
      async (repositories) => {
        operationCalls += 1;
        transactionRepositories.push(repositories);
        return "operation-result";
      },
    );
  } catch (candidate) {
    caughtError = candidate;
  }

  return {
    result,
    error: caughtError,
    transactionAttempts,
    operationCalls,
    transactionRepositories,
  };
}

async function exerciseSerializationSequence({ failures, successAtAttempt }) {
  const fakeDb = createFakeDrizzleDb();
  let transactionAttempts = 0;
  let operationCalls = 0;
  const transactionRepositories = [];
  fakeDb.transaction = async (operation, config) => {
    transactionAttempts += 1;
    assert.deepEqual(config, { isolationLevel: "serializable" });
    await operation(fakeDb);
    if (transactionAttempts < successAtAttempt) {
      throw failures[transactionAttempts - 1];
    }
    if (transactionAttempts === successAtAttempt) {
      return "committed";
    }
    throw failures.at(-1);
  };

  let result;
  let caughtError;
  try {
    result = await createDrizzlePlatformRepositories(fakeDb).workspaceAdminTransactions.run(
      async (repositories) => {
        operationCalls += 1;
        transactionRepositories.push(repositories);
        return "operation-result";
      },
    );
  } catch (candidate) {
    caughtError = candidate;
  }

  return {
    result,
    error: caughtError,
    transactionAttempts,
    operationCalls,
    transactionRepositories,
  };
}

function createPgDatabaseError(code) {
  const error = new DatabaseError("synthetic PostgreSQL error", 0, "ErrorResponse");
  Object.defineProperty(error, "code", {
    configurable: true,
    enumerable: true,
    value: code,
    writable: true,
  });
  return error;
}

function createFakeDrizzleDb({ selectRows, insertRows, updateRows, deleteRows } = {}) {
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
    delete(table) {
      calls.push({ operation: "delete", table });

      return {
        where(condition) {
          calls.push({ operation: "delete.where", table, condition });

          return {
            returning() {
              calls.push({ operation: "delete.returning", table });
              return Promise.resolve(deleteRows?.get(table) ?? []);
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

function collectSqlConditionFacts(condition) {
  const facts = {
    columns: [],
    params: [],
  };

  visitSqlConditionValue(condition, facts);

  return facts;
}

function visitSqlConditionValue(value, facts) {
  if (!value || typeof value !== "object") {
    return;
  }

  if (typeof value.name === "string" && typeof value.columnType === "string") {
    facts.columns.push(value.name);
  }
  if (value.constructor?.name === "Param") {
    facts.params.push(value.value);
  }
  if (Array.isArray(value.queryChunks)) {
    for (const chunk of value.queryChunks) {
      visitSqlConditionValue(chunk, facts);
    }
  }
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
