import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  AccessDecisionResult,
  WorkspaceAdminServiceError,
  changeWorkspaceMemberRole,
  decidePlatformAppAccess,
  disableWorkspaceMembership,
  listWorkspaceAppEntitlementsForAdmin,
  listWorkspaceMembersForAdmin,
  setWorkspaceAppEntitlementStatus,
} from "../dist/index.js";
import { createInMemoryPlatformRepositories } from "./helpers/in-memory-platform-repositories.mjs";

const now = "2026-06-27T00:00:00.000Z";
const earlier = "2026-06-26T23:00:00.000Z";
const future = "2026-06-27T01:00:00.000Z";
const past = "2026-06-26T22:00:00.000Z";
const privateStorageError =
  "database exploded postgresql://private-host raw-session-token provider-token select *";

test("owner and admin can list workspace members with safe user summaries", async () => {
  for (const role of ["owner", "admin"]) {
    const { repositories, input } = adminFixture({ role });

    const result = await listWorkspaceMembersForAdmin(repositories, input);

    assert.equal(result.workspaceId, "workspace_koncept_images");
    assert.deepEqual(
      result.members.map((member) => ({
        membershipId: member.membershipId,
        userId: member.user.id,
        email: member.user.email,
        displayName: member.user.displayName,
        role: member.role,
        status: member.status,
      })),
      [
        {
          membershipId: "membership_owner_example",
          userId: "user_owner_example",
          email: "owner@example.test",
          displayName: "Owner Example",
          role: "owner",
          status: "active",
        },
        {
          membershipId: "membership_admin_example",
          userId: "user_admin_example",
          email: "admin@example.test",
          displayName: "Admin Example",
          role: "admin",
          status: "active",
        },
        {
          membershipId: "membership_member_example",
          userId: "user_member_example",
          email: "member@example.test",
          displayName: "Member Example",
          role: "member",
          status: "active",
        },
        {
          membershipId: "membership_viewer_example",
          userId: "user_viewer_example",
          email: "viewer@example.test",
          displayName: "Viewer Example",
          role: "viewer",
          status: "active",
        },
      ],
    );
    assert.doesNotMatch(JSON.stringify(result), /provider-token|raw-claim|cookie|secret/i);
  }
});

test("member and viewer cannot manage workspace members or app access", async () => {
  for (const role of ["member", "viewer"]) {
    const { repositories, input } = adminFixture({ role });

    await assert.rejects(
      () => listWorkspaceMembersForAdmin(repositories, input),
      assertAdminError("not_authorized"),
    );
    await assert.rejects(
      () =>
        changeWorkspaceMemberRole(repositories, {
          ...input,
          membershipId: "membership_viewer_example",
          role: "member",
          auditEventId: "audit_role_denied",
        }),
      assertAdminError("not_authorized"),
    );
    await assert.rejects(
      () =>
        setWorkspaceAppEntitlementStatus(repositories, {
          ...input,
          appKey: "kqag",
          status: "disabled",
          auditEventId: "audit_app_denied",
        }),
      assertAdminError("not_authorized"),
    );
  }
});

test("missing disabled or expired admin context fails closed before mutation", async () => {
  for (const overrides of [
    { sessionId: "missing_session" },
    { session: { revokedAt: earlier } },
    { session: { expiresAt: past } },
    { user: { status: "disabled" } },
    { workspace: { status: "suspended" } },
    { memberships: [] },
    { actorMembership: { status: "disabled" } },
  ]) {
    const { repositories, input, records } = adminFixture(overrides);

    await assert.rejects(
      () =>
        disableWorkspaceMembership(repositories, {
          ...input,
          membershipId: "membership_member_example",
          auditEventId: "audit_disabled_context",
        }),
      assertAdminError("not_authorized"),
    );
    assert.equal(records.auditEvents.length, 0);
    const targetMembership = records.memberships.find(
      (membership) => membership.id === "membership_member_example",
    );
    assert.equal(targetMembership?.status ?? "active", "active");
  }
});

test("owner and admin can change a workspace member role and emit privacy-safe audit", async () => {
  for (const role of ["owner", "admin"]) {
    const { repositories, input, records } = adminFixture({ role });

    const result = await changeWorkspaceMemberRole(repositories, {
      ...input,
      membershipId: "membership_viewer_example",
      role: "member",
      auditEventId: `audit_role_change_${role}`,
    });

    assert.equal(result.role, "member");
    assert.equal(records.memberships.find((membership) => membership.id === result.id)?.role, "member");
    assert.deepEqual(records.auditEvents.at(-1), {
      id: `audit_role_change_${role}`,
      workspaceId: "workspace_koncept_images",
      actorUserId: `user_${role}_example`,
      eventType: "workspace.membership.role_changed",
      targetType: "membership",
      targetId: "membership_viewer_example",
      createdAt: now,
      metadata: {
        previousRole: "viewer",
        newRole: "member",
        previousStatus: "active",
        targetUserId: "user_viewer_example",
      },
    });
    assertAuditPrivacy(records.auditEvents.at(-1));
  }
});

test("last owner cannot be removed or demoted into an ownerless workspace", async () => {
  const onlyOwnerMemberships = baseMemberships().filter(
    (membership) => !["membership_admin_example"].includes(membership.id),
  );
  const { repositories, input } = adminFixture({
    role: "owner",
    memberships: onlyOwnerMemberships,
  });

  await assert.rejects(
    () =>
      changeWorkspaceMemberRole(repositories, {
        ...input,
        membershipId: "membership_owner_example",
        role: "admin",
        auditEventId: "audit_last_owner_role",
      }),
    assertAdminError("last_owner_required"),
  );
  await assert.rejects(
    () =>
      disableWorkspaceMembership(repositories, {
        ...input,
        membershipId: "membership_owner_example",
        auditEventId: "audit_last_owner_disable",
      }),
    assertAdminError("last_owner_required"),
  );
});

test("self-demotion and self-removal are guarded", async () => {
  const { repositories, input, records } = adminFixture({ role: "admin" });

  await assert.rejects(
    () =>
      changeWorkspaceMemberRole(repositories, {
        ...input,
        membershipId: "membership_admin_example",
        role: "member",
        auditEventId: "audit_self_demote",
      }),
    assertAdminError("self_change_not_allowed"),
  );
  await assert.rejects(
    () =>
      disableWorkspaceMembership(repositories, {
        ...input,
        membershipId: "membership_admin_example",
        auditEventId: "audit_self_remove",
      }),
    assertAdminError("self_change_not_allowed"),
  );
  assert.equal(records.auditEvents.length, 0);
});

test("owner and admin can disable membership and disabled user cannot launch SAQG", async () => {
  const { repositories, input, records } = adminFixture({ role: "owner" });

  const result = await disableWorkspaceMembership(repositories, {
    ...input,
    membershipId: "membership_member_example",
    auditEventId: "audit_membership_disabled",
  });

  assert.equal(result.status, "disabled");
  assert.equal(
    records.memberships.find((membership) => membership.id === "membership_member_example")
      ?.status,
    "disabled",
  );
  assert.deepEqual(records.auditEvents.at(-1), {
    id: "audit_membership_disabled",
    workspaceId: "workspace_koncept_images",
    actorUserId: "user_owner_example",
    eventType: "workspace.membership.disabled",
    targetType: "membership",
    targetId: "membership_member_example",
    createdAt: now,
    metadata: {
      previousRole: "member",
      previousStatus: "active",
      targetUserId: "user_member_example",
    },
  });
  assertAuditPrivacy(records.auditEvents.at(-1));

  const accessDecision = await decidePlatformAppAccess(repositories, {
    sessionId: "session_member_example",
    selectedWorkspaceId: "workspace_koncept_images",
    appKey: "kqag",
    now,
  });
  assert.equal(accessDecision.result, AccessDecisionResult.MembershipRequired);
});

test("owner and admin can list and enable or disable KQAG app entitlement", async () => {
  const { repositories, input, records } = adminFixture({ role: "admin" });

  const before = await listWorkspaceAppEntitlementsForAdmin(repositories, input);
  assert.deepEqual(before.entitlements, [
    {
      entitlementId: "entitlement_koncept_kqag",
      appId: "app_kqag",
      appKey: "kqag",
      appName: "KQAG / SAQG",
      appStatus: "private_preview",
      status: "enabled",
      grantedByUserId: "user_owner_example",
      updatedAt: now,
    },
  ]);

  const disabled = await setWorkspaceAppEntitlementStatus(repositories, {
    ...input,
    appKey: "kqag",
    status: "disabled",
    auditEventId: "audit_kqag_disabled",
  });
  assert.equal(disabled.status, "disabled");
  assert.deepEqual(records.auditEvents.at(-1), {
    id: "audit_kqag_disabled",
    workspaceId: "workspace_koncept_images",
    actorUserId: "user_admin_example",
    eventType: "workspace.app_entitlement.disabled",
    targetType: "app_entitlement",
    targetId: "entitlement_koncept_kqag",
    createdAt: now,
    metadata: {
      appId: "app_kqag",
      appKey: "kqag",
      previousStatus: "enabled",
      newStatus: "disabled",
    },
  });
  assertAuditPrivacy(records.auditEvents.at(-1));

  const enabled = await setWorkspaceAppEntitlementStatus(repositories, {
    ...input,
    appKey: "kqag",
    status: "enabled",
    auditEventId: "audit_kqag_enabled",
  });
  assert.equal(enabled.status, "enabled");
  assert.equal(enabled.grantedByUserId, "user_admin_example");
  assert.equal(records.auditEvents.at(-1).eventType, "workspace.app_entitlement.enabled");
  assertAuditPrivacy(records.auditEvents.at(-1));
});

test("owner can create a missing KQAG entitlement but cannot cross workspace boundaries", async () => {
  const { repositories, input, records } = adminFixture({
    appEntitlements: [],
  });

  const created = await setWorkspaceAppEntitlementStatus(repositories, {
    ...input,
    appKey: "kqag",
    status: "enabled",
    entitlementId: "entitlement_new_kqag",
    auditEventId: "audit_kqag_created",
  });

  assert.equal(created.id, "entitlement_new_kqag");
  assert.equal(created.workspaceId, "workspace_koncept_images");
  assert.equal(created.appId, "app_kqag");
  assert.equal(created.status, "enabled");
  assert.equal(records.appEntitlements.length, 1);

  await assert.rejects(
    () =>
      disableWorkspaceMembership(repositories, {
        ...input,
        workspaceId: "workspace_other_example",
        membershipId: "membership_member_example",
        auditEventId: "audit_cross_workspace",
      }),
    assertAdminError("not_authorized"),
  );
});

test("workspace admin service errors and source stay privacy-safe and boundary-clean", async () => {
  const { repositories, input } = adminFixture({ failMembershipList: true });

  await assert.rejects(
    () => listWorkspaceMembersForAdmin(repositories, input),
    assertAdminError("repository_failure"),
  );

  const contents = await readFile("src/platform/workspace-admin-service.ts", "utf8");
  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:db|drizzle|pg|migrations?|kqag)/i);
  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:react|next|vite|express|fastify|hono|node:http)/i);
  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:clerk|auth0|supabase)/i);
  assert.doesNotMatch(contents, /src\/db|\.{1,2}\/db|\.{1,2}\/\.{1,2}\/db/i);
});

test("admin mutations require audit repository before changing state", async () => {
  const { repositories, input, records } = adminFixture();
  repositories.auditEvents = undefined;

  await assert.rejects(
    () =>
      changeWorkspaceMemberRole(repositories, {
        ...input,
        membershipId: "membership_viewer_example",
        role: "member",
        auditEventId: "audit_missing_repo_role",
      }),
    assertAdminError("repository_failure"),
  );
  await assert.rejects(
    () =>
      setWorkspaceAppEntitlementStatus(repositories, {
        ...input,
        appKey: "kqag",
        status: "disabled",
        auditEventId: "audit_missing_repo_app",
      }),
    assertAdminError("repository_failure"),
  );

  assert.equal(
    records.memberships.find((membership) => membership.id === "membership_viewer_example")
      ?.role,
    "viewer",
  );
  assert.equal(records.appEntitlements[0]?.status, "enabled");
});

test("membership role change rolls back when audit append fails", async () => {
  const { repositories, input, records } = adminFixture({ failAuditAppend: true });

  await assert.rejects(
    () =>
      changeWorkspaceMemberRole(repositories, {
        ...input,
        membershipId: "membership_viewer_example",
        role: "member",
        auditEventId: "audit_role_append_failure",
      }),
    assertAdminError("repository_failure"),
  );

  assert.equal(
    records.memberships.find((membership) => membership.id === "membership_viewer_example")
      ?.role,
    "viewer",
  );
  assert.equal(records.auditEvents.length, 0);
});

test("membership disable rolls back when audit append fails", async () => {
  const { repositories, input, records } = adminFixture({ failAuditAppend: true });

  await assert.rejects(
    () =>
      disableWorkspaceMembership(repositories, {
        ...input,
        membershipId: "membership_member_example",
        auditEventId: "audit_disable_append_failure",
      }),
    assertAdminError("repository_failure"),
  );

  assert.equal(
    records.memberships.find((membership) => membership.id === "membership_member_example")
      ?.status,
    "active",
  );
  assert.equal(records.auditEvents.length, 0);
});

test("KQAG entitlement disable rolls back when audit append fails", async () => {
  const { repositories, input, records } = adminFixture({ failAuditAppend: true });

  await assert.rejects(
    () =>
      setWorkspaceAppEntitlementStatus(repositories, {
        ...input,
        appKey: "kqag",
        status: "disabled",
        auditEventId: "audit_kqag_disable_append_failure",
      }),
    assertAdminError("repository_failure"),
  );

  assert.equal(records.appEntitlements[0]?.status, "enabled");
  assert.equal(records.auditEvents.length, 0);
});

test("missing KQAG entitlement creation rolls back when audit append fails", async () => {
  const { repositories, input, records } = adminFixture({
    appEntitlements: [],
    failAuditAppend: true,
  });

  await assert.rejects(
    () =>
      setWorkspaceAppEntitlementStatus(repositories, {
        ...input,
        appKey: "kqag",
        status: "enabled",
        entitlementId: "entitlement_new_kqag",
        auditEventId: "audit_kqag_create_append_failure",
      }),
    assertAdminError("repository_failure"),
  );

  assert.equal(records.appEntitlements.length, 0);
  assert.equal(records.auditEvents.length, 0);
});

function adminFixture(overrides = {}) {
  const workspace = {
    id: "workspace_koncept_images",
    slug: "koncept-images-pte-ltd",
    displayName: "Koncept Images Pte Ltd",
    status: "active",
    createdAt: now,
    updatedAt: now,
    ...overrides.workspace,
  };
  const otherWorkspace = {
    id: "workspace_other_example",
    slug: "other-example",
    displayName: "Other Example",
    status: "active",
    createdAt: now,
    updatedAt: now,
  };
  const app = {
    id: "app_kqag",
    key: "kqag",
    name: "KQAG / SAQG",
    status: "private_preview",
    launchUrl: null,
    createdAt: now,
    updatedAt: now,
    ...overrides.app,
  };
  const users = baseUsers(overrides.usersByRole);
  const role = overrides.role ?? "owner";
  const actorUser = { ...users[role], ...overrides.user };
  const session = {
    id: `session_${role}_example`,
    userId: actorUser.id,
    createdAt: earlier,
    expiresAt: future,
    lastSeenAt: earlier,
    revokedAt: null,
    ...overrides.session,
  };
  const memberSession = {
    id: "session_member_example",
    userId: "user_member_example",
    createdAt: earlier,
    expiresAt: future,
    lastSeenAt: earlier,
    revokedAt: null,
  };
  const memberships = overrides.memberships ?? baseMemberships(overrides.actorMembership);
  const entitlement = {
    id: "entitlement_koncept_kqag",
    workspaceId: workspace.id,
    appId: app.id,
    status: "enabled",
    grantedByUserId: "user_owner_example",
    createdAt: now,
    updatedAt: now,
    ...overrides.entitlement,
  };
  const records = {
    users: overrides.users ?? Object.values({ ...users, [role]: actorUser }),
    providerIdentities: [
      {
        id: "provider_identity_private",
        userId: actorUser.id,
        providerKey: "example_oidc",
        providerSubject: "provider-token-raw-claim",
        createdAt: now,
        updatedAt: now,
      },
    ],
    sessions: overrides.sessions ?? [session, memberSession],
    workspaces: overrides.workspaces ?? [workspace, otherWorkspace],
    memberships,
    apps: overrides.apps ?? [app],
    appEntitlements: overrides.appEntitlements ?? [entitlement],
    auditEvents: [],
  };
  const repositories = createInMemoryPlatformRepositories(records);

  if (overrides.failMembershipList) {
    repositories.memberships.listForWorkspace = async () => {
      throw new Error(privateStorageError);
    };
  }
  if (overrides.failAuditAppend) {
    repositories.auditEvents.append = async () => {
      throw new Error(privateStorageError);
    };
  }

  return {
    records,
    repositories,
    input: {
      sessionId: overrides.sessionId ?? session.id,
      workspaceId: overrides.workspaceId ?? workspace.id,
      now: overrides.now ?? now,
    },
  };
}

function baseUsers(overrides = {}) {
  return Object.fromEntries(
    ["owner", "admin", "member", "viewer"].map((role) => [
      role,
      {
        id: `user_${role}_example`,
        email: `${role}@example.test`,
        displayName: `${role[0].toUpperCase()}${role.slice(1)} Example`,
        status: "active",
        createdAt: now,
        updatedAt: now,
        lastLoginAt: now,
        ...overrides[role],
      },
    ]),
  );
}

function baseMemberships(actorMembership = {}) {
  return ["owner", "admin", "member", "viewer"].map((role) => ({
    id: `membership_${role}_example`,
    workspaceId: "workspace_koncept_images",
    userId: `user_${role}_example`,
    role,
    status: "active",
    createdAt: now,
    updatedAt: now,
    ...(role === "owner" || role === "admin" ? actorMembership : {}),
  }));
}

function assertAdminError(expectedCode) {
  return (error) => {
    assert.equal(error instanceof WorkspaceAdminServiceError, true);
    assert.equal(error.code, expectedCode);
    assert.equal(error.publicMessage, "Workspace admin action could not be completed.");
    assert.doesNotMatch(error.message, /database exploded|postgresql:\/\/private-host/i);
    assert.doesNotMatch(error.message, /raw-session-token|provider-token|select \*/i);
    assert.doesNotMatch(error.message, /cookie|secret|oauth|claim/i);
    return true;
  };
}

function assertAuditPrivacy(event) {
  const serialized = JSON.stringify(event);
  assert.doesNotMatch(serialized, /@example\.test/);
  assert.doesNotMatch(serialized, /provider-token|raw-claim|oauth|cookie|secret/i);
  assert.doesNotMatch(serialized, /postgresql:\/\/private-host|select \*/i);
}
