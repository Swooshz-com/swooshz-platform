import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  AccessDecisionResult,
  WorkspaceAdminServiceError,
  addExistingWorkspaceUserByEmail,
  addWorkspaceMemberByEmail,
  changeWorkspaceMemberRole,
  decidePlatformAppAccess,
  disableWorkspaceMembership,
  listWorkspaceMembershipApprovalsForAdmin,
  listWorkspaceAppEntitlementsForAdmin,
  listWorkspaceAuditEventsForAdmin,
  listWorkspaceMembersForAdmin,
  reactivateWorkspaceMembership,
  revokeWorkspaceMembershipApproval,
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

test("owner and admin can list recent workspace audit events safely", async () => {
  for (const role of ["owner", "admin"]) {
    const { repositories, input } = adminFixture({
      role,
      auditEvents: [
        auditEvent({
          id: "audit_old",
          eventType: "workspace.membership.role_changed",
          targetId: "membership_member_example",
          createdAt: earlier,
          metadata: {
            previousRole: "viewer",
            newRole: "member",
            targetUserId: "user_member_example",
            privateProviderValue: "provider-token-raw-claim",
            providerSubject: "oidc-provider-subject-private",
            rawClaims: { sub: "provider-subject-private" },
            token: "raw-oauth-token",
            cookie: "raw-session-cookie",
            oauthCode: "raw-oauth-code",
            oauthState: "raw-oauth-state",
            oauthNonce: "raw-oauth-nonce",
            databaseUrl: "postgresql://private-host",
            quoteSession: "private-kqag-quote-session",
            pricingReference: "private-kqag-pricing-reference",
            generatedArtifact: "private-kqag-generated-artifact",
          },
        }),
        auditEvent({
          id: "audit_new",
          eventType: "workspace.app_entitlement.disabled",
          targetType: "app_entitlement",
          targetId: "entitlement_koncept_kqag",
          createdAt: now,
          metadata: {
            appId: "app_kqag",
            appKey: "kqag",
            previousStatus: "enabled",
            newStatus: "disabled",
            cookie: "raw-session-token",
          },
        }),
        auditEvent({
          id: "audit_other_workspace",
          workspaceId: "workspace_other_example",
          createdAt: future,
        }),
      ],
    });

    const result = await listWorkspaceAuditEventsForAdmin(repositories, {
      ...input,
      limit: 50,
    });

    assert.equal(result.workspaceId, "workspace_koncept_images");
    assert.deepEqual(
      result.events.map((event) => ({
        eventId: event.eventId,
        actorDisplayName: event.actorDisplayName,
        actorEmail: event.actorEmail,
        eventType: event.eventType,
        targetType: event.targetType,
        targetId: event.targetId,
        createdAt: event.createdAt,
        metadata: event.metadata,
      })),
      [
        {
          eventId: "audit_new",
          actorDisplayName: "Owner Example",
          actorEmail: "owner@example.test",
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
        },
        {
          eventId: "audit_old",
          actorDisplayName: "Owner Example",
          actorEmail: "owner@example.test",
          eventType: "workspace.membership.role_changed",
          targetType: "membership",
          targetId: "membership_member_example",
          createdAt: earlier,
          metadata: {
            previousRole: "viewer",
            newRole: "member",
            targetUserId: "user_member_example",
          },
        },
      ],
    );
    assertAuditPrivacy(result);
  }
});

test("workspace audit events resolve actor labels safely and keep system fallback", async () => {
  const { repositories, input } = adminFixture({
    auditEvents: [
      auditEvent({
        id: "audit_actor",
        actorUserId: "user_admin_example",
        eventType: "workspace.app_entitlement.enabled",
        targetType: "app_entitlement",
      }),
      auditEvent({
        id: "audit_system",
        actorUserId: null,
        eventType: "workspace.membership.added",
        createdAt: earlier,
      }),
    ],
  });

  const result = await listWorkspaceAuditEventsForAdmin(repositories, {
    ...input,
    limit: 10,
  });

  assert.deepEqual(
    result.events.map((event) => ({
      eventId: event.eventId,
      actorDisplayName: event.actorDisplayName,
      actorEmail: event.actorEmail,
    })),
    [
      {
        eventId: "audit_actor",
        actorDisplayName: "Admin Example",
        actorEmail: "admin@example.test",
      },
      {
        eventId: "audit_system",
        actorDisplayName: null,
        actorEmail: null,
      },
    ],
  );
  assertAuditPrivacy(result);
});

test("owner and admin can add an existing active provider-backed user by email", async () => {
  for (const role of ["owner", "admin"]) {
    for (const targetRole of ["admin", "member", "viewer"]) {
      const { repositories, input, records } = adminFixture({
        role,
        extraUsers: [existingProviderBackedUser()],
        providerBackedUserIds: ["user_existing_example"],
      });

      const result = await addExistingWorkspaceUserByEmail(repositories, {
        ...input,
        targetEmail: "  Existing.User@Example.Test  ",
        role: targetRole,
        membershipId: `membership_added_${role}_${targetRole}`,
        auditEventId: `audit_added_${role}_${targetRole}`,
      });

      assert.deepEqual(result, {
        id: `membership_added_${role}_${targetRole}`,
        workspaceId: "workspace_koncept_images",
        userId: "user_existing_example",
        role: targetRole,
        status: "active",
        createdAt: now,
        updatedAt: now,
      });
      assert.equal(
        records.memberships.filter((membership) => membership.userId === "user_existing_example")
          .length,
        1,
      );
      assert.deepEqual(records.auditEvents.at(-1), {
        id: `audit_added_${role}_${targetRole}`,
        workspaceId: "workspace_koncept_images",
        actorUserId: `user_${role}_example`,
        eventType: "workspace.membership.added",
        targetType: "membership",
        targetId: `membership_added_${role}_${targetRole}`,
        createdAt: now,
        metadata: {
          newRole: targetRole,
          newStatus: "active",
          targetUserId: "user_existing_example",
          source: "existing_provider_backed_user",
        },
      });
      assertAuditPrivacy(records.auditEvents.at(-1));
    }
  }
});

test("owner and admin can create and list pending approvals for unknown teammates", async () => {
  for (const role of ["owner", "admin"]) {
    const { repositories, input, records } = adminFixture({ role });

    const result = await addWorkspaceMemberByEmail(repositories, {
      ...input,
      targetEmail: "  New.Teammate@Example.Test  ",
      role: "member",
      membershipId: `membership_unused_${role}`,
      approvalId: `approval_new_teammate_${role}`,
      auditEventId: `audit_approval_created_${role}`,
    });

    assert.equal(result.outcome, "pending_approval_created");
    assert.deepEqual(result.approval, {
      id: `approval_new_teammate_${role}`,
      workspaceId: "workspace_koncept_images",
      email: "new.teammate@example.test",
      role: "member",
      status: "pending",
      requestedByUserId: `user_${role}_example`,
      createdAt: now,
      updatedAt: now,
      acceptedAt: null,
      revokedAt: null,
      acceptedUserId: null,
      revokedByUserId: null,
    });
    assert.equal(
      records.memberships.some((membership) => membership.id === `membership_unused_${role}`),
      false,
    );
    assert.deepEqual(records.auditEvents.at(-1), {
      id: `audit_approval_created_${role}`,
      workspaceId: "workspace_koncept_images",
      actorUserId: `user_${role}_example`,
      eventType: "workspace.membership_approval.created",
      targetType: "membership_approval",
      targetId: `approval_new_teammate_${role}`,
      createdAt: now,
      metadata: {
        newRole: "member",
        newStatus: "pending",
        source: "invite_less_onboarding",
      },
    });
    assertAuditPrivacy(records.auditEvents.at(-1));

    const listed = await listWorkspaceMembershipApprovalsForAdmin(repositories, input);

    assert.deepEqual(listed, {
      workspaceId: "workspace_koncept_images",
      approvals: [result.approval],
    });
  }
});

test("pending approval creation rejects duplicate email roles and unauthorized actors", async () => {
  const duplicate = adminFixture({
    membershipApprovals: [
      pendingApproval({
        id: "approval_existing_pending",
        email: "new.teammate@example.test",
      }),
    ],
  });

  await assert.rejects(
    () =>
      addWorkspaceMemberByEmail(duplicate.repositories, {
        ...duplicate.input,
        targetEmail: "NEW.Teammate@example.test",
        role: "admin",
        membershipId: "membership_unused_duplicate",
        approvalId: "approval_duplicate",
        auditEventId: "audit_duplicate",
      }),
    assertAdminError("approval_conflict"),
  );
  assert.equal(duplicate.records.membershipApprovals.length, 1);
  assert.equal(duplicate.records.auditEvents.length, 0);

  for (const [name, role, targetRole, expectedCode] of [
    ["member actor", "member", "member", "not_authorized"],
    ["viewer actor", "viewer", "member", "not_authorized"],
    ["owner target", "owner", "owner", "invalid_role"],
    ["invalid target", "owner", "operator", "invalid_role"],
  ]) {
    const { repositories, input, records } = adminFixture({ role });

    await assert.rejects(
      () =>
        addWorkspaceMemberByEmail(repositories, {
          ...input,
          targetEmail: "new.teammate@example.test",
          role: targetRole,
          membershipId: `membership_unused_${name.replaceAll(" ", "_")}`,
          approvalId: `approval_rejected_${name.replaceAll(" ", "_")}`,
          auditEventId: `audit_rejected_${name.replaceAll(" ", "_")}`,
        }),
      assertAdminError(expectedCode),
      name,
    );
    assert.equal(records.membershipApprovals.length, 0);
    assert.equal(records.auditEvents.length, 0);
  }
});

test("owner and admin can revoke pending approvals without creating memberships", async () => {
  for (const role of ["owner", "admin"]) {
    const { repositories, input, records } = adminFixture({
      role,
      membershipApprovals: [pendingApproval()],
    });

    const result = await revokeWorkspaceMembershipApproval(repositories, {
      ...input,
      approvalId: "approval_pending_example",
      auditEventId: `audit_approval_revoked_${role}`,
    });

    assert.deepEqual(result, {
      ...pendingApproval(),
      status: "revoked",
      updatedAt: now,
      revokedAt: now,
      revokedByUserId: `user_${role}_example`,
    });
    assert.equal(
      records.memberships.some((membership) => membership.userId === "user_pending_example"),
      false,
    );
    assert.deepEqual(records.auditEvents.at(-1), {
      id: `audit_approval_revoked_${role}`,
      workspaceId: "workspace_koncept_images",
      actorUserId: `user_${role}_example`,
      eventType: "workspace.membership_approval.revoked",
      targetType: "membership_approval",
      targetId: "approval_pending_example",
      createdAt: now,
      metadata: {
        previousStatus: "pending",
        newStatus: "revoked",
        newRole: "member",
      },
    });
    assertAuditPrivacy(records.auditEvents.at(-1));
  }
});

test("pending approvals do not grant app launch before provider-backed activation", async () => {
  const { repositories } = adminFixture({
    membershipApprovals: [pendingApproval()],
  });

  const accessDecision = await decidePlatformAppAccess(repositories, {
    sessionId: "session_pending_example",
    selectedWorkspaceId: "workspace_koncept_images",
    appKey: "kqag",
    now,
  });

  assert.equal(accessDecision.result, AccessDecisionResult.NotAuthenticated);
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
    await assert.rejects(
      () =>
        reactivateWorkspaceMembership(repositories, {
          ...input,
          membershipId: "membership_member_example",
          auditEventId: "audit_reactivate_denied",
        }),
      assertAdminError("not_authorized"),
    );
    await assert.rejects(
      () =>
        addExistingWorkspaceUserByEmail(repositories, {
          ...input,
          targetEmail: "existing.user@example.test",
          role: "member",
          membershipId: "membership_denied_add",
          auditEventId: "audit_denied_add",
        }),
      assertAdminError("not_authorized"),
    );
    await assert.rejects(
      () => listWorkspaceAuditEventsForAdmin(repositories, input),
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
    await assert.rejects(
      () =>
        addExistingWorkspaceUserByEmail(repositories, {
          ...input,
          targetEmail: "existing.user@example.test",
          role: "member",
          membershipId: "membership_disabled_context_add",
          auditEventId: "audit_disabled_context_add",
        }),
      assertAdminError("not_authorized"),
    );
    await assert.rejects(
      () =>
        reactivateWorkspaceMembership(repositories, {
          ...input,
          membershipId: "membership_member_example",
          auditEventId: "audit_disabled_context_reactivate",
        }),
      assertAdminError("not_authorized"),
    );
    await assert.rejects(
      () => listWorkspaceAuditEventsForAdmin(repositories, input),
      assertAdminError("not_authorized"),
    );
    assert.equal(records.auditEvents.length, 0);
    const targetMembership = records.memberships.find(
      (membership) => membership.id === "membership_member_example",
    );
    assert.equal(targetMembership?.status ?? "active", "active");
  }
});

test("audit event listing defaults and caps limits newest first", async () => {
  const { repositories, input } = adminFixture({
    auditEvents: Array.from({ length: 120 }, (_, index) =>
      auditEvent({
        id: `audit_${String(index).padStart(3, "0")}`,
        createdAt: new Date(Date.parse(now) + index * 1000).toISOString(),
      }),
    ),
  });

  const defaultResult = await listWorkspaceAuditEventsForAdmin(repositories, {
    ...input,
    limit: 0,
  });
  const cappedResult = await listWorkspaceAuditEventsForAdmin(repositories, {
    ...input,
    limit: 1000,
  });
  const smallResult = await listWorkspaceAuditEventsForAdmin(repositories, {
    ...input,
    limit: 3,
  });

  assert.equal(defaultResult.events.length, 50);
  assert.equal(cappedResult.events.length, 100);
  assert.deepEqual(
    smallResult.events.map((event) => event.eventId),
    ["audit_119", "audit_118", "audit_117"],
  );
});

test("add existing user rejects unsafe targets and roles without mutation", async () => {
  for (const [name, overrides, expectedCode] of [
    ["missing user", {}, "not_found"],
    ["user without provider identity", { extraUsers: [existingProviderBackedUser()] }, "not_found"],
    [
      "disabled user",
      {
        extraUsers: [existingProviderBackedUser({ status: "disabled" })],
        providerBackedUserIds: ["user_existing_example"],
      },
      "not_found",
    ],
    [
      "active member",
      {
        extraUsers: [existingProviderBackedUser()],
        providerBackedUserIds: ["user_existing_example"],
        extraMemberships: [
          {
            id: "membership_existing_user",
            workspaceId: "workspace_koncept_images",
            userId: "user_existing_example",
            role: "member",
            status: "active",
            createdAt: earlier,
            updatedAt: earlier,
          },
        ],
      },
      "membership_conflict",
    ],
    [
      "disabled member",
      {
        extraUsers: [existingProviderBackedUser()],
        providerBackedUserIds: ["user_existing_example"],
        extraMemberships: [
          {
            id: "membership_existing_user",
            workspaceId: "workspace_koncept_images",
            userId: "user_existing_example",
            role: "member",
            status: "disabled",
            createdAt: earlier,
            updatedAt: earlier,
          },
        ],
      },
      "membership_conflict",
    ],
    [
      "owner role",
      {
        extraUsers: [existingProviderBackedUser()],
        providerBackedUserIds: ["user_existing_example"],
        targetRole: "owner",
      },
      "invalid_role",
    ],
    [
      "invalid role",
      {
        extraUsers: [existingProviderBackedUser()],
        providerBackedUserIds: ["user_existing_example"],
        targetRole: "operator",
      },
      "invalid_role",
    ],
  ]) {
    const { repositories, input, records } = adminFixture(overrides);

    await assert.rejects(
      () =>
        addExistingWorkspaceUserByEmail(repositories, {
          ...input,
          targetEmail: "existing.user@example.test",
          role: overrides.targetRole ?? "member",
          membershipId: `membership_rejected_${name.replaceAll(" ", "_")}`,
          auditEventId: `audit_rejected_${name.replaceAll(" ", "_")}`,
        }),
      assertAdminError(expectedCode),
    );
    assert.equal(
      records.memberships.some((membership) =>
        membership.id.startsWith(`membership_rejected_${name.replaceAll(" ", "_")}`),
      ),
      false,
    );
    assert.equal(records.auditEvents.length, 0);
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

test("admin cannot manage owner memberships or grant owner role", async () => {
  for (const [name, action, assertUnchanged] of [
    [
      "demote owner",
      (repositories, input) =>
        changeWorkspaceMemberRole(repositories, {
          ...input,
          membershipId: "membership_owner_example",
          role: "admin",
          auditEventId: "audit_admin_demote_owner",
        }),
      (records) => {
        assert.equal(
          records.memberships.find((membership) => membership.id === "membership_owner_example")
            ?.role,
          "owner",
        );
      },
    ],
    [
      "promote member to owner",
      (repositories, input) =>
        changeWorkspaceMemberRole(repositories, {
          ...input,
          membershipId: "membership_member_example",
          role: "owner",
          auditEventId: "audit_admin_promote_owner",
        }),
      (records) => {
        assert.equal(
          records.memberships.find((membership) => membership.id === "membership_member_example")
            ?.role,
          "member",
        );
      },
    ],
    [
      "disable owner",
      (repositories, input) =>
        disableWorkspaceMembership(repositories, {
          ...input,
          membershipId: "membership_owner_example",
          auditEventId: "audit_admin_disable_owner",
        }),
      (records) => {
        assert.equal(
          records.memberships.find((membership) => membership.id === "membership_owner_example")
            ?.status,
          "active",
        );
      },
    ],
    [
      "reactivate owner",
      (repositories, input) =>
        reactivateWorkspaceMembership(repositories, {
          ...input,
          membershipId: "membership_owner_example",
          auditEventId: "audit_admin_reactivate_owner",
        }),
      (records) => {
        assert.equal(
          records.memberships.find((membership) => membership.id === "membership_owner_example")
            ?.status,
          "active",
        );
      },
    ],
  ]) {
    const { repositories, input, records } = adminFixture({ role: "admin" });

    await assert.rejects(
      () => action(repositories, input),
      assertAdminError("not_authorized"),
      name,
    );
    assertUnchanged(records);
    assert.equal(records.auditEvents.length, 0);
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

test("owner and admin can reactivate disabled non-owner membership", async () => {
  for (const role of ["owner", "admin"]) {
    const { repositories, input, records } = adminFixture({ role });

    await disableWorkspaceMembership(repositories, {
      ...input,
      membershipId: "membership_member_example",
      auditEventId: `audit_membership_disabled_${role}`,
    });

    const deniedWhileDisabled = await decidePlatformAppAccess(repositories, {
      sessionId: "session_member_example",
      selectedWorkspaceId: "workspace_koncept_images",
      appKey: "kqag",
      now,
    });
    assert.equal(deniedWhileDisabled.result, AccessDecisionResult.MembershipRequired);

    const result = await reactivateWorkspaceMembership(repositories, {
      ...input,
      membershipId: "membership_member_example",
      auditEventId: `audit_membership_reactivated_${role}`,
    });

    assert.equal(result.status, "active");
    assert.equal(
      records.memberships.find((membership) => membership.id === "membership_member_example")
        ?.status,
      "active",
    );
    assert.deepEqual(records.auditEvents.at(-1), {
      id: `audit_membership_reactivated_${role}`,
      workspaceId: "workspace_koncept_images",
      actorUserId: `user_${role}_example`,
      eventType: "workspace.membership.reactivated",
      targetType: "membership",
      targetId: "membership_member_example",
      createdAt: now,
      metadata: {
        previousRole: "member",
        previousStatus: "disabled",
        newStatus: "active",
        targetUserId: "user_member_example",
      },
    });
    assertAuditPrivacy(records.auditEvents.at(-1));

    const allowedAfterReactivation = await decidePlatformAppAccess(repositories, {
      sessionId: "session_member_example",
      selectedWorkspaceId: "workspace_koncept_images",
      appKey: "kqag",
      now,
    });
    assert.equal(allowedAfterReactivation.result, AccessDecisionResult.Allowed);
  }
});

test("membership reactivation rejects unsafe targets without mutation", async () => {
  for (const [name, overrides, membershipId, expectedCode] of [
    ["missing membership", {}, "membership_missing_example", "not_found"],
    [
      "already active membership",
      {},
      "membership_member_example",
      "membership_conflict",
    ],
    [
      "owner membership",
      {
        extraMemberships: [
          {
            id: "membership_disabled_owner_example",
            workspaceId: "workspace_koncept_images",
            userId: "user_member_example",
            role: "owner",
            status: "disabled",
            createdAt: earlier,
            updatedAt: earlier,
          },
        ],
      },
      "membership_disabled_owner_example",
      "invalid_role",
    ],
  ]) {
    const { repositories, input, records } = adminFixture(overrides);

    await assert.rejects(
      () =>
        reactivateWorkspaceMembership(repositories, {
          ...input,
          membershipId,
          auditEventId: `audit_reactivate_rejected_${name.replaceAll(" ", "_")}`,
        }),
      assertAdminError(expectedCode),
    );
    assert.equal(records.auditEvents.length, 0);
  }
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

test("owner and admin can manage future app entitlements through the generic service", async () => {
  const futureApp = {
    id: "app_ops_console",
    key: "ops_console",
    name: "Ops Console",
    status: "available",
    launchUrl: "https://apps.example.invalid/ops-console",
    createdAt: now,
    updatedAt: now,
  };

  for (const role of ["owner", "admin"]) {
    const { repositories, input, records } = adminFixture({
      role,
      apps: [futureApp],
      appEntitlements: [],
    });

    const created = await setWorkspaceAppEntitlementStatus(repositories, {
      ...input,
      appKey: futureApp.key,
      status: "enabled",
      entitlementId: `entitlement_ops_console_${role}`,
      auditEventId: `audit_ops_console_enabled_${role}`,
    });

    assert.equal(created.id, `entitlement_ops_console_${role}`);
    assert.equal(created.workspaceId, "workspace_koncept_images");
    assert.equal(created.appId, futureApp.id);
    assert.equal(created.status, "enabled");
    assert.deepEqual(records.auditEvents.at(-1), {
      id: `audit_ops_console_enabled_${role}`,
      workspaceId: "workspace_koncept_images",
      actorUserId: `user_${role}_example`,
      eventType: "workspace.app_entitlement.enabled",
      targetType: "app_entitlement",
      targetId: `entitlement_ops_console_${role}`,
      createdAt: now,
      metadata: {
        appId: futureApp.id,
        appKey: futureApp.key,
        previousStatus: null,
        newStatus: "enabled",
      },
    });
    assertAuditPrivacy(records.auditEvents.at(-1));

    const accessDecision = await decidePlatformAppAccess(repositories, {
      sessionId: "session_member_example",
      selectedWorkspaceId: "workspace_koncept_images",
      appKey: futureApp.key,
      now,
    });
    assert.equal(accessDecision.result, AccessDecisionResult.Allowed);
  }
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
  await assert.rejects(
    () =>
      addExistingWorkspaceUserByEmail(repositories, {
        ...input,
        targetEmail: "existing.user@example.test",
        role: "member",
        membershipId: "membership_missing_repo_add",
        auditEventId: "audit_missing_repo_add",
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

test("membership reactivation rolls back when audit append fails", async () => {
  const { repositories, input, records } = adminFixture({
    memberships: baseMemberships().map((membership) =>
      membership.id === "membership_member_example"
        ? { ...membership, status: "disabled" }
        : membership,
    ),
    failAuditAppend: true,
  });

  await assert.rejects(
    () =>
      reactivateWorkspaceMembership(repositories, {
        ...input,
        membershipId: "membership_member_example",
        auditEventId: "audit_reactivate_append_failure",
      }),
    assertAdminError("repository_failure"),
  );

  assert.equal(
    records.memberships.find((membership) => membership.id === "membership_member_example")
      ?.status,
    "disabled",
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

test("membership add rolls back when audit append fails", async () => {
  const { repositories, input, records } = adminFixture({
    extraUsers: [existingProviderBackedUser()],
    providerBackedUserIds: ["user_existing_example"],
    failAuditAppend: true,
  });

  await assert.rejects(
    () =>
      addExistingWorkspaceUserByEmail(repositories, {
        ...input,
        targetEmail: "existing.user@example.test",
        role: "member",
        membershipId: "membership_add_append_failure",
        auditEventId: "audit_add_append_failure",
      }),
    assertAdminError("repository_failure"),
  );

  assert.equal(
    records.memberships.some((membership) => membership.id === "membership_add_append_failure"),
    false,
  );
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
    users: overrides.users ?? [
      ...Object.values({ ...users, [role]: actorUser }),
      ...(overrides.extraUsers ?? []),
    ],
    providerIdentities: [
      {
        id: "provider_identity_private",
        userId: actorUser.id,
        providerKey: "example_oidc",
        providerSubject: "provider-token-raw-claim",
        createdAt: now,
        updatedAt: now,
      },
      ...(overrides.extraProviderIdentities ?? []),
    ],
    sessions: overrides.sessions ?? [session, memberSession],
    workspaces: overrides.workspaces ?? [workspace, otherWorkspace],
    memberships: [...memberships, ...(overrides.extraMemberships ?? [])],
    membershipApprovals: overrides.membershipApprovals ?? [],
    apps: overrides.apps ?? [app],
    appEntitlements: overrides.appEntitlements ?? [entitlement],
    auditEvents: overrides.auditEvents ?? [],
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
  if (overrides.providerBackedUserIds) {
    const providerBackedUserIds = new Set(overrides.providerBackedUserIds);
    const listForUser = repositories.providerIdentities.listForUser.bind(
      repositories.providerIdentities,
    );
    repositories.providerIdentities.listForUser = async (userId) => {
      if (providerBackedUserIds.has(userId)) {
        return [{ userId }];
      }
      return listForUser(userId);
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

function existingProviderBackedUser(overrides = {}) {
  return {
    id: "user_existing_example",
    email: "existing.user@example.test",
    displayName: "Existing User",
    status: "active",
    createdAt: earlier,
    updatedAt: earlier,
    lastLoginAt: now,
    ...overrides,
  };
}

function auditEvent(overrides = {}) {
  return {
    id: "audit_event_example",
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
    ...overrides,
  };
}

function pendingApproval(overrides = {}) {
  return {
    id: "approval_pending_example",
    workspaceId: "workspace_koncept_images",
    email: "pending.user@example.test",
    role: "member",
    status: "pending",
    requestedByUserId: "user_owner_example",
    createdAt: earlier,
    updatedAt: earlier,
    acceptedAt: null,
    revokedAt: null,
    acceptedUserId: null,
    revokedByUserId: null,
    ...overrides,
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
  const serialized = JSON.stringify(event).replace(
    /"actorEmail":"[^"]+"/g,
    '"actorEmail":"[safe-actor-email]"',
  );
  assert.doesNotMatch(serialized, /provider-token|raw-claim|oauth|cookie|secret/i);
  assert.doesNotMatch(serialized, /postgresql:\/\/private-host|select \*/i);
}
