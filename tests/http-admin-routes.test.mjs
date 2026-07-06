import assert from "node:assert/strict";
import test from "node:test";

import { handleNodePlatformHttpRequest } from "../dist/index.js";
import { createInMemoryPlatformRepositories } from "./helpers/in-memory-platform-repositories.mjs";

const now = "2026-06-27T00:00:00.000Z";
const earlier = "2026-06-26T23:00:00.000Z";
const future = "2026-06-27T01:00:00.000Z";
const past = "2026-06-26T22:00:00.000Z";
const allowedOrigin = "https://platform.example.test";
const validCsrfToken = "csrf-token-valid-example";
const privateStorageError =
  "database exploded postgresql://private-host raw-session-token provider-token select *";

test("owner and admin can list workspace members through admin route", async () => {
  for (const role of ["owner", "admin"]) {
    const fixture = createAdminRouteFixture();

    const { response, body } = await request({
      method: "GET",
      url: "/api/platform/workspaces/workspace_koncept_images/members",
      headers: sessionHeaders(role),
      dependencies: fixture.dependencies,
    });

    assert.equal(response.statusCode, 200);
    assertNoStoreHeaders(response.headers);
    assert.equal(body.outcome, "listed");
    assert.equal(body.workspaceId, "workspace_koncept_images");
    assert.deepEqual(
      body.members.map((member) => ({
        membershipId: member.membershipId,
        role: member.role,
        status: member.status,
        email: member.user.email,
      })),
      [
        {
          membershipId: "membership_owner_example",
          role: "owner",
          status: "active",
          email: "owner@example.test",
        },
        {
          membershipId: "membership_admin_example",
          role: "admin",
          status: "active",
          email: "admin@example.test",
        },
        {
          membershipId: "membership_member_example",
          role: "member",
          status: "active",
          email: "member@example.test",
        },
        {
          membershipId: "membership_viewer_example",
          role: "viewer",
          status: "active",
          email: "viewer@example.test",
        },
      ],
    );
    assert.equal(fixture.calls.csrfValidate, 0);
    assertResponseIsPrivacySafe(response);
  }
});

test("member and viewer cannot list or mutate workspace admin routes", async () => {
  for (const role of ["member", "viewer"]) {
    const fixture = createAdminRouteFixture({
      membershipApprovals: [pendingApproval()],
    });

    const list = await request({
      method: "GET",
      url: "/api/platform/workspaces/workspace_koncept_images/members",
      headers: sessionHeaders(role),
      dependencies: fixture.dependencies,
    });
    const mutate = await request({
      method: "POST",
      url: "/api/platform/workspaces/workspace_koncept_images/members/membership_viewer_example/role?role=member",
      headers: secureSessionHeaders(role),
      dependencies: fixture.dependencies,
    });
    const reactivate = await request({
      method: "POST",
      url: "/api/platform/workspaces/workspace_koncept_images/members/membership_member_example/reactivate",
      headers: secureSessionHeaders(role),
      dependencies: fixture.dependencies,
    });
    const remove = await request({
      method: "POST",
      url: "/api/platform/workspaces/workspace_koncept_images/members/membership_member_example/remove",
      headers: secureSessionHeaders(role),
      dependencies: fixture.dependencies,
    });
    const add = await request({
      method: "POST",
      url: "/api/platform/workspaces/workspace_koncept_images/members/add?email=existing.user%40example.test&role=member",
      headers: secureSessionHeaders(role),
      dependencies: fixture.dependencies,
    });
    const approvalList = await request({
      method: "GET",
      url: "/api/platform/workspaces/workspace_koncept_images/member-approvals",
      headers: sessionHeaders(role),
      dependencies: fixture.dependencies,
    });
    const approvalRevoke = await request({
      method: "POST",
      url: "/api/platform/workspaces/workspace_koncept_images/member-approvals/approval_pending_example/revoke",
      headers: secureSessionHeaders(role),
      dependencies: fixture.dependencies,
    });

    assert.equal(list.response.statusCode, 403);
    assert.deepEqual(list.body, {
      outcome: "denied",
      reason: "not_authorized",
    });
    assert.equal(mutate.response.statusCode, 403);
    assert.deepEqual(mutate.body, {
      outcome: "denied",
      reason: "not_authorized",
    });
    assert.equal(reactivate.response.statusCode, 403);
    assert.deepEqual(reactivate.body, {
      outcome: "denied",
      reason: "not_authorized",
    });
    assert.equal(remove.response.statusCode, 403);
    assert.deepEqual(remove.body, {
      outcome: "denied",
      reason: "not_authorized",
    });
    assert.equal(add.response.statusCode, 403);
    assert.deepEqual(add.body, {
      outcome: "denied",
      reason: "not_authorized",
    });
    assert.equal(approvalList.response.statusCode, 403);
    assert.deepEqual(approvalList.body, {
      outcome: "denied",
      reason: "not_authorized",
    });
    assert.equal(approvalRevoke.response.statusCode, 403);
    assert.deepEqual(approvalRevoke.body, {
      outcome: "denied",
      reason: "not_authorized",
    });
    assert.equal(
      fixture.records.memberships.find((membership) => membership.id === "membership_viewer_example")
        ?.role,
      "viewer",
    );
    assert.deepEqual(fixture.records.membershipApprovals, [pendingApproval()]);
    assert.equal(fixture.records.auditEvents.length, 0);
    assertResponseIsPrivacySafe(list.response);
    assertResponseIsPrivacySafe(mutate.response);
    assertResponseIsPrivacySafe(reactivate.response);
    assertResponseIsPrivacySafe(remove.response);
    assertResponseIsPrivacySafe(add.response);
    assertResponseIsPrivacySafe(approvalList.response);
    assertResponseIsPrivacySafe(approvalRevoke.response);
  }
});

test("removed admin existing session cannot list workspace admin data", async () => {
  const fixture = createAdminRouteFixture({
    memberships: baseMemberships().filter(
      (membership) => membership.id !== "membership_admin_example",
    ),
  });

  const { response, body } = await request({
    method: "GET",
    url: "/api/platform/workspaces/workspace_koncept_images/members",
    headers: sessionHeaders("admin"),
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 403);
  assert.deepEqual(body, {
    outcome: "denied",
    reason: "not_authorized",
  });
  assertResponseIsPrivacySafe(response);
});

test("missing expired revoked or disabled admin context fails closed", async () => {
  const cases = [
    [{}, 401, { outcome: "denied", reason: "missing_session" }],
    [
      sessionHeaders("owner"),
      403,
      { outcome: "denied", reason: "not_authorized" },
      { session: { expiresAt: past } },
    ],
    [
      sessionHeaders("owner"),
      403,
      { outcome: "denied", reason: "not_authorized" },
      { session: { revokedAt: earlier } },
    ],
    [
      sessionHeaders("owner"),
      403,
      { outcome: "denied", reason: "not_authorized" },
      { actorMembership: { status: "disabled" } },
    ],
    [
      sessionHeaders("owner"),
      403,
      { outcome: "denied", reason: "not_authorized" },
      { userByRole: { owner: { status: "disabled" } } },
    ],
    [
      sessionHeaders("owner"),
      403,
      { outcome: "denied", reason: "not_authorized" },
      { workspace: { status: "suspended" } },
    ],
    [
      sessionHeaders("owner"),
      403,
      { outcome: "denied", reason: "not_authorized" },
      { memberships: [] },
    ],
  ];

  for (const [headers, statusCode, expectedBody, overrides = {}] of cases) {
    const fixture = createAdminRouteFixture(overrides);

    const { response, body } = await request({
      method: "GET",
      url: "/api/platform/workspaces/workspace_koncept_images/app-entitlements",
      headers,
      dependencies: fixture.dependencies,
    });

    assert.equal(response.statusCode, statusCode);
    assert.deepEqual(body, expectedBody);
    assertResponseIsPrivacySafe(response);
  }
});

test("owner and admin can list workspace audit events through admin route", async () => {
  for (const role of ["owner", "admin"]) {
    const fixture = createAdminRouteFixture({
      extraUsers: [existingProviderBackedUser()],
      auditEvents: [
        auditEvent({
          id: "audit_old",
          eventType: "workspace.membership.added",
          targetId: "membership_http_1",
          createdAt: earlier,
          metadata: {
            newRole: "member",
            newStatus: "active",
            targetUserId: "user_existing_example",
            source: "existing_provider_backed_user",
            privateProviderValue: "raw-provider-claim-subject",
          },
        }),
        auditEvent({
          id: "audit_new",
          eventType: "workspace.app_entitlement.enabled",
          targetType: "app_entitlement",
          targetId: "entitlement_koncept_kqag",
          createdAt: now,
          metadata: {
            appId: "app_kqag",
            appKey: "kqag",
            previousStatus: "disabled",
            newStatus: "enabled",
            cookie: "raw-session-token",
          },
        }),
        auditEvent({
          id: "audit_reactivated",
          eventType: "workspace.membership.reactivated",
          targetId: "membership_member_example",
          createdAt: future,
          metadata: {
            previousRole: "member",
            previousStatus: "disabled",
            newStatus: "active",
            targetUserId: "user_member_example",
            providerSubject: "raw-provider-subject",
            cookie: "raw-session-token",
          },
        }),
      ],
    });

    const { response, body } = await request({
      method: "GET",
      url: "/api/platform/workspaces/workspace_koncept_images/audit-events?limit=50",
      headers: sessionHeaders(role),
      dependencies: fixture.dependencies,
    });

    assert.equal(response.statusCode, 200);
    assertNoStoreHeaders(response.headers);
    assert.deepEqual(body, {
      outcome: "listed",
      workspaceId: "workspace_koncept_images",
      events: [
        {
          eventId: "audit_reactivated",
          workspaceId: "workspace_koncept_images",
          actorUserId: "user_owner_example",
          actorDisplayName: "Owner Example",
          actorEmail: "owner@example.test",
          eventType: "workspace.membership.reactivated",
          targetType: "membership",
          targetId: "membership_member_example",
          targetLabel: "Member Example",
          createdAt: future,
          metadata: {
            previousRole: "member",
            previousStatus: "disabled",
            newStatus: "active",
            targetUserId: "user_member_example",
          },
        },
        {
          eventId: "audit_new",
          workspaceId: "workspace_koncept_images",
          actorUserId: "user_owner_example",
          actorDisplayName: "Owner Example",
          actorEmail: "owner@example.test",
          eventType: "workspace.app_entitlement.enabled",
          targetType: "app_entitlement",
          targetId: "entitlement_koncept_kqag",
          targetLabel: "KQAG access",
          createdAt: now,
          metadata: {
            appId: "app_kqag",
            appKey: "kqag",
            previousStatus: "disabled",
            newStatus: "enabled",
          },
        },
        {
          eventId: "audit_old",
          workspaceId: "workspace_koncept_images",
          actorUserId: "user_owner_example",
          actorDisplayName: "Owner Example",
          actorEmail: "owner@example.test",
          eventType: "workspace.membership.added",
          targetType: "membership",
          targetId: "membership_http_1",
          targetLabel: "Existing User",
          createdAt: earlier,
          metadata: {
            newRole: "member",
            newStatus: "active",
            targetUserId: "user_existing_example",
            source: "existing_provider_backed_user",
          },
        },
      ],
    });
    assert.equal(fixture.calls.csrfValidate, 0);
    assertResponseIsPrivacySafe(response);
  }
});

test("workspace audit event route fails closed and does not require CSRF", async () => {
  for (const role of ["member", "viewer"]) {
    const fixture = createAdminRouteFixture();

    const { response, body } = await request({
      method: "GET",
      url: "/api/platform/workspaces/workspace_koncept_images/audit-events",
      headers: sessionHeaders(role),
      dependencies: fixture.dependencies,
    });

    assert.equal(response.statusCode, 403);
    assert.deepEqual(body, {
      outcome: "denied",
      reason: "not_authorized",
    });
    assert.equal(fixture.calls.csrfValidate, 0);
    assertResponseIsPrivacySafe(response);
  }

  const missing = await request({
    method: "GET",
    url: "/api/platform/workspaces/workspace_koncept_images/audit-events",
    dependencies: createAdminRouteFixture().dependencies,
  });
  assert.equal(missing.response.statusCode, 401);
  assert.deepEqual(missing.body, {
    outcome: "denied",
    reason: "missing_session",
  });
});

test("workspace audit event route enforces default and max limits", async () => {
  const fixture = createAdminRouteFixture({
    auditEvents: Array.from({ length: 120 }, (_, index) =>
      auditEvent({
        id: `audit_${String(index).padStart(3, "0")}`,
        createdAt: new Date(Date.parse(now) + index * 1000).toISOString(),
      }),
    ),
  });

  const invalid = await request({
    method: "GET",
    url: "/api/platform/workspaces/workspace_koncept_images/audit-events?limit=0",
    headers: sessionHeaders("owner"),
    dependencies: fixture.dependencies,
  });
  const capped = await request({
    method: "GET",
    url: "/api/platform/workspaces/workspace_koncept_images/audit-events?limit=1000",
    headers: sessionHeaders("owner"),
    dependencies: fixture.dependencies,
  });
  const small = await request({
    method: "GET",
    url: "/api/platform/workspaces/workspace_koncept_images/audit-events?limit=3",
    headers: sessionHeaders("owner"),
    dependencies: fixture.dependencies,
  });

  assert.equal(invalid.body.events.length, 50);
  assert.equal(capped.body.events.length, 100);
  assert.deepEqual(
    small.body.events.map((event) => event.eventId),
    ["audit_119", "audit_118", "audit_117"],
  );
  assert.equal(fixture.calls.csrfValidate, 0);
});

test("state-changing admin routes validate Origin and CSRF before mutation", async () => {
  const missingOrigin = createAdminRouteFixture();
  const roleWithoutOrigin = await request({
    method: "POST",
    url: "/api/platform/workspaces/workspace_koncept_images/members/membership_viewer_example/role?role=member",
    headers: {
      cookie: "swooshz_session=session_owner_example",
      "x-csrf-token": validCsrfToken,
    },
    dependencies: missingOrigin.dependencies,
  });
  const missingCsrf = createAdminRouteFixture();
  const disableWithoutCsrf = await request({
    method: "POST",
    url: "/api/platform/workspaces/workspace_koncept_images/members/membership_member_example/disable",
    headers: {
      origin: allowedOrigin,
      cookie: "swooshz_session=session_owner_example",
    },
    dependencies: missingCsrf.dependencies,
  });
  const reactivateWithoutOriginFixture = createAdminRouteFixture({
    memberships: baseMemberships().map((membership) =>
      membership.id === "membership_member_example"
        ? { ...membership, status: "disabled" }
        : membership,
    ),
  });
  const reactivateWithoutOrigin = await request({
    method: "POST",
    url: "/api/platform/workspaces/workspace_koncept_images/members/membership_member_example/reactivate",
    headers: {
      cookie: "swooshz_session=session_owner_example",
      "x-csrf-token": validCsrfToken,
    },
    dependencies: reactivateWithoutOriginFixture.dependencies,
  });
  const invalidCsrf = createAdminRouteFixture({ csrfValid: false });
  const entitlementWithInvalidCsrf = await request({
    method: "POST",
    url: "/api/platform/workspaces/workspace_koncept_images/app-entitlements/kqag/status?status=disabled",
    headers: secureSessionHeaders("owner"),
    dependencies: invalidCsrf.dependencies,
  });
  const addWithoutOriginFixture = createAdminRouteFixture({
    extraUsers: [existingProviderBackedUser()],
    providerBackedUserIds: ["user_existing_example"],
  });
  const addWithoutOrigin = await request({
    method: "POST",
    url: "/api/platform/workspaces/workspace_koncept_images/members/add?email=existing.user%40example.test&role=member",
    headers: {
      cookie: "swooshz_session=session_owner_example",
      "x-csrf-token": validCsrfToken,
    },
    dependencies: addWithoutOriginFixture.dependencies,
  });
  const revokeWithoutOriginFixture = createAdminRouteFixture({
    membershipApprovals: [pendingApproval()],
  });
  const revokeWithoutOrigin = await request({
    method: "POST",
    url: "/api/platform/workspaces/workspace_koncept_images/member-approvals/approval_pending_example/revoke",
    headers: {
      cookie: "swooshz_session=session_owner_example",
      "x-csrf-token": validCsrfToken,
    },
    dependencies: revokeWithoutOriginFixture.dependencies,
  });
  const revokeWithoutCsrfFixture = createAdminRouteFixture({
    membershipApprovals: [pendingApproval()],
  });
  const revokeWithoutCsrf = await request({
    method: "POST",
    url: "/api/platform/workspaces/workspace_koncept_images/member-approvals/approval_pending_example/revoke",
    headers: {
      origin: allowedOrigin,
      cookie: "swooshz_session=session_owner_example",
    },
    dependencies: revokeWithoutCsrfFixture.dependencies,
  });
  const revokeInvalidCsrfFixture = createAdminRouteFixture({
    membershipApprovals: [pendingApproval()],
    csrfValid: false,
  });
  const revokeWithInvalidCsrf = await request({
    method: "POST",
    url: "/api/platform/workspaces/workspace_koncept_images/member-approvals/approval_pending_example/revoke",
    headers: secureSessionHeaders("owner"),
    dependencies: revokeInvalidCsrfFixture.dependencies,
  });

  assert.equal(roleWithoutOrigin.response.statusCode, 403);
  assert.deepEqual(roleWithoutOrigin.body, {
    outcome: "denied",
    reason: "missing_origin",
  });
  assert.equal(missingOrigin.calls.csrfValidate, 0);
  assert.equal(
    missingOrigin.records.memberships.find((membership) => membership.id === "membership_viewer_example")
      ?.role,
    "viewer",
  );
  assert.equal(missingOrigin.records.auditEvents.length, 0);
  assert.equal(disableWithoutCsrf.response.statusCode, 403);
  assert.deepEqual(disableWithoutCsrf.body, {
    outcome: "denied",
    reason: "missing_csrf_token",
  });
  assert.equal(missingCsrf.calls.csrfValidate, 0);
  assert.equal(
    missingCsrf.records.memberships.find((membership) => membership.id === "membership_member_example")
      ?.status,
    "active",
  );
  assert.equal(missingCsrf.records.auditEvents.length, 0);
  assert.equal(reactivateWithoutOrigin.response.statusCode, 403);
  assert.deepEqual(reactivateWithoutOrigin.body, {
    outcome: "denied",
    reason: "missing_origin",
  });
  assert.equal(reactivateWithoutOriginFixture.calls.csrfValidate, 0);
  assert.equal(
    reactivateWithoutOriginFixture.records.memberships.find(
      (membership) => membership.id === "membership_member_example",
    )?.status,
    "disabled",
  );
  assert.equal(reactivateWithoutOriginFixture.records.auditEvents.length, 0);
  assert.equal(entitlementWithInvalidCsrf.response.statusCode, 403);
  assert.deepEqual(entitlementWithInvalidCsrf.body, {
    outcome: "denied",
    reason: "invalid_csrf_token",
  });
  assert.equal(invalidCsrf.calls.csrfValidate, 1);
  assert.equal(invalidCsrf.records.appEntitlements[0]?.status, "enabled");
  assert.equal(invalidCsrf.records.auditEvents.length, 0);
  assert.equal(addWithoutOrigin.response.statusCode, 403);
  assert.deepEqual(addWithoutOrigin.body, {
    outcome: "denied",
    reason: "missing_origin",
  });
  assert.equal(Object.hasOwn(addWithoutOrigin.body, "message"), false);
  assert.equal(addWithoutOriginFixture.calls.csrfValidate, 0);
  assert.equal(
    addWithoutOriginFixture.records.memberships.some(
      (membership) => membership.userId === "user_existing_example",
    ),
    false,
  );
  assert.equal(addWithoutOriginFixture.records.auditEvents.length, 0);
  assert.equal(revokeWithoutOrigin.response.statusCode, 403);
  assert.deepEqual(revokeWithoutOrigin.body, {
    outcome: "denied",
    reason: "missing_origin",
  });
  assert.equal(Object.hasOwn(revokeWithoutOrigin.body, "message"), false);
  assert.equal(revokeWithoutOriginFixture.calls.csrfValidate, 0);
  assert.deepEqual(revokeWithoutOriginFixture.records.membershipApprovals, [
    pendingApproval(),
  ]);
  assert.equal(revokeWithoutOriginFixture.records.auditEvents.length, 0);
  assert.equal(revokeWithoutCsrf.response.statusCode, 403);
  assert.deepEqual(revokeWithoutCsrf.body, {
    outcome: "denied",
    reason: "missing_csrf_token",
  });
  assert.equal(Object.hasOwn(revokeWithoutCsrf.body, "message"), false);
  assert.equal(revokeWithoutCsrfFixture.calls.csrfValidate, 0);
  assert.deepEqual(revokeWithoutCsrfFixture.records.membershipApprovals, [
    pendingApproval(),
  ]);
  assert.equal(revokeWithoutCsrfFixture.records.auditEvents.length, 0);
  assert.equal(revokeWithInvalidCsrf.response.statusCode, 403);
  assert.deepEqual(revokeWithInvalidCsrf.body, {
    outcome: "denied",
    reason: "invalid_csrf_token",
  });
  assert.equal(Object.hasOwn(revokeWithInvalidCsrf.body, "message"), false);
  assert.equal(revokeInvalidCsrfFixture.calls.csrfValidate, 1);
  assert.deepEqual(revokeInvalidCsrfFixture.records.membershipApprovals, [
    pendingApproval(),
  ]);
  assert.equal(revokeInvalidCsrfFixture.records.auditEvents.length, 0);
  assertResponseIsPrivacySafe(revokeWithoutOrigin.response);
  assertResponseIsPrivacySafe(revokeWithoutCsrf.response);
  assertResponseIsPrivacySafe(revokeWithInvalidCsrf.response);
});

test("membership removal route validates Origin and CSRF before mutation", async () => {
  const withoutOriginFixture = createAdminRouteFixture();
  const withoutOrigin = await request({
    method: "POST",
    url: "/api/platform/workspaces/workspace_koncept_images/members/membership_member_example/remove",
    headers: {
      cookie: "swooshz_session=session_owner_example",
      "x-csrf-token": validCsrfToken,
    },
    dependencies: withoutOriginFixture.dependencies,
  });
  const withoutCsrfFixture = createAdminRouteFixture();
  const withoutCsrf = await request({
    method: "POST",
    url: "/api/platform/workspaces/workspace_koncept_images/members/membership_member_example/remove",
    headers: {
      origin: allowedOrigin,
      cookie: "swooshz_session=session_owner_example",
    },
    dependencies: withoutCsrfFixture.dependencies,
  });
  const invalidCsrfFixture = createAdminRouteFixture({ csrfValid: false });
  const invalidCsrf = await request({
    method: "POST",
    url: "/api/platform/workspaces/workspace_koncept_images/members/membership_member_example/remove",
    headers: secureSessionHeaders("owner"),
    dependencies: invalidCsrfFixture.dependencies,
  });

  assert.equal(withoutOrigin.response.statusCode, 403);
  assert.deepEqual(withoutOrigin.body, {
    outcome: "denied",
    reason: "missing_origin",
  });
  assert.equal(withoutOriginFixture.calls.csrfValidate, 0);
  assert.equal(
    withoutOriginFixture.records.memberships.some(
      (membership) => membership.id === "membership_member_example",
    ),
    true,
  );
  assert.equal(withoutOriginFixture.records.auditEvents.length, 0);

  assert.equal(withoutCsrf.response.statusCode, 403);
  assert.deepEqual(withoutCsrf.body, {
    outcome: "denied",
    reason: "missing_csrf_token",
  });
  assert.equal(withoutCsrfFixture.calls.csrfValidate, 0);
  assert.equal(
    withoutCsrfFixture.records.memberships.some(
      (membership) => membership.id === "membership_member_example",
    ),
    true,
  );
  assert.equal(withoutCsrfFixture.records.auditEvents.length, 0);

  assert.equal(invalidCsrf.response.statusCode, 403);
  assert.deepEqual(invalidCsrf.body, {
    outcome: "denied",
    reason: "invalid_csrf_token",
  });
  assert.equal(invalidCsrfFixture.calls.csrfValidate, 1);
  assert.equal(
    invalidCsrfFixture.records.memberships.some(
      (membership) => membership.id === "membership_member_example",
    ),
    true,
  );
  assert.equal(invalidCsrfFixture.records.auditEvents.length, 0);
  assertResponseIsPrivacySafe(withoutOrigin.response);
  assertResponseIsPrivacySafe(withoutCsrf.response);
  assertResponseIsPrivacySafe(invalidCsrf.response);
});

test("owner and admin can add an existing provider-backed user through admin route", async () => {
  for (const role of ["owner", "admin"]) {
    const fixture = createAdminRouteFixture({
      extraUsers: [existingProviderBackedUser()],
      providerBackedUserIds: ["user_existing_example"],
    });

    const { response, body } = await request({
      method: "POST",
      url: "/api/platform/workspaces/workspace_koncept_images/members/add?email=%20Existing.User%40Example.Test%20&role=member",
      headers: secureSessionHeaders(role),
      dependencies: fixture.dependencies,
    });

    assert.equal(response.statusCode, 201);
    assertNoStoreHeaders(response.headers);
    assert.deepEqual(body, {
      outcome: "created",
      membership: {
        membershipId: "membership_http_1",
        userId: "user_existing_example",
        workspaceId: "workspace_koncept_images",
        role: "member",
        status: "active",
        updatedAt: now,
      },
    });
    assert.equal(fixture.calls.csrfValidate, 1);
    assert.equal(
      fixture.records.memberships.find((membership) => membership.id === "membership_http_1")
        ?.userId,
      "user_existing_example",
    );
    assert.deepEqual(fixture.records.auditEvents.at(-1), {
      id: "audit_http_1",
      workspaceId: "workspace_koncept_images",
      actorUserId: `user_${role}_example`,
      eventType: "workspace.membership.added",
      targetType: "membership",
      targetId: "membership_http_1",
      createdAt: now,
      metadata: {
        newRole: "member",
        newStatus: "active",
        targetUserId: "user_existing_example",
        source: "existing_provider_backed_user",
      },
    });
    assertResponseIsPrivacySafe(response);
    assertResponseIsPrivacySafe({ body: fixture.records.auditEvents.at(-1) });
  }
});

test("owner and admin can create list and revoke pending approvals through admin routes", async () => {
  for (const role of ["owner", "admin"]) {
    const fixture = createAdminRouteFixture();

    const created = await request({
      method: "POST",
      url: "/api/platform/workspaces/workspace_koncept_images/members/add?email=%20New.Teammate%40Example.Test%20&role=viewer",
      headers: secureSessionHeaders(role),
      dependencies: fixture.dependencies,
    });
    const listed = await request({
      method: "GET",
      url: "/api/platform/workspaces/workspace_koncept_images/member-approvals",
      headers: sessionHeaders(role),
      dependencies: fixture.dependencies,
    });
    const revoked = await request({
      method: "POST",
      url: "/api/platform/workspaces/workspace_koncept_images/member-approvals/approval_http_1/revoke",
      headers: secureSessionHeaders(role),
      dependencies: fixture.dependencies,
    });

    assert.equal(created.response.statusCode, 201);
    assertNoStoreHeaders(created.response.headers);
    assert.deepEqual(created.body, {
      outcome: "pending_approval_created",
      approval: {
        approvalId: "approval_http_1",
        workspaceId: "workspace_koncept_images",
        email: "new.teammate@example.test",
        role: "viewer",
        status: "pending",
        createdAt: now,
        updatedAt: now,
      },
    });
    assert.equal(
      fixture.records.memberships.some((membership) =>
        membership.id.startsWith("membership_http_"),
      ),
      false,
    );
    assert.deepEqual(listed.body, {
      outcome: "listed",
      workspaceId: "workspace_koncept_images",
      approvals: [created.body.approval],
    });
    assert.equal(revoked.response.statusCode, 200);
    assert.deepEqual(revoked.body, {
      outcome: "revoked",
      approval: {
        ...created.body.approval,
        status: "revoked",
        updatedAt: now,
        revokedAt: now,
      },
    });
    assert.deepEqual(
      fixture.records.auditEvents.map((event) => event.eventType),
      [
        "workspace.membership_approval.created",
        "workspace.membership_approval.revoked",
      ],
    );
    assert.equal(fixture.calls.csrfValidate, 2);
    assertResponseIsPrivacySafe(created.response);
    assertResponseIsPrivacySafe(listed.response);
    assertResponseIsPrivacySafe(revoked.response);
  }
});

test("add existing user route returns safe operator guidance without mutation", async () => {
  const guidance =
    "Access request could not be recorded. Check the email and role, then try again.";

  for (const [name, overrides, query, expectedStatus, expectedMessage] of [
    [
      "target without provider identity",
      { extraUsers: [existingProviderBackedUser()] },
      "email=existing.user%40example.test&role=member",
      201,
      "Pending approval created. The teammate can sign in with that Google account to activate access.",
    ],
    [
      "disabled target",
      {
        extraUsers: [existingProviderBackedUser({ status: "disabled" })],
        providerBackedUserIds: ["user_existing_example"],
      },
      "email=existing.user%40example.test&role=member",
      404,
      guidance,
    ],
    [
      "existing membership",
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
      "email=existing.user%40example.test&role=member",
      409,
      "User is already a member of this workspace.",
    ],
    [
      "invalid role",
      {
        extraUsers: [existingProviderBackedUser()],
        providerBackedUserIds: ["user_existing_example"],
      },
      "email=existing.user%40example.test&role=owner",
      400,
      "Selected role is not allowed.",
    ],
    [
      "duplicate pending approval",
      {
        membershipApprovals: [
          pendingApproval({
            id: "approval_existing_pending",
            email: "existing.user@example.test",
          }),
        ],
      },
      "email=existing.user%40example.test&role=member",
      409,
      "Pending approval already exists for this email.",
    ],
  ]) {
    const fixture = createAdminRouteFixture(overrides);

    const { response, body } = await request({
      method: "POST",
      url: `/api/platform/workspaces/workspace_koncept_images/members/add?${query}`,
      headers: secureSessionHeaders("owner"),
      dependencies: fixture.dependencies,
    });

    assert.equal(response.statusCode, expectedStatus, name);
    if (expectedStatus === 201) {
      assert.deepEqual(body, {
        outcome: "pending_approval_created",
        approval: {
          approvalId: "approval_http_1",
          workspaceId: "workspace_koncept_images",
          email: "existing.user@example.test",
          role: "member",
          status: "pending",
          createdAt: now,
          updatedAt: now,
        },
      });
      assert.equal(fixture.records.auditEvents.length, 1);
    } else {
      assert.deepEqual(body, {
        outcome: "error",
        message: expectedMessage,
      });
      assertAdminMessagePrivacySafe(body.message);
      assert.equal(
        fixture.records.memberships.some((membership) => membership.id === "membership_http_1"),
        false,
      );
      assert.equal(fixture.records.auditEvents.length, 0);
    }
    assertResponseIsPrivacySafe(response);
  }
});

test("audit append failure through add existing user route rolls back membership creation", async () => {
  const fixture = createAdminRouteFixture({
    extraUsers: [existingProviderBackedUser()],
    providerBackedUserIds: ["user_existing_example"],
    failAuditAppend: true,
  });

  const { response, body } = await request({
    method: "POST",
    url: "/api/platform/workspaces/workspace_koncept_images/members/add?email=existing.user%40example.test&role=member",
    headers: secureSessionHeaders("owner"),
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 500);
  assert.deepEqual(body, {
    outcome: "error",
    message: "Workspace admin action could not be completed.",
  });
  assertAdminMessagePrivacySafe(body.message);
  assert.equal(
    fixture.records.memberships.some((membership) => membership.id === "membership_http_1"),
    false,
  );
  assert.equal(fixture.records.auditEvents.length, 0);
  assertResponseIsPrivacySafe(response);
});

test("audit append failure through pending approval create route rolls back approval creation", async () => {
  const fixture = createAdminRouteFixture({ failAuditAppend: true });

  const { response, body } = await request({
    method: "POST",
    url: "/api/platform/workspaces/workspace_koncept_images/members/add?email=new.teammate%40example.test&role=member",
    headers: secureSessionHeaders("owner"),
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 500);
  assert.deepEqual(body, {
    outcome: "error",
    message: "Workspace admin action could not be completed.",
  });
  assertAdminMessagePrivacySafe(body.message);
  assert.deepEqual(fixture.records.membershipApprovals, []);
  assert.equal(
    fixture.records.memberships.some((membership) => membership.id === "membership_http_1"),
    false,
  );
  assert.equal(fixture.records.auditEvents.length, 0);
  assertResponseIsPrivacySafe(response);
});

test("audit append failure through approval revoke route rolls back status change", async () => {
  const fixture = createAdminRouteFixture({
    membershipApprovals: [pendingApproval()],
    failAuditAppend: true,
  });

  const { response, body } = await request({
    method: "POST",
    url: "/api/platform/workspaces/workspace_koncept_images/member-approvals/approval_pending_example/revoke",
    headers: secureSessionHeaders("owner"),
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 500);
  assert.deepEqual(body, {
    outcome: "error",
    message: "Workspace admin action could not be completed.",
  });
  assertAdminMessagePrivacySafe(body.message);
  assert.deepEqual(fixture.records.membershipApprovals, [pendingApproval()]);
  assert.equal(fixture.records.auditEvents.length, 0);
  assertResponseIsPrivacySafe(response);
});

test("owner can change role disable and reactivate membership through admin routes", async () => {
  const fixture = createAdminRouteFixture();

  const roleChange = await request({
    method: "POST",
    url: "/api/platform/workspaces/workspace_koncept_images/members/membership_viewer_example/role?role=member",
    headers: secureSessionHeaders("owner"),
    dependencies: fixture.dependencies,
  });
  const disable = await request({
    method: "POST",
    url: "/api/platform/workspaces/workspace_koncept_images/members/membership_member_example/disable",
    headers: secureSessionHeaders("owner"),
    dependencies: fixture.dependencies,
  });
  const reactivate = await request({
    method: "POST",
    url: "/api/platform/workspaces/workspace_koncept_images/members/membership_member_example/reactivate",
    headers: secureSessionHeaders("owner"),
    dependencies: fixture.dependencies,
  });

  assert.equal(roleChange.response.statusCode, 200);
  assert.deepEqual(roleChange.body, {
    outcome: "updated",
    membership: {
      membershipId: "membership_viewer_example",
      userId: "user_viewer_example",
      workspaceId: "workspace_koncept_images",
      role: "member",
      status: "active",
      updatedAt: now,
    },
  });
  assert.equal(disable.response.statusCode, 200);
  assert.equal(disable.body.membership.membershipId, "membership_member_example");
  assert.equal(disable.body.membership.status, "disabled");
  assert.equal(reactivate.response.statusCode, 200);
  assert.deepEqual(reactivate.body, {
    outcome: "updated",
    membership: {
      membershipId: "membership_member_example",
      userId: "user_member_example",
      workspaceId: "workspace_koncept_images",
      role: "member",
      status: "active",
      updatedAt: now,
    },
  });
  assert.deepEqual(
    fixture.records.auditEvents.map((event) => event.eventType),
    [
      "workspace.membership.role_changed",
      "workspace.membership.disabled",
      "workspace.membership.reactivated",
    ],
  );
  assert.equal(fixture.calls.csrfValidate, 3);
  assertResponseIsPrivacySafe(roleChange.response);
  assertResponseIsPrivacySafe(disable.response);
  assertResponseIsPrivacySafe(reactivate.response);
});

test("owner and admin can remove membership through admin route", async () => {
  for (const role of ["owner", "admin"]) {
    const fixture = createAdminRouteFixture({
      memberships: baseMemberships().map((membership) =>
        membership.id === "membership_member_example" && role === "admin"
          ? { ...membership, status: "disabled" }
          : membership,
      ),
    });

    const removed = await request({
      method: "POST",
      url: "/api/platform/workspaces/workspace_koncept_images/members/membership_member_example/remove",
      headers: secureSessionHeaders(role),
      dependencies: fixture.dependencies,
    });

    assert.equal(removed.response.statusCode, 200);
    assert.deepEqual(removed.body, {
      outcome: "removed",
      membership: {
        membershipId: "membership_member_example",
        userId: "user_member_example",
        workspaceId: "workspace_koncept_images",
        role: "member",
        status: role === "admin" ? "disabled" : "active",
        updatedAt: now,
      },
    });
    assert.equal(
      fixture.records.memberships.some(
        (membership) => membership.id === "membership_member_example",
      ),
      false,
    );
    assert.deepEqual(
      fixture.records.auditEvents.map((event) => event.eventType),
      ["workspace.membership.removed"],
    );
    assert.equal(fixture.calls.csrfValidate, 1);
    assertResponseIsPrivacySafe(removed.response);
  }
});

test("last-owner and self-change guards surface safely through admin routes", async () => {
  const onlyOwnerFixture = createAdminRouteFixture({
    memberships: [
      {
        id: "membership_owner_example",
        workspaceId: "workspace_koncept_images",
        userId: "user_owner_example",
        role: "owner",
        status: "active",
        createdAt: now,
        updatedAt: now,
      },
    ],
  });
  const lastOwner = await request({
    method: "POST",
    url: "/api/platform/workspaces/workspace_koncept_images/members/membership_owner_example/role?role=admin",
    headers: secureSessionHeaders("owner"),
    dependencies: onlyOwnerFixture.dependencies,
  });
  const selfChangeFixture = createAdminRouteFixture();
  const selfChange = await request({
    method: "POST",
    url: "/api/platform/workspaces/workspace_koncept_images/members/membership_admin_example/disable",
    headers: secureSessionHeaders("admin"),
    dependencies: selfChangeFixture.dependencies,
  });
  const selfRemoveFixture = createAdminRouteFixture();
  const selfRemove = await request({
    method: "POST",
    url: "/api/platform/workspaces/workspace_koncept_images/members/membership_admin_example/remove",
    headers: secureSessionHeaders("admin"),
    dependencies: selfRemoveFixture.dependencies,
  });
  const lastOwnerRemoveFixture = createAdminRouteFixture({
    memberships: [
      {
        id: "membership_owner_example",
        workspaceId: "workspace_koncept_images",
        userId: "user_owner_example",
        role: "owner",
        status: "active",
        createdAt: now,
        updatedAt: now,
      },
    ],
  });
  const lastOwnerRemove = await request({
    method: "POST",
    url: "/api/platform/workspaces/workspace_koncept_images/members/membership_owner_example/remove",
    headers: secureSessionHeaders("owner"),
    dependencies: lastOwnerRemoveFixture.dependencies,
  });

  assert.equal(lastOwner.response.statusCode, 409);
  assert.deepEqual(lastOwner.body, {
    outcome: "error",
    message: "Workspace admin action could not be completed.",
  });
  assert.equal(selfChange.response.statusCode, 409);
  assert.deepEqual(selfChange.body, {
    outcome: "error",
    message: "Workspace admin action could not be completed.",
  });
  assert.equal(selfRemove.response.statusCode, 409);
  assert.deepEqual(selfRemove.body, {
    outcome: "error",
    message: "Workspace admin action could not be completed.",
  });
  assert.equal(lastOwnerRemove.response.statusCode, 409);
  assert.deepEqual(lastOwnerRemove.body, {
    outcome: "error",
    message: "Workspace admin action could not be completed.",
  });
  assert.equal(onlyOwnerFixture.records.auditEvents.length, 0);
  assert.equal(selfChangeFixture.records.auditEvents.length, 0);
  assert.equal(selfRemoveFixture.records.auditEvents.length, 0);
  assert.equal(lastOwnerRemoveFixture.records.auditEvents.length, 0);
  assertResponseIsPrivacySafe(lastOwner.response);
  assertResponseIsPrivacySafe(selfChange.response);
  assertResponseIsPrivacySafe(selfRemove.response);
  assertResponseIsPrivacySafe(lastOwnerRemove.response);
});

test("admin cannot change owner memberships through admin routes", async () => {
  for (const [name, url, expectedMembershipId, expectedField, expectedValue] of [
    [
      "demote owner",
      "/api/platform/workspaces/workspace_koncept_images/members/membership_owner_example/role?role=admin",
      "membership_owner_example",
      "role",
      "owner",
    ],
    [
      "promote member to owner",
      "/api/platform/workspaces/workspace_koncept_images/members/membership_member_example/role?role=owner",
      "membership_member_example",
      "role",
      "member",
    ],
    [
      "disable owner",
      "/api/platform/workspaces/workspace_koncept_images/members/membership_owner_example/disable",
      "membership_owner_example",
      "status",
      "active",
    ],
    [
      "reactivate owner",
      "/api/platform/workspaces/workspace_koncept_images/members/membership_owner_example/reactivate",
      "membership_owner_example",
      "status",
      "active",
    ],
    [
      "remove owner",
      "/api/platform/workspaces/workspace_koncept_images/members/membership_owner_example/remove",
      "membership_owner_example",
      "status",
      "active",
    ],
  ]) {
    const fixture = createAdminRouteFixture();
    const result = await request({
      method: "POST",
      url,
      headers: secureSessionHeaders("admin"),
      dependencies: fixture.dependencies,
    });

    assert.equal(result.response.statusCode, 403, name);
    assert.deepEqual(result.body, {
      outcome: "denied",
      reason: "not_authorized",
    });
    assert.equal(
      fixture.records.memberships.find((membership) => membership.id === expectedMembershipId)?.[
        expectedField
      ],
      expectedValue,
    );
    assert.equal(fixture.records.auditEvents.length, 0);
    assertResponseIsPrivacySafe(result.response);
  }
});

test("reactivation route fails safely for missing target and audit failure", async () => {
  const missingFixture = createAdminRouteFixture();
  const missing = await request({
    method: "POST",
    url: "/api/platform/workspaces/workspace_koncept_images/members/membership_missing_example/reactivate",
    headers: secureSessionHeaders("owner"),
    dependencies: missingFixture.dependencies,
  });
  const auditFailureFixture = createAdminRouteFixture({
    memberships: baseMemberships().map((membership) =>
      membership.id === "membership_member_example"
        ? { ...membership, status: "disabled" }
        : membership,
    ),
    failAuditAppend: true,
  });
  const auditFailure = await request({
    method: "POST",
    url: "/api/platform/workspaces/workspace_koncept_images/members/membership_member_example/reactivate",
    headers: secureSessionHeaders("owner"),
    dependencies: auditFailureFixture.dependencies,
  });

  assert.equal(missing.response.statusCode, 404);
  assert.deepEqual(missing.body, {
    outcome: "error",
    message: "Workspace admin action could not be completed.",
  });
  assert.equal(missingFixture.records.auditEvents.length, 0);
  assert.equal(auditFailure.response.statusCode, 500);
  assert.deepEqual(auditFailure.body, {
    outcome: "error",
    message: "Workspace admin action could not be completed.",
  });
  assert.equal(
    auditFailureFixture.records.memberships.find(
      (membership) => membership.id === "membership_member_example",
    )?.status,
    "disabled",
  );
  assert.equal(auditFailureFixture.records.auditEvents.length, 0);
  assertResponseIsPrivacySafe(missing.response);
  assertResponseIsPrivacySafe(auditFailure.response);
});

test("membership removal route fails safely for missing target and audit failure", async () => {
  const missingFixture = createAdminRouteFixture();
  const missing = await request({
    method: "POST",
    url: "/api/platform/workspaces/workspace_koncept_images/members/membership_missing_example/remove",
    headers: secureSessionHeaders("owner"),
    dependencies: missingFixture.dependencies,
  });
  const auditFailureFixture = createAdminRouteFixture({ failAuditAppend: true });
  const auditFailure = await request({
    method: "POST",
    url: "/api/platform/workspaces/workspace_koncept_images/members/membership_member_example/remove",
    headers: secureSessionHeaders("owner"),
    dependencies: auditFailureFixture.dependencies,
  });

  assert.equal(missing.response.statusCode, 404);
  assert.deepEqual(missing.body, {
    outcome: "error",
    message: "Workspace admin action could not be completed.",
  });
  assert.equal(missingFixture.records.auditEvents.length, 0);
  assert.equal(auditFailure.response.statusCode, 500);
  assert.deepEqual(auditFailure.body, {
    outcome: "error",
    message: "Workspace admin action could not be completed.",
  });
  assert.equal(
    auditFailureFixture.records.memberships.some(
      (membership) => membership.id === "membership_member_example",
    ),
    true,
  );
  assert.equal(auditFailureFixture.records.auditEvents.length, 0);
  assertResponseIsPrivacySafe(missing.response);
  assertResponseIsPrivacySafe(auditFailure.response);
});

test("owner can list and update KQAG app entitlement through admin routes", async () => {
  const fixture = createAdminRouteFixture();

  const list = await request({
    method: "GET",
    url: "/api/platform/workspaces/workspace_koncept_images/app-entitlements",
    headers: sessionHeaders("owner"),
    dependencies: fixture.dependencies,
  });
  const disabled = await request({
    method: "POST",
    url: "/api/platform/workspaces/workspace_koncept_images/app-entitlements/kqag/status?status=disabled",
    headers: secureSessionHeaders("owner"),
    dependencies: fixture.dependencies,
  });
  const enabled = await request({
    method: "POST",
    url: "/api/platform/workspaces/workspace_koncept_images/app-entitlements/kqag/status?status=enabled",
    headers: secureSessionHeaders("owner"),
    dependencies: fixture.dependencies,
  });

  assert.equal(list.response.statusCode, 200);
  assert.equal(list.body.outcome, "listed");
  assert.deepEqual(list.body.entitlements, [
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
  assert.equal(disabled.response.statusCode, 200);
  assert.equal(disabled.body.entitlement.status, "disabled");
  assert.equal(enabled.response.statusCode, 200);
  assert.equal(enabled.body.entitlement.status, "enabled");
  assert.deepEqual(
    fixture.records.auditEvents.map((event) => event.eventType),
    ["workspace.app_entitlement.disabled", "workspace.app_entitlement.enabled"],
  );
  assertResponseIsPrivacySafe(list.response);
  assertResponseIsPrivacySafe(disabled.response);
  assertResponseIsPrivacySafe(enabled.response);
});

test("audit append failure through admin route rolls back missing KQAG entitlement creation", async () => {
  const fixture = createAdminRouteFixture({
    appEntitlements: [],
    failAuditAppend: true,
  });

  const { response, body } = await request({
    method: "POST",
    url: "/api/platform/workspaces/workspace_koncept_images/app-entitlements/kqag/status?status=enabled",
    headers: secureSessionHeaders("owner"),
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 500);
  assert.deepEqual(body, {
    outcome: "error",
    message: "Workspace admin action could not be completed.",
  });
  assert.equal(fixture.records.appEntitlements.length, 0);
  assert.equal(fixture.records.auditEvents.length, 0);
  assertResponseIsPrivacySafe(response);
});

async function request({
  method,
  url,
  headers = {},
  dependencies = createAdminRouteFixture().dependencies,
}) {
  const response = await handleNodePlatformHttpRequest(dependencies, {
    method,
    url,
    headers,
  });

  return {
    response,
    body: JSON.parse(response.body),
  };
}

function createAdminRouteFixture(overrides = {}) {
  const users = ["owner", "admin", "member", "viewer"].map((role) => ({
    id: `user_${role}_example`,
    email: `${role}@example.test`,
    displayName: `${role[0].toUpperCase()}${role.slice(1)} Example`,
    status: "active",
    createdAt: now,
    updatedAt: now,
    lastLoginAt: now,
    ...(overrides.userByRole?.[role] ?? {}),
  }));
  const userByRole = Object.fromEntries(users.map((user) => [user.id.split("_")[1], user]));
  const memberships =
    overrides.memberships ??
    ["owner", "admin", "member", "viewer"].map((role) => ({
      id: `membership_${role}_example`,
      workspaceId: "workspace_koncept_images",
      userId: `user_${role}_example`,
      role,
      status: "active",
      createdAt: now,
      updatedAt: now,
      ...(overrides.actorMembership && ["owner", "admin"].includes(role)
        ? overrides.actorMembership
        : {}),
    }));
  const app = {
    id: "app_kqag",
    key: "kqag",
    name: "KQAG / SAQG",
    status: "private_preview",
    launchUrl: null,
    createdAt: now,
    updatedAt: now,
  };
  const records = {
    users: [...users, ...(overrides.extraUsers ?? [])],
    providerIdentities: [
      {
        id: "provider_identity_private",
        userId: "user_owner_example",
        providerKey: "example_oidc",
        providerSubject: "raw-provider-claim-subject",
        createdAt: now,
        updatedAt: now,
      },
      ...(overrides.extraProviderIdentities ?? []),
    ],
    sessions: ["owner", "admin", "member", "viewer"].map((role) => ({
      id: `session_${role}_example`,
      userId: userByRole[role].id,
      createdAt: earlier,
      expiresAt: future,
      lastSeenAt: earlier,
      revokedAt: null,
      ...(role === "owner" ? overrides.session : {}),
    })),
    workspaces: [
      {
        id: "workspace_koncept_images",
        slug: "koncept-images-pte-ltd",
        displayName: "Koncept Images Pte Ltd",
        status: "active",
        createdAt: now,
        updatedAt: now,
        ...overrides.workspace,
      },
    ],
    memberships: [...memberships, ...(overrides.extraMemberships ?? [])],
    membershipApprovals: overrides.membershipApprovals ?? [],
    apps: [app],
    appEntitlements:
      overrides.appEntitlements ??
      [
        {
          id: "entitlement_koncept_kqag",
          workspaceId: "workspace_koncept_images",
          appId: app.id,
          status: "enabled",
          grantedByUserId: "user_owner_example",
          createdAt: now,
          updatedAt: now,
        },
      ],
    auditEvents: overrides.auditEvents ?? [],
  };
  const repositories = createInMemoryPlatformRepositories(records);
  const calls = {
    csrfValidate: 0,
  };

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
    calls,
    dependencies: {
      repositories,
      now: () => now,
      cookie: { secure: true },
      originConfig: { allowedOrigins: [allowedOrigin] },
      csrfTokenValidator: {
        async validate(input) {
          calls.csrfValidate += 1;
          assert.equal(input.now, now);
          assert.equal(input.csrfToken, validCsrfToken);
          return overrides.csrfValid === false ? { valid: false } : { valid: true };
        },
      },
      workspaceAdminIdFactory: {
        createAuditEventId() {
          return `audit_http_${records.auditEvents.length + 1}`;
        },
        createEntitlementId() {
          return `entitlement_http_${records.appEntitlements.length + 1}`;
        },
        createMembershipId() {
          return `membership_http_${
            records.memberships.filter((membership) =>
              membership.id.startsWith("membership_http_"),
            ).length + 1
          }`;
        },
        createApprovalId() {
          return `approval_http_${records.membershipApprovals.length + 1}`;
        },
      },
    },
  };
}

function baseMemberships() {
  return ["owner", "admin", "member", "viewer"].map((role) => ({
    id: `membership_${role}_example`,
    workspaceId: "workspace_koncept_images",
    userId: `user_${role}_example`,
    role,
    status: "active",
    createdAt: now,
    updatedAt: now,
  }));
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

function sessionHeaders(role) {
  return {
    cookie: `swooshz_session=session_${role}_example`,
  };
}

function secureSessionHeaders(role) {
  return {
    origin: allowedOrigin,
    cookie: `swooshz_session=session_${role}_example`,
    "x-csrf-token": validCsrfToken,
  };
}

function assertNoStoreHeaders(headers) {
  assert.equal(headers["cache-control"], "no-store, no-cache, must-revalidate");
  assert.equal(headers.pragma, "no-cache");
  assert.equal(headers.expires, "0");
}

function assertResponseIsPrivacySafe(response) {
  const serialized = JSON.stringify(response);

  assert.doesNotMatch(serialized, /raw-session-token|session-secret|provider-token/i);
  assert.doesNotMatch(serialized, /raw-csrf-token|csrf-secret|auth-code|raw-claim/i);
  assert.doesNotMatch(serialized, /postgresql:\/\/private-host|select \*|database exploded/i);
  assert.doesNotMatch(serialized, /provider_identity|providerSubject|raw-provider-claim/i);
  assert.doesNotMatch(serialized, /quote export|pricing reference|logo_data_url/i);
}

function assertAdminMessagePrivacySafe(message) {
  assert.equal(typeof message, "string");
  assert.doesNotMatch(message, /user_[a-z0-9_]+|workspace_[a-z0-9_]+|membership_[a-z0-9_]+/i);
  assert.doesNotMatch(message, /provider|subject|raw claim|claim|oauth|state|nonce/i);
  assert.doesNotMatch(message, /token|cookie|postgres|DATABASE_URL|AUTH_ALLOWED|allowlist/i);
  assert.doesNotMatch(message, /stack|trace|quote|pricing|generated artifact|KQAG payload/i);
}
