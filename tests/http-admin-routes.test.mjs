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
    const fixture = createAdminRouteFixture();

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
    const add = await request({
      method: "POST",
      url: "/api/platform/workspaces/workspace_koncept_images/members/add?email=existing.user%40example.test&role=member",
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
    assert.equal(add.response.statusCode, 403);
    assert.deepEqual(add.body, {
      outcome: "denied",
      reason: "not_authorized",
    });
    assert.equal(
      fixture.records.memberships.find((membership) => membership.id === "membership_viewer_example")
        ?.role,
      "viewer",
    );
    assert.equal(fixture.records.auditEvents.length, 0);
    assertResponseIsPrivacySafe(list.response);
    assertResponseIsPrivacySafe(mutate.response);
    assertResponseIsPrivacySafe(add.response);
  }
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
          eventId: "audit_new",
          workspaceId: "workspace_koncept_images",
          actorUserId: "user_owner_example",
          eventType: "workspace.app_entitlement.enabled",
          targetType: "app_entitlement",
          targetId: "entitlement_koncept_kqag",
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
          eventType: "workspace.membership.added",
          targetType: "membership",
          targetId: "membership_http_1",
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
  assert.equal(addWithoutOriginFixture.calls.csrfValidate, 0);
  assert.equal(
    addWithoutOriginFixture.records.memberships.some(
      (membership) => membership.userId === "user_existing_example",
    ),
    false,
  );
  assert.equal(addWithoutOriginFixture.records.auditEvents.length, 0);
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

test("add existing user route returns generic safe failures without mutation", async () => {
  for (const [name, overrides, query, expectedStatus] of [
    ["missing target", {}, "email=missing%40example.test&role=member", 404],
    [
      "target without provider identity",
      { extraUsers: [existingProviderBackedUser()] },
      "email=existing.user%40example.test&role=member",
      404,
    ],
    [
      "disabled target",
      {
        extraUsers: [existingProviderBackedUser({ status: "disabled" })],
        providerBackedUserIds: ["user_existing_example"],
      },
      "email=existing.user%40example.test&role=member",
      404,
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
    ],
    [
      "invalid role",
      {
        extraUsers: [existingProviderBackedUser()],
        providerBackedUserIds: ["user_existing_example"],
      },
      "email=existing.user%40example.test&role=owner",
      400,
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
    assert.deepEqual(body, {
      outcome: "error",
      message: "Workspace admin action could not be completed.",
    });
    assert.equal(
      fixture.records.memberships.some((membership) => membership.id === "membership_http_1"),
      false,
    );
    assert.equal(fixture.records.auditEvents.length, 0);
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
  assert.equal(
    fixture.records.memberships.some((membership) => membership.id === "membership_http_1"),
    false,
  );
  assert.equal(fixture.records.auditEvents.length, 0);
  assertResponseIsPrivacySafe(response);
});

test("owner can change role and disable membership through admin routes", async () => {
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
  assert.deepEqual(
    fixture.records.auditEvents.map((event) => event.eventType),
    ["workspace.membership.role_changed", "workspace.membership.disabled"],
  );
  assert.equal(fixture.calls.csrfValidate, 2);
  assertResponseIsPrivacySafe(roleChange.response);
  assertResponseIsPrivacySafe(disable.response);
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
  assert.equal(onlyOwnerFixture.records.auditEvents.length, 0);
  assert.equal(selfChangeFixture.records.auditEvents.length, 0);
  assertResponseIsPrivacySafe(lastOwner.response);
  assertResponseIsPrivacySafe(selfChange.response);
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
      },
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
