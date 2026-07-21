import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { consumeFinalizationHandle, registerFinalizationHandle, validateAccessValidationGrant } from "../dist/platform/access-validation-grant-service.js";

const now = "2026-07-21T00:00:00.000Z";
const later = "2026-07-21T00:01:00.000Z";
const handle = "finalization_handle_abcdefghijklmnopqrstuvwxyz_123456";
const handleHash = createHash("sha256").update(handle).digest("hex");

test("finalization registration, consume, replay protection, and live validation", async () => {
  const fixture = createFixture();
  assert.equal(await registerFinalizationHandle(fixture.dependencies, { validationGrantId: fixture.grant.id, handleHashSha256: handleHash, expiresAt: later, intendedSqagOrigin: fixture.origin, now }), true);
  const consumed = await consumeFinalizationHandle(fixture.dependencies, { rawHandle: handle, intendedSqagOrigin: fixture.origin, now });
  assert.equal(consumed?.validationGrantId, fixture.grant.id);
  assert.equal(consumed?.currentRole, "member");
  assert.equal(await consumeFinalizationHandle(fixture.dependencies, { rawHandle: handle, intendedSqagOrigin: fixture.origin, now }), null);
  const validation = await validateAccessValidationGrant(fixture.dependencies, { validationGrantId: fixture.grant.id, workspaceId: "workspace_1", appKey: "sqag", now });
  assert.equal(validation?.userId, "user_1");
  fixture.session.revokedAt = now;
  assert.equal(await validateAccessValidationGrant(fixture.dependencies, { validationGrantId: fixture.grant.id, workspaceId: "workspace_1", appKey: "sqag", now }), null);
});

test("registration rejects wrong origin and unsafe expiry", async () => {
  const fixture = createFixture();
  assert.equal(await registerFinalizationHandle(fixture.dependencies, { validationGrantId: fixture.grant.id, handleHashSha256: handleHash, expiresAt: later, intendedSqagOrigin: "https://wrong.example", now }), false);
  assert.equal(await registerFinalizationHandle(fixture.dependencies, { validationGrantId: fixture.grant.id, handleHashSha256: handleHash, expiresAt: now, intendedSqagOrigin: fixture.origin, now }), false);
  const expired = createFixture(); expired.grant.launchTokenExpiresAt = now;
  assert.equal(await registerFinalizationHandle(expired.dependencies, { validationGrantId: expired.grant.id, handleHashSha256: handleHash, expiresAt: later, intendedSqagOrigin: expired.origin, now }), false);
  const beyond = createFixture(); beyond.grant.launchTokenExpiresAt = "2026-07-21T00:00:30.000Z";
  assert.equal(await registerFinalizationHandle(beyond.dependencies, { validationGrantId: beyond.grant.id, handleHashSha256: handleHash, expiresAt: later, intendedSqagOrigin: beyond.origin, now }), false);
});

test("live validation fails closed for every authoritative access invalidation", async () => {
  const scenarios = [
    ["expired session", (f) => { f.session.expiresAt = now; }],
    ["revoked session", (f) => { f.session.revokedAt = now; }],
    ["cross-user session substitution", (f) => { f.session.userId = "user_other"; }],
    ["disabled user", (f) => { f.user.status = "disabled"; }],
    ["disabled workspace", (f) => { f.workspace.status = "suspended"; }],
    ["removed membership", (f) => { f.repositories.memberships.findForUserInWorkspace = async () => null; f.repositories.memberships.listForUser = async () => []; }],
    ["disabled membership", (f) => { f.membership.status = "disabled"; }],
    ["unsupported role", (f) => { f.membership.role = "viewer"; }],
    ["disabled app", (f) => { f.app.status = "disabled"; }],
    ["wrong app binding", (f) => { f.app.key = "other"; }],
    ["disabled entitlement", (f) => { f.entitlement.status = "disabled"; }],
  ];
  for (const [name, mutate] of scenarios) {
    const fixture = createFixture();
    fixture.grant.consumedAt = now;
    mutate(fixture);
    assert.equal(await validateAccessValidationGrant(fixture.dependencies, { validationGrantId: fixture.grant.id, workspaceId: "workspace_1", appKey: "sqag", now }), null, name);
  }
  const wrongWorkspace = createFixture(); wrongWorkspace.grant.consumedAt = now;
  assert.equal(await validateAccessValidationGrant(wrongWorkspace.dependencies, { validationGrantId: wrongWorkspace.grant.id, workspaceId: "workspace_other", appKey: "sqag", now }), null);
});

test("live validation returns the role from the final membership read", async () => {
  const fixture = createFixture();
  fixture.grant.consumedAt = now;
  let membershipReads = 0;
  fixture.repositories.memberships.findForUserInWorkspace = async () => {
    membershipReads += 1;
    return { ...fixture.membership, role: membershipReads === 1 ? "owner" : "member" };
  };

  const validation = await validateAccessValidationGrant(fixture.dependencies, { validationGrantId: fixture.grant.id, workspaceId: "workspace_1", appKey: "sqag", now });

  assert.equal(membershipReads, 2);
  assert.equal(validation?.currentRole, "member");
});

test("expired handle, revoke, and repository failure remain fail closed", async () => {
  const expired = createFixture();
  expired.grant.handleHash = handleHash; expired.grant.handleExpiresAt = "2026-07-20T23:59:00.000Z";
  assert.equal(await consumeFinalizationHandle(expired.dependencies, { rawHandle: handle, intendedSqagOrigin: expired.origin, now }), null);
  const revoked = createFixture(); revoked.grant.consumedAt = now; revoked.grant.revokedAt = now;
  assert.equal(await validateAccessValidationGrant(revoked.dependencies, { validationGrantId: revoked.grant.id, workspaceId: "workspace_1", appKey: "sqag", now }), null);
  const failed = createFixture(); failed.grant.consumedAt = now; failed.repositories.sessions.findById = async () => { throw new Error("private database failure"); };
  assert.equal(await validateAccessValidationGrant(failed.dependencies, { validationGrantId: failed.grant.id, workspaceId: "workspace_1", appKey: "sqag", now }), null);
});

function createFixture() {
  const origin = "https://quote.swooshz.com";
  const session = { id: "session_1", userId: "user_1", createdAt: now, expiresAt: "2026-07-22T00:00:00.000Z", lastSeenAt: now, revokedAt: null };
  const grant = { id: "grant_abcdefghijklmnopqrstuvwxyz_1234567890", sessionId: session.id, userId: "user_1", workspaceId: "workspace_1", appId: "app_sqag", intendedOrigin: origin, launchTokenExpiresAt: later, handleHash: null, createdAt: now, handleExpiresAt: null, consumedAt: null, revokedAt: null };
  const user = { id: "user_1", email: "u@example.test", displayName: "User", status: "active", createdAt: now, updatedAt: now, lastLoginAt: now };
  const workspace = { id: "workspace_1", slug: "one", displayName: "One", status: "active", createdAt: now, updatedAt: now };
  const membership = { id: "membership_1", workspaceId: workspace.id, userId: user.id, role: "member", status: "active", createdAt: now, updatedAt: now };
  const app = { id: "app_sqag", key: "sqag", name: "SQAG", status: "available", launchUrl: null, createdAt: now, updatedAt: now };
  const entitlement = { id: "ent_1", workspaceId: workspace.id, appId: app.id, status: "enabled", grantedByUserId: user.id, createdAt: now, updatedAt: now };
  const grants = {
    async create(value) { Object.assign(grant, value); return grant; }, async findById(id) { return id === grant.id ? grant : null; },
    async registerHandle(id, hash, expiresAt) { if (id !== grant.id || grant.handleHash) return null; grant.handleHash = hash; grant.handleExpiresAt = expiresAt; return grant; },
    async consumeByHandleHash(hash, at) { if (grant.handleHash !== hash || grant.consumedAt || grant.revokedAt) return null; grant.consumedAt = at; return grant; },
    async revoke(id, at) { if (id !== grant.id) return null; grant.revokedAt = at; return grant; },
  };
  const repositories = { accessValidationGrants: grants, sessions: { async findById() { return session; } }, users: { async findById() { return user; } }, workspaces: { async findById() { return workspace; } }, memberships: { async findForUserInWorkspace() { return membership; }, async listForUser() { return [membership]; } }, apps: { async findById() { return app; }, async findByKey() { return app; }, async listAll() { return [app]; } }, appEntitlements: { async findForWorkspaceApp() { return entitlement; }, async listForWorkspace() { return [entitlement]; } } };
  return { origin, session, grant, user, workspace, membership, app, entitlement, repositories, dependencies: { repositories, intendedSqagOrigin: origin, grantIdFactory: () => grant.id, handleHasher: (raw) => createHash("sha256").update(raw).digest("hex") } };
}
