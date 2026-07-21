import { decideProtectedAppAccess } from "./protected-app-access-service.js";
import type { AccessValidationGrantRepository, PlatformRepositories } from "./repositories.js";

export interface AccessValidationGrantDependencies {
  repositories: PlatformRepositories & { accessValidationGrants: AccessValidationGrantRepository };
  intendedSqagOrigin: string;
  grantIdFactory(): string;
  handleHasher(rawHandle: string): string;
}

export async function issueAccessValidationGrant(deps: AccessValidationGrantDependencies, input: { sessionId: string; userId: string; workspaceId: string; appId: string; launchTokenExpiresAt: string; now: string }) {
  const id = deps.grantIdFactory();
  if (!id || id.length < 32) throw new Error("Grant creation failed.");
  return deps.repositories.accessValidationGrants.create({ id, ...input, intendedOrigin: deps.intendedSqagOrigin, handleHash: null, handleExpiresAt: null, consumedAt: null, revokedAt: null, createdAt: input.now });
}

export async function registerFinalizationHandle(deps: AccessValidationGrantDependencies, input: { validationGrantId: string; handleHashSha256: string; expiresAt: string; intendedSqagOrigin: string; now: string }) {
  if (!validGrantId(input.validationGrantId) || !/^[a-f0-9]{64}$/.test(input.handleHashSha256) || input.intendedSqagOrigin !== deps.intendedSqagOrigin) return false;
  const expires = Date.parse(input.expiresAt);
  const now = Date.parse(input.now);
  if (!Number.isFinite(expires) || expires <= now || expires > now + 5 * 60_000) return false;
  const grant = await deps.repositories.accessValidationGrants.findById(input.validationGrantId);
  const launchExpires = grant ? Date.parse(grant.launchTokenExpiresAt) : Number.NaN;
  if (!grant || grant.intendedOrigin !== input.intendedSqagOrigin || grant.revokedAt || grant.consumedAt || grant.handleHash || !Number.isFinite(launchExpires) || launchExpires <= now || expires > launchExpires) return false;
  return Boolean(await deps.repositories.accessValidationGrants.registerHandle(grant.id, input.handleHashSha256, input.expiresAt));
}

export async function consumeFinalizationHandle(deps: AccessValidationGrantDependencies, input: { rawHandle: string; intendedSqagOrigin: string; now: string }) {
  if (!validHandle(input.rawHandle) || input.intendedSqagOrigin !== deps.intendedSqagOrigin) return null;
  const consumed = await deps.repositories.accessValidationGrants.consumeByHandleHash(deps.handleHasher(input.rawHandle), input.now);
  if (!consumed || !consumed.handleExpiresAt || Date.parse(consumed.handleExpiresAt) <= Date.parse(input.now) || consumed.intendedOrigin !== input.intendedSqagOrigin) return null;
  const context = await validateGrant(deps, consumed.id, consumed.workspaceId, "sqag", input.now);
  return context ? { validationGrantId: consumed.id, ...context } : null;
}

export async function validateAccessValidationGrant(deps: AccessValidationGrantDependencies, input: { validationGrantId: string; workspaceId: string; appKey: string; now: string }) {
  if (!validGrantId(input.validationGrantId)) return null;
  try { return await validateGrant(deps, input.validationGrantId, input.workspaceId, input.appKey, input.now); } catch { return null; }
}

export async function revokeAccessValidationGrant(deps: AccessValidationGrantDependencies, validationGrantId: string, now: string) {
  if (!validGrantId(validationGrantId)) return false;
  return Boolean(await deps.repositories.accessValidationGrants.revoke(validationGrantId, now));
}

async function validateGrant(deps: AccessValidationGrantDependencies, id: string, workspaceId: string, appKey: string, now: string) {
  const grant = await deps.repositories.accessValidationGrants.findById(id);
  if (!grant || grant.revokedAt || !grant.consumedAt || grant.workspaceId !== workspaceId || appKey !== "sqag" || grant.intendedOrigin !== deps.intendedSqagOrigin) return null;
  const [session, user, workspace, app, membership] = await Promise.all([deps.repositories.sessions.findById(grant.sessionId), deps.repositories.users.findById(grant.userId), deps.repositories.workspaces.findById(grant.workspaceId), deps.repositories.apps.findById(grant.appId), deps.repositories.memberships.findForUserInWorkspace(grant.userId, grant.workspaceId)]);
  if (!session || session.userId !== grant.userId || !user || !workspace || !app || app.key !== "sqag" || !membership) return null;
  const decision = await decideProtectedAppAccess(deps.repositories, { sessionId: grant.sessionId, selectedWorkspaceId: grant.workspaceId, appKey: "sqag", now });
  if (decision.outcome !== "allowed") return null;
  return { userId: grant.userId, workspaceId: grant.workspaceId, appKey: "sqag" as const, launchTokenExpiresAt: grant.launchTokenExpiresAt, currentRole: membership.role };
}

function validGrantId(value: string) { return value.length >= 32 && value.length <= 256 && /^[A-Za-z0-9_-]+$/.test(value); }
function validHandle(value: string) { return value.length >= 32 && value.length <= 512 && /^[A-Za-z0-9_-]+$/.test(value); }
