import type {
  AuditEvent,
  IsoTimestamp,
  Membership,
  Role,
  Session,
  User,
  Workspace,
} from "../accounts/types.js";
import type { App, AppEntitlement, EntitlementStatus } from "../apps/types.js";
import type { AuditEventRepository, PlatformRepositories } from "./repositories.js";

export type WorkspaceAdminServiceErrorCode =
  | "not_authorized"
  | "not_found"
  | "invalid_role"
  | "invalid_entitlement_status"
  | "last_owner_required"
  | "self_change_not_allowed"
  | "repository_failure";

export class WorkspaceAdminServiceError extends Error {
  readonly code: WorkspaceAdminServiceErrorCode;
  readonly publicMessage = "Workspace admin action could not be completed.";

  constructor(code: WorkspaceAdminServiceErrorCode, message: string) {
    super(message);
    this.name = "WorkspaceAdminServiceError";
    this.code = code;
  }
}

export interface WorkspaceAdminInput {
  sessionId: string;
  workspaceId: string;
  now: IsoTimestamp;
}

export interface WorkspaceMemberSummary {
  membershipId: string;
  role: Role;
  status: Membership["status"];
  createdAt: IsoTimestamp;
  updatedAt: IsoTimestamp;
  user: {
    id: string;
    email: string;
    displayName: string;
    status: User["status"];
    lastLoginAt: IsoTimestamp | null;
  };
}

export interface WorkspaceMembersAdminResult {
  workspaceId: string;
  members: readonly WorkspaceMemberSummary[];
}

export interface WorkspaceRoleChangeInput extends WorkspaceAdminInput {
  membershipId: string;
  role: Role;
  auditEventId: string;
}

export interface WorkspaceMembershipDisableInput extends WorkspaceAdminInput {
  membershipId: string;
  auditEventId: string;
}

export interface WorkspaceAppEntitlementSummary {
  entitlementId: string;
  appId: string;
  appKey: string;
  appName: string;
  appStatus: App["status"];
  status: EntitlementStatus;
  grantedByUserId: string | null;
  updatedAt: IsoTimestamp;
}

export interface WorkspaceAppEntitlementsAdminResult {
  workspaceId: string;
  entitlements: readonly WorkspaceAppEntitlementSummary[];
}

export interface WorkspaceAppEntitlementStatusInput extends WorkspaceAdminInput {
  appKey: string;
  status: "enabled" | "disabled";
  auditEventId: string;
  entitlementId?: string;
}

interface AdminContext {
  session: Session;
  actor: User;
  workspace: Workspace;
  actorMembership: Membership;
}

export async function listWorkspaceMembersForAdmin(
  repositories: PlatformRepositories,
  input: WorkspaceAdminInput,
): Promise<WorkspaceMembersAdminResult> {
  return runSafely(async () => {
    await requireAdminContext(repositories, input);
    const memberships = await repositories.memberships.listForWorkspace(input.workspaceId);
    const members = await Promise.all(
      memberships.map(async (membership) => {
        const user = await repositories.users.findById(membership.userId);

        if (!user) {
          throw adminError("not_found", "Workspace member user was not found.");
        }

        return toMemberSummary(membership, user);
      }),
    );

    return {
      workspaceId: input.workspaceId,
      members,
    };
  });
}

export async function changeWorkspaceMemberRole(
  repositories: PlatformRepositories,
  input: WorkspaceRoleChangeInput,
): Promise<Membership> {
  assertValidRole(input.role);

  return runWorkspaceAdminTransaction(repositories, async (transactionRepositories) => {
    const context = await requireAdminContext(transactionRepositories, input);
    requireAuditRepository(transactionRepositories);
    const memberships = await transactionRepositories.memberships.listForWorkspace(
      input.workspaceId,
    );
    const target = findTargetMembership(memberships, input.membershipId);
    const previousRole = target.role;
    const previousStatus = target.status;

    if (previousRole === "owner" && input.role !== "owner" && activeOwnerCount(memberships) <= 1) {
      throw adminError("last_owner_required", "Workspace must keep at least one active owner.");
    }

    if (target.userId === context.actor.id && previousRole !== input.role) {
      throw adminError("self_change_not_allowed", "Administrators cannot change their own role.");
    }

    const updated = await transactionRepositories.memberships.updateRole(
      target.id,
      input.role,
      input.now,
    );

    if (!updated) {
      throw adminError("not_found", "Workspace membership was not found.");
    }

    await appendAuditEvent(transactionRepositories, {
      id: input.auditEventId,
      workspaceId: input.workspaceId,
      actorUserId: context.actor.id,
      eventType: "workspace.membership.role_changed",
      targetType: "membership",
      targetId: target.id,
      createdAt: input.now,
      metadata: {
        previousRole,
        newRole: input.role,
        previousStatus,
        targetUserId: target.userId,
      },
    });

    return updated;
  });
}

export async function disableWorkspaceMembership(
  repositories: PlatformRepositories,
  input: WorkspaceMembershipDisableInput,
): Promise<Membership> {
  return runWorkspaceAdminTransaction(repositories, async (transactionRepositories) => {
    const context = await requireAdminContext(transactionRepositories, input);
    requireAuditRepository(transactionRepositories);
    const memberships = await transactionRepositories.memberships.listForWorkspace(
      input.workspaceId,
    );
    const target = findTargetMembership(memberships, input.membershipId);
    const previousRole = target.role;
    const previousStatus = target.status;

    if (previousRole === "owner" && previousStatus === "active" && activeOwnerCount(memberships) <= 1) {
      throw adminError("last_owner_required", "Workspace must keep at least one active owner.");
    }

    if (target.userId === context.actor.id) {
      throw adminError("self_change_not_allowed", "Administrators cannot disable themselves.");
    }

    const updated = await transactionRepositories.memberships.updateStatus(
      target.id,
      "disabled",
      input.now,
    );

    if (!updated) {
      throw adminError("not_found", "Workspace membership was not found.");
    }

    await appendAuditEvent(transactionRepositories, {
      id: input.auditEventId,
      workspaceId: input.workspaceId,
      actorUserId: context.actor.id,
      eventType: "workspace.membership.disabled",
      targetType: "membership",
      targetId: target.id,
      createdAt: input.now,
      metadata: {
        previousRole,
        previousStatus,
        targetUserId: target.userId,
      },
    });

    return updated;
  });
}

export async function listWorkspaceAppEntitlementsForAdmin(
  repositories: PlatformRepositories,
  input: WorkspaceAdminInput,
): Promise<WorkspaceAppEntitlementsAdminResult> {
  return runSafely(async () => {
    await requireAdminContext(repositories, input);
    const entitlements = await repositories.appEntitlements.listForWorkspace(input.workspaceId);
    const summaries = await Promise.all(
      entitlements.map(async (entitlement) => {
        const app = await repositories.apps.findById(entitlement.appId);

        if (!app) {
          throw adminError("not_found", "Entitled app was not found.");
        }

        return toEntitlementSummary(entitlement, app);
      }),
    );

    return {
      workspaceId: input.workspaceId,
      entitlements: summaries,
    };
  });
}

export async function setWorkspaceAppEntitlementStatus(
  repositories: PlatformRepositories,
  input: WorkspaceAppEntitlementStatusInput,
): Promise<AppEntitlement> {
  assertValidEntitlementStatus(input.status);

  return runWorkspaceAdminTransaction(repositories, async (transactionRepositories) => {
    const context = await requireAdminContext(transactionRepositories, input);
    requireAuditRepository(transactionRepositories);
    const app = await transactionRepositories.apps.findByKey(input.appKey);

    if (!app || app.key !== "kqag" || !["available", "private_preview"].includes(app.status)) {
      throw adminError("not_found", "KQAG app was not found.");
    }

    const existing = await transactionRepositories.appEntitlements.findForWorkspaceApp(
      input.workspaceId,
      app.id,
    );
    const previousStatus = existing?.status ?? null;
    const entitlement =
      existing ??
      (await createMissingEntitlement(transactionRepositories, input, context, app));

    if (!existing && input.status === "disabled") {
      throw adminError("not_found", "Workspace app entitlement was not found.");
    }

    const updated = existing
      ? await transactionRepositories.appEntitlements.updateStatus(
          existing.id,
          input.status,
          input.status === "enabled" ? context.actor.id : existing.grantedByUserId,
          input.now,
        )
      : entitlement;

    if (!updated) {
      throw adminError("not_found", "Workspace app entitlement was not found.");
    }

    await appendAuditEvent(transactionRepositories, {
      id: input.auditEventId,
      workspaceId: input.workspaceId,
      actorUserId: context.actor.id,
      eventType: `workspace.app_entitlement.${input.status}`,
      targetType: "app_entitlement",
      targetId: updated.id,
      createdAt: input.now,
      metadata: {
        appId: app.id,
        appKey: app.key,
        previousStatus,
        newStatus: input.status,
      },
    });

    return updated;
  });
}

async function requireAdminContext(
  repositories: PlatformRepositories,
  input: WorkspaceAdminInput,
): Promise<AdminContext> {
  const session = await repositories.sessions.findById(input.sessionId);

  if (!session || session.revokedAt || Date.parse(session.expiresAt) <= Date.parse(input.now)) {
    throw adminError("not_authorized", "Workspace admin authorization failed.");
  }

  const [actor, workspace, actorMembership] = await Promise.all([
    repositories.users.findById(session.userId),
    repositories.workspaces.findById(input.workspaceId),
    repositories.memberships.findForUserInWorkspace(session.userId, input.workspaceId),
  ]);

  if (
    !actor ||
    actor.status !== "active" ||
    !workspace ||
    workspace.status !== "active" ||
    !actorMembership ||
    actorMembership.status !== "active" ||
    !["owner", "admin"].includes(actorMembership.role)
  ) {
    throw adminError("not_authorized", "Workspace admin authorization failed.");
  }

  return {
    session,
    actor,
    workspace,
    actorMembership,
  };
}

function toMemberSummary(membership: Membership, user: User): WorkspaceMemberSummary {
  return {
    membershipId: membership.id,
    role: membership.role,
    status: membership.status,
    createdAt: membership.createdAt,
    updatedAt: membership.updatedAt,
    user: {
      id: user.id,
      email: user.email,
      displayName: user.displayName,
      status: user.status,
      lastLoginAt: user.lastLoginAt,
    },
  };
}

function toEntitlementSummary(
  entitlement: AppEntitlement,
  app: App,
): WorkspaceAppEntitlementSummary {
  return {
    entitlementId: entitlement.id,
    appId: app.id,
    appKey: app.key,
    appName: app.name,
    appStatus: app.status,
    status: entitlement.status,
    grantedByUserId: entitlement.grantedByUserId,
    updatedAt: entitlement.updatedAt,
  };
}

function findTargetMembership(
  memberships: readonly Membership[],
  membershipId: string,
): Membership {
  const target = memberships.find((membership) => membership.id === membershipId);

  if (!target) {
    throw adminError("not_found", "Workspace membership was not found.");
  }

  return target;
}

function activeOwnerCount(memberships: readonly Membership[]): number {
  return memberships.filter(
    (membership) => membership.role === "owner" && membership.status === "active",
  ).length;
}

function assertValidRole(role: Role): void {
  if (!["owner", "admin", "member", "viewer"].includes(role)) {
    throw adminError("invalid_role", "Workspace role is not supported.");
  }
}

function assertValidEntitlementStatus(status: string): void {
  if (!["enabled", "disabled"].includes(status)) {
    throw adminError("invalid_entitlement_status", "Entitlement status is not supported.");
  }
}

async function createMissingEntitlement(
  repositories: PlatformRepositories,
  input: WorkspaceAppEntitlementStatusInput,
  context: AdminContext,
  app: App,
): Promise<AppEntitlement> {
  if (input.status !== "enabled" || !input.entitlementId) {
    throw adminError("not_found", "Workspace app entitlement was not found.");
  }

  return repositories.appEntitlements.create({
    id: input.entitlementId,
    workspaceId: input.workspaceId,
    appId: app.id,
    status: "enabled",
    grantedByUserId: context.actor.id,
    createdAt: input.now,
    updatedAt: input.now,
  });
}

async function appendAuditEvent(
  repositories: PlatformRepositories,
  event: AuditEvent,
): Promise<void> {
  await requireAuditRepository(repositories).append(event);
}

function requireAuditRepository(
  repositories: PlatformRepositories,
): AuditEventRepository {
  if (!repositories.auditEvents) {
    throw adminError("repository_failure", "Audit event repository is not configured.");
  }

  return repositories.auditEvents;
}

async function runWorkspaceAdminTransaction<T>(
  repositories: PlatformRepositories,
  operation: (repositories: PlatformRepositories) => Promise<T>,
): Promise<T> {
  return runSafely(async () => {
    if (!repositories.workspaceAdminTransactions) {
      throw adminError(
        "repository_failure",
        "Workspace admin transaction repository is not configured.",
      );
    }

    return repositories.workspaceAdminTransactions.run(operation);
  });
}

function adminError(
  code: WorkspaceAdminServiceErrorCode,
  message: string,
): WorkspaceAdminServiceError {
  return new WorkspaceAdminServiceError(code, message);
}

async function runSafely<T>(action: () => Promise<T>): Promise<T> {
  try {
    return await action();
  } catch (error) {
    if (error instanceof WorkspaceAdminServiceError) {
      throw error;
    }

    throw adminError("repository_failure", "Workspace admin repository operation failed.");
  }
}
