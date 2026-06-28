import {
  MembershipStatus,
  UserStatus,
  WorkspaceStatus,
  type Membership,
  type Session,
  type User,
  type Workspace,
} from "../accounts/types.js";
import { decideAppAccess, type AccessDecision } from "../access/decide-app-access.js";
import type { App, AppEntitlement } from "../apps/types.js";
import type { PlatformRepositories } from "./repositories.js";

export type PlatformSessionContextUnauthenticatedReason =
  | "missing_session"
  | "revoked_session"
  | "expired_session"
  | "missing_user"
  | "user_not_active";

export type PlatformSessionContextServiceErrorCode = "context_lookup_failed";

export interface PlatformSessionContextInput {
  sessionId: string;
  now: string;
  selectedWorkspaceId?: string | null;
}

export interface PlatformSessionContextUserSummary {
  userId: string;
  email: string;
  displayName: string;
  status: User["status"];
}

export interface PlatformSessionContextAppSummary {
  appKey: string;
  appName: string;
  appStatus: App["status"];
  entitlementStatus: AppEntitlement["status"] | null;
  access: AccessDecision;
}

export interface PlatformSessionContextWorkspaceSummary {
  workspaceId: string;
  workspaceSlug: string;
  workspaceName: string;
  membershipRole: Membership["role"];
  membershipStatus: Membership["status"];
  apps: readonly PlatformSessionContextAppSummary[];
}

export type PlatformSessionContextResult =
  | {
      outcome: "authenticated";
      session: {
        status: "active";
        expiresAt: string;
      };
      user: PlatformSessionContextUserSummary;
      selectedWorkspaceId: string | null;
      workspaces: readonly PlatformSessionContextWorkspaceSummary[];
    }
  | {
      outcome: "unauthenticated";
      reason: PlatformSessionContextUnauthenticatedReason;
    };

export class PlatformSessionContextServiceError extends Error {
  readonly code: PlatformSessionContextServiceErrorCode;
  readonly publicMessage = "Session context could not be loaded.";

  constructor(code: PlatformSessionContextServiceErrorCode) {
    super("Session context could not be loaded.");
    this.name = "PlatformSessionContextServiceError";
    this.code = code;
  }
}

export async function getPlatformSessionContext(
  repositories: PlatformRepositories,
  input: PlatformSessionContextInput,
): Promise<PlatformSessionContextResult> {
  try {
    const session = await repositories.sessions.findById(input.sessionId);

    if (!session) {
      return unauthenticated("missing_session");
    }

    if (session.revokedAt) {
      return unauthenticated("revoked_session");
    }

    if (isExpired(session, input.now)) {
      return unauthenticated("expired_session");
    }

    const user = await repositories.users.findById(session.userId);

    if (!user) {
      return unauthenticated("missing_user");
    }

    if (user.status !== UserStatus.Active) {
      return unauthenticated("user_not_active");
    }

    const memberships = await repositories.memberships.listForUser(user.id);
    const apps = await repositories.apps.listAll();
    const workspaceContexts = await readWorkspaceContexts(
      repositories,
      session,
      user,
      memberships,
      apps,
      input.now,
    );

    return {
      outcome: "authenticated",
      session: {
        status: "active",
        expiresAt: session.expiresAt,
      },
      user: {
        userId: user.id,
        email: user.email,
        displayName: user.displayName,
        status: user.status,
      },
      selectedWorkspaceId: readSelectedWorkspaceId(
        input.selectedWorkspaceId,
        workspaceContexts,
      ),
      workspaces: workspaceContexts,
    };
  } catch (error) {
    if (error instanceof PlatformSessionContextServiceError) {
      throw error;
    }

    throw new PlatformSessionContextServiceError("context_lookup_failed");
  }
}

async function readWorkspaceContexts(
  repositories: PlatformRepositories,
  session: Session,
  user: User,
  memberships: readonly Membership[],
  apps: readonly App[],
  now: string,
): Promise<readonly PlatformSessionContextWorkspaceSummary[]> {
  const contexts: PlatformSessionContextWorkspaceSummary[] = [];

  for (const membership of memberships) {
    if (membership.status !== MembershipStatus.Active) {
      continue;
    }

    const workspace = await repositories.workspaces.findById(membership.workspaceId);

    if (!workspace || workspace.status !== WorkspaceStatus.Active) {
      continue;
    }

    const entitlements =
      await repositories.appEntitlements.listForWorkspace(workspace.id);

    contexts.push({
      workspaceId: workspace.id,
      workspaceSlug: workspace.slug,
      workspaceName: workspace.displayName,
      membershipRole: membership.role,
      membershipStatus: membership.status,
      apps: readAppSummaries({
        session,
        user,
        workspace,
        membership,
        apps,
        entitlements,
        now,
      }),
    });
  }

  return contexts;
}

function readAppSummaries({
  session,
  user,
  workspace,
  membership,
  apps,
  entitlements,
  now,
}: {
  session: Session;
  user: User;
  workspace: Workspace;
  membership: Membership;
  apps: readonly App[];
  entitlements: readonly AppEntitlement[];
  now: string;
}): readonly PlatformSessionContextAppSummary[] {
  return apps.map((app) => {
    const entitlement =
      entitlements.find((candidate) => candidate.appId === app.id) ?? null;

    return {
      appKey: app.key,
      appName: app.name,
      appStatus: app.status,
      entitlementStatus: entitlement?.status ?? null,
      access: decideAppAccess({
        appKey: app.key,
        session,
        user,
        selectedWorkspaceId: workspace.id,
        workspaces: [workspace],
        memberships: [membership],
        apps: [app],
        entitlements: entitlement ? [entitlement] : [],
        now,
      }),
    };
  });
}

function readSelectedWorkspaceId(
  selectedWorkspaceId: string | null | undefined,
  workspaces: readonly PlatformSessionContextWorkspaceSummary[],
): string | null {
  if (!selectedWorkspaceId) {
    return null;
  }

  return workspaces.some((workspace) => workspace.workspaceId === selectedWorkspaceId)
    ? selectedWorkspaceId
    : null;
}

function unauthenticated(
  reason: PlatformSessionContextUnauthenticatedReason,
): PlatformSessionContextResult {
  return {
    outcome: "unauthenticated",
    reason,
  };
}

function isExpired(session: Session, now: string): boolean {
  return Date.parse(session.expiresAt) <= Date.parse(now);
}
