import {
  MembershipStatus,
  Role,
  UserStatus,
  WorkspaceStatus,
  type Membership,
  type Session,
  type User,
  type Workspace,
} from "../accounts/types.js";
import {
  AppStatus,
  EntitlementStatus,
  type App,
  type AppEntitlement,
} from "../apps/types.js";

export const AccessDecisionResult = {
  Allowed: "allowed",
  NotAuthenticated: "not_authenticated",
  WorkspaceNotSelected: "workspace_not_selected",
  UserNotActive: "user_not_active",
  MembershipRequired: "membership_required",
  WorkspaceNotActive: "workspace_not_active",
  AppNotAvailable: "app_not_available",
  AppNotEnabledForWorkspace: "app_not_enabled_for_workspace",
  RoleNotPermitted: "role_not_permitted",
  BillingBlocked: "billing_blocked",
} as const;

export type AccessDecisionResult =
  (typeof AccessDecisionResult)[keyof typeof AccessDecisionResult];

export interface BillingGate {
  blocked: boolean;
}

export interface DecideAppAccessInput {
  appKey: string;
  session?: Session | null;
  user?: User | null;
  selectedWorkspaceId?: string | null;
  workspaces: readonly Workspace[];
  memberships: readonly Membership[];
  apps: readonly App[];
  entitlements: readonly AppEntitlement[];
  billingGate?: BillingGate;
  now?: string;
}

export interface AccessDecision {
  result: AccessDecisionResult;
  allowed: boolean;
  message: string;
}

const decisionMessages: Record<AccessDecisionResult, string> = {
  [AccessDecisionResult.Allowed]: "Access allowed.",
  [AccessDecisionResult.NotAuthenticated]: "Authentication is required.",
  [AccessDecisionResult.WorkspaceNotSelected]: "Select a workspace before launching this app.",
  [AccessDecisionResult.UserNotActive]: "The user account cannot launch apps.",
  [AccessDecisionResult.MembershipRequired]: "Workspace membership is required.",
  [AccessDecisionResult.WorkspaceNotActive]: "The selected workspace cannot launch apps.",
  [AccessDecisionResult.AppNotAvailable]: "The requested app is not available.",
  [AccessDecisionResult.AppNotEnabledForWorkspace]: "The selected workspace is not enabled for this app.",
  [AccessDecisionResult.RoleNotPermitted]: "The current role cannot launch this app.",
  [AccessDecisionResult.BillingBlocked]: "A billing gate blocks this app launch.",
};

const allowedAppStatuses = new Set<AppStatus>([
  AppStatus.Available,
  AppStatus.PrivatePreview,
]);

const launchableEntitlementStatuses = new Set<EntitlementStatus>([
  EntitlementStatus.Enabled,
  EntitlementStatus.Trial,
]);

const kqagLaunchRoles = new Set<Role>([
  Role.Owner,
  Role.Admin,
  Role.Member,
]);

const defaultLaunchRoles = new Set<Role>([
  Role.Owner,
  Role.Admin,
  Role.Member,
  Role.Viewer,
]);

export function decideAppAccess(input: DecideAppAccessInput): AccessDecision {
  const { session, user } = input;

  if (!session || !user || session.userId !== user.id || !isSessionUsable(session, input.now)) {
    return decision(AccessDecisionResult.NotAuthenticated);
  }

  if (user.status !== UserStatus.Active) {
    return decision(AccessDecisionResult.UserNotActive);
  }

  if (!input.selectedWorkspaceId) {
    return decision(AccessDecisionResult.WorkspaceNotSelected);
  }

  const membership = input.memberships.find(
    (candidate) =>
      candidate.userId === user.id &&
      candidate.workspaceId === input.selectedWorkspaceId &&
      candidate.status === MembershipStatus.Active,
  );

  if (!membership) {
    return decision(AccessDecisionResult.MembershipRequired);
  }

  const workspace = input.workspaces.find(
    (candidate) => candidate.id === input.selectedWorkspaceId,
  );

  if (!workspace || workspace.status !== WorkspaceStatus.Active) {
    return decision(AccessDecisionResult.WorkspaceNotActive);
  }

  const app = input.apps.find((candidate) => candidate.key === input.appKey);

  if (!app || !allowedAppStatuses.has(app.status)) {
    return decision(AccessDecisionResult.AppNotAvailable);
  }

  const entitlement = input.entitlements.find(
    (candidate) => candidate.workspaceId === workspace.id && candidate.appId === app.id,
  );

  if (!entitlement || !launchableEntitlementStatuses.has(entitlement.status)) {
    return decision(AccessDecisionResult.AppNotEnabledForWorkspace);
  }

  if (!roleCanLaunchApp(membership.role, app.key)) {
    return decision(AccessDecisionResult.RoleNotPermitted);
  }

  if (input.billingGate?.blocked === true) {
    return decision(AccessDecisionResult.BillingBlocked);
  }

  return decision(AccessDecisionResult.Allowed);
}

function decision(result: AccessDecisionResult): AccessDecision {
  return {
    result,
    allowed: result === AccessDecisionResult.Allowed,
    message: decisionMessages[result],
  };
}

function isSessionUsable(session: Session, now?: string): boolean {
  if (session.revokedAt) {
    return false;
  }

  if (!now) {
    return true;
  }

  return Date.parse(session.expiresAt) > Date.parse(now);
}

function roleCanLaunchApp(role: Role, appKey: string): boolean {
  if (appKey === "kqag") {
    return kqagLaunchRoles.has(role);
  }

  return defaultLaunchRoles.has(role);
}
