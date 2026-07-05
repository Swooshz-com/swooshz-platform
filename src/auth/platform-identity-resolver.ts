import {
  MembershipStatus,
  Role,
  UserStatus,
  WorkspaceStatus,
  type AuditEvent,
  type Membership,
  type Session,
  type User,
} from "../accounts/types.js";
import type {
  ProviderIdentity,
  ProviderIdentityRepository,
  PlatformRepositories,
  SessionRepository,
  UserRepository,
  WorkspaceMembershipApprovalRecord,
} from "../platform/repositories.js";
import type {
  AuthCallbackPlatformIdentityResolution,
  AuthCallbackPlatformIdentityResolver,
  AuthenticatedPlatformIdentityInput,
} from "./callback-service.js";
import { AuthCallbackError } from "./errors.js";

export interface PlatformIdentitySessionResolverRepositories {
  users: UserRepository;
  providerIdentities: ProviderIdentityRepository;
  sessions: SessionRepository;
  workspaces?: PlatformRepositories["workspaces"];
  memberships?: PlatformRepositories["memberships"];
  membershipApprovals?: PlatformRepositories["membershipApprovals"];
  auditEvents?: PlatformRepositories["auditEvents"];
  appEntitlements?: PlatformRepositories["appEntitlements"];
  apps?: PlatformRepositories["apps"];
  workspaceAdminTransactions?: PlatformRepositories["workspaceAdminTransactions"];
}

export interface PlatformIdentitySessionResolverDependencies {
  repositories: PlatformIdentitySessionResolverRepositories;
  sessionIdFactory(input: SessionIdFactoryInput): string;
  userIdFactory(input: UserIdFactoryInput): string;
  providerIdentityIdFactory(input: ProviderIdentityIdFactoryInput): string;
  membershipIdFactory?(input: MembershipIdFactoryInput): string;
  auditEventIdFactory?(input: MembershipApprovalAuditEventIdFactoryInput): string;
  sessionDurationMs: number;
}

export interface SessionIdFactoryInput {
  userId: string;
  providerKey: string;
  providerSubject: string;
  now: string;
}

export interface UserIdFactoryInput {
  providerKey: string;
  providerSubject: string;
  verifiedEmail: string;
  now: string;
}

export interface ProviderIdentityIdFactoryInput {
  userId: string;
  providerKey: string;
  providerSubject: string;
  now: string;
}

export interface MembershipIdFactoryInput {
  approvalId: string;
  userId: string;
  workspaceId: string;
  now: string;
}

export interface MembershipApprovalAuditEventIdFactoryInput {
  approvalId: string;
  userId: string;
  workspaceId: string;
  now: string;
}

export function createPlatformIdentitySessionResolver(
  dependencies: PlatformIdentitySessionResolverDependencies,
): AuthCallbackPlatformIdentityResolver {
  return {
    async resolveAuthenticatedIdentity(input) {
      return resolveAuthenticatedIdentity(dependencies, input);
    },
  };
}

async function resolveAuthenticatedIdentity(
  dependencies: PlatformIdentitySessionResolverDependencies,
  input: AuthenticatedPlatformIdentityInput,
): Promise<AuthCallbackPlatformIdentityResolution> {
  const providerIdentity = await findProviderIdentitySafely(dependencies, input);

  if (providerIdentity) {
    const user = await findUserByIdSafely(dependencies, providerIdentity.userId);

    if (!user) {
      throw new AuthCallbackError(
        "invalid_platform_identity_state",
        "Authenticated platform identity could not be resolved.",
      );
    }

    assertUserCanCreateSession(user);

    return {
      platformUserId: user.id,
      providerIdentityId: providerIdentity.id,
      session: await createSession(dependencies, user.id, input),
    };
  }

  const pendingApprovalRequired = input.authPolicy?.providerEmailAllowed === false;
  const pendingApprovalResolution = await resolvePendingApprovedIdentity(dependencies, input, {
    requireApproval: pendingApprovalRequired,
  });

  if (pendingApprovalResolution) {
    return pendingApprovalResolution;
  }

  const user = await createUserForNewProviderIdentity(dependencies, input);
  const linkedProviderIdentity = await createProviderIdentity(
    dependencies,
    user.id,
    input,
  );

  return {
    platformUserId: user.id,
    providerIdentityId: linkedProviderIdentity.id,
    session: await createSession(dependencies, user.id, input),
  };
}

async function resolvePendingApprovedIdentity(
  dependencies: PlatformIdentitySessionResolverDependencies,
  input: AuthenticatedPlatformIdentityInput,
  options: { requireApproval: boolean },
): Promise<AuthCallbackPlatformIdentityResolution | null> {
  if (!input.identity.verifiedEmail) {
    if (!options.requireApproval) {
      return null;
    }

    throw new AuthCallbackError(
      "verified_email_required",
      "Verified provider email is required to accept workspace membership approval.",
    );
  }

  const transaction = dependencies.repositories.workspaceAdminTransactions;

  if (!transaction) {
    if (!options.requireApproval) {
      return null;
    }

    throw membershipApprovalAcceptanceError();
  }

  if (!dependencies.repositories.membershipApprovals) {
    if (!options.requireApproval) {
      return null;
    }

    throw membershipApprovalAcceptanceError();
  }

  try {
    return await transaction.run(async (transactionRepositories) => {
      const transactionDependencies = {
        ...dependencies,
        repositories: {
          ...dependencies.repositories,
          ...transactionRepositories,
        },
      };
      const approvals = await listPendingApprovalsForEmailSafely(
        transactionDependencies,
        input.identity.verifiedEmail ?? "",
      );

      if (approvals.length === 0) {
        if (!options.requireApproval) {
          return null;
        }

        throw new AuthCallbackError(
          "onboarding_approval_required",
          "Workspace membership approval is required for this provider identity.",
        );
      }

      await assertApprovalsCanBeAccepted(transactionDependencies, approvals, input);
      const user = await findOrCreatePendingApprovedUser(transactionDependencies, input);
      const linkedProviderIdentity = await createProviderIdentity(
        transactionDependencies,
        user.id,
        input,
      );

      for (const approval of approvals) {
        await acceptPendingApproval(transactionDependencies, approval, user, input);
      }

      return {
        platformUserId: user.id,
        providerIdentityId: linkedProviderIdentity.id,
        session: await createSession(transactionDependencies, user.id, input),
        workspaceMembershipGranted: true,
      };
    });
  } catch (error) {
    if (
      error instanceof AuthCallbackError &&
      error.code === "onboarding_approval_required"
    ) {
      throw error;
    }

    if (error instanceof AuthCallbackError && error.code === "verified_email_required") {
      throw error;
    }

    throw membershipApprovalAcceptanceError();
  }
}

async function findOrCreatePendingApprovedUser(
  dependencies: PlatformIdentitySessionResolverDependencies,
  input: AuthenticatedPlatformIdentityInput,
): Promise<User> {
  const verifiedEmail = input.identity.verifiedEmail;

  if (!verifiedEmail) {
    throw new AuthCallbackError(
      "verified_email_required",
      "Verified provider email is required to create a platform user.",
    );
  }

  const existingUser = await findUserByNormalizedEmailSafely(dependencies, verifiedEmail);

  if (!existingUser) {
    return createUserForNewProviderIdentity(dependencies, input);
  }

  assertUserCanCreateSession(existingUser);

  const existingIdentities = await dependencies.repositories.providerIdentities.listForUser(
    existingUser.id,
  );

  if (existingIdentities.length > 0) {
    throw new AuthCallbackError(
      "provider_identity_link_failed",
      "Authenticated provider identity could not be linked.",
    );
  }

  return existingUser;
}

async function listPendingApprovalsForEmailSafely(
  dependencies: PlatformIdentitySessionResolverDependencies,
  email: string,
): Promise<readonly WorkspaceMembershipApprovalRecord[]> {
  const approvals = dependencies.repositories.membershipApprovals;

  if (!approvals) {
    throw membershipApprovalAcceptanceError();
  }

  try {
    return approvals.listPendingForEmail(email);
  } catch {
    throw membershipApprovalAcceptanceError();
  }
}

async function assertApprovalsCanBeAccepted(
  dependencies: PlatformIdentitySessionResolverDependencies,
  approvals: readonly WorkspaceMembershipApprovalRecord[],
  input: AuthenticatedPlatformIdentityInput,
): Promise<void> {
  const workspaces = dependencies.repositories.workspaces;
  const memberships = dependencies.repositories.memberships;

  if (!workspaces || !memberships) {
    throw membershipApprovalAcceptanceError();
  }

  for (const approval of approvals) {
    if (
      approval.status !== "pending" ||
      approval.revokedAt ||
      approval.acceptedAt ||
      !["admin", "member", "viewer"].includes(approval.role)
    ) {
      throw membershipApprovalAcceptanceError();
    }

    const workspace = await workspaces.findById(approval.workspaceId);

    if (!workspace || workspace.status !== WorkspaceStatus.Active) {
      throw membershipApprovalAcceptanceError();
    }

    const existingUser = input.identity.verifiedEmail
      ? await findUserByNormalizedEmailSafely(dependencies, input.identity.verifiedEmail)
      : null;

    if (existingUser) {
      const existingMembership = await memberships.findForUserInWorkspace(
        existingUser.id,
        approval.workspaceId,
      );

      if (existingMembership) {
        throw membershipApprovalAcceptanceError();
      }
    }
  }
}

async function acceptPendingApproval(
  dependencies: PlatformIdentitySessionResolverDependencies,
  approval: WorkspaceMembershipApprovalRecord,
  user: User,
  input: AuthenticatedPlatformIdentityInput,
): Promise<void> {
  const memberships = dependencies.repositories.memberships;
  const approvals = dependencies.repositories.membershipApprovals;
  const auditEvents = dependencies.repositories.auditEvents;
  const membershipIdFactory = dependencies.membershipIdFactory;
  const auditEventIdFactory = dependencies.auditEventIdFactory;

  if (!memberships || !approvals || !auditEvents || !membershipIdFactory || !auditEventIdFactory) {
    throw membershipApprovalAcceptanceError();
  }

  const membership: Membership = {
    id: membershipIdFactory({
      approvalId: approval.id,
      userId: user.id,
      workspaceId: approval.workspaceId,
      now: input.now,
    }),
    workspaceId: approval.workspaceId,
    userId: user.id,
    role: approval.role,
    status: MembershipStatus.Active,
    createdAt: input.now,
    updatedAt: input.now,
  };

  await memberships.create(membership);
  const updated = await approvals.updateStatus(approval.id, "accepted", {
    updatedAt: input.now,
    acceptedAt: input.now,
    acceptedUserId: user.id,
  });

  if (!updated) {
    throw membershipApprovalAcceptanceError();
  }

  const event: AuditEvent = {
    id: auditEventIdFactory({
      approvalId: approval.id,
      userId: user.id,
      workspaceId: approval.workspaceId,
      now: input.now,
    }),
    workspaceId: approval.workspaceId,
    actorUserId: user.id,
    eventType: "workspace.membership_approval.accepted",
    targetType: "membership_approval",
    targetId: approval.id,
    createdAt: input.now,
    metadata: {
      newRole: approval.role,
      newStatus: "active",
      targetUserId: user.id,
      source: "provider_backed_sign_in",
    },
  };

  await auditEvents.append(event);
}

async function createUserForNewProviderIdentity(
  dependencies: PlatformIdentitySessionResolverDependencies,
  input: AuthenticatedPlatformIdentityInput,
): Promise<User> {
  if (!input.identity.verifiedEmail) {
    throw new AuthCallbackError(
      "verified_email_required",
      "Verified provider email is required to create a platform user.",
    );
  }

  const existingUser = await findUserByNormalizedEmailSafely(
    dependencies,
    input.identity.verifiedEmail,
  );

  if (existingUser) {
    throw new AuthCallbackError(
      "provider_identity_link_failed",
      "Authenticated provider identity could not be linked.",
    );
  }

  try {
    return await dependencies.repositories.users.create({
      id: dependencies.userIdFactory({
        providerKey: input.identity.providerKey,
        providerSubject: input.identity.providerSubject,
        verifiedEmail: input.identity.verifiedEmail,
        now: input.now,
      }),
      email: input.identity.verifiedEmail,
      displayName: input.identity.displayName?.trim() || input.identity.verifiedEmail,
      status: UserStatus.Active,
      createdAt: input.now,
      updatedAt: input.now,
      lastLoginAt: input.now,
    });
  } catch {
    throw new AuthCallbackError(
      "provider_identity_link_failed",
      "Authenticated provider identity could not be linked.",
    );
  }
}

async function findProviderIdentitySafely(
  dependencies: PlatformIdentitySessionResolverDependencies,
  input: AuthenticatedPlatformIdentityInput,
): Promise<ProviderIdentity | null> {
  try {
    return await dependencies.repositories.providerIdentities.findByProviderSubject(
      input.identity.providerKey,
      input.identity.providerSubject,
    );
  } catch {
    throw new AuthCallbackError(
      "provider_identity_link_failed",
      "Authenticated provider identity could not be linked.",
    );
  }
}

async function findUserByIdSafely(
  dependencies: PlatformIdentitySessionResolverDependencies,
  userId: string,
): Promise<User | null> {
  try {
    return await dependencies.repositories.users.findById(userId);
  } catch {
    throw new AuthCallbackError(
      "provider_identity_link_failed",
      "Authenticated provider identity could not be linked.",
    );
  }
}

async function findUserByNormalizedEmailSafely(
  dependencies: PlatformIdentitySessionResolverDependencies,
  email: string,
): Promise<User | null> {
  try {
    return await dependencies.repositories.users.findByNormalizedEmail(email);
  } catch {
    throw new AuthCallbackError(
      "provider_identity_link_failed",
      "Authenticated provider identity could not be linked.",
    );
  }
}

async function createProviderIdentity(
  dependencies: PlatformIdentitySessionResolverDependencies,
  userId: string,
  input: AuthenticatedPlatformIdentityInput,
): Promise<ProviderIdentity> {
  try {
    return await dependencies.repositories.providerIdentities.create({
      id: dependencies.providerIdentityIdFactory({
        userId,
        providerKey: input.identity.providerKey,
        providerSubject: input.identity.providerSubject,
        now: input.now,
      }),
      userId,
      providerKey: input.identity.providerKey,
      providerSubject: input.identity.providerSubject,
      createdAt: input.now,
      updatedAt: input.now,
    });
  } catch {
    throw new AuthCallbackError(
      "provider_identity_link_failed",
      "Authenticated provider identity could not be linked.",
    );
  }
}

async function createSession(
  dependencies: PlatformIdentitySessionResolverDependencies,
  userId: string,
  input: AuthenticatedPlatformIdentityInput,
): Promise<Session> {
  const session = {
    id: dependencies.sessionIdFactory({
      userId,
      providerKey: input.identity.providerKey,
      providerSubject: input.identity.providerSubject,
      now: input.now,
    }),
    userId,
    createdAt: input.now,
    expiresAt: addMilliseconds(input.now, dependencies.sessionDurationMs),
    lastSeenAt: input.now,
    revokedAt: null,
  };

  try {
    return await dependencies.repositories.sessions.create(session);
  } catch {
    throw new AuthCallbackError(
      "session_creation_failed",
      "Platform session could not be created.",
    );
  }
}

function assertUserCanCreateSession(user: User): void {
  if (user.status !== UserStatus.Active) {
    throw new AuthCallbackError(
      "user_not_active",
      "Platform user cannot create a session.",
    );
  }
}

function membershipApprovalAcceptanceError(): AuthCallbackError {
  return new AuthCallbackError(
    "membership_approval_acceptance_failed",
    "Workspace membership approval could not be accepted.",
  );
}

function addMilliseconds(timestamp: string, milliseconds: number): string {
  return new Date(Date.parse(timestamp) + milliseconds).toISOString();
}
