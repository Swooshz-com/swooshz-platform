import type { BillingGate } from "../access/decide-app-access.js";
import {
  decideProtectedAppAccess,
  ProtectedAppAccessServiceError,
} from "./protected-app-access-service.js";
import type {
  AppLaunchTokenRepository,
  PlatformRepositories,
} from "./repositories.js";
import type { AppLaunchTokenHasher } from "./app-launch-intent-service.js";
import { issueAccessValidationGrant, type AccessValidationGrantDependencies } from "./access-validation-grant-service.js";

export type AppLaunchTokenConsumeServiceErrorCode =
  | "launch_token_hash_failed"
  | "launch_token_lookup_failed"
  | "context_lookup_failed"
  | "access_decision_failed"
  | "launch_token_consume_failed";

export class AppLaunchTokenConsumeServiceError extends Error {
  readonly code: AppLaunchTokenConsumeServiceErrorCode;
  readonly publicMessage = "App launch token could not be consumed.";

  constructor(code: AppLaunchTokenConsumeServiceErrorCode) {
    super("App launch token could not be consumed.");
    this.name = "AppLaunchTokenConsumeServiceError";
    this.code = code;
  }
}

export type AppLaunchTokenConsumeInvalidReason =
  | "missing_launch_token"
  | "invalid_launch_token"
  | "expired_launch_token"
  | "consumed_launch_token"
  | "revoked_launch_token"
  | "app_mismatch"
  | "missing_session"
  | "revoked_session"
  | "expired_session"
  | "missing_user"
  | "missing_workspace"
  | "missing_app";

export interface AppLaunchTokenConsumeDependencies {
  repositories: PlatformRepositories & {
    appLaunchTokens: AppLaunchTokenRepository;
  };
  launchTokenHasher: AppLaunchTokenHasher;
  billingGate?: BillingGate;
  accessValidationGrant?: AccessValidationGrantDependencies;
}

export interface AppLaunchTokenConsumeInput {
  rawLaunchToken: string;
  appKey: string;
  now: string;
}

export type AppLaunchTokenConsumeResult =
  | {
      outcome: "consumed";
      user: {
        userId: string;
        email: string;
        displayName: string;
        status: string;
      };
      workspace: {
        workspaceId: string;
        workspaceSlug: string;
        workspaceName: string;
      };
      app: {
        appKey: string;
        appName: string;
      };
      membershipRole: string;
      launchTokenExpiresAt: string;
      validationGrantId?: string;
    }
  | {
      outcome: "invalid";
      reason: AppLaunchTokenConsumeInvalidReason;
    }
  | {
      outcome: "denied";
      reason: "app_access_denied";
      decision: NonNullable<
        Extract<
          Awaited<ReturnType<typeof decideProtectedAppAccess>>,
          { outcome: "denied" }
        >["decision"]
      >;
    };

export async function consumeAppLaunchToken(
  dependencies: AppLaunchTokenConsumeDependencies,
  input: AppLaunchTokenConsumeInput,
): Promise<AppLaunchTokenConsumeResult> {
  const rawLaunchToken = input.rawLaunchToken.trim();

  if (!rawLaunchToken) {
    return invalid("missing_launch_token");
  }

  const tokenHash = await hashTokenSafely(
    dependencies.launchTokenHasher,
    rawLaunchToken,
  );
  const token = await findTokenSafely(
    dependencies.repositories.appLaunchTokens,
    tokenHash,
  );

  if (!token) {
    return invalid("invalid_launch_token");
  }

  if (Date.parse(token.expiresAt) <= Date.parse(input.now)) {
    return invalid("expired_launch_token");
  }

  if (token.consumedAt) {
    return invalid("consumed_launch_token");
  }

  if (token.revokedAt) {
    return invalid("revoked_launch_token");
  }

  const context = await loadContextSafely(dependencies.repositories, token);

  if (!context.session) {
    return invalid("missing_session");
  }

  if (context.session.revokedAt) {
    return invalid("revoked_session");
  }

  if (Date.parse(context.session.expiresAt) <= Date.parse(input.now)) {
    return invalid("expired_session");
  }

  if (!context.user) {
    return invalid("missing_user");
  }

  if (!context.workspace) {
    return invalid("missing_workspace");
  }

  if (!context.app) {
    return invalid("missing_app");
  }

  if (context.app.key !== input.appKey) {
    return invalid("app_mismatch");
  }

  const access = await decideAccessSafely(dependencies, {
    sessionId: token.sessionId,
    selectedWorkspaceId: token.workspaceId,
    appKey: context.app.key,
    now: input.now,
  });

  if (access.outcome === "denied") {
    if (access.reason !== "app_access_denied") {
      return invalid(access.reason);
    }

    return {
      outcome: "denied",
      reason: "app_access_denied",
      decision: access.decision!,
    };
  }

  const membership = await findMembershipSafely(
    dependencies.repositories,
    context.user.id,
    context.workspace.id,
  );

  if (!membership) {
    return {
      outcome: "denied",
      reason: "app_access_denied",
      decision: {
        result: "membership_required",
        allowed: false,
        message: "Workspace membership is required.",
      },
    };
  }

  const consumed = await consumeTokenSafely(
    dependencies.repositories.appLaunchTokens,
    token.id,
    input.now,
  );

  if (!consumed) {
    return invalid("consumed_launch_token");
  }

  const grant = dependencies.accessValidationGrant
    ? await issueAccessValidationGrant(dependencies.accessValidationGrant, {
        sessionId: token.sessionId,
        userId: token.userId,
        workspaceId: token.workspaceId,
        appId: token.appId,
        launchTokenExpiresAt: token.expiresAt,
        now: input.now,
      })
    : null;

  return {
    outcome: "consumed",
    user: {
      userId: context.user.id,
      email: context.user.email,
      displayName: context.user.displayName,
      status: context.user.status,
    },
    workspace: {
      workspaceId: context.workspace.id,
      workspaceSlug: context.workspace.slug,
      workspaceName: context.workspace.displayName,
    },
    app: {
      appKey: context.app.key,
      appName: context.app.name,
    },
    membershipRole: membership.role,
    launchTokenExpiresAt: token.expiresAt,
    ...(grant ? { validationGrantId: grant.id } : {}),
  };
}

function invalid(
  reason: AppLaunchTokenConsumeInvalidReason,
): AppLaunchTokenConsumeResult {
  return {
    outcome: "invalid",
    reason,
  };
}

async function hashTokenSafely(
  hasher: AppLaunchTokenHasher,
  token: string,
): Promise<string> {
  try {
    const tokenHash = await hasher.hashToken(token);

    if (!tokenHash.trim()) {
      throw new Error("Blank launch token hash.");
    }

    return tokenHash;
  } catch {
    throw new AppLaunchTokenConsumeServiceError("launch_token_hash_failed");
  }
}

async function findTokenSafely(
  repository: AppLaunchTokenRepository,
  tokenHash: string,
) {
  try {
    return await repository.findByTokenHash(tokenHash);
  } catch {
    throw new AppLaunchTokenConsumeServiceError("launch_token_lookup_failed");
  }
}

async function loadContextSafely(
  repositories: PlatformRepositories,
  token: {
    sessionId: string;
    userId: string;
    workspaceId: string;
    appId: string;
  },
) {
  try {
    const [session, user, workspace, app] = await Promise.all([
      repositories.sessions.findById(token.sessionId),
      repositories.users.findById(token.userId),
      repositories.workspaces.findById(token.workspaceId),
      repositories.apps.findById(token.appId),
    ]);

    return {
      session,
      user,
      workspace,
      app,
    };
  } catch {
    throw new AppLaunchTokenConsumeServiceError("context_lookup_failed");
  }
}

async function decideAccessSafely(
  dependencies: AppLaunchTokenConsumeDependencies,
  input: {
    sessionId: string;
    selectedWorkspaceId: string;
    appKey: string;
    now: string;
  },
) {
  try {
    return await decideProtectedAppAccess(dependencies.repositories, {
      ...input,
      billingGate: dependencies.billingGate,
    });
  } catch (error) {
    if (error instanceof ProtectedAppAccessServiceError) {
      throw new AppLaunchTokenConsumeServiceError("access_decision_failed");
    }

    throw new AppLaunchTokenConsumeServiceError("access_decision_failed");
  }
}

async function findMembershipSafely(
  repositories: PlatformRepositories,
  userId: string,
  workspaceId: string,
) {
  try {
    return await repositories.memberships.findForUserInWorkspace(
      userId,
      workspaceId,
    );
  } catch {
    throw new AppLaunchTokenConsumeServiceError("context_lookup_failed");
  }
}

async function consumeTokenSafely(
  repository: AppLaunchTokenRepository,
  id: string,
  consumedAt: string,
) {
  try {
    return await repository.consumeUnconsumed(id, consumedAt);
  } catch {
    throw new AppLaunchTokenConsumeServiceError("launch_token_consume_failed");
  }
}
