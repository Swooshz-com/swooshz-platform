import type { BillingGate } from "../access/decide-app-access.js";
import {
  decideProtectedAppAccess,
  ProtectedAppAccessServiceError,
  type ProtectedAppAccessDeniedReason,
} from "./protected-app-access-service.js";
import type {
  AppLaunchTokenRecord,
  AppLaunchTokenRepository,
  PlatformRepositories,
} from "./repositories.js";

export type AppLaunchIntentServiceErrorCode =
  | "access_decision_failed"
  | "app_lookup_failed"
  | "invalid_expiry"
  | "launch_token_factory_failed"
  | "launch_token_hash_failed"
  | "launch_token_store_failed";

export class AppLaunchIntentServiceError extends Error {
  readonly code: AppLaunchIntentServiceErrorCode;
  readonly publicMessage = "App launch intent could not be created.";

  constructor(code: AppLaunchIntentServiceErrorCode) {
    super("App launch intent could not be created.");
    this.name = "AppLaunchIntentServiceError";
    this.code = code;
  }
}

export interface AppLaunchTokenFactory {
  createToken(): Promise<string>;
}

export interface AppLaunchTokenHasher {
  hashToken(token: string): Promise<string>;
}

export interface AppLaunchTokenIdFactory {
  createId(): string;
}

export interface AppLaunchIntentDependencies {
  repositories: PlatformRepositories & {
    appLaunchTokens: AppLaunchTokenRepository;
  };
  launchTokenFactory: AppLaunchTokenFactory;
  launchTokenHasher: AppLaunchTokenHasher;
  launchTokenIdFactory: AppLaunchTokenIdFactory;
  ttlSeconds: number;
  billingGate?: BillingGate;
}

export interface AppLaunchIntentInput {
  sessionId: string;
  selectedWorkspaceId: string;
  appKey: string;
  now: string;
}

export type AppLaunchIntentResult =
  | {
      outcome: "created";
      appKey: string;
      workspaceId: string;
      appLaunchUrl: string | null;
      launchToken: string;
      launchTokenExpiresAt: string;
    }
  | {
      outcome: "unauthenticated";
      reason: Exclude<
        ProtectedAppAccessDeniedReason,
        "app_access_denied"
      >;
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

export async function createAppLaunchIntent(
  dependencies: AppLaunchIntentDependencies,
  input: AppLaunchIntentInput,
): Promise<AppLaunchIntentResult> {
  const access = await decideAccessSafely(dependencies.repositories, input, dependencies);

  if (access.outcome === "denied") {
    if (access.reason === "app_access_denied") {
      return {
        outcome: "denied",
        reason: "app_access_denied",
        decision: access.decision!,
      };
    }

    return {
      outcome: "unauthenticated",
      reason: access.reason,
    };
  }

  const app = await findAppSafely(dependencies.repositories, access.appKey);
  const launchTokenExpiresAt = getExpiresAtSafely(input.now, dependencies.ttlSeconds);
  const launchToken = await createTokenSafely(dependencies.launchTokenFactory);
  const tokenHash = await hashTokenSafely(
    dependencies.launchTokenHasher,
    launchToken,
  );

  await createLaunchTokenRecordSafely(dependencies.repositories.appLaunchTokens, {
    id: createIdSafely(dependencies.launchTokenIdFactory),
    sessionId: access.sessionId,
    userId: access.userId,
    workspaceId: access.workspaceId,
    appId: app.id,
    tokenHash,
    createdAt: input.now,
    expiresAt: launchTokenExpiresAt,
    consumedAt: null,
    revokedAt: null,
  });

  return {
    outcome: "created",
    appKey: access.appKey,
    workspaceId: access.workspaceId,
    appLaunchUrl: app.launchUrl,
    launchToken,
    launchTokenExpiresAt,
  };
}

async function decideAccessSafely(
  repositories: PlatformRepositories,
  input: AppLaunchIntentInput,
  dependencies: Pick<AppLaunchIntentDependencies, "billingGate">,
) {
  try {
    return await decideProtectedAppAccess(repositories, {
      sessionId: input.sessionId,
      selectedWorkspaceId: input.selectedWorkspaceId,
      appKey: input.appKey,
      now: input.now,
      billingGate: dependencies.billingGate,
    });
  } catch (error) {
    if (error instanceof ProtectedAppAccessServiceError) {
      throw new AppLaunchIntentServiceError("access_decision_failed");
    }

    throw new AppLaunchIntentServiceError("access_decision_failed");
  }
}

async function findAppSafely(
  repositories: PlatformRepositories,
  appKey: string,
) {
  try {
    const app = await repositories.apps.findByKey(appKey);

    if (!app) {
      throw new Error("Missing app.");
    }

    return app;
  } catch {
    throw new AppLaunchIntentServiceError("app_lookup_failed");
  }
}

async function createTokenSafely(
  factory: AppLaunchTokenFactory,
): Promise<string> {
  try {
    const token = await factory.createToken();

    if (!token.trim()) {
      throw new Error("Blank launch token.");
    }

    return token;
  } catch {
    throw new AppLaunchIntentServiceError("launch_token_factory_failed");
  }
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
    throw new AppLaunchIntentServiceError("launch_token_hash_failed");
  }
}

function createIdSafely(idFactory: AppLaunchTokenIdFactory): string {
  try {
    return idFactory.createId();
  } catch {
    throw new AppLaunchIntentServiceError("launch_token_store_failed");
  }
}

async function createLaunchTokenRecordSafely(
  repository: AppLaunchTokenRepository,
  record: AppLaunchTokenRecord,
): Promise<AppLaunchTokenRecord> {
  try {
    return await repository.create(record);
  } catch {
    throw new AppLaunchIntentServiceError("launch_token_store_failed");
  }
}

function getExpiresAtSafely(now: string, ttlSeconds: number): string {
  if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) {
    throw new AppLaunchIntentServiceError("invalid_expiry");
  }

  const nowMs = Date.parse(now);

  if (!Number.isFinite(nowMs)) {
    throw new AppLaunchIntentServiceError("invalid_expiry");
  }

  return new Date(nowMs + ttlSeconds * 1000).toISOString();
}
