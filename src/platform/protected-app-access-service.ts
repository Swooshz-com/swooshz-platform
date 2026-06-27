import {
  type AccessDecision,
  type BillingGate,
} from "../access/decide-app-access.js";
import {
  decidePlatformAppAccess,
  type DecidePlatformAppAccessInput,
} from "./app-access-service.js";
import type { PlatformRepositories } from "./repositories.js";

export type ProtectedAppAccessDeniedReason =
  | "missing_session"
  | "revoked_session"
  | "expired_session"
  | "app_access_denied";

export type ProtectedAppAccessServiceErrorCode =
  | "session_lookup_failed"
  | "app_access_decision_failed";

export type ProtectedAppAccessDecisionResult =
  | {
      outcome: "allowed";
      sessionId: string;
      userId: string;
      workspaceId: string;
      appKey: string;
      decision: AccessDecision;
    }
  | {
      outcome: "denied";
      reason: ProtectedAppAccessDeniedReason;
      decision?: AccessDecision;
    };

export interface ProtectedAppAccessDecisionInput {
  sessionId: string;
  selectedWorkspaceId: string;
  appKey: string;
  now: string;
  billingGate?: BillingGate;
}

export class ProtectedAppAccessServiceError extends Error {
  readonly code: ProtectedAppAccessServiceErrorCode;
  readonly publicMessage = "App access decision could not be completed.";

  constructor(code: ProtectedAppAccessServiceErrorCode, message: string) {
    super(message);
    this.name = "ProtectedAppAccessServiceError";
    this.code = code;
  }
}

export async function decideProtectedAppAccess(
  repositories: PlatformRepositories,
  input: ProtectedAppAccessDecisionInput,
): Promise<ProtectedAppAccessDecisionResult> {
  const session = await findSessionSafely(repositories, input.sessionId);

  if (!session) {
    return denied("missing_session");
  }

  if (session.revokedAt) {
    return denied("revoked_session");
  }

  if (isExpired(session.expiresAt, input.now)) {
    return denied("expired_session");
  }

  const decision = await decideAppAccessSafely(repositories, input);

  if (!decision.allowed) {
    return {
      outcome: "denied",
      reason: "app_access_denied",
      decision,
    };
  }

  return {
    outcome: "allowed",
    sessionId: session.id,
    userId: session.userId,
    workspaceId: input.selectedWorkspaceId,
    appKey: input.appKey,
    decision,
  };
}

function denied(
  reason: ProtectedAppAccessDeniedReason,
): ProtectedAppAccessDecisionResult {
  return {
    outcome: "denied",
    reason,
  };
}

async function findSessionSafely(
  repositories: PlatformRepositories,
  sessionId: string,
) {
  try {
    return await repositories.sessions.findById(sessionId);
  } catch {
    throw new ProtectedAppAccessServiceError(
      "session_lookup_failed",
      "Session lookup could not be completed.",
    );
  }
}

async function decideAppAccessSafely(
  repositories: PlatformRepositories,
  input: ProtectedAppAccessDecisionInput,
) {
  try {
    const appAccessInput: DecidePlatformAppAccessInput = {
      sessionId: input.sessionId,
      selectedWorkspaceId: input.selectedWorkspaceId,
      appKey: input.appKey,
      now: input.now,
      billingGate: input.billingGate,
    };

    return await decidePlatformAppAccess(repositories, appAccessInput);
  } catch {
    throw new ProtectedAppAccessServiceError(
      "app_access_decision_failed",
      "App access decision could not be completed.",
    );
  }
}

function isExpired(expiresAt: string, now: string): boolean {
  return Date.parse(expiresAt) <= Date.parse(now);
}
