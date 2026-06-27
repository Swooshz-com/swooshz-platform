import type { SessionRepository } from "../platform/repositories.js";
import { AuthSessionError } from "./errors.js";

export type SessionRevocationResult =
  | {
      outcome: "revoked";
      sessionId: string;
      revokedAt: string;
    }
  | {
      outcome: "already_revoked";
      sessionId: string;
      revokedAt: string;
    }
  | {
      outcome: "not_found";
    };

export interface SessionRevocationServiceDependencies {
  sessions: SessionRepository;
}

export interface SessionRevocationInput {
  sessionId: string;
  now: string;
}

export async function revokePlatformSession(
  dependencies: SessionRevocationServiceDependencies,
  input: SessionRevocationInput,
): Promise<SessionRevocationResult> {
  const session = await findSessionSafely(dependencies.sessions, input.sessionId);

  if (!session) {
    return { outcome: "not_found" };
  }

  if (session.revokedAt) {
    return {
      outcome: "already_revoked",
      sessionId: session.id,
      revokedAt: session.revokedAt,
    };
  }

  const revokedSession = await revokeSessionSafely(
    dependencies.sessions,
    input.sessionId,
    input.now,
  );

  if (!revokedSession) {
    return { outcome: "not_found" };
  }

  return {
    outcome: "revoked",
    sessionId: revokedSession.id,
    revokedAt: revokedSession.revokedAt ?? input.now,
  };
}

async function findSessionSafely(
  sessions: SessionRepository,
  sessionId: string,
) {
  try {
    return await sessions.findById(sessionId);
  } catch {
    throw new AuthSessionError(
      "session_lookup_failed",
      "Session lookup could not be completed.",
    );
  }
}

async function revokeSessionSafely(
  sessions: SessionRepository,
  sessionId: string,
  revokedAt: string,
) {
  try {
    return await sessions.revoke(sessionId, revokedAt);
  } catch {
    throw new AuthSessionError(
      "session_revocation_failed",
      "Session revocation could not be completed.",
    );
  }
}
