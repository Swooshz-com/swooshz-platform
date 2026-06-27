import type { BillingGate } from "../access/decide-app-access.js";
import {
  revokePlatformSession,
  type SessionRevocationServiceDependencies,
} from "../auth/session-revocation-service.js";
import {
  decideProtectedAppAccess,
  ProtectedAppAccessServiceError,
} from "../platform/protected-app-access-service.js";
import type { PlatformRepositories, SessionRepository } from "../platform/repositories.js";
import {
  CsrfTokenServiceError,
  issueCsrfTokenForSession,
  type CsrfTokenServiceDependencies,
} from "./csrf-token-service.js";
import {
  buildBrowserSessionClearCookie,
  extractBrowserSessionIdFromCookieHeader,
  type BrowserSessionCookieConfig,
} from "./session-cookie.js";

export interface HttpRequestHeaders {
  [name: string]: string | undefined;
}

export interface HttpResponseLike {
  status: number;
  headers?: Record<string, string>;
  body?: unknown;
}

export interface ProtectedAppAccessHttpRequest {
  headers?: HttpRequestHeaders;
  selectedWorkspaceId: string;
  appKey: string;
  now: string;
  billingGate?: BillingGate;
  cookie?: BrowserSessionCookieConfig;
}

export interface LogoutHttpRequest {
  headers?: HttpRequestHeaders;
  now: string;
  cookie?: BrowserSessionCookieConfig;
}

export interface CsrfTokenIssueHttpDependencies {
  sessions: SessionRepository;
  csrf: CsrfTokenServiceDependencies;
}

export interface CsrfTokenIssueHttpRequest {
  headers?: HttpRequestHeaders;
  now: string;
  ttlSeconds: number;
  cookie?: BrowserSessionCookieConfig;
}

export async function handleProtectedAppAccessRequest(
  repositories: PlatformRepositories,
  request: ProtectedAppAccessHttpRequest,
): Promise<HttpResponseLike> {
  const sessionId = extractSessionId(request.headers, request.cookie);

  if (!sessionId) {
    return denied(401, "missing_session");
  }

  try {
    const decision = await decideProtectedAppAccess(repositories, {
      sessionId,
      selectedWorkspaceId: request.selectedWorkspaceId,
      appKey: request.appKey,
      now: request.now,
      billingGate: request.billingGate,
    });

    if (decision.outcome === "allowed") {
      return {
        status: 200,
        body: {
          outcome: "allowed",
          userId: decision.userId,
          workspaceId: decision.workspaceId,
          appKey: decision.appKey,
          decision: decision.decision,
        },
      };
    }

    if (
      decision.reason === "missing_session" ||
      decision.reason === "revoked_session" ||
      decision.reason === "expired_session"
    ) {
      return denied(401, decision.reason);
    }

    return {
      status: 403,
      body: {
        outcome: "denied",
        reason: "app_access_denied",
        decision: decision.decision,
      },
    };
  } catch (error) {
    if (error instanceof ProtectedAppAccessServiceError) {
      return serviceFailure();
    }

    return serviceFailure();
  }
}

export async function handleCsrfTokenIssueRequest(
  dependencies: CsrfTokenIssueHttpDependencies,
  request: CsrfTokenIssueHttpRequest,
): Promise<HttpResponseLike> {
  const sessionId = extractSessionId(request.headers, request.cookie);

  if (!sessionId) {
    return denied(401, "missing_session");
  }

  const session = await findSessionSafely(dependencies.sessions, sessionId);

  if (session === "failure") {
    return csrfIssueFailure();
  }

  if (!session) {
    return denied(401, "unknown_session");
  }

  if (session.revokedAt) {
    return denied(401, "revoked_session");
  }

  if (Date.parse(session.expiresAt) <= Date.parse(request.now)) {
    return denied(401, "expired_session");
  }

  try {
    const issued = await issueCsrfTokenForSession(dependencies.csrf, {
      sessionId: session.id,
      now: request.now,
      ttlSeconds: request.ttlSeconds,
      purpose: "browser_session",
    });

    return {
      status: 200,
      body: {
        outcome: "issued",
        csrfToken: issued.csrfToken,
        expiresAt: issued.expiresAt,
      },
    };
  } catch (error) {
    if (error instanceof CsrfTokenServiceError) {
      return csrfIssueFailure();
    }

    return csrfIssueFailure();
  }
}

export async function handleLogoutRequest(
  dependencies: SessionRevocationServiceDependencies,
  request: LogoutHttpRequest,
): Promise<HttpResponseLike> {
  const sessionId = extractSessionId(request.headers, request.cookie);

  if (sessionId) {
    try {
      await revokePlatformSession(dependencies, {
        sessionId,
        now: request.now,
      });
    } catch {
      // Logout responses intentionally do not reveal storage/session state.
    }
  }

  return {
    status: 200,
    headers: {
      "set-cookie": buildBrowserSessionClearCookie(request.cookie),
    },
    body: {
      outcome: "logged_out",
    },
  };
}

function extractSessionId(
  headers: HttpRequestHeaders | undefined,
  config: BrowserSessionCookieConfig | undefined,
): string | null {
  return extractBrowserSessionIdFromCookieHeader(readHeader(headers, "cookie"), config);
}

async function findSessionSafely(
  sessions: SessionRepository,
  sessionId: string,
): Promise<Awaited<ReturnType<SessionRepository["findById"]>> | "failure"> {
  try {
    return await sessions.findById(sessionId);
  } catch {
    return "failure";
  }
}

function readHeader(
  headers: HttpRequestHeaders | undefined,
  name: string,
): string | undefined {
  if (!headers) {
    return undefined;
  }

  const exact = headers[name];

  if (exact !== undefined) {
    return exact;
  }

  const lowerName = name.toLowerCase();
  const matchingKey = Object.keys(headers).find(
    (candidate) => candidate.toLowerCase() === lowerName,
  );

  return matchingKey ? headers[matchingKey] : undefined;
}

function denied(
  status: 401,
  reason:
    | "missing_session"
    | "unknown_session"
    | "revoked_session"
    | "expired_session",
) {
  return {
    status,
    body: {
      outcome: "denied",
      reason,
    },
  };
}

function csrfIssueFailure() {
  return {
    status: 500,
    body: {
      outcome: "error",
      message: "CSRF token could not be issued.",
    },
  };
}

function serviceFailure() {
  return {
    status: 500,
    body: {
      outcome: "error",
      message: "App access decision could not be completed.",
    },
  };
}
