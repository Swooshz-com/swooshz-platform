import type { BillingGate } from "../access/decide-app-access.js";
import {
  revokePlatformSession,
  type SessionRevocationServiceDependencies,
} from "../auth/session-revocation-service.js";
import {
  AppLaunchIntentServiceError,
  createAppLaunchIntent,
  type AppLaunchIntentDependencies,
} from "../platform/app-launch-intent-service.js";
import {
  AppLaunchTokenConsumeServiceError,
  consumeAppLaunchToken,
  type AppLaunchTokenConsumeDependencies,
  type AppLaunchTokenConsumeInvalidReason,
} from "../platform/app-launch-token-consume-service.js";
import {
  decideProtectedAppAccess,
  ProtectedAppAccessServiceError,
} from "../platform/protected-app-access-service.js";
import {
  getPlatformSessionContext,
  PlatformSessionContextServiceError,
} from "../platform/session-context-service.js";
import {
  addExistingWorkspaceUserByEmail,
  changeWorkspaceMemberRole,
  disableWorkspaceMembership,
  listWorkspaceAppEntitlementsForAdmin,
  listWorkspaceMembersForAdmin,
  setWorkspaceAppEntitlementStatus,
  WorkspaceAdminServiceError,
} from "../platform/workspace-admin-service.js";
import type { PlatformRepositories, SessionRepository } from "../platform/repositories.js";
import type { Role } from "../accounts/types.js";
import type { EntitlementStatus } from "../apps/types.js";
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

export interface SessionContextHttpRequest {
  headers?: HttpRequestHeaders;
  now: string;
  selectedWorkspaceId?: string | null;
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

export interface AppLaunchIntentHttpRequest {
  headers?: HttpRequestHeaders;
  selectedWorkspaceId: string;
  appKey: string;
  now: string;
  cookie?: BrowserSessionCookieConfig;
}

export interface AppLaunchTokenConsumeHttpRequest {
  headers?: HttpRequestHeaders;
  appKey: string;
  now: string;
}

export interface KqagBrowserLaunchHttpClient {
  post(input: {
    url: string;
    headers: HttpRequestHeaders;
  }): Promise<{
    status: number;
    headers?: HttpRequestHeaders;
    body?: unknown;
  }>;
}

export interface KqagBrowserLaunchDependencies {
  appLaunchIntent: AppLaunchIntentDependencies;
  kqag: {
    baseUrl: string;
    httpClient: KqagBrowserLaunchHttpClient;
  };
}

export interface KqagBrowserLaunchHttpRequest {
  headers?: HttpRequestHeaders;
  selectedWorkspaceId: string;
  appKey: string;
  now: string;
  cookie?: BrowserSessionCookieConfig;
}

export interface WorkspaceAdminHttpRequest {
  headers?: HttpRequestHeaders;
  workspaceId: string;
  now: string;
  cookie?: BrowserSessionCookieConfig;
}

export interface WorkspaceMemberRoleChangeHttpRequest extends WorkspaceAdminHttpRequest {
  membershipId: string;
  role: string;
  auditEventId: string;
}

export interface WorkspaceMemberAddHttpRequest extends WorkspaceAdminHttpRequest {
  targetEmail: string;
  role: string;
  membershipId: string;
  auditEventId: string;
}

export interface WorkspaceMembershipDisableHttpRequest extends WorkspaceAdminHttpRequest {
  membershipId: string;
  auditEventId: string;
}

export interface WorkspaceKqagEntitlementStatusHttpRequest extends WorkspaceAdminHttpRequest {
  status: string;
  auditEventId: string;
  entitlementId: string;
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
    return csrfIssueDenied("missing_session");
  }

  const session = await findSessionSafely(dependencies.sessions, sessionId);

  if (session === "failure") {
    return csrfIssueFailure();
  }

  if (!session) {
    return csrfIssueDenied("unknown_session");
  }

  if (session.revokedAt) {
    return csrfIssueDenied("revoked_session");
  }

  if (Date.parse(session.expiresAt) <= Date.parse(request.now)) {
    return csrfIssueDenied("expired_session");
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
      headers: csrfIssueHeaders(),
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

function csrfIssueDenied(
  reason:
    | "missing_session"
    | "unknown_session"
    | "revoked_session"
    | "expired_session",
) {
  return {
    status: 401,
    headers: csrfIssueHeaders(),
    body: {
      outcome: "denied",
      reason,
    },
  };
}

export async function handleAppLaunchIntentRequest(
  dependencies: AppLaunchIntentDependencies,
  request: AppLaunchIntentHttpRequest,
): Promise<HttpResponseLike> {
  const sessionId = extractSessionId(request.headers, request.cookie);

  if (!sessionId) {
    return appLaunchUnauthenticated("missing_session");
  }

  if (!request.selectedWorkspaceId.trim() || !request.appKey.trim()) {
    return {
      status: 400,
      headers: noStoreHeaders(),
      body: {
        outcome: "error",
        message: "Required query parameters are missing.",
      },
    };
  }

  try {
    const result = await createAppLaunchIntent(dependencies, {
      sessionId,
      selectedWorkspaceId: request.selectedWorkspaceId,
      appKey: request.appKey,
      now: request.now,
    });

    if (result.outcome === "created") {
      return {
        status: 201,
        headers: noStoreHeaders(),
        body: {
          outcome: "launch_intent_created",
          appKey: result.appKey,
          workspaceId: result.workspaceId,
          launchUrl: result.appLaunchUrl,
          launchToken: result.launchToken,
          launchTokenExpiresAt: result.launchTokenExpiresAt,
        },
      };
    }

    if (result.outcome === "unauthenticated") {
      return appLaunchUnauthenticated(result.reason);
    }

    return {
      status: 403,
      headers: noStoreHeaders(),
      body: {
        outcome: "denied",
        reason: "app_access_denied",
        decision: result.decision,
      },
    };
  } catch (error) {
    if (error instanceof AppLaunchIntentServiceError) {
      return appLaunchFailure();
    }

    return appLaunchFailure();
  }
}

export async function handleAppLaunchTokenConsumeRequest(
  dependencies: AppLaunchTokenConsumeDependencies,
  request: AppLaunchTokenConsumeHttpRequest,
): Promise<HttpResponseLike> {
  if (!request.appKey.trim()) {
    return {
      status: 400,
      headers: noStoreHeaders(),
      body: {
        outcome: "error",
        message: "Required query parameters are missing.",
      },
    };
  }

  const rawLaunchToken = readHeader(request.headers, "x-app-launch-token") ?? "";

  try {
    const result = await consumeAppLaunchToken(dependencies, {
      rawLaunchToken,
      appKey: request.appKey,
      now: request.now,
    });

    if (result.outcome === "consumed") {
      return {
        status: 200,
        headers: noStoreHeaders(),
        body: result,
      };
    }

    if (result.outcome === "denied") {
      return {
        status: 403,
        headers: noStoreHeaders(),
        body: result,
      };
    }

    return appLaunchConsumeInvalid(result.reason);
  } catch (error) {
    if (error instanceof AppLaunchTokenConsumeServiceError) {
      return appLaunchConsumeFailure();
    }

    return appLaunchConsumeFailure();
  }
}

export async function handleKqagBrowserLaunchRequest(
  dependencies: KqagBrowserLaunchDependencies,
  request: KqagBrowserLaunchHttpRequest,
): Promise<HttpResponseLike> {
  const sessionId = extractSessionId(request.headers, request.cookie);

  if (!sessionId) {
    return appLaunchUnauthenticated("missing_session");
  }

  if (!request.selectedWorkspaceId.trim() || !request.appKey.trim()) {
    return {
      status: 400,
      headers: noStoreHeaders(),
      body: {
        outcome: "error",
        message: "Required query parameters are missing.",
      },
    };
  }

  if (request.appKey !== "kqag") {
    return {
      status: 403,
      headers: noStoreHeaders(),
      body: {
        outcome: "denied",
        reason: "app_access_denied",
      },
    };
  }

  let launch: Awaited<ReturnType<typeof createAppLaunchIntent>>;

  try {
    launch = await createAppLaunchIntent(dependencies.appLaunchIntent, {
      sessionId,
      selectedWorkspaceId: request.selectedWorkspaceId,
      appKey: request.appKey,
      now: request.now,
    });
  } catch {
    return kqagLaunchFailure();
  }

  if (launch.outcome === "unauthenticated") {
    return appLaunchUnauthenticated(launch.reason);
  }

  if (launch.outcome === "denied") {
    return {
      status: 403,
      headers: noStoreHeaders(),
      body: {
        outcome: "denied",
        reason: "app_access_denied",
        decision: launch.decision,
      },
    };
  }

  const baseUrl = parseKqagBaseUrl(dependencies.kqag.baseUrl);

  if (!baseUrl) {
    return kqagLaunchNotConfigured();
  }

  let kqagResponse: Awaited<ReturnType<KqagBrowserLaunchHttpClient["post"]>>;

  try {
    kqagResponse = await dependencies.kqag.httpClient.post({
      url: new URL("/api/platform/launch", baseUrl).toString(),
      headers: {
        "x-app-launch-token": launch.launchToken,
      },
    });
  } catch {
    return kqagLaunchFailure();
  }

  if (kqagResponse.status < 200 || kqagResponse.status >= 300) {
    return kqagLaunchFailure();
  }

  const setCookie = readHeader(kqagResponse.headers, "set-cookie");

  if (!setCookie) {
    return kqagLaunchFailure();
  }

  return {
    status: 200,
    headers: {
      ...noStoreHeaders(),
      "set-cookie": setCookie,
    },
    body: {
      outcome: "launch_opened",
      appKey: launch.appKey,
      workspaceId: launch.workspaceId,
      launchUrl: baseUrl.toString(),
    },
  };
}

export async function handleWorkspaceMembersAdminRequest(
  repositories: PlatformRepositories,
  request: WorkspaceAdminHttpRequest,
): Promise<HttpResponseLike> {
  const sessionId = extractSessionId(request.headers, request.cookie);

  if (!sessionId) {
    return workspaceAdminMissingSession();
  }

  try {
    const result = await listWorkspaceMembersForAdmin(repositories, {
      sessionId,
      workspaceId: request.workspaceId,
      now: request.now,
    });

    return {
      status: 200,
      headers: noStoreHeaders(),
      body: {
        outcome: "listed",
        workspaceId: result.workspaceId,
        members: result.members,
      },
    };
  } catch (error) {
    return workspaceAdminErrorResponse(error);
  }
}

export async function handleWorkspaceMemberRoleChangeRequest(
  repositories: PlatformRepositories,
  request: WorkspaceMemberRoleChangeHttpRequest,
): Promise<HttpResponseLike> {
  const sessionId = extractSessionId(request.headers, request.cookie);

  if (!sessionId) {
    return workspaceAdminMissingSession();
  }

  try {
    const membership = await changeWorkspaceMemberRole(repositories, {
      sessionId,
      workspaceId: request.workspaceId,
      now: request.now,
      membershipId: request.membershipId,
      role: request.role as Role,
      auditEventId: request.auditEventId,
    });

    return {
      status: 200,
      headers: noStoreHeaders(),
      body: {
        outcome: "updated",
        membership: toWorkspaceMembershipHttpSummary(membership),
      },
    };
  } catch (error) {
    return workspaceAdminErrorResponse(error);
  }
}

export async function handleWorkspaceMemberAddRequest(
  repositories: PlatformRepositories,
  request: WorkspaceMemberAddHttpRequest,
): Promise<HttpResponseLike> {
  const sessionId = extractSessionId(request.headers, request.cookie);

  if (!sessionId) {
    return workspaceAdminMissingSession();
  }

  try {
    const membership = await addExistingWorkspaceUserByEmail(repositories, {
      sessionId,
      workspaceId: request.workspaceId,
      now: request.now,
      targetEmail: request.targetEmail,
      role: request.role as Role,
      membershipId: request.membershipId,
      auditEventId: request.auditEventId,
    });

    return {
      status: 201,
      headers: noStoreHeaders(),
      body: {
        outcome: "created",
        membership: toWorkspaceMembershipHttpSummary(membership),
      },
    };
  } catch (error) {
    return workspaceAdminErrorResponse(error);
  }
}

export async function handleWorkspaceMembershipDisableRequest(
  repositories: PlatformRepositories,
  request: WorkspaceMembershipDisableHttpRequest,
): Promise<HttpResponseLike> {
  const sessionId = extractSessionId(request.headers, request.cookie);

  if (!sessionId) {
    return workspaceAdminMissingSession();
  }

  try {
    const membership = await disableWorkspaceMembership(repositories, {
      sessionId,
      workspaceId: request.workspaceId,
      now: request.now,
      membershipId: request.membershipId,
      auditEventId: request.auditEventId,
    });

    return {
      status: 200,
      headers: noStoreHeaders(),
      body: {
        outcome: "updated",
        membership: toWorkspaceMembershipHttpSummary(membership),
      },
    };
  } catch (error) {
    return workspaceAdminErrorResponse(error);
  }
}

export async function handleWorkspaceAppEntitlementsAdminRequest(
  repositories: PlatformRepositories,
  request: WorkspaceAdminHttpRequest,
): Promise<HttpResponseLike> {
  const sessionId = extractSessionId(request.headers, request.cookie);

  if (!sessionId) {
    return workspaceAdminMissingSession();
  }

  try {
    const result = await listWorkspaceAppEntitlementsForAdmin(repositories, {
      sessionId,
      workspaceId: request.workspaceId,
      now: request.now,
    });

    return {
      status: 200,
      headers: noStoreHeaders(),
      body: {
        outcome: "listed",
        workspaceId: result.workspaceId,
        entitlements: result.entitlements,
      },
    };
  } catch (error) {
    return workspaceAdminErrorResponse(error);
  }
}

export async function handleWorkspaceKqagEntitlementStatusRequest(
  repositories: PlatformRepositories,
  request: WorkspaceKqagEntitlementStatusHttpRequest,
): Promise<HttpResponseLike> {
  const sessionId = extractSessionId(request.headers, request.cookie);

  if (!sessionId) {
    return workspaceAdminMissingSession();
  }

  try {
    const entitlement = await setWorkspaceAppEntitlementStatus(repositories, {
      sessionId,
      workspaceId: request.workspaceId,
      now: request.now,
      appKey: "kqag",
      status: request.status as Extract<EntitlementStatus, "enabled" | "disabled">,
      auditEventId: request.auditEventId,
      entitlementId: request.entitlementId,
    });

    return {
      status: 200,
      headers: noStoreHeaders(),
      body: {
        outcome: "updated",
        entitlement: {
          entitlementId: entitlement.id,
          workspaceId: entitlement.workspaceId,
          appId: entitlement.appId,
          appKey: "kqag",
          status: entitlement.status,
          grantedByUserId: entitlement.grantedByUserId,
          updatedAt: entitlement.updatedAt,
        },
      },
    };
  } catch (error) {
    return workspaceAdminErrorResponse(error);
  }
}

export async function handleSessionContextRequest(
  repositories: PlatformRepositories,
  request: SessionContextHttpRequest,
): Promise<HttpResponseLike> {
  const sessionId = extractSessionId(request.headers, request.cookie);

  if (!sessionId) {
    return sessionContextUnauthenticated("missing_session");
  }

  try {
    const context = await getPlatformSessionContext(repositories, {
      sessionId,
      now: request.now,
      selectedWorkspaceId: request.selectedWorkspaceId,
    });

    if (context.outcome === "unauthenticated") {
      return {
        status: 401,
        headers: noStoreHeaders(),
        body: context,
      };
    }

    return {
      status: 200,
      headers: noStoreHeaders(),
      body: context,
    };
  } catch (error) {
    if (error instanceof PlatformSessionContextServiceError) {
      return sessionContextFailure();
    }

    return sessionContextFailure();
  }
}

function sessionContextUnauthenticated(
  reason:
    | "missing_session"
    | "revoked_session"
    | "expired_session"
    | "missing_user"
    | "user_not_active",
) {
  return {
    status: 401,
    headers: noStoreHeaders(),
    body: {
      outcome: "unauthenticated",
      reason,
    },
  };
}

function workspaceAdminMissingSession(): HttpResponseLike {
  return {
    status: 401,
    headers: noStoreHeaders(),
    body: {
      outcome: "denied",
      reason: "missing_session",
    },
  };
}

function workspaceAdminErrorResponse(error: unknown): HttpResponseLike {
  if (error instanceof WorkspaceAdminServiceError) {
    if (error.code === "not_authorized") {
      return {
        status: 403,
        headers: noStoreHeaders(),
        body: {
          outcome: "denied",
          reason: "not_authorized",
        },
      };
    }

    return {
      status: workspaceAdminErrorStatus(error),
      headers: noStoreHeaders(),
      body: {
        outcome: "error",
        message: error.publicMessage,
      },
    };
  }

  return {
    status: 500,
    headers: noStoreHeaders(),
    body: {
      outcome: "error",
      message: "Workspace admin action could not be completed.",
    },
  };
}

function workspaceAdminErrorStatus(error: WorkspaceAdminServiceError): number {
  switch (error.code) {
    case "not_found":
      return 404;
    case "invalid_role":
    case "invalid_entitlement_status":
      return 400;
    case "last_owner_required":
    case "self_change_not_allowed":
    case "membership_conflict":
      return 409;
    case "repository_failure":
      return 500;
    case "not_authorized":
      return 403;
  }
}

function toWorkspaceMembershipHttpSummary(membership: {
  id: string;
  userId: string;
  workspaceId: string;
  role: string;
  status: string;
  updatedAt: string;
}) {
  return {
    membershipId: membership.id,
    userId: membership.userId,
    workspaceId: membership.workspaceId,
    role: membership.role,
    status: membership.status,
    updatedAt: membership.updatedAt,
  };
}

function appLaunchUnauthenticated(
  reason:
    | "missing_session"
    | "revoked_session"
    | "expired_session",
) {
  return {
    status: 401,
    headers: noStoreHeaders(),
    body: {
      outcome: "unauthenticated",
      reason,
    },
  };
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
    headers: csrfIssueHeaders(),
    body: {
      outcome: "error",
      message: "CSRF token could not be issued.",
    },
  };
}

function csrfIssueHeaders(): Record<string, string> {
  return noStoreHeaders();
}

function noStoreHeaders(): Record<string, string> {
  return {
    "cache-control": "no-store, no-cache, must-revalidate",
    pragma: "no-cache",
    expires: "0",
  };
}

function sessionContextFailure() {
  return {
    status: 500,
    headers: noStoreHeaders(),
    body: {
      outcome: "error",
      message: "Session context could not be loaded.",
    },
  };
}

function appLaunchFailure() {
  return {
    status: 500,
    headers: noStoreHeaders(),
    body: {
      outcome: "error",
      message: "App launch intent could not be created.",
    },
  };
}

function appLaunchConsumeInvalid(reason: AppLaunchTokenConsumeInvalidReason) {
  return {
    status: 401,
    headers: noStoreHeaders(),
    body: {
      outcome: "invalid",
      reason,
    },
  };
}

function appLaunchConsumeFailure() {
  return {
    status: 500,
    headers: noStoreHeaders(),
    body: {
      outcome: "error",
      message: "App launch token could not be consumed.",
    },
  };
}

function kqagLaunchFailure(): HttpResponseLike {
  return {
    status: 502,
    headers: noStoreHeaders(),
    body: {
      outcome: "error",
      message: "KQAG browser launch could not be completed.",
    },
  };
}

function kqagLaunchNotConfigured(): HttpResponseLike {
  return {
    status: 503,
    headers: noStoreHeaders(),
    body: {
      outcome: "error",
      message: "KQAG browser launch is not configured.",
    },
  };
}

function parseKqagBaseUrl(value: string): URL | null {
  try {
    const parsed = new URL(value);

    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return null;
    }

    parsed.pathname = parsed.pathname.endsWith("/")
      ? parsed.pathname
      : `${parsed.pathname}/`;
    parsed.search = "";
    parsed.hash = "";

    return parsed;
  } catch {
    return null;
  }
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
