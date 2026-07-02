import type { IncomingHttpHeaders, IncomingMessage, ServerResponse } from "node:http";
import type { BillingGate } from "../access/decide-app-access.js";
import type { SessionRevocationServiceDependencies } from "../auth/session-revocation-service.js";
import type { AppLaunchIntentDependencies } from "../platform/app-launch-intent-service.js";
import type { AppLaunchTokenConsumeDependencies } from "../platform/app-launch-token-consume-service.js";
import type { PlatformRepositories } from "../platform/repositories.js";
import {
  handleAuthCallbackRequest,
  handleAuthStartRequest,
  type AuthCallbackHttpDependencies,
  type AuthStartHttpDependencies,
} from "./auth-handlers.js";
import type { CsrfTokenValidator } from "./csrf.js";
import type { CsrfTokenServiceDependencies } from "./csrf-token-service.js";
import {
  handleCsrfTokenIssueRequest,
  handleAppLaunchTokenConsumeRequest,
  handleAppLaunchIntentRequest,
  handleKqagBrowserLaunchRequest,
  handleLogoutRequest,
  handleProtectedAppAccessRequest,
  handleSessionContextRequest,
  handleWorkspaceAdminAppEntitlementStatusRequest,
  handleWorkspaceAdminMembershipDisableRequest,
  handleWorkspaceAdminOverviewRequest,
  handleWorkspaceAdminRoleChangeRequest,
  type HttpRequestHeaders,
  type HttpResponseLike,
  type KqagBrowserLaunchDependencies,
} from "./handlers.js";
import type { HttpOriginValidationConfig } from "./origin-validation.js";
import {
  getHttpRouteContract,
  HTTP_ROUTE_CONTRACTS,
  type HttpRouteContract,
} from "./route-contracts.js";
import {
  renderAdminShellPage,
  renderAppShellPage,
  renderLandingPage,
} from "./platform-shell.js";
import type { BrowserSessionCookieConfig } from "./session-cookie.js";
import { extractBrowserSessionIdFromCookieHeader } from "./session-cookie.js";
import { validateHttpRequestSecurityForRoute } from "./request-security.js";

export interface WorkspaceAdminIdFactory {
  createAuditEventId(input: WorkspaceAdminIdFactoryInput): string;
  createEntitlementId(input: WorkspaceAdminIdFactoryInput): string;
}

export interface WorkspaceAdminIdFactoryInput {
  operation:
    | "member_role_change"
    | "membership_disable"
    | "app_entitlement_status";
  workspaceId: string;
  targetId?: string;
  appKey?: string;
  now: string;
}

export interface NodePlatformHttpAdapterDependencies {
  repositories: PlatformRepositories;
  now: () => string;
  cookie?: BrowserSessionCookieConfig;
  originConfig: HttpOriginValidationConfig;
  csrfTokenValidator?: CsrfTokenValidator;
  csrfTokenIssuer?: CsrfTokenServiceDependencies;
  csrfTokenTtlSeconds?: number;
  authStart?: AuthStartHttpDependencies;
  authCallback?: AuthCallbackHttpDependencies;
  appLaunchIntent?: AppLaunchIntentDependencies;
  appLaunchTokenConsume?: AppLaunchTokenConsumeDependencies;
  kqagBrowserLaunch?: KqagBrowserLaunchDependencies["kqag"];
  billingGate?: BillingGate;
  workspaceAdminIdFactory?: WorkspaceAdminIdFactory;
}

export interface NodePlatformHttpRequestLike {
  method?: string;
  url?: string;
  headers?: IncomingHttpHeaders | HttpRequestHeaders;
}

export interface NodePlatformHttpResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
}

const jsonContentType = "application/json; charset=utf-8";
const htmlContentType = "text/html; charset=utf-8";
const adapterUrlBase = "http://swooshz-platform.local";
const defaultCsrfTokenTtlSeconds = 900;
let workspaceAdminIdCounter = 0;

export async function handleNodePlatformHttpRequest(
  dependencies: NodePlatformHttpAdapterDependencies,
  request: NodePlatformHttpRequestLike,
): Promise<NodePlatformHttpResponse> {
  const parsedUrl = parseRequestUrl(request.url);

  if (!parsedUrl) {
    return jsonResponse(404, {
      outcome: "error",
      message: "Route not found.",
    });
  }

  const route = findRouteByPath(parsedUrl.pathname);

  if (!route) {
    return jsonResponse(404, {
      outcome: "error",
      message: "Route not found.",
    });
  }

  const method = normalizeMethod(request.method);

  if (method !== route.method) {
    return jsonResponse(
      405,
      {
        outcome: "error",
        message: "Method not allowed.",
      },
      {
        allow: route.method,
        ...(route.id === "platform_app_launch" ||
        route.id === "platform_app_launch_consume" ||
        route.responseKind === "html"
          ? noStoreHeaders()
          : {}),
      },
    );
  }

  const headers = normalizeHeaders(request.headers);

  if (route.id === "platform_landing_page") {
    return htmlResponse(200, renderLandingPage(), noStoreHeaders());
  }

  if (route.id === "platform_app_shell") {
    return htmlResponse(200, renderAppShellPage(), noStoreHeaders());
  }

  if (route.id === "platform_admin_shell") {
    return htmlResponse(200, renderAdminShellPage(), noStoreHeaders());
  }

  if (route.id === "healthz") {
    return jsonResponse(200, {
      outcome: "ok",
      service: "swooshz-platform",
    });
  }

  if (route.id === "platform_auth_start") {
    if (!dependencies.authStart) {
      return authStartFailureResponse();
    }

    return toNodeResponse(
      await handleAuthStartRequest(dependencies.authStart, {
        now: dependencies.now(),
      }),
    );
  }

  if (route.id === "platform_auth_callback") {
    if (!dependencies.authCallback) {
      return authCallbackFailureResponse(500);
    }

    return toNodeResponse(
      await handleAuthCallbackRequest(dependencies.authCallback, {
        query: {
          code: optionalSearchParam(parsedUrl, "code"),
          state: optionalSearchParam(parsedUrl, "state"),
          error: optionalSearchParam(parsedUrl, "error"),
          error_description: optionalSearchParam(parsedUrl, "error_description"),
        },
        now: dependencies.now(),
        cookie: dependencies.cookie,
      }),
    );
  }

  if (route.id === "platform_session_app_access") {
    const selectedWorkspaceId = parsedUrl.searchParams.get("workspaceId");
    const appKey = parsedUrl.searchParams.get("appKey");

    if (!selectedWorkspaceId || !appKey) {
      return jsonResponse(400, {
        outcome: "error",
        message: "Required query parameters are missing.",
      });
    }

    return toNodeResponse(
      await handleProtectedAppAccessRequest(dependencies.repositories, {
        headers,
        selectedWorkspaceId,
        appKey,
        now: dependencies.now(),
        billingGate: dependencies.billingGate,
        cookie: dependencies.cookie,
      }),
    );
  }

  if (route.id === "platform_session_context") {
    return toNodeResponse(
      await handleSessionContextRequest(dependencies.repositories, {
        headers,
        now: dependencies.now(),
        selectedWorkspaceId: optionalSearchParam(parsedUrl, "workspaceId"),
        cookie: dependencies.cookie,
      }),
    );
  }

  if (route.id === "platform_session_csrf") {
    if (!dependencies.csrfTokenIssuer) {
      return csrfIssueFailureResponse();
    }

    return toNodeResponse(
      await handleCsrfTokenIssueRequest(
        {
          sessions: dependencies.repositories.sessions,
          csrf: dependencies.csrfTokenIssuer,
        },
        {
          headers,
          now: dependencies.now(),
          ttlSeconds: dependencies.csrfTokenTtlSeconds ?? defaultCsrfTokenTtlSeconds,
          cookie: dependencies.cookie,
        },
      ),
    );
  }

  if (route.id === "platform_workspace_admin_overview") {
    const workspaceId = parsedUrl.searchParams.get("workspaceId");

    if (!workspaceId) {
      return jsonResponse(
        400,
        {
          outcome: "error",
          message: "Required query parameters are missing.",
        },
        noStoreHeaders(),
      );
    }

    return toNodeResponse(
      await handleWorkspaceAdminOverviewRequest(dependencies.repositories, {
        headers,
        workspaceId,
        now: dependencies.now(),
        cookie: dependencies.cookie,
      }),
    );
  }

  if (route.id === "platform_workspace_admin_member_role") {
    const workspaceId = parsedUrl.searchParams.get("workspaceId");
    const membershipId = parsedUrl.searchParams.get("membershipId");
    const role = parsedUrl.searchParams.get("role");

    if (!workspaceId || !membershipId || !role) {
      return jsonResponse(
        400,
        {
          outcome: "error",
          message: "Required query parameters are missing.",
        },
        noStoreHeaders(),
      );
    }

    const now = dependencies.now();
    const securityResult = await validateAdminRouteSecurity({
      dependencies,
      headers,
      routeId: "platform_workspace_admin_member_role",
      now,
    });

    if (!securityResult.allowed) {
      return securityFailureResponse(
        securityResult.recommendedStatus,
        securityResult.reason,
        noStoreHeaders(),
      );
    }

    const idFactory = dependencies.workspaceAdminIdFactory ?? defaultWorkspaceAdminIdFactory;

    return toNodeResponse(
      await handleWorkspaceAdminRoleChangeRequest(dependencies.repositories, {
        headers,
        workspaceId,
        membershipId,
        role,
        now,
        auditEventId: idFactory.createAuditEventId({
          operation: "member_role_change",
          workspaceId,
          targetId: membershipId,
          now,
        }),
        cookie: dependencies.cookie,
      }),
    );
  }

  if (route.id === "platform_workspace_admin_member_disable") {
    const workspaceId = parsedUrl.searchParams.get("workspaceId");
    const membershipId = parsedUrl.searchParams.get("membershipId");

    if (!workspaceId || !membershipId) {
      return jsonResponse(
        400,
        {
          outcome: "error",
          message: "Required query parameters are missing.",
        },
        noStoreHeaders(),
      );
    }

    const now = dependencies.now();
    const securityResult = await validateAdminRouteSecurity({
      dependencies,
      headers,
      routeId: "platform_workspace_admin_member_disable",
      now,
    });

    if (!securityResult.allowed) {
      return securityFailureResponse(
        securityResult.recommendedStatus,
        securityResult.reason,
        noStoreHeaders(),
      );
    }

    const idFactory = dependencies.workspaceAdminIdFactory ?? defaultWorkspaceAdminIdFactory;

    return toNodeResponse(
      await handleWorkspaceAdminMembershipDisableRequest(dependencies.repositories, {
        headers,
        workspaceId,
        membershipId,
        now,
        auditEventId: idFactory.createAuditEventId({
          operation: "membership_disable",
          workspaceId,
          targetId: membershipId,
          now,
        }),
        cookie: dependencies.cookie,
      }),
    );
  }

  if (route.id === "platform_workspace_admin_app_entitlement") {
    const workspaceId = parsedUrl.searchParams.get("workspaceId");
    const appKey = parsedUrl.searchParams.get("appKey");
    const status = parsedUrl.searchParams.get("status");

    if (!workspaceId || !appKey || !status) {
      return jsonResponse(
        400,
        {
          outcome: "error",
          message: "Required query parameters are missing.",
        },
        noStoreHeaders(),
      );
    }

    const now = dependencies.now();
    const securityResult = await validateAdminRouteSecurity({
      dependencies,
      headers,
      routeId: "platform_workspace_admin_app_entitlement",
      now,
    });

    if (!securityResult.allowed) {
      return securityFailureResponse(
        securityResult.recommendedStatus,
        securityResult.reason,
        noStoreHeaders(),
      );
    }

    const idFactory = dependencies.workspaceAdminIdFactory ?? defaultWorkspaceAdminIdFactory;
    const idInput = {
      operation: "app_entitlement_status" as const,
      workspaceId,
      appKey,
      now,
    };

    return toNodeResponse(
      await handleWorkspaceAdminAppEntitlementStatusRequest(
        dependencies.repositories,
        {
          headers,
          workspaceId,
          appKey,
          status,
          now,
          auditEventId: idFactory.createAuditEventId(idInput),
          entitlementId: idFactory.createEntitlementId(idInput),
          cookie: dependencies.cookie,
        },
      ),
    );
  }

  if (route.id === "platform_app_launch") {
    const selectedWorkspaceId = parsedUrl.searchParams.get("workspaceId");
    const appKey = parsedUrl.searchParams.get("appKey");

    if (!selectedWorkspaceId || !appKey) {
      return jsonResponse(
        400,
        {
          outcome: "error",
          message: "Required query parameters are missing.",
        },
        noStoreHeaders(),
      );
    }

    const now = dependencies.now();
    const sessionId = extractBrowserSessionIdFromCookieHeader(
      readHeader(headers, "cookie"),
      dependencies.cookie,
    );
    const securityResult = await validateHttpRequestSecurityForRoute({
      route: getHttpRouteContract("platform_app_launch"),
      headers,
      sessionId,
      now,
      originConfig: dependencies.originConfig,
      csrfTokenValidator: dependencies.csrfTokenValidator,
    });

    if (!securityResult.allowed) {
      return securityFailureResponse(
        securityResult.recommendedStatus,
        securityResult.reason,
        noStoreHeaders(),
      );
    }

    if (!dependencies.appLaunchIntent) {
      return appLaunchFailureResponse();
    }

    return toNodeResponse(
      await handleAppLaunchIntentRequest(dependencies.appLaunchIntent, {
        headers,
        selectedWorkspaceId,
        appKey,
        now,
        cookie: dependencies.cookie,
      }),
    );
  }

  if (route.id === "platform_kqag_launch_open") {
    const selectedWorkspaceId = parsedUrl.searchParams.get("workspaceId");
    const appKey = parsedUrl.searchParams.get("appKey");

    if (!selectedWorkspaceId || !appKey) {
      return jsonResponse(
        400,
        {
          outcome: "error",
          message: "Required query parameters are missing.",
        },
        noStoreHeaders(),
      );
    }

    const now = dependencies.now();
    const sessionId = extractBrowserSessionIdFromCookieHeader(
      readHeader(headers, "cookie"),
      dependencies.cookie,
    );

    if (!sessionId) {
      return toNodeResponse({
        status: 401,
        headers: noStoreHeaders(),
        body: {
          outcome: "unauthenticated",
          reason: "missing_session",
        },
      });
    }

    const securityResult = await validateHttpRequestSecurityForRoute({
      route: getHttpRouteContract("platform_kqag_launch_open"),
      headers,
      sessionId,
      now,
      originConfig: dependencies.originConfig,
      csrfTokenValidator: dependencies.csrfTokenValidator,
    });

    if (!securityResult.allowed) {
      return securityFailureResponse(
        securityResult.recommendedStatus,
        securityResult.reason,
        noStoreHeaders(),
      );
    }

    if (
      !dependencies.appLaunchIntent ||
      !dependencies.kqagBrowserLaunch ||
      !isSafeSameHostKqagLaunch(headers, dependencies.kqagBrowserLaunch.baseUrl)
    ) {
      return kqagLaunchNotConfiguredResponse();
    }

    return toNodeResponse(
      await handleKqagBrowserLaunchRequest(
        {
          appLaunchIntent: dependencies.appLaunchIntent,
          kqag: dependencies.kqagBrowserLaunch,
        },
        {
          headers,
          selectedWorkspaceId,
          appKey,
          now,
          cookie: dependencies.cookie,
        },
      ),
    );
  }

  if (route.id === "platform_app_launch_consume") {
    const appKey = parsedUrl.searchParams.get("appKey");

    if (!appKey) {
      return jsonResponse(
        400,
        {
          outcome: "error",
          message: "Required query parameters are missing.",
        },
        noStoreHeaders(),
      );
    }

    if (!dependencies.appLaunchTokenConsume) {
      return appLaunchConsumeFailureResponse();
    }

    return toNodeResponse(
      await handleAppLaunchTokenConsumeRequest(
        dependencies.appLaunchTokenConsume,
        {
          headers,
          appKey,
          now: dependencies.now(),
        },
      ),
    );
  }

  if (route.id === "platform_logout") {
    const now = dependencies.now();
    const sessionId = extractBrowserSessionIdFromCookieHeader(
      readHeader(headers, "cookie"),
      dependencies.cookie,
    );
    const securityResult = await validateHttpRequestSecurityForRoute({
      route: getHttpRouteContract("platform_logout"),
      headers,
      sessionId,
      now,
      originConfig: dependencies.originConfig,
      csrfTokenValidator: dependencies.csrfTokenValidator,
    });

    if (!securityResult.allowed) {
      return securityFailureResponse(
        securityResult.recommendedStatus,
        securityResult.reason,
      );
    }

    return toNodeResponse(
      await handleLogoutRequest(
        { sessions: dependencies.repositories.sessions } satisfies
          SessionRevocationServiceDependencies,
        {
          headers,
          now,
          cookie: dependencies.cookie,
        },
      ),
    );
  }

  return jsonResponse(404, {
    outcome: "error",
    message: "Route not found.",
  });
}

export async function writeNodePlatformHttpResponse(
  dependencies: NodePlatformHttpAdapterDependencies,
  request: IncomingMessage,
  response: ServerResponse,
): Promise<void> {
  const adapterResponse = await handleNodePlatformHttpRequest(dependencies, {
    method: request.method,
    url: request.url,
    headers: request.headers,
  });

  response.statusCode = adapterResponse.statusCode;

  for (const [name, value] of Object.entries(adapterResponse.headers)) {
    response.setHeader(name, value);
  }

  response.end(adapterResponse.body);
}

function parseRequestUrl(url: string | undefined): URL | null {
  if (!url) {
    return null;
  }

  try {
    return new URL(url, adapterUrlBase);
  } catch {
    return null;
  }
}

function findRouteByPath(pathname: string): HttpRouteContract | null {
  return HTTP_ROUTE_CONTRACTS.find((route) => route.path === pathname) ?? null;
}

async function validateAdminRouteSecurity({
  dependencies,
  headers,
  routeId,
  now,
}: {
  dependencies: NodePlatformHttpAdapterDependencies;
  headers: HttpRequestHeaders;
  routeId:
    | "platform_workspace_admin_member_role"
    | "platform_workspace_admin_member_disable"
    | "platform_workspace_admin_app_entitlement";
  now: string;
}): ReturnType<typeof validateHttpRequestSecurityForRoute> {
  const sessionId = extractBrowserSessionIdFromCookieHeader(
    readHeader(headers, "cookie"),
    dependencies.cookie,
  );

  return validateHttpRequestSecurityForRoute({
    route: getHttpRouteContract(routeId),
    headers,
    sessionId,
    now,
    originConfig: dependencies.originConfig,
    csrfTokenValidator: dependencies.csrfTokenValidator,
  });
}

function normalizeMethod(method: string | undefined): string {
  return method?.toUpperCase() ?? "";
}

function normalizeHeaders(
  headers: IncomingHttpHeaders | HttpRequestHeaders | undefined,
): HttpRequestHeaders {
  if (!headers) {
    return {};
  }

  const normalized: HttpRequestHeaders = {};

  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) {
      continue;
    }

    normalized[name.toLowerCase()] = Array.isArray(value)
      ? normalizeHeaderArray(name, value)
      : value;
  }

  return normalized;
}

function normalizeHeaderArray(name: string, values: readonly string[]): string {
  return name.toLowerCase() === "cookie"
    ? values.join("; ")
    : values.join(", ");
}

function toNodeResponse(response: HttpResponseLike): NodePlatformHttpResponse {
  return jsonResponse(
    response.status,
    response.body ?? null,
    response.headers,
  );
}

function csrfIssueFailureResponse(): NodePlatformHttpResponse {
  return jsonResponse(500, {
    outcome: "error",
    message: "CSRF token could not be issued.",
  });
}

function authStartFailureResponse(): NodePlatformHttpResponse {
  return jsonResponse(500, {
    outcome: "error",
    message: "Authentication start could not be completed.",
  });
}

function authCallbackFailureResponse(status: 400 | 500): NodePlatformHttpResponse {
  return jsonResponse(status, {
    outcome: "error",
    message: "Authentication callback could not be completed.",
  });
}

function appLaunchFailureResponse(): NodePlatformHttpResponse {
  return jsonResponse(
    500,
    {
      outcome: "error",
      message: "App launch intent could not be created.",
    },
    noStoreHeaders(),
  );
}

function appLaunchConsumeFailureResponse(): NodePlatformHttpResponse {
  return jsonResponse(
    500,
    {
      outcome: "error",
      message: "App launch token could not be consumed.",
    },
    noStoreHeaders(),
  );
}

function kqagLaunchNotConfiguredResponse(): NodePlatformHttpResponse {
  return jsonResponse(
    503,
    {
      outcome: "error",
      message: "KQAG browser launch is not configured.",
    },
    noStoreHeaders(),
  );
}

function securityFailureResponse(
  status: 403 | 500,
  reason: string,
  headers: Record<string, string> = {},
): NodePlatformHttpResponse {
  if (status === 500) {
    return jsonResponse(
      500,
      {
        outcome: "error",
        message: "Request security could not be completed.",
      },
      headers,
    );
  }

  return jsonResponse(
    403,
    {
      outcome: "denied",
      reason,
    },
    headers,
  );
}

function jsonResponse(
  statusCode: number,
  body: unknown,
  headers: Record<string, string> = {},
): NodePlatformHttpResponse {
  return {
    statusCode,
    headers: {
      "content-type": jsonContentType,
      ...headers,
    },
    body: JSON.stringify(body),
  };
}

function htmlResponse(
  statusCode: number,
  body: string,
  headers: Record<string, string> = {},
): NodePlatformHttpResponse {
  return {
    statusCode,
    headers: {
      "content-type": htmlContentType,
      ...headers,
    },
    body,
  };
}

function isSafeSameHostKqagLaunch(
  headers: HttpRequestHeaders,
  baseUrl: string,
): boolean {
  const requestHost = readHeader(headers, "host")?.split(":")[0]?.trim().toLowerCase();

  if (!requestHost) {
    return false;
  }

  try {
    const parsed = new URL(baseUrl);

    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return false;
    }

    return parsed.hostname.toLowerCase() === requestHost;
  } catch {
    return false;
  }
}

function readHeader(
  headers: HttpRequestHeaders,
  name: string,
): string | undefined {
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

function optionalSearchParam(parsedUrl: URL, name: string): string | undefined {
  return parsedUrl.searchParams.get(name) ?? undefined;
}

function noStoreHeaders(): Record<string, string> {
  return {
    "cache-control": "no-store, no-cache, must-revalidate",
    pragma: "no-cache",
    expires: "0",
  };
}

const defaultWorkspaceAdminIdFactory: WorkspaceAdminIdFactory = {
  createAuditEventId() {
    return createDefaultWorkspaceAdminId("audit");
  },
  createEntitlementId() {
    return createDefaultWorkspaceAdminId("entitlement");
  },
};

function createDefaultWorkspaceAdminId(prefix: "audit" | "entitlement"): string {
  workspaceAdminIdCounter += 1;
  return `${prefix}_${Date.now().toString(36)}_${workspaceAdminIdCounter}`;
}
