import type { IncomingHttpHeaders, IncomingMessage, ServerResponse } from "node:http";
import type { BillingGate } from "../access/decide-app-access.js";
import type { SessionRevocationServiceDependencies } from "../auth/session-revocation-service.js";
import type { PlatformRepositories } from "../platform/repositories.js";
import type { CsrfTokenValidator } from "./csrf.js";
import {
  handleLogoutRequest,
  handleProtectedAppAccessRequest,
  type HttpRequestHeaders,
  type HttpResponseLike,
} from "./handlers.js";
import type { HttpOriginValidationConfig } from "./origin-validation.js";
import {
  getHttpRouteContract,
  HTTP_ROUTE_CONTRACTS,
  type HttpRouteContract,
} from "./route-contracts.js";
import type { BrowserSessionCookieConfig } from "./session-cookie.js";
import { extractBrowserSessionIdFromCookieHeader } from "./session-cookie.js";
import { validateHttpRequestSecurityForRoute } from "./request-security.js";

export interface NodePlatformHttpAdapterDependencies {
  repositories: PlatformRepositories;
  now: () => string;
  cookie?: BrowserSessionCookieConfig;
  originConfig: HttpOriginValidationConfig;
  csrfTokenValidator?: CsrfTokenValidator;
  billingGate?: BillingGate;
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
const adapterUrlBase = "http://swooshz-platform.local";

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
      },
    );
  }

  const headers = normalizeHeaders(request.headers);

  if (route.id === "healthz") {
    return jsonResponse(200, {
      outcome: "ok",
      service: "swooshz-platform",
    });
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

function securityFailureResponse(
  status: 403 | 500,
  reason: string,
): NodePlatformHttpResponse {
  if (status === 500) {
    return jsonResponse(500, {
      outcome: "error",
      message: "Request security could not be completed.",
    });
  }

  return jsonResponse(403, {
    outcome: "denied",
    reason,
  });
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
