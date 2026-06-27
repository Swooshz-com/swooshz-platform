export type HttpRouteId =
  | "healthz"
  | "platform_session_app_access"
  | "platform_logout";

export type HttpRouteMethod = "GET" | "POST";

export type BrowserSessionRequirement = "none" | "optional" | "required";

export type CsrfStrategy =
  | "none"
  | "origin_referer_and_csrf_token";

export interface HttpRouteCsrfContract {
  required: boolean;
  strategy: CsrfStrategy;
}

export interface HttpRouteContract {
  id: HttpRouteId;
  method: HttpRouteMethod;
  path: string;
  browserSession: BrowserSessionRequirement;
  csrf: HttpRouteCsrfContract;
  requiredQuery: readonly string[];
  handlerContract: string | null;
  idempotent: boolean;
  implemented: false;
}

export const HTTP_ROUTE_CONTRACTS: readonly HttpRouteContract[] = [
  {
    id: "healthz",
    method: "GET",
    path: "/healthz",
    browserSession: "none",
    csrf: {
      required: false,
      strategy: "none",
    },
    requiredQuery: [],
    handlerContract: null,
    idempotent: true,
    implemented: false,
  },
  {
    id: "platform_session_app_access",
    method: "GET",
    path: "/api/platform/session/app-access",
    browserSession: "required",
    csrf: {
      required: false,
      strategy: "none",
    },
    requiredQuery: ["workspaceId", "appKey"],
    handlerContract: "handleProtectedAppAccessRequest",
    idempotent: true,
    implemented: false,
  },
  {
    id: "platform_logout",
    method: "POST",
    path: "/api/platform/logout",
    browserSession: "optional",
    csrf: {
      required: true,
      strategy: "origin_referer_and_csrf_token",
    },
    requiredQuery: [],
    handlerContract: "handleLogoutRequest",
    idempotent: true,
    implemented: false,
  },
] as const;

export function getHttpRouteContract(id: HttpRouteId): HttpRouteContract {
  const route = HTTP_ROUTE_CONTRACTS.find((candidate) => candidate.id === id);

  if (!route) {
    throw new Error("Unknown HTTP route contract.");
  }

  return route;
}
