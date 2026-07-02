export type HttpRouteId =
  | "platform_landing_page"
  | "platform_app_shell"
  | "platform_admin_shell"
  | "healthz"
  | "platform_auth_start"
  | "platform_auth_callback"
  | "platform_session_app_access"
  | "platform_session_context"
  | "platform_session_csrf"
  | "platform_workspace_admin_overview"
  | "platform_workspace_admin_member_role"
  | "platform_workspace_admin_member_disable"
  | "platform_workspace_admin_app_entitlement"
  | "platform_app_launch"
  | "platform_kqag_launch_open"
  | "platform_app_launch_consume"
  | "platform_logout";

export type HttpRouteMethod = "GET" | "POST";

export type HttpRouteResponseKind = "json" | "html";

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
  responseKind: HttpRouteResponseKind;
  idempotent: boolean;
  implemented: false;
}

export const HTTP_ROUTE_CONTRACTS: readonly HttpRouteContract[] = [
  {
    id: "platform_landing_page",
    method: "GET",
    path: "/",
    browserSession: "none",
    csrf: {
      required: false,
      strategy: "none",
    },
    requiredQuery: [],
    handlerContract: "renderLandingPage",
    responseKind: "html",
    idempotent: true,
    implemented: false,
  },
  {
    id: "platform_app_shell",
    method: "GET",
    path: "/app",
    browserSession: "none",
    csrf: {
      required: false,
      strategy: "none",
    },
    requiredQuery: [],
    handlerContract: "renderAppShellPage",
    responseKind: "html",
    idempotent: true,
    implemented: false,
  },
  {
    id: "platform_admin_shell",
    method: "GET",
    path: "/app/admin",
    browserSession: "none",
    csrf: {
      required: false,
      strategy: "none",
    },
    requiredQuery: [],
    handlerContract: "renderAdminShellPage",
    responseKind: "html",
    idempotent: true,
    implemented: false,
  },
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
    responseKind: "json",
    idempotent: true,
    implemented: false,
  },
  {
    id: "platform_auth_start",
    method: "GET",
    path: "/api/platform/auth/start",
    browserSession: "none",
    csrf: {
      required: false,
      strategy: "none",
    },
    requiredQuery: [],
    handlerContract: "handleAuthStartRequest",
    responseKind: "json",
    idempotent: false,
    implemented: false,
  },
  {
    id: "platform_auth_callback",
    method: "GET",
    path: "/api/platform/auth/callback",
    browserSession: "none",
    csrf: {
      required: false,
      strategy: "none",
    },
    requiredQuery: ["code", "state"],
    handlerContract: "handleAuthCallbackRequest",
    responseKind: "json",
    idempotent: false,
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
    responseKind: "json",
    idempotent: true,
    implemented: false,
  },
  {
    id: "platform_session_context",
    method: "GET",
    path: "/api/platform/session/context",
    browserSession: "required",
    csrf: {
      required: false,
      strategy: "none",
    },
    requiredQuery: [],
    handlerContract: "handleSessionContextRequest",
    responseKind: "json",
    idempotent: true,
    implemented: false,
  },
  {
    id: "platform_session_csrf",
    method: "GET",
    path: "/api/platform/session/csrf",
    browserSession: "required",
    csrf: {
      required: false,
      strategy: "none",
    },
    requiredQuery: [],
    handlerContract: "handleCsrfTokenIssueRequest",
    responseKind: "json",
    idempotent: false,
    implemented: false,
  },
  {
    id: "platform_workspace_admin_overview",
    method: "GET",
    path: "/api/platform/admin/workspace",
    browserSession: "required",
    csrf: {
      required: false,
      strategy: "none",
    },
    requiredQuery: ["workspaceId"],
    handlerContract: "handleWorkspaceAdminOverviewRequest",
    responseKind: "json",
    idempotent: true,
    implemented: false,
  },
  {
    id: "platform_workspace_admin_member_role",
    method: "POST",
    path: "/api/platform/admin/members/role",
    browserSession: "required",
    csrf: {
      required: true,
      strategy: "origin_referer_and_csrf_token",
    },
    requiredQuery: ["workspaceId", "membershipId", "role"],
    handlerContract: "handleWorkspaceAdminRoleChangeRequest",
    responseKind: "json",
    idempotent: false,
    implemented: false,
  },
  {
    id: "platform_workspace_admin_member_disable",
    method: "POST",
    path: "/api/platform/admin/members/disable",
    browserSession: "required",
    csrf: {
      required: true,
      strategy: "origin_referer_and_csrf_token",
    },
    requiredQuery: ["workspaceId", "membershipId"],
    handlerContract: "handleWorkspaceAdminMembershipDisableRequest",
    responseKind: "json",
    idempotent: false,
    implemented: false,
  },
  {
    id: "platform_workspace_admin_app_entitlement",
    method: "POST",
    path: "/api/platform/admin/apps/entitlement",
    browserSession: "required",
    csrf: {
      required: true,
      strategy: "origin_referer_and_csrf_token",
    },
    requiredQuery: ["workspaceId", "appKey", "status"],
    handlerContract: "handleWorkspaceAdminAppEntitlementStatusRequest",
    responseKind: "json",
    idempotent: false,
    implemented: false,
  },
  {
    id: "platform_app_launch",
    method: "POST",
    path: "/api/platform/apps/launch",
    browserSession: "required",
    csrf: {
      required: true,
      strategy: "origin_referer_and_csrf_token",
    },
    requiredQuery: ["workspaceId", "appKey"],
    handlerContract: "handleAppLaunchIntentRequest",
    responseKind: "json",
    idempotent: false,
    implemented: false,
  },
  {
    id: "platform_kqag_launch_open",
    method: "POST",
    path: "/api/platform/apps/launch/open",
    browserSession: "required",
    csrf: {
      required: true,
      strategy: "origin_referer_and_csrf_token",
    },
    requiredQuery: ["workspaceId", "appKey"],
    handlerContract: "handleKqagBrowserLaunchRequest",
    responseKind: "json",
    idempotent: false,
    implemented: false,
  },
  {
    id: "platform_app_launch_consume",
    method: "POST",
    path: "/api/platform/apps/launch/consume",
    browserSession: "none",
    csrf: {
      required: false,
      strategy: "none",
    },
    requiredQuery: ["appKey"],
    handlerContract: "handleAppLaunchTokenConsumeRequest",
    responseKind: "json",
    idempotent: false,
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
    responseKind: "json",
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
