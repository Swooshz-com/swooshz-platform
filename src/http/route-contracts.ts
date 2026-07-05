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
  | "platform_workspace_members"
  | "platform_workspace_member_add"
  | "platform_workspace_member_role"
  | "platform_workspace_member_disable"
  | "platform_workspace_member_reactivate"
  | "platform_workspace_app_entitlements"
  | "platform_workspace_kqag_entitlement_status"
  | "platform_workspace_audit_events"
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
  implemented: boolean;
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
    implemented: true,
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
    implemented: true,
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
    implemented: true,
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
    implemented: true,
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
    implemented: true,
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
    implemented: true,
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
    implemented: true,
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
    implemented: true,
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
    implemented: true,
  },
  {
    id: "platform_workspace_members",
    method: "GET",
    path: "/api/platform/workspaces/:workspaceId/members",
    browserSession: "required",
    csrf: {
      required: false,
      strategy: "none",
    },
    requiredQuery: [],
    handlerContract: "handleWorkspaceMembersAdminRequest",
    responseKind: "json",
    idempotent: true,
    implemented: true,
  },
  {
    id: "platform_workspace_member_add",
    method: "POST",
    path: "/api/platform/workspaces/:workspaceId/members/add",
    browserSession: "required",
    csrf: {
      required: true,
      strategy: "origin_referer_and_csrf_token",
    },
    requiredQuery: ["email", "role"],
    handlerContract: "handleWorkspaceMemberAddRequest",
    responseKind: "json",
    idempotent: false,
    implemented: true,
  },
  {
    id: "platform_workspace_member_role",
    method: "POST",
    path: "/api/platform/workspaces/:workspaceId/members/:membershipId/role",
    browserSession: "required",
    csrf: {
      required: true,
      strategy: "origin_referer_and_csrf_token",
    },
    requiredQuery: ["role"],
    handlerContract: "handleWorkspaceMemberRoleChangeRequest",
    responseKind: "json",
    idempotent: false,
    implemented: true,
  },
  {
    id: "platform_workspace_member_disable",
    method: "POST",
    path: "/api/platform/workspaces/:workspaceId/members/:membershipId/disable",
    browserSession: "required",
    csrf: {
      required: true,
      strategy: "origin_referer_and_csrf_token",
    },
    requiredQuery: [],
    handlerContract: "handleWorkspaceMembershipDisableRequest",
    responseKind: "json",
    idempotent: false,
    implemented: true,
  },
  {
    id: "platform_workspace_member_reactivate",
    method: "POST",
    path: "/api/platform/workspaces/:workspaceId/members/:membershipId/reactivate",
    browserSession: "required",
    csrf: {
      required: true,
      strategy: "origin_referer_and_csrf_token",
    },
    requiredQuery: [],
    handlerContract: "handleWorkspaceMembershipReactivateRequest",
    responseKind: "json",
    idempotent: false,
    implemented: true,
  },
  {
    id: "platform_workspace_app_entitlements",
    method: "GET",
    path: "/api/platform/workspaces/:workspaceId/app-entitlements",
    browserSession: "required",
    csrf: {
      required: false,
      strategy: "none",
    },
    requiredQuery: [],
    handlerContract: "handleWorkspaceAppEntitlementsAdminRequest",
    responseKind: "json",
    idempotent: true,
    implemented: true,
  },
  {
    id: "platform_workspace_kqag_entitlement_status",
    method: "POST",
    path: "/api/platform/workspaces/:workspaceId/app-entitlements/kqag/status",
    browserSession: "required",
    csrf: {
      required: true,
      strategy: "origin_referer_and_csrf_token",
    },
    requiredQuery: ["status"],
    handlerContract: "handleWorkspaceKqagEntitlementStatusRequest",
    responseKind: "json",
    idempotent: false,
    implemented: true,
  },
  {
    id: "platform_workspace_audit_events",
    method: "GET",
    path: "/api/platform/workspaces/:workspaceId/audit-events",
    browserSession: "required",
    csrf: {
      required: false,
      strategy: "none",
    },
    requiredQuery: [],
    handlerContract: "handleWorkspaceAuditEventsAdminRequest",
    responseKind: "json",
    idempotent: true,
    implemented: true,
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
    implemented: true,
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
    implemented: true,
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
    implemented: true,
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
    implemented: true,
  },
] as const;

export function getHttpRouteContract(id: HttpRouteId): HttpRouteContract {
  const route = HTTP_ROUTE_CONTRACTS.find((candidate) => candidate.id === id);

  if (!route) {
    throw new Error("Unknown HTTP route contract.");
  }

  return route;
}
