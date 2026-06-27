import {
  validateCsrfTokenForRoute,
  type CsrfTokenValidator,
} from "./csrf.js";
import type { HttpRequestHeaders } from "./handlers.js";
import {
  validateHttpRequestOrigin,
  type HttpOriginValidationConfig,
  type OriginValidationResult,
} from "./origin-validation.js";
import type { HttpRouteContract } from "./route-contracts.js";

export type HttpRequestSecurityDeniedReason =
  | Extract<OriginValidationResult, { valid: false }>["reason"]
  | "missing_csrf_token"
  | "invalid_csrf_token"
  | "csrf_validation_failed";

export type HttpRequestSecurityResult =
  | {
      allowed: true;
    }
  | {
      allowed: false;
      reason: HttpRequestSecurityDeniedReason;
      recommendedStatus: 403 | 500;
    };

export interface ValidateHttpRequestSecurityForRouteInput {
  route: HttpRouteContract;
  headers?: HttpRequestHeaders;
  sessionId: string | null;
  now: string;
  originConfig: HttpOriginValidationConfig;
  csrfTokenValidator?: CsrfTokenValidator;
}

export async function validateHttpRequestSecurityForRoute(
  input: ValidateHttpRequestSecurityForRouteInput,
): Promise<HttpRequestSecurityResult> {
  if (!input.route.csrf.required) {
    return { allowed: true };
  }

  const originResult = validateHttpRequestOrigin({
    headers: input.headers,
    config: input.originConfig,
  });

  if (!originResult.valid) {
    return denied(originResult.reason);
  }

  const csrfResult = await validateCsrfTokenForRoute({
    route: input.route,
    headers: input.headers,
    sessionId: input.sessionId,
    now: input.now,
    csrfTokenValidator: input.csrfTokenValidator,
  });

  if (!csrfResult.valid) {
    return denied(csrfResult.reason);
  }

  return { allowed: true };
}

function denied(reason: HttpRequestSecurityDeniedReason): HttpRequestSecurityResult {
  return {
    allowed: false,
    reason,
    recommendedStatus: isConfigurationOrServiceFailure(reason) ? 500 : 403,
  };
}

function isConfigurationOrServiceFailure(
  reason: HttpRequestSecurityDeniedReason,
): boolean {
  return reason === "invalid_allowed_origin_config" ||
    reason === "csrf_validation_failed";
}
