import type { HttpRequestHeaders } from "./handlers.js";
import type { HttpRouteContract } from "./route-contracts.js";

export interface CsrfTokenValidator {
  validate(input: {
    csrfToken: string;
    sessionId: string | null;
    now: string;
  }): Promise<{ valid: true } | { valid: false; reason: string }>;
}

export type CsrfValidationResult =
  | {
      valid: true;
    }
  | {
      valid: false;
      reason:
        | "missing_csrf_token"
        | "invalid_csrf_token"
        | "csrf_validation_failed";
    };

export interface ValidateCsrfTokenForRouteInput {
  route: HttpRouteContract;
  headers?: HttpRequestHeaders;
  sessionId: string | null;
  now: string;
  csrfTokenValidator?: CsrfTokenValidator;
}

export async function validateCsrfTokenForRoute(
  input: ValidateCsrfTokenForRouteInput,
): Promise<CsrfValidationResult> {
  if (!input.route.csrf.required) {
    return { valid: true };
  }

  const csrfToken = extractCsrfToken(input.headers);

  if (!csrfToken) {
    return {
      valid: false,
      reason: "missing_csrf_token",
    };
  }

  if (!input.csrfTokenValidator) {
    return {
      valid: false,
      reason: "csrf_validation_failed",
    };
  }

  try {
    const result = await input.csrfTokenValidator.validate({
      csrfToken,
      sessionId: input.sessionId,
      now: input.now,
    });

    if (!result.valid) {
      return {
        valid: false,
        reason: "invalid_csrf_token",
      };
    }

    return { valid: true };
  } catch {
    return {
      valid: false,
      reason: "csrf_validation_failed",
    };
  }
}

export function extractCsrfToken(
  headers: HttpRequestHeaders | undefined,
): string | null {
  const value = readHeader(headers, "x-csrf-token");

  if (!value || !isSafeCsrfTokenReference(value)) {
    return null;
  }

  return value;
}

function isSafeCsrfTokenReference(value: string): boolean {
  return /^[A-Za-z0-9._~-]{8,512}$/.test(value);
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
