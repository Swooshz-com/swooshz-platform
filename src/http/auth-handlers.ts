import type {
  AuthStateIssueStore,
  RawAuthCallbackParams,
  StoredAuthStateInput,
} from "../auth/callback.js";
import type { AuthCallbackServiceDependencies } from "../auth/callback-service.js";
import { handleAuthCallback } from "../auth/callback-service.js";
import type { AuthConfig } from "../auth/config.js";
import type { OidcProviderAdapter } from "../auth/oidc.js";
import {
  AuthCallbackError,
  AuthProviderError,
} from "../auth/errors.js";
import type { HttpResponseLike } from "./handlers.js";
import {
  buildBrowserSessionSetCookie,
  type BrowserSessionCookieConfig,
} from "./session-cookie.js";

export interface AuthStartValueFactory {
  createState(): string;
}

export interface AuthNonceValueFactory {
  createNonce(): string;
}

export type AuthReferenceFactory = (value: string) => string;

export interface AuthStartHttpDependencies {
  authConfig: AuthConfig;
  oidcAdapter: Pick<OidcProviderAdapter, "buildAuthorizationUrl">;
  stateStore: AuthStateIssueStore;
  stateFactory: AuthStartValueFactory;
  nonceFactory: AuthNonceValueFactory;
  stateReferenceFactory: AuthReferenceFactory;
  nonceReferenceFactory?: AuthReferenceFactory;
  ttlSeconds: number;
  startFailureReporter?: AuthStartFailureReporter;
}

export interface AuthStartHttpRequest {
  now: string;
}

export interface AuthStartFailureDiagnostic {
  category: AuthStartFailureCategory;
}

export type AuthStartFailureReporter = (
  diagnostic: AuthStartFailureDiagnostic,
) => void;

export type AuthStartFailureCategory =
  | "state_generation_failed"
  | "nonce_generation_failed"
  | "state_reference_failed"
  | "nonce_reference_failed"
  | "state_store_failed"
  | "authorization_url_build_failed"
  | "invalid_authorization_redirect"
  | "unexpected_auth_start_failure";

export interface AuthCallbackHttpDependencies
  extends AuthCallbackServiceDependencies {
  successRedirectPath?: string;
  callbackFailureReporter?: AuthCallbackFailureReporter;
}

export interface AuthCallbackFailureDiagnostic {
  category: AuthCallbackFailureCategory;
}

export type AuthCallbackFailureReporter = (
  diagnostic: AuthCallbackFailureDiagnostic,
) => void;

export type AuthCallbackFailureCategory =
  | "provider_error"
  | "missing_code"
  | "missing_state"
  | "missing_stored_state"
  | "expired_state"
  | "provider_identity_rejected"
  | "email_not_allowed"
  | "domain_not_allowed"
  | "verified_email_required"
  | "provider_identity_link_failed"
  | "session_creation_failed"
  | "user_not_active"
  | "invalid_platform_identity_state"
  | "oidc_http_client_unavailable"
  | "authorization_url_build_failed"
  | "token_exchange_failed"
  | "token_response_invalid"
  | "token_verification_failed"
  | "verifier_config_incomplete"
  | "id_token_invalid"
  | "id_token_algorithm_unsupported"
  | "jwks_fetch_failed"
  | "jwks_response_invalid"
  | "jwks_signing_key_not_found"
  | "jwks_key_invalid"
  | "id_token_signature_invalid"
  | "issuer_mismatch"
  | "audience_mismatch"
  | "provider_subject_missing"
  | "token_expiry_invalid"
  | "id_token_expired"
  | "id_token_not_before_invalid"
  | "id_token_not_yet_valid"
  | "id_token_issued_at_invalid"
  | "id_token_issued_at_future"
  | "nonce_mismatch"
  | "userinfo_fetch_failed"
  | "userinfo_response_invalid"
  | "provider_subject_mismatch"
  | "provider_key_mismatch"
  | "invalid_verified_identity"
  | "provider_verification_failed"
  | "unexpected_callback_failure";

export interface AuthCallbackHttpRequest {
  query: RawAuthCallbackParams;
  now: string;
  cookie?: BrowserSessionCookieConfig;
}

const defaultAuthSuccessRedirectPath = "/app";

export async function handleAuthStartRequest(
  dependencies: AuthStartHttpDependencies,
  request: AuthStartHttpRequest,
): Promise<HttpResponseLike> {
  let state: string;
  let nonce: string;
  let stateHash: string;
  let nonceHash: string;

  try {
    state = readFactoryValue(
      dependencies.stateFactory.createState(),
    );
  } catch (error) {
    return authStartFailureFor(
      dependencies,
      error,
      "state_generation_failed",
    );
  }

  try {
    nonce = readFactoryValue(
      dependencies.nonceFactory.createNonce(),
    );
  } catch (error) {
    return authStartFailureFor(
      dependencies,
      error,
      "nonce_generation_failed",
    );
  }

  try {
    stateHash = readReference(
      dependencies.stateReferenceFactory(state),
    );
  } catch (error) {
    return authStartFailureFor(
      dependencies,
      error,
      "state_reference_failed",
    );
  }

  try {
    nonceHash = readReference(
      (dependencies.nonceReferenceFactory ?? dependencies.stateReferenceFactory)(
        nonce,
      ),
    );
  } catch (error) {
    return authStartFailureFor(
      dependencies,
      error,
      "nonce_reference_failed",
    );
  }

  const stateRecord = createStoredAuthStateRecordSafely({
    dependencies,
    request,
    stateHash,
    nonceHash,
  });

  if (!stateRecord) {
    return authStartFailureFor(
      dependencies,
      new Error("Invalid auth state expiry."),
      "unexpected_auth_start_failure",
    );
  }

  try {
    await dependencies.stateStore.storeState(stateRecord);
  } catch (error) {
    return authStartFailureFor(
      dependencies,
      error,
      "state_store_failed",
    );
  }

  let authorizationUrl: string;

  try {
    const authorization = await dependencies.oidcAdapter.buildAuthorizationUrl({
      providerKey: dependencies.authConfig.providerKey,
      authorizationUrl: dependencies.authConfig.authorizationUrl,
      clientId: dependencies.authConfig.clientId,
      redirectUri: dependencies.authConfig.redirectUri,
      state,
      nonce,
      additionalParams: {
        prompt: "select_account",
      },
    });
    authorizationUrl = authorization.url;
  } catch (error) {
    return authStartFailureFor(
      dependencies,
      error,
      "authorization_url_build_failed",
    );
  }

  let location: string;

  try {
    location = readRedirectUrl(authorizationUrl);
  } catch (error) {
    return authStartFailureFor(
      dependencies,
      error,
      "invalid_authorization_redirect",
    );
  }

  return {
    status: 302,
    headers: {
      location,
    },
    body: {
      outcome: "redirecting",
    },
  };
}

export async function handleAuthCallbackRequest(
  dependencies: AuthCallbackHttpDependencies,
  request: AuthCallbackHttpRequest,
): Promise<HttpResponseLike> {
  try {
    const result = await handleAuthCallback(dependencies, {
      params: request.query,
      now: request.now,
    });

    return {
      status: 302,
      headers: {
        location: normalizeLocalRedirectPath(dependencies.successRedirectPath),
        "set-cookie": buildBrowserSessionSetCookie(
          result.session.id,
          request.cookie,
        ),
      },
      body: {
        outcome: "authenticated",
      },
    };
  } catch (error) {
    dependencies.callbackFailureReporter?.({
      category: classifyAuthCallbackFailure(error),
    });

    return authCallbackFailure();
  }
}

export function reportAuthCallbackFailureToConsole(
  diagnostic: AuthCallbackFailureDiagnostic,
): void {
  console.error(formatAuthCallbackFailureDiagnostic(diagnostic));
}

export function reportAuthStartFailureToConsole(
  diagnostic: AuthStartFailureDiagnostic,
): void {
  console.error(formatAuthStartFailureDiagnostic(diagnostic));
}

export function formatAuthStartFailureDiagnostic(
  diagnostic: AuthStartFailureDiagnostic,
): string {
  return `auth_start_failure category=${diagnostic.category}`;
}

export function formatAuthCallbackFailureDiagnostic(
  diagnostic: AuthCallbackFailureDiagnostic,
): string {
  return `auth_callback_failure category=${diagnostic.category}`;
}

export function classifyAuthStartFailure(
  error: unknown,
  fallbackCategory: AuthStartFailureCategory =
    "unexpected_auth_start_failure",
): AuthStartFailureCategory {
  if (error instanceof AuthProviderError) {
    return classifyAuthProviderStartFailure(error) ?? fallbackCategory;
  }

  return fallbackCategory;
}

export function classifyAuthCallbackFailure(
  error: unknown,
): AuthCallbackFailureCategory {
  if (error instanceof AuthCallbackError) {
    return error.code;
  }

  if (error instanceof AuthProviderError) {
    return classifyAuthProviderFailure(error);
  }

  return "unexpected_callback_failure";
}

function classifyAuthProviderStartFailure(
  error: AuthProviderError,
): AuthStartFailureCategory | null {
  switch (error.message) {
    case "OIDC authorization URL could not be built.":
      return "authorization_url_build_failed";
    default:
      return null;
  }
}

function classifyAuthProviderFailure(
  error: AuthProviderError,
): AuthCallbackFailureCategory {
  if (error.code === "invalid_verified_identity") {
    return "invalid_verified_identity";
  }

  switch (error.message) {
    case "OIDC HTTP client is unavailable.":
      return "oidc_http_client_unavailable";
    case "OIDC authorization URL could not be built.":
      return "authorization_url_build_failed";
    case "OIDC token exchange failed.":
      return "token_exchange_failed";
    case "OIDC token response was invalid.":
      return "token_response_invalid";
    case "OIDC token verification failed.":
      return "token_verification_failed";
    case "OIDC verifier configuration is incomplete.":
      return "verifier_config_incomplete";
    case "OIDC ID token was invalid.":
      return "id_token_invalid";
    case "OIDC ID token algorithm is not supported.":
      return "id_token_algorithm_unsupported";
    case "OIDC JWKS request failed.":
      return "jwks_fetch_failed";
    case "OIDC JWKS response was invalid.":
      return "jwks_response_invalid";
    case "OIDC signing key was not found.":
      return "jwks_signing_key_not_found";
    case "OIDC JWKS could not be used.":
      return "jwks_key_invalid";
    case "OIDC ID token signature could not be verified.":
      return "id_token_signature_invalid";
    case "OIDC issuer did not match.":
      return "issuer_mismatch";
    case "OIDC audience did not match.":
      return "audience_mismatch";
    case "OIDC subject was missing.":
      return "provider_subject_missing";
    case "OIDC expiry was invalid.":
      return "token_expiry_invalid";
    case "OIDC ID token expired.":
      return "id_token_expired";
    case "OIDC not-before claim was invalid.":
      return "id_token_not_before_invalid";
    case "OIDC ID token is not yet valid.":
      return "id_token_not_yet_valid";
    case "OIDC issued-at claim was invalid.":
      return "id_token_issued_at_invalid";
    case "OIDC ID token issued-at claim is in the future.":
      return "id_token_issued_at_future";
    case "OIDC nonce could not be verified.":
      return "nonce_mismatch";
    case "OIDC userinfo request failed.":
      return "userinfo_fetch_failed";
    case "OIDC userinfo response was invalid.":
      return "userinfo_response_invalid";
    case "OIDC userinfo subject did not match.":
      return "provider_subject_mismatch";
    case "OIDC provider key did not match configuration.":
      return "provider_key_mismatch";
    default:
      return "provider_verification_failed";
  }
}

function readFactoryValue(value: string): string {
  const normalized = value.trim();

  if (!normalized) {
    throw new Error("Invalid auth value.");
  }

  return normalized;
}

function readReference(value: string): string {
  const normalized = value.trim();

  if (!normalized) {
    throw new Error("Invalid auth reference.");
  }

  return normalized;
}

function addSeconds(now: string, ttlSeconds: number): string {
  const timestamp = Date.parse(now);

  if (!Number.isFinite(timestamp) || !Number.isFinite(ttlSeconds) || ttlSeconds <= 0) {
    throw new Error("Invalid auth state expiry.");
  }

  return new Date(timestamp + ttlSeconds * 1000).toISOString();
}

function createStoredAuthStateRecordSafely({
  dependencies,
  request,
  stateHash,
  nonceHash,
}: {
  dependencies: AuthStartHttpDependencies;
  request: AuthStartHttpRequest;
  stateHash: string;
  nonceHash: string;
}): StoredAuthStateInput | null {
  try {
    return {
      providerKey: dependencies.authConfig.providerKey,
      stateHash,
      nonceHash,
      redirectUri: dependencies.authConfig.redirectUri,
      createdAt: request.now,
      expiresAt: addSeconds(request.now, dependencies.ttlSeconds),
    };
  } catch {
    return null;
  }
}

function readRedirectUrl(value: string): string {
  const parsed = new URL(value);

  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error("Invalid auth redirect.");
  }

  return parsed.toString();
}

function normalizeLocalRedirectPath(value: string | undefined): string {
  const candidate = value?.trim() || defaultAuthSuccessRedirectPath;

  if (!candidate.startsWith("/") || candidate.startsWith("//") || candidate.includes("\\")) {
    return defaultAuthSuccessRedirectPath;
  }

  return candidate;
}

function authStartFailureFor(
  dependencies: AuthStartHttpDependencies,
  error: unknown,
  fallbackCategory: AuthStartFailureCategory,
): HttpResponseLike {
  dependencies.startFailureReporter?.({
    category: classifyAuthStartFailure(error, fallbackCategory),
  });

  return authStartFailure();
}

function authStartFailure(): HttpResponseLike {
  return {
    status: 500,
    body: {
      outcome: "error",
      message: "Authentication start could not be completed.",
    },
  };
}

function authCallbackFailure(): HttpResponseLike {
  return {
    status: 400,
    body: {
      outcome: "error",
      message: "Authentication callback could not be completed.",
    },
  };
}
