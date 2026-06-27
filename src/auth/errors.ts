export type AuthConfigErrorCode =
  | "missing_required_env"
  | "invalid_provider_key"
  | "invalid_url"
  | "session_secret_too_short"
  | "invalid_allowed_email"
  | "invalid_allowed_domain";

export type AuthCallbackErrorCode =
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
  | "invalid_platform_identity_state";

export type AuthProviderErrorCode =
  | "invalid_verified_identity"
  | "provider_verification_failed";

export type AuthSessionErrorCode =
  | "session_lookup_failed"
  | "session_revocation_failed";

export class AuthConfigError extends Error {
  readonly code: AuthConfigErrorCode;
  readonly publicMessage = "Authentication configuration is invalid.";

  constructor(code: AuthConfigErrorCode, message: string) {
    super(message);
    this.name = "AuthConfigError";
    this.code = code;
  }
}

export class AuthCallbackError extends Error {
  readonly code: AuthCallbackErrorCode;
  readonly publicMessage = "Authentication callback could not be completed.";

  constructor(code: AuthCallbackErrorCode, message: string) {
    super(message);
    this.name = "AuthCallbackError";
    this.code = code;
  }
}

export class AuthProviderError extends Error {
  readonly code: AuthProviderErrorCode;
  readonly publicMessage = "Authentication provider verification failed.";

  constructor(code: AuthProviderErrorCode, message: string) {
    super(message);
    this.name = "AuthProviderError";
    this.code = code;
  }
}

export class AuthSessionError extends Error {
  readonly code: AuthSessionErrorCode;
  readonly publicMessage = "Session operation could not be completed.";

  constructor(code: AuthSessionErrorCode, message: string) {
    super(message);
    this.name = "AuthSessionError";
    this.code = code;
  }
}
