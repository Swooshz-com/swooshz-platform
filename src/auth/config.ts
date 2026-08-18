import { AuthConfigError } from "./errors.js";

export const AUTH_SESSION_SECRET_MIN_LENGTH = 32;

const providerKeyPattern = /^[a-z][a-z0-9-]{1,63}$/;
const retiredClientCredentialEnvNames = [
  "AUTH_CLIENT_ID",
  "AUTH_CLIENT_SECRET",
] as const;

export interface AuthEnvironment {
  [key: string]: string | undefined;
  AUTH_PROVIDER_KEY?: string;
  AUTH_ISSUER_URL?: string;
  AUTH_AUTHORIZATION_URL?: string;
  AUTH_TOKEN_URL?: string;
  AUTH_USERINFO_URL?: string;
  AUTH_JWKS_URL?: string;
  OIDC_CLIENT_ID?: string;
  OIDC_CLIENT_SECRET?: string;
  AUTH_REDIRECT_URI?: string;
  SESSION_SECRET?: string;
}

export interface AuthConfig {
  providerKey: string;
  authorizationUrl: string;
  tokenUrl: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  sessionSecret: string;
  issuerUrl: string | null;
  userinfoUrl: string | null;
  jwksUrl: string | null;
}

export function readAuthConfig(env: AuthEnvironment): AuthConfig {
  assertRetiredClientCredentialNamesAbsent(env);
  const providerKey = normalizeProviderKey(readRequiredEnv(env, "AUTH_PROVIDER_KEY"));
  const authorizationUrl = readRequiredUrl(env, "AUTH_AUTHORIZATION_URL");
  const tokenUrl = readRequiredUrl(env, "AUTH_TOKEN_URL");
  const clientId = readRequiredEnv(env, "OIDC_CLIENT_ID");
  const clientSecret = readRequiredEnv(env, "OIDC_CLIENT_SECRET");
  const redirectUri = readRequiredUrl(env, "AUTH_REDIRECT_URI");
  const sessionSecret = readRequiredEnv(env, "SESSION_SECRET");

  if (sessionSecret.length < AUTH_SESSION_SECRET_MIN_LENGTH) {
    throw new AuthConfigError(
      "session_secret_too_short",
      `SESSION_SECRET must be at least ${AUTH_SESSION_SECRET_MIN_LENGTH} characters.`,
    );
  }

  return {
    providerKey,
    authorizationUrl,
    tokenUrl,
    clientId,
    clientSecret,
    redirectUri,
    sessionSecret,
    issuerUrl: readOptionalIssuerUrl(env, "AUTH_ISSUER_URL"),
    userinfoUrl: readOptionalUrl(env, "AUTH_USERINFO_URL"),
    jwksUrl: readOptionalUrl(env, "AUTH_JWKS_URL"),
  };
}

export function normalizeProviderKey(value: string): string {
  const normalized = value.trim().toLowerCase();

  if (!providerKeyPattern.test(normalized)) {
    throw new AuthConfigError(
      "invalid_provider_key",
      "AUTH_PROVIDER_KEY must use lowercase letters, numbers, and hyphens.",
    );
  }

  return normalized;
}

function assertRetiredClientCredentialNamesAbsent(env: AuthEnvironment): void {
  if (retiredClientCredentialEnvNames.some((key) => env[key] !== undefined)) {
    throw new AuthConfigError(
      "missing_required_env",
      "Retired OIDC client credential names are not accepted.",
    );
  }
}

function readRequiredEnv(env: AuthEnvironment, key: keyof AuthEnvironment): string {
  const value = env[key]?.trim();

  if (!value) {
    throw new AuthConfigError(
      "missing_required_env",
      `${key} is required for auth configuration.`,
    );
  }

  return value;
}

function readRequiredUrl(env: AuthEnvironment, key: keyof AuthEnvironment): string {
  return normalizeUrl(readRequiredEnv(env, key), key);
}

function readOptionalUrl(env: AuthEnvironment, key: keyof AuthEnvironment): string | null {
  const value = env[key]?.trim();

  if (!value) {
    return null;
  }

  return normalizeUrl(value, key);
}

function readOptionalIssuerUrl(
  env: AuthEnvironment,
  key: keyof AuthEnvironment,
): string | null {
  const value = env[key]?.trim();

  if (!value) {
    return null;
  }

  validateUrl(value, key);

  return value;
}

function normalizeUrl(value: string, key: keyof AuthEnvironment): string {
  const parsed = validateUrl(value, key);

  return parsed.toString();
}

function validateUrl(value: string, key: keyof AuthEnvironment): URL {
  try {
    const parsed = new URL(value);

    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      throw new Error("Unsupported URL protocol.");
    }

    return parsed;
  } catch {
    throw new AuthConfigError("invalid_url", `${key} must be a valid URL.`);
  }
}
