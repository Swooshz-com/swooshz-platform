import { normalizeEmail } from "../accounts/normalization.js";
import { AuthConfigError } from "./errors.js";

export const AUTH_SESSION_SECRET_MIN_LENGTH = 32;

const providerKeyPattern = /^[a-z][a-z0-9-]{1,63}$/;
const allowedDomainPattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

export interface AuthEnvironment {
  AUTH_PROVIDER_KEY?: string;
  AUTH_ISSUER_URL?: string;
  AUTH_AUTHORIZATION_URL?: string;
  AUTH_TOKEN_URL?: string;
  AUTH_USERINFO_URL?: string;
  AUTH_JWKS_URL?: string;
  AUTH_CLIENT_ID?: string;
  AUTH_CLIENT_SECRET?: string;
  AUTH_REDIRECT_URI?: string;
  AUTH_ALLOWED_EMAILS?: string;
  AUTH_ALLOWED_DOMAINS?: string;
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
  allowedEmails: readonly string[];
  allowedDomains: readonly string[];
}

export function readAuthConfig(env: AuthEnvironment): AuthConfig {
  const providerKey = normalizeProviderKey(readRequiredEnv(env, "AUTH_PROVIDER_KEY"));
  const authorizationUrl = readRequiredUrl(env, "AUTH_AUTHORIZATION_URL");
  const tokenUrl = readRequiredUrl(env, "AUTH_TOKEN_URL");
  const clientId = readRequiredEnv(env, "AUTH_CLIENT_ID");
  const clientSecret = readRequiredEnv(env, "AUTH_CLIENT_SECRET");
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
    issuerUrl: readOptionalUrl(env, "AUTH_ISSUER_URL"),
    userinfoUrl: readOptionalUrl(env, "AUTH_USERINFO_URL"),
    jwksUrl: readOptionalUrl(env, "AUTH_JWKS_URL"),
    allowedEmails: readAllowedEmails(env.AUTH_ALLOWED_EMAILS),
    allowedDomains: readAllowedDomains(env.AUTH_ALLOWED_DOMAINS),
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

function normalizeUrl(value: string, key: keyof AuthEnvironment): string {
  try {
    const parsed = new URL(value);

    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      throw new Error("Unsupported URL protocol.");
    }

    return parsed.toString();
  } catch {
    throw new AuthConfigError("invalid_url", `${key} must be a valid URL.`);
  }
}

function readAllowedEmails(value: string | undefined): readonly string[] {
  return uniqueCommaSeparatedValues(value).map((email) => {
    const normalized = normalizeEmail(email);

    if (!normalized.includes("@")) {
      throw new AuthConfigError(
        "invalid_allowed_email",
        "AUTH_ALLOWED_EMAILS must contain valid email-like values.",
      );
    }

    return normalized;
  });
}

function readAllowedDomains(value: string | undefined): readonly string[] {
  return uniqueCommaSeparatedValues(value).map((domain) => {
    const normalized = domain.trim().toLowerCase().replace(/^@+/, "");

    if (!allowedDomainPattern.test(normalized)) {
      throw new AuthConfigError(
        "invalid_allowed_domain",
        "AUTH_ALLOWED_DOMAINS must contain valid domain names.",
      );
    }

    return normalized;
  });
}

function uniqueCommaSeparatedValues(value: string | undefined): string[] {
  if (!value) {
    return [];
  }

  const seen = new Set<string>();
  const values: string[] = [];

  for (const item of value.split(",")) {
    const normalized = item.trim().toLowerCase();

    if (!normalized || seen.has(normalized)) {
      continue;
    }

    seen.add(normalized);
    values.push(item.trim());
  }

  return values;
}
