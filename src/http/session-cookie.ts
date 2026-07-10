export const DEFAULT_BROWSER_SESSION_COOKIE_NAME = "swooshz_session";
export const DEFAULT_AUTH_STATE_COOKIE_NAME = "swooshz_auth_state";

export type BrowserSessionSameSite = "Lax" | "Strict" | "None";

export interface BrowserSessionCookieConfig {
  name?: string;
  secure?: boolean;
  sameSite?: BrowserSessionSameSite;
  path?: string;
  maxAgeSeconds?: number;
}

interface NormalizedBrowserSessionCookieConfig {
  name: string;
  secure: boolean;
  sameSite: BrowserSessionSameSite;
  path: string;
  maxAgeSeconds?: number;
}

const safeCookieNamePattern = /^[A-Za-z0-9_!#$%&'*+.^`|~-]+$/;
const safeSessionReferencePattern = /^[A-Za-z0-9._~-]{8,256}$/;
const safeAuthStateBindingPattern = /^[A-Za-z0-9._~:%+-]{8,512}$/;

export function parseCookieHeader(
  cookieHeader: string | null | undefined,
): Record<string, string> {
  if (!cookieHeader) {
    return {};
  }

  const cookies: Record<string, string> = {};

  for (const part of cookieHeader.split(";")) {
    const separatorIndex = part.indexOf("=");

    if (separatorIndex <= 0) {
      continue;
    }

    const name = part.slice(0, separatorIndex).trim();
    const rawValue = part.slice(separatorIndex + 1).trim();

    if (!safeCookieNamePattern.test(name)) {
      continue;
    }

    const value = decodeCookieValue(rawValue);

    if (value === null || !isSafeSessionReference(value)) {
      continue;
    }

    cookies[name] = value;
  }

  return cookies;
}

export function extractBrowserSessionIdFromCookieHeader(
  cookieHeader: string | null | undefined,
  config: BrowserSessionCookieConfig = {},
): string | null {
  const normalized = normalizeBrowserSessionCookieConfig(config);
  const cookies = parseCookieHeader(cookieHeader);
  const value = cookies[normalized.name];

  return value && isSafeSessionReference(value) ? value : null;
}

export function buildBrowserSessionSetCookie(
  sessionId: string,
  config: BrowserSessionCookieConfig = {},
): string {
  if (!isSafeSessionReference(sessionId)) {
    throw new Error("Invalid browser session reference.");
  }

  const normalized = normalizeBrowserSessionCookieConfig(config);
  const parts = [
    `${normalized.name}=${encodeURIComponent(sessionId)}`,
    "HttpOnly",
    `Path=${normalized.path}`,
    `SameSite=${normalized.sameSite}`,
  ];

  if (normalized.maxAgeSeconds !== undefined) {
    parts.push(`Max-Age=${normalized.maxAgeSeconds}`);
  }

  if (normalized.secure) {
    parts.push("Secure");
  }

  return parts.join("; ");
}

export function buildBrowserSessionClearCookie(
  config: BrowserSessionCookieConfig = {},
): string {
  const normalized = normalizeBrowserSessionCookieConfig(config);
  const parts = [
    `${normalized.name}=`,
    "HttpOnly",
    `Path=${normalized.path}`,
    `SameSite=${normalized.sameSite}`,
    "Max-Age=0",
    "Expires=Thu, 01 Jan 1970 00:00:00 GMT",
  ];

  if (normalized.secure) {
    parts.push("Secure");
  }

  return parts.join("; ");
}

function normalizeBrowserSessionCookieConfig(
  config: BrowserSessionCookieConfig,
): NormalizedBrowserSessionCookieConfig {
  const name = config.name ?? DEFAULT_BROWSER_SESSION_COOKIE_NAME;

  if (!safeCookieNamePattern.test(name)) {
    throw new Error("Invalid browser session cookie name.");
  }

  return {
    name,
    secure: config.secure ?? false,
    sameSite: config.sameSite ?? "Lax",
    path: config.path ?? "/api/platform",
    maxAgeSeconds: config.maxAgeSeconds,
  };
}

function decodeCookieValue(value: string): string | null {
  try {
    return decodeURIComponent(value);
  } catch {
    return null;
  }
}

function isSafeSessionReference(value: string): boolean {
  return safeSessionReferencePattern.test(value);
}

export function buildAuthStateBindingCookie(
  bindingReference: string,
  ttlSeconds: number,
  config: BrowserSessionCookieConfig = {},
): string {
  if (!safeAuthStateBindingPattern.test(bindingReference)) {
    throw new Error("Invalid auth state binding reference.");
  }

  if (!Number.isInteger(ttlSeconds) || ttlSeconds <= 0) {
    throw new Error("Invalid auth state binding expiry.");
  }

  const parts = [
    DEFAULT_AUTH_STATE_COOKIE_NAME + "=" + encodeURIComponent(bindingReference),
    "HttpOnly",
    "Path=/api/platform/auth/callback",
    "SameSite=Lax",
    "Max-Age=" + ttlSeconds,
  ];

  if (config.secure) {
    parts.push("Secure");
  }

  return parts.join("; ");
}

export function buildAuthStateBindingClearCookie(
  config: BrowserSessionCookieConfig = {},
): string {
  const parts = [
    DEFAULT_AUTH_STATE_COOKIE_NAME + "=",
    "HttpOnly",
    "Path=/api/platform/auth/callback",
    "SameSite=Lax",
    "Max-Age=0",
    "Expires=Thu, 01 Jan 1970 00:00:00 GMT",
  ];

  if (config.secure) {
    parts.push("Secure");
  }

  return parts.join("; ");
}

export function extractAuthStateBindingFromCookieHeader(
  cookieHeader: string | null | undefined,
): string | null {
  if (!cookieHeader) {
    return null;
  }

  let binding: string | null = null;

  for (const part of cookieHeader.split(";")) {
    const separatorIndex = part.indexOf("=");

    if (separatorIndex <= 0) {
      continue;
    }

    const name = part.slice(0, separatorIndex).trim();

    if (name !== DEFAULT_AUTH_STATE_COOKIE_NAME) {
      continue;
    }

    if (binding !== null) {
      return null;
    }

    const value = decodeCookieValue(part.slice(separatorIndex + 1).trim());

    if (!value || !safeAuthStateBindingPattern.test(value)) {
      return null;
    }

    binding = value;
  }

  return binding;
}
