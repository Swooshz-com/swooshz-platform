export const DEFAULT_BROWSER_SESSION_COOKIE_NAME = "swooshz_session";

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
    path: config.path ?? "/",
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
