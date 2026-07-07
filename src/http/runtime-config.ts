import type { HttpOriginValidationConfig } from "./origin-validation.js";
import type { BrowserSessionCookieConfig } from "./session-cookie.js";

export interface NodePlatformRuntimeConfigEnv {
  [name: string]: string | undefined;
}

export type NodePlatformRuntimeConfigErrorCode =
  | "invalid_host"
  | "invalid_port"
  | "missing_public_base_url"
  | "invalid_public_base_url"
  | "missing_allowed_origins"
  | "invalid_allowed_origin"
  | "invalid_cookie_secure"
  | "insecure_cookie_config";

export class NodePlatformRuntimeConfigError extends Error {
  readonly code: NodePlatformRuntimeConfigErrorCode;
  readonly publicMessage = "Platform HTTP runtime config is invalid.";

  constructor(code: NodePlatformRuntimeConfigErrorCode) {
    super("Platform HTTP runtime config is invalid.");
    this.name = "NodePlatformRuntimeConfigError";
    this.code = code;
  }
}

export interface NodePlatformRuntimeConfig {
  host: string;
  port: number;
  nodeEnv: string;
  publicBaseUrl: string;
  originConfig: HttpOriginValidationConfig;
  cookie: BrowserSessionCookieConfig;
}

const localDefaultHost = "127.0.0.1";
const localDefaultPort = 3000;

export function readNodePlatformRuntimeConfig(
  env: NodePlatformRuntimeConfigEnv,
): NodePlatformRuntimeConfig {
  const nodeEnv = readString(env.NODE_ENV) ?? "development";
  const production = nodeEnv === "production";
  const host = readString(env.PLATFORM_HTTP_HOST) ?? localDefaultHost;

  if (!host) {
    throw new NodePlatformRuntimeConfigError("invalid_host");
  }

  const port = readPort(env.PLATFORM_HTTP_PORT);
  const publicBaseUrl = readPublicBaseUrl(env.PLATFORM_PUBLIC_BASE_URL, {
    production,
    port,
  });
  const cookieSecure = readCookieSecure(env.PLATFORM_COOKIE_SECURE, production);

  if (production && !cookieSecure) {
    throw new NodePlatformRuntimeConfigError("insecure_cookie_config");
  }

  const allowedOrigins = readAllowedOrigins(env.PLATFORM_ALLOWED_ORIGINS, {
    production,
    publicBaseUrl,
  });

  return {
    host,
    port,
    nodeEnv,
    publicBaseUrl,
    originConfig: {
      allowedOrigins,
      publicBaseUrl,
    },
    cookie: {
      secure: cookieSecure,
    },
  };
}

function readPort(value: string | undefined): number {
  const raw = readString(value);

  if (!raw) {
    return localDefaultPort;
  }

  const port = Number(raw);

  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new NodePlatformRuntimeConfigError("invalid_port");
  }

  return port;
}

function readPublicBaseUrl(
  value: string | undefined,
  options: { production: boolean; port: number },
): string {
  const raw = readString(value);

  if (!raw) {
    if (options.production) {
      throw new NodePlatformRuntimeConfigError("missing_public_base_url");
    }

    return `http://${localDefaultHost}:${options.port}`;
  }

  if (!isSafeHttpUrl(raw)) {
    throw new NodePlatformRuntimeConfigError("invalid_public_base_url");
  }

  if (options.production && !isHttpsUrlWithoutQueryOrFragment(raw)) {
    throw new NodePlatformRuntimeConfigError("invalid_public_base_url");
  }

  return raw;
}

function readCookieSecure(value: string | undefined, production: boolean): boolean {
  const raw = readString(value);

  if (!raw) {
    return production;
  }

  if (raw === "true") {
    return true;
  }

  if (raw === "false") {
    return false;
  }

  throw new NodePlatformRuntimeConfigError("invalid_cookie_secure");
}

function readAllowedOrigins(
  value: string | undefined,
  options: { production: boolean; publicBaseUrl: string },
): string[] {
  const raw = readString(value);

  if (!raw) {
    if (options.production) {
      throw new NodePlatformRuntimeConfigError("missing_allowed_origins");
    }

    return [toOrigin(options.publicBaseUrl, "invalid_public_base_url")];
  }

  const origins = raw
    .split(",")
    .map((candidate) => candidate.trim())
    .filter(Boolean);

  if (origins.length === 0) {
    throw new NodePlatformRuntimeConfigError("missing_allowed_origins");
  }

  return origins.map((origin) =>
    normalizeAllowedOrigin(origin, options.production),
  );
}

function normalizeAllowedOrigin(value: string, production: boolean): string {
  const origin = toOrigin(value, "invalid_allowed_origin");
  const withoutTrailingSlash = value.endsWith("/") ? value.slice(0, -1) : value;

  if (withoutTrailingSlash !== origin) {
    throw new NodePlatformRuntimeConfigError("invalid_allowed_origin");
  }

  if (production && !isHttpsUrl(origin)) {
    throw new NodePlatformRuntimeConfigError("invalid_allowed_origin");
  }

  return origin;
}

function toOrigin(
  value: string,
  errorCode: NodePlatformRuntimeConfigErrorCode,
): string {
  try {
    const parsed = new URL(value);

    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new Error("unsupported protocol");
    }

    return parsed.origin;
  } catch {
    throw new NodePlatformRuntimeConfigError(errorCode);
  }
}

function isSafeHttpUrl(value: string): boolean {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

function isHttpsUrl(value: string): boolean {
  try {
    return new URL(value).protocol === "https:";
  } catch {
    return false;
  }
}

function isHttpsUrlWithoutQueryOrFragment(value: string): boolean {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" && !parsed.search && !parsed.hash;
  } catch {
    return false;
  }
}

function readString(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}
