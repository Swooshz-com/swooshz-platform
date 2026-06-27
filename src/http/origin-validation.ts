import type { HttpRequestHeaders } from "./handlers.js";

export interface HttpOriginValidationConfig {
  allowedOrigins: readonly string[];
  publicBaseUrl?: string;
}

export type OriginValidationResult =
  | {
      valid: true;
      origin: string;
      source: "origin" | "referer";
    }
  | {
      valid: false;
      reason:
        | "missing_origin"
        | "invalid_origin"
        | "origin_not_allowed"
        | "invalid_allowed_origin_config";
    };

export interface ValidateHttpRequestOriginInput {
  headers?: HttpRequestHeaders;
  config: HttpOriginValidationConfig;
}

export function validateHttpRequestOrigin(
  input: ValidateHttpRequestOriginInput,
): OriginValidationResult {
  const allowedOrigins = normalizeAllowedOrigins(input.config);

  if (!allowedOrigins) {
    return {
      valid: false,
      reason: "invalid_allowed_origin_config",
    };
  }

  const originHeader = readHeader(input.headers, "origin");
  const refererHeader = readHeader(input.headers, "referer");
  const source = originHeader ? "origin" : refererHeader ? "referer" : null;

  if (!source) {
    return {
      valid: false,
      reason: "missing_origin",
    };
  }

  const origin = source === "origin"
    ? normalizeOriginValue(originHeader)
    : normalizeRefererOrigin(refererHeader);

  if (!origin) {
    return {
      valid: false,
      reason: "invalid_origin",
    };
  }

  if (!allowedOrigins.has(origin)) {
    return {
      valid: false,
      reason: "origin_not_allowed",
    };
  }

  return {
    valid: true,
    origin,
    source,
  };
}

function normalizeAllowedOrigins(
  config: HttpOriginValidationConfig,
): Set<string> | null {
  const normalized = new Set<string>();

  for (const value of config.allowedOrigins) {
    const origin = normalizeOriginValue(value);

    if (!origin) {
      return null;
    }

    normalized.add(origin);
  }

  if (config.publicBaseUrl) {
    const origin = normalizeRefererOrigin(config.publicBaseUrl);

    if (!origin) {
      return null;
    }

    normalized.add(origin);
  }

  return normalized;
}

function normalizeOriginValue(value: string | undefined): string | null {
  if (!value) {
    return null;
  }

  try {
    const parsed = new URL(value);
    const origin = parsed.origin;
    const withoutTrailingSlash = value.endsWith("/") ? value.slice(0, -1) : value;

    return withoutTrailingSlash === origin ? origin : null;
  } catch {
    return null;
  }
}

function normalizeRefererOrigin(value: string | undefined): string | null {
  if (!value) {
    return null;
  }

  try {
    const parsed = new URL(value);
    return parsed.origin;
  } catch {
    return null;
  }
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
