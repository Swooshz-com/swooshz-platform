import { createHmac, randomBytes } from "node:crypto";

import type {
  CsrfTokenFactory,
  CsrfTokenHasher,
  CsrfTokenIdFactory,
} from "./csrf-token-service.js";

export type CsrfTokenCryptoConfigErrorCode =
  | "invalid_secret"
  | "invalid_token";

export class CsrfTokenCryptoConfigError extends Error {
  readonly code: CsrfTokenCryptoConfigErrorCode;
  readonly publicMessage = "CSRF token crypto configuration is invalid.";

  constructor(code: CsrfTokenCryptoConfigErrorCode) {
    super("CSRF token crypto configuration is invalid.");
    this.name = "CsrfTokenCryptoConfigError";
    this.code = code;
  }
}

export interface SecureCsrfTokenFactoryOptions {
  byteLength?: number;
}

export interface HmacCsrfTokenHasherOptions {
  secret: string;
}

const defaultTokenByteLength = 32;
const minimumSecretLength = 32;
const hashPrefix = "csrf:v1:hmac-sha256";

export function createSecureCsrfTokenFactory(
  options: SecureCsrfTokenFactoryOptions = {},
): CsrfTokenFactory {
  const byteLength = options.byteLength ?? defaultTokenByteLength;

  return {
    async createToken() {
      const token = randomBytes(byteLength).toString("base64url");

      if (!token.trim()) {
        throw new CsrfTokenCryptoConfigError("invalid_token");
      }

      return token;
    },
  };
}

export function createHmacCsrfTokenHasher(
  options: HmacCsrfTokenHasherOptions,
): CsrfTokenHasher {
  const secret = options.secret.trim();

  if (secret.length < minimumSecretLength) {
    throw new CsrfTokenCryptoConfigError("invalid_secret");
  }

  return {
    async hashToken(token) {
      if (!token.trim()) {
        throw new CsrfTokenCryptoConfigError("invalid_token");
      }

      const digest = createHmac("sha256", secret)
        .update(token, "utf8")
        .digest("base64url");

      return `${hashPrefix}:${digest}`;
    },
  };
}

export function createSecureCsrfTokenIdFactory(
  options: SecureCsrfTokenFactoryOptions = {},
): CsrfTokenIdFactory {
  const byteLength = options.byteLength ?? defaultTokenByteLength;

  return {
    createId() {
      const id = randomBytes(byteLength).toString("base64url");

      if (!id.trim()) {
        throw new CsrfTokenCryptoConfigError("invalid_token");
      }

      return `csrf_${id}`;
    },
  };
}
