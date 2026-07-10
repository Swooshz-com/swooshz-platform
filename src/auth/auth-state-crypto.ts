import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export type AuthStateCryptoConfigErrorCode = "invalid_secret" | "invalid_value";

export class AuthStateCryptoConfigError extends Error {
  readonly code: AuthStateCryptoConfigErrorCode;
  readonly publicMessage = "Auth state crypto configuration is invalid.";

  constructor(code: AuthStateCryptoConfigErrorCode) {
    super("Auth state crypto configuration is invalid.");
    this.name = "AuthStateCryptoConfigError";
    this.code = code;
  }
}

export interface SecureAuthStateFactory {
  createState(): string;
}

export interface SecureAuthNonceFactory {
  createNonce(): string;
}

export type AuthStateReferenceFactory = (value: string) => string;

export interface SecureAuthValueFactoryOptions {
  byteLength?: number;
}

export interface HmacAuthStateReferenceFactoryOptions {
  secret: string;
}

const defaultByteLength = 32;
const minimumSecretLength = 32;
const referencePrefix = "auth-state:v1:hmac-sha256";

export function createSecureAuthStateFactory(
  options: SecureAuthValueFactoryOptions = {},
): SecureAuthStateFactory {
  const byteLength = readByteLength(options.byteLength);

  return {
    createState() {
      return createOpaqueValue(byteLength);
    },
  };
}

export function createSecureAuthNonceFactory(
  options: SecureAuthValueFactoryOptions = {},
): SecureAuthNonceFactory {
  const byteLength = readByteLength(options.byteLength);

  return {
    createNonce() {
      return createOpaqueValue(byteLength);
    },
  };
}

export function createHmacAuthStateReferenceFactory(
  options: HmacAuthStateReferenceFactoryOptions,
): AuthStateReferenceFactory {
  const secret = readSecret(options.secret);

  return (value) => {
    const normalized = value.trim();

    if (!normalized) {
      throw new AuthStateCryptoConfigError("invalid_value");
    }

    const digest = createHmac("sha256", secret)
      .update(normalized, "utf8")
      .digest("base64url");

    return `${referencePrefix}:${digest}`;
  };
}

export function authStateReferencesEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left, "utf8");
  const rightBytes = Buffer.from(right, "utf8");

  return leftBytes.length === rightBytes.length && timingSafeEqual(
    leftBytes,
    rightBytes,
  );
}

function readByteLength(value: number | undefined): number {
  const byteLength = value ?? defaultByteLength;

  if (!Number.isInteger(byteLength) || byteLength < defaultByteLength) {
    throw new AuthStateCryptoConfigError("invalid_value");
  }

  return byteLength;
}

function readSecret(value: string): string {
  const normalized = value.trim();

  if (normalized.length < minimumSecretLength) {
    throw new AuthStateCryptoConfigError("invalid_secret");
  }

  return normalized;
}

function createOpaqueValue(byteLength: number): string {
  const value = randomBytes(byteLength).toString("base64url");

  if (!value.trim()) {
    throw new AuthStateCryptoConfigError("invalid_value");
  }

  return value;
}
