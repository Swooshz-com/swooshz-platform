import { randomBytes } from "node:crypto";

import type {
  ProviderIdentityIdFactoryInput,
  SessionIdFactoryInput,
  UserIdFactoryInput,
} from "./platform-identity-resolver.js";

export type PlatformIdentityCryptoConfigErrorCode = "invalid_value";

export class PlatformIdentityCryptoConfigError extends Error {
  readonly code: PlatformIdentityCryptoConfigErrorCode;
  readonly publicMessage = "Platform identity crypto configuration is invalid.";

  constructor(code: PlatformIdentityCryptoConfigErrorCode) {
    super("Platform identity crypto configuration is invalid.");
    this.name = "PlatformIdentityCryptoConfigError";
    this.code = code;
  }
}

export interface SecurePlatformIdentityIdFactoryOptions {
  byteLength?: number;
}

const defaultByteLength = 32;

export function createSecureAuthSessionIdFactory(
  options: SecurePlatformIdentityIdFactoryOptions = {},
): (input: SessionIdFactoryInput) => string {
  const byteLength = readByteLength(options.byteLength);

  return () => `session_${createOpaqueValue(byteLength)}`;
}

export function createSecureAuthUserIdFactory(
  options: SecurePlatformIdentityIdFactoryOptions = {},
): (input: UserIdFactoryInput) => string {
  const byteLength = readByteLength(options.byteLength);

  return () => `user_${createOpaqueValue(byteLength)}`;
}

export function createSecureAuthProviderIdentityIdFactory(
  options: SecurePlatformIdentityIdFactoryOptions = {},
): (input: ProviderIdentityIdFactoryInput) => string {
  const byteLength = readByteLength(options.byteLength);

  return () => `provider_identity_${createOpaqueValue(byteLength)}`;
}

function readByteLength(value: number | undefined): number {
  const byteLength = value ?? defaultByteLength;

  if (!Number.isInteger(byteLength) || byteLength < defaultByteLength) {
    throw new PlatformIdentityCryptoConfigError("invalid_value");
  }

  return byteLength;
}

function createOpaqueValue(byteLength: number): string {
  const value = randomBytes(byteLength).toString("base64url");

  if (!value.trim()) {
    throw new PlatformIdentityCryptoConfigError("invalid_value");
  }

  return value;
}
