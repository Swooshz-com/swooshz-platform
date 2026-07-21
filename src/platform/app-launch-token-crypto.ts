import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

import type {
  AppLaunchTokenFactory,
  AppLaunchTokenHasher,
  AppLaunchTokenIdFactory,
} from "./app-launch-intent-service.js";

export type AppLaunchTokenCryptoConfigErrorCode =
  | "invalid_secret"
  | "invalid_token";

export class AppLaunchTokenCryptoConfigError extends Error {
  readonly code: AppLaunchTokenCryptoConfigErrorCode;
  readonly publicMessage = "App launch token crypto configuration is invalid.";

  constructor(code: AppLaunchTokenCryptoConfigErrorCode) {
    super("App launch token crypto configuration is invalid.");
    this.name = "AppLaunchTokenCryptoConfigError";
    this.code = code;
  }
}

export interface SecureAppLaunchTokenFactoryOptions {
  byteLength?: number;
}

export interface HmacAppLaunchTokenHasherOptions {
  secret: string;
}

const defaultTokenByteLength = 32;
const minimumSecretLength = 32;
const hashPrefix = "app-launch:v1:hmac-sha256";

export function createSecureAppLaunchTokenFactory(
  options: SecureAppLaunchTokenFactoryOptions = {},
): AppLaunchTokenFactory {
  const byteLength = options.byteLength ?? defaultTokenByteLength;

  return {
    async createToken() {
      const token = randomBytes(byteLength).toString("base64url");

      if (!token.trim()) {
        throw new AppLaunchTokenCryptoConfigError("invalid_token");
      }

      return token;
    },
  };
}

export function createHmacAppLaunchTokenHasher(
  options: HmacAppLaunchTokenHasherOptions,
): AppLaunchTokenHasher {
  const secret = options.secret.trim();

  if (secret.length < minimumSecretLength) {
    throw new AppLaunchTokenCryptoConfigError("invalid_secret");
  }

  return {
    async hashToken(token) {
      if (!token.trim()) {
        throw new AppLaunchTokenCryptoConfigError("invalid_token");
      }

      const digest = createHmac("sha256", secret)
        .update(token, "utf8")
        .digest("base64url");

      return `${hashPrefix}:${digest}`;
    },
  };
}

export function createSecureAppLaunchTokenIdFactory(
  options: SecureAppLaunchTokenFactoryOptions = {},
): AppLaunchTokenIdFactory {
  const byteLength = options.byteLength ?? defaultTokenByteLength;

  return {
    createId() {
      const id = randomBytes(byteLength).toString("base64url");

      if (!id.trim()) {
        throw new AppLaunchTokenCryptoConfigError("invalid_token");
      }

      return `app_launch_${id}`;
    },
  };
}

export function createAccessValidationGrantId(): string {
  return randomBytes(32).toString("base64url");
}

export function hashFinalizationHandle(rawHandle: string): string {
  return createHash("sha256").update(rawHandle, "utf8").digest("hex");
}

export function serviceAuthorizationMatches(actual: string, expected: string): boolean {
  const left = Buffer.from(actual, "utf8");
  const right = Buffer.from(expected, "utf8");
  return left.length === right.length && timingSafeEqual(left, right);
}
