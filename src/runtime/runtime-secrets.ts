export interface PlatformRuntimeSecretEnv {
  [name: string]: string | undefined;
}

export type PlatformRuntimeSecretConfigErrorCode =
  | "missing_csrf_token_hash_secret"
  | "invalid_csrf_token_hash_secret"
  | "missing_auth_state_hash_secret"
  | "invalid_auth_state_hash_secret"
  | "missing_app_launch_token_hash_secret"
  | "invalid_app_launch_token_hash_secret";

export class PlatformRuntimeSecretConfigError extends Error {
  readonly code: PlatformRuntimeSecretConfigErrorCode;
  readonly publicMessage = "Platform runtime secret config is invalid.";

  constructor(code: PlatformRuntimeSecretConfigErrorCode) {
    super("Platform runtime secret config is invalid.");
    this.name = "PlatformRuntimeSecretConfigError";
    this.code = code;
  }
}

export interface PlatformRuntimeSecretConfig {
  csrfTokenHashSecret: string;
  authStateHashSecret?: string;
  appLaunchTokenHashSecret?: string;
}

export interface PlatformRuntimeSecretConfigReadOptions {
  requireAuthStateHashSecret?: boolean;
  requireAppLaunchTokenHashSecret?: boolean;
}

const minimumCsrfTokenHashSecretLength = 32;
const minimumAuthStateHashSecretLength = 32;
const minimumAppLaunchTokenHashSecretLength = 32;

export function readPlatformRuntimeSecretConfig(
  env: PlatformRuntimeSecretEnv,
  options: PlatformRuntimeSecretConfigReadOptions = {},
): PlatformRuntimeSecretConfig {
  const csrfTokenHashSecret = readString(env.CSRF_TOKEN_HASH_SECRET);
  const authStateHashSecret = readString(env.AUTH_STATE_HASH_SECRET);
  const appLaunchTokenHashSecret = readString(env.APP_LAUNCH_TOKEN_HASH_SECRET);

  if (!csrfTokenHashSecret) {
    throw new PlatformRuntimeSecretConfigError("missing_csrf_token_hash_secret");
  }

  if (csrfTokenHashSecret.length < minimumCsrfTokenHashSecretLength) {
    throw new PlatformRuntimeSecretConfigError("invalid_csrf_token_hash_secret");
  }

  if (options.requireAuthStateHashSecret && !authStateHashSecret) {
    throw new PlatformRuntimeSecretConfigError("missing_auth_state_hash_secret");
  }

  if (
    authStateHashSecret &&
    authStateHashSecret.length < minimumAuthStateHashSecretLength
  ) {
    throw new PlatformRuntimeSecretConfigError("invalid_auth_state_hash_secret");
  }

  if (options.requireAppLaunchTokenHashSecret && !appLaunchTokenHashSecret) {
    throw new PlatformRuntimeSecretConfigError("missing_app_launch_token_hash_secret");
  }

  if (
    appLaunchTokenHashSecret &&
    appLaunchTokenHashSecret.length < minimumAppLaunchTokenHashSecretLength
  ) {
    throw new PlatformRuntimeSecretConfigError(
      "invalid_app_launch_token_hash_secret",
    );
  }

  return {
    csrfTokenHashSecret,
    ...(authStateHashSecret ? { authStateHashSecret } : {}),
    ...(appLaunchTokenHashSecret ? { appLaunchTokenHashSecret } : {}),
  };
}

function readString(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}
