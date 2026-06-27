export interface PlatformRuntimeSecretEnv {
  [name: string]: string | undefined;
}

export type PlatformRuntimeSecretConfigErrorCode =
  | "missing_csrf_token_hash_secret"
  | "invalid_csrf_token_hash_secret";

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
}

const minimumCsrfTokenHashSecretLength = 32;

export function readPlatformRuntimeSecretConfig(
  env: PlatformRuntimeSecretEnv,
): PlatformRuntimeSecretConfig {
  const csrfTokenHashSecret = readString(env.CSRF_TOKEN_HASH_SECRET);

  if (!csrfTokenHashSecret) {
    throw new PlatformRuntimeSecretConfigError("missing_csrf_token_hash_secret");
  }

  if (csrfTokenHashSecret.length < minimumCsrfTokenHashSecretLength) {
    throw new PlatformRuntimeSecretConfigError("invalid_csrf_token_hash_secret");
  }

  return {
    csrfTokenHashSecret,
  };
}

function readString(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}
