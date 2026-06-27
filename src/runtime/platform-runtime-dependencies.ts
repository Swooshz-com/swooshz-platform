import { createDrizzleCsrfTokenRepository } from "../db/csrf-token-repository.js";
import {
  createDrizzlePlatformRepositories,
  type DrizzleDatabase,
} from "../db/repositories.js";
import {
  createHmacCsrfTokenHasher,
  createSecureCsrfTokenFactory,
  CsrfTokenCryptoConfigError,
} from "../http/csrf-token-crypto.js";
import {
  createRepositoryBackedCsrfTokenValidator,
  type CsrfTokenIdFactory,
} from "../http/csrf-token-service.js";
import type { NodePlatformHttpAdapterDependencies } from "../http/node-adapter.js";
import type { NodePlatformRuntimeConfig } from "../http/runtime-config.js";
import {
  PlatformRuntimeSecretConfigError,
  type PlatformRuntimeSecretConfig,
} from "./runtime-secrets.js";

export interface PlatformRuntimeDependencyInput {
  db: DrizzleDatabase;
  runtimeConfig: NodePlatformRuntimeConfig;
  secrets: PlatformRuntimeSecretConfig;
  now: () => string;
  csrfTokenIdFactory: CsrfTokenIdFactory;
  csrfTokenByteLength?: number;
  csrfTokenTtlSeconds?: number;
}

const defaultCsrfTokenTtlSeconds = 900;

export function createPlatformRuntimeDependencies(
  input: PlatformRuntimeDependencyInput,
): NodePlatformHttpAdapterDependencies {
  const repositories = createDrizzlePlatformRepositories(input.db);
  const csrfTokens = createDrizzleCsrfTokenRepository(input.db);
  const tokenFactory = createSecureCsrfTokenFactory({
    byteLength: input.csrfTokenByteLength,
  });
  const tokenHasher = createCsrfTokenHasherSafely(input.secrets);
  const csrfTokenIssuer = {
    tokens: csrfTokens,
    tokenFactory,
    tokenHasher,
    idFactory: input.csrfTokenIdFactory,
  };

  return {
    repositories,
    now: input.now,
    cookie: input.runtimeConfig.cookie,
    originConfig: input.runtimeConfig.originConfig,
    csrfTokenIssuer,
    csrfTokenValidator: createRepositoryBackedCsrfTokenValidator({
      tokens: csrfTokens,
      tokenHasher,
    }),
    csrfTokenTtlSeconds: input.csrfTokenTtlSeconds ?? defaultCsrfTokenTtlSeconds,
  };
}

function createCsrfTokenHasherSafely(secrets: PlatformRuntimeSecretConfig) {
  try {
    return createHmacCsrfTokenHasher({
      secret: secrets.csrfTokenHashSecret,
    });
  } catch (error) {
    if (error instanceof CsrfTokenCryptoConfigError) {
      throw new PlatformRuntimeSecretConfigError("invalid_csrf_token_hash_secret");
    }

    throw new PlatformRuntimeSecretConfigError("invalid_csrf_token_hash_secret");
  }
}
