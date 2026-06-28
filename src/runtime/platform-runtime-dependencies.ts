import { createDrizzleAuthStateStore } from "../db/auth-state-repository.js";
import { createDrizzleCsrfTokenRepository } from "../db/csrf-token-repository.js";
import {
  createDrizzlePlatformRepositories,
  type DrizzleDatabase,
} from "../db/repositories.js";
import {
  AuthStateCryptoConfigError,
  createHmacAuthStateReferenceFactory,
  createSecureAuthNonceFactory,
  createSecureAuthStateFactory,
} from "../auth/auth-state-crypto.js";
import type {
  ProviderIdentityIdFactoryInput,
  SessionIdFactoryInput,
  UserIdFactoryInput,
} from "../auth/platform-identity-resolver.js";
import { createPlatformIdentitySessionResolver } from "../auth/platform-identity-resolver.js";
import type { AuthConfig } from "../auth/config.js";
import type { OidcProviderAdapter } from "../auth/oidc.js";
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
  auth?: PlatformRuntimeAuthDependencyInput;
}

export interface PlatformRuntimeAuthDependencyInput {
  authConfig: AuthConfig;
  oidcAdapter: OidcProviderAdapter;
  sessionDurationMs: number;
  sessionIdFactory(input: SessionIdFactoryInput): string;
  userIdFactory(input: UserIdFactoryInput): string;
  providerIdentityIdFactory(input: ProviderIdentityIdFactoryInput): string;
  stateTtlSeconds?: number;
  stateByteLength?: number;
  nonceByteLength?: number;
  successRedirectPath?: string;
}

const defaultCsrfTokenTtlSeconds = 900;
const defaultAuthStateTtlSeconds = 600;

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
  const authDependencies = input.auth
    ? createAuthDependencies({
        auth: input.auth,
        db: input.db,
        repositories,
        secrets: input.secrets,
      })
    : {};

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
    ...authDependencies,
  };
}

function createAuthDependencies({
  auth,
  db,
  repositories,
  secrets,
}: {
  auth: PlatformRuntimeAuthDependencyInput;
  db: DrizzleDatabase;
  repositories: ReturnType<typeof createDrizzlePlatformRepositories>;
  secrets: PlatformRuntimeSecretConfig;
}): Pick<NodePlatformHttpAdapterDependencies, "authStart" | "authCallback"> {
  const stateStore = createDrizzleAuthStateStore(db);
  const stateReferenceFactory = createAuthStateReferenceFactorySafely(secrets);

  return {
    authStart: {
      authConfig: auth.authConfig,
      oidcAdapter: auth.oidcAdapter,
      stateStore,
      stateFactory: createSecureAuthStateFactory({
        byteLength: auth.stateByteLength,
      }),
      nonceFactory: createSecureAuthNonceFactory({
        byteLength: auth.nonceByteLength,
      }),
      stateReferenceFactory,
      ttlSeconds: auth.stateTtlSeconds ?? defaultAuthStateTtlSeconds,
    },
    authCallback: {
      authConfig: auth.authConfig,
      oidcAdapter: auth.oidcAdapter,
      stateStore,
      stateReferenceFactory,
      platformIdentityResolver: createPlatformIdentitySessionResolver({
        repositories: {
          users: repositories.users,
          providerIdentities: repositories.providerIdentities!,
          sessions: repositories.sessions,
        },
        sessionDurationMs: auth.sessionDurationMs,
        sessionIdFactory: auth.sessionIdFactory,
        userIdFactory: auth.userIdFactory,
        providerIdentityIdFactory: auth.providerIdentityIdFactory,
      }),
      successRedirectPath: auth.successRedirectPath,
    },
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

function createAuthStateReferenceFactorySafely(secrets: PlatformRuntimeSecretConfig) {
  const secret = secrets.authStateHashSecret?.trim();

  if (!secret) {
    throw new PlatformRuntimeSecretConfigError("missing_auth_state_hash_secret");
  }

  try {
    return createHmacAuthStateReferenceFactory({ secret });
  } catch (error) {
    if (error instanceof AuthStateCryptoConfigError) {
      throw new PlatformRuntimeSecretConfigError("invalid_auth_state_hash_secret");
    }

    throw new PlatformRuntimeSecretConfigError("invalid_auth_state_hash_secret");
  }
}
