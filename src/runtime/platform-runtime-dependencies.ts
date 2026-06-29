import { createDrizzleAuthStateStore } from "../db/auth-state-repository.js";
import { createDrizzleAppLaunchTokenRepository } from "../db/app-launch-token-repository.js";
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
import {
  createGenericOidcJwksTokenVerifier,
} from "../auth/generic-oidc-jwks-verifier.js";
import {
  createGenericOidcProviderAdapter,
  type GenericOidcHttpClient,
} from "../auth/generic-oidc-provider-adapter.js";
import type {
  ProviderIdentityIdFactoryInput,
  SessionIdFactoryInput,
  UserIdFactoryInput,
} from "../auth/platform-identity-resolver.js";
import { createPlatformIdentitySessionResolver } from "../auth/platform-identity-resolver.js";
import type { AuthConfig } from "../auth/config.js";
import type { OidcProviderAdapter } from "../auth/oidc.js";
import {
  AppLaunchTokenCryptoConfigError,
  createHmacAppLaunchTokenHasher,
  createSecureAppLaunchTokenFactory,
} from "../platform/app-launch-token-crypto.js";
import type {
  AppLaunchTokenIdFactory,
} from "../platform/app-launch-intent-service.js";
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
import type { KqagBrowserLaunchDependencies } from "../http/handlers.js";
import {
  reportAuthCallbackFailureToConsole,
  type AuthCallbackFailureReporter,
} from "../http/auth-handlers.js";
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
  appLaunch?: PlatformRuntimeAppLaunchDependencyInput;
  auth?: PlatformRuntimeAuthDependencyInput;
  kqagBrowserLaunch?: KqagBrowserLaunchDependencies["kqag"];
}

export interface PlatformRuntimeAppLaunchDependencyInput {
  tokenIdFactory: AppLaunchTokenIdFactory;
  tokenByteLength?: number;
  ttlSeconds?: number;
}

export type PlatformRuntimeAuthProviderMode = "injected_adapter" | "generic_oidc";

export type PlatformRuntimeAuthConfigErrorCode =
  | "missing_injected_oidc_adapter"
  | "missing_generic_oidc_issuer_url"
  | "missing_generic_oidc_jwks_url"
  | "missing_generic_oidc_http_client"
  | "invalid_auth_provider_mode";

export class PlatformRuntimeAuthConfigError extends Error {
  readonly code: PlatformRuntimeAuthConfigErrorCode;
  readonly publicMessage = "Platform runtime auth config is invalid.";

  constructor(code: PlatformRuntimeAuthConfigErrorCode) {
    super("Platform runtime auth config is invalid.");
    this.name = "PlatformRuntimeAuthConfigError";
    this.code = code;
  }
}

export interface PlatformRuntimeAuthDependencyInput {
  authConfig: AuthConfig;
  oidcAdapter?: OidcProviderAdapter;
  providerMode?: PlatformRuntimeAuthProviderMode;
  genericOidcHttpClient?: GenericOidcHttpClient;
  sessionDurationMs: number;
  sessionIdFactory(input: SessionIdFactoryInput): string;
  userIdFactory(input: UserIdFactoryInput): string;
  providerIdentityIdFactory(input: ProviderIdentityIdFactoryInput): string;
  stateTtlSeconds?: number;
  stateByteLength?: number;
  nonceByteLength?: number;
  successRedirectPath?: string;
  callbackFailureReporter?: AuthCallbackFailureReporter;
}

const defaultCsrfTokenTtlSeconds = 900;
const defaultAuthStateTtlSeconds = 600;
const defaultAppLaunchTokenTtlSeconds = 300;

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
  const appLaunchDependencies = input.appLaunch
    ? createAppLaunchDependencies({
        appLaunch: input.appLaunch,
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
    kqagBrowserLaunch: input.kqagBrowserLaunch,
    ...appLaunchDependencies,
    ...authDependencies,
  };
}

function createAppLaunchDependencies({
  appLaunch,
  db,
  repositories,
  secrets,
}: {
  appLaunch: PlatformRuntimeAppLaunchDependencyInput;
  db: DrizzleDatabase;
  repositories: ReturnType<typeof createDrizzlePlatformRepositories>;
  secrets: PlatformRuntimeSecretConfig;
}): Pick<
  NodePlatformHttpAdapterDependencies,
  "appLaunchIntent" | "appLaunchTokenConsume"
> {
  const appLaunchTokens = createDrizzleAppLaunchTokenRepository(db);
  const launchTokenHasher = createAppLaunchTokenHasherSafely(secrets);

  return {
    appLaunchIntent: {
      repositories: {
        ...repositories,
        appLaunchTokens,
      },
      launchTokenFactory: createSecureAppLaunchTokenFactory({
        byteLength: appLaunch.tokenByteLength,
      }),
      launchTokenHasher,
      launchTokenIdFactory: appLaunch.tokenIdFactory,
      ttlSeconds: appLaunch.ttlSeconds ?? defaultAppLaunchTokenTtlSeconds,
    },
    appLaunchTokenConsume: {
      repositories: {
        ...repositories,
        appLaunchTokens,
      },
      launchTokenHasher,
    },
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
  const oidcAdapter = createOidcAdapterSafely(auth, stateReferenceFactory);

  return {
    authStart: {
      authConfig: auth.authConfig,
      oidcAdapter,
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
      oidcAdapter,
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
      callbackFailureReporter:
        auth.callbackFailureReporter ?? reportAuthCallbackFailureToConsole,
    },
  };
}

function createOidcAdapterSafely(
  auth: PlatformRuntimeAuthDependencyInput,
  stateReferenceFactory: (value: string) => string,
): OidcProviderAdapter {
  const mode = auth.providerMode ?? "injected_adapter";

  if (mode === "injected_adapter") {
    if (!auth.oidcAdapter) {
      throw new PlatformRuntimeAuthConfigError("missing_injected_oidc_adapter");
    }

    return auth.oidcAdapter;
  }

  if (mode === "generic_oidc") {
    assertGenericOidcConfig(auth.authConfig);
    const httpClient = readGenericOidcHttpClient(auth);

    const tokenVerifier = createGenericOidcJwksTokenVerifier({
      httpClient,
    });

    return createGenericOidcProviderAdapter({
      authConfig: auth.authConfig,
      httpClient,
      tokenVerifier,
      nonceReferenceFactory: stateReferenceFactory,
    });
  }

  throw new PlatformRuntimeAuthConfigError("invalid_auth_provider_mode");
}

function assertGenericOidcConfig(authConfig: AuthConfig): void {
  if (!authConfig.issuerUrl?.trim()) {
    throw new PlatformRuntimeAuthConfigError("missing_generic_oidc_issuer_url");
  }

  if (!authConfig.jwksUrl?.trim()) {
    throw new PlatformRuntimeAuthConfigError("missing_generic_oidc_jwks_url");
  }
}

function readGenericOidcHttpClient(
  auth: PlatformRuntimeAuthDependencyInput,
): GenericOidcHttpClient {
  if (!auth.genericOidcHttpClient) {
    throw new PlatformRuntimeAuthConfigError("missing_generic_oidc_http_client");
  }

  return auth.genericOidcHttpClient;
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

function createAppLaunchTokenHasherSafely(secrets: PlatformRuntimeSecretConfig) {
  const secret = secrets.appLaunchTokenHashSecret?.trim();

  if (!secret) {
    throw new PlatformRuntimeSecretConfigError(
      "missing_app_launch_token_hash_secret",
    );
  }

  try {
    return createHmacAppLaunchTokenHasher({ secret });
  } catch (error) {
    if (error instanceof AppLaunchTokenCryptoConfigError) {
      throw new PlatformRuntimeSecretConfigError(
        "invalid_app_launch_token_hash_secret",
      );
    }

    throw new PlatformRuntimeSecretConfigError(
      "invalid_app_launch_token_hash_secret",
    );
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
