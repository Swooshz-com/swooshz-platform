import {
  createDatabaseClient,
  readDatabaseConfig,
  type DatabaseClient,
  type DatabaseEnvironment,
} from "../db/client.js";
import {
  readAuthConfig,
  type AuthConfig,
  type AuthEnvironment,
} from "../auth/config.js";
import type { GenericOidcHttpClient } from "../auth/generic-oidc-provider-adapter.js";
import type { OidcProviderAdapter } from "../auth/oidc.js";
import type {
  ProviderIdentityIdFactoryInput,
  SessionIdFactoryInput,
  UserIdFactoryInput,
} from "../auth/platform-identity-resolver.js";
import type { DrizzleDatabase } from "../db/repositories.js";
import { createSecureCsrfTokenIdFactory } from "../http/csrf-token-crypto.js";
import { createNodePlatformHttpServer } from "../http/node-server.js";
import {
  readNodePlatformRuntimeConfig,
  type NodePlatformRuntimeConfig,
  type NodePlatformRuntimeConfigEnv,
} from "../http/runtime-config.js";
import type { CsrfTokenIdFactory } from "../http/csrf-token-service.js";
import type { NodePlatformHttpAdapterDependencies } from "../http/node-adapter.js";
import {
  createPlatformRuntimeDependencies,
  type PlatformRuntimeAuthProviderMode,
  type PlatformRuntimeDependencyInput,
} from "./platform-runtime-dependencies.js";
import {
  readPlatformRuntimeSecretConfig,
  type PlatformRuntimeSecretConfig,
  type PlatformRuntimeSecretEnv,
} from "./runtime-secrets.js";
import { PlatformNodeBootstrapError } from "./bootstrap-config.js";

export type PlatformNodeBootstrapEnv =
  NodePlatformRuntimeConfigEnv &
  PlatformRuntimeSecretEnv &
  DatabaseEnvironment &
  AuthEnvironment & {
    PLATFORM_AUTH_PROVIDER_MODE?: string;
  };

export interface PlatformBootstrapDatabaseClient {
  db: DrizzleDatabase;
  close?(): Promise<void> | void;
}

export interface PlatformBootstrapServer {
  readonly listening?: boolean;
  once(event: "error", listener: (error: unknown) => void): unknown;
  off?(event: "error", listener: (error: unknown) => void): unknown;
  removeListener?(event: "error", listener: (error: unknown) => void): unknown;
  listen(
    port: number,
    host: string,
    callback: (error?: unknown) => void,
  ): unknown;
  close(callback: (error?: unknown) => void): unknown;
}

export interface PlatformNodeBootstrapInput {
  env: PlatformNodeBootstrapEnv;
  now?: () => string;
  databaseClientFactory?: (
    config: ReturnType<typeof readDatabaseConfig>,
  ) => PlatformBootstrapDatabaseClient;
  serverFactory?: (
    dependencies: NodePlatformHttpAdapterDependencies,
  ) => PlatformBootstrapServer;
  oidcAdapter?: OidcProviderAdapter;
  authProviderAdapter?: OidcProviderAdapter;
  genericOidcHttpClient?: GenericOidcHttpClient;
  authSessionDurationMs?: number;
  authSessionIdFactory?(input: SessionIdFactoryInput): string;
  authUserIdFactory?(input: UserIdFactoryInput): string;
  authProviderIdentityIdFactory?(input: ProviderIdentityIdFactoryInput): string;
  authStateTtlSeconds?: number;
  authStateByteLength?: number;
  authNonceByteLength?: number;
  authSuccessRedirectPath?: string;
  csrfTokenIdFactory?: CsrfTokenIdFactory;
  csrfTokenByteLength?: number;
  csrfTokenTtlSeconds?: number;
}

export interface PlatformNodeBootstrapStartResult {
  host: string;
  port: number;
}

export interface PlatformNodeBootstrapController {
  start(): Promise<PlatformNodeBootstrapStartResult>;
  stop(): Promise<void>;
  getServer(): PlatformBootstrapServer | null;
}

interface BootstrapState {
  runtimeConfig: NodePlatformRuntimeConfig | null;
  secrets: PlatformRuntimeSecretConfig | null;
  authConfig: AuthConfig | null;
  databaseClient: PlatformBootstrapDatabaseClient | null;
  server: PlatformBootstrapServer | null;
  started: boolean;
}

export function createPlatformNodeBootstrap(
  input: PlatformNodeBootstrapInput,
): PlatformNodeBootstrapController {
  const state: BootstrapState = {
    runtimeConfig: null,
    secrets: null,
    authConfig: null,
    databaseClient: null,
    server: null,
    started: false,
  };

  return {
    async start() {
      if (state.started) {
        throw new PlatformNodeBootstrapError("already_started");
      }

      const runtimeConfig = readRuntimeConfigSafely(input.env);
      const authProviderMode = readAuthProviderModeSafely(input.env);
      const authAdapter = readAuthAdapter(input);
      const authEnabled =
        authProviderMode === "generic_oidc" || Boolean(authAdapter);
      const secrets = readSecretConfigSafely(input.env, authEnabled);
      const authConfig = authEnabled
        ? readAuthConfigSafely(input.env, authProviderMode)
        : null;
      assertGenericOidcRuntimeInput(input, authProviderMode);
      const databaseClient = createDatabaseClientSafely(input);

      try {
        const dependencies = createDependenciesSafely({
          db: databaseClient.db,
          runtimeConfig,
          secrets,
          now: input.now ?? (() => new Date().toISOString()),
          csrfTokenIdFactory:
            input.csrfTokenIdFactory ?? createSecureCsrfTokenIdFactory(),
          csrfTokenByteLength: input.csrfTokenByteLength,
          csrfTokenTtlSeconds: input.csrfTokenTtlSeconds,
          auth: authEnabled && authConfig
            ? createBootstrapAuthInput(
                input,
                authAdapter,
                authConfig,
                authProviderMode,
              )
            : undefined,
        });
        const server = (input.serverFactory ?? createNodePlatformHttpServer)(
          dependencies,
        ) as PlatformBootstrapServer;

        await listenSafely(server, runtimeConfig);

        state.runtimeConfig = runtimeConfig;
        state.secrets = secrets;
        state.authConfig = authConfig;
        state.databaseClient = databaseClient;
        state.server = server;
        state.started = true;

        return {
          host: runtimeConfig.host,
          port: runtimeConfig.port,
        };
      } catch (error) {
        await closeDatabaseQuietly(databaseClient);

        if (error instanceof PlatformNodeBootstrapError) {
          throw error;
        }

        throw new PlatformNodeBootstrapError("server_start_failed");
      }
    },
    async stop() {
      const server = state.server;
      const databaseClient = state.databaseClient;

      state.runtimeConfig = null;
      state.secrets = null;
      state.authConfig = null;
      state.server = null;
      state.databaseClient = null;
      state.started = false;

      if (server) {
        await closeServerSafely(server);
      }

      if (databaseClient) {
        await closeDatabaseSafely(databaseClient);
      }
    },
    getServer() {
      return state.server;
    },
  };
}

function readRuntimeConfigSafely(
  env: PlatformNodeBootstrapEnv,
): NodePlatformRuntimeConfig {
  try {
    return readNodePlatformRuntimeConfig(env);
  } catch {
    throw new PlatformNodeBootstrapError("invalid_config");
  }
}

function readSecretConfigSafely(
  env: PlatformNodeBootstrapEnv,
  requireAuthStateHashSecret: boolean,
): PlatformRuntimeSecretConfig {
  try {
    return readPlatformRuntimeSecretConfig(env, { requireAuthStateHashSecret });
  } catch {
    throw new PlatformNodeBootstrapError("invalid_config");
  }
}

function readAuthProviderModeSafely(
  env: PlatformNodeBootstrapEnv,
): PlatformRuntimeAuthProviderMode | undefined {
  const mode = env.PLATFORM_AUTH_PROVIDER_MODE?.trim();

  if (!mode) {
    return undefined;
  }

  if (mode === "generic_oidc") {
    return "generic_oidc";
  }

  throw new PlatformNodeBootstrapError("invalid_config");
}

function readAuthConfigSafely(
  env: PlatformNodeBootstrapEnv,
  authProviderMode: PlatformRuntimeAuthProviderMode | undefined,
): AuthConfig {
  try {
    const authConfig = readAuthConfig(env);

    if (authProviderMode === "generic_oidc") {
      assertGenericOidcAuthConfig(authConfig);
    }

    return authConfig;
  } catch {
    throw new PlatformNodeBootstrapError("invalid_config");
  }
}

function readAuthAdapter(
  input: PlatformNodeBootstrapInput,
): OidcProviderAdapter | undefined {
  return input.oidcAdapter ?? input.authProviderAdapter;
}

function createBootstrapAuthInput(
  input: PlatformNodeBootstrapInput,
  oidcAdapter: OidcProviderAdapter | undefined,
  authConfig: AuthConfig,
  authProviderMode: PlatformRuntimeAuthProviderMode | undefined,
): NonNullable<PlatformRuntimeDependencyInput["auth"]> {
  if (
    !input.authSessionDurationMs ||
    !input.authSessionIdFactory ||
    !input.authUserIdFactory ||
    !input.authProviderIdentityIdFactory
  ) {
    throw new PlatformNodeBootstrapError("dependency_composition_failed");
  }

  return {
    authConfig,
    oidcAdapter,
    providerMode: authProviderMode ?? "injected_adapter",
    genericOidcHttpClient: input.genericOidcHttpClient,
    sessionDurationMs: input.authSessionDurationMs,
    sessionIdFactory: input.authSessionIdFactory,
    userIdFactory: input.authUserIdFactory,
    providerIdentityIdFactory: input.authProviderIdentityIdFactory,
    stateTtlSeconds: input.authStateTtlSeconds,
    stateByteLength: input.authStateByteLength,
    nonceByteLength: input.authNonceByteLength,
    successRedirectPath: input.authSuccessRedirectPath,
  };
}

function assertGenericOidcAuthConfig(authConfig: AuthConfig): void {
  if (!authConfig.issuerUrl?.trim() || !authConfig.jwksUrl?.trim()) {
    throw new PlatformNodeBootstrapError("invalid_config");
  }
}

function assertGenericOidcRuntimeInput(
  input: PlatformNodeBootstrapInput,
  authProviderMode: PlatformRuntimeAuthProviderMode | undefined,
): void {
  if (authProviderMode === "generic_oidc" && !input.genericOidcHttpClient) {
    throw new PlatformNodeBootstrapError("invalid_config");
  }
}

function createDatabaseClientSafely(
  input: PlatformNodeBootstrapInput,
): PlatformBootstrapDatabaseClient {
  try {
    const config = readDatabaseConfig(input.env);
    const factory = input.databaseClientFactory ?? createDefaultDatabaseClient;
    return factory(config);
  } catch {
    throw new PlatformNodeBootstrapError("database_client_failed");
  }
}

function createDefaultDatabaseClient(
  config: ReturnType<typeof readDatabaseConfig>,
): PlatformBootstrapDatabaseClient {
  const client = createDatabaseClient(config) as DatabaseClient;

  return {
    db: client.db as unknown as DrizzleDatabase,
    close() {
      return client.pool.end();
    },
  };
}

function createDependenciesSafely(
  input: PlatformRuntimeDependencyInput,
): NodePlatformHttpAdapterDependencies {
  try {
    return createPlatformRuntimeDependencies(input);
  } catch {
    throw new PlatformNodeBootstrapError("dependency_composition_failed");
  }
}

function listenSafely(
  server: PlatformBootstrapServer,
  runtimeConfig: NodePlatformRuntimeConfig,
): Promise<void> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const cleanup = () => {
      removeServerErrorListener(server, onError);
    };
    const fail = () => {
      if (settled) {
        return;
      }

      settled = true;
      cleanup();
      reject(new PlatformNodeBootstrapError("server_start_failed"));
    };
    const succeed = () => {
      if (settled) {
        return;
      }

      settled = true;
      cleanup();
      resolve();
    };
    const onError = () => {
      fail();
    };

    try {
      server.once("error", onError);
      server.listen(runtimeConfig.port, runtimeConfig.host, (error?: unknown) => {
        if (error) {
          fail();
          return;
        }

        succeed();
      });
    } catch {
      fail();
    }
  });
}

function removeServerErrorListener(
  server: PlatformBootstrapServer,
  listener: (error: unknown) => void,
): void {
  if (server.off) {
    server.off("error", listener);
    return;
  }

  server.removeListener?.("error", listener);
}

function closeServerSafely(server: PlatformBootstrapServer): Promise<void> {
  return new Promise((resolve, reject) => {
    try {
      server.close((error?: unknown) => {
        if (error) {
          reject(new PlatformNodeBootstrapError("server_stop_failed"));
          return;
        }

        resolve();
      });
    } catch {
      reject(new PlatformNodeBootstrapError("server_stop_failed"));
    }
  });
}

async function closeDatabaseSafely(
  databaseClient: PlatformBootstrapDatabaseClient,
): Promise<void> {
  try {
    await databaseClient.close?.();
  } catch {
    throw new PlatformNodeBootstrapError("server_stop_failed");
  }
}

async function closeDatabaseQuietly(
  databaseClient: PlatformBootstrapDatabaseClient,
): Promise<void> {
  try {
    await databaseClient.close?.();
  } catch {
    // Startup failure remains privacy-safe and does not expose cleanup details.
  }
}
