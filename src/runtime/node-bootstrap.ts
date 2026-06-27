import {
  createDatabaseClient,
  readDatabaseConfig,
  type DatabaseClient,
  type DatabaseEnvironment,
} from "../db/client.js";
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
  DatabaseEnvironment;

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
      const secrets = readSecretConfigSafely(input.env);
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
        });
        const server = (input.serverFactory ?? createNodePlatformHttpServer)(
          dependencies,
        ) as PlatformBootstrapServer;

        await listenSafely(server, runtimeConfig);

        state.runtimeConfig = runtimeConfig;
        state.secrets = secrets;
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
): PlatformRuntimeSecretConfig {
  try {
    return readPlatformRuntimeSecretConfig(env);
  } catch {
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
