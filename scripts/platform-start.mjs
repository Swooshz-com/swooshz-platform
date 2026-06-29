#!/usr/bin/env node

import { pathToFileURL } from "node:url";

import {
  createPlatformNodeBootstrap,
  createSecureAuthProviderIdentityIdFactory,
  createSecureAuthSessionIdFactory,
  createSecureAuthUserIdFactory,
} from "../dist/index.js";

export const DEFAULT_AUTH_SESSION_DURATION_MS = 60 * 60 * 1000;

export class PlatformStartCliError extends Error {
  constructor(code) {
    super("Platform server could not be started.");
    this.name = "PlatformStartCliError";
    this.code = code;
    this.publicMessage = this.message;
  }
}

export function createPlatformStartBootstrapInput(options = {}) {
  const { env, fetchImplementation } = options;
  const authMode = readAuthMode(env);
  const fetchForProvider =
    Object.hasOwn(options, "fetchImplementation")
      ? fetchImplementation
      : globalThis.fetch;
  const input = {
    env,
  };

  if (authMode === "generic_oidc") {
    input.genericOidcHttpClient = createPlatformStartGenericOidcHttpClient({
      fetchImplementation: readFetchImplementation(fetchForProvider),
    });
    input.authSessionDurationMs = DEFAULT_AUTH_SESSION_DURATION_MS;
    input.authSessionIdFactory = createSecureAuthSessionIdFactory();
    input.authUserIdFactory = createSecureAuthUserIdFactory();
    input.authProviderIdentityIdFactory =
      createSecureAuthProviderIdentityIdFactory();
  }

  return input;
}

export function createPlatformStartGenericOidcHttpClient(options = {}) {
  const { fetchImplementation } = options;
  const fetchForProvider = readFetchImplementation(
    Object.hasOwn(options, "fetchImplementation")
      ? fetchImplementation
      : globalThis.fetch,
  );

  return async (request) => {
    const response = await fetchForProvider(request.url, {
      method: request.method,
      headers: request.headers,
      body: request.body,
    });

    return {
      ok: response.ok,
      status: response.status,
      async json() {
        return response.json();
      },
    };
  };
}

export async function executePlatformStart(options = {}) {
  const {
    env,
    createBootstrap = createPlatformNodeBootstrap,
    fetchImplementation,
    writeLine = console.log,
    registerSignalHandler,
  } = options;

  try {
    const input = createPlatformStartBootstrapInput({
      env,
      fetchImplementation:
        Object.hasOwn(options, "fetchImplementation")
          ? fetchImplementation
          : globalThis.fetch,
    });
    const bootstrap = createBootstrap(input);
    const result = await bootstrap.start();

    writeLine(
      formatPlatformStartSummary({
        host: result.host,
        port: result.port,
        environment: readEnvironment(env),
        authMode: readAuthMode(env) ?? "not_configured",
        env,
      }),
    );

    if (registerSignalHandler) {
      const shutdownHandler = createPlatformStartShutdownHandler({
        bootstrap,
      });
      registerSignalHandler("SIGINT", shutdownHandler);
      registerSignalHandler("SIGTERM", shutdownHandler);
    }

    return {
      bootstrap,
      startResult: result,
    };
  } catch (error) {
    if (error instanceof PlatformStartCliError) {
      throw error;
    }

    throw new PlatformStartCliError("start_failed");
  }
}

export function createPlatformStartShutdownHandler({
  bootstrap,
  writeLine = console.log,
  writeError = console.error,
  exit = (code) => {
    process.exitCode = code;
  },
}) {
  let shutdownStarted = false;

  return async () => {
    if (shutdownStarted) {
      return;
    }

    shutdownStarted = true;

    try {
      await bootstrap.stop();
      writeLine("Platform server stopped.");
      exit(0);
    } catch {
      writeError("Platform server shutdown failed.");
      exit(1);
    }
  };
}

export function formatPlatformStartSummary({
  host,
  port,
  environment,
  authMode,
}) {
  return [
    "Swooshz Platform server started.",
    `host=${host}`,
    `port=${port}`,
    `environment=${environment}`,
    `authMode=${authMode}`,
  ].join(" ");
}

function readFetchImplementation(fetchImplementation) {
  if (typeof fetchImplementation !== "function") {
    throw new PlatformStartCliError("invalid_config");
  }

  return fetchImplementation;
}

function readAuthMode(env) {
  const mode = env?.PLATFORM_AUTH_PROVIDER_MODE?.trim();

  return mode || undefined;
}

function readEnvironment(env) {
  return env?.NODE_ENV?.trim() || "development";
}

async function main() {
  try {
    await executePlatformStart({
      env: process.env,
      registerSignalHandler(signal, handler) {
        process.once(signal, handler);
      },
    });
  } catch (error) {
    if (error instanceof PlatformStartCliError) {
      console.error(error.publicMessage);
    } else {
      console.error("Platform server could not be started.");
    }
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
