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
  const sqagLaunchMode = readSqagLaunchMode(env);
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

  if (sqagLaunchMode === "server_handoff") {
    input.sqagBrowserLaunch = {
      baseUrl: readSqagAppBaseUrl(env),
      httpClient: createPlatformStartSqagBrowserLaunchHttpClient({
        fetchImplementation: readFetchImplementation(fetchForProvider),
      }),
    };
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

export function createPlatformStartSqagBrowserLaunchHttpClient(options = {}) {
  const { fetchImplementation } = options;
  const fetchForSqag = readFetchImplementation(
    Object.hasOwn(options, "fetchImplementation")
      ? fetchImplementation
      : globalThis.fetch,
  );

  return {
    async post(request) {
      const response = await fetchForSqag(request.url, {
        method: "POST",
        headers: request.headers,
        redirect: "manual",
      });

      return {
        status: response.status,
        headers: {
          "x-sqag-finalization-handle": readHeaderValue(response.headers, "x-sqag-finalization-handle"),
        },
        body: await readJsonSafely(response),
      };
    },
  };
}

async function readJsonSafely(response) {
  try { return await response.json(); } catch { return null; }
}

function readHeaderValue(headers, name) {
  return typeof headers?.get === "function" ? headers.get(name) || undefined : undefined;
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

function readSqagLaunchMode(env) {
  const mode = env?.PLATFORM_SQAG_LAUNCH_MODE?.trim() || "manual";

  if (mode === "manual" || mode === "server_handoff") {
    return mode;
  }

  throw new PlatformStartCliError("invalid_config");
}

function readSqagAppBaseUrl(env) {
  const value = env?.PLATFORM_SQAG_APP_BASE_URL?.trim();
  const production = readEnvironment(env) === "production";

  if (!value) {
    throw new PlatformStartCliError("invalid_config");
  }

  try {
    const parsed = new URL(value);

    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new Error("unsupported protocol");
    }

    if (production && parsed.protocol !== "https:") {
      throw new Error("hosted handoff URL must use HTTPS");
    }

    if (production && (parsed.search || parsed.hash)) {
      throw new Error("hosted handoff URL must not include query or fragment");
    }

    if (production && (parsed.origin !== "https://quote.swooshz.com" || parsed.pathname !== "/" || parsed.username || parsed.password)) {
      throw new Error("hosted handoff URL must use the canonical SQAG origin");
    }

    parsed.search = "";
    parsed.hash = "";
    parsed.pathname = parsed.pathname.endsWith("/")
      ? parsed.pathname
      : `${parsed.pathname}/`;

    return parsed.toString();
  } catch {
    throw new PlatformStartCliError("invalid_config");
  }
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
