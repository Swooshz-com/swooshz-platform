import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { join } from "node:path";
import test from "node:test";

import {
  NodePlatformRuntimeConfigError,
  createNodePlatformHttpServer,
  readNodePlatformRuntimeConfig,
} from "../dist/index.js";
import { createInMemoryPlatformRepositories } from "./helpers/in-memory-platform-repositories.mjs";

const now = "2026-06-27T00:00:00.000Z";
const publicBaseUrl = "https://platform.example.test/app";
const allowedOrigin = "https://platform.example.test";
const alternateAllowedOrigin = "https://admin.example.test";
const syntheticPrivateUrl =
  "https://private.example.test/path?token=raw-session-token&db=postgresql://private-host";

test("runtime config parses safe local defaults", () => {
  const config = readNodePlatformRuntimeConfig({});

  assert.equal(config.host, "127.0.0.1");
  assert.equal(config.port, 3000);
  assert.equal(config.nodeEnv, "development");
  assert.equal(config.publicBaseUrl, "http://127.0.0.1:3000");
  assert.deepEqual(config.originConfig, {
    allowedOrigins: ["http://127.0.0.1:3000"],
    publicBaseUrl: "http://127.0.0.1:3000",
  });
  assert.deepEqual(config.cookie, {
    secure: false,
  });
});

test("runtime config parses explicit host port public base URL and allowed origins", () => {
  const config = readNodePlatformRuntimeConfig({
    PLATFORM_HTTP_HOST: "0.0.0.0",
    PLATFORM_HTTP_PORT: "8080",
    PLATFORM_PUBLIC_BASE_URL: publicBaseUrl,
    PLATFORM_ALLOWED_ORIGINS: `${allowedOrigin}, ${alternateAllowedOrigin}/`,
    PLATFORM_COOKIE_SECURE: "true",
    NODE_ENV: "staging",
  });

  assert.equal(config.host, "0.0.0.0");
  assert.equal(config.port, 8080);
  assert.equal(config.nodeEnv, "staging");
  assert.equal(config.publicBaseUrl, publicBaseUrl);
  assert.deepEqual(config.originConfig, {
    allowedOrigins: [allowedOrigin, alternateAllowedOrigin],
    publicBaseUrl,
  });
  assert.deepEqual(config.cookie, {
    secure: true,
  });
});

test("runtime config rejects invalid port safely", () => {
  assertConfigError(
    () => readNodePlatformRuntimeConfig({ PLATFORM_HTTP_PORT: "not-a-port-raw-secret" }),
    "invalid_port",
  );
});

test("runtime config rejects invalid public base URL safely", () => {
  assertConfigError(
    () => readNodePlatformRuntimeConfig({ PLATFORM_PUBLIC_BASE_URL: "not a url raw-secret" }),
    "invalid_public_base_url",
  );
});

test("runtime config rejects invalid allowed origin safely", () => {
  assertConfigError(
    () => readNodePlatformRuntimeConfig({
      PLATFORM_ALLOWED_ORIGINS: syntheticPrivateUrl,
    }),
    "invalid_allowed_origin",
  );
});

test("production rejects insecure cookie config", () => {
  assertConfigError(
    () => readNodePlatformRuntimeConfig({
      NODE_ENV: "production",
      PLATFORM_PUBLIC_BASE_URL: publicBaseUrl,
      PLATFORM_ALLOWED_ORIGINS: allowedOrigin,
      PLATFORM_COOKIE_SECURE: "false",
    }),
    "insecure_cookie_config",
  );
});

test("production rejects missing public base URL", () => {
  assertConfigError(
    () => readNodePlatformRuntimeConfig({
      NODE_ENV: "production",
      PLATFORM_ALLOWED_ORIGINS: allowedOrigin,
      PLATFORM_COOKIE_SECURE: "true",
    }),
    "missing_public_base_url",
  );
});

test("production rejects non-HTTPS public base URL", () => {
  assertConfigError(
    () => readNodePlatformRuntimeConfig({
      NODE_ENV: "production",
      PLATFORM_PUBLIC_BASE_URL: "http://platform.example.test",
      PLATFORM_ALLOWED_ORIGINS: allowedOrigin,
      PLATFORM_COOKIE_SECURE: "true",
    }),
    "invalid_public_base_url",
  );
});

test("production rejects public base URL query or fragment", () => {
  assertConfigError(
    () => readNodePlatformRuntimeConfig({
      NODE_ENV: "production",
      PLATFORM_PUBLIC_BASE_URL: "https://platform.example.test?token=raw-secret",
      PLATFORM_ALLOWED_ORIGINS: allowedOrigin,
      PLATFORM_COOKIE_SECURE: "true",
    }),
    "invalid_public_base_url",
  );
});

test("production rejects empty allowed origins", () => {
  assertConfigError(
    () => readNodePlatformRuntimeConfig({
      NODE_ENV: "production",
      PLATFORM_PUBLIC_BASE_URL: publicBaseUrl,
      PLATFORM_ALLOWED_ORIGINS: " ",
      PLATFORM_COOKIE_SECURE: "true",
    }),
    "missing_allowed_origins",
  );
});

test("production rejects non-HTTPS allowed origins", () => {
  assertConfigError(
    () => readNodePlatformRuntimeConfig({
      NODE_ENV: "production",
      PLATFORM_PUBLIC_BASE_URL: publicBaseUrl,
      PLATFORM_ALLOWED_ORIGINS: "http://platform.example.test",
      PLATFORM_COOKIE_SECURE: "true",
    }),
    "invalid_allowed_origin",
  );
});

test("config errors do not echo raw env values private URLs or secrets", () => {
  assertConfigError(
    () => readNodePlatformRuntimeConfig({
      NODE_ENV: "production",
      PLATFORM_PUBLIC_BASE_URL: publicBaseUrl,
      PLATFORM_ALLOWED_ORIGINS: syntheticPrivateUrl,
      PLATFORM_COOKIE_SECURE: "false-raw-secret",
    }),
    "invalid_cookie_secure",
  );
});

test("server factory does not listen until explicitly invoked", () => {
  const server = createNodePlatformHttpServer(createServerDependencies());

  try {
    assert.equal(server.listening, false);
  } finally {
    server.close();
  }
});

test("server factory delegates to the Node HTTP adapter for GET /healthz", async () => {
  const server = createNodePlatformHttpServer(createServerDependencies());
  const address = await listenOnEphemeralPort(server);

  try {
    const response = await fetch(`http://127.0.0.1:${address.port}/healthz`);
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(response.headers.get("content-type"), "application/json; charset=utf-8");
    assert.deepEqual(body, {
      outcome: "ok",
      service: "swooshz-platform",
    });
  } finally {
    await closeServer(server);
  }
});

test("server can close cleanly in tests", async () => {
  const server = createNodePlatformHttpServer(createServerDependencies());
  await listenOnEphemeralPort(server);
  await closeServer(server);

  assert.equal(server.listening, false);
});

test("server runtime import does not auto-listen", async () => {
  const source = await readFile("src/http/node-server.ts", "utf8");

  assert.doesNotMatch(source, /\.listen\s*\(/);
});

test("node:http imports stay only in Node adapter and server runtime modules", async () => {
  const sourceFiles = await listFiles("src");
  const allowed = new Set([
    "src/http/node-adapter.ts",
    "src/http/node-server.ts",
  ]);

  for (const filePath of sourceFiles) {
    const normalized = filePath.replaceAll("\\", "/");
    const contents = await readFile(filePath, "utf8");

    if (allowed.has(normalized)) {
      continue;
    }

    assert.doesNotMatch(contents, /node:http/);
  }
});

test("runtime modules do not import frontend SQAG provider SDK framework live DB or migrations", async () => {
  const files = [
    "src/http/runtime-config.ts",
    "src/http/node-server.ts",
  ];

  for (const filePath of files) {
    const contents = await readFile(filePath, "utf8");

    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:react|next|vite|express|fastify|hono)/i);
    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:sqag|clerk|auth0|supabase)/i);
    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:db|drizzle|pg|migrations?)/i);
    assert.doesNotMatch(contents, /src\/db|\.{1,2}\/db|\.{1,2}\/\.{1,2}\/db/i);
  }
});

function createServerDependencies() {
  return {
    repositories: createInMemoryPlatformRepositories(),
    now: () => now,
    cookie: { secure: false },
    originConfig: { allowedOrigins: ["http://127.0.0.1:3000"] },
    csrfTokenValidator: {
      async validate() {
        return { valid: false, reason: "not_configured" };
      },
    },
  };
}

function assertConfigError(fn, expectedCode) {
  assert.throws(
    fn,
    (error) => {
      assert.equal(error instanceof NodePlatformRuntimeConfigError, true);
      assert.equal(error.code, expectedCode);
      assert.equal(error.publicMessage, "Platform HTTP runtime config is invalid.");
      assert.doesNotMatch(error.message, /raw-secret|raw-session-token|postgresql:\/\/private-host/);
      assert.doesNotMatch(error.message, /private\.example\.test|\/path\?|token=/);
      assert.doesNotMatch(error.message, /PLATFORM_PUBLIC_BASE_URL=.*|PLATFORM_ALLOWED_ORIGINS=.*/);
      return true;
    },
  );
}

function listenOnEphemeralPort(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      const address = server.address();
      if (!address || typeof address === "string") {
        reject(new Error("Expected TCP server address."));
        return;
      }

      resolve(address);
    });
  });
}

function closeServer(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
        return;
      }

      resolve();
    });
  });
}

async function listFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const path = join(directory, entry.name);

    if (entry.isDirectory()) {
      files.push(...(await listFiles(path)));
    } else if (entry.isFile() && path.endsWith(".ts")) {
      files.push(path);
    }
  }

  return files;
}
