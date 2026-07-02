import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  AppLaunchTokenCryptoConfigError,
  createHmacAppLaunchTokenHasher,
  createSecureAppLaunchTokenFactory,
  createSecureAppLaunchTokenIdFactory,
} from "../dist/index.js";

const strongSecret = "synthetic_app_launch_hash_secret_32_chars_min";
const alternateSecret = "alternate_app_launch_hash_secret_32_chars_min";
const rawLaunchToken = "synthetic-raw-launch-token-reference";

test("secure app launch token factory returns an opaque base64url token", async () => {
  const factory = createSecureAppLaunchTokenFactory();

  const token = await factory.createToken();

  assert.equal(typeof token, "string");
  assert.ok(token.length >= 43);
  assert.match(token, /^[A-Za-z0-9_-]+$/);
});

test("app launch token HMAC hasher is stable and differentiates token and secret values", async () => {
  const hasher = createHmacAppLaunchTokenHasher({ secret: strongSecret });
  const alternateHasher = createHmacAppLaunchTokenHasher({ secret: alternateSecret });

  const first = await hasher.hashToken(rawLaunchToken);
  const second = await hasher.hashToken(rawLaunchToken);
  const differentToken = await hasher.hashToken(`${rawLaunchToken}-different`);
  const differentSecret = await alternateHasher.hashToken(rawLaunchToken);

  assert.equal(first, second);
  assert.notEqual(first, differentToken);
  assert.notEqual(first, differentSecret);
  assert.match(first, /^app-launch:v1:hmac-sha256:[A-Za-z0-9_-]+$/);
  assert.doesNotMatch(first, new RegExp(rawLaunchToken));
  assert.doesNotMatch(first, new RegExp(strongSecret));
});

test("app launch token crypto rejects weak secret and blank token safely", async () => {
  for (const secret of ["", "   ", "short-secret"]) {
    assert.throws(
      () => createHmacAppLaunchTokenHasher({ secret }),
      assertPrivacySafeCryptoError("invalid_secret"),
    );
  }

  const hasher = createHmacAppLaunchTokenHasher({ secret: strongSecret });
  await assert.rejects(
    () => hasher.hashToken(""),
    assertPrivacySafeCryptoError("invalid_token"),
  );
});

test("secure app launch token id factory creates non-secret ids", () => {
  const idFactory = createSecureAppLaunchTokenIdFactory();

  const id = idFactory.createId();

  assert.match(id, /^app_launch_[A-Za-z0-9_-]+$/);
  assert.doesNotMatch(id, new RegExp(rawLaunchToken));
  assert.doesNotMatch(id, new RegExp(strongSecret));
});

test("app launch crypto imports stay only in dedicated crypto adapter modules", async () => {
  const sourceFiles = await listFiles("src");
  const allowed = new Set([
    "src/auth/auth-state-crypto.ts",
    "src/auth/generic-oidc-jwks-verifier.ts",
    "src/auth/platform-identity-crypto.ts",
    "src/http/csrf-token-crypto.ts",
    "src/platform/app-launch-token-crypto.ts",
    "src/platform/workspace-admin-id-crypto.ts",
  ]);

  for (const filePath of sourceFiles) {
    const normalized = filePath.replaceAll("\\", "/");
    const contents = await readFile(filePath, "utf8");

    if (allowed.has(normalized)) {
      continue;
    }

    assert.doesNotMatch(contents, /node:crypto|from\s+["']crypto["']/);
  }
});

function assertPrivacySafeCryptoError(expectedCode) {
  return (error) => {
    assert.equal(error instanceof AppLaunchTokenCryptoConfigError, true);
    assert.equal(error.code, expectedCode);
    assert.equal(error.publicMessage, "App launch token crypto configuration is invalid.");
    const serialized = JSON.stringify(error) + String(error.message ?? "");
    assert.doesNotMatch(serialized, new RegExp(strongSecret));
    assert.doesNotMatch(serialized, new RegExp(rawLaunchToken));
    assert.doesNotMatch(serialized, /postgresql:\/\/private-host|storage exploded/i);
    return true;
  };
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
