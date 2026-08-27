#!/usr/bin/env node

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, readFile, writeFile } from "node:fs/promises";
import { dirname, extname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export const OPERATOR_BUILD_MANIFEST_VERSION = 1;
export const OPERATOR_BUILD_MANIFEST_RELATIVE_PATH = "dist/db/platform-db-operation-build.json";

const OPERATOR_ENTRYPOINTS = Object.freeze({
  durableOperations: "db/durable-operations.js",
  databaseClient: "db/client.js",
});
const HEX40 = /^[0-9a-f]{40}$/u;
const HEX64 = /^[0-9a-f]{64}$/u;

function verificationError() {
  return new Error("Platform operator executable build is not verified.");
}

function assertGitSha(value) {
  if (typeof value !== "string" || !HEX40.test(value)) throw verificationError();
  return value;
}

async function gitOutput(rootDir, args) {
  try {
    return (await execFileAsync("git", args, {
      cwd: rootDir,
      windowsHide: true,
      maxBuffer: 32 * 1024,
    })).stdout.trim().toLowerCase();
  } catch {
    throw verificationError();
  }
}

async function readSourceRevision(rootDir, expectedGitSha, requireClean) {
  const revision = await gitOutput(rootDir, ["rev-parse", "--verify", "HEAD"]);
  if (!HEX40.test(revision)) throw verificationError();
  if (expectedGitSha && revision !== assertGitSha(expectedGitSha)) throw verificationError();
  if (requireClean) {
    const status = await gitOutput(rootDir, ["status", "--porcelain=v1", "--untracked-files=all"]);
    if (status) throw verificationError();
  }
  return revision;
}

function normalizeDistRelativePath(value) {
  return value.split(sep).join("/");
}

function assertDistRelativePath(value) {
  if (
    typeof value !== "string" ||
    !value ||
    isAbsolute(value) ||
    value.includes("\\") ||
    value.split("/").some((part) => !part || part === "." || part === "..") ||
    ![".js", ".json"].includes(extname(value))
  ) {
    throw verificationError();
  }
  return value;
}

function absoluteDistPath(distRoot, relativePath) {
  const normalized = assertDistRelativePath(relativePath);
  const absolute = resolve(distRoot, normalized);
  const outside = relative(distRoot, absolute);
  if (!outside || outside === ".." || outside.startsWith(`..${sep}`) || isAbsolute(outside)) {
    throw verificationError();
  }
  return absolute;
}

async function assertRegularFile(filePath) {
  try {
    const details = await lstat(filePath);
    if (!details.isFile() || details.isSymbolicLink()) throw verificationError();
  } catch (error) {
    if (error instanceof Error && error.message === "Platform operator executable build is not verified.") throw error;
    throw verificationError();
  }
}

function extractModuleSpecifiers(source) {
  const specifiers = new Set();
  const patterns = [
    /\b(?:import|export)\s+[^"'\n;]*?\sfrom\s*["']([^"']+)["']/gu,
    /\bimport\s*["']([^"']+)["']/gu,
    /\bimport\s*\(\s*["']([^"']+)["']\s*\)/gu,
  ];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) specifiers.add(match[1]);
  }
  return specifiers;
}

async function resolveLocalModule(distRoot, currentRelativePath, specifier) {
  const base = resolve(distRoot, dirname(currentRelativePath), specifier);
  const candidates = extname(base)
    ? [base]
    : [base + ".js", base + ".json", join(base, "index.js")];
  for (const candidate of candidates) {
    try {
      await assertRegularFile(candidate);
      const candidateRelative = normalizeDistRelativePath(relative(distRoot, candidate));
      absoluteDistPath(distRoot, candidateRelative);
      return candidateRelative;
    } catch (error) {
      if (error instanceof Error && error.message === "Platform operator executable build is not verified.") {
        const candidateExists = await lstat(candidate).then(() => true).catch(() => false);
        if (candidateExists) throw error;
      }
    }
  }
  throw verificationError();
}

async function collectModulePaths(distRoot) {
  const pending = [...Object.values(OPERATOR_ENTRYPOINTS)];
  const visited = new Set();
  while (pending.length > 0) {
    const currentRelativePath = assertDistRelativePath(pending.shift());
    if (visited.has(currentRelativePath)) continue;
    const currentPath = absoluteDistPath(distRoot, currentRelativePath);
    await assertRegularFile(currentPath);
    const source = await readFile(currentPath, "utf8");
    visited.add(currentRelativePath);
    for (const specifier of extractModuleSpecifiers(source)) {
      if (specifier.startsWith(".")) {
        pending.push(await resolveLocalModule(distRoot, currentRelativePath, specifier));
      }
    }
  }
  return [...visited].sort();
}

async function digestFile(distRoot, relativePath) {
  const filePath = absoluteDistPath(distRoot, relativePath);
  await assertRegularFile(filePath);
  const contents = await readFile(filePath);
  return {
    path: relativePath,
    bytes: contents.byteLength,
    sha256: createHash("sha256").update(contents).digest("hex"),
  };
}

async function collectModuleManifest(distRoot) {
  const paths = await collectModulePaths(distRoot);
  return Promise.all(paths.map((relativePath) => digestFile(distRoot, relativePath)));
}

function assertModuleRecord(record) {
  if (
    !record ||
    typeof record !== "object" ||
    Array.isArray(record) ||
    assertDistRelativePath(record.path) !== record.path ||
    !Number.isSafeInteger(record.bytes) ||
    record.bytes < 0 ||
    typeof record.sha256 !== "string" ||
    !HEX64.test(record.sha256)
  ) {
    throw verificationError();
  }
}

function assertManifestShape(manifest, revision) {
  if (
    !manifest ||
    typeof manifest !== "object" ||
    Array.isArray(manifest) ||
    manifest.version !== OPERATOR_BUILD_MANIFEST_VERSION ||
    manifest.source_git_sha !== revision ||
    !manifest.entrypoints ||
    typeof manifest.entrypoints !== "object" ||
    Array.isArray(manifest.entrypoints) ||
    manifest.entrypoints.durableOperations !== OPERATOR_ENTRYPOINTS.durableOperations ||
    manifest.entrypoints.databaseClient !== OPERATOR_ENTRYPOINTS.databaseClient ||
    !Array.isArray(manifest.modules)
  ) {
    throw verificationError();
  }
  const paths = new Set();
  for (const record of manifest.modules) {
    assertModuleRecord(record);
    if (paths.has(record.path)) throw verificationError();
    paths.add(record.path);
  }
}

function manifestsEqual(expected, actual) {
  return expected.length === actual.length && expected.every((record, index) => {
    const observed = actual[index];
    return record.path === observed.path && record.bytes === observed.bytes && record.sha256 === observed.sha256;
  });
}

export async function writePlatformDbOperationBuildManifest({ rootDir }) {
  const resolvedRootDir = resolve(rootDir);
  const revision = await readSourceRevision(resolvedRootDir);
  const distRoot = resolve(resolvedRootDir, "dist");
  const modules = await collectModuleManifest(distRoot);
  const manifest = {
    version: OPERATOR_BUILD_MANIFEST_VERSION,
    source_git_sha: revision,
    entrypoints: { ...OPERATOR_ENTRYPOINTS },
    modules,
  };
  await writeFile(resolve(resolvedRootDir, OPERATOR_BUILD_MANIFEST_RELATIVE_PATH), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  return manifest;
}

export async function verifyPlatformDbOperationBuild({ rootDir, expectedGitSha }) {
  const resolvedRootDir = resolve(rootDir);
  const expected = assertGitSha(expectedGitSha);
  const revision = await readSourceRevision(resolvedRootDir, expected, true);
  const manifestPath = resolve(resolvedRootDir, OPERATOR_BUILD_MANIFEST_RELATIVE_PATH);
  let manifest;
  try {
    manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  } catch {
    throw verificationError();
  }
  assertManifestShape(manifest, revision);
  const actualModules = await collectModuleManifest(resolve(resolvedRootDir, "dist"));
  if (!manifestsEqual(manifest.modules, actualModules)) throw verificationError();
  await readSourceRevision(resolvedRootDir, expected, true);
  return {
    sourceGitSha: revision,
    manifestPath,
    entrypoints: {
      durableOperations: absoluteDistPath(resolve(resolvedRootDir, "dist"), manifest.entrypoints.durableOperations),
      databaseClient: absoluteDistPath(resolve(resolvedRootDir, "dist"), manifest.entrypoints.databaseClient),
    },
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  if (process.argv[2] !== "--write-manifest") {
    process.stderr.write("Platform operator build manifest command failed.\n");
    process.exitCode = 1;
  } else {
    writePlatformDbOperationBuildManifest({ rootDir }).catch(() => {
      process.stderr.write("Platform operator build manifest command failed.\n");
      process.exitCode = 1;
    });
  }
}
