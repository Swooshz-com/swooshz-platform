#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { verifyPlatformDbOperationBuild } from "./platform-db-operation-build.mjs";

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function parseArguments(argv) {
  const parsed = { expectedGitSha: null, operation: null };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--expected-git-sha") parsed.expectedGitSha = argv[++index] ?? null;
    else if (argument === "--operation") parsed.operation = argv[++index] ?? null;
    else throw new Error("unsupported arguments");
  }
  if (!/^[0-9a-f]{40}$/u.test(parsed.expectedGitSha ?? "") || !["observe", "migration"].includes(parsed.operation)) {
    throw new Error("required arguments missing");
  }
  return parsed;
}

export async function runPlatformDbOperation(input) {
  if (!input?.broker || (input.operation === "migration" && !input.attemptStore)) {
    throw new Error("BROKER_ADAPTER_UNAVAILABLE");
  }
  if (process.env.DATABASE_OPERATOR_URL?.trim()) throw new Error("direct_database_credential_prohibited");
  const verifiedBuild = await verifyPlatformDbOperationBuild({ rootDir, expectedGitSha: input.expectedGitSha });
  const brokered = await import(pathToFileURL(verifiedBuild.entrypoints.brokeredMigration).href);
  const durable = await import(pathToFileURL(verifiedBuild.entrypoints.durableOperations).href);
  const observationBundle = brokered.compileBrokerObservationBundle(input.contract);
  if (input.operation === "observe") {
    const rawEvidence = await input.broker.observe(
      brokered.canonicalSerializeBrokerBundle(observationBundle),
      observationBundle.bundle_digest,
    );
    const evidence = brokered.normalizeBrokerObservationEvidence(rawEvidence, observationBundle);
    return { operation: "observe", observation_bundle_digest: observationBundle.bundle_digest, evidence_digest: evidence.evidence_digest };
  }
  const migrationSql = await readFile(path.join(rootDir, "drizzle", "migrations", "0010_admin_operator_viewer_role_collapse.sql"), "utf8");
  return durable.executeBrokeredMigrationPlan({
    observationBundle,
    prestateDigest: input.prestateDigest,
    planDigest: input.planDigest,
    migrationSql,
    broker: input.broker,
    attemptStore: input.attemptStore,
  });
}

async function main() {
  const args = parseArguments(process.argv.slice(2));
  await verifyPlatformDbOperationBuild({ rootDir, expectedGitSha: args.expectedGitSha });
  throw new Error("BROKER_ADAPTER_UNAVAILABLE");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(() => {
    process.stderr.write("Platform database operation failed. support_ref=platform_db_broker_unavailable\n");
    process.exitCode = 1;
  });
}
