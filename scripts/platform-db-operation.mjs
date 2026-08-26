#!/usr/bin/env node

import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  JOURNAL_PREFIX_DOMAIN_SEPARATOR,
  PRESTATE_DOMAIN_SEPARATOR,
  assertRevisionBinding,
  canonicalDigest,
  captureNormalizedPrestate,
  createDurablePlan,
  computeContractDigest,
  computeTargetBindingDigest,
  executeDurablePlan,
  loadCanonicalMigrationJournal,
  projectReceipt,
  serializeReceipt,
} from "../dist/db/durable-operations.js";
import {
  assertMigrationExecutionAllowed,
  createDatabaseClient,
} from "../dist/db/client.js";

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const migrationsFolder = path.join(rootDir, "drizzle", "migrations");

function parseArguments(argv) {
  const result = { expectedGitSha: null, operation: "migration" };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--expected-git-sha") {
      result.expectedGitSha = argv[++index] ?? null;
    } else if (argument === "--operation") {
      result.operation = argv[++index] ?? null;
    } else {
      throw new Error("unsupported arguments");
    }
  }
  if (!result.expectedGitSha || result.operation !== "migration") {
    throw new Error("required arguments missing");
  }
  return result;
}

function databaseNameFromConfig(config) {
  try {
    const pathname = new URL(config.databaseUrl).pathname.replace(/^\//u, "");
    if (!/^[a-z_][a-z0-9_$]{0,62}$/u.test(pathname)) throw new Error();
    return pathname;
  } catch {
    throw new Error("target binding unavailable");
  }
}

function targetBinding(client, config) {
  return {
    version: "target-binding-v1",
    logicalDatabaseName: databaseNameFromConfig(config),
    expectedCurrentUser: "platform_migrator",
    expectedSessionUser: "platform_migrator",
    expectedPostgresMajor: 17,
    connect: () => client.pool.connect(),
  };
}

function migrationOperations(journal, appliedRows) {
  const operations = [];
  let prefix = appliedRows.slice();
  for (const entry of journal.entries.slice(appliedRows.length)) {
    const next = [...prefix, { when: entry.when, sql_sha256: entry.sql_sha256 }];
    operations.push({
      kind: "migration",
      tag: entry.tag,
      journal_index: entry.idx,
      when: entry.when,
      sql_sha256: entry.sql_sha256,
      expected_applied_prefix_digest: canonicalDigest(JOURNAL_PREFIX_DOMAIN_SEPARATOR, prefix),
      expected_post_journal_digest: canonicalDigest(JOURNAL_PREFIX_DOMAIN_SEPARATOR, next),
    });
    prefix = next;
  }
  return operations;
}

async function run() {
  const args = parseArguments(process.argv.slice(2));
  const gitSha = await assertRevisionBinding({ rootDir, expectedGitSha: args.expectedGitSha });
  const config = assertMigrationExecutionAllowed(process.env);
  const client = createDatabaseClient(config);
  try {
    const binding = targetBinding(client, config);
    const journal = await loadCanonicalMigrationJournal(rootDir);
    const contractDigest = await computeContractDigest(rootDir);
    const captured = await captureNormalizedPrestate(binding, journal);
    const operations = migrationOperations(journal, captured.prestate.migration_journal.applied_rows);
    const plan = createDurablePlan({
      expected_git_sha: gitSha,
      contract_digest: contractDigest,
      target_binding_digest: computeTargetBindingDigest(binding),
      prestate_digest: canonicalDigest(PRESTATE_DOMAIN_SEPARATOR, captured.prestate),
      operation_kind: "migration",
      operations,
    });
    const receipt = await executeDurablePlan({
      plan,
      binding,
      expectedPrestate: captured.prestate,
      expectedContractDigest: contractDigest,
      migrationsFolder,
      journal,
      rootDir,
    });
    process.stdout.write(`${serializeReceipt(projectReceipt(receipt))}\n`);
    if (receipt.outcome !== "PASS") process.exitCode = 1;
  } finally {
    await client.pool.end();
  }
}

run().catch(() => {
  process.stderr.write("Platform database operation failed.\n");
  process.exitCode = 1;
});
