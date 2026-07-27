import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  RUNTIME_TABLE_GRANT_CONTRACT,
  RUNTIME_TABLE_GRANT_DIGEST,
  RuntimeGrantContractError,
  assertRuntimeTableGrantSet,
  runtimeTableGrantKey,
  validateRuntimeTableGrantContract,
} from "../dist/db/runtime-grant-contract.js";
import {
  assertProductionAdapterGrantEquality,
  extractProductionAdapterOperations,
  readCanonicalMigrationObjects,
} from "../scripts/runtime-grant-contract-validator.mjs";

const requiredUpdates = [
  "access_validation_grants",
  "app_entitlements",
  "app_launch_tokens",
  "auth_states",
];
const staleUpdates = [
  "csrf_tokens",
  "provider_identities",
  "users",
  "workspaces",
];

test("canonical runtime table-grant contract is a deterministic closed 39-record set", () => {
  assert.equal(RUNTIME_TABLE_GRANT_CONTRACT.length, 39);
  assert.match(RUNTIME_TABLE_GRANT_DIGEST, /^[a-f0-9]{64}$/);
  assert.equal(
    RUNTIME_TABLE_GRANT_DIGEST,
    createHash("sha256")
      .update(
        RUNTIME_TABLE_GRANT_CONTRACT.map(runtimeTableGrantKey).join("\n"),
        "utf8",
      )
      .digest("hex"),
  );
  assert.doesNotThrow(() =>
    validateRuntimeTableGrantContract(RUNTIME_TABLE_GRANT_CONTRACT),
  );

  const keys = RUNTIME_TABLE_GRANT_CONTRACT.map(runtimeTableGrantKey);
  assert.deepEqual(keys, [...keys].sort());
  assert.equal(new Set(keys).size, 39);

  for (const record of RUNTIME_TABLE_GRANT_CONTRACT) {
    assert.deepEqual(
      {
        objectClass: record.objectClass,
        schema: record.schema,
        authoritySource: record.authoritySource,
        grantOption: record.grantOption,
      },
      {
        objectClass: "table",
        schema: "public",
        authoritySource: "direct",
        grantOption: false,
      },
    );
    assert.match(record.objectName, /^[a-z_][a-z0-9_]*$/);
    assert.match(record.migrationFile, /^\d{4}_[a-z0-9_]+\.sql$/);
    assert.ok(record.operationSources.length > 0);
    assert.equal(Object.isFrozen(record), true);
    assert.equal(Object.isFrozen(record.operationSources), true);
  }
});

test("canonical correction contains the four required UPDATE records and no stale UPDATE records", () => {
  const updates = new Set(
    RUNTIME_TABLE_GRANT_CONTRACT
      .filter((record) => record.privilege === "UPDATE")
      .map((record) => record.objectName),
  );

  for (const tableName of requiredUpdates) {
    assert.equal(updates.has(tableName), true, tableName);
  }
  for (const tableName of staleUpdates) {
    assert.equal(updates.has(tableName), false, tableName);
  }
});

test("contract validation rejects duplicate, non-canonical, and invalid records", () => {
  const valid = RUNTIME_TABLE_GRANT_CONTRACT.map(cloneRecord);
  assert.throws(
    () =>
      validateRuntimeTableGrantContract([
        ...valid,
        cloneRecord(valid[0]),
      ]),
    contractError("runtime_grant_contract_duplicate"),
  );
  assert.throws(
    () =>
      validateRuntimeTableGrantContract([
        valid[1],
        valid[0],
        ...valid.slice(2),
      ]),
    contractError("runtime_grant_contract_order"),
  );
  assert.throws(
    () =>
      validateRuntimeTableGrantContract([
        { ...valid[0], privilege: "EXECUTE" },
        ...valid.slice(1),
      ]),
    contractError("runtime_grant_contract_schema"),
  );
  assert.throws(
    () =>
      validateRuntimeTableGrantContract([
        { ...valid[0], objectClass: "sequence" },
        ...valid.slice(1),
      ]),
    contractError("runtime_grant_contract_schema"),
  );
});

test("canonical migration provenance contains every contracted object", async () => {
  const migrationObjects = await readCanonicalMigrationObjects();
  assert.doesNotThrow(() =>
    validateRuntimeTableGrantContract(RUNTIME_TABLE_GRANT_CONTRACT, {
      migrationObjects,
    }),
  );

  const missing = new Map(migrationObjects);
  missing.delete(RUNTIME_TABLE_GRANT_CONTRACT[0].objectName);
  assert.throws(
    () =>
      validateRuntimeTableGrantContract(RUNTIME_TABLE_GRANT_CONTRACT, {
        migrationObjects: missing,
      }),
    contractError("runtime_grant_contract_migration"),
  );
});

test("production adapter operations exactly equal the canonical contract", async () => {
  const operations = await extractProductionAdapterOperations();
  assert.equal(operations.length, 39);
  assert.doesNotThrow(() =>
    assertProductionAdapterGrantEquality(
      RUNTIME_TABLE_GRANT_CONTRACT,
      operations,
    ),
  );
});

test("production adapter extraction detects an undeclared operation structurally", async () => {
  const path = "src/db/repositories.ts";
  const original = await readFile(path, "utf8");
  const operations = await extractProductionAdapterOperations({
    sourceOverrides: new Map([
      [
        path,
        `${original}
export function syntheticUndeclaredRuntimeOperation(db) {
  return db.update(users);
}
`,
      ],
    ]),
  });

  assert.throws(
    () =>
      assertProductionAdapterGrantEquality(
        RUNTIME_TABLE_GRANT_CONTRACT,
        operations,
      ),
    contractError("runtime_grant_adapter_extra"),
  );
});

test("adapter equality rejects contract authority unused by production operations", async () => {
  const operations = await extractProductionAdapterOperations();
  assert.throws(
    () =>
      assertProductionAdapterGrantEquality(
        RUNTIME_TABLE_GRANT_CONTRACT,
        operations.slice(1),
      ),
    contractError("runtime_grant_adapter_missing"),
  );
});

test("exact grant-set validation rejects every drift category", () => {
  const observed = RUNTIME_TABLE_GRANT_CONTRACT.map(observedRecord);
  assert.doesNotThrow(() => assertRuntimeTableGrantSet(observed));

  const cases = [
    [
      "missing required grant",
      observed.slice(1),
      {},
      "runtime_grant_set_missing",
    ],
    [
      "unexpected broader grant",
      [
        ...observed,
        {
          ...observed[0],
          objectName: "users",
          privilege: "UPDATE",
        },
      ],
      {},
      "runtime_grant_set_extra",
    ],
    [
      "correct privilege on wrong object",
      [
        { ...observed[0], objectName: "wrong_object" },
        ...observed.slice(1),
      ],
      {},
      "runtime_grant_set_mismatch",
    ],
    [
      "wrong privilege on correct object",
      [
        { ...observed[0], privilege: "TRIGGER" },
        ...observed.slice(1),
      ],
      {},
      "runtime_grant_set_mismatch",
    ],
    [
      "grant option drift",
      [
        { ...observed[0], grantOption: true },
        ...observed.slice(1),
      ],
      {},
      "runtime_grant_set_grant_option",
    ],
    [
      "inherited authority",
      [
        { ...observed[0], authoritySource: "inherited" },
        ...observed.slice(1),
      ],
      {},
      "runtime_grant_set_authority",
    ],
    [
      "membership-derived authority",
      observed,
      { membershipDerived: true },
      "runtime_grant_set_membership",
    ],
    [
      "ownership-derived authority",
      observed,
      { ownershipDerived: true },
      "runtime_grant_set_ownership",
    ],
  ];

  for (const [name, records, options, code] of cases) {
    assert.throws(
      () => assertRuntimeTableGrantSet(records, options),
      contractError(code),
      name,
    );
  }
});

function cloneRecord(record) {
  return {
    ...record,
    operationSources: [...record.operationSources],
  };
}

function observedRecord(record) {
  return {
    objectClass: record.objectClass,
    schema: record.schema,
    objectName: record.objectName,
    privilege: record.privilege,
    authoritySource: record.authoritySource,
    grantOption: record.grantOption,
  };
}

function contractError(code) {
  return (error) => {
    assert.equal(error instanceof RuntimeGrantContractError, true);
    assert.equal(error.code, code);
    assert.equal(error.message, "Runtime grant contract validation failed.");
    assert.doesNotMatch(
      String(error),
      /acl|oid|postgres(?:ql)?:\/\/|password|hostname/i,
    );
    return true;
  };
}
