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
  inspectProductionDatabaseAccessInventory,
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
    "9474972215869ec9b194f537c3b2400d8701aa8f00494bcfc0ede849dd94bf65",
  );
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
  assert.throws(
    () =>
      validateRuntimeTableGrantContract([
        {
          ...valid[0],
          operationSources: [
            valid[0].operationSources[0],
            valid[0].operationSources[0],
          ],
        },
        ...valid.slice(1),
      ]),
    contractError("runtime_grant_source_duplicate"),
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
  const declaredSourceCount = RUNTIME_TABLE_GRANT_CONTRACT.reduce(
    (count, record) => count + record.operationSources.length,
    0,
  );
  assert.equal(operations.length, declaredSourceCount);
  assert.doesNotThrow(() =>
    assertProductionAdapterGrantEquality(
      RUNTIME_TABLE_GRANT_CONTRACT,
      operations,
    ),
  );
});

test("production database access inventory is recursive, explicit, and closed", async () => {
  const inventory = await inspectProductionDatabaseAccessInventory();

  assert.deepEqual(inventory, [
    ["src/db/access-validation-grant-repository.ts", "runtime_data_adapter"],
    ["src/db/app-launch-token-repository.ts", "runtime_data_adapter"],
    ["src/db/auth-state-repository.ts", "runtime_data_adapter"],
    ["src/db/client.ts", "operational_control_plane"],
    ["src/db/csrf-token-repository.ts", "runtime_data_adapter"],
    ["src/db/readiness.ts", "operational_control_plane"],
    ["src/db/repositories.ts", "runtime_data_adapter"],
    ["src/db/runtime-posture.ts", "operational_control_plane"],
    ["src/db/schema.ts", "runtime_data_adapter"],
    ["src/runtime/node-bootstrap.ts", "operational_control_plane"],
    ["src/runtime/platform-runtime-dependencies.ts", "runtime_data_adapter"],
  ]);
});

const nodeServerPath = "src/http/node-server.ts";
const builtInImportAuthorityError =
  "runtime_grant_inventory_unclassified";
const builtInSourceShapeError =
  "runtime_grant_inventory_unclassified";

const builtInImportRejectionCases = [
  [
    "a neutral new source importing node:http request",
    () =>
      new Map([
        [
          "src/platform/transport.ts",
          `import { request } from "node:http";
export function relay(target) {
  return request(target);
}`,
        ],
      ]),
    builtInImportAuthorityError,
  ],
  [
    "a neutral internal wrapper around an unapproved network source",
    () =>
      new Map([
        [
          "src/platform/transport-core.ts",
          `import { request as send } from "node:http";
export function relay(target) {
  return send(target);
}`,
        ],
        [
          "src/platform/transport-wrapper.ts",
          `import { relay } from "./transport-core.js";
export function forward(target) {
  return relay(target);
}`,
        ],
      ]),
    builtInImportAuthorityError,
  ],
  [
    "a renamed local network binding",
    (nodeServer) =>
      new Map([
        [
          nodeServerPath,
          nodeServer
            .replace(
              'import { createServer, type Server } from "node:http";',
              'import { createServer as openTransport, type Server } from "node:http";',
            )
            .replace("return createServer(", "return openTransport("),
        ],
      ]),
    builtInImportAuthorityError,
  ],
  [
    "an additional imported network binding",
    (nodeServer) =>
      new Map([
        [
          nodeServerPath,
          nodeServer.replace(
            'import { createServer, type Server } from "node:http";',
            'import { createServer, request as send, type Server } from "node:http";',
          ),
        ],
      ]),
    builtInImportAuthorityError,
  ],
  [
    "a namespace network import",
    (nodeServer) =>
      new Map([
        [
          nodeServerPath,
          nodeServer
            .replace(
              'import { createServer, type Server } from "node:http";',
              'import * as transport from "node:http";\nimport type { Server } from "node:http";',
            )
            .replace("return createServer(", "return transport.createServer("),
        ],
      ]),
    builtInImportAuthorityError,
  ],
  [
    "a default network import",
    (nodeServer) =>
      new Map([
        [
          nodeServerPath,
          nodeServer
            .replace(
              'import { createServer, type Server } from "node:http";',
              'import transport from "node:http";\nimport type { Server } from "node:http";',
            )
            .replace("return createServer(", "return transport.createServer("),
        ],
      ]),
    builtInImportAuthorityError,
  ],
  [
    "a side-effect network import",
    () =>
      new Map([
        [
          "src/platform/transport-side-effect.ts",
          `import "node:http";
export const transportMarker = true;`,
        ],
      ]),
    builtInImportAuthorityError,
  ],
  [
    "an approved network binding from the wrong source path",
    () =>
      new Map([
        [
          "src/platform/transport-server.ts",
          `import { createServer } from "node:http";
export function openTransport(handler) {
  return createServer(handler);
}`,
        ],
      ]),
    builtInImportAuthorityError,
  ],
  [
    "a re-export of an approved network binding",
    () =>
      new Map([
        [
          "src/platform/transport-export.ts",
          `export { createServer } from "node:http";`,
        ],
      ]),
    builtInImportAuthorityError,
  ],
  [
    "network source API-shape drift after an approved import",
    (nodeServer) =>
      new Map([
        [
          nodeServerPath,
          `${nodeServer}
export const networkAuthorityDrift = true;
`,
        ],
      ]),
    builtInSourceShapeError,
  ],
  [
    "an undeclared Node built-in",
    () =>
      new Map([
        [
          "src/platform/transport-net.ts",
          `import { connect as openTransport } from "node:net";
export function relay(target) {
  return openTransport(target);
}`,
        ],
      ]),
    builtInImportAuthorityError,
  ],
  [
    "an undeclared network-capable built-in subpath",
    () =>
      new Map([
        [
          "src/platform/transport-subpath.ts",
          `import { request as openTransport } from "node:http/promises";
export function relay(target) {
  return openTransport(target);
}`,
        ],
      ]),
    builtInImportAuthorityError,
  ],
];

for (const [name, sourceOverrides, expectedCode] of builtInImportRejectionCases) {
  test(`built-in import authority rejects ${name}`, async () => {
    const nodeServer = await readFile(nodeServerPath, "utf8");
    await assert.rejects(
      () =>
        inspectProductionDatabaseAccessInventory({
          sourceOverrides: sourceOverrides(nodeServer),
        }),
      contractError(expectedCode),
    );
  });
}

test("non-network built-in authority is also exact by source and binding", async () => {
  const cryptoPath = "src/auth/platform-identity-crypto.ts";
  const cryptoSource = await readFile(cryptoPath, "utf8");
  const assetPath = "src/http/public-site-assets.ts";
  const assetSource = await readFile(assetPath, "utf8");
  const cases = [
    [
      "crypto binding from the wrong source",
      new Map([
        [
          "src/platform/crypto-control.ts",
          `import { randomBytes } from "node:crypto";
export function createValue() {
  return randomBytes(16);
}`,
        ],
      ]),
    ],
    [
      "crypto alias from the approved source",
      new Map([
        [
          cryptoPath,
          cryptoSource
            .replace(
              'import { randomBytes } from "node:crypto";',
              'import { randomBytes as createValue } from "node:crypto";',
            )
            .replaceAll("randomBytes(", "createValue("),
        ],
      ]),
    ],
    [
      "filesystem binding from the wrong source",
      new Map([
        [
          "src/platform/file-control.ts",
          `import { readFile } from "node:fs/promises";
export function load(path) {
  return readFile(path);
}`,
        ],
      ]),
    ],
    [
      "filesystem alias from the approved source",
      new Map([
        [
          assetPath,
          assetSource
            .replace(
              'import { readFile } from "node:fs/promises";',
              'import { readFile as loadAsset } from "node:fs/promises";',
            )
            .replaceAll("readFile(", "loadAsset("),
        ],
      ]),
    ],
  ];

  for (const [name, sourceOverrides] of cases) {
    await assert.rejects(
      () =>
        inspectProductionDatabaseAccessInventory({
          sourceOverrides,
        }),
      contractError(builtInImportAuthorityError),
      name,
    );
  }
});

test("exact approved built-in imports preserve semantic formatting controls", async () => {
  const baseline = await inspectProductionDatabaseAccessInventory();
  assert.equal(baseline.length, 11);

  const cryptoPath = "src/auth/platform-identity-crypto.ts";
  const cryptoSource = await readFile(cryptoPath, "utf8");
  const assetPath = "src/http/public-site-assets.ts";
  const assetSource = await readFile(assetPath, "utf8");
  const nodeServer = await readFile(nodeServerPath, "utf8");
  const approvedOverrides = [
    new Map([[cryptoPath, `// approved cryptographic capability\n${cryptoSource}`]]),
    new Map([[assetPath, `// approved filesystem capability\n${assetSource}`]]),
    new Map([
      [
        nodeServerPath,
        `/* approved network capability */\n${nodeServer}`.replace(
          "return createServer(",
          "return createServer  (",
        ),
      ],
    ]),
    new Map([[nodeServerPath, nodeServer.replace(/\r\n?/gu, "\n")]]),
    new Map([
      [
        nodeServerPath,
        nodeServer.replace(/\r\n?/gu, "\n").replace(/\n/gu, "\r\n"),
      ],
    ]),
  ];

  for (const sourceOverrides of approvedOverrides) {
    const inventory = await inspectProductionDatabaseAccessInventory({
      sourceOverrides,
    });
    assert.equal(inventory.length, 11);
  }
});

test("dynamic runtime built-in loading forms remain prohibited", async () => {
  const cases = [
    `export async function load() { return import("node:http"); }`,
    `export function load() { return require("node:http"); }`,
    `import transport = require("node:http"); export const load = transport;`,
    `export function load() { return eval("1"); }`,
    `export function load() { return Function("return 1"); }`,
    `export function load() { return new Function("return 1"); }`,
    `export function load() { return process.getBuiltinModule("http"); }`,
  ];

  for (const [index, source] of cases.entries()) {
    await assert.rejects(
      () =>
        inspectProductionDatabaseAccessInventory({
          sourceOverrides: new Map([
            [`src/platform/dynamic-transport-${index}.ts`, source],
          ]),
        }),
      contractError("runtime_grant_inventory_unclassified"),
    );
  }
});

test("production dependency and import admission is mechanically closed", async () => {
  const unapprovedExternalCases = [
    [
      "unknown constructor and method",
      `import { Archive } from "unknown-database-package";
const store = new Archive({});
export function modifyUser() {
  return store.persistTable("users");
}`,
    ],
    [
      "neutral store with updateTable",
      `import { Kysely } from "unknown-database-package";
const store = new Kysely({});
export function modifyUser() {
  return store.updateTable("users").set({ status: "active" }).execute();
}`,
    ],
    [
      "unknown query-builder vocabulary",
      `import { DataEngine } from "unknown-database-package";
const store = new DataEngine({});
export function modifyUser() {
  return store.mutateRows("users", { status: "active" });
}`,
    ],
    [
      "namespace import",
      `import * as storage from "unknown-database-package";
const store = new storage.Engine({});
export function modifyUser() {
  return store.persistRows("users");
}`,
    ],
    [
      "default import",
      `import Storage from "unknown-database-package";
const store = new Storage({});
export function modifyUser() {
  return store.persistRows("users");
}`,
    ],
    [
      "dynamic import",
      `export async function modifyUser() {
  const storage = await import("unknown-database-package");
  const store = new storage.Engine({});
  return store.persistRows("users");
}`,
    ],
    [
      "approved database package under neutral aliases",
      `import { Pool as StorageEngine } from "pg";
const store = new StorageEngine({});
export function modifyUser() {
  return store.persistRows("users");
}`,
    ],
  ];

  for (const [name, source] of unapprovedExternalCases) {
    await assert.rejects(
      () =>
        inspectProductionDatabaseAccessInventory({
          sourceOverrides: new Map([
            ["src/platform/unknown-storage.ts", source],
          ]),
        }),
      contractError("runtime_grant_inventory_unclassified"),
      name,
    );
  }

  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/storage-bridge.ts",
            `import { createDatabasePool } from "../db/client.js";
export function openStorage(configuration) {
  const store = createDatabasePool(configuration);
  return store.persistRows("users");
}`,
          ],
        ]),
      }),
    contractError("runtime_grant_inventory_unclassified"),
    "neutral internal wrapper around an approved database client",
  );

  const nodeBootstrapPath = "src/runtime/node-bootstrap.ts";
  const nodeBootstrap = await readFile(nodeBootstrapPath, "utf8");
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/neutral-storage-wrapper.ts",
            `export function persistRows(store) {
  return store.persistRows("users");
}`,
          ],
          [
            nodeBootstrapPath,
            `import { persistRows } from "../platform/neutral-storage-wrapper.js";
${nodeBootstrap}
export function unsupportedNeutralWrapper(databaseClient) {
  return persistRows(databaseClient);
}`,
          ],
        ]),
      }),
    contractError("runtime_grant_inventory_unclassified"),
    "classified database module importing a neutral wrapper",
  );

  const packageManifest = JSON.parse(
    await readFile("package.json", "utf8"),
  );
  const packageLock = JSON.parse(
    await readFile("package-lock.json", "utf8"),
  );
  packageManifest.dependencies["unknown-runtime-package"] = "1.0.0";
  packageLock.packages[""].dependencies["unknown-runtime-package"] =
    "1.0.0";
  packageLock.packages["node_modules/unknown-runtime-package"] = {
    version: "1.0.0",
  };
  const dependencyCases = [
    [
      "package and lockfile dependency",
      new Map([
        ["package.json", JSON.stringify(packageManifest)],
        ["package-lock.json", JSON.stringify(packageLock)],
      ]),
    ],
    [
      "package-only dependency",
      new Map([
        ["package.json", JSON.stringify(packageManifest)],
      ]),
    ],
    [
      "lockfile-only dependency",
      new Map([
        ["package-lock.json", JSON.stringify(packageLock)],
      ]),
    ],
  ];
  for (const [name, sourceOverrides] of dependencyCases) {
    await assert.rejects(
      () =>
        inspectProductionDatabaseAccessInventory({
          sourceOverrides,
        }),
      contractError("runtime_grant_inventory_unclassified"),
      `${name} without recognizable database syntax`,
    );
  }

  const clientPath = "src/db/client.ts";
  const clientSource = await readFile(clientPath, "utf8");
  const newlineNormalizedInventory =
    await inspectProductionDatabaseAccessInventory({
      sourceOverrides: new Map([
        [
          clientPath,
          clientSource.replace(/\r\n?/gu, "\n"),
        ],
      ]),
    });
  assert.equal(newlineNormalizedInventory.length, 11);

  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            clientPath,
            clientSource.replace(
              'import { Pool } from "pg";',
              'import { Client, Pool } from "pg";',
            ),
          ],
        ]),
      }),
    contractError("runtime_grant_inventory_unclassified"),
    "new constructor from an approved database package",
  );

  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            clientPath,
            `${clientSource}
export function unsupportedApprovedClientShape(store) {
  return store.persistRows();
}
`,
          ],
        ]),
      }),
    contractError("runtime_grant_inventory_unclassified"),
    "new API shape inside an approved database module",
  );

  const runtimeLockDrift = JSON.parse(
    await readFile("package-lock.json", "utf8"),
  );
  runtimeLockDrift.packages["node_modules/pg"].integrity += "-drift";
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["package-lock.json", JSON.stringify(runtimeLockDrift)],
        ]),
      }),
    contractError("runtime_grant_inventory_unclassified"),
    "runtime lock closure drift",
  );

  const cryptoPath = "src/auth/platform-identity-crypto.ts";
  const cryptoSource = await readFile(cryptoPath, "utf8");
  const inventory = await inspectProductionDatabaseAccessInventory({
    sourceOverrides: new Map([
      [
        cryptoPath,
        `// approved non-network capability control
${cryptoSource}`,
      ],
    ]),
  });
  assert.equal(inventory.length, 11);

  const operations = await extractProductionAdapterOperations();
  assert.equal(operations.length, 59);
  assert.doesNotThrow(() =>
    assertProductionAdapterGrantEquality(
      RUNTIME_TABLE_GRANT_CONTRACT,
      operations,
    ),
  );
});

test("database source authority rejects an undeclared operation before equality", async () => {
  const path = "src/db/repositories.ts";
  const original = await readFile(path, "utf8");
  await assert.rejects(
    () =>
      extractProductionAdapterOperations({
        sourceOverrides: new Map([
          [
            path,
            original.replace(
              "async findById(id) {",
              `async syntheticUndeclaredRuntimeOperation() {
        return db.update(users);
      },
      async findById(id) {`,
            ),
          ],
        ]),
      }),
    contractError("runtime_grant_inventory_unclassified"),
  );
});

test("exact operation-source equality rejects every mismatch category", async () => {
  const operations = await extractProductionAdapterOperations();
  const first = operations[0];
  const cases = [
    [
      "missing source",
      operations.slice(1),
      "runtime_grant_source_missing",
    ],
    [
      "extra source",
      [
        ...operations,
        { ...first, sourceId: "src/db/repositories.ts#users.syntheticExtra" },
      ],
      "runtime_grant_source_extra",
    ],
    [
      "duplicate source tuple",
      [...operations, { ...first }],
      "runtime_grant_source_duplicate",
    ],
    [
      "wrong source name",
      [
        { ...first, sourceId: `${first.sourceId}Renamed` },
        ...operations.slice(1),
      ],
      "runtime_grant_source_mismatch",
    ],
    [
      "correct source on wrong relation",
      [
        { ...first, objectName: "users" },
        ...operations.slice(1),
      ],
      "runtime_grant_source_mismatch",
    ],
    [
      "correct source on wrong privilege",
      [
        {
          ...first,
          privilege: first.privilege === "SELECT" ? "INSERT" : "SELECT",
        },
        ...operations.slice(1),
      ],
      "runtime_grant_source_mismatch",
    ],
  ];

  for (const [name, candidate, code] of cases) {
    assert.throws(
      () =>
        assertProductionAdapterGrantEquality(
          RUNTIME_TABLE_GRANT_CONTRACT,
          candidate,
        ),
      contractError(code),
      name,
    );
  }
});

test("recursive source discovery rejects every unsupported database-access shape", async () => {
  const repositoryPath = "src/db/access-validation-grant-repository.ts";
  const repository = await readFile(repositoryPath, "utf8");
  const compositionPath = "src/runtime/platform-runtime-dependencies.ts";
  const composition = await readFile(compositionPath, "utf8");
  const cases = [
    [
      "off-pattern adapter",
      "src/db/token-store.ts",
      adapterSource("db.update(users)"),
      "runtime_grant_inventory_unclassified",
    ],
    [
      "nested adapter",
      "src/db/nested/token-store.ts",
      adapterSource("db.update(users)"),
      "runtime_grant_inventory_unclassified",
    ],
    [
      "unsupported raw query",
      "src/platform/raw-store.ts",
      `export function run(client) { return client.query("select * from users"); }`,
      "runtime_grant_inventory_unclassified",
    ],
    [
      "alternative unclassified client",
      "src/platform/alternative-store.ts",
      `export function run(database) { return database.execute("select 1"); }`,
      "runtime_grant_inventory_unclassified",
    ],
    [
      "imported schema binding without attribution",
      "src/platform/schema-consumer.ts",
      `import { users } from "../db/schema.js"; export const table = users;`,
      "runtime_grant_inventory_unclassified",
    ],
  ];

  for (const [name, path, source, code] of cases) {
    await assert.rejects(
      () =>
        inspectProductionDatabaseAccessInventory({
          sourceOverrides: new Map([[path, source]]),
        }),
      contractError(code),
      name,
    );
  }

  const adapterCases = [
    [
      "unsupported method",
      repository.replace(
        "db.insert(accessValidationGrants)",
        "db.execute(accessValidationGrants)",
      ),
    ],
    [
      "dynamic table argument",
      repository.replace(
        "db.insert(accessValidationGrants)",
        "db.insert(record.table)",
      ),
    ],
    [
      "computed database method",
      repository.replace(
        "db.insert(accessValidationGrants)",
        'db["insert"](accessValidationGrants)',
      ),
    ],
    [
      "unresolved database alias",
      repository.replace(
        "const rows = await db.insert(accessValidationGrants)",
        "const alias = db; const rows = await alias.insert(accessValidationGrants)",
      ),
    ],
    [
      "unknown database wrapper",
      repository.replace(
        "db.insert(accessValidationGrants)",
        "runUnknown(db, accessValidationGrants)",
      ),
    ],
    [
      "unknown query-builder method",
      repository.replace(
        "db.insert(accessValidationGrants)",
        'db.updateTable("access_validation_grants")',
      ),
    ],
  ];

  for (const [name, source] of adapterCases) {
    await assert.rejects(
      () =>
        extractProductionAdapterOperations({
          sourceOverrides: new Map([[repositoryPath, source]]),
        }),
      contractError("runtime_grant_inventory_unclassified"),
      name,
    );
  }

  await assert.rejects(
    () =>
      extractProductionAdapterOperations({
        sourceOverrides: new Map([
          [
            repositoryPath,
            `${repository}
export function unsupportedExportedAccess(db) {
  return db.update(accessValidationGrants);
}
`,
          ],
        ]),
      }),
    contractError("runtime_grant_inventory_unclassified"),
    "unclassified access hidden inside an otherwise classified adapter",
  );

  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            compositionPath,
            `${composition}
export function unsupportedDirectRuntimeAccess(input) {
  return input.db.execute("select 1");
}
`,
          ],
        ]),
      }),
    contractError("runtime_grant_inventory_unclassified"),
    "direct access hidden inside a classified composition module",
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
      "correct relation authority in the wrong schema",
      [
        { ...observed[0], schema: "runtime_extra" },
        ...observed.slice(1),
      ],
      {},
      "runtime_grant_set_authority",
    ],
    [
      "view-like relation authority",
      [
        { ...observed[0], objectClass: "view" },
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

const globalNetworkRejectionCode = "runtime_grant_inventory_unclassified";
const oidcAdapterPath = "src/auth/generic-oidc-provider-adapter.ts";

test("no-import runtime network Fetch authority rejects a neutral new Fetch source", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/neutral-fetch.ts",
            `export async function relay(target) {
  const response = await globalThis.fetch(target);
  return response.json();
}`,
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import runtime network authority rejects bare global Fetch", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/bare-fetch.ts",
            `export async function relay(target) {
  const response = await fetch(target);
  return response.json();
}`,
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import runtime network authority rejects node global Fetch", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/global-fetch.ts",
            `export async function relay(target) {
  const response = await global.fetch(target);
  return response.json();
}`,
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import runtime network authority rejects static element access", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/element-fetch.ts",
            `export async function relay(target) {
  const response = await globalThis["fetch"](target);
  return response.json();
}`,
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import runtime network authority rejects destructured Fetch", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/destructured-fetch.ts",
            `const { fetch: send } = globalThis;
export async function relay(target) {
  const response = await send(target);
  return response.json();
}`,
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import runtime network authority rejects global-object alias chain", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/alias-fetch.ts",
            `const runtimeGlobal = globalThis;
const send = runtimeGlobal.fetch;
export async function relay(target) {
  const response = await send(target);
  return response.json();
}`,
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import runtime network authority rejects exported network wrapper", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/wrapper-fetch.ts",
            `export function send(url) {
  return globalThis.fetch(url);
}`,
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import runtime network authority rejects capability exported as a value", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/exported-fetch.ts",
            `export const send = globalThis.fetch;`,
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import authority rejects additional Fetch reference in approved OIDC source", async () => {
  const oidcSource = await readFile(oidcAdapterPath, "utf8");
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            oidcAdapterPath,
            `${oidcSource}
export function extraNetworkAccess(target) {
  const direct = globalThis.fetch;
  return direct(target);
}`,
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import authority rejects alias change in approved OIDC source", async () => {
  const oidcSource = await readFile(oidcAdapterPath, "utf8");
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            oidcAdapterPath,
            oidcSource
              .replace(
                "const fetchImplementation = globalThis.fetch;",
                "const renamedFetch = globalThis.fetch;",
              )
              .replaceAll("fetchImplementation(", "renamedFetch("),
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import authority rejects approved-source wrapper drift", async () => {
  const oidcSource = await readFile(oidcAdapterPath, "utf8");
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            oidcAdapterPath,
            oidcSource.replace(
              "const fetchImplementation = globalThis.fetch;",
              `function getHttpClient() { return globalThis.fetch; }
const fetchImplementation = getHttpClient();`,
            ),
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import authority rejects computed dynamic global-property access", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/dynamic-fetch.ts",
            `const propertyName = "fetch";
export async function relay(target) {
  const response = await globalThis[propertyName](target);
  return response.json();
}`,
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import authority rejects reflective access", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/reflect-fetch.ts",
            `const propertyName = "fetch";
export async function relay(target) {
  const fn = Reflect.get(globalThis, propertyName);
  return fn(target);
}`,
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import authority rejects global WebSocket usage", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/ws-transport.ts",
            `export function connect(target) {
  const socket = new globalThis.WebSocket(target);
  return socket;
}`,
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import authority rejects global EventSource usage", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/event-transport.ts",
            `export function connect(target) {
  const source = new globalThis.EventSource(target);
  return source;
}`,
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import authority rejects global-primitive mutation", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/mutate-fetch.ts",
            `globalThis.fetch = () => {
  throw new Error("blocked");
};`,
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import authority rejects missing authority after source override removes OIDC Fetch", async () => {
  const oidcSource = await readFile(oidcAdapterPath, "utf8");
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            oidcAdapterPath,
            oidcSource.replace(
              "const fetchImplementation = globalThis.fetch;",
              "const fetchImplementation = (() => { throw new Error('unavailable'); }) as unknown as typeof globalThis.fetch;",
            ),
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import approved OIDC network path passes exact authority", async () => {
  const inventory = await inspectProductionDatabaseAccessInventory();
  assert.equal(inventory.length, 11);
});

test("no-import approved OIDC path passes with comment-only variant", async () => {
  const oidcSource = await readFile(oidcAdapterPath, "utf8");
  const inventory = await inspectProductionDatabaseAccessInventory({
    sourceOverrides: new Map([
      [oidcAdapterPath, `// OIDC HTTP transport\n${oidcSource}`],
    ]),
  });
  assert.equal(inventory.length, 11);
});

test("no-import approved OIDC path passes with LF line ending", async () => {
  const oidcSource = await readFile(oidcAdapterPath, "utf8");
  const inventory = await inspectProductionDatabaseAccessInventory({
    sourceOverrides: new Map([
      [oidcAdapterPath, oidcSource.replace(/\r\n?/gu, "\n")],
    ]),
  });
  assert.equal(inventory.length, 11);
});

test("no-import approved OIDC path passes with CRLF line ending", async () => {
  const oidcSource = await readFile(oidcAdapterPath, "utf8");
  const inventory = await inspectProductionDatabaseAccessInventory({
    sourceOverrides: new Map([
      [oidcAdapterPath, oidcSource.replace(/\r\n?/gu, "\n").replace(/\n/gu, "\r\n")],
    ]),
  });
  assert.equal(inventory.length, 11);
});

test("no-import shadowed function parameter is not classified as global Fetch", async () => {
  const source = `export function execute(fetch: (url: string) => Promise<unknown>) {
  return fetch("synthetic");
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/shadow-fetch.ts", source],
        ]),
      }),
    "a source with a shadowed fetch parameter must not be classified as global Fetch",
  );
});

test("no-import shadowed local variable is not classified as global Fetch", async () => {
  const source = `const fetch = (url: string) => Promise.resolve();
export function execute() {
  return fetch("synthetic");
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/shadow-local-fetch.ts", source],
        ]),
      }),
    "a source with a local shadow must not be classified as global Fetch",
  );
});

test("no-import imported local binding named fetch does not trigger false positive", async () => {
  const importedSource = `export const fetch = (url: string) => Promise.resolve();`;
  const consumerSource = `import { fetch as injectedClient } from "./local-client.js";
export function execute() {
  return injectedClient("synthetic");
}`;
  const inventory = await inspectProductionDatabaseAccessInventory({
    sourceOverrides: new Map([
      ["src/platform/local-client.ts", importedSource],
      ["src/platform/imported-fetch.ts", consumerSource],
    ]),
  });
  assert.equal(inventory.length, 11);
});

test("no-import authority preserves existing 11-source inventory", async () => {
  const inventory = await inspectProductionDatabaseAccessInventory();
  assert.equal(inventory.length, 11);
});

test("no-import authority preserves existing 59 operation-source tuples", async () => {
  const operations = await extractProductionAdapterOperations();
  assert.equal(operations.length, 59);
  assert.doesNotThrow(() =>
    assertProductionAdapterGrantEquality(
      RUNTIME_TABLE_GRANT_CONTRACT,
      operations,
    ),
  );
});

test("no-import authority preserves existing 39 grant records and digest", async () => {
  assert.equal(RUNTIME_TABLE_GRANT_CONTRACT.length, 39);
  assert.equal(
    RUNTIME_TABLE_GRANT_DIGEST,
    "9474972215869ec9b194f537c3b2400d8701aa8f00494bcfc0ede849dd94bf65",
  );
});

test("no-import authority preserves existing built-in import authority", async () => {
  const inventory = await inspectProductionDatabaseAccessInventory();
  assert.equal(inventory.length, 11);

  const nodeServer = await readFile("src/http/node-server.ts", "utf8");
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/http/node-server.ts",
            nodeServer.replace(
              'import { createServer, type Server } from "node:http";',
              'import { createServer, request as send, type Server } from "node:http";',
            ),
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
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

function adapterSource(operation) {
  return `
import { users } from "./schema.js";
export function createStore(db) {
  return { async run() { return ${operation}; } };
}
`;
}
