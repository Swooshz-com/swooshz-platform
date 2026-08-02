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

test("unbound process built-in acquisition is rejected through aliases, computed access, destructuring, and reflection", async () => {
  const cases = [
    `export function load() { return process.getBuiltinModule("fs"); }`,
    `export function load() { const p = process; return p.getBuiltinModule("fs"); }`,
    `export function load() { return globalThis.process.getBuiltinModule("fs"); }`,
    `export function load() { return globalThis["process"]["getBuiltinModule"]("fs"); }`,
    `export function load() { return globalThis?.process?.getBuiltinModule?.("fs"); }`,
    `export function load() { const { process: p } = globalThis; return p.getBuiltinModule("fs"); }`,
    `export function load() { const { getBuiltinModule } = process; return getBuiltinModule("fs"); }`,
    `export function load() { const get = process.getBuiltinModule; return get("fs"); }`,
    `export function load() { const g = globalThis; return Reflect.get(g, "process").getBuiltinModule("fs"); }`,
    `export function load() { return Reflect.get(globalThis, "process"); }`,
  ];

  for (const [index, source] of cases.entries()) {
    await assert.rejects(
      () =>
        inspectProductionDatabaseAccessInventory({
          sourceOverrides: new Map([
            [`src/platform/process-authority-${index}.ts`, source],
          ]),
        }),
      contractError(globalNetworkRejectionCode),
    );
  }
});

test("unbound process acquisition rejects value-producing comma expressions", async () => {
  const cases = [
    `export function load() { return (0, globalThis).process.getBuiltinModule("fs"); }`,
    `export function load() { const g = (0, globalThis); return g.process.getBuiltinModule("fs"); }`,
    `export function load() { return (0, globalThis)["process"]["getBuiltinModule"]("fs"); }`,
    `export function load() { return (0, globalThis)?.process?.getBuiltinModule?.("fs"); }`,
    `export function load() { const { process: p } = (0, globalThis); return p.getBuiltinModule("fs"); }`,
    `export function load() { const get = (0, globalThis).process.getBuiltinModule; return get("fs"); }`,
    `export function load() { return (0, process).getBuiltinModule("fs"); }`,
    `export function load() { return Reflect.get((0, globalThis), (0, "process")); }`,
  ];

  for (const [index, source] of cases.entries()) {
    await assert.rejects(
      () =>
        inspectProductionDatabaseAccessInventory({
          sourceOverrides: new Map([
            [`src/platform/run05-sequence-process-${index}.ts`, source],
          ]),
        }),
      contractError(globalNetworkRejectionCode),
    );
  }
});

test("process authority scanner closes computed global destructuring and assignment patterns", async () => {
  const rejected = [
    `export function load() { const {["process"]: p} = globalThis; return p.getBuiltinModule("node:net"); }`,
    `export function load() { const {[(0, "process")]: p} = (0, globalThis); return p.getBuiltinModule("node:http"); }`,
    "export function load() { const {[`process`]: p} = globalThis; return p.getBuiltinModule(\"node:module\"); }",
    `export function load() { const {["pro" + "cess"]: p} = globalThis; return p.getBuiltinModule("node:net"); }`,
    `export function load() { const {outer: {["process"]: p}} = globalThis; return p.getBuiltinModule("node:http"); }`,
    `export function load() { const g = globalThis; const {["process"]: p} = g; return p.getBuiltinModule("node:module"); }`,
    `export function load() { let p; ({[(0, "process")]: p} = (0, globalThis)); return p.getBuiltinModule("node:net"); }`,
    `export function load() { const g = globalThis; let p; ({["process"]: p} = g); const get = p.getBuiltinModule; return get("node:http"); }`,
    `export function load() { const key = process.env.PROPERTY; const {[key]: p} = globalThis; return p.getBuiltinModule("node:net"); }`,
  ];

  for (const [index, source] of rejected.entries()) {
    await assert.rejects(
      () =>
        inspectProductionDatabaseAccessInventory({
          sourceOverrides: new Map([
            [`src/platform/run08-computed-process-${index}.ts`, source],
          ]),
        }),
      contractError(globalNetworkRejectionCode),
    );
  }
});

test("computed process destructuring keeps local and discarded controls safe", async () => {
  const safeCases = [
    `export function load() { const local = {["process"]: { getBuiltinModule() {} }}; const { ["process"]: p } = local; return p.getBuiltinModule(); }`,
    `export function load(globalThis) { const {["process"]: p} = globalThis; return p.getBuiltinModule(); }`,
    `export function load() { const value = {}; const {["other"]: p} = globalThis; return value ?? p; }`,
    `export function load() { const value = {}; return (globalThis, value); }`,
    `type GlobalShape = typeof globalThis; export function load(): GlobalShape | undefined { return undefined; }`,
  ];

  for (const [index, source] of safeCases.entries()) {
    await assert.doesNotReject(
      () =>
        inspectProductionDatabaseAccessInventory({
          sourceOverrides: new Map([
            [`src/platform/run08-computed-process-safe-${index}.ts`, source],
          ]),
        }),
    );
  }
});

test("sequence-expression scanner keeps discarded left operands from becoming authority", async () => {
  const safeCases = [
    `export function load(value) { return (globalThis, value); }`,
    `export function load(value) { return ((0, globalThis), value); }`,
    `export function load(value) { return (globalThis, value.fetch()); }`,
  ];

  for (const [index, source] of safeCases.entries()) {
    await assert.doesNotReject(
      () =>
        inspectProductionDatabaseAccessInventory({
          sourceOverrides: new Map([
            [`src/platform/run05-sequence-discarded-${index}.ts`, source],
          ]),
        }),
    );
  }
});

test("process scanner preserves local shadowing and type-only references", async () => {
  const cases = [
    `export function load(process) { return process.getBuiltinModule("fs"); }`,
    `export function load(globalThis) { return globalThis.process; }`,
    `export function load() { const process = { getBuiltinModule() {} }; return process.getBuiltinModule(); }`,
    `import type { Process } from "node:process";
type RuntimeProcess = typeof process;
export function load(value: Process): RuntimeProcess | undefined { return undefined; }`,
  ];

  for (const [index, source] of cases.entries()) {
    await assert.doesNotReject(
      () =>
        inspectProductionDatabaseAccessInventory({
          sourceOverrides: new Map([
            [`src/platform/process-shadow-${index}.ts`, source],
          ]),
        }),
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

test("no-import authority rejects bare WebSocket constructor", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/ws-bare.ts",
            `export function connect(url) {
  const socket = new WebSocket(url);
  return socket;
}`,
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import authority rejects bare EventSource constructor", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/es-bare.ts",
            `export function connect(url) {
  const source = new EventSource(url);
  return source;
}`,
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import authority rejects parenthesised bare constructor", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/ws-paren.ts",
            `export function connect(url) {
  const socket = new (WebSocket)(url);
  return socket;
}`,
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import authority rejects constructor exported through a wrapper", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/ws-wrapper.ts",
            `export function createWebSocket(url) {
  return new WebSocket(url);
}`,
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import authority rejects qualified WebSocket constructor", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/ws-qualified.ts",
            `export function connect(url) {
  const socket = new globalThis.WebSocket(url);
  return socket;
}`,
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import shadowed WebSocket parameter is not classified as global", async () => {
  const source = `export function connect(WebSocket: { new(url: string): unknown }) {
  return new WebSocket("wss://example.com");
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/ws-shadow.ts", source]]),
      }),
    "a source with a shadowed WebSocket parameter must not be classified as global",
  );
});

test("no-import imported WebSocket is not classified as global constructor", async () => {
  const importedSource = `export class WebSocket { constructor(url: string) {} }`;
  const consumerSource = `import { WebSocket } from "./local-ws.js";
export function connect(url: string) {
  return new WebSocket(url);
}`;
  const inventory = await inspectProductionDatabaseAccessInventory({
    sourceOverrides: new Map([
      ["src/platform/local-ws.ts", importedSource],
      ["src/platform/ws-imported.ts", consumerSource],
    ]),
  });
  assert.equal(inventory.length, 11);
});

test("no-import local WebSocket class shadow is not classified as global", async () => {
  const source = `export function connect() {
  class WebSocket { constructor() {} }
  return new WebSocket();
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/ws-class.ts", source]]),
      }),
    "a source with a local WebSocket class must not be classified as global",
  );
});

test("no-import authority rejects optional global-object Fetch access", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/optional-fetch.ts",
            `export async function relay(target) {
  const response = await globalThis?.fetch(target);
  return response.json();
}`,
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import authority rejects optional invocation of global Fetch", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/optional-invoke.ts",
            `export async function relay(target) {
  const response = await globalThis.fetch?.(target);
  return response.json();
}`,
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import authority rejects optional static element access", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/optional-element.ts",
            `export async function relay(target) {
  const response = await globalThis?.["fetch"](target);
  return response.json();
}`,
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import authority rejects two-level alias chain", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/alias-two.ts",
            `const first = globalThis;
const second = first;
export async function relay(target) {
  const response = await second.fetch(target);
  return response.json();
}`,
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import authority rejects three-level alias chain", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/alias-three.ts",
            `const first = globalThis;
const second = first;
const third = second;
export async function relay(target) {
  const response = await third.fetch(target);
  return response.json();
}`,
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import shadowed global-object alias parameter is not classified as global", async () => {
  const source = `const runtimeGlobal = globalThis;
export function execute(runtimeGlobal: { fetch: (url: string) => Promise<unknown> }) {
  return runtimeGlobal.fetch("synthetic");
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/alias-shadow.ts", source]]),
      }),
    "a source with a shadowed alias parameter must not be classified as global",
  );
});

test("no-import shadowed block-local alias is not classified as global", async () => {
  const source = `const runtimeGlobal = globalThis;
export function execute() {
  const runtimeGlobal = { fetch: (url: string) => Promise.resolve() };
  return runtimeGlobal.fetch("synthetic");
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/alias-block.ts", source]]),
      }),
    "a source with a shadowed block-local alias must not be classified as global",
  );
});

test("no-import authority rejects Object.getOwnPropertyDescriptor on global", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/obj-descriptor.ts",
            `export function inspect() {
  const desc = Object.getOwnPropertyDescriptor(globalThis, "fetch");
  return desc;
}`,
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import authority rejects Object.getOwnPropertyDescriptors on global", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/obj-descriptors.ts",
            `export function inspect() {
  const descs = Object.getOwnPropertyDescriptors(globalThis);
  return descs;
}`,
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import authority rejects dynamic Object.defineProperty on global", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/obj-define-dynamic.ts",
            `export function patch(name, desc) {
  Object.defineProperty(globalThis, name, desc);
}`,
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import authority rejects Object.defineProperties on global", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/obj-define-props.ts",
            `export function patch(descs) {
  Object.defineProperties(globalThis, descs);
}`,
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import authority rejects Reflect.defineProperty on global", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/reflect-define.ts",
            `export function patch() {
  Reflect.defineProperty(globalThis, "fetch", { value: null });
}`,
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import authority rejects deletion via element access", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/delete-element.ts",
            `export function clear() {
  delete globalThis["fetch"];
}`,
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import locally shadowed Object is not rejected for getOwnPropertyDescriptor", async () => {
  const source = `export function execute(Object: { getOwnPropertyDescriptor(o: object, p: string): unknown }) {
  return Object.getOwnPropertyDescriptor({}, "fetch");
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/obj-shadow.ts", source]]),
      }),
    "a source with a locally shadowed Object must not be rejected",
  );
});

test("no-import locally shadowed Reflect is not rejected for get", async () => {
  const source = `const Reflect = { get: (o: object, p: string) => o[p] };
export function execute(val: Record<string, unknown>) {
  return Reflect.get(val, "fetch");
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/reflect-shadow.ts", source]]),
      }),
    "a source with a locally shadowed Reflect must not be rejected",
  );
});

test("no-import function-local Fetch shadow is not classified as global", async () => {
  const source = `export function execute() {
  const fetch = (url: string) => Promise.resolve();
  return fetch("synthetic");
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/fn-local-fetch.ts", source]]),
      }),
    "a source with function-local fetch shadow must not be classified as global",
  );
});

test("no-import function-local function declaration shadow is not classified as global", async () => {
  const source = `export function execute() {
  function fetch(url: string) {
    return Promise.resolve();
  }
  return fetch("synthetic");
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/fn-decl-fetch.ts", source]]),
      }),
    "a source with function-local function declaration must not be classified as global",
  );
});

test("no-import block-local Fetch shadow is not classified as global", async () => {
  const source = `export function execute() {
  {
    const fetch = (url: string) => Promise.resolve();
    fetch("synthetic");
  }
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/block-fetch.ts", source]]),
      }),
    "a source with block-local fetch shadow must not be classified as global",
  );
});

test("no-import destructured parameter Fetch is not classified as global", async () => {
  const source = `export function execute({ fetch }: { fetch: (url: string) => Promise<unknown> }) {
  return fetch("synthetic");
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/destructured-param.ts", source]]),
      }),
    "a source with destructured fetch parameter must not be classified as global",
  );
});

test("no-import unshadowed global Fetch inside nested blocks is rejected", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          [
            "src/platform/nested-global.ts",
            `export function execute() {
  {
    {
      return fetch("unshadowed");
    }
  }
}`,
          ],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import rejects object shorthand fetch", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/shorthand.ts",
            `export function create() { const client = { fetch }; return client; }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import rejects named property fetch", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/named-prop.ts",
            `export function create() { const client = { request: fetch }; return client; }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import rejects fetch passed as argument", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/arg-fetch.ts",
            `export function use(fn: Function) { return fn("url"); } export function relay() { return use(fetch, "url"); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import rejects fetch.bind", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/bind-fetch.ts",
            `export function relay() { const f = fetch.bind(globalThis); return f("url"); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import rejects fetch as typeof fetch", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/cast-fetch.ts",
            `export function relay() { const f = fetch as typeof fetch; return f("url"); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import rejects comma-expression invocation", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/comma-fetch.ts",
            `export function relay(url: string) { return (0, fetch)(url); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import rejects cast-wrapped WebSocket constructor", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/cast-ws.ts",
            `export function connect(url: string) { return new (WebSocket as any)(url); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import rejects comma-wrapped WebSocket constructor", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/comma-ws.ts",
            `export function connect(url: string) { return new (0, WebSocket)(url); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import rejects assignment-created global alias", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/assign-alias.ts",
            `let runtimeGlobal; runtimeGlobal = globalThis; export async function relay(url: string) { return runtimeGlobal.fetch(url); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import rejects reassignment of proven alias", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/reassign-alias.ts",
            `const runtimeGlobal = globalThis; runtimeGlobal = {} as typeof globalThis; export async function relay(url: string) { return runtimeGlobal.fetch(url); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import rejects mutable let global alias", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/let-alias.ts",
            `let runtimeGlobal = globalThis; export async function relay(url: string) { return runtimeGlobal.fetch(url); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import loop-local let fetch then real global call is rejected", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/loop-let-fetch.ts",
            `export function execute(url: string) { for (let fetch = (u: string) => Promise.resolve(); false; ) { void fetch; } return fetch(url); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import function-scoped var fetch is a valid shadow", async () => {
  const source = `export function execute(url: string) {
  {
    var fetch = (u: string) => Promise.resolve();
  }
  return fetch(url);
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/var-fetch.ts", source]]),
      }),
    "function-scoped var fetch must shadow the global",
  );
});

test("no-import recursive binding patterns are resolved correctly", async () => {
  const source = `export function execute({ a: { b: { fetch } } }: { a: { b: { fetch: (u: string) => Promise<unknown> } } }) {
  return fetch("synthetic");
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/recursive-pattern.ts", source]]),
      }),
    "recursive binding pattern must resolve correctly",
  );
});

test("no-import switch-local bindings are scoped correctly", async () => {
  const source = `export function execute(url: string) {
  switch (url) { case "x": { const fetch = (u: string) => Promise.resolve(); fetch(url); } }
  return fetch(url);
}`;
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/switch-fetch.ts", source]]),
      }),
    contractError(globalNetworkRejectionCode),
    "switch case block fetch must shadow only inside the case, global fetch must still be detected",
  );
});

test("no-import rejects Reflect.set on global", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/reflect-set.ts",
            `export function patch() { Reflect.set(globalThis, "fetch", () => null); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import rejects Object.assign on global", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/obj-assign.ts",
            `export function patch() { Object.assign(globalThis, { fetch() { return null; } }); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import rejects computed Object defineProperty mutation", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/computed-define.ts",
            `export function patch() { Object["defineProperty"](globalThis, "fetch", { value: null }); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import rejects destructured defineProperty mutation", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/destructured-define.ts",
            `const { defineProperty } = Object; export function patch() { defineProperty(globalThis, "fetch", { value: null }); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import rejects spread of globalThis", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/spread-global.ts",
            `export function clone() { return { ...globalThis }; }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import rejects rest-copy of globalThis", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/rest-global.ts",
            `export function clone() { const { ...clone } = globalThis; return clone; }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("no-import rejects passing globalThis to unclassified helper", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/pass-global.ts",
            `function helper(g: typeof globalThis) { return g.fetch("url"); } export function relay() { return helper(globalThis); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

// --- Design Lock A: primitive receiver classification ---
// The generic classifier must classify every unbound `fetch`, `WebSocket`,
// or `EventSource` used as a runtime value, including when the identifier
// is the receiver of property/element access. These tests reproduce the
// finding recorded in PRRT_kwDOS-kliM6UFqJr.

test("run-16: no-import rejects fetch.bind with null receiver", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run16-bind-null.ts",
            `export function relay() { const f = fetch.bind(null); return f("url"); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-16: no-import rejects fetch.call with null receiver", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run16-call-null.ts",
            `export function relay() { return fetch.call(null, "url"); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-16: no-import rejects fetch.apply with null receiver", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run16-apply-null.ts",
            `export function relay() { return fetch.apply(null, ["url"]); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-16: no-import rejects fetch computed bind with null receiver", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run16-bracket-bind.ts",
            `export function relay() { const f = fetch["bind"](null); return f("url"); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-16: no-import rejects fetch.bind property access alone", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run16-bind-prop.ts",
            `export function relay() { const m = fetch.bind; return m; }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-16: no-import rejects WebSocket.prototype property access", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run16-ws-proto.ts",
            `export function relay() { return WebSocket.prototype; }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-16: no-import rejects EventSource.prototype property access", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run16-es-proto.ts",
            `export function relay() { return EventSource.prototype; }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-16: no-import rejects parenthesised fetch.bind", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run16-parens-bind.ts",
            `export function relay() { const f = (fetch).bind(null); return f("url"); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-16: no-import rejects non-null fetch.bind", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run16-nonnull-bind.ts",
            `export function relay() { const f = fetch!.bind(null); return f("url"); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-16: no-import does not reject local fetch.bind shadow", async () => {
  const source = `export function relay() {
  const fetch = (u: string) => Promise.resolve();
  const f = fetch.bind(null);
  return f("url");
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/run16-local-bind.ts", source]]),
      }),
    "locally declared fetch must shadow the global",
  );
});

test("run-16: no-import does not reject imported fetch.bind", async () => {
  const importedSource = `export const fetch = (u: string) => Promise.resolve();`;
  const consumerSource = `import { fetch as injectedClient } from "./run16-local-fetch.js";
export function relay() {
  const f = injectedClient.bind(null);
  return f("url");
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run16-local-fetch.ts", importedSource],
          ["src/platform/run16-imported-bind.ts", consumerSource],
        ]),
      }),
    "imported fetch must shadow the global",
  );
});

test("run-16: no-import does not reject parameter fetch.bind", async () => {
  const source = `export function relay(fetch: (u: string) => Promise<unknown>) {
  const f = fetch.bind(null);
  return f("url");
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/run16-param-bind.ts", source]]),
      }),
    "parameter fetch must shadow the global",
  );
});

// --- Design Lock B: recursive global-object escape closure ---
// The global object or a proven alias must not escape inside any structural
// wrapper when passed, returned, exported, assigned, spread, or used as an
// unclassified call target/source. These tests reproduce the finding recorded
// in PRRT_kwDOS-kliM6UC1vp.

test("run-16: no-import rejects object property value holding global", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run16-wrap-global.ts",
            `function helper(_o: { runtimeGlobal: typeof globalThis }) {}
export function relay() { return helper({ runtimeGlobal: globalThis }); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-16: no-import rejects nested object property value holding global", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run16-nest-global.ts",
            `function helper(_o: { nested: { runtimeGlobal: typeof globalThis } }) {}
export function relay() { return helper({ nested: { runtimeGlobal: globalThis } }); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-16: no-import rejects conditional with global as call argument", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run16-cond-global.ts",
            `function helper(_g: typeof globalThis) {}
export function relay(c: boolean) { return helper(c ? globalThis : { fetch: () => null }); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-16: no-import rejects proven alias inside nested wrapper", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run16-alias-nest.ts",
            `const runtimeGlobal = globalThis;
function helper(_o: { runtimeGlobal: typeof globalThis }) {}
export function relay() { return helper({ runtimeGlobal: runtimeGlobal }); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-16: no-import rejects returning object literal holding global", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run16-return-obj.ts",
            `export function relay() { return { runtimeGlobal: globalThis }; }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-16: no-import rejects array envelope holding alias in object", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run16-envelope-alias.ts",
            `const alias = globalThis;
const local = { ok: true };
export function relay() {
  const envelope = [local, { runtimeGlobal: alias }];
  return envelope;
}`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-16: no-import accepts helper call with normal object value", async () => {
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run16-normal-obj.ts",
            `function helper(_o: { a: string }) {}
export function relay() { return helper({ a: "value" }); }`],
        ]),
      }),
    "helper call with normal object value must not be rejected",
  );
});

test("run-16: no-import accepts helper call with local-shadowed object", async () => {
  const source = `const g = { a: 1 };
function helper(_o: { a: number }) {}
export function relay() { return helper(g); }`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/run16-shadow-control.ts", source]]),
      }),
    "local-shadowed object must not be rejected",
  );
});

// --- Design Lock C: exact type-only positions ---
// Pure TypeScript type references must not be classified as runtime capability
// use. TypeQueryNode contexts (typeof X) are type-only and the inner identifier
// must not be classified. Runtime assertions/satisfies must still be classified.

test("run-16: no-import accepts type alias of typeof fetch", async () => {
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run16-typeof-typealias.ts",
            `export type FetchType = typeof fetch;
export const value: FetchType = (() => undefined) as unknown as FetchType;`],
        ]),
      }),
    "type alias of typeof fetch must not be classified as runtime",
  );
});

test("run-16: no-import accepts type alias of typeof WebSocket", async () => {
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run16-typeof-ws.ts",
            `export type WebSocketType = typeof WebSocket;
export const value: WebSocketType = (() => undefined) as unknown as WebSocketType;`],
        ]),
      }),
    "type alias of typeof WebSocket must not be classified as runtime",
  );
});

test("run-16: no-import accepts type alias of typeof EventSource", async () => {
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run16-typeof-es.ts",
            `export type EventSourceType = typeof EventSource;
export const value: EventSourceType = (() => undefined) as unknown as EventSourceType;`],
        ]),
      }),
    "type alias of typeof EventSource must not be classified as runtime",
  );
});

test("run-16: no-import accepts interface property of typeof fetch", async () => {
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run16-typeof-iface.ts",
            `export interface Holder { fetcher: typeof fetch; }
export const _value: Holder = {} as Holder;`],
        ]),
      }),
    "interface property of typeof fetch must not be classified as runtime",
  );
});

test("run-16: no-import accepts nested type alias containing typeof fetch", async () => {
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run16-typeof-nest.ts",
            `export type Outer = { value: typeof fetch };
export const _value: Outer = {} as Outer;`],
        ]),
      }),
    "nested type alias containing typeof fetch must not be classified as runtime",
  );
});

test("run-16: no-import accepts generic type context with typeof fetch default", async () => {
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run16-typeof-generic.ts",
            `export type Outer<T = typeof fetch> = T;
export const _value: Outer = {} as Outer;`],
        ]),
      }),
    "generic type context with typeof fetch default must not be classified as runtime",
  );
});

test("run-16: no-import still rejects runtime WebSocket satisfies typeof WebSocket", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run16-runtime-satisfies.ts",
            `export function relay() { const s = WebSocket satisfies typeof WebSocket; return s; }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

// --- Run 17: callable-wrapper closure ---
// Arrow and function expressions that capture, return, package or expose the
// global object or a proven immutable alias must be treated as an escape. The
// structural global-object classifier currently returns false for every
// ArrowFunction and FunctionExpression, and resolveGlobalObjectName does not
// recognise call-results, so `getGlobal().fetch(url)` evades the authority.
// These tests reproduce the finding recorded in PRRT_kwDOS-kliM6UJMzx.

test("run-17: no-import rejects concise arrow returning globalThis", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run17-arrow-global.ts",
            `export function relay() { const getGlobal = () => globalThis; return getGlobal().fetch("url"); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-17: no-import rejects concise arrow returning global", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run17-arrow-global-alias.ts",
            `export function relay() { const getGlobal = () => global; return getGlobal().fetch("url"); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-17: no-import rejects concise arrow returning proven alias", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run17-arrow-alias.ts",
            `const alias = globalThis;
export function relay() { const getAlias = () => alias; return getAlias().fetch("url"); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-17: no-import rejects block-bodied arrow returning globalThis", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run17-block-arrow.ts",
            `export function relay() { const getGlobal = () => { return globalThis; }; return getGlobal().fetch("url"); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-17: no-import rejects block-bodied arrow returning alias through local", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run17-block-arrow-alias.ts",
            `export function relay() { const getGlobal = () => { const g = globalThis; return g; }; return getGlobal().fetch("url"); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-17: no-import rejects function expression returning globalThis", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run17-fn-expr.ts",
            `export function relay() { const getGlobal = function () { return globalThis; }; return getGlobal().fetch("url"); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-17: no-import rejects async arrow returning globalThis", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run17-async-arrow.ts",
            `export async function relay() { const getGlobal = async () => globalThis; return getGlobal().WebSocket; }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-17: no-import rejects async function expression returning globalThis", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run17-async-fn.ts",
            `export async function relay() { const getGlobal = async function () { return globalThis; }; return getGlobal().WebSocket; }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-17: no-import rejects callable passed as an argument", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run17-callable-arg.ts",
            `function use(fn: () => typeof globalThis) { return fn(); }
export function relay() { return use(() => globalThis).fetch("url"); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-17: no-import rejects callable nested inside an object", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run17-callable-object.ts",
            `export function relay() { const holder = { getGlobal: () => globalThis }; return holder.getGlobal().fetch("url"); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-17: no-import rejects callable nested inside an array", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run17-callable-array.ts",
            `export function relay() { const wrappers = [() => globalThis]; return wrappers[0]().fetch("url"); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-17: no-import rejects conditional callable", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run17-conditional-callable.ts",
            `export function relay(c: boolean) { const f = c ? () => globalThis : () => ({ fetch: () => null }); return f().fetch("url"); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-17: no-import rejects spread-nested callable", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run17-spread-callable.ts",
            `export function relay() { const base = { g: () => globalThis }; return { ...base }.g().fetch("url"); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-17: no-import rejects returned callable", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run17-returned-callable.ts",
            `export function make() { return () => globalThis; }
export function relay() { return make().fetch("url"); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-17: no-import rejects IIFE call-result receiver", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run17-iife-receiver.ts",
            `export function relay() { return (() => globalThis)().fetch("url"); }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-17: no-import rejects alias-returning callable followed by WebSocket access", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run17-alias-callable-ws.ts",
            `const alias = globalThis;
export function relay() { const getAlias = () => alias; return getAlias().WebSocket; }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-17: no-import rejects alias-returning callable followed by EventSource access", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run17-alias-callable-es.ts",
            `const alias = globalThis;
export function relay() { const getAlias = () => alias; return getAlias().EventSource; }`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

// --- Run 17: callable-wrapper GREEN controls ---
// Valid local shadows and normal callbacks must not be rejected.

test("run-17: no-import accepts parameter-shadowed globalThis", async () => {
  const source = `export function relay(fetch: (u: string) => Promise<unknown>) {
  const getGlobal = (globalThis: typeof globalThis) => globalThis;
  return fetch("synthetic");
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/run17-param-global.ts", source]]),
      }),
    "parameter-shadowed globalThis must not be treated as the global object",
  );
});

test("run-17: no-import accepts parameter-shadowed global", async () => {
  const source = `export function relay(fetch: (u: string) => Promise<unknown>, global: typeof globalThis) {
  return fetch("synthetic");
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/run17-param-global-alias.ts", source]]),
      }),
    "parameter-shadowed global must not be treated as the global object",
  );
});

test("run-17: no-import accepts function-local shadowing inside arrow", async () => {
  const source = `export function relay() {
  const getGlobal = () => {
    const globalThis = { fetch: (u: string) => Promise.resolve() };
    return globalThis;
  };
  return getGlobal().fetch("synthetic");
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/run17-fn-local-shadow.ts", source]]),
      }),
    "function-local shadowing inside arrow must not be rejected",
  );
});

test("run-17: no-import accepts normal callback without global authority", async () => {
  const source = `function use(fn: (u: string) => Promise<unknown>, u: string) { return fn(u); }
export function relay() { return use((u) => Promise.resolve(u), "synthetic"); }`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/run17-normal-callback.ts", source]]),
      }),
    "normal callback without global authority must not be rejected",
  );
});

test("run-17: no-import accepts local fetch shadow inside arrow", async () => {
  const source = `export function relay() {
  const getClient = () => {
    const fetch = (u: string) => Promise.resolve();
    return fetch;
  };
  return getClient()("synthetic");
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/run17-local-fetch-arrow.ts", source]]),
      }),
    "local fetch shadow inside arrow must not be classified as global",
  );
});

test("run-17: no-import accepts imported fetch shadow inside arrow", async () => {
  const importedSource = `export const fetch = (u: string) => Promise.resolve();`;
  const consumerSource = `import { fetch as injectedClient } from "./run17-local-fetch.js";
export function relay() {
  const getClient = () => injectedClient;
  return getClient()("synthetic");
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run17-local-fetch.ts", importedSource],
          ["src/platform/run17-imported-arrow.ts", consumerSource],
        ]),
      }),
    "imported fetch shadow inside arrow must not be classified as global",
  );
});

// --- Run 18: nested-callable scope RED controls ---
// Nested callables that genuinely escape the global object must still be rejected.

test("run-18: no-import rejects nested function declaration returning real globalThis", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run18-nested-fndecl-global.ts",
            `export function relay() {
  function getGlobal() { return globalThis; }
  return getGlobal().fetch("url");
}`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-18: no-import rejects nested function declaration returning real global", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run18-nested-fndecl-global-alias.ts",
            `export function relay() {
  function getGlobal() { return global; }
  return getGlobal().fetch("url");
}`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-18: no-import rejects nested function expression returning proven alias", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run18-nested-fnexpr-alias.ts",
            `const alias = globalThis;
export function relay() {
  const getAlias = function () { return alias; };
  return getAlias().fetch("url");
}`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-18: no-import rejects nested callable packaging global in object", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run18-nested-package-object.ts",
            `export function relay() {
  function pack() { return { g: globalThis }; }
  return pack().g.fetch("url");
}`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-18: no-import rejects nested callable packaging global in array", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run18-nested-package-array.ts",
            `export function relay() {
  function pack() { return [globalThis]; }
  return pack()[0].fetch("url");
}`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-18: no-import rejects nested callable result used as network receiver", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run18-nested-receiver.ts",
            `export function relay() {
  function getWs() { return new WebSocket("ws://example.com"); }
  return getWs();
}`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

// --- Run 18: nested-callable scope GREEN controls ---
// Valid nested scopes with shadowed globals must not be rejected.

test("run-18: no-import accepts nested function declaration with parameter-shadowed globalThis", async () => {
  const source = `export function relay(localClient: { fetch(u: string): Promise<unknown> }) {
  const wrapper = () => {
    function local(globalThis: typeof localClient) {
      return globalThis;
    }
    return local(localClient);
  };
  return wrapper().fetch("synthetic");
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/run18-nested-fndecl-shadow.ts", source]]),
      }),
    "nested function declaration with parameter-shadowed globalThis must not be rejected",
  );
});

test("run-18: no-import accepts nested function expression with parameter-shadowed global", async () => {
  const source = `export function relay(localClient: { fetch(u: string): Promise<unknown> }) {
  const wrapper = () => {
    const local = function (global: typeof localClient) {
      return global;
    };
    return local(localClient);
  };
  return wrapper().fetch("synthetic");
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/run18-nested-fnexpr-shadow.ts", source]]),
      }),
    "nested function expression with parameter-shadowed global must not be rejected",
  );
});

test("run-18: no-import accepts nested arrow with destructured local authority", async () => {
  const source = `export function relay(injected: { fetch: (u: string) => Promise<unknown> }) {
  const wrapper = () => {
    const handler = ({ fetch }: { fetch: (u: string) => Promise<unknown> }) => fetch;
    return handler(injected);
  };
  return wrapper()("synthetic");
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/run18-nested-destructured-shadow.ts", source]]),
      }),
    "nested arrow with destructured local authority must not be rejected",
  );
});

test("run-18: no-import accepts nested block-local shadow of globalThis", async () => {
  const source = `export function relay(localClient: { fetch(u: string): Promise<unknown> }) {
  const wrapper = () => {
    {
      const globalThis = localClient;
      return globalThis;
    }
  };
  return wrapper().fetch("synthetic");
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/run18-nested-block-shadow.ts", source]]),
      }),
    "nested block-local shadow of globalThis must not be rejected",
  );
});

test("run-18: no-import accepts nested function and class declarations shadowing primitives", async () => {
  const source = `export function relay() {
  const wrapper = () => {
    function fetch(url: string) { return Promise.resolve(url); }
    class WebSocket { constructor(_u: string) {} }
    return fetch("synthetic");
  };
  return wrapper();
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/run18-nested-fn-class-shadow.ts", source]]),
      }),
    "nested function and class declarations shadowing primitives must not be rejected",
  );
});

test("run-18: no-import accepts nested callable returning local object with fetch property", async () => {
  const source = `export function relay() {
  const wrapper = () => {
    function makeClient() {
      return { fetch: (u: string) => Promise.resolve(u) };
    }
    return makeClient();
  };
  return wrapper().fetch("synthetic");
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/run18-nested-local-fetch-object.ts", source]]),
      }),
    "nested callable returning local object with fetch property must not be rejected",
  );
});

test("run-18: no-import accepts normal nested callback without global authority", async () => {
  const source = `function map<T, U>(arr: T[], fn: (item: T) => U): U[] {
  return arr.map(fn);
}
export function relay() {
  function transform(x: number) { return x * 2; }
  return map([1, 2, 3], transform);
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/run18-normal-nested-callback.ts", source]]),
      }),
    "normal nested callback without global authority must not be rejected",
  );
});

// --- Run 19: non-block loop scope RED controls ---
// Loop bodies that genuinely escape the global object must still be rejected.

test("run-19: no-import rejects loop body returning real globalThis", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run19-loop-return-global.ts",
            `export function relay(clients: unknown[]) {
  for (const c of clients) return globalThis;
}`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-19: no-import rejects loop body returning real global", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run19-loop-return-global-alias.ts",
            `export function relay(clients: unknown[]) {
  for (const c of clients) return global;
}`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-19: no-import rejects loop body returning proven alias", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run19-loop-return-alias.ts",
            `const alias = globalThis;
export function relay(clients: unknown[]) {
  for (const c of clients) return alias;
}`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-19: no-import rejects loop body packaging global in object", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run19-loop-package-object.ts",
            `export function relay(clients: unknown[]) {
  for (const c of clients) return { g: globalThis };
}`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-19: no-import rejects loop body using real fetch authority", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run19-loop-use-fetch.ts",
            `export function relay(urls: string[]) {
  for (const u of urls) return globalThis.fetch(u);
}`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

test("run-19: no-import rejects loop body using real WebSocket authority", async () => {
  await assert.rejects(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([
          ["src/platform/run19-loop-use-ws.ts",
            `export function relay(urls: string[]) {
  for (const u of urls) return new globalThis.WebSocket(u);
}`],
        ]),
      }),
    contractError(globalNetworkRejectionCode),
  );
});

// --- Run 19: non-block loop scope GREEN controls ---
// Valid loop-local shadows must not be rejected.

test("run-19: no-import accepts non-block for-of with loop-local globalThis", async () => {
  const source = `export function relay(clients: { fetch(u: string): Promise<unknown> }[]) {
  for (const globalThis of clients) return globalThis;
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/run19-forof-shadow.ts", source]]),
      }),
    "non-block for-of with loop-local globalThis must not be rejected",
  );
});

test("run-19: no-import accepts non-block for-in with loop-local global", async () => {
  const source = `export function relay(map: Record<string, { fetch(u: string): Promise<unknown> }>) {
  for (const global in map) return map[global];
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/run19-forin-shadow.ts", source]]),
      }),
    "non-block for-in with loop-local global must not be rejected",
  );
});

test("run-19: no-import accepts non-block classic for with loop-local fetch", async () => {
  const source = `export function relay(clients: { fetch(u: string): Promise<unknown> }[]) {
  for (let i = 0; i < clients.length; i) return clients[i];
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/run19-for-shadow.ts", source]]),
      }),
    "non-block classic for with loop-local binding must not be rejected",
  );
});

test("run-19: no-import accepts destructured for-of binding with loop-local globalThis", async () => {
  const source = `export function relay(pairs: { client: { fetch(u: string): Promise<unknown> } }[]) {
  for (const { client: globalThis } of pairs) return globalThis;
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/run19-forof-destructured-shadow.ts", source]]),
      }),
    "destructured for-of binding with loop-local globalThis must not be rejected",
  );
});

test("run-19: no-import accepts block-bodied for-of with loop-local globalThis", async () => {
  const source = `export function relay(clients: { fetch(u: string): Promise<unknown> }[]) {
  for (const globalThis of clients) {
    return globalThis;
  }
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/run19-forof-block-shadow.ts", source]]),
      }),
    "block-bodied for-of with loop-local globalThis must not be rejected",
  );
});

test("run-19: no-import accepts nested loop with inner locally shadowed primitive", async () => {
  const source = `export function relay(matrix: { fetch(u: string): Promise<unknown> }[][]) {
  for (const row of matrix) {
    for (const fetch of row) {
      return fetch;
    }
  }
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/run19-nested-loop-shadow.ts", source]]),
      }),
    "nested loop with inner locally shadowed primitive must not be rejected",
  );
});

test("run-19: no-import accepts normal loop with no global authority", async () => {
  const source = `export function relay(items: number[]) {
  let sum = 0;
  for (const item of items) sum += item;
  return sum;
}`;
  await assert.doesNotReject(
    () =>
      inspectProductionDatabaseAccessInventory({
        sourceOverrides: new Map([["src/platform/run19-normal-loop.ts", source]]),
      }),
    "normal loop with no global authority must not be rejected",
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
