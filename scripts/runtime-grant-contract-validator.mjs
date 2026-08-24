import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

import ts from "typescript";

import {
  RuntimeGrantContractError,
  runtimeTableGrantKey,
} from "../dist/db/runtime-grant-contract.js";

const productionSourceDirectory = "src";
const schemaPath = "src/db/schema.ts";
const migrationDirectory = "drizzle/migrations";
const packageManifestPath = "package.json";
const packageLockPath = "package-lock.json";

const runtimeAdapterPaths = new Set([
  "src/db/access-validation-grant-repository.ts",
  "src/db/app-launch-token-repository.ts",
  "src/db/auth-state-repository.ts",
  "src/db/csrf-token-repository.ts",
  "src/db/repositories.ts",
]);

const runtimeDataSupportPaths = new Set([
  "src/db/schema.ts",
  "src/runtime/platform-runtime-dependencies.ts",
]);

const databaseAccessInventory = new Map([
  ...[...runtimeAdapterPaths].map((filePath) => [
    filePath,
    "runtime_data_adapter",
  ]),
  ["src/db/client.ts", "operational_control_plane"],
  ["src/db/readiness.ts", "operational_control_plane"],
  ["src/db/runtime-posture.ts", "operational_control_plane"],
  ["src/db/schema.ts", "runtime_data_adapter"],
  ["src/runtime/node-bootstrap.ts", "operational_control_plane"],
  [
    "src/runtime/platform-runtime-dependencies.ts",
    "runtime_data_adapter",
  ],
]);

const runtimeDependencyAuthority = new Map([
  [
    "drizzle-orm",
    {
      classification: "database_capable",
      manifestSpecifier: "^0.45.2",
    },
  ],
  [
    "pg",
    {
      classification: "database_capable",
      manifestSpecifier: "^8.22.0",
    },
  ],
]);

// SHA-256 over the canonical production (non-dev) package-lock entries.
const productionDependencyLockDigest =
  "277034001943bbfcd1033820f2764d06dce5d565ce0fdf6111e12836a645f84a";

// SHA-256 over TypeScript tokens (comments and formatting are ignored).
const databaseSourceShapeAuthority = new Map([
  [
    "src/db/access-validation-grant-repository.ts",
    "5f9434df56a9f5bc67468ed8c17ea9fbf60c765c0fa6a88d6902a22d7b9a4271",
  ],
  [
    "src/db/app-launch-token-repository.ts",
    "0eb3ee642d25f6f25c56910f22fb82355a21ef302fa8d53b71728915ecd62d13",
  ],
  [
    "src/db/auth-state-repository.ts",
    "b97f92148ff07fcd9934590485a0b2a0d467575214d7ffc31d1e78cd09ec27e6",
  ],
  [
    "src/db/client.ts",
    "8f2cf8e5890a54dbe9a73dbf91e4ffd48df4731831473fdcc11cff83b8c43b65",
  ],
  [
    "src/db/csrf-token-repository.ts",
    "cd1974c88c1c2c00f3237d79c26dfd272dfd81e6165a44570e9968568625324c",
  ],
  [
    "src/db/readiness.ts",
    "b4198f68eef89def57a52c08d7ad0f3a930e1918df9c74f3904effd2d8caa77a",
  ],
  [
    "src/db/repositories.ts",
    "79329b71a434e5e7b78b4e7edd274a4d42b9d60374bfbc9c575ee15820aba835",
  ],
  [
    "src/db/runtime-posture.ts",
    "ec982b3559cb1d84f32366a31a578f013972b9e6590b423c84324c4829aa7387",
  ],
  [
    "src/db/schema.ts",
    "f9a93c10fb2588e52e8106013cb7f3992f63238c3036ded1292d0476638a6e79",
  ],
  [
    "src/runtime/node-bootstrap.ts",
    "b9b6f5ffbbd2dbcf558a6da62d30ea5b5ead6a999cbbcfdc5b2f5ada7f8cb15f",
  ],
  [
    "src/runtime/platform-runtime-dependencies.ts",
    "bb95698a2ba31e621f4ab6f6e31aad7a31fd94e0c9fd24cffaf523e086b55dd6",
  ],
]);

const builtInCapabilityClassifications = new Set([
  "non_network_cryptographic",
  "filesystem",
  "network",
]);

const builtInImportAuthorityRecords = [
  builtInImportAuthorityRecord({
    sourcePath: "src/auth/auth-state-crypto.ts",
    moduleName: "node:crypto",
    capability: "non_network_cryptographic",
    bindings: [
      namedBuiltInBinding("createHmac"),
      namedBuiltInBinding("randomBytes"),
      namedBuiltInBinding("timingSafeEqual"),
    ],
  }),
  builtInImportAuthorityRecord({
    sourcePath: "src/auth/generic-oidc-jwks-verifier.ts",
    moduleName: "node:crypto",
    capability: "non_network_cryptographic",
    bindings: [
      namedBuiltInBinding("createPublicKey"),
      namedBuiltInBinding("createVerify"),
    ],
  }),
  builtInImportAuthorityRecord({
    sourcePath: "src/auth/platform-identity-crypto.ts",
    moduleName: "node:crypto",
    capability: "non_network_cryptographic",
    bindings: [
      namedBuiltInBinding("randomBytes"),
    ],
  }),
  builtInImportAuthorityRecord({
    sourcePath: "src/http/csrf-token-crypto.ts",
    moduleName: "node:crypto",
    capability: "non_network_cryptographic",
    bindings: [
      namedBuiltInBinding("createHmac"),
      namedBuiltInBinding("randomBytes"),
    ],
  }),
  builtInImportAuthorityRecord({
    sourcePath: "src/http/node-server.ts",
    moduleName: "node:http",
    capability: "network",
    bindings: [
      namedBuiltInBinding("createServer"),
    ],
    sourceShapeDigest:
      "bf0c6776283c22736b439c2b20e507c1225f0974c623ef1acfbac550e37eba4b",
  }),
  builtInImportAuthorityRecord({
    sourcePath: "src/http/public-site-assets.ts",
    moduleName: "node:fs/promises",
    capability: "filesystem",
    bindings: [
      namedBuiltInBinding("readFile"),
    ],
  }),
  builtInImportAuthorityRecord({
    sourcePath: "src/platform/app-launch-token-crypto.ts",
    moduleName: "node:crypto",
    capability: "non_network_cryptographic",
    bindings: [
      namedBuiltInBinding("createHash"),
      namedBuiltInBinding("createHmac"),
      namedBuiltInBinding("randomBytes"),
      namedBuiltInBinding("timingSafeEqual"),
    ],
  }),
  builtInImportAuthorityRecord({
    sourcePath: "src/platform/workspace-admin-id-crypto.ts",
    moduleName: "node:crypto",
    capability: "non_network_cryptographic",
    bindings: [
      namedBuiltInBinding("randomBytes"),
    ],
  }),
];

const builtInImportAuthority = new Map(
  builtInImportAuthorityRecords.map((record) => [
    builtInImportKey(
      record.sourcePath,
      record.moduleName,
      record.importKind,
      record.bindings,
    ),
    record,
  ]),
);

if (builtInImportAuthority.size !== builtInImportAuthorityRecords.length) {
  throw new RuntimeGrantContractError(
    "runtime_grant_inventory_unclassified",
  );
}

// Node 22 stable global outbound-network primitives.
// Repository evidence: CI selects Node 22; build and runtime images use node:22-alpine.
// EventSource requires --experimental-eventsource in Node 22 and is not enabled
// by the repository launch contract. It remains in the detection set for fail-closed
// source analysis but is not described as enabled stable production authority.
const globalNetworkPrimitiveNames = new Set([
  "fetch",
  "WebSocket",
  "EventSource",
]);

const globalNetworkCapabilityRecords = [
  {
    sourcePath: "src/auth/generic-oidc-provider-adapter.ts",
    primitive: "fetch",
    globalObjectForm: "globalThis.fetch",
    acquisitionForm: "const_binding",
    localBinding: "fetchImplementation",
    referenceCount: 1,
    capability: "network",
    sourceShapeDigest:
      "527be9eb33354ebc1f359692b3211c9def7254a46c7610362cccadf289464724",
  },
];

const globalNetworkCapabilityAuthority = new Map(
  globalNetworkCapabilityRecords.map((record) => [
    globalNetworkCapabilityKey(record),
    Object.freeze({ ...record }),
  ]),
);

if (
  globalNetworkCapabilityAuthority.size !==
  globalNetworkCapabilityRecords.length
) {
  throw new RuntimeGrantContractError(
    "runtime_grant_inventory_unclassified",
  );
}

const globalObjectIdentifiers = new Set(["globalThis", "global"]);
const processIdentifierNames = new Set(["process"]);
const dynamicConstructorIdentifierNames = new Set(["Function"]);
const globalConstructorIdentifierNames = new Set([
  "AbortController",
  "AbortSignal",
  "Array",
  "ArrayBuffer",
  "BigInt",
  "BigInt64Array",
  "BigUint64Array",
  "Boolean",
  "DataView",
  "Date",
  "Error",
  "EvalError",
  "Float32Array",
  "Float64Array",
  "Function",
  "Int8Array",
  "Int16Array",
  "Int32Array",
  "Map",
  "Number",
  "Object",
  "Promise",
  "Proxy",
  "RangeError",
  "ReferenceError",
  "RegExp",
  "Set",
  "String",
  "Symbol",
  "SyntaxError",
  "TypeError",
  "Uint8Array",
  "Uint8ClampedArray",
  "Uint16Array",
  "Uint32Array",
  "URIError",
  "URL",
  "URLSearchParams",
  "WeakMap",
  "WeakSet",
]);

const databaseExternalImportAuthority = new Set([
  databaseExternalImportKey(
    "src/db/access-validation-grant-repository.ts",
    "drizzle-orm",
    ["and", "eq", "isNull"],
  ),
  databaseExternalImportKey(
    "src/db/app-launch-token-repository.ts",
    "drizzle-orm",
    ["and", "eq", "isNull"],
  ),
  databaseExternalImportKey(
    "src/db/auth-state-repository.ts",
    "drizzle-orm",
    ["and", "eq", "isNotNull", "isNull", "lte", "or"],
  ),
  databaseExternalImportKey(
    "src/db/client.ts",
    "drizzle-orm/node-postgres",
    ["drizzle"],
  ),
  databaseExternalImportKey(
    "src/db/client.ts",
    "pg",
    ["Pool"],
  ),
  databaseExternalImportKey(
    "src/db/csrf-token-repository.ts",
    "drizzle-orm",
    ["and", "eq", "gt", "inArray", "isNotNull", "isNull", "lte", "or"],
  ),
  databaseExternalImportKey(
    "src/db/repositories.ts",
    "drizzle-orm",
    ["and", "eq", "isNull"],
  ),
  databaseExternalImportKey(
    "src/db/schema.ts",
    "drizzle-orm",
    ["sql"],
  ),
  databaseExternalImportKey(
    "src/db/schema.ts",
    "drizzle-orm/pg-core",
    [
      "index",
      "jsonb",
      "pgEnum",
      "pgTable",
      "text",
      "timestamp",
      "uniqueIndex",
    ],
  ),
]);

const databaseCapabilityFacadePaths = new Set([
  "src/index.ts",
]);

const internalDatabaseImportAuthority = new Set(
  [
    [
      "src/db/access-validation-grant-repository.ts",
      ["src/db/mappers.ts", "src/db/schema.ts"],
    ],
    [
      "src/db/app-launch-token-repository.ts",
      ["src/db/mappers.ts", "src/db/schema.ts"],
    ],
    [
      "src/db/auth-state-repository.ts",
      ["src/db/mappers.ts", "src/db/schema.ts"],
    ],
    [
      "src/db/client.ts",
      ["src/db/repositories.ts", "src/db/schema.ts"],
    ],
    [
      "src/db/csrf-token-repository.ts",
      ["src/db/mappers.ts", "src/db/schema.ts"],
    ],
    ["src/db/readiness.ts", ["src/db/client.ts"]],
    [
      "src/db/repositories.ts",
      ["src/db/mappers.ts", "src/db/schema.ts"],
    ],
    [
      "src/db/runtime-posture.ts",
      ["src/db/runtime-grant-contract.ts"],
    ],
    [
      "src/index.ts",
      [
        "src/db/runtime-posture.ts",
        "src/runtime/node-bootstrap.ts",
        "src/runtime/platform-runtime-dependencies.ts",
      ],
    ],
    [
      "src/runtime/node-bootstrap.ts",
      [
        "src/auth/config.ts",
        "src/db/client.ts",
        "src/db/runtime-posture.ts",
        "src/http/csrf-token-crypto.ts",
        "src/http/node-server.ts",
        "src/http/runtime-config.ts",
        "src/platform/app-launch-token-crypto.ts",
        "src/runtime/bootstrap-config.ts",
        "src/runtime/platform-runtime-dependencies.ts",
        "src/runtime/runtime-secrets.ts",
      ],
    ],
    [
      "src/runtime/platform-runtime-dependencies.ts",
      [
        "src/auth/auth-state-crypto.ts",
        "src/auth/generic-oidc-jwks-verifier.ts",
        "src/auth/generic-oidc-provider-adapter.ts",
        "src/auth/platform-identity-resolver.ts",
        "src/db/access-validation-grant-repository.ts",
        "src/db/app-launch-token-repository.ts",
        "src/db/auth-state-repository.ts",
        "src/db/csrf-token-repository.ts",
        "src/db/repositories.ts",
        "src/http/auth-handlers.ts",
        "src/http/csrf-token-crypto.ts",
        "src/http/csrf-token-service.ts",
        "src/platform/app-launch-token-crypto.ts",
        "src/platform/workspace-admin-id-crypto.ts",
        "src/runtime/runtime-secrets.ts",
      ],
    ],
  ].flatMap(([sourcePath, targetPaths]) =>
    targetPaths.map((targetPath) =>
      internalImportKey(sourcePath, targetPath),
    ),
  ),
);

const operationPrivileges = new Map([
  ["from", "SELECT"],
  ["insert", "INSERT"],
  ["update", "UPDATE"],
  ["delete", "DELETE"],
]);

const allowedDatabaseChainMethods = new Set([
  ...operationPrivileges.keys(),
  "bind",
  "for",
  "limit",
  "returning",
  "select",
  "set",
  "transaction",
  "values",
  "where",
]);

const databaseCandidateMethods = new Set([
  ...allowedDatabaseChainMethods,
  "execute",
  "query",
  "raw",
  "run",
]);

const databaseLikeIdentifiers =
  /^(?:db|database|client|pool|tx|transactionDb|queryBuilder)$/u;

export async function inspectProductionDatabaseAccessInventory({
  sourceOverrides = new Map(),
} = {}) {
  const normalizedOverrides = normalizeSourceOverrides(sourceOverrides);
  const sourcePaths = await productionSourcePaths(normalizedOverrides);
  const discovered = new Set(sourcePaths);

  for (const requiredPath of databaseAccessInventory.keys()) {
    if (!discovered.has(requiredPath)) {
      throw new RuntimeGrantContractError(
        "runtime_grant_inventory_unclassified",
      );
    }
  }

  await assertProductionRuntimeImportAuthority({
    sourceOverrides: normalizedOverrides,
    sourcePaths,
  });

  const inventory = [];
  for (const sourcePath of sourcePaths) {
    const source = await sourceText(sourcePath, normalizedOverrides);
    const sourceFile = parseSourceFile(
      sourcePath,
      source,
      "runtime_grant_inventory_unclassified",
    );
    const candidate = isDatabaseAccessCandidate(sourceFile);
    const classification = databaseAccessInventory.get(sourcePath);

    if (candidate && !classification) {
      throw new RuntimeGrantContractError(
        "runtime_grant_inventory_unclassified",
      );
    }
    if (runtimeDataSupportPaths.has(sourcePath)) {
      assertRuntimeDataSupportOnly(sourcePath, sourceFile);
    }
    if (classification) {
      inventory.push([sourcePath, classification]);
    }
  }

  return inventory.sort(([left], [right]) => compare(left, right));
}

export async function extractProductionAdapterOperations({
  sourceOverrides = new Map(),
} = {}) {
  const normalizedOverrides = normalizeSourceOverrides(sourceOverrides);
  await inspectProductionDatabaseAccessInventory({
    sourceOverrides: normalizedOverrides,
  });
  const schemaSource = await sourceText(schemaPath, normalizedOverrides);
  const schemaBindings = extractSchemaBindings(schemaSource);
  const operations = [];

  for (const adapterPath of [...runtimeAdapterPaths].sort(compare)) {
    const source = await sourceText(adapterPath, normalizedOverrides);
    operations.push(
      ...extractAdapterOperations(
        adapterPath,
        source,
        schemaBindings,
      ),
    );
  }

  return operations.sort((left, right) =>
    compare(operationSourceKey(left), operationSourceKey(right)),
  );
}

export function assertProductionAdapterGrantEquality(
  contract,
  operations,
) {
  const expected = contract.flatMap((record) =>
    record.operationSources.map((sourceId) => ({
      objectClass: record.objectClass,
      schema: record.schema,
      objectName: record.objectName,
      privilege: record.privilege,
      authoritySource: record.authoritySource,
      grantOption: record.grantOption,
      sourceId,
    })),
  );
  const expectedKeys = expected.map(operationSourceKey);
  const operationKeys = operations.map(operationSourceKey);
  if (new Set(operationKeys).size !== operationKeys.length) {
    throw new RuntimeGrantContractError("runtime_grant_source_duplicate");
  }

  const expectedSet = new Set(expectedKeys);
  const operationSet = new Set(operationKeys);
  const missing = expectedKeys.filter((key) => !operationSet.has(key));
  const extra = operationKeys.filter((key) => !expectedSet.has(key));

  if (missing.length > 0 && extra.length > 0) {
    throw new RuntimeGrantContractError("runtime_grant_source_mismatch");
  }
  if (missing.length > 0) {
    throw new RuntimeGrantContractError("runtime_grant_source_missing");
  }
  if (extra.length > 0) {
    throw new RuntimeGrantContractError("runtime_grant_source_extra");
  }
}

export async function readCanonicalMigrationObjects({
  sourceOverrides = new Map(),
} = {}) {
  const normalizedOverrides = normalizeSourceOverrides(sourceOverrides);
  const entries = await readdir(migrationDirectory, {
    withFileTypes: true,
  });
  const migrations = entries
    .filter((entry) => entry.isFile() && /^\d{4}_.+\.sql$/.test(entry.name))
    .map((entry) => entry.name)
    .sort(compare);
  const objects = new Map();

  for (const migrationFile of migrations) {
    const migrationPath = `${migrationDirectory}/${migrationFile}`;
    const source = await sourceText(migrationPath, normalizedOverrides);
    const pattern =
      /\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:"public"\.)?"([a-z_][a-z0-9_]*)"\s*\(/giu;
    for (const match of source.matchAll(pattern)) {
      if (objects.has(match[1])) {
        throw new RuntimeGrantContractError(
          "runtime_grant_contract_migration",
        );
      }
      objects.set(match[1], migrationFile);
    }
  }
  return objects;
}

function extractSchemaBindings(source) {
  const sourceFile = parseSourceFile(
    schemaPath,
    source,
    "runtime_grant_adapter_unsupported",
  );
  const bindings = new Map();

  for (const statement of sourceFile.statements) {
    if (!ts.isVariableStatement(statement)) {
      continue;
    }
    for (const declaration of statement.declarationList.declarations) {
      if (
        !ts.isIdentifier(declaration.name) ||
        !declaration.initializer ||
        !ts.isCallExpression(declaration.initializer) ||
        !ts.isIdentifier(declaration.initializer.expression) ||
        declaration.initializer.expression.text !== "pgTable"
      ) {
        continue;
      }
      const [name] = declaration.initializer.arguments;
      if (!name || !ts.isStringLiteral(name)) {
        throw new RuntimeGrantContractError(
          "runtime_grant_adapter_unsupported",
        );
      }
      bindings.set(declaration.name.text, name.text);
    }
  }
  return bindings;
}

function extractAdapterOperations(adapterPath, source, schemaBindings) {
  const sourceFile = parseSourceFile(
    adapterPath,
    source,
    "runtime_grant_adapter_unsupported",
  );
  const importedTables = importedSchemaTables(sourceFile, schemaBindings);
  if (importedTables.size === 0) {
    throw new RuntimeGrantContractError(
      "runtime_grant_adapter_unsupported",
    );
  }

  const helpers = extractOperationHelpers(sourceFile, importedTables);
  const repositoryMethods = extractRepositoryMethods(
    sourceFile,
    adapterPath,
  );
  if (repositoryMethods.length === 0) {
    throw new RuntimeGrantContractError(
      "runtime_grant_adapter_unsupported",
    );
  }

  const operations = new Map();
  const usedHelpers = new Set();
  for (const repositoryMethod of repositoryMethods) {
    extractMethodOperations({
      importedTables,
      method: repositoryMethod,
      operations,
      helpers,
      usedHelpers,
    });
  }
  assertNoUnclassifiedAdapterAccess(
    sourceFile,
    repositoryMethods,
    helpers,
  );

  for (const [helperName, helper] of helpers) {
    if (helper.operations.length > 0 && !usedHelpers.has(helperName)) {
      throw new RuntimeGrantContractError(
        "runtime_grant_adapter_unsupported",
      );
    }
  }

  return [...operations.values()];
}

function importedSchemaTables(sourceFile, schemaBindings) {
  const importedTables = new Map();
  for (const statement of sourceFile.statements) {
    if (
      !ts.isImportDeclaration(statement) ||
      !ts.isStringLiteral(statement.moduleSpecifier) ||
      statement.moduleSpecifier.text !== "./schema.js" ||
      !statement.importClause?.namedBindings ||
      !ts.isNamedImports(statement.importClause.namedBindings)
    ) {
      continue;
    }
    for (const element of statement.importClause.namedBindings.elements) {
      const exportedName = element.propertyName?.text ?? element.name.text;
      const tableName = schemaBindings.get(exportedName);
      if (tableName) {
        importedTables.set(element.name.text, tableName);
      }
    }
  }
  return importedTables;
}

function extractOperationHelpers(sourceFile, importedTables) {
  const helpers = new Map();
  for (const statement of sourceFile.statements) {
    if (
      !ts.isFunctionDeclaration(statement) ||
      !statement.name ||
      !statement.body ||
      hasExportModifier(statement)
    ) {
      continue;
    }
    const parameters = new Map(
      statement.parameters.flatMap((parameter, index) =>
        ts.isIdentifier(parameter.name)
          ? [[parameter.name.text, index]]
          : [],
      ),
    );
    const operations = [];

    const visit = (node) => {
      rejectUnsupportedDatabaseSyntax(node);
      if (ts.isCallExpression(node)) {
        const method = callMethodName(node.expression);
        const privilege = operationPrivileges.get(method);
        if (privilege) {
          const table = resolveOperationTable(
            node.arguments[0],
            importedTables,
            parameters,
          );
          operations.push({ privilege, ...table });
        } else {
          rejectUnsupportedDatabaseCall(node);
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(statement.body);
    if (operations.length > 0) {
      helpers.set(statement.name.text, {
        node: statement,
        operations,
      });
    }
  }
  return helpers;
}

function assertNoUnclassifiedAdapterAccess(
  sourceFile,
  repositoryMethods,
  helpers,
) {
  const methodNodes = new Set(
    repositoryMethods.map((repositoryMethod) => repositoryMethod.node),
  );
  const helperNodes = new Set(
    [...helpers.values()].map((helper) => helper.node),
  );
  const classifiedAncestor = (node) => {
    let current = node.parent;
    while (current) {
      if (methodNodes.has(current) || helperNodes.has(current)) {
        return true;
      }
      current = current.parent;
    }
    return false;
  };
  const visit = (node) => {
    if (
      ts.isTaggedTemplateExpression(node) &&
      ts.isIdentifier(node.tag) &&
      node.tag.text === "sql" &&
      !classifiedAncestor(node)
    ) {
      throw new RuntimeGrantContractError(
        "runtime_grant_adapter_unsupported",
      );
    }
    if (ts.isCallExpression(node)) {
      const method = callMethodName(node.expression);
      const databaseAccess =
        operationPrivileges.has(method) ||
        ["execute", "query", "raw"].includes(method) ||
        (
          ts.isElementAccessExpression(node.expression) &&
          containsDatabaseIdentifier(node.expression.expression)
        );
      if (databaseAccess && !classifiedAncestor(node)) {
        throw new RuntimeGrantContractError(
          "runtime_grant_adapter_unsupported",
        );
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
}

function extractRepositoryMethods(sourceFile, adapterPath) {
  const methods = [];
  const visit = (node) => {
    if (ts.isMethodDeclaration(node)) {
      const factory = nearestExportedFunction(node);
      const returnStatement = nearestReturnStatement(node);
      if (factory && returnStatement && isDescendant(returnStatement, factory)) {
        const methodPath = repositoryMethodPath(node, returnStatement);
        if (!methodPath) {
          throw new RuntimeGrantContractError(
            "runtime_grant_adapter_unsupported",
          );
        }
        methods.push({
          node,
          sourceId: `${adapterPath}#${methodPath}`,
        });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return methods;
}

function extractMethodOperations({
  importedTables,
  method,
  operations,
  helpers,
  usedHelpers,
}) {
  const add = (tableName, privilege) => {
    const record = Object.freeze({
      objectClass: "table",
      schema: "public",
      objectName: tableName,
      privilege,
      authoritySource: "direct",
      grantOption: false,
      sourceId: method.sourceId,
    });
    operations.set(operationSourceKey(record), record);
  };

  const visit = (node) => {
    rejectUnsupportedDatabaseSyntax(node);

    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.initializer &&
      ts.isIdentifier(node.initializer) &&
      databaseLikeIdentifiers.test(node.initializer.text)
    ) {
      throw new RuntimeGrantContractError(
        "runtime_grant_adapter_unsupported",
      );
    }

    if (ts.isCallExpression(node)) {
      const operationMethod = callMethodName(node.expression);
      const privilege = operationPrivileges.get(operationMethod);
      if (privilege) {
        const tableArgument = node.arguments[0];
        if (!tableArgument || !ts.isIdentifier(tableArgument)) {
          throw new RuntimeGrantContractError(
            "runtime_grant_adapter_unsupported",
          );
        }
        const tableName = importedTables.get(tableArgument.text);
        if (!tableName) {
          throw new RuntimeGrantContractError(
            "runtime_grant_adapter_unsupported",
          );
        }
        add(tableName, privilege);
      } else if (ts.isIdentifier(node.expression)) {
        const helper = helpers.get(node.expression.text);
        if (helper) {
          usedHelpers.add(node.expression.text);
          for (const operation of helper.operations) {
            const tableName =
              operation.tableName ??
              resolveHelperTableArgument(
                node.arguments[operation.parameterIndex],
                importedTables,
              );
            add(tableName, operation.privilege);
          }
        } else if (
          node.arguments.some(
            (argument) =>
              ts.isIdentifier(argument) &&
              databaseLikeIdentifiers.test(argument.text),
          ) &&
          !node.expression.text.startsWith("createDrizzle")
        ) {
          throw new RuntimeGrantContractError(
            "runtime_grant_adapter_unsupported",
          );
        }
      } else {
        rejectUnsupportedDatabaseCall(node);
      }
    }

    ts.forEachChild(node, visit);
  };
  visit(method.node.body);
}

function resolveOperationTable(argument, importedTables, parameters) {
  if (!argument || !ts.isIdentifier(argument)) {
    throw new RuntimeGrantContractError(
      "runtime_grant_adapter_unsupported",
    );
  }
  const tableName = importedTables.get(argument.text);
  if (tableName) {
    return { tableName };
  }
  const parameterIndex = parameters.get(argument.text);
  if (parameterIndex !== undefined) {
    return { parameterIndex };
  }
  throw new RuntimeGrantContractError(
    "runtime_grant_adapter_unsupported",
  );
}

function resolveHelperTableArgument(argument, importedTables) {
  if (!argument || !ts.isIdentifier(argument)) {
    throw new RuntimeGrantContractError(
      "runtime_grant_adapter_unsupported",
    );
  }
  const tableName = importedTables.get(argument.text);
  if (!tableName) {
    throw new RuntimeGrantContractError(
      "runtime_grant_adapter_unsupported",
    );
  }
  return tableName;
}

function rejectUnsupportedDatabaseSyntax(node) {
  if (
    ts.isElementAccessExpression(node) &&
    databaseRootIdentifier(node.expression)
  ) {
    throw new RuntimeGrantContractError(
      "runtime_grant_adapter_unsupported",
    );
  }
  if (
    ts.isTaggedTemplateExpression(node) &&
    ts.isIdentifier(node.tag) &&
    node.tag.text === "sql"
  ) {
    throw new RuntimeGrantContractError(
      "runtime_grant_adapter_unsupported",
    );
  }
}

function rejectUnsupportedDatabaseCall(node) {
  const method = callMethodName(node.expression);
  const root = databaseRootIdentifier(node.expression);
  if (
    root &&
    (!method || !allowedDatabaseChainMethods.has(method))
  ) {
    throw new RuntimeGrantContractError(
      "runtime_grant_adapter_unsupported",
    );
  }
}

function assertRuntimeDataSupportOnly(sourcePath, sourceFile) {
  const visit = (node) => {
    if (
      sourcePath !== schemaPath &&
      ts.isTaggedTemplateExpression(node) &&
      ts.isIdentifier(node.tag) &&
      node.tag.text === "sql"
    ) {
      throw new RuntimeGrantContractError(
        "runtime_grant_adapter_unsupported",
      );
    }
    if (ts.isCallExpression(node)) {
      const method = callMethodName(node.expression);
      if (
        method &&
        [
          ...operationPrivileges.keys(),
          "execute",
          "query",
          "raw",
        ].includes(method) &&
        containsDatabaseIdentifier(node.expression)
      ) {
        throw new RuntimeGrantContractError(
          "runtime_grant_adapter_unsupported",
        );
      }
      if (
        ts.isElementAccessExpression(node.expression) &&
        containsDatabaseIdentifier(node.expression.expression)
      ) {
        throw new RuntimeGrantContractError(
          "runtime_grant_adapter_unsupported",
        );
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
}

function repositoryMethodPath(method, returnStatement) {
  const parts = [propertyName(method.name)];
  let current = method.parent;
  while (current && current !== returnStatement) {
    if (ts.isPropertyAssignment(current)) {
      parts.unshift(propertyName(current.name));
    }
    current = current.parent;
  }
  return parts.every(Boolean) ? parts.join(".") : null;
}

function propertyName(name) {
  if (ts.isIdentifier(name) || ts.isStringLiteral(name)) {
    return name.text;
  }
  return null;
}

function nearestExportedFunction(node) {
  let current = node.parent;
  while (current) {
    if (ts.isFunctionDeclaration(current)) {
      return hasExportModifier(current) ? current : null;
    }
    current = current.parent;
  }
  return null;
}

function nearestReturnStatement(node) {
  let current = node.parent;
  while (current) {
    if (ts.isReturnStatement(current)) {
      return current;
    }
    if (ts.isFunctionDeclaration(current)) {
      return null;
    }
    current = current.parent;
  }
  return null;
}

function isDescendant(node, ancestor) {
  let current = node.parent;
  while (current) {
    if (current === ancestor) {
      return true;
    }
    current = current.parent;
  }
  return false;
}

function hasExportModifier(node) {
  return Boolean(
    node.modifiers?.some(
      (modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword,
    ),
  );
}

function callMethodName(expression) {
  if (
    ts.isPropertyAccessExpression(expression) ||
    ts.isPropertyAccessChain(expression)
  ) {
    return expression.name.text;
  }
  if (ts.isElementAccessExpression(expression)) {
    return null;
  }
  return null;
}

function databaseRootIdentifier(expression) {
  let current = expression;
  while (current) {
    if (ts.isIdentifier(current)) {
      return databaseLikeIdentifiers.test(current.text)
        ? current.text
        : null;
    }
    if (
      ts.isPropertyAccessExpression(current) ||
      ts.isPropertyAccessChain(current) ||
      ts.isElementAccessExpression(current)
    ) {
      current = current.expression;
      continue;
    }
    if (ts.isCallExpression(current)) {
      current = current.expression;
      continue;
    }
    if (
      ts.isParenthesizedExpression(current) ||
      ts.isNonNullExpression(current) ||
      ts.isAsExpression(current)
    ) {
      current = current.expression;
      continue;
    }
    return null;
  }
  return null;
}

function containsDatabaseIdentifier(node) {
  let found = false;
  const visit = (candidate) => {
    if (
      ts.isIdentifier(candidate) &&
      databaseLikeIdentifiers.test(candidate.text)
    ) {
      found = true;
      return;
    }
    ts.forEachChild(candidate, visit);
  };
  visit(node);
  return found;
}

async function assertProductionRuntimeImportAuthority({
  sourceOverrides,
  sourcePaths,
}) {
  assertExactAuthoritySet(
    new Set(databaseSourceShapeAuthority.keys()),
    new Set(databaseAccessInventory.keys()),
  );
  const dependencyAuthority = await readRuntimeDependencyAuthority(
    sourceOverrides,
  );
  const discoveredSources = new Set(sourcePaths);
  const internalEdges = [];
  const observedDatabaseImports = new Set();
  const observedBuiltInImports = new Set();
  const externalDatabaseSources = new Set();
  const sourceFiles = new Map();

  for (const sourcePath of sourcePaths) {
    const source = await sourceText(sourcePath, sourceOverrides);
    const sourceFile = parseSourceFile(
      sourcePath,
      source,
      "runtime_grant_inventory_unclassified",
    );
    const expectedSourceShape =
      databaseSourceShapeAuthority.get(sourcePath);
    if (
      expectedSourceShape &&
      sourceShapeDigest(source) !== expectedSourceShape
    ) {
      throw new RuntimeGrantContractError(
        "runtime_grant_inventory_unclassified",
      );
    }
    sourceFiles.set(sourcePath, sourceFile);
    rejectUnsupportedRuntimeModuleLoading(sourceFile);

    for (const reference of runtimeModuleReferences(sourceFile)) {
      const moduleName = reference.moduleName;
      if (moduleName.startsWith(".")) {
        const targetPath = resolveInternalModulePath(
          sourcePath,
          moduleName,
        );
        if (!discoveredSources.has(targetPath)) {
          throw new RuntimeGrantContractError(
            "runtime_grant_inventory_unclassified",
          );
        }
        internalEdges.push({ sourcePath, targetPath });
        continue;
      }

      if (moduleName.startsWith("node:")) {
        const importKey = builtInImportKeyFromReference(
          sourcePath,
          moduleName,
          reference,
        );
        const authority = builtInImportAuthority.get(importKey);
        if (!authority) {
          throw new RuntimeGrantContractError(
            "runtime_grant_inventory_unclassified",
          );
        }
        if (observedBuiltInImports.has(importKey)) {
          throw new RuntimeGrantContractError(
            "runtime_grant_inventory_unclassified",
          );
        }
        observedBuiltInImports.add(importKey);
        if (
          authority.capability === "network" &&
          sourceShapeDigest(source) !== authority.sourceShapeDigest
        ) {
          throw new RuntimeGrantContractError(
            "runtime_grant_inventory_unclassified",
          );
        }
        continue;
      }

      const packageName = externalPackageName(moduleName);
      const authority = dependencyAuthority.get(packageName);
      if (!authority) {
        throw new RuntimeGrantContractError(
          "runtime_grant_inventory_unclassified",
        );
      }
      if (authority.classification === "database_capable") {
        const importKey = databaseExternalImportKeyFromReference(
          sourcePath,
          moduleName,
          reference,
        );
        if (!databaseExternalImportAuthority.has(importKey)) {
          throw new RuntimeGrantContractError(
            "runtime_grant_inventory_unclassified",
          );
        }
        observedDatabaseImports.add(importKey);
        externalDatabaseSources.add(sourcePath);
      }
    }
  }

  assertExactAuthoritySet(
    observedDatabaseImports,
    databaseExternalImportAuthority,
  );
  assertExactBuiltInImportAuthority(observedBuiltInImports);

  const databaseCapableSources = new Set([
    ...databaseAccessInventory.keys(),
    ...externalDatabaseSources,
  ]);
  const observedInternalDatabaseEdges = new Set();
  let changed = true;
  while (changed) {
    changed = false;
    for (const edge of internalEdges) {
      const importsDatabaseCapability =
        databaseCapableSources.has(edge.targetPath);
      const leavesDatabaseBoundary =
        databaseAccessInventory.has(edge.sourcePath);
      if (!importsDatabaseCapability && !leavesDatabaseBoundary) {
        continue;
      }
      const edgeKey = internalImportKey(
        edge.sourcePath,
        edge.targetPath,
      );
      if (!internalDatabaseImportAuthority.has(edgeKey)) {
        throw new RuntimeGrantContractError(
          "runtime_grant_inventory_unclassified",
        );
      }
      observedInternalDatabaseEdges.add(edgeKey);
      if (
        importsDatabaseCapability &&
        !databaseCapableSources.has(edge.sourcePath)
      ) {
        databaseCapableSources.add(edge.sourcePath);
        changed = true;
      }
    }
  }

  assertExactAuthoritySet(
    observedInternalDatabaseEdges,
    internalDatabaseImportAuthority,
  );

  for (const sourcePath of databaseCapableSources) {
    if (
      !databaseAccessInventory.has(sourcePath) &&
      !databaseCapabilityFacadePaths.has(sourcePath)
    ) {
      throw new RuntimeGrantContractError(
        "runtime_grant_inventory_unclassified",
      );
    }
  }

  for (const facadePath of databaseCapabilityFacadePaths) {
    assertDatabaseCapabilityFacadeOnly(sourceFiles.get(facadePath));
  }

  const allObservedGlobalNetworkKeys = new Set();
  for (const [sourcePath, sourceFile] of sourceFiles) {
    const observedMap = detectGlobalNetworkCapabilities(
      sourcePath,
      sourceFile,
    );
    for (const [key, observed] of observedMap) {
      if (allObservedGlobalNetworkKeys.has(key)) {
        throw new RuntimeGrantContractError(
          "runtime_grant_inventory_unclassified",
        );
      }
      allObservedGlobalNetworkKeys.add(key);

      const authority = globalNetworkCapabilityAuthority.get(key);
      if (authority) {
        if (observed.referenceCount !== authority.referenceCount) {
          throw new RuntimeGrantContractError(
            "runtime_grant_inventory_unclassified",
          );
        }
      }
    }
  }

  assertGlobalNetworkCapabilityEquality(
    allObservedGlobalNetworkKeys,
    globalNetworkCapabilityAuthority,
  );

  for (const key of allObservedGlobalNetworkKeys) {
    const authority = globalNetworkCapabilityAuthority.get(key);
    if (!authority) {
      throw new RuntimeGrantContractError(
        "runtime_grant_inventory_unclassified",
      );
    }
    if (authority.sourceShapeDigest) {
      const source = await sourceText(
        authority.sourcePath,
        sourceOverrides,
      );
      if (sourceShapeDigest(source) !== authority.sourceShapeDigest) {
        throw new RuntimeGrantContractError(
          "runtime_grant_inventory_unclassified",
        );
      }
    }
  }

  for (const [authKey, authority] of globalNetworkCapabilityAuthority) {
    if (authority.sourceShapeDigest && sourceFiles.has(authority.sourcePath)) {
      const source = await sourceText(
        authority.sourcePath,
        sourceOverrides,
      );
      if (sourceShapeDigest(source) !== authority.sourceShapeDigest) {
        throw new RuntimeGrantContractError(
          "runtime_grant_inventory_unclassified",
        );
      }
    }
  }
}

async function readRuntimeDependencyAuthority(sourceOverrides) {
  const packageManifest = parseJsonObject(
    await sourceText(packageManifestPath, sourceOverrides),
  );
  const packageLock = parseJsonObject(
    await sourceText(packageLockPath, sourceOverrides),
  );
  const manifestDependencies = stringRecord(
    packageManifest.dependencies,
  );
  const lockPackages = plainRecord(packageLock.packages);
  const lockRoot = plainRecord(lockPackages[""]);
  const lockDependencies = stringRecord(lockRoot.dependencies);

  assertExactStringRecord(
    manifestDependencies,
    lockDependencies,
  );

  const authorityDependencies = Object.fromEntries(
    [...runtimeDependencyAuthority]
      .sort(([left], [right]) => compare(left, right))
      .map(([dependency, authority]) => [
        dependency,
        authority.manifestSpecifier,
      ]),
  );
  assertExactStringRecord(
    manifestDependencies,
    authorityDependencies,
  );

  for (const dependency of Object.keys(manifestDependencies)) {
    const installedPath = `node_modules/${dependency}`;
    if (!plainRecord(lockPackages[installedPath])) {
      throw new RuntimeGrantContractError(
        "runtime_grant_inventory_unclassified",
      );
    }
  }

  const productionLockPackages = Object.fromEntries(
    Object.entries(lockPackages)
      .filter(
        ([packagePath, packageRecord]) =>
          packagePath && plainRecord(packageRecord).dev !== true,
      )
      .sort(([left], [right]) => compare(left, right)),
  );
  if (
    sha256(canonicalJson(productionLockPackages)) !==
    productionDependencyLockDigest
  ) {
    throw new RuntimeGrantContractError(
      "runtime_grant_inventory_unclassified",
    );
  }

  return runtimeDependencyAuthority;
}

function runtimeModuleReferences(sourceFile) {
  const references = [];
  for (const statement of sourceFile.statements) {
    if (
      ts.isImportDeclaration(statement) &&
      ts.isStringLiteral(statement.moduleSpecifier) &&
      hasRuntimeImport(statement)
    ) {
      references.push({
        kind: "import",
        moduleName: statement.moduleSpecifier.text,
        statement,
      });
      continue;
    }
    if (
      ts.isExportDeclaration(statement) &&
      statement.moduleSpecifier &&
      ts.isStringLiteral(statement.moduleSpecifier) &&
      hasRuntimeExport(statement)
    ) {
      references.push({
        kind: "export",
        moduleName: statement.moduleSpecifier.text,
        statement,
      });
      continue;
    }
    if (
      ts.isImportEqualsDeclaration(statement) &&
      !statement.isTypeOnly
    ) {
      throw new RuntimeGrantContractError(
        "runtime_grant_inventory_unclassified",
      );
    }
  }
  return references;
}

function assertDatabaseCapabilityFacadeOnly(sourceFile) {
  if (!sourceFile) {
    throw new RuntimeGrantContractError(
      "runtime_grant_inventory_unclassified",
    );
  }
  for (const statement of sourceFile.statements) {
    if (
      (
        ts.isImportDeclaration(statement) &&
        hasRuntimeImport(statement)
      ) ||
      (
        ts.isImportEqualsDeclaration(statement) &&
        !statement.isTypeOnly
      )
    ) {
      throw new RuntimeGrantContractError(
        "runtime_grant_inventory_unclassified",
      );
    }
  }
}

function rejectUnsupportedRuntimeModuleLoading(sourceFile) {
  rejectGlobalDynamicConstructorAuthority(sourceFile);
  rejectUnboundGlobalProcessAuthority(sourceFile);

  const visit = (node) => {
    if (
      ts.isCallExpression(node) &&
      (
        node.expression.kind === ts.SyntaxKind.ImportKeyword ||
        (
          ts.isIdentifier(node.expression) &&
          ["eval", "require"].includes(node.expression.text)
        )
      )
    ) {
      throw new RuntimeGrantContractError(
        "runtime_grant_inventory_unclassified",
      );
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
}

const containerMutatingMethodNames = new Set([
  "push",
  "pop",
  "shift",
  "unshift",
  "splice",
  "fill",
  "copyWithin",
  "reverse",
  "sort",
]);

const containerReadOnlyMethodNames = new Set([
  "at",
  "concat",
  "entries",
  "every",
  "filter",
  "find",
  "findIndex",
  "findLast",
  "findLastIndex",
  "flat",
  "flatMap",
  "forEach",
  "includes",
  "indexOf",
  "join",
  "keys",
  "lastIndexOf",
  "map",
  "reduce",
  "reduceRight",
  "slice",
  "some",
  "toLocaleString",
  "toReversed",
  "toSorted",
  "toSpliced",
  "toString",
  "values",
  "with",
  "iterator",
]);

const containerReflectionMutationMethods = new Set([
  "assign",
  "defineProperty",
  "defineProperties",
  "set",
  "deleteProperty",
]);

const containerReflectionReadOnlyMethods = new Set([
  "get",
  "getOwnPropertyDescriptor",
  "getOwnPropertyDescriptors",
  "getOwnPropertyNames",
  "getOwnPropertySymbols",
  "getPrototypeOf",
  "has",
  "hasOwn",
  "hasOwnProperty",
  "is",
  "isExtensible",
  "isFrozen",
  "isSealed",
  "keys",
  "ownKeys",
  "values",
  "entries",
]);

const containerAssignmentOperatorKinds = new Set([
  ts.SyntaxKind.EqualsToken,
  ts.SyntaxKind.PlusEqualsToken,
  ts.SyntaxKind.MinusEqualsToken,
  ts.SyntaxKind.AsteriskEqualsToken,
  ts.SyntaxKind.AsteriskAsteriskEqualsToken,
  ts.SyntaxKind.SlashEqualsToken,
  ts.SyntaxKind.PercentEqualsToken,
  ts.SyntaxKind.LessThanLessThanEqualsToken,
  ts.SyntaxKind.GreaterThanGreaterThanEqualsToken,
  ts.SyntaxKind.GreaterThanGreaterThanGreaterThanEqualsToken,
  ts.SyntaxKind.AmpersandEqualsToken,
  ts.SyntaxKind.BarEqualsToken,
  ts.SyntaxKind.CaretEqualsToken,
  ts.SyntaxKind.BarBarEqualsToken,
  ts.SyntaxKind.AmpersandAmpersandEqualsToken,
  ts.SyntaxKind.QuestionQuestionEqualsToken,
]);

function rejectGlobalDynamicConstructorAuthority(sourceFile) {
  const reject = () => {
    throw new RuntimeGrantContractError("runtime_grant_inventory_unclassified");
  };
  const rootScope = {
    bindings: new Map(),
    globalAliases: new Set(),
    globalConstructorAliases: new Set(),
    callableBindings: new Map(),
    valueBindings: new Map(),
    valueSnapshots: new Map(),
    containerBindings: new Map(),
    containerMutatorAliases: new Map(),
    containerRegistry: new Map(),
    containerDependents: new Map(),
    containerNextId: 1,
    node: null,
    varScope: null,
  };
  rootScope.varScope = rootScope;
  addModuleScopeDeclarations(sourceFile, rootScope);

  const scopes = [rootScope];
  const visit = (node) => {
    recordStaticValueBinding(node, scopes);
    recordStaticValueAssignment(node, scopes);
    recordContainerMutation(node, scopes);
    if (
      isRuntimeValueIdentifierReferenceForName(
        node,
        scopes,
        dynamicConstructorIdentifierNames,
      ) &&
      dynamicConstructorReferenceIsAuthority(node)
    ) {
      reject();
    }

    if (
      dynamicConstructorPropertyAccess(node, scopes) &&
      dynamicConstructorReferenceIsAuthority(node)
    ) {
      reject();
    }

    if (ts.isVariableDeclaration(node) && node.initializer) {
      if (
        (ts.isObjectBindingPattern(node.name) || ts.isArrayBindingPattern(node.name)) &&
        destructuringPatternCanReachCallableOrUnknown(
          node.name,
          node.initializer,
          scopes,
        )
      ) {
        reject();
      }
      if (
        (ts.isObjectBindingPattern(node.name) ||
          ts.isArrayBindingPattern(node.name)) &&
        isDirectGlobalObjectReference(node.initializer, scopes) &&
        bindingPatternCanReachDynamicConstructor(node.name)
      ) {
        reject();
      }
      recordContainerDestructuredMutators(node, scopes);
      recordGlobalConstructorAlias(node, scopes);
      checkGlobalObjectAlias(node, scopes);
    }

    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      isAssignmentDestructuringPattern(node.left)
    ) {
      if (
        isDirectGlobalObjectReference(node.right, scopes) &&
        bindingPatternCanReachDynamicConstructor(node.left)
      ) {
        reject();
      }
      if (
        destructuringPatternCanReachCallableOrUnknown(
          node.left,
          node.right,
          scopes,
        )
      ) {
        reject();
      }
    }

    if (ts.isForOfStatement(node)) {
      const pattern = ts.isVariableDeclarationList(node.initializer)
        ? node.initializer.declarations[0]?.name
        : node.initializer;
      if (
        pattern &&
        (isAssignmentDestructuringPattern(pattern) ||
          ts.isObjectBindingPattern(pattern) ||
          ts.isArrayBindingPattern(pattern)) &&
        forOfPatternCanReachCallableOrUnknown(
          pattern,
          node.expression,
          scopes,
        )
      ) {
        reject();
      }
    }

    if (
      ts.isCallExpression(node) &&
      reflectiveDynamicConstructorAcquisition(node, scopes)
    ) {
      reject();
    }

    if (ts.isCallExpression(node)) {
      recordContainerMutatorInvocation(node, scopes);
    }

    const isScope = isScopeNode(node);
    if (isScope) {
      const newScope = {
        bindings: new Map(),
        globalAliases: new Set(),
        callableBindings: new Map(),
        valueBindings: new Map(),
        valueSnapshots: new Map(),
        containerBindings: new Map(),
        containerMutatorAliases: new Map(),
        globalConstructorAliases: new Set(),
        node,
        varScope: null,
      };
      newScope.varScope =
        scopes[scopes.length - 1].varScope || scopes[scopes.length - 1];
      addNodeScopeDeclarations(node, newScope);
      scopes.push(newScope);
    }

    ts.forEachChild(node, visit);

    if (isScope) {
      scopes.pop();
    }
  };

  visit(sourceFile);
}

function dynamicConstructorReferenceIsAuthority(node) {
  if (isDiscardedSequenceOperand(node)) return false;
  if (isInTypePosition(node)) return false;
  const parent = node.parent;
  return !(
    parent &&
    ts.isTypeOfExpression(parent) &&
    parent.expression === node
  );
}

function dynamicConstructorPropertyAccess(node, scopes) {
  const access = staticPropertyAccessParts(node);
  if (!access) return false;

  const { objectExpression, propertyExpression } = access;
  const propertyName = staticPropertyName(propertyExpression);
  if (isInTypePosition(node) || isDiscardedSequenceOperand(node)) return false;
  if (propertyName === "constructor") {
    return staticallyKnownCallableValueKind(objectExpression, scopes) !== "non_callable";
  }
  if (propertyName === null) {
    return Boolean(resolveGlobalObjectName(objectExpression, scopes));
  }
  if (
    propertyName === "Function" &&
    resolveGlobalObjectName(objectExpression, scopes)
  ) {
    return true;
  }
  return (
    propertyName === "constructor" &&
    globalConstructorValueReference(objectExpression, scopes)
  );
}

function staticallyKnownCallableValueKind(expression, scopes, resolving = new Set()) {
  const value = valueProducingExpression(expression);
  if (!value) return "unknown";

  if (resolveGlobalObjectName(value, scopes)) return "non_callable";

  if (ts.isIdentifier(value)) {
    const name = value.text;
    for (let index = scopes.length - 1; index >= 0; index--) {
      const scope = scopes[index];
      if (
        scope.valueSnapshots?.has(name) &&
        profileHasInheritedConstructor(scope.valueSnapshots.get(name))
      ) {
        return "callable";
      }
      if (scope.valueBindings?.has(name)) {
        return scope.valueBindings.get(name);
      }
      const bindingKind = scope.bindings.get(name);
      if (bindingKind) {
        return bindingKind === "function" || bindingKind === "class"
          ? "callable"
          : "unknown";
      }
    }
    if (
      globalConstructorIdentifierNames.has(name) ||
      isGlobalConstructorAlias(name, scopes)
    ) {
      return "callable";
    }
    return "unknown";
  }

  if (
    ts.isFunctionExpression(value) ||
    ts.isArrowFunction(value) ||
    ts.isClassExpression(value)
  ) {
    return "callable";
  }

  if (
    ts.isObjectLiteralExpression(value) ||
    ts.isArrayLiteralExpression(value) ||
    ts.isNewExpression(value) ||
    ts.isTypeOfExpression(value) ||
    ts.isLiteralExpression(value) ||
    [
      ts.SyntaxKind.NullKeyword,
      ts.SyntaxKind.TrueKeyword,
      ts.SyntaxKind.FalseKeyword,
    ].includes(value.kind)
  ) {
    return "non_callable";
  }

  if (ts.isConditionalExpression(value)) {
    const whenTrue = staticallyKnownCallableValueKind(
      value.whenTrue,
      scopes,
      resolving,
    );
    const whenFalse = staticallyKnownCallableValueKind(
      value.whenFalse,
      scopes,
      resolving,
    );
    return whenTrue === whenFalse && whenTrue !== "unknown"
      ? whenTrue
      : "unknown";
  }

  const access = staticPropertyAccessParts(value);
  if (!access) return "unknown";

  const propertyName = staticPropertyName(access.propertyExpression);
  if (propertyName === "constructor") {
    return staticallyKnownCallableValueKind(
      access.objectExpression,
      scopes,
      resolving,
    ) === "callable"
      ? "callable"
      : "unknown";
  }
  if (propertyName === "prototype") {
    return staticallyKnownCallableValueKind(
      access.objectExpression,
      scopes,
      resolving,
    ) === "callable"
      ? "non_callable"
      : "unknown";
  }
  return globalConstructorValueReference(value, scopes)
    ? "callable"
    : "unknown";
}

function bindingScopeForName(name, scopes) {
  for (let index = scopes.length - 1; index >= 0; index--) {
    if (scopes[index].bindings.has(name)) return scopes[index];
  }
  return null;
}

function recordStaticValueBinding(node, scopes) {
  if (!ts.isVariableDeclaration(node) || !ts.isIdentifier(node.name)) {
    return;
  }
  const scope = bindingScopeForName(node.name.text, scopes);
  if (!scope?.valueBindings) return;

  scope.valueBindings.delete(node.name.text);
  scope.callableBindings.delete(node.name.text);
  scope.valueSnapshots?.delete(node.name.text);
  if (!node.initializer) return;

  const snapshot = staticValueProfile(node.initializer, scopes);
  scope.valueBindings.set(node.name.text, snapshot.kind);
  scope.valueSnapshots?.set(node.name.text, snapshot);
  if (snapshot.kind === "callable") {
    scope.callableBindings.set(node.name.text, node.initializer);
  }
  registerContainerBinding(node.name.text, node.initializer, snapshot, scope, scopes);
  registerContainerMutatorAlias(node.name.text, node.initializer, scope, scopes);
}

function recordStaticValueAssignment(node, scopes) {
  if (
    !ts.isBinaryExpression(node) ||
    node.operatorToken.kind !== ts.SyntaxKind.EqualsToken ||
    !ts.isIdentifier(node.left)
  ) {
    return;
  }
  const scope = bindingScopeForName(node.left.text, scopes);
  if (!scope?.valueBindings) return;

  const snapshot = staticValueProfile(node.right, scopes);
  scope.valueBindings.set(node.left.text, snapshot.kind);
  scope.valueSnapshots?.set(node.left.text, snapshot);
  scope.callableBindings.delete(node.left.text);
  if (snapshot.kind === "callable") {
    scope.callableBindings.set(node.left.text, node.right);
  }
  registerContainerBinding(node.left.text, node.right, snapshot, scope, scopes);
  registerContainerMutatorAlias(node.left.text, node.right, scope, scopes);
}

function recordContainerMutation(node, scopes) {
  if (ts.isBinaryExpression(node) && containerAssignmentOperatorKinds.has(node.operatorToken.kind)) {
    if (!staticPropertyAccessParts(node.left)) return;
    const containerId = containerBaseOfMemberChain(node.left, scopes);
    if (containerId) invalidateContainer(containerId, scopes);
    return;
  }
  if (
    (ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node)) &&
    (node.operator === ts.SyntaxKind.PlusPlusToken ||
      node.operator === ts.SyntaxKind.MinusMinusToken)
  ) {
    if (!staticPropertyAccessParts(node.operand)) return;
    const containerId = containerBaseOfMemberChain(node.operand, scopes);
    if (containerId) invalidateContainer(containerId, scopes);
    return;
  }
  if (ts.isDeleteExpression(node)) {
    if (!staticPropertyAccessParts(node.expression)) return;
    const containerId = containerBaseOfMemberChain(node.expression, scopes);
    if (containerId) invalidateContainer(containerId, scopes);
    return;
  }
  if (ts.isCallExpression(node)) {
    recordContainerMethodMutation(node, scopes);
    recordContainerReflectionMutation(node, scopes);
  }
}

function containerBaseOfMemberChain(node, scopes) {
  let current = node;
  while (true) {
    const access = staticPropertyAccessParts(current);
    if (!access) break;
    current = access.objectExpression;
  }
  const base = valueProducingExpression(current);
  if (ts.isIdentifier(base)) return resolveContainerBinding(base.text, scopes);
  return null;
}

function registerContainerBinding(name, initializer, snapshot, scope, scopes) {
  const value = valueProducingExpression(initializer);
  if (!value) return;
  if (ts.isArrayLiteralExpression(value) || ts.isObjectLiteralExpression(value)) {
    const containerId = nextContainerId(scopes);
    scopes[0].containerRegistry.set(containerId, {
      profile: snapshot,
      invalidated: false,
    });
    scope.containerBindings.set(name, containerId);
    registerContainerDependents(value, containerId, scopes);
    return;
  }
  if (ts.isIdentifier(value)) {
    const target = resolveContainerBinding(value.text, scopes);
    if (target) {
      scope.containerBindings.set(name, target);
      return;
    }
  }
  scope.containerBindings.delete(name);
}

function nextContainerId(scopes) {
  const id = scopes[0].containerNextId;
  scopes[0].containerNextId += 1;
  return id;
}

function resolveContainerBinding(name, scopes) {
  for (let index = scopes.length - 1; index >= 0; index--) {
    if (scopes[index].containerBindings?.has(name)) {
      return scopes[index].containerBindings.get(name);
    }
    if (scopes[index].bindings.has(name)) return null;
  }
  return null;
}

function registerContainerDependents(node, containerId, scopes, visited = new Set()) {
  if (visited.has(node)) return;
  visited.add(node);
  const recordDependency = (expression) => {
    const value = valueProducingExpression(expression);
    if (ts.isIdentifier(value)) {
      const target = resolveContainerBinding(value.text, scopes);
      if (target && target !== containerId) {
        const dependents = scopes[0].containerDependents;
        let set = dependents.get(target);
        if (!set) {
          set = new Set();
          dependents.set(target, set);
        }
        set.add(containerId);
      }
      return;
    }
    if (ts.isArrayLiteralExpression(value) || ts.isObjectLiteralExpression(value)) {
      registerContainerDependents(value, containerId, scopes, visited);
    }
  };
  if (ts.isArrayLiteralExpression(node)) {
    for (const element of node.elements) {
      if (ts.isSpreadElement(element) || ts.isOmittedExpression(element)) continue;
      recordDependency(element);
    }
    return;
  }
  if (ts.isObjectLiteralExpression(node)) {
    for (const property of node.properties) {
      if (ts.isSpreadAssignment(property) || ts.isSpreadElement(property)) continue;
      if (ts.isPropertyAssignment(property)) recordDependency(property.initializer);
      else if (ts.isShorthandPropertyAssignment(property)) recordDependency(property.name);
    }
  }
}

function registerContainerMutatorAlias(name, initializer, scope, scopes) {
  const containerId = mutatorAliasContainer(initializer, scopes);
  if (containerId) {
    scope.containerMutatorAliases.set(name, containerId);
  } else {
    scope.containerMutatorAliases.delete(name);
  }
}

function mutatorAliasContainer(expression, scopes) {
  const value = valueProducingExpression(expression);
  if (!value) return null;
  if (ts.isIdentifier(value)) {
    return resolveContainerMutatorAlias(value.text, scopes);
  }
  const access = staticPropertyAccessParts(value);
  if (access) {
    const methodName = staticPropertyName(access.propertyExpression);
    if (methodName !== null && containerMutatingMethodNames.has(methodName)) {
      const containerId = containerBaseOfMemberChain(access.objectExpression, scopes);
      if (containerId) return containerId;
    }
    return null;
  }
  if (ts.isCallExpression(value) && value.arguments.length > 0) {
    const callee = valueProducingExpression(value.expression);
    if (!callee) return null;
    const bindAccess = staticPropertyAccessParts(callee);
    if (!bindAccess) return null;
    const bindName = staticPropertyName(bindAccess.propertyExpression);
    if (bindName !== "bind" && bindName !== "call" && bindName !== "apply") return null;
    const inner = valueProducingExpression(bindAccess.objectExpression);
    if (ts.isIdentifier(inner)) {
      return resolveContainerMutatorAlias(inner.text, scopes);
    }
    const innerAccess = staticPropertyAccessParts(inner);
    if (!innerAccess) return null;
    const methodName = staticPropertyName(innerAccess.propertyExpression);
    if (methodName === null || !containerMutatingMethodNames.has(methodName)) return null;
    return containerBaseOfMemberChain(innerAccess.objectExpression, scopes);
  }
  return null;
}

function recordContainerMutatorInvocation(node, scopes) {
  if (!ts.isCallExpression(node)) return;
  const callee = valueProducingExpression(node.expression);
  let aliasName = null;
  if (ts.isIdentifier(callee)) {
    aliasName = callee.text;
  } else {
    const access = staticPropertyAccessParts(callee);
    if (access) {
      const invokedName = staticPropertyName(access.propertyExpression);
      if (invokedName !== "call" && invokedName !== "apply" && invokedName !== "bind") return;
      const base = valueProducingExpression(access.objectExpression);
      if (ts.isIdentifier(base)) aliasName = base.text;
    }
  }
  if (!aliasName) return;
  const containerId = resolveContainerMutatorAlias(aliasName, scopes);
  if (containerId) invalidateContainer(containerId, scopes);
}

function resolveContainerMutatorAlias(name, scopes) {
  for (let index = scopes.length - 1; index >= 0; index--) {
    if (scopes[index].containerMutatorAliases?.has(name)) {
      return scopes[index].containerMutatorAliases.get(name);
    }
    if (scopes[index].bindings.has(name)) return null;
  }
  return null;
}

function recordContainerDestructuredMutators(node, scopes) {
  if (!ts.isObjectBindingPattern(node.name)) return;
  const containerId = destructuredMutatorSourceContainer(
    node.initializer,
    scopes,
  );
  if (!containerId) return;
  for (const element of node.name.elements) {
    if (ts.isOmittedExpression(element) || element.dotDotDotToken) continue;
    const propertyName = element.propertyName
      ? staticPropertyName(element.propertyName)
      : ts.isIdentifier(element.name)
        ? element.name.text
        : null;
    if (
      propertyName !== null &&
      containerMutatingMethodNames.has(propertyName) &&
      ts.isIdentifier(element.name)
    ) {
      const scope =
        bindingScopeForName(element.name.text, scopes) ??
        scopes[scopes.length - 1];
      scope.containerMutatorAliases.set(element.name.text, containerId);
    }
  }
}

function destructuredMutatorSourceContainer(expression, scopes) {
  const value = valueProducingExpression(expression);
  if (!value) return null;
  if (ts.isIdentifier(value)) {
    const containerId = resolveContainerBinding(value.text, scopes);
    if (containerId) return containerId;
  }
  return mutatorAliasContainer(expression, scopes);
}

function invalidateContainer(containerId, scopes, visited = new Set()) {
  if (visited.has(containerId)) return;
  visited.add(containerId);
  const state = scopes[0].containerRegistry.get(containerId);
  if (state) state.invalidated = true;
  const dependents = scopes[0].containerDependents.get(containerId);
  if (dependents) {
    for (const dependent of dependents) {
      invalidateContainer(dependent, scopes, visited);
    }
  }
}

function recordContainerMethodMutation(call, scopes) {
  const access = staticPropertyAccessParts(call.expression);
  if (!access) return;
  const containerId = containerBaseOfMemberChain(access.objectExpression, scopes);
  if (!containerId) return;
  const methodName = staticPropertyName(access.propertyExpression);
  if (methodName === null) {
    invalidateContainer(containerId, scopes);
    return;
  }
  if (containerMutatingMethodNames.has(methodName)) {
    invalidateContainer(containerId, scopes);
    return;
  }
  if (!containerReadOnlyMethodNames.has(methodName)) {
    invalidateContainer(containerId, scopes);
  }
}

function recordContainerReflectionMutation(call, scopes) {
  const access = staticPropertyAccessParts(call.expression);
  if (!access) return;
  const receiver = valueProducingExpression(access.objectExpression);
  if (!ts.isIdentifier(receiver)) return;
  const receiverName = receiver.text;
  if (receiverName !== "Object" && receiverName !== "Reflect") return;
  if (isLocallyBound(receiverName, scopes)) return;
  const target = call.arguments[0];
  if (!target) return;
  const containerId = containerBaseOfMemberChain(target, scopes);
  if (!containerId) return;
  const methodName = staticPropertyName(access.propertyExpression);
  if (methodName === null) {
    invalidateContainer(containerId, scopes);
    return;
  }
  if (containerReflectionMutationMethods.has(methodName)) {
    invalidateContainer(containerId, scopes);
    return;
  }
  if (!containerReflectionReadOnlyMethods.has(methodName)) {
    invalidateContainer(containerId, scopes);
  }
}

function destructuringPatternCanReachCallableOrUnknown(
  pattern,
  source,
  scopes,
) {
  return patternProfileCanReachConstructor(
    pattern,
    staticValueProfile(source, scopes),
  );
}

function forOfPatternCanReachCallableOrUnknown(pattern, iterable, scopes) {
  return iterableProfileCanReachConstructor(
    pattern,
    staticValueProfile(iterable, scopes),
  );
}

function iterableProfileCanReachConstructor(pattern, iterableProfile) {
  if (!patternContainsConstructorAccess(pattern)) return false;
  if (iterableProfile.alternatives) {
    return iterableProfile.alternatives.some((profile) =>
      iterableProfileCanReachConstructor(pattern, profile),
    );
  }
  if (iterableProfile.kind !== "non_callable") return true;
  if (!iterableProfile.arrayElements) return !iterableProfile.closedValue;
  if (iterableProfile.arraySpreadIndex !== null) return true;
  return iterableProfile.arrayElements.some((profile) =>
    patternProfileCanReachConstructor(pattern, profile),
  );
}

function staticValueProfile(expression, scopes, resolving = new Set()) {
  const value = valueProducingExpression(expression);
  if (!value) return staticUnknownValueProfile();
  if (resolving.has(value)) return staticUnknownValueProfile();

  const nextResolving = new Set(resolving);
  nextResolving.add(value);

  if (resolveGlobalObjectName(value, scopes)) {
    return staticNonCallableValueProfile({ closedValue: true });
  }

  if (ts.isIdentifier(value)) {
    const name = value.text;
    for (let index = scopes.length - 1; index >= 0; index--) {
      const scope = scopes[index];
      if (scope.containerBindings?.has(name)) {
        const containerId = scope.containerBindings.get(name);
        const state = scopes[0]?.containerRegistry?.get(containerId);
        if (state) {
          if (state.invalidated) return staticUnknownValueProfile();
          return state.profile;
        }
      }
      if (scope.valueSnapshots?.has(name)) {
        return scope.valueSnapshots.get(name);
      }
      if (scope.valueBindings?.has(name)) {
        return staticValueProfileForKind(scope.valueBindings.get(name));
      }
      const bindingKind = scope.bindings.get(name);
      if (bindingKind) {
        return staticValueProfileForKind(
          bindingKind === "function" || bindingKind === "class"
            ? "callable"
            : "unknown",
        );
      }
    }
    if (globalConstructorIdentifierNames.has(name)) {
      return staticCallableValueProfile();
    }
    if (["undefined", "NaN", "Infinity"].includes(name)) {
      return staticNonCallableValueProfile({ closedValue: true });
    }
    return staticUnknownValueProfile();
  }

  if (
    ts.isFunctionExpression(value) ||
    ts.isArrowFunction(value) ||
    ts.isClassExpression(value)
  ) {
    return staticCallableValueProfile();
  }

  if (ts.isArrayLiteralExpression(value)) {
    const elements = [];
    let spreadIndex = null;
    for (const [index, element] of value.elements.entries()) {
      if (ts.isSpreadElement(element)) {
        spreadIndex ??= index;
        elements.push(staticUnknownValueProfile());
      } else if (ts.isOmittedExpression(element)) {
        elements.push(staticNonCallableValueProfile({ closedValue: true }));
      } else {
        elements.push(staticValueProfile(element, scopes, nextResolving));
      }
    }
    return staticNonCallableValueProfile({
      arrayElements: elements,
      arraySpreadIndex: spreadIndex,
      closedValue: true,
    });
  }

  if (ts.isObjectLiteralExpression(value)) {
    const properties = new Map();
    let hasUnknownProperties = false;
    for (const property of value.properties) {
      if (ts.isSpreadAssignment(property) || ts.isSpreadElement(property)) {
        hasUnknownProperties = true;
        continue;
      }
      const propertyName = staticPropertyName(property.name);
      if (propertyName === null) {
        hasUnknownProperties = true;
        continue;
      }
      if (ts.isPropertyAssignment(property)) {
        properties.set(
          propertyName,
          staticValueProfile(property.initializer, scopes, nextResolving),
        );
      } else if (ts.isShorthandPropertyAssignment(property)) {
        properties.set(
          propertyName,
          staticValueProfile(property.name, scopes, nextResolving),
        );
      } else if (ts.isMethodDeclaration(property)) {
        properties.set(propertyName, staticCallableValueProfile());
      } else {
        hasUnknownProperties = true;
      }
    }
    return staticNonCallableValueProfile({
      objectProperties: properties,
      objectHasUnknownProperties: hasUnknownProperties,
      closedValue: !hasUnknownProperties,
    });
  }

  if (ts.isConditionalExpression(value)) {
    return staticValueProfileUnion([
      staticValueProfile(value.whenTrue, scopes, nextResolving),
      staticValueProfile(value.whenFalse, scopes, nextResolving),
    ]);
  }

  const access = staticPropertyAccessParts(value);
  if (access) {
    if (globalConstructorValueReference(value, scopes)) {
      return staticCallableValueProfile();
    }
    return staticValueProfileForProperty(
      staticValueProfile(access.objectExpression, scopes, nextResolving),
      staticPropertyName(access.propertyExpression),
    );
  }

  if (
    ts.isNewExpression(value) ||
    ts.isLiteralExpression(value) ||
    [
      ts.SyntaxKind.NullKeyword,
      ts.SyntaxKind.TrueKeyword,
      ts.SyntaxKind.FalseKeyword,
    ].includes(value.kind)
  ) {
    return staticNonCallableValueProfile({ closedValue: true });
  }

  return staticUnknownValueProfile();
}

function staticValueProfileForKind(kind) {
  if (kind === "callable") return staticCallableValueProfile();
  if (kind === "non_callable") {
    return staticNonCallableValueProfile();
  }
  return staticUnknownValueProfile();
}

function staticCallableValueProfile() {
  return Object.freeze({ kind: "callable" });
}

function staticUnknownValueProfile() {
  return Object.freeze({ kind: "unknown" });
}

function staticNonCallableValueProfile(details = {}) {
  return Object.freeze({ kind: "non_callable", ...details });
}

function staticInheritedConstructorValueProfile() {
  return staticNonCallableValueProfile({
    closedValue: true,
    inheritedConstructor: true,
  });
}

function profileHasInheritedConstructor(profile) {
  if (profile?.inheritedConstructor) return true;
  return Boolean(
    profile?.alternatives?.some((alternative) =>
      profileHasInheritedConstructor(alternative),
    ),
  );
}

function staticValueProfileUnion(profiles) {
  const firstKind = profiles[0]?.kind ?? "unknown";
  const kind =
    firstKind !== "unknown" && profiles.every((profile) => profile.kind === firstKind)
      ? firstKind
      : "unknown";
  return Object.freeze({ kind, alternatives: Object.freeze(profiles) });
}

function staticValueProfileForProperty(objectProfile, propertyName) {
  if (objectProfile.alternatives) {
    return staticValueProfileUnion(
      objectProfile.alternatives.map((profile) =>
        staticValueProfileForProperty(profile, propertyName),
      ),
    );
  }
  if (propertyName === null) return staticUnknownValueProfile();

  if (objectProfile.objectProperties?.has(propertyName)) {
    return objectProfile.objectProperties.get(propertyName);
  }

  if (objectProfile.arrayElements && /^(?:0|[1-9][0-9]*)$/u.test(propertyName)) {
    return staticArrayElementProfile(objectProfile, Number(propertyName));
  }

  if (propertyName === "constructor") {
    if (objectProfile.kind === "callable") {
      return staticCallableValueProfile();
    }
    if (objectProfile.kind === "unknown") {
      return staticUnknownValueProfile();
    }
    if (objectProfile.arrayElements || objectProfile.closedValue) {
      return staticInheritedConstructorValueProfile();
    }
  }

  if (objectProfile.kind === "unknown") {
    return staticUnknownValueProfile();
  }
  if (objectProfile.objectHasUnknownProperties) {
    return staticUnknownValueProfile();
  }
  if (objectProfile.closedValue) {
    return staticNonCallableValueProfile({ closedValue: true });
  }
  return staticUnknownValueProfile();
}

function staticArrayElementProfile(arrayProfile, index) {
  if (
    arrayProfile.arraySpreadIndex !== null &&
    index >= arrayProfile.arraySpreadIndex
  ) {
    return staticUnknownValueProfile();
  }
  return (
    arrayProfile.arrayElements[index] ??
    staticNonCallableValueProfile({ closedValue: true })
  );
}

function patternProfileCanReachConstructor(pattern, sourceProfile) {
  if (!patternContainsConstructorAccess(pattern)) return false;

  if (sourceProfile.alternatives) {
    return sourceProfile.alternatives.some((profile) =>
      patternProfileCanReachConstructor(pattern, profile),
    );
  }

  if (sourceProfile.kind !== "non_callable") return true;

  if (ts.isArrayBindingPattern(pattern) || ts.isArrayLiteralExpression(pattern)) {
    if (!sourceProfile.arrayElements) return !sourceProfile.closedValue;
    let sourceIndex = 0;
    for (const element of pattern.elements) {
      if (ts.isOmittedExpression(element)) {
        sourceIndex += 1;
        continue;
      }
      if (ts.isSpreadElement(element) || element.dotDotDotToken) {
        return arrayRestCanReachConstructor(sourceProfile, sourceIndex);
      }
      const childPattern = ts.isBindingElement(element) ? element.name : element;
      if (
        patternProfileCanReachConstructor(
          childPattern,
          staticArrayElementProfile(sourceProfile, sourceIndex),
        )
      ) {
        return true;
      }
      sourceIndex += 1;
    }
    return false;
  }

  if (ts.isObjectBindingPattern(pattern) || ts.isObjectLiteralExpression(pattern)) {
    const elements = ts.isObjectBindingPattern(pattern)
      ? pattern.elements
      : pattern.properties;
    for (const element of elements) {
      if (ts.isSpreadAssignment(element) || ts.isSpreadElement(element)) {
        if (objectRestCanReachConstructor(sourceProfile)) return true;
        continue;
      }

      let propertyName;
      let childPattern;
      if (ts.isBindingElement(element)) {
        propertyName = element.propertyName
          ? staticPropertyName(element.propertyName)
          : ts.isIdentifier(element.name)
            ? element.name.text
            : null;
        childPattern = element.name;
      } else if (ts.isShorthandPropertyAssignment(element)) {
        propertyName = element.name.text;
        childPattern = element.name;
      } else if (ts.isPropertyAssignment(element)) {
        propertyName = staticPropertyName(element.name);
        childPattern = element.initializer;
      } else {
        propertyName = staticPropertyName(element.name);
        childPattern = element;
      }

      if (propertyName === null) return true;
      const childProfile = staticValueProfileForProperty(
        sourceProfile,
        propertyName,
      );
      if (isDestructuringPatternNode(childPattern)) {
        if (patternProfileCanReachConstructor(childPattern, childProfile)) {
          return true;
        }
      } else if (
        propertyName === "constructor" &&
        profileIsCallableOrUnknown(childProfile)
      ) {
        return true;
      }
    }
  }

  return false;
}

function patternContainsConstructorAccess(pattern) {
  if (ts.isArrayBindingPattern(pattern) || ts.isArrayLiteralExpression(pattern)) {
    return pattern.elements.some((element) => {
      if (ts.isOmittedExpression(element)) return false;
      if (ts.isSpreadElement(element) || element.dotDotDotToken) return true;
      return patternContainsConstructorAccess(
        ts.isBindingElement(element) ? element.name : element,
      );
    });
  }

  if (ts.isObjectBindingPattern(pattern)) {
    return pattern.elements.some((element) => {
      if (element.dotDotDotToken) return true;
      const propertyName = element.propertyName
        ? staticPropertyName(element.propertyName)
        : ts.isIdentifier(element.name)
          ? element.name.text
          : null;
      return (
        propertyName === null ||
        propertyName === "constructor" ||
        patternContainsConstructorAccess(element.name)
      );
    });
  }

  if (ts.isObjectLiteralExpression(pattern)) {
    return pattern.properties.some((property) => {
      if (ts.isSpreadAssignment(property) || ts.isSpreadElement(property)) {
        return true;
      }
      if (ts.isShorthandPropertyAssignment(property)) {
        return property.name.text === "constructor";
      }
      if (!ts.isPropertyAssignment(property)) return false;
      const propertyName = staticPropertyName(property.name);
      return (
        propertyName === null ||
        propertyName === "constructor" ||
        patternContainsConstructorAccess(property.initializer)
      );
    });
  }

  return false;
}

function isDestructuringPatternNode(node) {
  return (
    ts.isObjectBindingPattern(node) ||
    ts.isArrayBindingPattern(node) ||
    ts.isObjectLiteralExpression(node) ||
    ts.isArrayLiteralExpression(node)
  );
}

function profileIsCallableOrUnknown(profile) {
  if (profile.alternatives) {
    return profile.alternatives.some(profileIsCallableOrUnknown);
  }
  return profile.kind !== "non_callable";
}

function arrayRestCanReachConstructor(arrayProfile, startIndex) {
  if (arrayProfile.kind !== "non_callable") return true;
  if (!arrayProfile.arrayElements) return !arrayProfile.closedValue;
  if (
    arrayProfile.arraySpreadIndex !== null &&
    arrayProfile.arraySpreadIndex <= startIndex
  ) {
    return true;
  }
  for (let index = startIndex; index < arrayProfile.arrayElements.length; index++) {
    if (profileIsCallableOrUnknown(arrayProfile.arrayElements[index])) {
      return true;
    }
  }
  return false;
}

function objectRestCanReachConstructor(objectProfile) {
  if (objectProfile.kind !== "non_callable") return true;
  if (objectProfile.objectHasUnknownProperties) return true;
  if (!objectProfile.closedValue && !objectProfile.objectProperties) return true;
  return profileIsCallableOrUnknown(
    objectProfile.objectProperties?.get("constructor") ??
      staticNonCallableValueProfile({ closedValue: true }),
  );
}

function isDiscardedSequenceOperand(node) {
  let current = node;
  while (current?.parent) {
    const parent = current.parent;
    if (
      (ts.isParenthesizedExpression(parent) ||
        ts.isNonNullExpression(parent) ||
        ts.isAsExpression(parent) ||
        ts.isTypeAssertionExpression(parent) ||
        ts.isSatisfiesExpression(parent)) &&
      parent.expression === current
    ) {
      current = parent;
      continue;
    }
    if (
      ts.isBinaryExpression(parent) &&
      parent.operatorToken.kind === ts.SyntaxKind.CommaToken &&
      parent.left === current
    ) {
      return true;
    }
    return false;
  }
  return false;
}
function staticPropertyAccessParts(node) {
  if (
    ts.isPropertyAccessExpression(node) ||
    ts.isPropertyAccessChain(node)
  ) {
    return {
      objectExpression: node.expression,
      propertyExpression: node.name,
    };
  }
  if (
    ts.isElementAccessExpression(node) ||
    (typeof ts.isElementAccessChain === "function" &&
      ts.isElementAccessChain(node))
  ) {
    return {
      objectExpression: node.expression,
      propertyExpression: node.argumentExpression,
    };
  }
  return null;
}

function globalConstructorValueReference(expression, scopes) {
  expression = valueProducingExpression(expression);
  if (!expression) return false;

  if (ts.isIdentifier(expression)) {
    if (isLocallyBound(expression.text, scopes)) {
      return isGlobalConstructorAlias(expression.text, scopes);
    }
    return globalConstructorIdentifierNames.has(expression.text);
  }

  const access = staticPropertyAccessParts(expression);
  if (!access) return false;
  const objectReference = access.objectExpression;
  const propertyName = staticPropertyName(access.propertyExpression);
  if (propertyName === "constructor") {
    return (
      Boolean(resolveGlobalObjectName(objectReference, scopes)) ||
      globalConstructorValueReference(objectReference, scopes)
    );
  }
  return (
    Boolean(resolveGlobalObjectName(objectReference, scopes)) &&
    propertyName !== null &&
    globalConstructorIdentifierNames.has(propertyName)
  );
}

function isGlobalConstructorAlias(name, scopes) {
  for (let i = scopes.length - 1; i >= 0; i--) {
    if (scopes[i].globalConstructorAliases?.has(name)) return true;
    if (scopes[i].bindings.has(name)) return false;
  }
  return false;
}

function recordGlobalConstructorAlias(node, scopes) {
  const currentScope = scopes[scopes.length - 1];
  if (ts.isIdentifier(node.name)) {
    if (globalConstructorValueReference(node.initializer, scopes)) {
      currentScope.globalConstructorAliases.add(node.name.text);
    }
    return;
  }
  if (
    (ts.isObjectBindingPattern(node.name) ||
      ts.isArrayBindingPattern(node.name)) &&
    isDirectGlobalObjectReference(node.initializer, scopes)
  ) {
    recordGlobalConstructorBindingPattern(node.name, currentScope);
  }
}

function recordGlobalConstructorBindingPattern(pattern, scope) {
  if (!ts.isObjectBindingPattern(pattern)) return;
  for (const element of pattern.elements) {
    if (ts.isOmittedExpression(element) || element.dotDotDotToken) continue;
    const propertyName =
      element.propertyName && staticPropertyName(element.propertyName);
    const sourceName =
      propertyName ||
      (ts.isIdentifier(element.name) ? element.name.text : null);
    if (
      sourceName === null ||
      (!globalConstructorIdentifierNames.has(sourceName) &&
        sourceName !== "constructor")
    ) {
      continue;
    }
    addBindingPatternNamesToSet(element.name, scope.globalConstructorAliases);
  }
}

function addBindingPatternNamesToSet(pattern, target) {
  if (ts.isIdentifier(pattern)) {
    target.add(pattern.text);
    return;
  }
  if (
    ts.isObjectBindingPattern(pattern) ||
    ts.isArrayBindingPattern(pattern)
  ) {
    for (const element of pattern.elements) {
      if (!ts.isOmittedExpression(element) && !element.dotDotDotToken) {
        addBindingPatternNamesToSet(element.name, target);
      }
    }
  }
}

function bindingPatternCanReachDynamicConstructor(pattern) {
  if (ts.isArrayBindingPattern(pattern) || ts.isArrayLiteralExpression(pattern)) {
    return true;
  }

  const elements =
    ts.isObjectBindingPattern(pattern) || ts.isArrayBindingPattern(pattern)
      ? pattern.elements
      : null;
  if (elements) {
    for (const element of elements) {
      if (ts.isOmittedExpression(element) || element.dotDotDotToken) return true;
      if (
        element.propertyName &&
        staticPropertyName(element.propertyName) === null
      ) {
        return true;
      }
      if (
        (element.propertyName &&
          staticPropertyName(element.propertyName) === "Function") ||
        (!element.propertyName &&
          ts.isIdentifier(element.name) &&
          element.name.text === "Function")
      ) {
        return true;
      }
      if (
        (ts.isObjectBindingPattern(element.name) ||
          ts.isArrayBindingPattern(element.name)) &&
        bindingPatternCanReachDynamicConstructor(element.name)
      ) {
        return true;
      }
    }
    return false;
  }

  if (ts.isObjectLiteralExpression(pattern)) {
    for (const property of pattern.properties) {
      if (ts.isSpreadAssignment(property)) return true;
      if (ts.isShorthandPropertyAssignment(property)) {
        if (staticPropertyName(property.name) === "Function") return true;
        continue;
      }
      if (!ts.isPropertyAssignment(property)) continue;
      const propertyName = staticPropertyName(property.name);
      if (propertyName === null || propertyName === "Function") return true;
      if (
        isAssignmentDestructuringPattern(property.initializer) &&
        bindingPatternCanReachDynamicConstructor(property.initializer)
      ) {
        return true;
      }
    }
  }
  return false;
}

function reflectiveDynamicConstructorAcquisition(call, scopes) {
  if (
    !ts.isPropertyAccessExpression(call.expression) &&
    !ts.isPropertyAccessChain(call.expression)
  ) {
    return false;
  }

  const receiver = call.expression.expression;
  const method = call.expression.name.text;
  const receiverName =
    ts.isIdentifier(receiver) && !isLocallyBound(receiver.text, scopes)
      ? receiver.text
      : null;
  if (
    !receiverName ||
    !(
      (receiverName === "Reflect" &&
        ["get", "getOwnPropertyDescriptor"].includes(method)) ||
      (receiverName === "Object" &&
        ["getOwnPropertyDescriptor", "getOwnPropertyDescriptors"].includes(
          method,
        ))
    )
  ) {
    return false;
  }

  const target = call.arguments[0];
  if (!target || !resolveGlobalObjectName(target, scopes)) return false;
  if (call.arguments.length < 2) return true;
  const propertyName = staticPropertyName(call.arguments[1]);
  return propertyName === null || propertyName === "Function";
}

function rejectUnboundGlobalProcessAuthority(sourceFile) {
  const reject = (node) => {
    throw new RuntimeGrantContractError("runtime_grant_inventory_unclassified");
  };
  const rootScope = {
    bindings: new Map(),
    globalAliases: new Set(),
    callableBindings: new Map(),
    node: null,
    varScope: null,
  };
  rootScope.varScope = rootScope;
  addModuleScopeDeclarations(sourceFile, rootScope);

  const scopes = [rootScope];
  const visit = (node) => {
    if (
      isRuntimeValueIdentifierReferenceForName(
        node,
        scopes,
        processIdentifierNames,
    )
      && unboundProcessReferenceIsAuthority(node)
    ) {
      reject(node);
    }

    if (
      (ts.isPropertyAccessExpression(node) ||
        ts.isPropertyAccessChain(node)) &&
      node.name.text === "process" &&
      resolveGlobalObjectName(node.expression, scopes)
    ) {
      reject(node);
    }

    if (
      ts.isElementAccessExpression(node) &&
      resolveGlobalObjectName(node.expression, scopes) &&
      globalObjectElementCanReachProcess(node)
    ) {
      throw new RuntimeGrantContractError(
        "runtime_grant_inventory_unclassified",
      );
    }

    if (ts.isVariableDeclaration(node) && node.initializer) {
      if (
        (ts.isObjectBindingPattern(node.name) ||
          ts.isArrayBindingPattern(node.name)) &&
        isDirectGlobalObjectReference(node.initializer, scopes) &&
        bindingPatternCanReachProcess(node.name)
      ) {
        reject(node);
      }
      checkGlobalObjectAlias(node, scopes);
    }

    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      isAssignmentDestructuringPattern(node.left) &&
      isDirectGlobalObjectReference(node.right, scopes) &&
      bindingPatternCanReachProcess(node.left)
    ) {
      reject(node);
    }

    if (
      ts.isCallExpression(node) &&
      reflectiveProcessAcquisition(node, scopes)
    ) {
      throw new RuntimeGrantContractError(
        "runtime_grant_inventory_unclassified",
      );
    }

    const isScope = isScopeNode(node);
    if (isScope) {
      const newScope = {
        bindings: new Map(),
        globalAliases: new Set(),
        callableBindings: new Map(),
        node,
        varScope: null,
      };
      newScope.varScope =
        scopes[scopes.length - 1].varScope || scopes[scopes.length - 1];
      addNodeScopeDeclarations(node, newScope);
      scopes.push(newScope);
    }

    ts.forEachChild(node, visit);

    if (isScope) {
      scopes.pop();
    }
  };

  visit(sourceFile);
}

function unboundProcessReferenceIsAuthority(node) {
  const parent = node.parent;
  if (!parent) return true;

  if (
    (ts.isPropertyAccessExpression(parent) ||
      ts.isPropertyAccessChain(parent)) &&
    parent.expression === node
  ) {
    return parent.name.text === "getBuiltinModule";
  }

  if (ts.isElementAccessExpression(parent) && parent.expression === node) {
    return true;
  }

  if (ts.isTypeOfExpression(parent)) return false;
  return true;
}

function globalObjectElementCanReachProcess(node) {
  if (!node.argumentExpression) return true;
  const argument = valueProducingExpression(node.argumentExpression);
  return !ts.isStringLiteral(argument) || argument.text === "process";
}

function bindingPatternCanReachProcess(pattern) {
  if (ts.isArrayBindingPattern(pattern)) return true;
  if (ts.isArrayLiteralExpression(pattern)) return true;
  if (ts.isObjectLiteralExpression(pattern)) {
    for (const property of pattern.properties) {
      if (ts.isSpreadAssignment(property)) return true;
      if (ts.isShorthandPropertyAssignment(property)) {
        if (property.name.text === "process") return true;
        continue;
      }
      if (!ts.isPropertyAssignment(property)) continue;
      const propertyName = staticPropertyName(property.name);
      if (propertyName === null || propertyName === "process") return true;
      if (isAssignmentDestructuringPattern(property.initializer) &&
          bindingPatternCanReachProcess(property.initializer)) {
        return true;
      }
    }
    return false;
  }
  for (const element of pattern.elements) {
    if (ts.isOmittedExpression(element)) continue;
    if (element.dotDotDotToken) return true;
    if (element.propertyName && staticPropertyName(element.propertyName) === null) {
      return true;
    }
    if (element.propertyName && staticPropertyName(element.propertyName) === "process") {
      return true;
    }
    if (
      !element.propertyName &&
      ts.isIdentifier(element.name) &&
      element.name.text === "process"
    ) {
      return true;
    }
    if (
      (ts.isObjectBindingPattern(element.name) ||
        ts.isArrayBindingPattern(element.name)) &&
      bindingPatternCanReachProcess(element.name)
    ) {
      return true;
    }
  }
  return false;
}

function isAssignmentDestructuringPattern(node) {
  return ts.isObjectLiteralExpression(node) || ts.isArrayLiteralExpression(node);
}

function staticPropertyName(node) {
  if (!node) return null;
  if (ts.isIdentifier(node) || ts.isStringLiteral(node) || ts.isNumericLiteral(node)) {
    return node.text;
  }
  const expression = ts.isComputedPropertyName(node) ? node.expression : node;
  return staticStringValue(expression);
}

function staticStringValue(expression) {
  const value = valueProducingExpression(expression);
  if (ts.isStringLiteral(value) || ts.isNoSubstitutionTemplateLiteral(value)) {
    return value.text;
  }
  if (
    ts.isBinaryExpression(value) &&
    value.operatorToken.kind === ts.SyntaxKind.PlusToken
  ) {
    const left = staticStringValue(value.left);
    const right = staticStringValue(value.right);
    return left !== null && right !== null ? left + right : null;
  }
  if (ts.isTemplateExpression(value)) {
    let result = value.head.text;
    for (const span of value.templateSpans) {
      const expressionValue = staticStringValue(span.expression);
      if (expressionValue === null) return null;
      result += expressionValue + span.literal.text;
    }
    return result;
  }
  return null;
}

function reflectiveProcessAcquisition(call, scopes) {
  if (!ts.isPropertyAccessExpression(call.expression) &&
      !ts.isPropertyAccessChain(call.expression)) {
    return false;
  }

  const receiver = call.expression.expression;
  const method = call.expression.name.text;
  const receiverName =
    ts.isIdentifier(receiver) && !isLocallyBound(receiver.text, scopes)
      ? receiver.text
      : null;
  if (!receiverName ||
      !((receiverName === "Reflect" &&
        ["get", "getOwnPropertyDescriptor"].includes(method)) ||
        (receiverName === "Object" &&
          ["getOwnPropertyDescriptor", "getOwnPropertyDescriptors"].includes(method)))) {
    return false;
  }

  const target = call.arguments[0];
  if (!target || !resolveGlobalObjectName(target, scopes)) return false;
  if (call.arguments.length < 2) return true;
  const property = valueProducingExpression(call.arguments[1]);
  return !ts.isStringLiteral(property) || property.text === "process";
}

function resolveInternalModulePath(sourcePath, moduleName) {
  const resolved = normalizePath(
    path.posix.normalize(
      path.posix.join(path.posix.dirname(sourcePath), moduleName),
    ),
  );
  if (resolved.endsWith(".js")) {
    return `${resolved.slice(0, -3)}.ts`;
  }
  if (resolved.endsWith(".ts")) {
    return resolved;
  }
  throw new RuntimeGrantContractError(
    "runtime_grant_inventory_unclassified",
  );
}

function externalPackageName(moduleName) {
  if (
    !moduleName ||
    moduleName.startsWith("/") ||
    moduleName.startsWith("#") ||
    moduleName.includes("\\") ||
    moduleName.includes(":")
  ) {
    throw new RuntimeGrantContractError(
      "runtime_grant_inventory_unclassified",
    );
  }
  const parts = moduleName.split("/");
  const packageName = moduleName.startsWith("@")
    ? parts.slice(0, 2).join("/")
    : parts[0];
  if (
    !packageName ||
    (moduleName.startsWith("@") && parts.length < 2)
  ) {
    throw new RuntimeGrantContractError(
      "runtime_grant_inventory_unclassified",
    );
  }
  return packageName;
}

function databaseExternalImportKeyFromReference(
  sourcePath,
  moduleName,
  reference,
) {
  if (
    reference.kind !== "import" ||
    !ts.isImportDeclaration(reference.statement)
  ) {
    return `${sourcePath}\u0000${moduleName}\u0000unsupported`;
  }
  const bindings = runtimeImportBindings(reference.statement);
  return databaseExternalImportKey(
    sourcePath,
    moduleName,
    bindings.map((binding) => binding.exported),
    bindings,
  );
}

function builtInImportKeyFromReference(
  sourcePath,
  moduleName,
  reference,
) {
  if (
    reference.kind !== "import" ||
    !ts.isImportDeclaration(reference.statement)
  ) {
    return `${sourcePath}\u0000${moduleName}\u0000${reference.kind}\u0000unsupported`;
  }
  return builtInImportKey(
    sourcePath,
    moduleName,
    reference.kind,
    runtimeImportBindings(reference.statement),
  );
}

function builtInImportKey(
  sourcePath,
  moduleName,
  importKind,
  bindings,
) {
  const signature = bindings
    .map(
      (binding) =>
        `${binding.kind}:${binding.exported}:${binding.local}`,
    )
    .sort(compare)
    .join(",");
  return `${sourcePath}\u0000${moduleName}\u0000${importKind}\u0000${signature}`;
}

function namedBuiltInBinding(exported, local = exported) {
  return Object.freeze({
    exported,
    local,
    kind: "named",
  });
}

function builtInImportAuthorityRecord({
  sourcePath,
  moduleName,
  capability,
  bindings,
  sourceShapeDigest = null,
}) {
  if (!builtInCapabilityClassifications.has(capability)) {
    throw new RuntimeGrantContractError(
      "runtime_grant_inventory_unclassified",
    );
  }
  if (
    capability === "network" &&
    !/^[a-f0-9]{64}$/u.test(sourceShapeDigest ?? "")
  ) {
    throw new RuntimeGrantContractError(
      "runtime_grant_inventory_unclassified",
    );
  }
  if (capability !== "network" && sourceShapeDigest !== null) {
    throw new RuntimeGrantContractError(
      "runtime_grant_inventory_unclassified",
    );
  }
  return Object.freeze({
    sourcePath,
    moduleName,
    importKind: "import",
    bindings: Object.freeze([...bindings]),
    capability,
    sourceShapeDigest,
  });
}

function globalNetworkCapabilityKey(record) {
  return [
    record.sourcePath,
    record.primitive,
    record.globalObjectForm,
    record.acquisitionForm,
    record.localBinding ?? "",
  ].join("\u0000");
}

function assertGlobalNetworkCapabilityEquality(
  observed,
  expected,
) {
  assertExactAuthoritySet(observed, new Set([...expected.keys()]));
}

function databaseExternalImportKey(
  sourcePath,
  moduleName,
  exportedNames,
  bindings = exportedNames.map((name) => ({
    exported: name,
    local: name,
    kind: "named",
  })),
) {
  const signature = bindings
    .map(
      (binding) =>
        `${binding.kind}:${binding.exported}:${binding.local}`,
    )
    .sort(compare)
    .join(",");
  return `${sourcePath}\u0000${moduleName}\u0000${signature}`;
}

function runtimeImportBindings(statement) {
  const importClause = statement.importClause;
  if (!importClause) {
    return [{ exported: "", local: "", kind: "side_effect" }];
  }
  const bindings = [];
  if (importClause.name) {
    bindings.push({
      exported: "default",
      local: importClause.name.text,
      kind: "default",
    });
  }
  const namedBindings = importClause.namedBindings;
  if (namedBindings && ts.isNamespaceImport(namedBindings)) {
    bindings.push({
      exported: "*",
      local: namedBindings.name.text,
      kind: "namespace",
    });
  } else if (namedBindings) {
    for (const element of namedBindings.elements) {
      if (element.isTypeOnly) {
        continue;
      }
      bindings.push({
        exported: element.propertyName?.text ?? element.name.text,
        local: element.name.text,
        kind: "named",
      });
    }
  }
  return bindings;
}

function hasRuntimeExport(statement) {
  if (statement.isTypeOnly) {
    return false;
  }
  const exportClause = statement.exportClause;
  if (!exportClause || ts.isNamespaceExport(exportClause)) {
    return true;
  }
  return exportClause.elements.some((element) => !element.isTypeOnly);
}

function internalImportKey(sourcePath, targetPath) {
  return `${sourcePath}\u0000${targetPath}`;
}

function parseJsonObject(source) {
  try {
    return plainRecord(JSON.parse(source));
  } catch {
    throw new RuntimeGrantContractError(
      "runtime_grant_inventory_unclassified",
    );
  }
}

function plainRecord(value) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value)
  ) {
    throw new RuntimeGrantContractError(
      "runtime_grant_inventory_unclassified",
    );
  }
  return value;
}

function stringRecord(value) {
  const record = plainRecord(value);
  if (
    Object.values(record).some(
      (entry) => typeof entry !== "string",
    )
  ) {
    throw new RuntimeGrantContractError(
      "runtime_grant_inventory_unclassified",
    );
  }
  return record;
}

function assertExactStringRecord(observed, expected) {
  const observedEntries = Object.entries(observed).sort(
    ([left], [right]) => compare(left, right),
  );
  const expectedEntries = Object.entries(expected).sort(
    ([left], [right]) => compare(left, right),
  );
  if (JSON.stringify(observedEntries) !== JSON.stringify(expectedEntries)) {
    throw new RuntimeGrantContractError(
      "runtime_grant_inventory_unclassified",
    );
  }
}

function assertExactAuthoritySet(observed, expected) {
  const observedValues = [...observed].sort(compare);
  const expectedValues = [...expected].sort(compare);
  if (
    JSON.stringify(observedValues) !== JSON.stringify(expectedValues)
  ) {
    throw new RuntimeGrantContractError(
      "runtime_grant_inventory_unclassified",
    );
  }
}

function assertExactBuiltInImportAuthority(observed) {
  const observedValues = [...observed].sort(compare);
  const expectedValues = [...builtInImportAuthority.keys()].sort(compare);
  if (
    JSON.stringify(observedValues) !== JSON.stringify(expectedValues)
  ) {
    throw new RuntimeGrantContractError(
      "runtime_grant_inventory_unclassified",
    );
  }
}

export function sourceShapeDigest(source) {
  const normalizedSource = source.replace(/\r\n?/gu, "\n");
  const scanner = ts.createScanner(
    ts.ScriptTarget.Latest,
    true,
    ts.LanguageVariant.Standard,
    normalizedSource,
  );
  const tokens = [];
  for (
    let token = scanner.scan();
    token !== ts.SyntaxKind.EndOfFileToken;
    token = scanner.scan()
  ) {
    tokens.push(`${token}:${scanner.getTokenText()}`);
  }
  return sha256(tokens.join("\n"));
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort(compare)
      .map(
        (key) =>
          `${JSON.stringify(key)}:${canonicalJson(value[key])}`,
      )
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function isDatabaseAccessCandidate(sourceFile) {
  let candidate = false;
  const valueImports = new Set();

  for (const statement of sourceFile.statements) {
    if (
      !ts.isImportDeclaration(statement) ||
      !ts.isStringLiteral(statement.moduleSpecifier) ||
      !hasRuntimeImport(statement)
    ) {
      continue;
    }
    const moduleName = statement.moduleSpecifier.text;
    if (databaseModule(moduleName)) {
      candidate = true;
    }
    for (const name of importedValueNames(statement)) {
      valueImports.add(name);
    }
  }

  const visit = (node) => {
    if (
      ts.isTaggedTemplateExpression(node) &&
      ts.isIdentifier(node.tag) &&
      node.tag.text === "sql"
    ) {
      candidate = true;
    }
    if (
      ts.isNewExpression(node) &&
      ts.isIdentifier(node.expression) &&
      valueImports.has(node.expression.text) &&
      /^(?:Pool|Client)$/u.test(node.expression.text)
    ) {
      candidate = true;
    }
    if (ts.isCallExpression(node)) {
      if (
        ts.isIdentifier(node.expression) &&
        valueImports.has(node.expression.text) &&
        /^(?:drizzle|createDatabase|createDrizzle|assertRuntimeDatabase|inspectRuntimeDatabase)/u.test(
          node.expression.text,
        )
      ) {
        candidate = true;
      }
      const method = callMethodName(node.expression);
      if (
        method &&
        databaseCandidateMethods.has(method) &&
        (
          ["query", "execute", "select", "insert", "delete", "transaction"]
            .includes(method) ||
          databaseRootIdentifier(node.expression)
        )
      ) {
        candidate = true;
      }
      if (
        ts.isElementAccessExpression(node.expression) &&
        databaseRootIdentifier(node.expression.expression)
      ) {
        candidate = true;
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return candidate;
}

function databaseModule(moduleName) {
  return (
    moduleName === "pg" ||
    moduleName === "drizzle-orm" ||
    moduleName.startsWith("drizzle-orm/") ||
    /(?:^|\/)db\/(?:client|runtime-posture|schema|repositories|[a-z0-9-]+-repository)\.js$/u.test(
      moduleName,
    ) ||
    moduleName === "./schema.js"
  );
}

function hasRuntimeImport(statement) {
  const importClause = statement.importClause;
  if (!importClause) {
    return true;
  }
  if (importClause.isTypeOnly) {
    return false;
  }
  if (importClause.name) {
    return true;
  }
  const bindings = importClause.namedBindings;
  if (ts.isNamespaceImport(bindings)) {
    return true;
  }
  return Boolean(
    bindings?.elements.some((element) => !element.isTypeOnly),
  );
}

function importedValueNames(statement) {
  const names = [];
  const importClause = statement.importClause;
  if (!importClause || importClause.isTypeOnly) {
    return names;
  }
  if (importClause.name) {
    names.push(importClause.name.text);
  }
  const bindings = importClause.namedBindings;
  if (ts.isNamespaceImport(bindings)) {
    names.push(bindings.name.text);
  } else if (bindings) {
    for (const element of bindings.elements) {
      if (!element.isTypeOnly) {
        names.push(element.name.text);
      }
    }
  }
  return names;
}

async function productionSourcePaths(sourceOverrides) {
  const paths = await listTypeScriptFiles(productionSourceDirectory);
  for (const sourcePath of sourceOverrides.keys()) {
    if (
      sourcePath.startsWith(`${productionSourceDirectory}/`) &&
      sourcePath.endsWith(".ts")
    ) {
      paths.push(sourcePath);
    }
  }
  return [...new Set(paths)]
    .filter((sourcePath) => !excludedProductionSurface(sourcePath))
    .sort(compare);
}

async function listTypeScriptFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const filePath = normalizePath(`${directory}/${entry.name}`);
    if (entry.isDirectory()) {
      files.push(...(await listTypeScriptFiles(filePath)));
    } else if (entry.isFile() && entry.name.endsWith(".ts")) {
      files.push(filePath);
    }
  }
  return files;
}

function excludedProductionSurface(sourcePath) {
  return (
    /(?:^|\/)(?:__fixtures__|__tests__|fixtures|generated|tests)(?:\/|$)/u.test(
      sourcePath,
    ) || /\.test\.ts$/u.test(sourcePath)
  );
}

function normalizeSourceOverrides(sourceOverrides) {
  return new Map(
    [...sourceOverrides].map(([filePath, source]) => [
      normalizePath(filePath),
      source,
    ]),
  );
}

function parseSourceFile(filePath, source, errorCode) {
  const sourceFile = ts.createSourceFile(
    filePath,
    source,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  if (sourceFile.parseDiagnostics.length > 0) {
    throw new RuntimeGrantContractError(errorCode);
  }
  return sourceFile;
}

function detectGlobalNetworkCapabilities(sourcePath, sourceFile) {
  const observedKeys = new Map();
  const rootScope = { bindings: new Map(), globalAliases: new Set(), callableBindings: new Map(), node: null, varScope: null };
  rootScope.varScope = rootScope;
  const scopes = [rootScope];

  addModuleScopeDeclarations(sourceFile, rootScope);

  walkNetworkCapabilityNodes(sourcePath, sourceFile, scopes, observedKeys);

  for (const [key, observed] of observedKeys) {
    if (
      observed.acquisitionForm === "const_binding" &&
      observed.localBinding
    ) {
      observed.referenceCount = countBindingCallSites(
        sourceFile,
        observed.localBinding,
      );
    }
  }

  return observedKeys;
}

function addModuleScopeDeclarations(sourceFile, scope) {
  for (const statement of sourceFile.statements) {
    addStatementDeclarations(statement, scope, scope);
  }
}

function addDeclarationBindings(declaration, bindings) {
  collectBindingNames(declaration.name, bindings, "variable");
}

function collectBindingNames(nameNode, bindings, kind) {
  if (!nameNode) return;
  if (ts.isIdentifier(nameNode)) {
    bindings.set(nameNode.text, kind);
  } else if (ts.isObjectBindingPattern(nameNode)) {
    for (const element of nameNode.elements) {
      if (ts.isOmittedExpression(element)) continue;
      if (ts.isIdentifier(element.name)) {
        bindings.set(element.name.text, kind);
      } else if (ts.isObjectBindingPattern(element.name) || ts.isArrayBindingPattern(element.name)) {
        collectBindingNames(element.name, bindings, kind);
      }
    }
  } else if (ts.isArrayBindingPattern(nameNode)) {
    for (const element of nameNode.elements) {
      if (ts.isOmittedExpression(element)) continue;
      if (ts.isIdentifier(element.name)) {
        bindings.set(element.name.text, kind);
      } else if (ts.isObjectBindingPattern(element.name) || ts.isArrayBindingPattern(element.name)) {
        collectBindingNames(element.name, bindings, kind);
      }
    }
  }
}

function isScopeNode(node) {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isGetAccessor(node) ||
    ts.isSetAccessor(node) ||
    ts.isConstructorDeclaration(node) ||
    ts.isBlock(node) ||
    ts.isCatchClause(node) ||
    ts.isModuleDeclaration(node) ||
    ts.isSourceFile(node) ||
    ts.isSwitchStatement(node) ||
    ts.isForStatement(node) ||
    ts.isForInStatement(node) ||
    ts.isForOfStatement(node)
  );
}

function addNodeScopeDeclarations(node, scope) {
  if (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isConstructorDeclaration(node)
  ) {
    scope.varScope = scope;
    if (node.name && ts.isIdentifier(node.name)) {
      scope.bindings.set(node.name.text, "function");
    }
    for (const param of node.parameters) {
      collectBindingNames(param.name, scope.bindings, "parameter");
    }
  }

  if (ts.isForStatement(node) || ts.isForInStatement(node) || ts.isForOfStatement(node)) {
    const initializer = ts.isForInStatement(node) || ts.isForOfStatement(node)
      ? node.initializer
      : node.initializer;
    if (initializer && ts.isVariableDeclarationList(initializer)) {
      for (const decl of initializer.declarations) {
        if (initializer.flags & ts.NodeFlags.Let || initializer.flags & ts.NodeFlags.Const) {
          collectBindingNames(decl.name, scope.bindings, "loop");
        } else {
          collectBindingNames(decl.name, scope.varScope.bindings, "variable");
        }
      }
    }
  }

  if (
    (ts.isBlock(node) || ts.isModuleDeclaration(node) || ts.isSourceFile(node) || ts.isSwitchStatement(node)) &&
    Array.isArray(node.statements)
  ) {
    for (const statement of node.statements) {
      addStatementDeclarations(statement, scope, scope.varScope || scope);
    }
  }

  if (ts.isCatchClause(node) && node.variableDeclaration) {
    collectBindingNames(node.variableDeclaration.name, scope.bindings, "catch");
  }
}

function addStatementDeclarations(statement, scope, varScope) {
  if (ts.isImportDeclaration(statement)) {
    const bindings = runtimeImportBindings(statement);
    for (const b of bindings) {
      if (b.kind !== "side_effect") {
        scope.bindings.set(b.local, "import");
      }
    }
  } else if (ts.isVariableStatement(statement)) {
    for (const decl of statement.declarationList.declarations) {
      if (statement.declarationList.flags & ts.NodeFlags.Let || statement.declarationList.flags & ts.NodeFlags.Const) {
        collectBindingNames(decl.name, scope.bindings, "variable");
      } else {
        collectBindingNames(decl.name, varScope.bindings, "variable");
      }
    }
  } else if (ts.isFunctionDeclaration(statement) && statement.name) {
    scope.bindings.set(statement.name.text, "function");
  } else if (ts.isClassDeclaration(statement) && statement.name) {
    scope.bindings.set(statement.name.text, "class");
  }
}

function isLocallyBound(name, scopes) {
  for (let i = scopes.length - 1; i >= 0; i--) {
    if (scopes[i].bindings.has(name)) {
      return true;
    }
  }
  return false;
}

function isRuntimeValueIdentifierReference(node, scopes) {
  return isRuntimeValueIdentifierReferenceForName(
    node,
    scopes,
    globalNetworkPrimitiveNames,
  );
}

function isRuntimeValueIdentifierReferenceForName(node, scopes, names) {
  if (!ts.isIdentifier(node)) return false;
  const name = node.text;
  if (!names.has(name)) return false;
  if (isLocallyBound(name, scopes)) return false;

  const parent = node.parent;
  if (!parent) return true;

  if (ts.isQualifiedName(parent) && parent.left === node) return false;
  if (ts.isPropertyAccessExpression(parent) && parent.name === node) return false;
  if (ts.isPropertyAccessChain(parent) && parent.name === node) return false;
  if (ts.isElementAccessExpression(parent) && parent.argumentExpression === node) return false;
  if ((ts.isImportSpecifier(parent) || ts.isExportSpecifier(parent)) && parent.propertyName !== node) return false;
  if ((ts.isImportSpecifier(parent) || ts.isExportSpecifier(parent)) && parent.propertyName === node) return false;
  if (ts.isBindingElement(parent) && parent.propertyName === node) return false;
  if (ts.isPropertySignature(parent) && parent.name === node) return false;
  if (ts.isPropertyAssignment(parent) && parent.name === node) return false;
  if (ts.isShorthandPropertyAssignment(parent)) return true;
  if (ts.isMethodDeclaration(parent) && parent.name === node) return false;
  if (ts.isMethodSignature(parent) && parent.name === node) return false;
  if (ts.isPropertyDeclaration(parent) && parent.name === node) return false;
  if (ts.isGetAccessor(parent) && parent.name === node) return false;
  if (ts.isSetAccessor(parent) && parent.name === node) return false;
  if (ts.isClassDeclaration(parent) && parent.name === node) return false;
  if (ts.isInterfaceDeclaration(parent) && parent.name === node) return false;
  if (ts.isFunctionDeclaration(parent) && parent.name === node) return false;
  if (ts.isVariableDeclaration(parent) && parent.name === node) return false;
  if (ts.isParameter(parent) && parent.name === node) return false;
  if (ts.isCatchClause(parent) && parent.variableDeclaration && parent.variableDeclaration.name === node) return false;
  if (ts.isLabeledStatement(parent) && parent.label === node) return false;
  if (ts.isEnumDeclaration(parent) && parent.name === node) return false;
  if (ts.isModuleDeclaration(parent) && parent.name === node) return false;
  if (ts.isExpressionWithTypeArguments(parent) && parent.expression === node) return false;
  if (ts.isNamespaceImport(parent) && parent.name === node) return false;
  if (ts.isImportEqualsDeclaration(parent) && parent.name === node) return false;

  if (isInTypePosition(node)) return false;

  return true;
}

function isInTypePosition(node) {
  let current = node.parent;
  while (current) {
    if (ts.isTypeQueryNode(current)) return true;
    if (ts.isTypeAliasDeclaration(current)) return true;
    if (ts.isInterfaceDeclaration(current)) return true;
    if (ts.isTypeParameterDeclaration(current)) return true;
    current = current.parent;
  }
  return false;
}

function isDirectGlobalObjectReference(expression, scopes) {
  if (!expression) return false;
  const valueExpression = valueProducingExpression(expression);
  if (valueExpression !== expression) {
    return isDirectGlobalObjectReference(valueExpression, scopes);
  }
  if (ts.isIdentifier(expression)) {
    return resolveGlobalObjectName(expression, scopes) !== null;
  }
  if (ts.isParenthesizedExpression(expression) || ts.isNonNullExpression(expression)) {
    return isDirectGlobalObjectReference(expression.expression, scopes);
  }
  if (ts.isAsExpression(expression) || ts.isTypeAssertionExpression(expression) || ts.isSatisfiesExpression(expression)) {
    return isDirectGlobalObjectReference(expression.expression, scopes);
  }
  return false;
}

function expressionContainsGlobalObject(expression, scopes) {
  if (!expression) return false;
  if (isDirectGlobalObjectReference(expression, scopes)) return true;

  if (ts.isObjectLiteralExpression(expression)) {
    for (const property of expression.properties) {
      if (ts.isPropertyAssignment(property)) {
        if (expressionContainsGlobalObject(property.initializer, scopes)) return true;
        if (property.name && ts.isComputedPropertyName(property.name)) {
          if (expressionContainsGlobalObject(property.name.expression, scopes)) return true;
        }
      } else if (ts.isShorthandPropertyAssignment(property)) {
        if (expressionContainsGlobalObject(property.name, scopes)) return true;
      } else if (ts.isSpreadElement(property) || ts.isSpreadAssignment(property)) {
        if (expressionContainsGlobalObject(property.expression, scopes)) return true;
      }
    }
    return false;
  }

  if (ts.isArrayLiteralExpression(expression)) {
    for (const element of expression.elements) {
      if (ts.isSpreadElement(element)) {
        if (expressionContainsGlobalObject(element.expression, scopes)) return true;
      } else if (expressionContainsGlobalObject(element, scopes)) {
        return true;
      }
    }
    return false;
  }

  if (ts.isElementAccessExpression(expression)) {
    return expressionContainsGlobalObject(expression.expression, scopes);
  }

  if (ts.isConditionalExpression(expression)) {
    return (
      expressionContainsGlobalObject(expression.whenTrue, scopes) ||
      expressionContainsGlobalObject(expression.whenFalse, scopes)
    );
  }

  if (ts.isBinaryExpression(expression) && expression.operatorToken.kind === ts.SyntaxKind.CommaToken) {
    // Only the right operand is the value produced by a comma expression.
    // The discarded left operand cannot become the resulting authority.
    return expressionContainsGlobalObject(expression.right, scopes);
  }

  if (ts.isCallExpression(expression) || ts.isNewExpression(expression)) {
    for (const arg of expression.arguments) {
      if (ts.isSpreadElement(arg)) {
        if (expressionContainsGlobalObject(arg.expression, scopes)) return true;
      } else if (expressionContainsGlobalObject(arg, scopes)) {
        return true;
      }
    }
    return false;
  }

  if (ts.isTemplateExpression(expression)) {
    for (const span of expression.templateSpans) {
      if (expressionContainsGlobalObject(span.expression, scopes)) return true;
    }
    return false;
  }

  if (ts.isTaggedTemplateExpression(expression)) {
    return expressionContainsGlobalObject(expression.template, scopes);
  }

  if (ts.isCallExpression(expression) || ts.isNewExpression(expression)) {
    if (callResultResolvesToGlobalObject(expression, scopes)) return true;
    return false;
  }

  if (ts.isArrowFunction(expression) || ts.isFunctionExpression(expression)) {
    return analyzeCallableBody(expression, scopes);
  }

  return false;
}

function callResultResolvesToGlobalObject(callExpression, scopes) {
  const callee = callExpression.expression;
  const resolved = resolveCallableExpression(callee, scopes);
  if (!resolved) return false;
  return analyzeCallableBody(resolved, scopes);
}

function resolveCallableExpression(node, scopes) {
  node = valueProducingExpression(node);
  if (ts.isIdentifier(node)) {
    const name = node.text;
    for (let i = scopes.length - 1; i >= 0; i--) {
      const scope = scopes[i];
      if (scope.callableBindings && scope.callableBindings.has(name)) {
        return scope.callableBindings.get(name);
      }
      if (scope.bindings.has(name)) {
        return null;
      }
    }
    return null;
  }
  if (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) {
    return node;
  }
  return null;
}

function analyzeCallableBody(callable, outerScopes) {
  if (ts.isArrowFunction(callable)) {
    if (!callable.body) return false;
    const fnScope = {
      bindings: new Map(),
      globalAliases: new Set(),
      callableBindings: new Map(),
      node: callable,
      varScope: null,
    };
    fnScope.varScope = fnScope;
    addNodeScopeDeclarations(callable, fnScope);
    if (!ts.isBlock(callable.body)) {
      return expressionContainsGlobalObject(callable.body, [...outerScopes, fnScope]);
    }
    return blockContainsGlobalObjectWithScope(callable.body, fnScope, outerScopes);
  }
  if (callable.body) {
    const fnScope = {
      bindings: new Map(),
      globalAliases: new Set(),
      callableBindings: new Map(),
      node: callable,
      varScope: null,
    };
    fnScope.varScope = fnScope;
    addNodeScopeDeclarations(callable, fnScope);
    return blockContainsGlobalObjectWithScope(callable.body, fnScope, outerScopes);
  }
  return false;
}

function blockContainsGlobalObjectWithScope(block, parentScope, outerScopes) {
  const blockScope = {
    bindings: new Map(),
    globalAliases: new Set(),
    callableBindings: new Map(),
    node: block,
    varScope: parentScope,
  };
  addNodeScopeDeclarations(block, blockScope);
  const scopes = [...outerScopes, parentScope, blockScope];
  return blockContainsGlobalObject(block, blockScope, scopes);
}

function blockContainsGlobalObject(block, currentScope, scopes) {
  for (const stmt of block.statements) {
    if (ts.isVariableStatement(stmt)) {
      for (const decl of stmt.declarationList.declarations) {
        if (decl.initializer && ts.isIdentifier(decl.name)) {
          if (isDirectGlobalObjectReference(decl.initializer, scopes)) {
            currentScope.globalAliases.add(decl.name.text);
          }
        }
      }
    }
  }

  let found = false;
  const visit = (node, visitScopes) => {
    if (found) return;
    const effectiveScopes = visitScopes || scopes;

    if (ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node)) {
      if (analyzeCallableBody(node, effectiveScopes)) {
        found = true;
      }
      return;
    }

    if (ts.isClassDeclaration(node) || ts.isClassExpression(node)) {
      for (const member of node.members) {
        if (found) return;
        if (
          ts.isMethodDeclaration(member) ||
          ts.isConstructorDeclaration(member) ||
          ts.isGetAccessor(member) ||
          ts.isSetAccessor(member)
        ) {
          if (analyzeCallableBody(member, effectiveScopes)) {
            found = true;
          }
        }
      }
      return;
    }

    if (ts.isBlock(node) && node !== block) {
      const nestedScope = {
        bindings: new Map(),
        globalAliases: new Set(),
        callableBindings: new Map(),
        node,
        varScope: effectiveScopes[effectiveScopes.length - 1],
      };
      addNodeScopeDeclarations(node, nestedScope);
      if (blockContainsGlobalObject(node, nestedScope, [...effectiveScopes, nestedScope])) {
        found = true;
      }
      return;
    }

    if (ts.isCatchClause(node)) {
      const catchScope = {
        bindings: new Map(),
        globalAliases: new Set(),
        callableBindings: new Map(),
        node,
        varScope: effectiveScopes[effectiveScopes.length - 1],
      };
      addNodeScopeDeclarations(node, catchScope);
      if (node.block && blockContainsGlobalObject(node.block, catchScope, [...effectiveScopes, catchScope])) {
        found = true;
      }
      return;
    }

    if (ts.isForStatement(node) || ts.isForInStatement(node) || ts.isForOfStatement(node)) {
      const loopScope = {
        bindings: new Map(),
        globalAliases: new Set(),
        callableBindings: new Map(),
        node,
        varScope: effectiveScopes[effectiveScopes.length - 1],
      };
      addNodeScopeDeclarations(node, loopScope);
      const loopScopes = [...effectiveScopes, loopScope];
      if (node.statement) {
        if (ts.isBlock(node.statement)) {
          const nestedScope = {
            bindings: new Map(),
            globalAliases: new Set(),
            callableBindings: new Map(),
            node: node.statement,
            varScope: loopScope,
          };
          addNodeScopeDeclarations(node.statement, nestedScope);
          if (blockContainsGlobalObject(node.statement, nestedScope, [...loopScopes, nestedScope])) {
            found = true;
          }
        } else {
          visit(node.statement, loopScopes);
        }
      }
      return;
    }

    if (ts.isReturnStatement(node) && node.expression) {
      if (expressionContainsGlobalObject(node.expression, effectiveScopes)) {
        found = true;
        return;
      }
    }
    if (ts.isExpressionStatement(node)) {
      if (expressionContainsGlobalObject(node.expression, effectiveScopes)) {
        found = true;
        return;
      }
    }
    ts.forEachChild(node, (child) => {
      if (!found) visit(child, effectiveScopes);
    });
  };
  visit(block);
  return found;
}

function walkNetworkCapabilityNodes(sourcePath, node, scopes, observedKeys) {
  if (ts.isIdentifier(node)) {
    if (isRuntimeValueIdentifierReference(node, scopes)) {
      classifyRuntimeGlobalPrimitive(node, scopes, observedKeys, sourcePath);
    }
  }

  if (ts.isPropertyAccessExpression(node) || ts.isPropertyAccessChain(node)) {
    checkGlobalPropertyAccess(sourcePath, node, scopes, observedKeys);
  }

  if (ts.isElementAccessExpression(node)) {
    checkGlobalElementAccess(sourcePath, node, scopes, observedKeys);
  }

  if (ts.isVariableDeclaration(node) && node.initializer) {
    checkGlobalDestructuring(sourcePath, node, scopes, observedKeys);
    if (ts.isIdentifier(node.initializer)) {
      checkBareGlobalAssignment(sourcePath, node, scopes, observedKeys);
    }
    checkGlobalObjectAlias(node, scopes);
    if (ts.isIdentifier(node.name)) {
      if (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer)) {
        const currentScope = scopes[scopes.length - 1];
        currentScope.callableBindings.set(node.name.text, node.initializer);
      }
    }
  }

  if (ts.isSpreadElement(node) || ts.isSpreadAssignment(node)) {
    checkGlobalObjectSpread(sourcePath, node, scopes);
  }

  rejectGlobalObjectEscape(sourcePath, node, scopes);
  rejectProhibitedNetworkMutation(node, scopes);
  rejectGlobalObjectMutation(node, scopes);
  rejectDynamicGlobalAccess(node, scopes);

  const isScope = isScopeNode(node);

  if (isScope) {
    const newScope = { bindings: new Map(), globalAliases: new Set(), callableBindings: new Map(), node, varScope: null };
    newScope.varScope = scopes[scopes.length - 1].varScope || scopes[scopes.length - 1];
    addNodeScopeDeclarations(node, newScope);
    scopes.push(newScope);
  }

  ts.forEachChild(node, (child) =>
    walkNetworkCapabilityNodes(sourcePath, child, scopes, observedKeys),
  );

  if (isScope) {
    scopes.pop();
  }
}

function classifyRuntimeGlobalPrimitive(node, scopes, observedKeys, sourcePath) {
  const name = node.text;
  observeGlobalNetworkCapability({
    sourcePath,
    primitive: name,
    globalObjectForm: name,
    acquisitionForm: "bare_reference",
    localBinding: "",
    observedKeys,
    node,
  });
}

function checkGlobalPropertyAccess(sourcePath, node, scopes, observedKeys) {
  const objectName = resolveGlobalObjectName(node.expression, scopes);
  if (!objectName) return;

  const propName = node.name.text;
  if (!globalNetworkPrimitiveNames.has(propName)) return;

  observeGlobalNetworkCapability({
    sourcePath,
    primitive: propName,
    globalObjectForm: `${objectName}.${propName}`,
    acquisitionForm: "property_access",
    localBinding: "",
    observedKeys,
    node,
  });
}

function checkGlobalElementAccess(sourcePath, node, scopes, observedKeys) {
  const objectName = resolveGlobalObjectName(node.expression, scopes);
  if (!objectName) return;
  if (!ts.isStringLiteral(node.argumentExpression)) return;

  const propName = node.argumentExpression.text;
  if (!globalNetworkPrimitiveNames.has(propName)) return;

  observeGlobalNetworkCapability({
    sourcePath,
    primitive: propName,
    globalObjectForm: `${objectName}["${propName}"]`,
    acquisitionForm: "element_access",
    localBinding: "",
    observedKeys,
    node,
  });
}

function checkGlobalDestructuring(sourcePath, node, scopes, observedKeys) {
  if (!ts.isObjectBindingPattern(node.name) && !ts.isArrayBindingPattern(node.name)) return;
  const objectName = resolveGlobalObjectName(node.initializer, scopes);
  if (!objectName) return;

  if (ts.isObjectBindingPattern(node.name)) {
    for (const element of node.name.elements) {
      if (element.dotDotDotToken) {
        throw new RuntimeGrantContractError("runtime_grant_inventory_unclassified");
      }
      const exportedName =
        element.propertyName && ts.isIdentifier(element.propertyName)
          ? element.propertyName.text
          : ts.isIdentifier(element.name)
            ? element.name.text
            : null;
      const localName = ts.isIdentifier(element.name) ? element.name.text : null;
      if (exportedName && localName && globalNetworkPrimitiveNames.has(exportedName)) {
        observeGlobalNetworkCapability({
          sourcePath,
          primitive: exportedName,
          globalObjectForm: `${objectName}.${exportedName}`,
          acquisitionForm: "destructuring",
          localBinding: exportedName !== localName ? localName : exportedName,
          observedKeys,
          node,
        });
      }
    }
  }
}

function checkBareGlobalAssignment(sourcePath, node, scopes, observedKeys) {
  const name = node.initializer.text;
  if (!globalNetworkPrimitiveNames.has(name)) return;
  if (isLocallyBound(name, scopes)) return;

  let localBinding = "";
  if (ts.isIdentifier(node.name)) {
    localBinding = node.name.text;
  }

  observeGlobalNetworkCapability({
    sourcePath,
    primitive: name,
    globalObjectForm: name,
    acquisitionForm: "const_binding",
    localBinding,
    observedKeys,
    node,
  });
}

function checkGlobalObjectSpread(sourcePath, node, scopes) {
  const expression = node.expression;
  if (!expression) return;
  const objectName = resolveGlobalObjectName(expression, scopes);
  if (objectName) {
    throw new RuntimeGrantContractError("runtime_grant_inventory_unclassified");
  }
}

function checkGlobalObjectAlias(node, scopes) {
  if (!node.initializer) return;
  if (!ts.isIdentifier(node.name)) return;

  const declName = node.name.text;
  const parent = node.parent;
  let isConst = false;

  if (parent && ts.isVariableDeclarationList(parent)) {
    isConst = !(parent.flags & ts.NodeFlags.Let) && !(parent.flags & ts.NodeFlags.Const)
      ? false : !(parent.flags & ts.NodeFlags.Let);
  }

  if (isDirectGlobalObjectReference(node.initializer, scopes)) {
    if (isConst) {
      const currentScope = scopes[scopes.length - 1];
      currentScope.globalAliases.add(declName);
    } else {
      throw new RuntimeGrantContractError("runtime_grant_inventory_unclassified");
    }
    return;
  }

  if (expressionContainsGlobalObject(node.initializer, scopes)) {
    throw new RuntimeGrantContractError("runtime_grant_inventory_unclassified");
  }
}

function rejectGlobalObjectEscape(sourcePath, node, scopes) {
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
    if (expressionContainsGlobalObject(node.right, scopes)) {
      throw new RuntimeGrantContractError("runtime_grant_inventory_unclassified");
    }
  }

  if (ts.isSpreadElement(node) || ts.isSpreadAssignment(node)) {
    const expression = node.expression;
    if (expression && expressionContainsGlobalObject(expression, scopes)) {
      throw new RuntimeGrantContractError("runtime_grant_inventory_unclassified");
    }
  }

  if (ts.isCallExpression(node) && node.arguments.length > 0) {
    if (ts.isIdentifier(node.expression) && !isLocallyBound(node.expression.text, scopes)) return;
    for (const arg of node.arguments) {
      if (ts.isSpreadElement(arg)) {
        if (expressionContainsGlobalObject(arg.expression, scopes)) {
          throw new RuntimeGrantContractError("runtime_grant_inventory_unclassified");
        }
      } else if (expressionContainsGlobalObject(arg, scopes)) {
        throw new RuntimeGrantContractError("runtime_grant_inventory_unclassified");
      }
    }
  }

  if (ts.isReturnStatement(node) && node.expression) {
    if (expressionContainsGlobalObject(node.expression, scopes)) {
      throw new RuntimeGrantContractError("runtime_grant_inventory_unclassified");
    }
  }

  if (ts.isExportAssignment(node) && !node.isExportEquals && node.expression) {
    if (expressionContainsGlobalObject(node.expression, scopes)) {
      throw new RuntimeGrantContractError("runtime_grant_inventory_unclassified");
    }
  }

  if (ts.isArrayLiteralExpression(node)) {
    for (const element of node.elements) {
      if (ts.isSpreadElement(element)) {
        if (expressionContainsGlobalObject(element.expression, scopes)) {
          throw new RuntimeGrantContractError("runtime_grant_inventory_unclassified");
        }
      } else if (expressionContainsGlobalObject(element, scopes)) {
        throw new RuntimeGrantContractError("runtime_grant_inventory_unclassified");
      }
    }
  }

  if (ts.isObjectLiteralExpression(node)) {
    for (const property of node.properties) {
      if (ts.isPropertyAssignment(property)) {
        if (expressionContainsGlobalObject(property.initializer, scopes)) {
          throw new RuntimeGrantContractError("runtime_grant_inventory_unclassified");
        }
        if (property.name && ts.isComputedPropertyName(property.name)) {
          if (expressionContainsGlobalObject(property.name.expression, scopes)) {
            throw new RuntimeGrantContractError("runtime_grant_inventory_unclassified");
          }
        }
      } else if (ts.isShorthandPropertyAssignment(property)) {
        if (expressionContainsGlobalObject(property.name, scopes)) {
          throw new RuntimeGrantContractError("runtime_grant_inventory_unclassified");
        }
      } else if (ts.isSpreadElement(property) || ts.isSpreadAssignment(property)) {
        if (expressionContainsGlobalObject(property.expression, scopes)) {
          throw new RuntimeGrantContractError("runtime_grant_inventory_unclassified");
        }
      }
    }
  }
}

function resolveGlobalObjectName(expression, scopes) {
  expression = valueProducingExpression(expression);
  if (ts.isIdentifier(expression)) {
    const name = expression.text;
    if (globalObjectIdentifiers.has(name) && !isLocallyBound(name, scopes)) return name;
    if (isGlobalObjectAlias(name, scopes)) {
      if (checkAliasReassignment(expression)) {
        throw new RuntimeGrantContractError("runtime_grant_inventory_unclassified");
      }
      return name;
    }
    return null;
  }
  if (ts.isPropertyAccessExpression(expression) || ts.isPropertyAccessChain(expression)) return null;
  if (ts.isCallExpression(expression) || ts.isNewExpression(expression)) {
    if (callResultResolvesToGlobalObject(expression, scopes)) return "globalThis";
    return null;
  }
  return null;
}

function valueProducingExpression(expression) {
  let current = expression;
  while (current) {
    if (
      ts.isParenthesizedExpression(current) ||
      ts.isNonNullExpression(current) ||
      ts.isAsExpression(current) ||
      ts.isTypeAssertionExpression(current) ||
      ts.isSatisfiesExpression(current)
    ) {
      current = current.expression;
      continue;
    }
    if (
      ts.isBinaryExpression(current) &&
      current.operatorToken.kind === ts.SyntaxKind.CommaToken
    ) {
      current = current.right;
      continue;
    }
    break;
  }
  return current;
}

function checkAliasReassignment(identifier) {
  const parent = identifier.parent;
  if (!parent) return false;
  if (ts.isBinaryExpression(parent) && parent.left === identifier &&
    parent.operatorToken.kind !== ts.SyntaxKind.EqualsToken) return false;
  if (ts.isPostfixUnaryExpression(parent)) return true;
  if (ts.isPrefixUnaryExpression(parent)) return true;
  if (ts.isDeleteExpression(parent) && parent.expression === identifier) return true;
  return false;
}

function isGlobalObjectAlias(name, scopes) {
  for (let i = scopes.length - 1; i >= 0; i--) {
    if (scopes[i].globalAliases.has(name)) return true;
    if (scopes[i].bindings.has(name)) return false;
  }
  return false;
}

function rejectProhibitedNetworkMutation(node, scopes) {
  if (ts.isBinaryExpression(node)) {
    if (node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      if (ts.isPropertyAccessExpression(node.left)) {
        const objName = resolveGlobalObjectName(node.left.expression, scopes);
        if (objName && globalNetworkPrimitiveNames.has(node.left.name.text)) {
          throw new RuntimeGrantContractError("runtime_grant_inventory_unclassified");
        }
      }
      if (ts.isElementAccessExpression(node.left)) {
        const objName = resolveGlobalObjectName(node.left.expression, scopes);
        if (objName && ts.isStringLiteral(node.left.argumentExpression) &&
          globalNetworkPrimitiveNames.has(node.left.argumentExpression.text)) {
          throw new RuntimeGrantContractError("runtime_grant_inventory_unclassified");
        }
      }
    }

    if (ts.isPropertyAccessExpression(node.left) || ts.isElementAccessExpression(node.left)) {
      const parent = node.parent;
      if (parent && ts.isExpressionStatement(parent) && !ts.isForStatement(parent.parent)) {
        const objName = ts.isPropertyAccessExpression(node.left)
          ? resolveGlobalObjectName(node.left.expression, scopes)
          : resolveGlobalObjectName(node.left.expression, scopes);
        if (objName) {
          const propName = ts.isPropertyAccessExpression(node.left)
            ? node.left.name.text
            : (ts.isStringLiteral(node.left.argumentExpression) ? node.left.argumentExpression.text : null);
          if (propName && globalNetworkPrimitiveNames.has(propName)) {
            throw new RuntimeGrantContractError("runtime_grant_inventory_unclassified");
          }
        }

        if (ts.isIdentifier(node.left) && isGlobalObjectAlias(node.left.text, scopes)) {
          throw new RuntimeGrantContractError("runtime_grant_inventory_unclassified");
        }
      }
    }
  }

  if (ts.isPostfixUnaryExpression(node) || ts.isPrefixUnaryExpression(node)) {
    if (ts.isPropertyAccessExpression(node.operand)) {
      const objName = resolveGlobalObjectName(node.operand.expression, scopes);
      const propName = node.operand.name.text;
      if (objName && globalNetworkPrimitiveNames.has(propName)) {
        throw new RuntimeGrantContractError("runtime_grant_inventory_unclassified");
      }
    }
  }

  if (ts.isDeleteExpression(node)) {
    if (ts.isPropertyAccessExpression(node.expression)) {
      const objName = resolveGlobalObjectName(node.expression.expression, scopes);
      if (objName && globalNetworkPrimitiveNames.has(node.expression.name.text)) {
        throw new RuntimeGrantContractError("runtime_grant_inventory_unclassified");
      }
    }
    if (ts.isElementAccessExpression(node.expression)) {
      const objName = resolveGlobalObjectName(node.expression.expression, scopes);
      if (objName && ts.isStringLiteral(node.expression.argumentExpression) &&
        globalNetworkPrimitiveNames.has(node.expression.argumentExpression.text)) {
        throw new RuntimeGrantContractError("runtime_grant_inventory_unclassified");
      }
    }
  }
}

function rejectGlobalObjectMutation(node, scopes) {
  rejectBuiltInMutation(node, scopes);
  rejectReflectiveGlobalAccess(node, scopes);
}

const classifiedMutationReceivers = new Set(["Object", "Reflect"]);
const classifiedMutationMethods = new Set([
  "defineProperty", "defineProperties", "assign",
  "set", "deleteProperty",
  "getOwnPropertyDescriptor", "getOwnPropertyDescriptors", "get",
  "entries", "values",
]);

function rejectBuiltInMutation(node, scopes) {
  if (!ts.isCallExpression(node)) return;

  let receiverName = null;
  let methodName = null;

  const expr = node.expression;

  if (ts.isPropertyAccessExpression(expr) && ts.isIdentifier(expr.expression)) {
    receiverName = expr.expression.text;
    methodName = expr.name.text;
  } else if (ts.isElementAccessExpression(expr) && ts.isIdentifier(expr.expression)) {
    receiverName = expr.expression.text;
    if (ts.isStringLiteral(expr.argumentExpression)) {
      methodName = expr.argumentExpression.text;
    }
  }

  if (!receiverName || !classifiedMutationReceivers.has(receiverName) || isLocallyBound(receiverName, scopes)) return;
  if (!methodName || !classifiedMutationMethods.has(methodName)) return;

  for (const arg of node.arguments) {
    if (!ts.isSpreadElement(arg)) {
      const targetName = resolveGlobalObjectName(arg, scopes);
      if (targetName) {
        throw new RuntimeGrantContractError("runtime_grant_inventory_unclassified");
      }
    }
  }
}

function rejectReflectiveGlobalAccess(node, scopes) {
  if (
    ts.isCallExpression(node) &&
    ts.isPropertyAccessExpression(node.expression) &&
    ts.isIdentifier(node.expression.expression)
  ) {
    const receiver = node.expression.expression.text;
    const method = node.expression.name.text;
    const isReflective =
      (receiver === "Reflect" && (method === "get" || method === "getOwnPropertyDescriptor")) ||
      (receiver === "Object" && (method === "getOwnPropertyDescriptor" || method === "getOwnPropertyDescriptors"));

    if (isReflective && !isLocallyBound(receiver, scopes) && node.arguments.length > 0) {
      const targetName = resolveGlobalObjectName(node.arguments[0], scopes);
      if (targetName) {
        throw new RuntimeGrantContractError("runtime_grant_inventory_unclassified");
      }
    }
  }
}

function rejectDynamicGlobalAccess(node, scopes) {
  if (ts.isElementAccessExpression(node)) {
    const objectName = resolveGlobalObjectName(node.expression, scopes);
    if (objectName && !ts.isStringLiteral(node.argumentExpression)) {
      throw new RuntimeGrantContractError("runtime_grant_inventory_unclassified");
    }
  }
}

function observeGlobalNetworkCapability({
  sourcePath,
  primitive,
  globalObjectForm,
  acquisitionForm,
  localBinding,
  observedKeys,
  node,
}) {
  let effectiveAcquisitionForm = acquisitionForm;
  let effectiveLocalBinding = localBinding;

  if (
    acquisitionForm === "property_access" &&
    node.parent &&
    ts.isVariableDeclaration(node.parent) &&
    ts.isIdentifier(node.parent.name)
  ) {
    effectiveAcquisitionForm = "const_binding";
    effectiveLocalBinding = node.parent.name.text;
  }

  const key = globalNetworkCapabilityKey({
    sourcePath,
    primitive,
    globalObjectForm,
    acquisitionForm: effectiveAcquisitionForm,
    localBinding: effectiveLocalBinding,
  });

  if (observedKeys.has(key)) return;

  observedKeys.set(key, {
    key,
    sourcePath,
    primitive,
    globalObjectForm,
    acquisitionForm: effectiveAcquisitionForm,
    localBinding: effectiveLocalBinding,
    referenceCount: effectiveAcquisitionForm === "bare_call" || effectiveAcquisitionForm === "bare_reference" ? 1 : 0,
  });
}

function countBindingCallSites(sourceFile, bindingName) {
  let count = 0;

  const visit = (node) => {
    if (
      ts.isIdentifier(node) &&
      node.text === bindingName
    ) {
      if (
        node.parent &&
        ts.isVariableDeclaration(node.parent) &&
        node.parent.name === node
      ) {
        return;
      }

      if (
        node.parent &&
        ts.isCallExpression(node.parent) &&
        node.parent.expression === node
      ) {
        count++;
        return;
      }

      if (
        node.parent &&
        ts.isPropertyAccessExpression(node.parent) &&
        node.parent.name === node
      ) {
        return;
      }

      if (
        node.parent &&
        ts.isParameter(node.parent) &&
        node.parent.name === node
      ) {
        return;
      }

      if (
        node.parent &&
        ts.isBindingElement(node.parent) &&
        node.parent.name === node
      ) {
        return;
      }

      if (
        node.parent &&
        ts.isExportAssignment(node.parent) &&
        node.parent.expression === node
      ) {
        count++;
        return;
      }

      if (
        node.parent &&
        ts.isReturnStatement(node.parent) &&
        node.parent.expression === node
      ) {
        count++;
        return;
      }
    }
    ts.forEachChild(node, visit);
  };

  visit(sourceFile);
  return count;
}

function operationSourceKey(record) {
  if (typeof record?.sourceId !== "string") {
    throw new RuntimeGrantContractError(
      "runtime_grant_source_mismatch",
    );
  }
  return `${runtimeTableGrantKey(record)}\u0000${record.sourceId}`;
}

async function sourceText(filePath, sourceOverrides) {
  const normalized = normalizePath(filePath);
  if (sourceOverrides.has(normalized)) {
    return sourceOverrides.get(normalized);
  }
  return readFile(path.normalize(normalized), "utf8");
}

function normalizePath(value) {
  return value.replaceAll("\\", "/");
}

function compare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}
