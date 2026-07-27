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
    "ef50968061d83e2c7217a215b68067eca27aae5c30005aec1b48ba4e3c377189",
  ],
  [
    "src/db/csrf-token-repository.ts",
    "cd1974c88c1c2c00f3237d79c26dfd272dfd81e6165a44570e9968568625324c",
  ],
  [
    "src/db/readiness.ts",
    "f12f570935e42867de9fd8bb94bb12b9ba8139b8dfecfc2d8c5bd3a4d012c7e3",
  ],
  [
    "src/db/repositories.ts",
    "0fcba5cbb615dd52e7063d506df51d150a7ea67bee3ec01e0815c5143448655c",
  ],
  [
    "src/db/runtime-posture.ts",
    "26e76abd42e40dda4905db1ae29acdaf4424408974a6e21c2063147418c1dbd9",
  ],
  [
    "src/db/schema.ts",
    "1f05ac9ec79a25b4d0fb49cd01af7d44fdad8fedbeedd9c1544803ee8beecfeb",
  ],
  [
    "src/runtime/node-bootstrap.ts",
    "c752bf40ac0e0efde65e248e48d7b491b5855665cd583e3fde93825a98aac972",
  ],
  [
    "src/runtime/platform-runtime-dependencies.ts",
    "bb95698a2ba31e621f4ab6f6e31aad7a31fd94e0c9fd24cffaf523e086b55dd6",
  ],
]);

const approvedNonDatabaseExternalModules = new Set([
  "node:crypto",
  "node:fs/promises",
  "node:http",
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
        if (!approvedNonDatabaseExternalModules.has(moduleName)) {
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
  const visit = (node) => {
    if (
      ts.isCallExpression(node) &&
      (
        node.expression.kind === ts.SyntaxKind.ImportKeyword ||
        (
          ts.isIdentifier(node.expression) &&
          ["eval", "require"].includes(node.expression.text)
        ) ||
        (
          ts.isPropertyAccessExpression(node.expression) &&
          ts.isIdentifier(node.expression.expression) &&
          node.expression.expression.text === "process" &&
          node.expression.name.text === "getBuiltinModule"
        )
      )
    ) {
      throw new RuntimeGrantContractError(
        "runtime_grant_inventory_unclassified",
      );
    }
    if (
      ts.isNewExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === "Function"
    ) {
      throw new RuntimeGrantContractError(
        "runtime_grant_inventory_unclassified",
      );
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
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
  if (ts.isNamespaceImport(namedBindings)) {
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

function sourceShapeDigest(source) {
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
