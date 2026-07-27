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
  if (!importClause || importClause.isTypeOnly) {
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
