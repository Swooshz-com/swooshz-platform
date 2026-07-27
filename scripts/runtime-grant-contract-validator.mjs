import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

import ts from "typescript";

import {
  RuntimeGrantContractError,
  runtimeTableGrantKey,
} from "../dist/db/runtime-grant-contract.js";

const adapterDirectory = "src/db";
const schemaPath = "src/db/schema.ts";
const migrationDirectory = "drizzle/migrations";
const operationPrivileges = new Map([
  ["from", "SELECT"],
  ["insert", "INSERT"],
  ["update", "UPDATE"],
  ["delete", "DELETE"],
]);

export async function extractProductionAdapterOperations({
  sourceOverrides = new Map(),
} = {}) {
  const schemaSource = await sourceText(schemaPath, sourceOverrides);
  const schemaBindings = extractSchemaBindings(schemaSource);
  const entries = await readdir(adapterDirectory, { withFileTypes: true });
  const adapterPaths = entries
    .filter(
      (entry) =>
        entry.isFile() &&
        (entry.name === "repositories.ts" ||
          entry.name.endsWith("-repository.ts")),
    )
    .map((entry) => `${adapterDirectory}/${entry.name}`)
    .sort();

  const operations = new Map();
  for (const adapterPath of adapterPaths) {
    const source = await sourceText(adapterPath, sourceOverrides);
    const extracted = extractAdapterOperations(
      adapterPath,
      source,
      schemaBindings,
    );
    for (const operation of extracted) {
      operations.set(runtimeTableGrantKey(operation), operation);
    }
  }

  return [...operations.values()].sort((left, right) => {
    const leftKey = runtimeTableGrantKey(left);
    const rightKey = runtimeTableGrantKey(right);
    return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
  });
}

export function assertProductionAdapterGrantEquality(
  contract,
  operations,
) {
  const contractKeys = new Set(contract.map(runtimeTableGrantKey));
  const operationKeys = new Set(operations.map(runtimeTableGrantKey));
  if (
    [...contractKeys].some((key) => !operationKeys.has(key))
  ) {
    throw new RuntimeGrantContractError("runtime_grant_adapter_missing");
  }
  if (
    [...operationKeys].some((key) => !contractKeys.has(key))
  ) {
    throw new RuntimeGrantContractError("runtime_grant_adapter_extra");
  }
}

export async function readCanonicalMigrationObjects({
  sourceOverrides = new Map(),
} = {}) {
  const entries = await readdir(migrationDirectory, {
    withFileTypes: true,
  });
  const migrations = entries
    .filter((entry) => entry.isFile() && /^\d{4}_.+\.sql$/.test(entry.name))
    .map((entry) => entry.name)
    .sort();
  const objects = new Map();

  for (const migrationFile of migrations) {
    const migrationPath = `${migrationDirectory}/${migrationFile}`;
    const source = await sourceText(migrationPath, sourceOverrides);
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
  const sourceFile = ts.createSourceFile(
    schemaPath,
    source,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
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
          "runtime_grant_adapter_ambiguous",
        );
      }
      bindings.set(declaration.name.text, name.text);
    }
  }
  return bindings;
}

function extractAdapterOperations(adapterPath, source, schemaBindings) {
  const sourceFile = ts.createSourceFile(
    adapterPath,
    source,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  if (sourceFile.parseDiagnostics.length > 0) {
    throw new RuntimeGrantContractError(
      "runtime_grant_adapter_ambiguous",
    );
  }

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

  const wrappers = findTableOperationWrappers(sourceFile);
  const operations = new Map();

  const add = (tableName, privilege) => {
    const record = Object.freeze({
      objectClass: "table",
      schema: "public",
      objectName: tableName,
      privilege,
      authoritySource: "direct",
      grantOption: false,
    });
    operations.set(runtimeTableGrantKey(record), record);
  };

  const visit = (node, currentFunction = null) => {
    let nextFunction = currentFunction;
    if (
      (ts.isFunctionDeclaration(node) ||
        ts.isFunctionExpression(node) ||
        ts.isArrowFunction(node)) &&
      node.name &&
      ts.isIdentifier(node.name)
    ) {
      nextFunction = node.name.text;
    }

    if (ts.isCallExpression(node)) {
      const method = callMethodName(node.expression);
      const privilege = operationPrivileges.get(method);
      if (privilege) {
        const tableArgument = node.arguments[0];
        if (tableArgument && ts.isIdentifier(tableArgument)) {
          const tableName = importedTables.get(tableArgument.text);
          if (tableName) {
            add(tableName, privilege);
          } else if (
            !wrapperOwnsParameter(
              wrappers,
              nextFunction,
              method,
              tableArgument.text,
            )
          ) {
            throw new RuntimeGrantContractError(
              "runtime_grant_adapter_ambiguous",
            );
          }
        } else {
          throw new RuntimeGrantContractError(
            "runtime_grant_adapter_ambiguous",
          );
        }
      }

      if (ts.isIdentifier(node.expression)) {
        const wrapper = wrappers.get(node.expression.text);
        if (wrapper) {
          for (const operation of wrapper.operations) {
            const argument = node.arguments[operation.parameterIndex];
            if (!argument || !ts.isIdentifier(argument)) {
              throw new RuntimeGrantContractError(
                "runtime_grant_adapter_ambiguous",
              );
            }
            const tableName = importedTables.get(argument.text);
            if (!tableName) {
              throw new RuntimeGrantContractError(
                "runtime_grant_adapter_ambiguous",
              );
            }
            add(tableName, operation.privilege);
          }
        }
      }
    }
    ts.forEachChild(node, (child) => visit(child, nextFunction));
  };
  visit(sourceFile);
  return [...operations.values()];
}

function findTableOperationWrappers(sourceFile) {
  const wrappers = new Map();
  for (const statement of sourceFile.statements) {
    if (
      !ts.isFunctionDeclaration(statement) ||
      !statement.name ||
      !statement.body
    ) {
      continue;
    }
    const parameters = new Map(
      statement.parameters
        .map((parameter, index) =>
          ts.isIdentifier(parameter.name)
            ? [parameter.name.text, index]
            : null,
        )
        .filter(Boolean),
    );
    const operations = [];
    const visit = (node) => {
      if (ts.isCallExpression(node)) {
        const method = callMethodName(node.expression);
        const privilege = operationPrivileges.get(method);
        const argument = node.arguments[0];
        if (
          privilege &&
          argument &&
          ts.isIdentifier(argument) &&
          parameters.has(argument.text)
        ) {
          operations.push({
            method,
            parameterName: argument.text,
            parameterIndex: parameters.get(argument.text),
            privilege,
          });
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(statement.body);
    if (operations.length > 0) {
      wrappers.set(statement.name.text, {
        operations,
      });
    }
  }
  return wrappers;
}

function wrapperOwnsParameter(
  wrappers,
  functionName,
  method,
  parameterName,
) {
  const wrapper = wrappers.get(functionName);
  return Boolean(
    wrapper?.operations.some(
      (operation) =>
        operation.method === method &&
        operation.parameterName === parameterName,
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
  return null;
}

async function sourceText(filePath, sourceOverrides) {
  const normalized = filePath.replaceAll("\\", "/");
  if (sourceOverrides.has(normalized)) {
    return sourceOverrides.get(normalized);
  }
  return readFile(path.normalize(normalized), "utf8");
}
