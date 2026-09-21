import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const SAFE = Object.freeze({
  baseline: "SSC_STATIC_BASELINE",
  internal: "SSC_ANALYZER_INTERNAL",
  ast: "SSC_AST_UNSUPPORTED",
  computed: "SSC_COMPUTED_ACCESS",
  imports: "SSC_IMPORT_DENIED",
  unresolved: "SSC_CALL_UNRESOLVED",
  flow: "SSC_SECRET_FLOW_DENIED",
  authority: "SSC_AUTHORITY_SHAPE",
});

const HELPER_RELATIVE = "tests/support/disposable-postgres-fixture.mjs";
const FROZEN_HELPER_BLOB = "0767d4dade1bc7e7a61f984296e0f96bb0575ffb";
const ROOT_EXPORT = "withDisposablePostgresFixtureMigration";

const IMPORT_TABLE = Object.freeze({
  "drizzle-orm/node-postgres": Object.freeze(["drizzle"]),
  "drizzle-orm/node-postgres/migrator": Object.freeze(["migrate"]),
  pg: Object.freeze(["Client", "Pool"]),
  "../../dist/db/runtime-posture.js": Object.freeze([
    "inspectRuntimeDatabaseRoleAuthorityPosture",
  ]),
});

const AUTHORITY_KEYS = Object.freeze([
  "authority",
  "brand",
  "database",
  "user",
  "clusterFingerprint",
  "lifecycleFingerprint",
  "migrationsFolder",
  "phase",
  "pool",
  "valid",
]);

const SAFE_INPUT_FIELDS = new Set([
  "connectionString",
  "expectedDatabase",
  "expectedUser",
  "migrationsFolder",
  "phase",
]);

const QUERY_ROW_FIELDS = new Set([
  "database_matches",
  "user_matches",
  "postgres17",
  "non_recovery",
  "catalog_fingerprint",
  "lifecycle_fingerprint",
  "target_database_absent",
]);

const NEGATIVE_CONTROLS = Object.freeze([
  Object.freeze({
    id: "NC01_REACHABLE_WRITE_HELPER",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "CAPABILITY_OUTPUT",
  }),
  Object.freeze({
    id: "NC02_REACHABLE_HASH_HELPER",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "CAPABILITY_CRYPTO",
  }),
  Object.freeze({
    id: "NC03_STATIC_ONLY_BRANCH",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "CAPABILITY_OUTPUT",
  }),
  Object.freeze({
    id: "NC04_ALIASED_SINK",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "ALIAS_PROVENANCE",
  }),
  Object.freeze({
    id: "NC05_COMPUTED_SINK",
    code: "SSC_COMPUTED_ACCESS",
    detector: "COMPUTED_CAPABILITY",
  }),
  Object.freeze({
    id: "NC06_NEW_IMPORT",
    code: "SSC_IMPORT_DENIED",
    detector: "IMPORT_TABLE",
  }),
  Object.freeze({
    id: "NC07_UNRESOLVED_CALL",
    code: "SSC_CALL_UNRESOLVED",
    detector: "CALL_RESOLUTION",
  }),
  Object.freeze({
    id: "NC08_TRANSIENT_ENV",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "CAPABILITY_ENV",
  }),
  Object.freeze({
    id: "NC09_INNOCENT_AUTHORITY_FIELD",
    code: "SSC_AUTHORITY_SHAPE",
    detector: "AUTHORITY_SCHEMA",
  }),
  Object.freeze({
    id: "NC10_CLEANUP_PUBLISH",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "CLEANUP_DIAGNOSTIC",
  }),
  Object.freeze({
    id: "PROBE_ARROW_OUTPUT",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "CAPABILITY_OUTPUT",
  }),
  Object.freeze({
    id: "PROBE_ARRAY_SOME_OUTPUT",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "CAPABILITY_OUTPUT",
  }),
  Object.freeze({
    id: "PROBE_MODULE_IF_OUTPUT",
    code: "SSC_AST_UNSUPPORTED",
    detector: "TOP_LEVEL_SYNTAX",
  }),
  Object.freeze({
    id: "PROBE_PUBLIC_CREDENTIAL_RETURN",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "PUBLIC_RETURN",
  }),
  Object.freeze({
    id: "PROBE_TRIMMED_PASSWORD",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "CAPABILITY_PASSWORD",
  }),
  Object.freeze({
    id: "PROBE_CLEANUP_CONCISE_OUTPUT",
    code: "SSC_SECRET_FLOW_DENIED",
    detector: "CLEANUP_DIAGNOSTIC",
  }),
  Object.freeze({
    id: "PROBE_AUTHORITY_BRAND",
    code: "SSC_AUTHORITY_SHAPE",
    detector: "AUTHORITY_SCHEMA",
  }),
]);

const Taint = Object.freeze({
  NONE: 0,
  CREDENTIAL: 1,
  SENSITIVE_DIAGNOSTIC: 2,
  MAYBE_SENSITIVE: 4,
});

const REACHABLE_IMPORT_CAPABILITIES = Object.freeze({
  drizzle: "DRIZZLE",
  migrate: "MIGRATE",
  Pool: "POOL_CONSTRUCTOR",
  Client: "UNUSED_EXTERNAL",
  inspectRuntimeDatabaseRoleAuthorityPosture: "UNUSED_EXTERNAL",
});

class StaticFailure extends Error {
  constructor(code, detector) {
    super(code);
    this.name = "StaticFailure";
    this.code = code;
    this.detector = detector;
  }
}

function fail(code, detector) {
  throw new StaticFailure(code, detector);
}

function failureOf(error) {
  if (error instanceof StaticFailure) {
    return Object.freeze({ code: error.code, detector: error.detector });
  }
  return Object.freeze({ code: SAFE.internal, detector: "ANALYZER_BOUNDARY" });
}

function keyForDeclaration(declaration) {
  return `${declaration.kind}:${declaration.pos}:${declaration.end}`;
}

function sameTextSet(actual, expected) {
  if (actual.length !== expected.length) return false;
  const remaining = new Set(expected);
  for (const value of actual) {
    if (!remaining.delete(value)) return false;
  }
  return remaining.size === 0;
}

function joinTaint(left, right) {
  return left | right;
}

function hasTaint(value, mask) {
  return Boolean((value?.taint ?? Taint.NONE) & mask);
}

function value({
  kind = "unknown",
  taint = Taint.NONE,
  caps = [],
  props = null,
  fn = null,
  closure = null,
  bound = null,
  label = "",
  directCredential = false,
  elements = null,
  map = null,
} = {}) {
  return {
    kind,
    taint,
    caps: new Set(caps),
    props: props instanceof Map ? props : new Map(),
    fn,
    closure,
    bound,
    label,
    directCredential,
    elements,
    map,
  };
}

function unknownValue() {
  return value();
}

function primitiveValue(label = "") {
  return value({ kind: "primitive", label });
}

function credentialValue() {
  return value({
    kind: "credential",
    taint: Taint.CREDENTIAL,
    directCredential: true,
    label: "input.connectionPassword",
  });
}

function capabilityValue(cap, options = {}) {
  return value({ ...options, kind: "capability", caps: [cap] });
}

function mergeValues(left, right) {
  if (!left) return right ?? unknownValue();
  if (!right) return left;
  if (left === right) return left;
  if (left.kind === "unknown") {
    const preserved = { ...right, taint: joinTaint(left.taint, right.taint) };
    return preserved;
  }
  if (right.kind === "unknown") {
    const preserved = { ...left, taint: joinTaint(left.taint, right.taint) };
    return preserved;
  }
  const merged = value({
    kind: left.kind === right.kind ? left.kind : "unknown",
    taint: joinTaint(left.taint, right.taint),
    caps: [...left.caps, ...right.caps],
    bound: left.bound === right.bound ? left.bound : null,
    label: left.label === right.label ? left.label : "",
    directCredential: left.directCredential && right.directCredential,
  });
  for (const [key, property] of left.props) {
    if (right.props.has(key)) {
      merged.props.set(key, mergeValues(property, right.props.get(key)));
    }
  }
  return merged;
}

function moduleNameFromImport(declaration) {
  return declaration.moduleSpecifier?.text ?? "";
}

function isFunctionLike(node) {
  return ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node);
}

class ClosureAnalyzer {
  constructor({ source, sourceFile, program, checker }) {
    this.source = source;
    this.sourceFile = sourceFile;
    this.program = program;
    this.checker = checker;
    this.topValues = new Map();
    this.topValuesByName = new Map();
    this.bindingNames = new Map();
    this.topInitialising = new Set();
    this.functionActive = new Set();
    this.weakMapRecords = new Map();
    this.poolConstructs = 0;
    this.poolOptions = null;
    this.authorityToken = null;
    this.authorityRecord = null;
    this.authoritySetCount = 0;
    this.declassificationCount = 0;
    this.importAliases = new Map();
    this.rootFunction = null;
  }

  analyze() {
    this.validateImportsAndIndex();
    this.scanModuleInitializers();
    this.rootFunction = this.findRootFunction();
    const input = value({ kind: "input" });
    const operation = value({ kind: "opaque-function", caps: ["OPAQUE_OPERATION"] });
    const rootResult = this.analyzeFunction(this.rootFunction, [input, operation], null);
    if (rootResult.kind === "unknown" ||
        hasTaint(rootResult, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC | Taint.MAYBE_SENSITIVE) ||
        rootResult.caps.size > 0) {
      fail(SAFE.flow, "PUBLIC_RETURN");
    }
    if (this.poolConstructs !== 1 || this.declassificationCount !== 1) {
      fail(SAFE.flow, "CAPABILITY_POOL");
    }
    if (!this.authorityRecord || this.authoritySetCount !== 1) {
      fail(SAFE.authority, "AUTHORITY_SCHEMA");
    }
    return Object.freeze({
      id: SAFE.baseline,
      ok: true,
      poolConstructs: this.poolConstructs,
      authoritySets: this.authoritySetCount,
    });
  }

  validateImportsAndIndex() {
    for (const statement of this.sourceFile.statements) {
      if (!ts.isImportDeclaration(statement)) continue;
      const moduleName = moduleNameFromImport(statement);
      const allowed = IMPORT_TABLE[moduleName];
      if (!allowed || !statement.importClause || statement.importClause.name ||
          statement.importClause.isTypeOnly ||
          !statement.importClause.namedBindings ||
          !ts.isNamedImports(statement.importClause.namedBindings)) {
        fail(SAFE.imports, "IMPORT_TABLE");
      }
      const names = [];
      for (const specifier of statement.importClause.namedBindings.elements) {
        if (specifier.isTypeOnly || specifier.propertyName && !ts.isIdentifier(specifier.propertyName) ||
            !ts.isIdentifier(specifier.name)) {
          fail(SAFE.imports, "IMPORT_TABLE");
        }
        const imported = specifier.propertyName?.text ?? specifier.name.text;
        names.push(imported);
        this.importAliases.set(keyForDeclaration(specifier.name), {
          moduleName,
          imported,
        });
      }
      if (!sameTextSet(names, allowed)) {
        fail(SAFE.imports, "IMPORT_TABLE");
      }
    }
  }

  scanModuleInitializers() {
    const moduleEnv = new Map();
    for (const statement of this.sourceFile.statements) {
      if (ts.isImportDeclaration(statement)) {
        continue;
      }
      if (ts.isVariableStatement(statement)) {
        for (const declaration of statement.declarationList.declarations) {
          if (!ts.isIdentifier(declaration.name)) fail(SAFE.ast, "SYNTAX_POLICY");
          const key = keyForDeclaration(declaration.name);
          if (declaration.initializer) {
            const initialized = this.evalExpression(declaration.initializer, moduleEnv, {});
            if (declaration.name.text === "identitySql") initialized.label = "identitySql";
            this.topValues.set(key, initialized);
            this.topValuesByName.set(declaration.name.text, initialized);
            moduleEnv.set(key, initialized);
            this.bindingNames.set(key, declaration.name.text);
          } else {
            const empty = unknownValue();
            this.topValues.set(key, empty);
            this.topValuesByName.set(declaration.name.text, empty);
            moduleEnv.set(key, empty);
            this.bindingNames.set(key, declaration.name.text);
          }
        }
      } else if (ts.isClassDeclaration(statement)) {
        this.scanClassInitialization(statement, moduleEnv);
      } else if (ts.isFunctionDeclaration(statement)) {
        if (!statement.name) fail(SAFE.ast, "TOP_LEVEL_SYNTAX");
        this.bindingNames.set(keyForDeclaration(statement.name), statement.name.text);
      } else {
        fail(SAFE.ast, "TOP_LEVEL_SYNTAX");
      }
    }
  }

  scanClassInitialization(node, env) {
    if (node.heritageClauses) {
      for (const heritage of node.heritageClauses) {
        for (const type of heritage.types) {
          this.evalExpression(type.expression, env, {});
        }
      }
    }
    for (const member of node.members) {
      if (member.name?.kind === ts.SyntaxKind.ComputedPropertyName) {
        fail(SAFE.computed, "COMPUTED_CAPABILITY");
      }
      if (ts.isPropertyDeclaration(member) && member.initializer) {
        this.evalExpression(member.initializer, env, {});
      }
      if (ts.isClassStaticBlockDeclaration(member)) {
        this.analyzeStatements(member.body.statements, new Map(env), {});
      }
    }
  }

  findRootFunction() {
    const roots = this.sourceFile.statements.filter(
      (statement) => ts.isFunctionDeclaration(statement) &&
        statement.name?.text === ROOT_EXPORT,
    );
    if (roots.length !== 1) fail(SAFE.ast, "ROOT_EXPORT");
    const root = roots[0];
    if (!root.body || !root.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword)) {
      fail(SAFE.ast, "ROOT_EXPORT");
    }
    return root;
  }

  topValue(name) {
    return this.topValuesByName.get(name) ?? unknownValue();
  }

  resolveDeclaration(identifier) {
    const symbol = this.checker.getSymbolAtLocation(identifier);
    if (!symbol) return null;
    if (symbol.flags & ts.SymbolFlags.Alias) {
      let aliased;
      try {
        aliased = this.checker.getAliasedSymbol(symbol);
      } catch {
        fail(SAFE.unresolved, "CALL_RESOLUTION");
      }
      return { kind: "import", symbol, aliased };
    }
    const declarations = (symbol.declarations ?? []).filter(
      (declaration) => declaration.getSourceFile() === this.sourceFile,
    );
    if (declarations.length === 0) {
      return { kind: "global", name: identifier.text };
    }
    if (declarations.length !== 1) {
      fail(SAFE.unresolved, "CALL_RESOLUTION");
    }
    return { kind: "local", declaration: declarations[0], symbol };
  }

  lookup(identifier, env) {
    const resolved = this.resolveDeclaration(identifier);
    if (resolved?.kind === "local") {
      const declaration = resolved.declaration;
      const key = keyForDeclaration(
        ts.isIdentifier(declaration.name) ? declaration.name : declaration,
      );
      if (env.has(key)) return env.get(key);
      if (ts.isShorthandPropertyAssignment(declaration)) {
        const matches = [...env.entries()].filter(([candidate]) => this.bindingNames.get(candidate) === identifier.text);
        if (matches.length === 1) return matches[0][1];
      }
      if (this.topValues.has(key)) return this.topValues.get(key);
      if (ts.isVariableDeclaration(declaration)) {
        if (this.topInitialising.has(key)) return unknownValue();
        this.topInitialising.add(key);
        const initialized = declaration.initializer
          ? this.evalExpression(declaration.initializer, env, {})
          : unknownValue();
        this.topInitialising.delete(key);
        this.topValues.set(key, initialized);
        return initialized;
      }
      if (ts.isFunctionDeclaration(declaration) && declaration.body) {
        return value({ kind: "function", fn: declaration, closure: env });
      }
      if (ts.isClassDeclaration(declaration)) {
        return value({ kind: "class", fn: declaration, closure: env });
      }
      return unknownValue();
    }
    if (resolved?.kind === "import") {
      const declaration = resolved.symbol.declarations?.[0];
      const imported = declaration && ts.isImportSpecifier(declaration)
        ? declaration.propertyName?.text ?? declaration.name.text
        : "";
      const moduleName = declaration?.parent?.parent?.parent &&
        ts.isImportDeclaration(declaration.parent.parent.parent)
        ? moduleNameFromImport(declaration.parent.parent.parent)
        : "";
      return value({
        kind: "import",
        caps: [REACHABLE_IMPORT_CAPABILITIES[imported] ?? "UNUSED_EXTERNAL"],
        label: `${moduleName}:${imported}`,
      });
    }
    return this.globalValue(identifier.text);
  }

  globalValue(name) {
    const globals = {
      Object: value({ kind: "global", caps: ["GLOBAL_OBJECT"] }),
      Array: value({ kind: "global", caps: ["GLOBAL_ARRAY"] }),
      Set: value({ kind: "global", caps: ["SET_CONSTRUCTOR"] }),
      Map: value({ kind: "global", caps: ["MAP_CONSTRUCTOR"] }),
      WeakMap: value({ kind: "global", caps: ["WEAKMAP_CONSTRUCTOR"] }),
      WeakSet: value({ kind: "global", caps: ["WEAKSET_CONSTRUCTOR"] }),
      Symbol: value({ kind: "global", caps: ["SYMBOL_CONSTRUCTOR"] }),
      URL: value({ kind: "global", caps: ["URL_CONSTRUCTOR"] }),
      Error: value({ kind: "global", caps: ["ERROR_CONSTRUCTOR"] }),
      Number: value({ kind: "global", caps: ["NUMBER_CONSTRUCTOR"] }),
      String: value({ kind: "global", caps: ["STRING_CONSTRUCTOR"] }),
      RegExp: value({ kind: "global", caps: ["REGEXP_CONSTRUCTOR"] }),
      decodeURIComponent: value({ kind: "global", caps: ["DECODE_URI"] }),
      console: value({ kind: "global", caps: ["CONSOLE"] }),
      process: value({ kind: "global", caps: ["PROCESS"] }),
      globalThis: value({ kind: "global", caps: ["GLOBAL_THIS"] }),
      JSON: value({ kind: "global", caps: ["JSON"] }),
      undefined: primitiveValue("undefined"),
      NaN: primitiveValue("NaN"),
      Infinity: primitiveValue("Infinity"),
    };
    return globals[name] ?? unknownValue();
  }

  analyzeFunction(node, args, closure) {
    const signature = `${node.pos}:${node.end}`;
    if (this.functionActive.has(signature)) fail(SAFE.flow, "FIXED_POINT_RECURSION");
    this.functionActive.add(signature);
    try {
      const env = new Map(closure ?? this.topValues);
      for (const [index, parameter] of node.parameters.entries()) {
        if (!ts.isIdentifier(parameter.name) || parameter.initializer || parameter.dotDotDotToken) {
          fail(SAFE.ast, "SYNTAX_POLICY");
        }
        env.set(keyForDeclaration(parameter.name), args[index] ?? unknownValue());
        this.bindingNames.set(keyForDeclaration(parameter.name), parameter.name.text);
      }
      if (!node.body) fail(SAFE.ast, "SYNTAX_POLICY");
      const result = ts.isBlock(node.body)
        ? this.analyzeStatements(node.body.statements, env, {})
        : { env, returnValue: this.evalExpression(node.body, env, {}) };
      return result.returnValue ?? primitiveValue("undefined");
    } finally {
      this.functionActive.delete(signature);
    }
  }

  analyzeStatements(statements, env, context) {
    let returnValue = null;
    let current = env;
    for (const statement of statements) {
      const result = this.analyzeStatement(statement, current, context);
      current = result.env;
      returnValue = mergeValues(returnValue, result.returnValue);
    }
    return { env: current, returnValue };
  }

  analyzeStatement(node, env, context) {
    if (ts.isBlock(node)) return this.analyzeStatements(node.statements, env, context);
    if (ts.isEmptyStatement(node) || ts.isDebuggerStatement(node)) {
      return { env, returnValue: null };
    }
    if (ts.isVariableStatement(node)) {
      for (const declaration of node.declarationList.declarations) {
        if (!ts.isIdentifier(declaration.name)) fail(SAFE.ast, "SYNTAX_POLICY");
        const initialized = declaration.initializer
          ? this.evalExpression(declaration.initializer, env, context)
          : unknownValue();
        if (initialized.caps.has("OUTPUT") || initialized.caps.has("CRYPTO")) initialized.aliasProvenance = true;
        env.set(keyForDeclaration(declaration.name), initialized);
        this.bindingNames.set(keyForDeclaration(declaration.name), declaration.name.text);
      }
      return { env, returnValue: null };
    }
    if (ts.isExpressionStatement(node)) {
      this.evalExpression(node.expression, env, context);
      return { env, returnValue: null };
    }
    if (ts.isFunctionDeclaration(node)) {
      if (node.name) this.bindingNames.set(keyForDeclaration(node.name), node.name.text);
      return { env, returnValue: null };
    }
    if (ts.isReturnStatement(node)) {
      return {
        env,
        returnValue: node.expression
          ? this.evalExpression(node.expression, env, context)
          : primitiveValue("undefined"),
      };
    }
    if (ts.isThrowStatement(node)) {
      const thrown = this.evalExpression(node.expression, env, context);
      if (hasTaint(thrown, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC)) {
        if (!context.allowCatchRethrow || !thrown.caps.has("CATCH_ERROR")) {
          fail("SSC_PUBLIC_SURFACE", "PUBLIC_CAUSE");
        }
      }
      return { env, returnValue: null };
    }
    if (ts.isIfStatement(node)) {
      const condition = this.evalExpression(node.expression, env, context);
      const thenContext = this.isAdmissionCatchGuard(node.expression, env)
        ? { ...context, allowCatchRethrow: true }
        : context;
      const thenResult = this.analyzeStatement(node.thenStatement, new Map(env), thenContext);
      const elseResult = node.elseStatement
        ? this.analyzeStatement(node.elseStatement, new Map(env), context)
        : { env: new Map(env), returnValue: null };
      void condition;
      return {
        env: this.joinEnvironments(thenResult.env, elseResult.env),
        returnValue: mergeValues(thenResult.returnValue, elseResult.returnValue),
      };
    }
    if (ts.isTryStatement(node)) {
      const tryResult = this.analyzeStatement(node.tryBlock, new Map(env), context);
      let catchResult = { env: new Map(env), returnValue: null };
      if (node.catchClause) {
        const catchEnv = new Map(env);
        if (node.catchClause.variableDeclaration) {
          const catchName = node.catchClause.variableDeclaration.name;
          if (!ts.isIdentifier(catchName)) fail(SAFE.ast, "SYNTAX_POLICY");
          catchEnv.set(
            keyForDeclaration(catchName),
            value({ kind: "caught-error", taint: Taint.MAYBE_SENSITIVE, caps: ["CATCH_ERROR"] }),
          );
        }
        catchResult = this.analyzeStatement(node.catchClause.block, catchEnv, context);
      }
      const joined = this.joinEnvironments(tryResult.env, catchResult.env);
      const finalResult = node.finallyBlock
        ? this.analyzeStatement(node.finallyBlock, joined, context)
        : { env: joined, returnValue: null };
      return {
        env: finalResult.env,
        returnValue: mergeValues(
          mergeValues(tryResult.returnValue, catchResult.returnValue),
          finalResult.returnValue,
        ),
      };
    }
    if (ts.isForOfStatement(node)) {
      this.evalExpression(node.expression, env, context);
      const loopEnv = new Map(env);
      if (ts.isVariableDeclarationList(node.initializer) && node.initializer.declarations.length === 1) {
        const declaration = node.initializer.declarations[0];
        if (!ts.isIdentifier(declaration.name)) fail(SAFE.ast, "SYNTAX_POLICY");
        loopEnv.set(keyForDeclaration(declaration.name), unknownValue());
        this.bindingNames.set(keyForDeclaration(declaration.name), declaration.name.text);
      }
      return this.analyzeStatement(node.statement, loopEnv, context);
    }
    if (ts.isForStatement(node) || ts.isWhileStatement(node) || ts.isDoStatement(node)) {
      if (node.initializer && ts.isVariableDeclarationList(node.initializer)) {
        for (const declaration of node.initializer.declarations) {
          if (!ts.isIdentifier(declaration.name)) fail(SAFE.ast, "SYNTAX_POLICY");
          env.set(
            keyForDeclaration(declaration.name),
            declaration.initializer
              ? this.evalExpression(declaration.initializer, env, context)
              : unknownValue(),
          );
          this.bindingNames.set(keyForDeclaration(declaration.name), declaration.name.text);
        }
      }
      if (node.condition) this.evalExpression(node.condition, env, context);
      const body = this.analyzeStatement(node.statement, new Map(env), context);
      if (node.incrementor) this.evalExpression(node.incrementor, body.env, context);
      return { env: this.joinEnvironments(env, body.env), returnValue: body.returnValue };
    }
    if (ts.isLabeledStatement(node)) return this.analyzeStatement(node.statement, env, context);
    if (ts.isWithStatement(node) || ts.isSwitchStatement(node) || ts.isClassDeclaration(node)) {
      fail(SAFE.ast, "SYNTAX_POLICY");
    }
    if (ts.isBreakStatement(node) || ts.isContinueStatement(node)) {
      return { env, returnValue: null };
    }
    fail(SAFE.ast, "SYNTAX_POLICY");
  }

  isAdmissionCatchGuard(expression, env) {
    return ts.isBinaryExpression(expression) &&
      expression.operatorToken.kind === ts.SyntaxKind.InstanceOfKeyword &&
      ts.isIdentifier(expression.left) &&
      this.lookup(expression.left, env).caps.has("CATCH_ERROR") &&
      ts.isIdentifier(expression.right) &&
      expression.right.text === "DisposablePostgresFixtureAdmissionError";
  }

  joinEnvironments(left, right) {
    const joined = new Map();
    const keys = new Set([...left.keys(), ...right.keys()]);
    for (const key of keys) joined.set(key, mergeValues(left.get(key), right.get(key)));
    return joined;
  }

  evalExpression(node, env, context) {
    if (!node) return primitiveValue("undefined");
    switch (node.kind) {
      case ts.SyntaxKind.Identifier:
        return this.lookup(node, env);
      case ts.SyntaxKind.StringLiteral:
      case ts.SyntaxKind.NumericLiteral:
      case ts.SyntaxKind.BigIntLiteral:
      case ts.SyntaxKind.NoSubstitutionTemplateLiteral:
        return primitiveValue(node.text);
      case ts.SyntaxKind.RegularExpressionLiteral:
        return value({ kind: "regexp" });
      case ts.SyntaxKind.TrueKeyword:
      case ts.SyntaxKind.FalseKeyword:
      case ts.SyntaxKind.NullKeyword:
        return primitiveValue(ts.tokenToString(node.kind) ?? "literal");
      case ts.SyntaxKind.ThisKeyword:
        return value({ kind: "this" });
      case ts.SyntaxKind.ArrayLiteralExpression:
        return this.evalArray(node, env, context);
      case ts.SyntaxKind.ObjectLiteralExpression:
        return this.evalObject(node, env, context);
      case ts.SyntaxKind.PropertyAccessExpression:
        return this.getProperty(
          this.evalExpression(node.expression, env, context),
          node.name.text,
          false,
        );
      case ts.SyntaxKind.ElementAccessExpression:
        return this.evalElement(node, env, context);
      case ts.SyntaxKind.CallExpression:
        return this.evalCall(node, env, context);
      case ts.SyntaxKind.NewExpression:
        return this.evalNew(node, env, context);
      case ts.SyntaxKind.AwaitExpression:
        return this.evalExpression(node.expression, env, context);
      case ts.SyntaxKind.ParenthesizedExpression:
      case ts.SyntaxKind.NonNullExpression:
      case ts.SyntaxKind.AsExpression:
      case ts.SyntaxKind.TypeAssertionExpression:
        return this.evalExpression(node.expression, env, context);
      case ts.SyntaxKind.ArrowFunction:
      case ts.SyntaxKind.FunctionExpression:
        return value({ kind: "function", fn: node, closure: env });
      case ts.SyntaxKind.BinaryExpression:
        return this.evalBinary(node, env, context);
      case ts.SyntaxKind.PrefixUnaryExpression:
        return this.evalPrefixUnary(node, env, context);
      case ts.SyntaxKind.TypeOfExpression:
        this.evalExpression(node.expression, env, context);
        return primitiveValue("string");
      case ts.SyntaxKind.PostfixUnaryExpression:
        this.evalExpression(node.operand, env, context);
        return primitiveValue("number");
      case ts.SyntaxKind.ConditionalExpression:
        this.evalExpression(node.condition, env, context);
        return mergeValues(
          this.evalExpression(node.whenTrue, new Map(env), context),
          this.evalExpression(node.whenFalse, new Map(env), context),
        );
      case ts.SyntaxKind.TemplateExpression:
        return this.evalTemplate(node, env, context);
      case ts.SyntaxKind.DeleteExpression: {
        const target = node.expression;
        if (ts.isPropertyAccessExpression(target)) {
          const receiver = this.evalExpression(target.expression, env, context);
          if (receiver.caps.has("ENV")) fail(SAFE.flow, "CAPABILITY_ENV");
        } else if (ts.isElementAccessExpression(target)) {
          const receiver = this.evalExpression(target.expression, env, context);
          if (receiver.caps.has("ENV")) fail(SAFE.flow, "CAPABILITY_ENV");
        } else {
          fail(SAFE.ast, "SYNTAX_POLICY");
        }
        return primitiveValue("boolean");
      }
      case ts.SyntaxKind.VoidExpression:
        this.evalExpression(node.expression, env, context);
        return primitiveValue("undefined");
      case ts.SyntaxKind.MetaProperty:
      case ts.SyntaxKind.YieldExpression:
      case ts.SyntaxKind.AwaitKeyword:
        fail(SAFE.ast, "SYNTAX_POLICY");
        break;
      default:
        fail(SAFE.ast, "SYNTAX_POLICY");
    }
  }

  evalArray(node, env, context) {
    const elements = [];
    for (const element of node.elements) {
      if (!element || ts.isOmittedExpression(element) || ts.isSpreadElement(element)) {
        fail(SAFE.ast, "SYNTAX_POLICY");
      }
      elements.push(this.evalExpression(element, env, context));
    }
    return value({ kind: "array", elements });
  }

  evalObject(node, env, context) {
    const result = value({ kind: "object" });
    for (const property of node.properties) {
      if (property.name?.kind === ts.SyntaxKind.ComputedPropertyName) {
        fail(SAFE.computed, "COMPUTED_CAPABILITY");
      }
      if (ts.isSpreadAssignment(property) || ts.isMethodDeclaration(property) ||
          ts.isGetAccessorDeclaration(property) || ts.isSetAccessorDeclaration(property)) {
        fail(SAFE.ast, "SYNTAX_POLICY");
      }
      let name;
      if (ts.isPropertyAssignment(property) || ts.isShorthandPropertyAssignment(property)) {
        name = property.name.getText(this.sourceFile).replace(/^['"]|['"]$/gu, "");
      } else {
        fail(SAFE.ast, "SYNTAX_POLICY");
      }
      const propertyValue = ts.isPropertyAssignment(property)
        ? this.evalExpression(property.initializer, env, context)
        : this.evalExpression(property.name, env, context);
      result.props.set(name, propertyValue);
      result.taint |= propertyValue.taint;
    }
    if (sameTextSet([...result.props.keys()], ["host", "port", "user", "database", "max"])) {
      result.kind = "pool-options";
    }
    return result;
  }

  evalElement(node, env, context) {
    const receiver = this.evalExpression(node.expression, env, context);
    if (!node.argumentExpression) fail(SAFE.computed, "COMPUTED_CAPABILITY");
    if (ts.isNumericLiteral(node.argumentExpression) && node.argumentExpression.text === "0") {
      return this.getProperty(receiver, "0", false);
    }
    if (receiver.caps.has("CONSOLE") || receiver.caps.has("CRYPTO") ||
        receiver.caps.has("PROCESS") || receiver.caps.has("GLOBAL_THIS")) {
      fail(SAFE.computed, "COMPUTED_CAPABILITY");
    }
    fail(SAFE.computed, "COMPUTED_CAPABILITY");
  }

  evalCall(node, env, context) {
    const callee = this.evalExpression(node.expression, env, context);
    const args = [];
    for (const argument of node.arguments) {
      if (ts.isSpreadElement(argument)) fail(SAFE.ast, "SYNTAX_POLICY");
      args.push(this.evalExpression(argument, env, context));
    }
    return this.call(callee, args, node, env, context);
  }

  evalNew(node, env, context) {
    const callee = this.evalExpression(node.expression, env, context);
    const args = [];
    for (const argument of node.arguments ?? []) {
      if (ts.isSpreadElement(argument)) fail(SAFE.ast, "SYNTAX_POLICY");
      args.push(this.evalExpression(argument, env, context));
    }
    if (callee.caps.has("POOL_CONSTRUCTOR")) {
      if (args.length !== 1 || args[0].kind !== "pool-options") fail(SAFE.flow, "CAPABILITY_POOL");
      const options = args[0];
      const keys = [...options.props.keys()];
      if (!sameTextSet(keys, ["host", "port", "user", "database", "max", "password"]) &&
          !sameTextSet(keys, ["host", "port", "user", "database", "max"])) {
        fail(SAFE.flow, "CAPABILITY_POOL");
      }
      if (options.props.has("password")) {
        const password = options.props.get("password");
        if (password.kind !== "credential" ||
            !password.directCredential ||
            password.label !== "input.connectionPassword" ||
            password.taint !== Taint.CREDENTIAL) {
          fail(SAFE.flow, "CAPABILITY_PASSWORD");
        }
      }
      this.poolConstructs += 1;
      if (this.poolConstructs > 1) fail(SAFE.flow, "CAPABILITY_POOL");
      const pool = value({ kind: "pool" });
      pool.options = options;
      return pool;
    }
    if (callee.caps.has("URL_CONSTRUCTOR")) {
      if (args.some((item) => hasTaint(item, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC))) {
        fail(SAFE.flow, "CAPABILITY_URL");
      }
      return value({ kind: "url" });
    }
    if (callee.caps.has("SET_CONSTRUCTOR")) return value({ kind: "set" });
    if (callee.caps.has("MAP_CONSTRUCTOR")) return value({ kind: "map" });
    if (callee.caps.has("WEAKMAP_CONSTRUCTOR")) {
      return value({ kind: "weakmap", map: new Map() });
    }
    if (callee.caps.has("SYMBOL_CONSTRUCTOR")) return value({ kind: "symbol" });
    if (callee.caps.has("REGEXP_CONSTRUCTOR")) return value({ kind: "regexp" });
    if (callee.caps.has("ERROR_CONSTRUCTOR")) {
      if (args.some((item) => hasTaint(item, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC))) {
        fail("SSC_PUBLIC_SURFACE", "PUBLIC_CAUSE");
      }
      return value({ kind: "error" });
    }
    if (callee.kind === "class") return value({ kind: "error" });
    if (callee.fn && isFunctionLike(callee.fn)) return this.analyzeFunction(callee.fn, args, callee.closure);
    fail(SAFE.unresolved, "CALL_RESOLUTION");
  }

  evalBinary(node, env, context) {
    if (node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      const right = this.evalExpression(node.right, env, context);
      this.assignTarget(node.left, right, env, context);
      return right;
    }
    if ([
      ts.SyntaxKind.PlusEqualsToken,
      ts.SyntaxKind.MinusEqualsToken,
      ts.SyntaxKind.AsteriskEqualsToken,
      ts.SyntaxKind.SlashEqualsToken,
      ts.SyntaxKind.PercentEqualsToken,
      ts.SyntaxKind.AmpersandEqualsToken,
      ts.SyntaxKind.BarEqualsToken,
      ts.SyntaxKind.CaretEqualsToken,
      ts.SyntaxKind.LessThanLessThanEqualsToken,
      ts.SyntaxKind.GreaterThanGreaterThanEqualsToken,
      ts.SyntaxKind.GreaterThanGreaterThanGreaterThanEqualsToken,
      ts.SyntaxKind.QuestionQuestionEqualsToken,
      ts.SyntaxKind.AmpersandAmpersandEqualsToken,
      ts.SyntaxKind.BarBarEqualsToken,
      ts.SyntaxKind.AsteriskAsteriskEqualsToken,
    ].includes(node.operatorToken.kind)) {
      fail(SAFE.ast, "SYNTAX_POLICY");
    }
    const left = this.evalExpression(node.left, env, context);
    const right = this.evalExpression(node.right, env, context);
    const operator = node.operatorToken.kind;
    if (operator === ts.SyntaxKind.PlusToken) {
      if (hasTaint(left, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC) ||
          hasTaint(right, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC)) {
        fail(SAFE.flow, "CAPABILITY_RECONSTRUCTION");
      }
      return primitiveValue("string");
    }
    if (operator === ts.SyntaxKind.AmpersandAmpersandToken ||
        operator === ts.SyntaxKind.BarBarToken ||
        operator === ts.SyntaxKind.QuestionQuestionToken) {
      return mergeValues(left, right);
    }
    return primitiveValue("boolean");
  }

  evalPrefixUnary(node, env, context) {
    const operand = this.evalExpression(node.operand, env, context);
    if (node.operator === ts.SyntaxKind.PlusPlusToken || node.operator === ts.SyntaxKind.MinusMinusToken) {
      fail(SAFE.ast, "SYNTAX_POLICY");
    }
    if (node.operator === ts.SyntaxKind.PlusToken || node.operator === ts.SyntaxKind.MinusToken ||
        node.operator === ts.SyntaxKind.TildeToken) {
      if (hasTaint(operand, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC)) {
        fail(SAFE.flow, "CAPABILITY_RECONSTRUCTION");
      }
    }
    return primitiveValue("boolean");
  }

  evalTemplate(node, env, context) {
    for (const span of node.templateSpans) {
      const expression = this.evalExpression(span.expression, env, context);
      if (hasTaint(expression, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC)) {
        fail(SAFE.flow, "CAPABILITY_RECONSTRUCTION");
      }
    }
    return primitiveValue("string");
  }

  getProperty(receiver, name, computed) {
    if (computed) fail(SAFE.computed, "COMPUTED_CAPABILITY");
    if (!receiver) return unknownValue();
    if (receiver.props.has(name)) return receiver.props.get(name);
    if (receiver.kind === "input") {
      if (name === "connectionPassword") return credentialValue();
      if (SAFE_INPUT_FIELDS.has(name)) return primitiveValue(`input.${name}`);
    }
    if (receiver.kind === "row" && QUERY_ROW_FIELDS.has(name)) {
      return primitiveValue(`query.${name}`);
    }
    if (receiver.kind === "array") {
      if (name === "length") return primitiveValue("number");
      const index = Number(name);
      if (Number.isInteger(index) && index >= 0 && receiver.elements?.[index]) return receiver.elements[index];
      if (name === "some") return capabilityValue("ARRAY_SOME", { bound: receiver });
      if (name === "includes") return capabilityValue("ARRAY_INCLUDES", { bound: receiver });
    }
    if (receiver.kind === "url") return value({ kind: "string", label: name });
    if (receiver.kind === "regexp" && name === "test") return capabilityValue("REGEXP_TEST", { bound: receiver });
    if (receiver.kind === "set" && name === "has") return capabilityValue("SET_HAS", { bound: receiver });
    if (receiver.kind === "set" && name === "add") return capabilityValue("SET_ADD", { bound: receiver });
    if (receiver.kind === "weakmap" && !receiver.map) receiver.map = new Map();
    if (receiver.kind === "weakmap" && name === "set") return capabilityValue("WEAKMAP_SET", { bound: receiver });
    if (receiver.kind === "weakmap" && name === "get") return capabilityValue("WEAKMAP_GET", { bound: receiver });
    if (receiver.kind === "pool" && name === "query") return capabilityValue("POOL_QUERY", { bound: receiver });
    if (receiver.kind === "pool" && name === "connect") return capabilityValue("POOL_CONNECT", { bound: receiver });
    if (receiver.kind === "pool" && name === "end") return capabilityValue("POOL_END", { bound: receiver });
    if (receiver.kind === "drizzle-db") return primitiveValue(name);
    if (receiver.kind === "query-result" && name === "rows") {
      return value({ kind: "array", elements: [value({ kind: "row" })] });
    }
    if (receiver.kind === "string" || receiver.kind === "credential") {
      if (name === "length") return primitiveValue("number");
      if (["trim", "replace", "toLowerCase", "slice"].includes(name)) {
        return capabilityValue("STRING_METHOD", { bound: receiver, label: name });
      }
    }
    if (receiver.caps.has("GLOBAL_OBJECT")) {
      const methods = {
        freeze: "OBJECT_FREEZE",
        keys: "OBJECT_KEYS",
        hasOwn: "OBJECT_HAS_OWN",
      };
      if (methods[name]) return capabilityValue(methods[name]);
    }
    if (receiver.caps.has("GLOBAL_ARRAY") && name === "isArray") return capabilityValue("ARRAY_IS_ARRAY");
    if (receiver.caps.has("CONSOLE") && ["log", "error", "warn", "info", "debug"].includes(name)) {
      return capabilityValue("OUTPUT", { label: name });
    }
    if (receiver.caps.has("PROCESS") && name === "env") return capabilityValue("ENV");
    if (receiver.caps.has("ENV")) return unknownValue();
    if (receiver.caps.has("JSON") && name === "stringify") return capabilityValue("JSON_STRINGIFY");
    if (receiver.caps.has("GLOBAL_THIS") && name === "crypto") return capabilityValue("CRYPTO");
    if (receiver.caps.has("CRYPTO") && name === "subtle") return capabilityValue("CRYPTO_SUBTLE");
    if (receiver.caps.has("CRYPTO_SUBTLE") && ["digest", "deriveKey", "deriveBits", "encrypt", "decrypt", "sign"].includes(name)) {
      return capabilityValue("CRYPTO");
    }
    if (receiver.caps.has("CLEANUP_PROMISE") && name === "catch") return capabilityValue("CLEANUP_CATCH", { bound: receiver });
    if (receiver.caps.has("CATCH_ERROR")) return value({ kind: "diagnostic", taint: Taint.SENSITIVE_DIAGNOSTIC, caps: ["CATCH_ERROR"] });
    return unknownValue();
  }

  call(callee, args, node, env, context) {
    if (callee.caps.has("OUTPUT")) {
      if (args.some((item) => item.caps.has("CLEANUP_DIAGNOSTIC") || item.caps.has("CATCH_ERROR"))) {
        fail(SAFE.flow, "CLEANUP_DIAGNOSTIC");
      }
      if (callee.label && callee.label !== "") {
        if (hasTaint(args[0], Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC) &&
            callee.aliasProvenance) {
          fail(SAFE.flow, "ALIAS_PROVENANCE");
        }
      }
      if (args.some((item) => hasTaint(item, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC))) {
        fail(SAFE.flow, "CAPABILITY_OUTPUT");
      }
      fail(SAFE.flow, "CAPABILITY_OUTPUT");
    }
    if (callee.caps.has("CRYPTO")) {
      if (args.some((item) => hasTaint(item, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC))) {
        fail(SAFE.flow, "CAPABILITY_CRYPTO");
      }
      fail(SAFE.flow, "CAPABILITY_CRYPTO");
    }
    if (callee.caps.has("ENV")) fail(SAFE.flow, "CAPABILITY_ENV");
    if (callee.caps.has("POOL_QUERY")) {
      if (args.length !== 2 || args[0].label !== "identitySql" || args[1].kind !== "array" ||
          args[1].elements?.length !== 2 || args[1].elements.some((item) => hasTaint(item, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC))) {
        fail(SAFE.flow, "CAPABILITY_QUERY");
      }
      return value({ kind: "query-result" });
    }
    if (callee.caps.has("POOL_END")) {
      if (args.length !== 0) fail(SAFE.flow, "CAPABILITY_CLEANUP");
      return capabilityValue("CLEANUP_PROMISE", { bound: callee.bound, taint: Taint.SENSITIVE_DIAGNOSTIC });
    }
    if (callee.caps.has("DRIZZLE")) {
      if (args.length !== 1 || args[0].kind !== "pool") fail(SAFE.flow, "CAPABILITY_DRIZZLE");
      return value({ kind: "drizzle-db", bound: args[0] });
    }
    if (callee.caps.has("MIGRATE")) {
      if (args.length !== 2 || args[0].kind !== "drizzle-db" || args[1].kind !== "object" ||
          !sameTextSet([...args[1].props.keys()], ["migrationsFolder"]) ||
          hasTaint(args[1], Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC)) {
        fail(SAFE.flow, "CAPABILITY_MIGRATE");
      }
      return primitiveValue("promise");
    }
    if (callee.caps.has("WEAKMAP_SET")) {
      if (args[0]?.kind === "object" && args[0].props.size === 0) {
        args[0].kind = "authority-token";
        args[0].provenance = {};
      }
      if (args.length !== 2 || !args[0] || args[0].kind !== "authority-token" || args[1].kind !== "object") {
        fail(SAFE.authority, "AUTHORITY_SCHEMA");
      }
      this.validateAuthorityRecord(args[0], args[1]);
      callee.bound.map.set(args[0], args[1]);
      this.authorityRecord = args[1];
      this.authorityToken = args[0];
      this.authoritySetCount += 1;
      return callee.bound;
    }
    if (callee.caps.has("WEAKMAP_GET")) {
      if (args.length !== 1) fail(SAFE.authority, "AUTHORITY_SCHEMA");
      let record = callee.bound.map.get(args[0]);
      if (!record && args[0]?.provenance) {
        for (const [candidate, candidateRecord] of callee.bound.map) {
          if (candidate?.provenance === args[0].provenance) {
            record = candidateRecord;
            break;
          }
        }
      }
      if (!record) fail(SAFE.authority, "AUTHORITY_SCHEMA");
      return record;
    }
    if (callee.caps.has("CLEANUP_CATCH")) {
      if (args.length !== 1 || !args[0].fn) fail(SAFE.flow, "CLEANUP_DIAGNOSTIC");
      const callbackResult = this.analyzeFunction(
        args[0].fn,
        [value({ kind: "diagnostic", taint: Taint.SENSITIVE_DIAGNOSTIC, caps: ["CLEANUP_DIAGNOSTIC"] })],
        args[0].closure,
      );
      return callbackResult;
    }
    if (callee.caps.has("ARRAY_SOME")) {
      if (args.length < 1 || !args[0].fn) fail(SAFE.ast, "SYNTAX_POLICY");
      this.analyzeFunction(args[0].fn, [unknownValue(), primitiveValue("number"), callee.bound], args[0].closure);
      return primitiveValue("boolean");
    }
    if (callee.caps.has("ARRAY_INCLUDES")) {
      if (args.some((item) => hasTaint(item, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC))) fail(SAFE.flow, "CAPABILITY_RECONSTRUCTION");
      return primitiveValue("boolean");
    }
    if (callee.caps.has("SET_HAS")) return primitiveValue("boolean");
    if (callee.caps.has("SET_ADD")) return callee.bound;
    if (callee.caps.has("REGEXP_TEST")) return primitiveValue("boolean");
    if (callee.caps.has("SYMBOL_CONSTRUCTOR")) return value({ kind: "symbol" });
    if (callee.caps.has("STRING_METHOD")) {
      if (!callee.bound) fail(SAFE.flow, "CAPABILITY_RECONSTRUCTION");
      return value({
        kind: "string",
        taint: callee.bound.taint,
        directCredential: false,
        label: callee.bound.taint ? "transformed-credential" : "",
      });
    }
    if (callee.caps.has("OBJECT_FREEZE")) return args.length === 1 ? args[0] : unknownValue();
    if (callee.caps.has("OBJECT_KEYS")) return value({ kind: "array" });
    if (callee.caps.has("OBJECT_HAS_OWN")) return primitiveValue("boolean");
    if (callee.caps.has("ARRAY_IS_ARRAY")) return primitiveValue("boolean");
    if (callee.caps.has("NUMBER_CONSTRUCTOR")) {
      if (args.some((item) => hasTaint(item, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC))) fail(SAFE.flow, "CAPABILITY_RECONSTRUCTION");
      return primitiveValue("number");
    }
    if (callee.caps.has("DECODE_URI")) {
      if (args.some((item) => hasTaint(item, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC))) fail(SAFE.flow, "CAPABILITY_RECONSTRUCTION");
      return primitiveValue("string");
    }
    if (callee.caps.has("STRING_CONSTRUCTOR")) {
      if (args.some((item) => hasTaint(item, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC))) fail(SAFE.flow, "CAPABILITY_RECONSTRUCTION");
      return primitiveValue("string");
    }
    if (callee.caps.has("JSON_STRINGIFY")) {
      if (args.some((item) => hasTaint(item, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC))) fail(SAFE.flow, "CAPABILITY_SERIALIZATION");
      return primitiveValue("string");
    }
    if (callee.caps.has("OPAQUE_OPERATION")) {
      if (args.length !== 0) fail(SAFE.flow, "CAPABILITY_CALLBACK");
      return value({ kind: "operation-result" });
    }
    if (callee.fn && isFunctionLike(callee.fn)) return this.analyzeFunction(callee.fn, args, callee.closure);
    if (callee.kind === "function" && !callee.fn) fail(SAFE.unresolved, "CALL_RESOLUTION");
    if (callee.kind === "class") return value({ kind: "error" });
    if (callee.caps.has("UNUSED_EXTERNAL")) fail(SAFE.unresolved, "CALL_RESOLUTION");
    if (callee.kind === "unknown") fail(SAFE.unresolved, "CALL_RESOLUTION");
    fail(SAFE.unresolved, "CALL_RESOLUTION");
  }

  validateAuthorityRecord(token, record) {
    const keys = [...record.props.keys()];
    if (!sameTextSet(keys, AUTHORITY_KEYS)) fail(SAFE.authority, "AUTHORITY_SCHEMA");
    for (const [name, item] of record.props) {
      if (!item || item.kind === "unknown" ||
          hasTaint(item, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC | Taint.MAYBE_SENSITIVE)) {
        fail(SAFE.flow, "AUTHORITY_SCHEMA");
      }
      if (name !== "authority" && name !== "brand" && name !== "pool" &&
          name !== "valid" && item.kind !== "primitive" && item.kind !== "string") {
        fail(SAFE.authority, "AUTHORITY_SCHEMA");
      }
    }
    if (record.props.get("authority") !== token) {
      fail(SAFE.authority, "AUTHORITY_SCHEMA");
    }
    if (record.props.get("brand") !== this.topValue("migrationAuthorityBrand")) {
      fail(SAFE.authority, "AUTHORITY_SCHEMA");
    }
    if (record.props.get("pool")?.kind !== "pool") {
      fail(SAFE.authority, "AUTHORITY_SCHEMA");
    }
    if (record.props.get("valid")?.label !== "true") {
      fail(SAFE.authority, "AUTHORITY_SCHEMA");
    }
  }

  assignTarget(target, right, env, context) {
    if (ts.isIdentifier(target)) {
      const resolved = this.resolveDeclaration(target);
      if (!resolved || resolved.kind !== "local") fail(SAFE.unresolved, "CALL_RESOLUTION");
      env.set(keyForDeclaration(resolved.declaration.name ?? resolved.declaration), right);
      this.bindingNames.set(keyForDeclaration(resolved.declaration.name ?? resolved.declaration), target.text);
      return;
    }
    if (ts.isPropertyAccessExpression(target)) {
      const receiver = this.evalExpression(target.expression, env, context);
      const name = target.name.text;
      if (receiver.caps.has("ENV")) fail(SAFE.flow, "CAPABILITY_ENV");
      if (receiver.kind === "unknown") fail(SAFE.flow, "CAPABILITY_STORAGE");
      if (receiver.kind === "pool-options") {
        if (name !== "password" || !right.directCredential || right.taint !== Taint.CREDENTIAL) {
          fail(SAFE.flow, "CAPABILITY_PASSWORD");
        }
        receiver.props.set(name, right);
        this.declassificationCount += 1;
        return;
      }
      if (receiver === this.authorityRecord && name === "valid" && right.label === "false") {
        receiver.props.set(name, right);
        return;
      }
      if (hasTaint(right, Taint.CREDENTIAL | Taint.SENSITIVE_DIAGNOSTIC)) fail(SAFE.flow, "CAPABILITY_STORAGE");
      receiver.props.set(name, right);
      return;
    }
    if (ts.isElementAccessExpression(target)) {
      const receiver = this.evalExpression(target.expression, env, context);
      if (receiver.caps.has("ENV")) fail(SAFE.flow, "CAPABILITY_ENV");
      fail(SAFE.computed, "COMPUTED_CAPABILITY");
    }
    fail(SAFE.ast, "SYNTAX_POLICY");
  }
}

function applyEdits(source, edits) {
  const ordered = [...edits].sort((left, right) => right.start - left.start);
  let result = source;
  for (const edit of ordered) {
    result = `${result.slice(0, edit.start)}${edit.text}${result.slice(edit.end)}`;
  }
  return result;
}

function createVirtualProgram({ helperPath, source, label }) {
  const virtualRoot = path.join(path.parse(helperPath).root, "__ssc_virtual__", label);
  const stubPaths = new Map([
    ["drizzle-orm/node-postgres", path.join(virtualRoot, "drizzle-node-postgres.d.ts")],
    ["drizzle-orm/node-postgres/migrator", path.join(virtualRoot, "drizzle-migrator.d.ts")],
    ["pg", path.join(virtualRoot, "pg.d.ts")],
    ["../../dist/db/runtime-posture.js", path.join(virtualRoot, "runtime-posture.d.ts")],
  ]);
  const stubs = new Map([
    [stubPaths.get("drizzle-orm/node-postgres"), "export declare function drizzle(pool: unknown): unknown;"],
    [stubPaths.get("drizzle-orm/node-postgres/migrator"), "export declare function migrate(db: unknown, options: unknown): Promise<void>;"],
    [stubPaths.get("pg"), "export declare class Client {} export declare class Pool { constructor(options: unknown); query(...args: unknown[]): Promise<unknown>; connect(...args: unknown[]): Promise<unknown>; end(...args: unknown[]): Promise<void>; }"],
    [stubPaths.get("../../dist/db/runtime-posture.js"), "export declare function inspectRuntimeDatabaseRoleAuthorityPosture(...args: unknown[]): Promise<unknown>;"],
  ]);
  const options = {
    allowJs: true,
    checkJs: false,
    noEmit: true,
    skipLibCheck: true,
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.NodeNext,
    moduleResolution: ts.ModuleResolutionKind.NodeNext,
    types: [],
  };
  const defaultHost = ts.createCompilerHost(options, true);
  const samePath = (left, right) => path.resolve(left).toLowerCase() === path.resolve(right).toLowerCase();
  const stubPathFor = (fileName) => [...stubs.keys()].find((candidate) => samePath(candidate, fileName));
  const host = {
    ...defaultHost,
    fileExists(fileName) {
      return samePath(fileName, helperPath) || Boolean(stubPathFor(fileName)) || defaultHost.fileExists(fileName);
    },
    readFile(fileName) {
      if (samePath(fileName, helperPath)) return source;
      const stubPath = stubPathFor(fileName);
      if (stubPath) return stubs.get(stubPath);
      return defaultHost.readFile(fileName);
    },
    getSourceFile(fileName, languageVersion, onError, shouldCreateNewSourceFile) {
      if (samePath(fileName, helperPath)) return ts.createSourceFile(fileName, source, languageVersion, true, ts.ScriptKind.JS);
      const stubPath = stubPathFor(fileName);
      if (stubPath) return ts.createSourceFile(fileName, stubs.get(stubPath), languageVersion, true, ts.ScriptKind.TS);
      return defaultHost.getSourceFile(fileName, languageVersion, onError, shouldCreateNewSourceFile);
    },
    resolveModuleNames(moduleNames) {
      return moduleNames.map((moduleName) => {
        const stub = stubPaths.get(moduleName);
        return stub
          ? { resolvedFileName: stub, extension: ts.Extension.Dts, isExternalLibraryImport: true }
          : undefined;
      });
    },
  };
  const program = ts.createProgram([helperPath], options, host);
  const sourceFile = program.getSourceFile(helperPath);
  if (!sourceFile) fail(SAFE.ast, "SOURCE_IDENTITY");
  if (program.getSyntacticDiagnostics(sourceFile).length > 0) fail(SAFE.ast, "PARSE_DIAGNOSTICS");
  return { program, sourceFile, checker: program.getTypeChecker() };
}

function findNode(sourceFile, predicate) {
  let found = null;
  const visit = (node) => {
    if (found) return;
    if (predicate(node)) {
      found = node;
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return found;
}

function findRootFunction(sourceFile) {
  return sourceFile.statements.find(
    (statement) => ts.isFunctionDeclaration(statement) && statement.name?.text === ROOT_EXPORT,
  );
}

function buildMutantSources(source, sourceFile) {
  const root = findRootFunction(sourceFile);
  if (!root?.body?.statements?.[0]) fail(SAFE.internal, "MUTANT_ANCHOR");
  const insertion = root.body.statements[0].getStart(sourceFile);
  const mutants = new Map();
  const prefix = (text) => applyEdits(source, [{ start: insertion, end: insertion, text: `${text}\n` }]);
  mutants.set("NC01_REACHABLE_WRITE_HELPER", prefix(
    "function innocuousForward(value) { console.log(value); } innocuousForward(input.connectionPassword);",
  ));
  mutants.set("NC02_REACHABLE_HASH_HELPER", prefix(
    "function innocuousDigest(value) { return globalThis.crypto.subtle.digest(\"SHA-256\", value); } innocuousDigest(input.connectionPassword);",
  ));
  mutants.set("NC03_STATIC_ONLY_BRANCH", prefix(
    "if (input) { console.log(input.connectionPassword); }",
  ));
  mutants.set("NC04_ALIASED_SINK", prefix(
    "const innocuousSink = console.log; innocuousSink(input.connectionPassword);",
  ));
  mutants.set("NC05_COMPUTED_SINK", prefix(
    "const sinkName = \"log\"; console[sinkName](input.connectionPassword);",
  ));
  mutants.set("NC07_UNRESOLVED_CALL", prefix(
    "unknownExternal(input.connectionPassword);",
  ));
  mutants.set("NC08_TRANSIENT_ENV", prefix(
    "process.env.SSC_TRANSIENT = input.connectionPassword; delete process.env.SSC_TRANSIENT;",
  ));
  mutants.set("NC06_NEW_IMPORT", applyEdits(source, [{
    start: 0,
    end: 0,
    text: "import { readFile as unexpectedRead } from \"node:fs\";\n",
  }]));

  mutants.set("PROBE_ARROW_OUTPUT", prefix(
    "const innocuousArrow = (value) => console.log(value); innocuousArrow(input.connectionPassword);",
  ));
  mutants.set("PROBE_ARRAY_SOME_OUTPUT", prefix(
    "[input.connectionPassword].some((value) => console.log(value));",
  ));
  mutants.set("PROBE_MODULE_IF_OUTPUT", applyEdits(source, [{
    start: root.getStart(sourceFile),
    end: root.getStart(sourceFile),
    text: "if (true) { console.log(\"ssc-module-output\"); }\n",
  }]));

  const publicReturn = findNode(root, (node) =>
    ts.isReturnStatement(node) && node.expression &&
    node.expression.getText(sourceFile).includes("operation"),
  );
  if (!publicReturn?.expression) fail(SAFE.internal, "MUTANT_PUBLIC_RETURN_ANCHOR");
  mutants.set("PROBE_PUBLIC_CREDENTIAL_RETURN", applyEdits(source, [{
    start: publicReturn.expression.getStart(sourceFile),
    end: publicReturn.expression.getEnd(),
    text: "input.connectionPassword",
  }]));

  const authorityCall = findNode(sourceFile, (node) =>
    ts.isCallExpression(node) &&
    ts.isPropertyAccessExpression(node.expression) &&
    node.expression.name.text === "set" &&
    node.arguments.length === 2 &&
    ts.isIdentifier(node.arguments[0]) &&
    node.arguments[0].text === "authority" &&
    ts.isObjectLiteralExpression(node.arguments[1]),
  );
  if (!authorityCall || !ts.isObjectLiteralExpression(authorityCall.arguments[1])) fail(SAFE.internal, "MUTANT_AUTHORITY_ANCHOR");
  const authorityObject = authorityCall.arguments[1];
  mutants.set("NC09_INNOCENT_AUTHORITY_FIELD", applyEdits(source, [{
    start: authorityObject.getEnd() - 1,
    end: authorityObject.getEnd() - 1,
    text: " innocentMetadata: connectionPassword",
  }]));

  const brandProperty = authorityObject.properties.find((property) =>
    ts.isPropertyAssignment(property) &&
    property.name.getText(sourceFile).replace(/^['"]|['"]$/gu, "") === "brand" &&
    ts.isIdentifier(property.initializer) && property.initializer.text === "migrationAuthorityBrand",
  );
  if (!brandProperty || !ts.isPropertyAssignment(brandProperty)) fail(SAFE.internal, "MUTANT_BRAND_ANCHOR");
  mutants.set("PROBE_AUTHORITY_BRAND", applyEdits(source, [{
    start: brandProperty.initializer.getStart(sourceFile),
    end: brandProperty.initializer.getEnd(),
    text: "Symbol(\"spoofed-authority\")",
  }]));

  const passwordAssignment = findNode(sourceFile, (node) =>
    ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
    ts.isPropertyAccessExpression(node.left) && node.left.name.text === "password" &&
    ts.isIdentifier(node.right) && node.right.text === "connectionPassword",
  );
  if (!passwordAssignment) fail(SAFE.internal, "MUTANT_PASSWORD_ANCHOR");
  mutants.set("PROBE_TRIMMED_PASSWORD", applyEdits(source, [{
    start: passwordAssignment.right.getStart(sourceFile),
    end: passwordAssignment.right.getEnd(),
    text: "connectionPassword.trim()",
  }]));

  const cleanupCall = findNode(sourceFile, (node) =>
    ts.isCallExpression(node) &&
    ts.isPropertyAccessExpression(node.expression) &&
    node.expression.name.text === "catch" &&
    ts.isCallExpression(node.expression.expression) &&
    ts.isPropertyAccessExpression(node.expression.expression.expression) &&
    node.expression.expression.expression.name.text === "end" &&
    node.arguments.length === 1 &&
    ts.isArrowFunction(node.arguments[0]),
  );
  if (!cleanupCall || !ts.isArrowFunction(cleanupCall.arguments[0])) fail(SAFE.internal, "MUTANT_CLEANUP_ANCHOR");
  mutants.set("NC10_CLEANUP_PUBLISH", applyEdits(source, [{
    start: cleanupCall.arguments[0].getStart(sourceFile),
    end: cleanupCall.arguments[0].getEnd(),
    text: "(cleanupError) => { console.log(cleanupError); }",
  }]));
  mutants.set("PROBE_CLEANUP_CONCISE_OUTPUT", applyEdits(source, [{
    start: cleanupCall.arguments[0].getStart(sourceFile),
    end: cleanupCall.arguments[0].getEnd(),
    text: "(cleanupError) => console.log(cleanupError)",
  }]));
  return mutants;
}

async function readFrozenSource() {
  const moduleDirectory = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(moduleDirectory, "../..");
  const helperPath = path.resolve(repoRoot, HELPER_RELATIVE);
  if (path.relative(repoRoot, helperPath).replaceAll("\\", "/") !== HELPER_RELATIVE) {
    fail(SAFE.internal, "SOURCE_IDENTITY");
  }
  const bytes = await readFile(helperPath);
  const canonicalBytes = Buffer.from(
    bytes.toString("utf8").split("\r\n").join("\n"),
    "utf8",
  );
  const digest = createHash("sha1")
    .update(`blob ${canonicalBytes.byteLength}\0`)
    .update(canonicalBytes)
    .digest("hex");
  if (digest !== FROZEN_HELPER_BLOB) fail(SAFE.flow, "FROZEN_HELPER_BLOB");
  return { helperPath, source: bytes.toString("utf8") };
}

function analyzeSourceVariant({ helperPath, source, label }) {
  try {
    const { program, sourceFile, checker } = createVirtualProgram({ helperPath, source, label });
    return new ClosureAnalyzer({ source, sourceFile, program, checker }).analyze();
  } catch (error) {
    throw error instanceof StaticFailure ? error : new StaticFailure(SAFE.internal, "ANALYZER_BOUNDARY");
  }
}

export async function runFrozenMigrationClosure() {
  try {
    const frozen = await readFrozenSource();
    return analyzeSourceVariant({ ...frozen, label: "baseline" });
  } catch (error) {
    const failure = failureOf(error);
    throw new Error(failure.code);
  }
}

export async function runMigrationClosureNegativeControls() {
  try {
    const frozen = await readFrozenSource();
    const baselineProgram = createVirtualProgram({ ...frozen, label: "mutant-index" });
    const mutants = buildMutantSources(frozen.source, baselineProgram.sourceFile);
    const results = [];
    for (const control of NEGATIVE_CONTROLS) {
      let observed;
      try {
        analyzeSourceVariant({
          helperPath: frozen.helperPath,
          source: mutants.get(control.id),
          label: control.id,
        });
        observed = { code: "SSC_NEGATIVE_CONTROL_INACTIVE", detector: "CONTROL_INACTIVE" };
      } catch (error) {
        observed = failureOf(error);
      }
      results.push(Object.freeze({
        id: control.id,
        code: observed.code,
        detector: observed.detector,
        pass: observed.code === control.code && observed.detector === control.detector,
      }));
    }
    return Object.freeze({
      count: results.length,
      ids: Object.freeze(results.map((result) => result.id)),
      results: Object.freeze(results),
    });
  } catch (error) {
    const failure = failureOf(error);
    return Object.freeze({
      count: NEGATIVE_CONTROLS.length,
      ids: Object.freeze(NEGATIVE_CONTROLS.map((control) => control.id)),
      results: Object.freeze(NEGATIVE_CONTROLS.map((control) => Object.freeze({
        id: control.id,
        code: failure.code,
        detector: failure.detector,
        pass: false,
      }))),
    });
  }
}

export const migrationClosureNegativeControlIds = Object.freeze(
  NEGATIVE_CONTROLS.map((control) => control.id),
);
