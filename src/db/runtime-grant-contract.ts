export const RUNTIME_TABLE_PRIVILEGES = [
  "DELETE",
  "INSERT",
  "REFERENCES",
  "SELECT",
  "TRIGGER",
  "TRUNCATE",
  "UPDATE",
] as const;

export type RuntimeTablePrivilege =
  (typeof RUNTIME_TABLE_PRIVILEGES)[number];
export type RuntimeGrantAuthoritySource = "direct";

export interface RuntimeTableGrantRecord {
  readonly objectClass: "table";
  readonly schema: "public";
  readonly objectName: string;
  readonly privilege: RuntimeTablePrivilege;
  readonly authoritySource: RuntimeGrantAuthoritySource;
  readonly grantOption: false;
  readonly migrationFile: string;
  readonly operationSources: readonly string[];
}

export interface ObservedRuntimeTableGrantRecord {
  readonly objectClass: string;
  readonly schema: string;
  readonly objectName: string;
  readonly privilege: string;
  readonly authoritySource: string;
  readonly grantOption: boolean;
}

export type RuntimeGrantContractErrorCode =
  | "runtime_grant_contract_schema"
  | "runtime_grant_contract_duplicate"
  | "runtime_grant_contract_order"
  | "runtime_grant_contract_migration"
  | "runtime_grant_adapter_missing"
  | "runtime_grant_adapter_extra"
  | "runtime_grant_adapter_ambiguous"
  | "runtime_grant_set_missing"
  | "runtime_grant_set_extra"
  | "runtime_grant_set_mismatch"
  | "runtime_grant_set_grant_option"
  | "runtime_grant_set_authority"
  | "runtime_grant_set_membership"
  | "runtime_grant_set_ownership";

export class RuntimeGrantContractError extends Error {
  readonly code: RuntimeGrantContractErrorCode;

  constructor(code: RuntimeGrantContractErrorCode) {
    super("Runtime grant contract validation failed.");
    this.name = "RuntimeGrantContractError";
    this.code = code;
  }
}

interface RuntimeTableSpecification {
  readonly objectName: string;
  readonly migrationFile: string;
  readonly operations: Readonly<
    Partial<Record<RuntimeTablePrivilege, readonly string[]>>
  >;
}

const runtimeTableSpecifications: readonly RuntimeTableSpecification[] = [
  specification(
    "access_validation_grants",
    "0009_wonderful_star_brand.sql",
    {
      INSERT: ["src/db/access-validation-grant-repository.ts#create"],
      SELECT: ["src/db/access-validation-grant-repository.ts#findById"],
      UPDATE: [
        "src/db/access-validation-grant-repository.ts#registerHandle",
        "src/db/access-validation-grant-repository.ts#consumeByHandleHash",
        "src/db/access-validation-grant-repository.ts#revoke",
      ],
    },
  ),
  specification("app_entitlements", "0000_overconfident_onslaught.sql", {
    INSERT: ["src/db/repositories.ts#appEntitlements.create"],
    SELECT: [
      "src/db/repositories.ts#appEntitlements.findForWorkspaceApp",
      "src/db/repositories.ts#appEntitlements.listForWorkspace",
    ],
    UPDATE: ["src/db/repositories.ts#appEntitlements.updateStatus"],
  }),
  specification("app_launch_tokens", "0003_worthless_scourge.sql", {
    INSERT: [
      "src/db/repositories.ts#appLaunchTokens.create",
      "src/db/app-launch-token-repository.ts#create",
    ],
    SELECT: [
      "src/db/repositories.ts#appLaunchTokens.findByTokenHash",
      "src/db/app-launch-token-repository.ts#findByTokenHash",
    ],
    UPDATE: [
      "src/db/repositories.ts#appLaunchTokens.consumeUnconsumed",
      "src/db/app-launch-token-repository.ts#consumeUnconsumed",
    ],
  }),
  specification("apps", "0000_overconfident_onslaught.sql", {
    INSERT: ["src/db/repositories.ts#apps.create"],
    SELECT: [
      "src/db/repositories.ts#apps.findByKey",
      "src/db/repositories.ts#apps.findById",
      "src/db/repositories.ts#apps.listAll",
    ],
  }),
  specification("audit_events", "0000_overconfident_onslaught.sql", {
    INSERT: ["src/db/repositories.ts#auditEvents.append"],
    SELECT: ["src/db/repositories.ts#auditEvents.listForWorkspace"],
  }),
  specification("auth_states", "0002_futuristic_aaron_stack.sql", {
    DELETE: ["src/db/auth-state-repository.ts#storeState"],
    INSERT: ["src/db/auth-state-repository.ts#storeState"],
    SELECT: [
      "src/db/auth-state-repository.ts#storeState",
      "src/db/auth-state-repository.ts#consumeState",
    ],
    UPDATE: ["src/db/auth-state-repository.ts#consumeState"],
  }),
  specification("csrf_tokens", "0001_lovely_famine.sql", {
    DELETE: ["src/db/csrf-token-repository.ts#createBoundedForSession"],
    INSERT: ["src/db/csrf-token-repository.ts#createBoundedForSession"],
    SELECT: [
      "src/db/csrf-token-repository.ts#createBoundedForSession",
      "src/db/csrf-token-repository.ts#findBySessionAndTokenHash",
    ],
  }),
  specification("invitations", "0000_overconfident_onslaught.sql", {
    INSERT: ["src/db/repositories.ts#invitations.create"],
    SELECT: ["src/db/repositories.ts#invitations.findById"],
    UPDATE: ["src/db/repositories.ts#invitations.updateStatus"],
  }),
  specification("memberships", "0000_overconfident_onslaught.sql", {
    DELETE: ["src/db/repositories.ts#memberships.removeIfCurrentTarget"],
    INSERT: ["src/db/repositories.ts#memberships.create"],
    SELECT: [
      "src/db/repositories.ts#memberships.findForUserInWorkspace",
      "src/db/repositories.ts#memberships.listForUser",
      "src/db/repositories.ts#memberships.listForWorkspace",
    ],
    UPDATE: [
      "src/db/repositories.ts#memberships.updateRole",
      "src/db/repositories.ts#memberships.updateStatus",
    ],
  }),
  specification(
    "provider_identities",
    "0000_overconfident_onslaught.sql",
    {
      INSERT: ["src/db/repositories.ts#providerIdentities.create"],
      SELECT: [
        "src/db/repositories.ts#providerIdentities.findByProviderSubject",
        "src/db/repositories.ts#providerIdentities.listForUser",
      ],
    },
  ),
  specification("sessions", "0000_overconfident_onslaught.sql", {
    INSERT: ["src/db/repositories.ts#sessions.create"],
    SELECT: ["src/db/repositories.ts#sessions.findById"],
    UPDATE: [
      "src/db/repositories.ts#sessions.revoke",
      "src/db/repositories.ts#sessions.revokeActiveForUser",
    ],
  }),
  specification("users", "0000_overconfident_onslaught.sql", {
    INSERT: ["src/db/repositories.ts#users.create"],
    SELECT: [
      "src/db/repositories.ts#users.findById",
      "src/db/repositories.ts#users.findByNormalizedEmail",
    ],
  }),
  specification(
    "workspace_membership_approvals",
    "0004_illegal_william_stryker.sql",
    {
      INSERT: ["src/db/repositories.ts#membershipApprovals.create"],
      SELECT: [
        "src/db/repositories.ts#membershipApprovals.findById",
        "src/db/repositories.ts#membershipApprovals.findPendingForWorkspaceEmail",
        "src/db/repositories.ts#membershipApprovals.listPendingForEmail",
        "src/db/repositories.ts#membershipApprovals.listPendingForWorkspace",
      ],
      UPDATE: [
        "src/db/repositories.ts#membershipApprovals.updatePendingStatus",
      ],
    },
  ),
  specification("workspaces", "0000_overconfident_onslaught.sql", {
    INSERT: ["src/db/repositories.ts#workspaces.create"],
    SELECT: [
      "src/db/repositories.ts#workspaces.findById",
      "src/db/repositories.ts#workspaces.findBySlug",
    ],
  }),
] as const;

const runtimeTableGrantContract = runtimeTableSpecifications
  .flatMap((table) =>
    Object.entries(table.operations).map(([privilege, operationSources]) =>
      Object.freeze({
        objectClass: "table" as const,
        schema: "public" as const,
        objectName: table.objectName,
        privilege: privilege as RuntimeTablePrivilege,
        authoritySource: "direct" as const,
        grantOption: false as const,
        migrationFile: table.migrationFile,
        operationSources: Object.freeze([...(operationSources ?? [])]),
      }),
    ),
  )
  .sort((left, right) =>
    compareRuntimeTableGrantKeys(
      runtimeTableGrantKey(left),
      runtimeTableGrantKey(right),
    ),
  );

validateRuntimeTableGrantContract(runtimeTableGrantContract);

export const RUNTIME_TABLE_GRANT_CONTRACT: readonly RuntimeTableGrantRecord[] =
  Object.freeze(runtimeTableGrantContract);

export const RUNTIME_TABLE_GRANT_DIGEST =
  "9474972215869ec9b194f537c3b2400d8701aa8f00494bcfc0ede849dd94bf65";

export function runtimeTableGrantKey(
  record: Pick<
    ObservedRuntimeTableGrantRecord,
    | "objectClass"
    | "schema"
    | "objectName"
    | "privilege"
    | "authoritySource"
    | "grantOption"
  >,
): string {
  return [
    record.objectClass,
    record.schema,
    record.objectName,
    record.privilege,
    record.authoritySource,
    record.grantOption ? "YES" : "NO",
  ].join("\u0000");
}

export function validateRuntimeTableGrantContract(
  records: readonly RuntimeTableGrantRecord[],
  {
    migrationObjects,
  }: {
    migrationObjects?: ReadonlyMap<string, string>;
  } = {},
): void {
  if (!Array.isArray(records) || records.length === 0) {
    throw new RuntimeGrantContractError("runtime_grant_contract_schema");
  }

  const keys: string[] = [];
  for (const record of records) {
    if (!validContractRecord(record)) {
      throw new RuntimeGrantContractError("runtime_grant_contract_schema");
    }
    if (
      migrationObjects &&
      migrationObjects.get(record.objectName) !== record.migrationFile
    ) {
      throw new RuntimeGrantContractError("runtime_grant_contract_migration");
    }
    keys.push(runtimeTableGrantKey(record));
  }

  if (new Set(keys).size !== keys.length) {
    throw new RuntimeGrantContractError("runtime_grant_contract_duplicate");
  }
  const sortedKeys = [...keys].sort(compareRuntimeTableGrantKeys);
  if (keys.some((key, index) => key !== sortedKeys[index])) {
    throw new RuntimeGrantContractError("runtime_grant_contract_order");
  }
}

export function assertRuntimeTableGrantSet(
  observed: readonly ObservedRuntimeTableGrantRecord[],
  {
    membershipDerived = false,
    ownershipDerived = false,
  }: {
    membershipDerived?: boolean;
    ownershipDerived?: boolean;
  } = {},
): void {
  if (membershipDerived) {
    throw new RuntimeGrantContractError("runtime_grant_set_membership");
  }
  if (ownershipDerived) {
    throw new RuntimeGrantContractError("runtime_grant_set_ownership");
  }
  if (!Array.isArray(observed)) {
    throw new RuntimeGrantContractError("runtime_grant_set_mismatch");
  }
  if (observed.some((record) => record.grantOption !== false)) {
    throw new RuntimeGrantContractError(
      "runtime_grant_set_grant_option",
    );
  }
  if (
    observed.some(
      (record) =>
        record.authoritySource !== "direct" ||
        record.objectClass !== "table" ||
        record.schema !== "public",
    )
  ) {
    throw new RuntimeGrantContractError("runtime_grant_set_authority");
  }

  const expectedKeys = new Set(
    RUNTIME_TABLE_GRANT_CONTRACT.map(runtimeTableGrantKey),
  );
  const observedKeys = observed.map(runtimeTableGrantKey);
  const observedKeySet = new Set(observedKeys);
  if (observedKeySet.size !== observedKeys.length) {
    throw new RuntimeGrantContractError("runtime_grant_set_extra");
  }

  const missing = RUNTIME_TABLE_GRANT_CONTRACT.filter(
    (record) => !observedKeySet.has(runtimeTableGrantKey(record)),
  );
  const extra = observed.filter(
    (record) => !expectedKeys.has(runtimeTableGrantKey(record)),
  );
  if (missing.length > 0 && extra.length > 0) {
    throw new RuntimeGrantContractError("runtime_grant_set_mismatch");
  }
  if (missing.length > 0) {
    throw new RuntimeGrantContractError("runtime_grant_set_missing");
  }
  if (extra.length > 0) {
    throw new RuntimeGrantContractError("runtime_grant_set_extra");
  }
}

function compareRuntimeTableGrantKeys(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function specification(
  objectName: string,
  migrationFile: string,
  operations: RuntimeTableSpecification["operations"],
): RuntimeTableSpecification {
  return Object.freeze({
    objectName,
    migrationFile,
    operations: Object.freeze(
      Object.fromEntries(
        Object.entries(operations).map(([privilege, sources]) => [
          privilege,
          Object.freeze([...(sources ?? [])]),
        ]),
      ),
    ),
  });
}

function validContractRecord(
  record: RuntimeTableGrantRecord,
): boolean {
  return (
    record !== null &&
    typeof record === "object" &&
    record.objectClass === "table" &&
    record.schema === "public" &&
    /^[a-z_][a-z0-9_]*$/.test(record.objectName) &&
    RUNTIME_TABLE_PRIVILEGES.includes(record.privilege) &&
    record.authoritySource === "direct" &&
    record.grantOption === false &&
    /^\d{4}_[a-z0-9_]+\.sql$/.test(record.migrationFile) &&
    Array.isArray(record.operationSources) &&
    record.operationSources.length > 0 &&
    record.operationSources.every(
      (source) =>
        typeof source === "string" &&
        /^src\/db\/[a-z0-9-]+\.ts#[A-Za-z0-9_.]+$/.test(source),
    )
  );
}
