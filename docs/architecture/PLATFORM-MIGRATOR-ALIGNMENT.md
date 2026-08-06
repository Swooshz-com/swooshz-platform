# Platform Migrator Alignment

## Purpose

This document is the repository contract for issue #128 (dedicated Platform
migrator authority) under parent #104. It implements the controller corrections
in `DL-128-REPO-001` and the Run-02 authority in #128 comment `5193670650`.

It is repository contract and disposable-rehearsal evidence only. It creates no
role, grants no privilege, transfers no ownership, rotates no credential,
creates no projection, accesses no Neon/provider API, touches no Coolify state
and performs no deployment. It releases no live-system authority.

## Sources of authority

- Parent issue #104 rolling queue.
- Child issue #128, including the current body and comment `5193670650`.
- Repository Design Lock `DL-128-REPO-001`.
- Completed topology evidence #116 / Run-49.
- Completed #127 and merged PR #129, including the accepted 39-record runtime
  grant contract and the exact disposable PostgreSQL 17 fixture authority.
- Blocked successor #122.

## Locked role model

The following model is the intended future state. None of it is claimed to
already exist in the live system, and no recovery branch, role, membership,
grant, ownership transfer, credential or projection is claimed to exist.

### platform_migrator

Future dedicated operator/migration role:

- `LOGIN`.
- `NOSUPERUSER`.
- `NOCREATEDB` in final state (temporary `CREATEDB` is permitted only inside a
  separately authorised transfer phase and is revoked before the phase ends).
- `NOCREATEROLE`.
- `NOREPLICATION`.
- `NOBYPASSRLS`.
- No permanent memberships.
- Never used by the long-running Coolify application.
- Future private projection: `NEONDB_SWOOSHZ_PLATFORM_MIGRATOR_URL`.
- Process-local operator alias: `DATABASE_OPERATOR_URL`.

### platform_runtime

Unchanged by this amendment:

- Non-owning.
- Zero memberships.
- No migration authority.
- No default-ACL authority.
- Accepted exact 39-record direct grant contract remains unchanged.
- Remains `NOLOGIN` until separately authorised under #122.

### platform_app

Current transitional legacy authority:

- The repository does not claim its live attributes, ownership, membership or
  credential have changed.
- Future retirement may occur only after complete independent proof that
  `platform_migrator` works.
- Intended eventual state is dormant and unreachable, but this repository
  amendment performs no such transition.

## Ownership-transfer correction

The following model is rejected as insufficient:

> Give `platform_migrator` temporary `CREATEDB`, then execute
> `ALTER DATABASE ... OWNER TO platform_migrator` from an unrelated current
> role.

That does not prove that the executing role can assume the new owner.

A future live transfer may use only one of the following paths.

### Path A - provider/role-lifecycle authority

An explicitly authorised provider or equivalent role-lifecycle authority
performs the ownership transfer and exact read-back.

The repository must not assume this capability exists. A later live preflight
must prove it before the live Design Lock is issued.

### Path B - bounded temporary SET-capable membership

The executing current owner:

1. Is proved to own the object being transferred.
2. Holds the exact required `CREATEDB` or schema authority.
3. Receives a temporary membership allowing it to `SET ROLE` to
   `platform_migrator`.
4. Performs only the authorised ownership transfers.
5. Immediately revokes the temporary membership.
6. Proves that no membership remains.
7. Proves the complete final ownership inventory.

No permanent membership-derived migration authority is allowed.

## public schema decision boundary

The repository does not state that `public` definitely becomes owned by
`platform_migrator`. The later live read-back decides fail-closed:

- If fresh live read-back proves `public` is application-controlled and safely
  transferable, the later live Design Lock may transfer it.
- If `public` is provider-managed or represented through provider ownership
  semantics, preserve that ownership and grant `platform_migrator` only the
  exact `CREATE`/`USAGE` authority required by reviewed migration tooling.
- Any inconclusive owner or provider result blocks mutation.

Application schemas, application objects and the Drizzle ledger may still
target `platform_migrator` ownership when the later live Design Lock proves the
exact transfer path.

## Projection-name contract

Use only these programme names:

- Existing transition authority: `NEONDB_SWOOSHZ_PLATFORM_LEGACY_OWNER_URL`.
- Existing Platform control-plane authority: `NEONDB_SWOOSHZ_PLATFORM_API_KEY`.
- Future migrator projection: `NEONDB_SWOOSHZ_PLATFORM_MIGRATOR_URL`.
- Process-local migration alias: `DATABASE_OPERATOR_URL`.
- Migration confirmation: `DATABASE_MIGRATIONS_CONFIRM=apply-reviewed-migrations`.
- Future Coolify runtime variables under #122: `DATABASE_URL` and
  `DATABASE_EXPECTED_RUNTIME_ROLE=platform_runtime`.

No generic local requirements named `NEON_API_KEY` or `NEON_PROJECT_ID` are
introduced. The future migrator projection is not claimed to currently exist.

## Disposable PostgreSQL 17 rehearsal

The repository proof command is `npm run test:disposable-migrator-alignment`
(`scripts/run-disposable-migrator-alignment-tests.mjs`). It is Docker-dependent
and is therefore not part of ordinary `npm test`.

### Fixture identity and fail-closed admission

- A new exact owned container/listener identity that cannot collide with the
  existing runtime-posture fixture (`codex-platform127-pg17`).
- Fails closed if its exact container or listener already exists.
- Publishes PostgreSQL only through an explicit `127.0.0.1:<ownedPort>:5432`
  Docker binding. A bounded Docker inspection runs after container creation and
  before any PostgreSQL admission or connection and proves exactly one host
  entry on container port `5432/tcp` with host IP `127.0.0.1` and the exact
  owned host port; blank, wildcard, `0.0.0.0`, `::`, additional or malformed
  bindings fail closed into cleanup and exact absence verification.
- Uses only loopback.
- Uses PostgreSQL 17.
- Never accepts caller-provided database URLs.

### Disposable equivalents

The rehearsal creates disposable equivalents of:

- current legacy owner (`platform_app`, modelled with its transitional
  `CREATEDB` attribute);
- future migrator (`platform_migrator`, final attributes);
- restricted runtime (`platform_runtime`, non-owning, `NOLOGIN`);
- a provider-managed public owner variant (`provider_owner`);
- application schema, migration schema and ledger;
- representative table, index, enum, routine and sequence;
- the accepted 39-record runtime grant contract;
- the provider-managed-public-owner variant where needed.

### Starting fingerprint

The rehearsal captures a non-vacuous starting fingerprint covering database
owner and database ACL entries, `public`/`appdata`/`drizzle` owners and complete
schema ACL entries, relevant `pg_default_acl` entries, relation/index/sequence/
enum/routine ownership, exact role attributes and exact membership edges with
`admin_option`, `inherit_option` and `set_option`. ACL evidence is normalised
into stable structured grantor/grantee/privilege/grantability records.

### Deterministic cleanup

The runner removes all runner-owned databases, roles, schemas and objects,
then the container and listener, and proves exact container and listener
absence after success and after every failure path.

### Required negative control

The rehearsal proves that:

- `platform_migrator` receiving `CREATEDB`;
- while the executing legacy owner cannot `SET ROLE` to it;

does not satisfy the database-owner transfer contract. The test observes the
failure and proves zero unintended persistent mutation.

### Required positive transfer rehearsal

The rehearsal proves the bounded temporary-membership path:

1. Create exact final migrator attributes.
2. Establish only the temporary SET-capable membership required for transfer and
   prove the exact sole edge with `admin_option=false`, `inherit_option=false`
   and `set_option=true`.
3. Transfer the disposable database where PostgreSQL permits the model.
4. Transfer application schema, migration schema, table, index-following
   ownership, enum, sequence, routine and ledger.
5. Revoke temporary membership immediately and every temporary transfer
   database/schema privilege.
6. Prove zero membership edges remain.
7. Prove the migrator can perform a bounded migration transaction.
8. Roll back the bounded capability proof.
9. Prove the restricted runtime contract is unchanged and non-owning.
10. Prove the legacy role cannot be retired until all replacement proof
    passes.
11. Exercise the reverse ownership rollback procedure and restore the exact
    baseline database/schema/default-ACL fingerprint, including the
    migrator database `CONNECT` grant.
12. Prove the complete original fingerprint (owners, ACLs, default ACLs, role
    attributes and membership edges) can be restored.

### public ownership variants

The rehearsal covers:

- application-controlled `public` that can be transferred safely;
- provider-managed `public` whose owner is preserved while exact migration
  `CREATE`/`USAGE` authority is granted, including a real bounded
  `platform_migrator` transaction that creates a disposable migration object in
  `public`, validates it and rolls it back, proving the object is absent after
  rollback, `public` ownership remains `provider_owner` and runtime authority is
  unchanged.

Neither variant may widen runtime authority.

### Exact summary

The runner emits one fixed public-safe summary containing exact totals for
tests, passed, failed and skipped. Reduced, skipped, malformed or unparseable
totals fail closed. No database URL, password, host credential or private
material appears in output.

## Runtime-contract preservation

The rehearsal reuses the accepted disposable fixture admission model and the
canonical `src/db/runtime-posture.ts` role-authority posture inspector. The
restricted runtime role must remain non-owning, membership-free and exactly
equal to the accepted 39-record contract before, during and after every
transfer variant.

## Validation

The amendment is validated by:

- `node --check` on every changed JavaScript file.
- The focused RED-to-GREEN runbook contract tests.
- `npm run test:disposable-migrator-alignment`.
- `npm test`.
- `npm run typecheck`.
- `npm run build`.
- The existing `npm run test:disposable-runtime-postgres` suite, which must
  remain exactly successful and unweakened.
- `docker build .`.
- `git diff --check`.
- Conflict-marker, forbidden-file and visible-secret scans.

## Safety boundary

No live operation is authorised by this document or by the disposable
rehearsal. No Neon connection, provider API call, live role mutation, live
grant/revoke, live ownership transfer, credential rotation or projection
addition, Coolify change, deployment or restart occurs. All PostgreSQL work is
limited to the runner-owned local disposable fixture.

Secret-exposure classification for this document: none.
