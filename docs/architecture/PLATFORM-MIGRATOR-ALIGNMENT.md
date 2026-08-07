# Platform Migrator Alignment

## Purpose

This document is the repository contract for issue #128 (dedicated Platform
migrator authority) under parent #104. It implements the controller corrections
in `DL-128-REPO-001`, `DL-128-REPO-002` (PostgreSQL 17 creator-edge,
transaction, rollback and credential-order semantics) and `DL-128-REPO-003`
(creator-edge finality), under the Run-06R4 authority in #128 comment
`5206359921`.

It is repository contract and disposable-rehearsal evidence only. It creates no
role, grants no privilege, transfers no ownership, rotates no credential,
creates no projection, accesses no Neon/provider API, touches no Coolify state
and performs no deployment. It releases no live-system authority.

## Sources of authority

- Parent issue #104 rolling queue.
- Child issue #128, including the current body and comment `5206359921`.
- Repository Design Lock `DL-128-REPO-001`, amended by repository contract
  amendment `DL-128-REPO-002` (PostgreSQL 17 creator-edge, transaction,
  rollback and credential-order semantics), and superseded for creator-edge
  finality by repository contract amendment `DL-128-REPO-003`.
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
- `NOCREATEDB` (final and throughout). No temporary `CREATEDB` on `platform_migrator`.
- `NOCREATEROLE`.
- `NOREPLICATION`.
- `NOBYPASSRLS`.
- The automatic bootstrap edge
  (`granted_role=platform_migrator`, `member=platform_app`,
  bootstrap-superuser grantor, `admin_option=true`, `inherit_option=false`,
  `set_option=false`) is the exact protected bootstrap creator edge that
  PostgreSQL 17 creates when a non-superuser `CREATEROLE` creator creates the
  role; it grants no inherited privilege and no `SET ROLE` path and is not
  removable by the creator through an ordinary `REVOKE` (plain `REVOKE`
  removes only the creator's own grants, and `GRANTED BY` revocation of the
  bootstrap grant is denied). It must be rejected if any field, direction,
  grantor or multiplicity differs. Exactly one protected automatic edge is
  admitted during that window; it is not removable by the creator.
- A second grant `granted_role=platform_migrator`, `member=platform_app`,
  grantor `platform_app`, `SET=true`, `INHERIT=false` may exist only during the
  bounded transfer window and must be revoked by the same grantor before final
  acceptance.
- The automatic bootstrap edge may exist only during creation, credential
  admission and ownership transfer. After the successful transfer and complete
  read-back, the provider/bootstrap authority revokes the automatic edge after
  successful transfer/read-back; final accepted `platform_migrator` membership
  posture is zero edges across granted-role, member and grantor positions.
- After final revocation, prove `platform_app` cannot grant itself membership
  in `platform_migrator` and cannot `SET ROLE platform_migrator`.
- Never used by the long-running Coolify application.
- Future private projection: `NEONDB_SWOOSHZ_PLATFORM_MIGRATOR_URL`.
- Process-local operator alias: `DATABASE_OPERATOR_URL`.

## Creator-edge finality (`DL-128-REPO-003`)

`DL-128-REPO-003` supersedes `DL-128-REPO-002` only for creator-edge finality:

- `SET=false` and `INHERIT=false` do not create a security boundary while `ADMIN=true` remains: `platform_app` can grant itself a fresh `SET=true` or
  `INHERIT=true` edge and reacquire migrator authority.
- The automatic edge protects against accidents only: it lets the creator
  revoke its own accidental supplemental grants while it cannot remove the
  bootstrap grant itself.
- Provider revocation is mandatory before final acceptance: the
  provider/bootstrap authority must revoke the automatic edge after the
  successful transfer and complete read-back.
- Final migrator membership is zero: no `platform_migrator` membership edge may
  remain across granted-role, member or grantor positions.
- After final revocation, `platform_app` cannot grant itself membership in
  `platform_migrator` and cannot `SET ROLE platform_migrator`.
- Provider/bootstrap authority for final revocation and complete reverse
  rollback must be proven in the fresh read-only live preflight before any
  write; absence blocks mutation.

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
2. Holds the exact required `CREATEDB` and `SET ROLE` authority; the target role
   never receives temporary `CREATEDB`.
3. Creates the target role as `NOLOGIN` with final non-administrative
   attributes; PostgreSQL 17 automatically creates the protected bootstrap creator edge (bootstrap-superuser
   grantor, `admin_option=true`, `inherit_option=false`, `set_option=false`) which the
   creator cannot remove through an ordinary `REVOKE`.
4. Grants itself a separately grantable and separately revocable supplemental
   `SET=true`, `INHERIT=false` edge for the bounded transfer window.
5. Proves credential/login admission (private password, `LOGIN` enablement,
   private projection installation and a validated direct read-only migrator
   connection) before any ownership transfer.
6. Performs only the authorised ownership transfers, preferably in one
   rollback-capable transaction (the PostgreSQL 17 `ALTER DATABASE ... OWNER`
   ownership form is transactional; the `SET TABLESPACE` restriction does not
   apply).
7. Revokes only the supplemental `SET=true` edge by its own grantor, then
   proves the remaining automatic edge still grants the creator the ability to
   mint a fresh `SET=true` edge and `SET ROLE platform_migrator` (the latent
   self-escalation consequence), and revokes only that self-granted edge.
8. Proves the complete final ownership inventory and the exact automatic edge,
   then the provider/bootstrap authority revokes the automatic edge.
9. Proves the final `platform_migrator` membership inventory is exactly zero
   across granted-role, member and grantor positions, and proves
   `platform_app` cannot grant itself membership and cannot
   `SET ROLE platform_migrator`.

No permanent membership-derived migration authority is allowed in the final
state: final migrator membership is zero.

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

The rehearsal proves the bounded temporary-membership path per
`DL-128-REPO-002` and the creator-edge finality per `DL-128-REPO-003`:

1. Create `platform_migrator` as `NOLOGIN` with final non-administrative
   attributes through the non-superuser `CREATEROLE` legacy owner.
2. Admit the exact protected bootstrap creator-admin edge
   (`grantor` = the fixture bootstrap superuser, `admin_option=true`,
   `inherit_option=false`, `set_option=false`) and prove it is not removable by
   the creator through an ordinary `REVOKE`.
3. Prove a separately granted and separately revocable supplemental
   `SET=true`, `INHERIT=false` edge with a distinct grantor.
4. Prove credential/login admission (password set, `LOGIN` enablement, direct
   read-only migrator connection) before ownership transfer, and prove a failed
   login leaves ownership unchanged.
5. Prove the exact transaction boundary: database and object ownership
   transfer inside one rollback-capable transaction in PostgreSQL 17.
6. Transfer database, `drizzle`, migration ledger and the application-owned
   object inventory (tables, index-following ownership, sequences, enums,
   routines); retain provider-managed `public` ownership with only the exact
   migrator `CREATE`/`USAGE` authority.
7. Revoke only the supplemental `SET=true` edge; prove the remaining automatic
   `ADMIN=true` edge still lets `platform_app` grant itself a fresh
   `SET=true` edge and successfully `SET ROLE platform_migrator` (the latent
   self-escalation consequence), then revoke only that self-granted edge.
8. Revoke the automatic edge using the provider/bootstrap authority after the
   successful transfer and complete read-back, and prove the final
   `platform_migrator` membership inventory is exactly zero across
   granted-role, member and grantor positions.
9. Prove the final ownership remains assigned to `platform_migrator`, the
   final attributes (`LOGIN`, `NOSUPERUSER`, `NOCREATEDB`, `NOCREATEROLE`,
   `NOREPLICATION`, `NOBYPASSRLS`) remain exact, `public` remains
   provider-owned with only the reviewed `CREATE`/`USAGE` authority, and
   `platform_runtime` remains zero-membership, zero-ownership and exactly equal
   to the 39-record contract; then prove `platform_app` cannot grant itself
   membership in `platform_migrator` and cannot `SET ROLE platform_migrator`.
10. Revoke the existing `platform_runtime`/`platform_app` edge and prove
    runtime zero-membership with the exact 39-record contract unchanged.
11. Execute a mechanically valid complete reverse rollback through the
    provider/bootstrap authority and prove the exact baseline restoration,
    including owners, ACLs, default ACLs, role attributes, memberships,
    removal of `platform_migrator` default-privilege records and a clean role
    drop.
12. Prove the legacy role cannot be retired until all replacement proof
    passes; conversion to `NOLOGIN` occurs only after complete proof.

### public ownership variants

The rehearsal covers provider-managed `public` only:

- `public` is owned by the disposable provider owner in every variant and is
  never transferred.
- `platform_migrator` receives only the exact reviewed `CREATE`/`USAGE`
  authority required for migration work, including a real bounded migrator
  transaction that creates a disposable migration object in `public`,
  validates it and rolls it back, proving the object is absent after rollback,
  `public` ownership remains with the provider owner and runtime authority is
  unchanged.

No variant may widen runtime authority.

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
- The focused RED-to-GREEN runbook contract tests, including the
  `DL-128-REPO-003` negative case proving that accepting the protected
  bootstrap edge as final omits the latent self-escalation consequence.
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
