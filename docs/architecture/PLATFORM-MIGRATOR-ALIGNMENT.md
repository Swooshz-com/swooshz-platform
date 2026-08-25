# Platform Migrator Alignment

## Purpose

This document is the repository contract for issue #128 (dedicated Platform
migrator authority) under parent #104. It implements the controller corrections
in `DL-128-REPO-001`, `DL-128-REPO-002` (PostgreSQL 17 creator-edge,
transaction, rollback and credential-order semantics), `DL-128-REPO-003`
(creator-edge finality) and `DL-128-REPO-004` (real password credential
admission, complete membership-position closure, target-`NOCREATEDB` negative
control, legacy-retirement guard and real PostgreSQL 17 `pg_database_owner`
semantics), under the Run-09 authority in #128 comment `5211873287`.

It is repository contract and disposable-rehearsal evidence only. It creates no
role, grants no privilege, transfers no ownership, rotates no credential,
creates no projection, accesses no Neon/provider API, touches no Coolify state
and performs no deployment. It releases no live-system authority.
## Current Run-164 contract (authoritative)

Run-164 and `DL-122-LIVE-098-RUNTIME-MIGRATOR-CONTROL-PLANE-CONTRACT-IMPLEMENTATION-G3`
lock the current Platform repository contract. This section supersedes any
conflicting historical rehearsal language later in this document. It does not
claim that live Neon roles or ownership have already converged.

### Technical roles

- `platform_runtime` is the direct long-running application identity. It is
  `LOGIN`, `NOINHERIT`, non-superuser, `NOCREATEDB`, `NOCREATEROLE`,
  `NOREPLICATION`, and `NOBYPASSRLS`; it owns no database, schema, relation,
  type, sequence, index, routine, or application object. It has no migration
  or DDL authority and retains only the accepted 39-record direct grant set.
  `DATABASE_URL` must connect directly as `platform_runtime`, with
  `session_user = current_user = platform_runtime`. `DATABASE_EXPECTED_RUNTIME_ROLE`
  is not an identity selector; the expected role is fixed in code and any
  supplied value must be exactly `platform_runtime`.
- `platform_migrator` is the direct one-off migration/operator identity. It
  is `NOINHERIT`, non-superuser, `NOCREATEDB`, `NOCREATEROLE`,
  `NOREPLICATION`, and `NOBYPASSRLS`; it is `LOGIN` only during a controlled
  operator window and may be returned to `NOLOGIN` while dormant. It is never
  the Coolify runtime identity and never uses `DATABASE_URL`.
  `DATABASE_OPERATOR_URL` must connect directly as `platform_migrator`; the
  operator path requires `DATABASE_MIGRATIONS_CONFIRM=apply-reviewed-migrations`
  for migration execution and has no `DATABASE_URL` fallback.
- `platform_app` remains the initial Platform database owner and privileged
  control-plane/rollback identity. It is not an application runtime or
  migrator binding. After a healthy Platform deployment and bounded rollback
  observation, a separately authorised operation may invalidate its ordinary
  credential and set `NOLOGIN`; it must not be dropped while it remains the
  database owner.
- `platform_maintenance` is not a Platform application role. No distinct
  workload justifies a fourth role.

### Ownership and membership

The intended converged ownership matrix is: application database owner
`platform_app`; `public` schema owner `pg_database_owner`; application
namespace schemas and canonical application objects owned by
`platform_migrator`; and zero application ownership for `platform_runtime`.
The namespace includes the Drizzle schema and ledger, Platform tables,
enums/types, sequences, indexes, routines and other canonical application
objects. `platform_migrator` receives only the schema/database privileges
needed for reviewed migrations; it is not made database owner and does not
receive `CREATEDB`. `platform_runtime` has effective database `CONNECT=true`,
`CREATE=false`, and `TEMPORARY=false`.
Synthetic `appdata` objects used by the disposable migrator-alignment
fixture are fixture-only and are not a live production namespace or readiness
requirement.

Every membership read is scoped to rows where a selected role is the granted
role, member, or grantor. The only accepted creator-admin tuple touching
`platform_runtime` is `granted_role=platform_runtime`,
`member=platform_app`, `grantor=cloud_admin`, `ADMIN=true`,
`INHERIT=false`, `SET=false`. The only accepted future creator-admin tuple
touching `platform_migrator` has the same member, grantor, and options with
`granted_role=platform_migrator`. `ADMIN=true` is real administrative
authority, even with `INHERIT=false` and `SET=false`; `cloud_admin` remains
outside ordinary Platform runtime configuration. Missing, extra, reversed, or
option-drifted tuples fail closed.

### Later migration and live-operation boundary

Migration `0010_admin_operator_viewer_role_collapse.sql` and its Drizzle
journal remain unchanged and unapplied. A later controlled window must prove
recovery/restore, writer quiescence, role provisioning and direct migrator
identity, trusted journal state, canonical migration execution, post-migration
journal state, the exact `admin`/`operator`/`viewer` enum and mapping,
membership/invitation/approval invariants, the active-workspace admin
invariant, runtime privilege/ownership separation, and containment or
retirement of temporary authority. Migration, DNS/TLS, deployment, Coolify,
Neon/provider role convergence, and application activation remain separately
gated and are not authorised by this repository contract.

## Sources of authority

- Parent issue #104 rolling queue.
- Child issue #128, including the current body and comment `5211873287`.
- Repository Design Lock `DL-128-REPO-001`, amended by repository contract
  amendment `DL-128-REPO-002` (PostgreSQL 17 creator-edge, transaction,
  rollback and credential-order semantics), superseded for creator-edge
  finality by repository contract amendment `DL-128-REPO-003`, and amended by
  repository contract amendment `DL-128-REPO-004` (post-merge repair of the
  six PR #131 review findings: real password credential admission, complete
  membership-position closure, target-`NOCREATEDB` negative control,
  legacy-retirement guard and real PostgreSQL 17 `pg_database_owner`
  semantics).
- Completed topology evidence #116 / Run-49.
- Completed #127 and merged PR #129, including the accepted 39-record runtime
  grant contract and the exact disposable PostgreSQL 17 fixture authority.
- Merged PR #131 and its six post-merge review threads, all adjudicated
  `VALID_OPEN` by the controller and repaired under Run-09.
- Blocked successor #122.

## Historical Run-09 rehearsal record (non-operative)

The following material preserves earlier disposable evidence and its
provenance. It is not the current live topology or an instruction to retain
zero migrator memberships, transfer database ownership, or mutate a provider.
Where it conflicts with the Current Run-164 contract above, the current
contract controls.

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

## public schema ownership contract

The accepted read-only live evidence establishes one current starting fact:

> In the live database, the `public` schema is owned by the predefined
> `pg_database_owner` role.

PostgreSQL defines `pg_database_owner` as having exactly one implicit member:
the **current database owner**. A `public` schema owned by `pg_database_owner`
is therefore governed by the current database owner, and `pg_database_owner`
must not be described as an unrelated independent provider role. The repository
does not carry an application-controlled-`public` branch: that question was
already resolved by the accepted live evidence.

Consequence: if a later live transaction transfers database ownership to
`platform_migrator` while `public` remains owned by `pg_database_owner`,
`platform_migrator` becomes the implicit role exercising the associated
`public` owner authority. The disposable rehearsal models, proves and reports
that consequence and its complete reverse rollback; it does not claim `public`
stays independently provider-controlled.

The repository contract performs no live ownership mutation. Run-09 chooses no
live ownership decision. After this repair is merged and independently
accepted, a fresh read-only live preflight will determine whether the final
live Design Lock should explicitly accept the database-owner/public-owner
authority relationship, establish a separately proven stable owner for
`public` before/with the transfer, or choose another safe topology. The final
live Design Lock may choose among only facts mechanically proven by that fresh
preflight.

A separate explicitly labelled **stable-provider-owner fixture**
(`provider_owner`) may remain in the rehearsal only as a distinct possible
future topology. It is not evidence for the known live `pg_database_owner`
topology and may not substitute for it.

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
- The disposable migrator runner owns the exact named PostgreSQL data volume
  `deepseek-platform128-pg17-data`, mounted read/write at
  `/var/lib/postgresql/data`. It proves the exact volume is absent before
  creation or attachment and rejects a pre-existing exact-volume identity
  collision. Each invocation binds a fresh in-memory ownership token to the
  volume labels and requires that same token during inspection, reconciliation
  and cleanup; fixed-marker, pre-existing, mismatched-token and ambiguous
  evidence is never treated as runner ownership.
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
- Enforces real password authentication on the migrator credential-admission
  path. The runner replaces the container host-authentication configuration
  with an exact managed `pg_hba.conf` whose first-match rules require
  `scram-sha-256` for `platform_migrator` host connections (loopback and any
  forwarded source address) before the bootstrap `trust` fallback for the
  fixture's operator and legacy roles, reloads the configuration through
  `pg_reload_conf()` and verifies the written rules. The bootstrap
  `POSTGRES_HOST_AUTH_METHOD=trust` posture is superseded before any migrator
  connection and is never used as credential-admission evidence.

### Disposable equivalents

The rehearsal creates disposable equivalents of:

- current legacy owner (`platform_app`, modelled with its transitional
  `CREATEDB` attribute);
- future migrator (`platform_migrator`, final attributes);
- restricted runtime (`platform_runtime`, non-owning, `NOLOGIN`);
- the real `pg_database_owner` topology of the primary fixture (`public`
  remains owned by the predefined `pg_database_owner` role, whose implicit
  member is the current database owner);
- an explicitly labelled stable-provider-owner fixture (`provider_owner`) in
  the secondary fixture, modelling only a distinct possible future topology;
- application schema, migration schema and ledger;
- representative table, index, enum, routine and sequence;
- the accepted 39-record runtime grant contract.

### Starting fingerprint

The rehearsal captures a non-vacuous starting fingerprint covering database
owner and database ACL entries, `public`/`appdata`/`drizzle` owners and complete
schema ACL entries, relevant `pg_default_acl` entries, relation/index/sequence/
enum/routine ownership, exact role attributes and exact membership edges with
`admin_option`, `inherit_option` and `set_option`. ACL evidence is normalised
into stable structured grantor/grantee/privilege/grantability records.

### Deterministic cleanup

The runner removes all runner-owned databases, roles, schemas and objects,
then the exact container and the exact named volume
`deepseek-platform128-pg17-data`, and proves exact container absence,
exact volume absence, and exact listener absence after success and after every
failure path. Exact volume removal occurs only after container removal. Normal
and ambiguous owned-create cleanup converge on one bounded volume-removal
attempt; once `volumeRemoved=true`, no second attempt is made. Caller-managed or
unproven resources are untouched. Broad/global Docker volume pruning is
prohibited. The unidentified historical anonymous volume is not selected or
deleted.

### Required negative control

The rehearsal proves that the executing legacy/database owner, holding only
the automatic bootstrap edge (`SET=false`, `INHERIT=false`), lacks the
target-role assumption/SET-capable authority required for the ownership
transfer. `platform_migrator` remains `NOCREATEDB` throughout; no temporary
`CREATEDB` is granted to it. The test attempts the database-owner transfer
from the executing legacy owner before the bounded transfer window, observes
the PostgreSQL 17 rejection (`must be able to SET ROLE` / `permission denied`),
proves the target attributes remain exact (`NOCREATEDB`, `LOGIN` unchanged)
and proves zero unintended persistent mutation by baseline-equality of the
ownership fingerprint.

### Pre-completion legacy retirement effect

`DROP ROLE platform_app` remains mechanically rejected while dependent objects or ownership remain. `ALTER ROLE platform_app NOLOGIN` is distinct: PostgreSQL can apply it while those dependencies remain, so the controller sequence, rather than a claimed PostgreSQL dependency rejection, must forbid premature retirement. The disposable rehearsal may exercise `NOLOGIN` only as a bounded reversible negative control: require `LOGIN` before the check, apply `NOLOGIN` through admitted disposable admin authority, prove that a brand-new `platform_app` connection fails, restore `LOGIN`, and prove that a brand-new connection succeeds. An already-open session is diagnostic only. No live `NOLOGIN` action is authorized by this repository rehearsal.

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
4. Prove credential/login admission under real password authentication: the
   disposable fixture enforces `scram-sha-256` for the migrator host path
   (the bootstrap `trust` posture is superseded before any migrator
   connection), `platform_migrator` begins `NOLOGIN` with no password, direct
   login fails before activation, the exact synthetic password is installed
   with `LOGIN` enablement, a fresh connection using that exact password
   succeeds and reads back the exact role and database, a fresh connection
   with a wrong password fails, a fresh connection with the password omitted
   fails, and a failed login leaves ownership unchanged.
5. Prove the exact transaction boundary: database and object ownership
   transfer inside one rollback-capable transaction in PostgreSQL 17. The
   statement order inside that transaction satisfies the directional
   PostgreSQL 17 owner checks: the application-owned objects transfer first
   while the target still holds `CREATE` on their schemas, the `drizzle` and
   `appdata` schemas transfer while the executing legacy owner still holds
   database-`CREATE` (the `ALTER SCHEMA ... OWNER` check), the database
   ownership transfers next (the `ALTER DATABASE ... OWNER` SET-capable
   check), and the `public` table transfers run last so the new database
   owner satisfies the new-owner schema-`CREATE` requirement through the
   implicit `pg_database_owner` membership (the `ALTER TABLE ... OWNER`
   check).
6. Transfer database, `drizzle`, migration ledger and the application-owned
   object inventory (tables, index-following ownership, sequences, enums,
   routines); `public` remains owned by `pg_database_owner` and the rehearsal
   proves the effective-authority consequence: the database owner exercises
   the associated `public` owner authority before and after the transfer and
   through complete reverse rollback.
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
   `NOREPLICATION`, `NOBYPASSRLS`) remain exact, `public` remains owned by
   `pg_database_owner` with the effective authority following the current
   database owner, and `platform_runtime` remains zero-membership,
   zero-ownership and exactly equal to the 39-record contract; then prove
   `platform_app` cannot grant itself membership in `platform_migrator` and
   cannot `SET ROLE platform_migrator`.
10. Revoke the existing `platform_runtime`/`platform_app` edge and prove
    runtime zero-membership with the exact 39-record contract unchanged.
11. Execute a mechanically valid complete reverse rollback through the
    provider/bootstrap authority and prove the exact baseline restoration,
    including owners, ACLs, default ACLs, role attributes, memberships,
    removal of `platform_migrator` default-privilege records and a clean role
    drop; the original database owner and the corresponding
    `pg_database_owner`-derived `public` authority are restored with no
    residue.
12. Prove the legacy role cannot be retired until all replacement proof
    passes: at the migrated zero-membership state before the completion point,
    `DROP ROLE platform_app` is mechanically rejected and the legacy
    authority remains available for rollback; conversion to `NOLOGIN` occurs
    only after complete proof.

### public ownership variants

The rehearsal covers two explicitly labelled variants:

- **Real `pg_database_owner` topology (primary fixture, models the known live
  starting state).** `public` is owned by the predefined `pg_database_owner`
  role and is never transferred. Its single implicit member is the current
  database owner. The rehearsal proves which role exercises the
  database-owner/`public`-owner authority before the transfer
  (`platform_app`), that the database-owner transfer to `platform_migrator`
  makes `platform_migrator` the implicit role exercising that `public` owner
  authority, that the effective authority over `public` changes accordingly
  (with runtime authority unchanged), and that complete reverse rollback
  restores the original database owner and the corresponding
  `pg_database_owner` authority with no residue. The fixture also mirrors the
  accepted live default-privilege posture: the `pg_database_owner` creator
  role receives explicit default-privilege revokes (tables, sequences and
  functions from `PUBLIC`) exactly like the other fixture creator roles, so
  the runtime posture gate observes no `PUBLIC` default authority. This
  variant is the live topology proof; it does not claim `public` stays
  independently provider-controlled.
- **Explicitly labelled stable-provider-owner fixture (secondary fixture).**
  `public` is owned by the disposable `provider_owner` role and `platform_migrator`
  receives the exact reviewed `CREATE`/`USAGE` authority, including a real
  bounded migrator transaction that creates a disposable migration object in
  `public`, validates it and rolls it back, proving the object is absent after
  rollback and runtime authority is unchanged. This fixture models only a
  distinct possible future topology; its evidence may not substitute for the
  known live `pg_database_owner` proof.

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
