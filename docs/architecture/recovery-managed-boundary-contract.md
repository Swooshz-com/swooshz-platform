# Managed recovery boundary contract

This document is the implementation-facing summary of the Web-accepted
Run-370/372/374/376 contracts and their custody and supervisor-registration
amendments. It is intentionally descriptive; the wire and Store definitions
in `recovery/managed/backend.py` and the canonical Store/locator modules are
the executable sources of truth.

## Ownership and admission

One qualified native `RecoverySupervisor` owns the dedicated endpoint,
generation lifecycle, listener, accepted connections, child admission, host
identity custody, and retirement. A connection is admitted only after
`ACCEPTED_SOCKET -> SSH_AUTHENTICATED -> BOOTSTRAP -> CHALLENGE -> EVIDENCE ->
CONTROLLER_VALIDATED -> ACCEPT_SENT -> REMOTE_ACCEPTED -> OPERATIONAL`. Store
access is unavailable before controller validation and remote acceptance.

The generation lifecycle is `OFFLINE -> QUALIFIED -> ACTIVE -> DRAINING ->
RETIRING -> OFFLINE`. The broker is one-use and fail-closed; uncertainty after
the CAS consume is terminal and cannot be retried.

## Native boundary

Each accepted socket gets a fresh OpenSSH 10.5p1 inetd process. The supervisor
creates the exact AF_UNIX host-key-agent listener and session-control channel.
The custodian receives a registration record and exactly one SCM_RIGHTS pidfd
before the supervisor releases the blocked child with one `0xA5` byte followed
by EOF. The record is `SWZREG01` plus three 32-byte raw bindings (104 bytes).
The bootstrap context is `SWZCTX01` plus session, generation, connection, and
cookie bindings (136 bytes). The custodian accepts only a registered live
process whose pidfd, peer credentials, process tree, namespace, label, and
generation all match.

The host public key is immutable at
`/etc/ssh/recovery_host_ed25519_key.pub`; signing is available only through
the restricted direct `HostKeyAgent
/run/swz/recovery-hostkey-agent.sock` path. There is no stock `ssh-agent`,
`ssh-add`, environment-socket authority, provider, or PKCS#11 path. The
production seed is a root-owned 32-byte file at
`/var/lib/swooshz-recovery/host-key/ed25519.seed`; qualification creates only
ephemeral disposable material.

## Identity and wire rules

Managed identities use
`SHA256(LP("swz-managed.v1") || LP(ASCII(domain)) || LP(each raw argument))`,
where `LP` is a big-endian 32-bit byte length followed by the exact bytes.
Store commitments use the separate `recovery-commitment.v1` domain. Store
documents are compact UTF-8 JSON with insertion order preserved and one final
LF. StoreWire is exactly
`["store-json.v1", schema_id, exact_store_document_text]`.

The `SWZFRM02` header is 56 bytes: magic, version, direction, message, flags,
sequence, previous hash, and payload length. Payloads are bounded to 4096
bytes, sessions to 16 frames and 1 MiB. The accepted transcript is
`BOOT -> CHALLENGE -> EVIDENCE -> ACCEPT -> ACCEPTED -> DISCOVERY ->
RESTORE_BEGIN -> PROCEED -> RESULT`; frame hashes are plain SHA-256 over the
exact header and payload.

The Store sequence is `RESTORE_BEGIN -> PROCEED -> RESULT` with a real
ControllerStore CAS consume, durable spool frames, an exact transition ID,
one terminal result, input EOF, output EOF, and cleanup/retirement evidence.

## Qualification

Native components are compiled on Linux with unchanged
`-std=c11 -O2 -Wall -Wextra -Werror -Wpedantic` and checked for closure before
publication. OpenSSH and musl are fetched only at the pinned hashes in
`build.lock.json`; generated output is rooted under `_output` or a disposable
runner directory. Final candidate qualification additionally boots a
dm-verity image, proves SELinux Enforcing and denial cases, exercises the
inetd/custody boundary, and proves process and generation finality. Mandatory
security skips are zero.

## Run-401 contract-conformance matrix

This matrix was rebuilt for Run-401 from the accepted Run-370, Run-372,
Run-374, Run-376, custody, supervisor-registration, execution-only,
Run-395, Run-400, and Run-401 records. No status below is inherited from an
older scratch. A status is PASS only where the current scratch has fresh
evidence; implementation and hosted/security rows begin as NOT_YET_PROVEN,
with known prior defects tracked explicitly until the corrected path has fresh
proof.

| ID | Invariant | Implementation file/function | Deterministic test | Required hosted/guest proof | Status |
| --- | --- | --- | --- | --- | --- |
| A01 | The full Run-401 FINAL CLEAR and Run-400 amendment are the execution authority. | Issue #105 comments 5595350538, 5595339224 | Authenticated gh api body read in full | None | PASS (fresh) |
| A02 | Canonical main is exactly 3bff98ac5ef10c1675d4691f516952ac937915d3 with tree 6acfd821b69af986eb81f6bbcbce501d93c8cd92; signature is VERIFIED/VALID. | GitHub commit object | gh api and local rev-parse | None | PASS (fresh) |
| A03 | PR #163 is CLOSED, UNMERGED, EVIDENCE_ONLY at the accepted head. | GitHub PR object | gh api pulls/163 | None | PASS (fresh) |
| A04 | Run-398 remains frozen at the exact accepted head and tree. | Git ref/commit object | gh api commit and local tree check | None | PASS (fresh) |
| A05 | No remote Run-399 scratch exists; #105 is CURRENT under #104; #115 is BLOCKED. | GitHub refs/issues | Authenticated ref and issue reads | None | PASS (fresh) |
| A06 | Scratch has exactly the retained 41 tracked paths, no generated output, no secret exposure, and canonical Store/locator paths are byte-identical to main. | Git index and git diff | Path ceiling, byte comparison, secret-pattern scan | None | PASS (fresh baseline) |
| A07 | Run-401 scratch starts from exact canonical main, with any Run-398 baseline uncommitted and evidence-only. | Scratch worktree | git write-tree equals Run-398 tree before edits | None | PASS (fresh baseline) |
| I01 | Run-374 LiteralEndpointRecord and identity preimages use the accepted domains, tags, lengths, and graph. | recovery/managed/backend.py identity helpers; platform.c identity checks | test_protocol.py, identity KATs | Guest runtime identity proof | NOT_YET_PROVEN |
| I02 | C and Python identity implementations agree byte-for-byte on all accepted KATs. | platform.c, backend.py | Native and Python KAT tests | Guest KAT evidence | NOT_YET_PROVEN |
| I03 | Store and locator canonical source/tests remain unchanged from main. | Canonical Store/locator files | Byte-for-byte comparison | Hosted artifact comparison | NOT_YET_PROVEN |
| I04 | No path outside the retained 41-path scope is tracked or generated. | qualify.py path ceiling | test_publication.py and qualification path audit | Candidate tree audit | NOT_YET_PROVEN |
| W01 | Every managed frame uses exact SWZFRM02 56-byte !8sBBBBQ32sI header. | backend.py FrameSession; protocol.c | test_protocol.py wire KATs | Guest transcript bytes | NOT_YET_PROVEN |
| W02 | previous_hash is always raw N_local; hash covers only the exact payload. | backend.py, protocol.c | Frame/hash KATs | Guest transcript verification | NOT_YET_PROVEN |
| W03 | Managed-wire scalar widths, tags, sequence, direction, bounds, and one-LF JSON are exact. | backend.py frame validators | Protocol negative/positive tests | Guest transcript | NOT_YET_PROVEN |
| W04 | The accepted transcript is exactly BOOT, CHALLENGE, EVIDENCE, ACCEPT, ACCEPTED, DISCOVERY, RESTORE_BEGIN, PROCEED, RESULT, with no READY. | bootstrap.c, broker.c, controller.py | Transcript state tests | Real managed session | NOT_YET_PROVEN |
| W05 | fd6 records use exact SWZRCB01/SWZRCF01 framing, field order, and SHA-256 over all preceding bytes. | agent.c, broker.c, backend.py | Context vector tests | Guest native capture | NOT_YET_PROVEN |
| W06 | fd6 is one-use, bounded to the accepted per-record/combined/stream limits, and ends immediately after FINAL with EOF. | agent.c, broker.c | Short/long/trailing/third-record tests | Guest native capture | NOT_YET_PROVEN |
| W07 | BIND and FINAL identity, generation, connection, session, S, transition, TD, PC, digest, and replay bindings are exact. | agent.c, broker.c, controller.py | Reorder/stale/wrong-binding tests | Guest replay/negative cases | NOT_YET_PROVEN |
| W08 | The native agent, not Python or a callback, owns the mandatory runtime RESULT. | agent.c result construction | Native RESULT ownership test | Guest proves native origin | NOT_YET_PROVEN (Run-399 defect addressed; guest proof pending) |
| S01 | Canonical Store/CAS bytes, commitments, schema, and locator remain exact. | backend.py and unchanged canonical Store/locator sources | Store/locator KATs | Hosted artifact/readback | NOT_YET_PROVEN |
| S02 | Matching ACCEPTED precedes exactly one Store/CAS consume and durable RESTORE_BEGIN. | controller.py run; broker.c | CAS ordering/failure tests | Guest Store trace | NOT_YET_PROVEN |
| S03 | RESTORE_BEGIN is exact Run-376 StoreWire with accepted payload bytes, fields, and commitment. | backend.py build_restore_begin | RESTORE_BEGIN KATs | Guest managed transcript | NOT_YET_PROVEN |
| S04 | PROCEED is exact Run-376 StoreWire and validates all accepted bindings before execution. | backend.py build_proceed; agent.c | PC/PROCEED KAT and rejection tests | Guest barrier trace | NOT_YET_PROVEN |
| S05 | Final Store COMMIT/readback/finality is impossible before controller validation of native RESULT and finality. | controller.py commit path | Commit-gating tests | Guest final Store evidence | NOT_YET_PROVEN |
| L01 | ACCEPT is a real authorization barrier with immutable session/generation and no pre-accept restore effect. | bootstrap.c, broker.c, supervisor.c | Pre-accept effect tests | Guest lifecycle proof | NOT_YET_PROVEN |
| L02 | No restore-capable effect occurs before valid PROCEED plus terminal controller EOF. | agent.c, broker.c | Barrier/no-effect tests | Guest restore trace | NOT_YET_PROVEN (Run-399 defect addressed; guest proof pending) |
| L03 | The controller performs exactly one stdin half-close; native observes EOF and zero trailing managed input. | controller.py, agent.c | Missing/second half-close/trailing-input tests | Guest socket trace | NOT_YET_PROVEN |
| L04 | Restore, worker, readback, cleanup, retirement, and finality observations are durable and ordered. | broker.c, supervisor.c, controller.py | Lifecycle/finality tests | Guest supervisor/worker evidence | NOT_YET_PROVEN |
| L05 | Source, sink, readback, and cleanup failures reject success and preserve sticky uncertainty/quarantine semantics. | broker.c, backend.py | Failure-injection tests | Guest failure evidence | NOT_YET_PROVEN |
| L06 | Managed output reaches EOF with zero trailing bytes before final commit. | controller.py, agent.c | Output EOF/trailing-byte tests | Guest socket capture | NOT_YET_PROVEN |
| C01 | Only the exact raw32 Ed25519 seed is consumed from the accepted custody path and zeroised. | custodian.c, supervisor.c | Seed-length/zeroisation tests | Guest custody evidence | NOT_YET_PROVEN |
| C02 | Production host-key paths, direct HostKeyAgent, and pinned public key are exact; caller cannot substitute them. | custodian.c, sshd_config, file_contexts | Path/public-pin/agent tests | Guest OpenSSH custody session | NOT_YET_PROVEN |
| C03 | Supervisor, custodian, registered restore worker, dispatcher, and agent lifecycle are owned and retired by the supervisor. | supervisor.c, custodian.c, dispatcher.c | Lifecycle tests | Guest process/finality proof | NOT_YET_PROVEN |
| C04 | Registration is raw32 SWZREG01 plus exactly one retained pidfd SCM_RIGHTS record, with exact ACK. | supervisor.c, custodian.c | Registration/pidfd negatives | Guest socket/process proof | NOT_YET_PROVEN |
| C05 | SWZRGOK1 precedes exactly one 0xA5 plus EOF exec grant; no argv/env bootstrap authority exists. | supervisor.c | Gate ordering and argv/env negatives | Guest real inetd OpenSSH proof | NOT_YET_PROVEN |
| C06 | CTX is raw32 SWZCTX01 plus four raw32 values over supervisor-authenticated SOCK_SEQPACKET. | supervisor.c, bootstrap.c | CTX framing/peer tests | Guest session-control proof | NOT_YET_PROVEN |
| C07 | HostKeyAgent accepted operations and mandatory negative operations are enforced. | custodian.c | HostKeyAgent KATs | Guest direct-agent negatives | NOT_YET_PROVEN |
| C08 | Seed, private key material, dumps, and cores are zeroised or blocked under the accepted lifecycle. | custodian.c, supervisor.c, kernel/image policy | Zeroisation/core/dump tests | Guest security evidence | NOT_YET_PROVEN |
| B01 | Native post-exec fd map is exactly 0 stdin, 1 stdout, 2 bounded stderr, 3 closed, 4 source, 5 restore write, 6 context read, and >=7 closed. | bootstrap.c, agent.c | fd-map inheritance test | Guest /proc/native proof | NOT_YET_PROVEN |
| B02 | LAUNCH_AGENT_DESCRIPTORS_V1 returns exactly three SCM_RIGHTS descriptors in fixed SOURCE_ARTIFACT, RESTORE_TARGET, RESULT_CONTEXT order. | broker.c, supervisor.c | Typed-operation vectors | Guest broker/native proof | NOT_YET_PROVEN |
| B03 | The operation has no caller-selected path, fd number, role, count, flags, target, or remapping. | broker.c, bootstrap.c | Caller-authority negative tests | Guest malformed-operation proof | NOT_YET_PROVEN |
| B04 | Bootstrap validates exact roles/count, maps with dup3(...,0) to 4/5/6, closes originals/unexpected fds, then immediately execs the fixed agent. | bootstrap.c | Missing/swapped/duplicate/extra/wrong-fd tests | Guest native inheritance proof | NOT_YET_PROVEN |
| B05 | fd4 is the exact qualified source descriptor with no reopen, pathname authority, substitution, or rebinding. | agent.c, broker.c | Wrong type/mode/identity and reopen tests | Guest source descriptor proof | NOT_YET_PROVEN |
| B06 | fd5 is the anonymous broker-created restore-target pipe to the fixed registered worker and cannot be retargeted. | broker.c, supervisor.c, agent.c | Pipe identity/retarget tests | Guest worker/restore proof | NOT_YET_PROVEN |
| B07 | fd6 is the anonymous connection-private RESULT-context pipe and cannot be substituted or reused. | broker.c, agent.c | Context identity/replay tests | Guest native context proof | NOT_YET_PROVEN |
| B08 | No unexpected descriptor >=7 survives bootstrap or native validation. | bootstrap.c, agent.c | Descriptor-closure tests | Guest /proc/exec proof | NOT_YET_PROVEN |
| B09 | Wrong descriptor type, mode, identity, missing, swapped, duplicate, extra, and stale descriptors are rejected. | bootstrap.c, agent.c | Complete descriptor negative suite | Guest native negative suite | NOT_YET_PROVEN |
| B10 | Descriptor role and target authority are broker/supervisor-owned and connection-private. | broker.c, supervisor.c | Authority/remapping negatives | Guest process/socket proof | NOT_YET_PROVEN |
| B11 | Native validates fd4/5/6 after exec and sets FD_CLOEXEC on retained descriptors. | agent.c | Post-exec validation/KAT | Guest native proof | NOT_YET_PROVEN |
| R01 | Matching ACCEPTED, consume, RESTORE_BEGIN, BIND availability, exact PROCEED, one half-close, EOF, restore, FINAL, RESULT, validation, output EOF, and commit occur in exact order. | controller.py, broker.c, agent.c | Full sequence/state tests | Guest complete trace | NOT_YET_PROVEN |
| R02 | Native constructs the exact canonical B_R only from validated final observations, with exact Store schema/order/final LF. | agent.c, backend.py validator | B_R schema/order/vector tests | Guest native bytes | NOT_YET_PROVEN |
| R03 | Native computes exact RC from S, transition ID, PC, and B_R, and the controller independently recomputes it. | agent.c, controller.py | RC KAT/agreement tests | Guest independent recomputation | NOT_YET_PROVEN |
| R04 | Exactly one native RESULT is emitted; duplicate, pre-restore, non-native, malformed, digest-invalid, or replayed RESULT is rejected. | agent.c, controller.py, broker.c | RESULT ownership/negative suite | Guest native origin/rejection proof | NOT_YET_PROVEN (Run-399 defect addressed; guest proof pending) |
| R05 | The controller never accepts a caller-supplied or callback-supplied result payload as authority. | controller.py _run_supervised_agent, run | Callback/result injection tests | Guest controller/native boundary | NOT_YET_PROVEN (Run-399 defect addressed; guest proof pending) |
| R06 | PYTHON_FABRICATED_RESULT=ABSENT; Python may only parse, validate, and recompute. | controller.py, qualify.py | Source/runtime ownership tests | Guest runtime trace | NOT_YET_PROVEN (Run-399 defect addressed; guest proof pending) |
| R07 | Native stdout/stderr are bounded exact captures; diagnostics cannot alter RESULT or protocol bytes. | agent.c, controller.py | Capture bound/diagnostic tests | Guest output capture | NOT_YET_PROVEN |
| R08 | Result/finality cleanup and retirement are retained as evidence and cannot be fabricated by fixtures or callbacks. | agent.c, broker.c, supervisor.c | Cleanup/finality provenance tests | Guest process evidence | NOT_YET_PROVEN |
| N01 | Native build remains C11 with -Wall -Wextra -Werror -Wpedantic. | recovery/managed/Makefile | Native build | Guest/build artifact | NOT_YET_PROVEN |
| N02 | Native/static closure is proved with no unexpected dynamic or host-path dependency. | qualify.py, Makefile | Static-closure test | Guest image closure | NOT_YET_PROVEN |
| N03 | Pinned OpenSSH 10.5p1 and musl sources/build/runtime are exact. | build.lock.json, build scripts/patches | Lock/hash/build tests | Guest runtime proof | NOT_YET_PROVEN |
| N04 | Locator uses disposable exact /usr/local/bin/psql and does not grant external authority. | Unchanged canonical locator sources; qualify.py | Locator integration test | Hosted/guest locator proof | NOT_YET_PROVEN |
| N05 | A real inetd OpenSSH custody session exercises the native boundary. | sshd_config, supervisor.c, qualification-vm.py | Integration harness | Guest runtime proof | NOT_YET_PROVEN |
| N06 | q35 guest boots a dm-verity image with the accepted immutable layout. | image-layout.json, qualification-vm.py | Image-layout checks | Guest boot proof | NOT_YET_PROVEN |
| N07 | Actual SELinux policy loads, reaches Enforcing, and direct denial cases are observed. | selinux.cil, file_contexts, guest scripts | Policy parse/static tests | Guest SELinux evidence | NOT_YET_PROVEN |
| N08 | Socket and process confinement is enforced across supervisor, custodian, worker, agent, and sshd. | selinux.cil, supervisor.c, sshd_config | Confinement negative tests | Guest denial/runtime proof | NOT_YET_PROVEN |
| N09 | MANDATORY_SECURITY_SKIPS=0 in the complete qualification. | qualify.py, qualification-vm.py | Qualification summary test | Complete guest/security run | NOT_YET_PROVEN |
| Q01 | Every safely available deterministic test is run and failures are repaired or reported. | qualify.py, tests/recovery-managed | Focused unittest/native test suite | None | NOT_YET_PROVEN |
| Q02 | At most two pre-guest checkpoints and two guest snapshots are consumed. | Qualification run record | Budget accounting test | Hosted run ledger | NOT_YET_PROVEN |
| Q03 | At most four hosted runs are used, with no hidden retry or fifth run. | Qualification run record | Run ledger check | Hosted run ledger | NOT_YET_PROVEN |
| Q04 | No candidate branch or PR is created before one exact scratch head passes complete guest/security qualification with zero mandatory skips. | Git refs/PR | Publication guard tests | Controller review | NOT_YET_PROVEN |
| Q05 | Final packet records exact scratch head/tree, path ceiling, Store/locator equality, all evidence, and truthful verdict; no G4 self-start. | qualify.py, issue #105 comment | Terminal-packet schema test | Hosted/controller review | NOT_YET_PROVEN |

CONTRACT_MATRIX_COMPLETE=YES
