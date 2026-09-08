# Managed recovery boundary contract

This document is the repository-side implementation index for the Web-accepted
Run-370 architecture and Run-372/374/376 contracts. It is not a production
enrollment record and it does not provide live, credential, deployment or
restore authority.

The admitted boundary is one qualified native `RecoverySupervisor` generation
with a dedicated listener, fresh per-connection OpenSSH 10.5p1 inetd process,
restricted host-key custodian, native dispatcher/bootstrap, typed broker and
operational agent. The pre-ACCEPT chain has no Store, Docker, locator, artifact,
private-state or restore capability. The broker grants typed operations only
after the same-session `CHALLENGE -> EVIDENCE -> ACCEPT -> ACCEPTED` barrier.

The retained ControllerStore and persisted locator are separate authorities and
remain byte-identical. Their Store bytes use compact UTF-8 JSON with the
retained object order and one final LF. `RESTORE_BEGIN` at the Store spool
boundary is exactly the two-key frame payload `{ref, commitment}` in that
order. The managed StoreWire boundary carries the complete retained document as
the third string member of `["store-json.v1", schema_id, store_text]`.

Restore is one-use and fail-closed:

```
accepted admission
 -> canonical Store/CAS consumption
 -> durable RESTORE_BEGIN
 -> PROCEED
 -> exactly one controller stdin half-close
 -> remote EOF and zero trailing input
 -> authorised restore
 -> deterministic RESULT and process/generation finality
```

Managed identities use `swz-managed.v1`, one outer U32 length prefix per
argument, and the 43 distinct domain strings in `backend.py`. Store
commitments never use the managed hash. Raw key blobs, managed digests and
tagged Store digests have distinct constructors and validators.

Qualification is fail-fast and records stage, command, return code and bounded
redacted output. Deterministic, native, pinned-build, Store/locator and
host-side lifecycle/custody checks run before the expensive booted guest. A
guest result is a PASS only when QEMU boots the candidate root through the
verified dm-verity mapping, SELinux is Enforcing in the guest, policy and file
contexts are applied, denials are observed and the candidate processes reach
their terminal states. Provider or kernel capability failures remain explicit
holds; they are never converted into success.

The exact source scope is the 40 managed recovery paths plus the CI workflow.
The four canonical Store/locator files and their tests are outside the mutation
scope and must remain byte-identical to admitted main.
