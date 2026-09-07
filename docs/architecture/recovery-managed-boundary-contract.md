# Managed recovery boundary contract

This document records the single implementation definition for the fresh
Run-377 managed recovery generation. It is a repository contract, not a
deployment or production-activation instruction.

## Authority and ordering

The controller is the only component allowed to cross from an accepted
session into the broker. The required order is:

```text
accepted admission
-> Store/CAS-A
-> durable RESTORE_BEGIN
-> PROCEED
-> one controller stdin half-close
-> remote EOF with zero trailing input
-> authorized restore
-> deterministic RESULT and FINAL
```

Admission validation has no Store mutation path. ACCEPT is an admission
message only and never authorizes a restore. Any rejection after CAS-A enters
sticky `CONSUMED_UNCERTAINTY`; consumed authority is not rolled back.

## Byte domains

Managed records use canonical `J` JSON and length-prefixed `H` digests. A
retained Store record uses insertion-ordered `SB` bytes with one terminal LF
and tagged `SC` commitments. The Store object is never parsed and regenerated
as managed sorted-key JSON at a crossing.

The only retained crossing is:

```text
["store-json.v1", schema_id, StrictUTF8Decode(original_store_bytes)]
```

Only the three registered Store schemas in `backend.py` are accepted. The
decoded string must reconstruct the original bytes exactly; nested objects,
Base64, hex, untagged strings, alternate markers and dual formats are
rejected.

## Native boundary

The native implementation is dependency-free C11 with warnings-as-errors,
stack protection, fortified libc, and non-writable generated output. The
host-key custodian has no private key material and cannot sign directly. The
launch base requires static native code, no PAM, verified dm-verity and
enforcing SELinux before activation.

OpenSSH, account, namespace, SELinux and kernel inputs are immutable
qualification inputs. No production endpoint, credential, backup, restore,
provider, Docker or deployment default is defined here.

## Qualification

Deterministic tests cover canonical JSON, raw-versus-derived identities,
StoreWire round trips, all transcript commitments, lifecycle gates and scope
guards. Kernel-backed, OpenSSH, SELinux and dm-verity cases are mandatory in
the isolated hosted qualification job; an unavailable security primitive is a
failure, not a skipped pass.
