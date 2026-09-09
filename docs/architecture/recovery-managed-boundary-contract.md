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

