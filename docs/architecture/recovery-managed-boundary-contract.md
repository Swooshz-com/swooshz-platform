# Managed recovery boundary

This directory is the disposable, testable implementation of the accepted
Run-370 architecture as amended by Run-374 identity/preimage closure and
Run-376 StoreWire closure. It is not a deployment recipe and has no authority
to operate a production host, private backup, credential, Docker, Coolify or
Traefik resource.

## Authority and lifecycle

Admission is a same-session, two-sided sequence:

BOOT -> CHALLENGE -> EVIDENCE -> ACCEPT -> ACCEPTED -> DISCOVERY

The controller validates the complete identity and authority context before
the matching ACCEPTED barrier. Before that barrier no Store, locator, Docker,
artifact, restore, cleanup or operational-success path is reachable. After
the barrier the only restore sequence is:

accepted admission -> Store/CAS -> durable RESTORE_BEGIN -> PROCEED -> one
stdin half-close -> remote EOF with zero trailing input -> authorised native
restore -> RESULT/finality.

The Python controller calls the unchanged canonical ControllerStore and the
unchanged persisted-locator adapter. The native agent receives a single exact
PROCEED frame, recomputes its managed commitment, authenticates the artifact
stream commitment from descriptor-based reads, and performs an atomic,
fsynced replacement. A failed or uncertain consumed transition is terminal
and is never retried as a new restore.

## Representations

Managed JSON is strict UTF-8, has no BOM, whitespace or final LF, has sorted
unique ASCII object members, uses exact escaping, booleans and bounded U32
integers, and rejects floats, nulls, duplicate members and alternate forms.
Stored managed documents add exactly one LF.

For every byte string x, LP(x) = U32-big-endian(len(x)) || x, and:

H(domain; parts) = SHA256(LP("swz-managed.v1") || LP(ASCII(domain)) ||
LP(part1) || ... || LP(partN)).

Store bytes remain the canonical insertion-ordered compact JSON document plus
one LF. Store commitment is independently:

SC(domain,B) = "sha256:v1:" || hexlower(SHA256(LP("recovery-commitment.v1") ||
LP(ASCII(domain)) || LP(B))).

StoreWire(schema,B) is exactly the managed array
["store-json.v1", schema, StrictUTF8Decode(B)]. The decoder reconstructs the
third element byte-for-byte and applies an exact retained-schema/order
validator. It never parses a Store object and reserializes it as managed JSON.

The three registered profiles are
restore-ledger-transition-data.v2, restore-begin-evidence.v2 and
swz-recovery-result.v2; their exact field orders are in backend.py and the
independent wire fixture. Tagged Store digests and bare managed digests are
different types and are never implicitly converted.

## Native boundaries

swz-supervisor owns one active generation and one listener/connection
lifecycle. swz-dispatcher and swz-bootstrap are separate executable
boundaries. swz-broker accepts only the typed post-ACCEPTED transcript.
swz-agent requires the exact PROCEED payload, owner PID, session, generation,
cookie and ACTIVE lifecycle before opening the qualified artifact.

swz-custodian starts the pinned OpenSSH ssh-agent, loads the disposable test
key only through the pinned ssh-add, and exposes a restricted proxy. The
proxy permits identities and signing for the enrolled public blob only; it
rejects all other agent messages and checks peer credentials, ancestry and
environment bindings. OpenSSH uses HostKeyAgent plus the public HostKey
file. No private key is embedded in the server or bypasses custody.

## Generation and guest proof

build.lock.json pins OpenSSH 10.5p1 and musl 1.2.5 by SHA-256. build.py
verifies every archive, applies a real zero-fuzz patch to a fresh extraction,
builds the binaries, and checks the runtime OpenSSH version marker. The
qualification harness boots a real q35 QEMU guest with software TCG when
hardware acceleration is unavailable. It requires guest-observed SELinux
enforcement, candidate policy loading, dm-verity verification, native
component execution and the pinned OpenSSH binary. Host-only probes, an empty
VM, process-existence checks and synthetic markers are not accepted.

## Evidence

The frozen identity vector, StoreWire profile bytes and accepted Run-376
metadata are kept in tests/recovery-managed/fixtures. native_unit.c
recomputes the locked identity vector independently of Python. The
qualification case registry contains no skippable mandatory security case;
provider outages are reported as QUALIFICATION_PROVIDER_HOLD, harness
failures as QUALIFICATION_HARNESS_DEFECT, and candidate failures as
CANDIDATE_DEFECT.
