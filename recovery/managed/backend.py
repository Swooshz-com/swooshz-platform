"""Managed recovery boundary primitives.

This module is deliberately small and typed around the accepted wire
contracts.  It does not provide a compatibility parser: every public record
is canonical UTF-8 JSON, every digest has an explicit domain, and every
state machine rejects an out-of-order transition.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import stat
import struct
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Sequence

MANAGED_SCHEMA = "swz-managed.v1"
STORE_MARKER = "store-json.v1"
MAX_CONTROL_PAYLOAD_BYTES = 4096
MAX_FRAME_BYTES = 65536
MAX_SESSION_FRAMES = 16
MAX_SESSION_BYTES = 1048576
SWZFRM02_MAGIC = b"SWZFRM02"
SWZFRM02_VERSION = 2
SWZFRM02_FLAGS = 0
FRAME_HEADER = struct.Struct("!8sBBBBQ32sI")
FRAME_HEADER_BYTES = FRAME_HEADER.size
DIRECTION_LOCAL_TO_REMOTE = 1
DIRECTION_REMOTE_TO_LOCAL = 2
MESSAGE_NAMES = {
    1: "BOOT",
    # ID 2 was the historical READY frame and is permanently reserved.
    3: "CHALLENGE",
    4: "EVIDENCE",
    5: "ACCEPT",
    6: "ACCEPTED",
    7: "DISCOVERY",
    8: "RESTORE_BEGIN",
    9: "PROCEED",
    10: "RESULT",
    11: "ABORT",
}
MESSAGE_BY_NAME = {name: number for number, name in MESSAGE_NAMES.items()}
COMMITMENT_PREFIX = "sha256:v1:"
MANAGED_HEX_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
STORE_COMMITMENT_RE = re.compile(r"sha256:v1:[0-9a-f]{64}\Z", re.ASCII)
TRANSITION_ID_RE = re.compile(r"restore-v2-[0-9a-f]{48}\Z", re.ASCII)
UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z",
    re.ASCII,
)
REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z", re.ASCII)
UTC6_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z\Z", re.ASCII)


@dataclass(frozen=True)
class _WireBytes:
    """A typed 32-byte value; subclasses prevent domain substitution in APIs."""

    raw: bytes
    kind: str

    def __post_init__(self) -> None:
        if type(self.raw) is not bytes or len(self.raw) != 32:
            raise ProtocolError(f"{self.kind}-length")

    @property
    def wire(self) -> str:
        return self.raw.hex()


@dataclass(frozen=True)
class Managed32(_WireBytes):
    kind: str = "managed32"


@dataclass(frozen=True)
class FrameHash32(_WireBytes):
    kind: str = "frame-hash32"


@dataclass(frozen=True)
class PlainSHA256(_WireBytes):
    kind: str = "plain-sha256"


@dataclass(frozen=True)
class RawNonce32(_WireBytes):
    kind: str = "raw-nonce32"


def _typed_hex(value: Any, cls: type[_WireBytes], label: str) -> _WireBytes:
    if isinstance(value, cls):
        return value
    if not isinstance(value, str) or MANAGED_HEX_RE.fullmatch(value) is None:
        raise ProtocolError(f"{label}-format")
    return cls(bytes.fromhex(value))


def managed32(value: Any) -> Managed32:
    return _typed_hex(value, Managed32, "managed32")  # type: ignore[return-value]


def frame_hash32(value: Any) -> FrameHash32:
    return _typed_hex(value, FrameHash32, "frame-hash32")  # type: ignore[return-value]


def plain_sha256(value: Any) -> PlainSHA256:
    return _typed_hex(value, PlainSHA256, "plain-sha256")  # type: ignore[return-value]


def raw_nonce32(value: Any) -> RawNonce32:
    return _typed_hex(value, RawNonce32, "raw-nonce32")  # type: ignore[return-value]


class BoundaryError(ValueError):
    """Base error for a rejected boundary value."""


class CanonicalJSONError(BoundaryError):
    pass


class StoreWireError(BoundaryError):
    pass


class IdentityError(BoundaryError):
    pass


class ProtocolError(BoundaryError):
    pass


class StateTransitionError(BoundaryError):
    pass


@dataclass(frozen=True)
class ManagedDigest:
    raw: bytes

    def __post_init__(self) -> None:
        if type(self.raw) is not bytes or len(self.raw) != 32:
            raise BoundaryError("managed-digest-length")

    @property
    def hex(self) -> str:
        return self.raw.hex()


@dataclass(frozen=True)
class StoreDigest:
    raw: bytes

    def __post_init__(self) -> None:
        if type(self.raw) is not bytes or len(self.raw) != 32:
            raise BoundaryError("store-digest-length")

    @property
    def text(self) -> str:
        return COMMITMENT_PREFIX + self.raw.hex()


def _strict_text(value: Any, label: str, *, max_bytes: int = MAX_CONTROL_PAYLOAD_BYTES) -> str:
    if not isinstance(value, str) or not value:
        raise CanonicalJSONError(f"{label}-text")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError as error:
        raise CanonicalJSONError(f"{label}-utf8") from error
    if len(encoded) > max_bytes:
        raise CanonicalJSONError(f"{label}-size")
    return value


def _reject_constant(value: str) -> None:
    raise CanonicalJSONError(f"json-constant:{value}")


def _managed_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    previous: str | None = None
    for key, value in pairs:
        if not isinstance(key, str) or any(ord(char) > 0x7F for char in key):
            raise CanonicalJSONError("key-ascii")
        if key in result:
            raise CanonicalJSONError("duplicate-key")
        if previous is not None and key <= previous:
            raise CanonicalJSONError("key-order")
        result[key] = value
        previous = key
    return result


def _validate_managed_tree(value: Any) -> None:
    if isinstance(value, float):
        raise CanonicalJSONError("float")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise CanonicalJSONError("key-type")
            _strict_text(key, "key")
            _validate_managed_tree(child)
    elif isinstance(value, list):
        for child in value:
            _validate_managed_tree(child)
    elif isinstance(value, str):
        try:
            value.encode("utf-8", "strict")
        except UnicodeEncodeError as error:
            raise CanonicalJSONError("string-utf8") from error
    elif value is None:
        raise CanonicalJSONError("null")
    elif type(value) not in (bool, int):
        raise CanonicalJSONError("value-type")


def managed_json(value: Any) -> bytes:
    _validate_managed_tree(value)
    try:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False,
                             separators=(",", ":"), sort_keys=True).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise CanonicalJSONError("json-encode") from error
    if len(encoded) > MAX_CONTROL_PAYLOAD_BYTES:
        raise CanonicalJSONError("json-size")
    return encoded


def parse_managed_json(payload: bytes) -> Any:
    if type(payload) is not bytes or not payload or len(payload) > MAX_CONTROL_PAYLOAD_BYTES:
        raise CanonicalJSONError("json-size")
    if payload.startswith(b"\xef\xbb\xbf") or payload.endswith(b"\n"):
        raise CanonicalJSONError("json-newline-or-bom")
    try:
        text = payload.decode("utf-8", "strict")
        value = json.loads(text, object_pairs_hook=_managed_pairs,
                           parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, CanonicalJSONError) as error:
        raise CanonicalJSONError("json-parse") from error
    if managed_json(value) != payload:
        raise CanonicalJSONError("json-noncanonical")
    return value


TRANSITION_FIELDS = (
    "schema", "version", "epoch_ref", "authority_ref", "barrier_utc",
    "barrier_commitment", "runner_commitment", "bundle_commitment",
    "image_commitment", "target_commitment", "isolation_commitment",
    "artifact_commitment", "artifact_stream_commitment", "pre_cas_ledger_digest",
)
EVIDENCE_FIELDS = (
    "schema", "epoch_ref", "transition_id", "transition_data_commitment",
    "artifact_commitment", "artifact_stream_commitment", "ledger_state",
    "record_state", "spool_previous_stage", "frame_sequence", "previous_frame_hash",
    "frame_hash", "spool_commitment", "ledger_after_digest", "durability",
)
DURABILITY_FIELDS = (
    "file_flush_verified", "readback_verified", "atomic_authority_transition",
    "directory_flush_verified",
)
RESULT_FIELDS = (
    "schema", "classification", "stage", "epoch_ref", "authority_ref", "barrier_utc",
    "ssh_endpoint_commitment", "epoch_commitment", "authority_commitment",
    "barrier_commitment", "runner_commitment", "bundle_commitment", "launcher_commitment",
    "agent_commitment", "image_commitment", "target_commitment", "isolation_commitment",
    "artifact_commitment", "artifact_stream_commitment", "transition_id",
    "pre_cas_ledger_digest", "transition_data_commitment", "consumed_record_commitment",
    "restore_begin_commitment", "process_commitment", "restore_commitment", "cleanup_commitment",
    "stdout_capture_commitment", "stderr_capture_commitment", "result_code", "restore_count",
    "exit_status", "stdin_eof", "stdout_eof", "stderr_eof", "trailing_unframed_bytes",
    "terminal_input_eof", "terminal_input_trailing_bytes", "cleanup_state",
)
STORE_PROFILES: Mapping[str, tuple[str, ...]] = MappingProxyType({
    "restore-ledger-transition-data.v2": TRANSITION_FIELDS,
    "restore-begin-evidence.v2": EVIDENCE_FIELDS,
    "swz-recovery-result.v2": RESULT_FIELDS,
})


def _store_dump(record: Mapping[str, Any]) -> bytes:
    try:
        encoded = (json.dumps(record, ensure_ascii=False, allow_nan=False,
                              separators=(",", ":"), sort_keys=False) + "\n").encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise StoreWireError("store-serialization") from error
    if len(encoded) > MAX_SESSION_BYTES:
        raise StoreWireError("store-size")
    return encoded


def _store_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise StoreWireError(f"{label}-text-invalid")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError as error:
        raise StoreWireError(f"{label}-utf8") from error
    return value


def _store_tagged(value: Any, label: str) -> str:
    if not isinstance(value, str) or STORE_COMMITMENT_RE.fullmatch(value) is None:
        raise StoreWireError(f"{label}-commitment-invalid")
    return value


def _validate_store_profile(schema_id: str, value: Mapping[str, Any]) -> None:
    fields = STORE_PROFILES.get(schema_id)
    if fields is None or tuple(value.keys()) != fields or value.get("schema") != schema_id:
        raise StoreWireError("store-schema-order-invalid")
    if schema_id == "restore-ledger-transition-data.v2":
        if type(value["version"]) is not int or value["version"] != 2:
            raise StoreWireError("store-transition-version-invalid")
        for field in ("epoch_ref", "authority_ref", "barrier_utc"):
            _store_text(value[field], field)
        for field in TRANSITION_FIELDS[5:]:
            _store_tagged(value[field], field)
        return
    if schema_id == "restore-begin-evidence.v2":
        for field in ("epoch_ref", "transition_id", "ledger_state", "record_state", "spool_previous_stage"):
            _store_text(value[field], field)
        if TRANSITION_ID_RE.fullmatch(value["transition_id"]) is None:
            raise StoreWireError("store-transition-id-invalid")
        for field in ("transition_data_commitment", "artifact_commitment", "artifact_stream_commitment",
                      "previous_frame_hash", "frame_hash", "spool_commitment", "ledger_after_digest"):
            _store_tagged(value[field], field)
        if type(value["frame_sequence"]) is not int or not 1 <= value["frame_sequence"] <= MAX_SESSION_FRAMES:
            raise StoreWireError("store-frame-sequence-invalid")
        durability = value["durability"]
        if not isinstance(durability, Mapping) or tuple(durability.keys()) != DURABILITY_FIELDS:
            raise StoreWireError("store-durability-order-invalid")
        if any(type(durability[field]) is not bool for field in DURABILITY_FIELDS) or not all(durability.values()):
            raise StoreWireError("store-durability-invalid")
        return
    for field in RESULT_FIELDS[1:]:
        if field in {"result_code", "restore_count", "exit_status"}:
            if type(value[field]) is not int or value[field] < 0:
                raise StoreWireError(f"{field}-integer-invalid")
        elif field in {"stdin_eof", "stdout_eof", "stderr_eof", "trailing_unframed_bytes",
                       "terminal_input_eof", "terminal_input_trailing_bytes"}:
            if type(value[field]) is not bool:
                raise StoreWireError(f"{field}-boolean-invalid")
        elif field in {"classification", "stage", "epoch_ref", "authority_ref", "barrier_utc", "cleanup_state"}:
            _store_text(value[field], field)
        elif field == "transition_id":
            if TRANSITION_ID_RE.fullmatch(value[field]) is None:
                raise StoreWireError("result-transition-id-invalid")
        else:
            _store_tagged(value[field], field)


def validate_retained_store_bytes(schema_id: str, store_bytes_value: bytes) -> OrderedDict[str, Any]:
    if schema_id not in STORE_PROFILES or type(store_bytes_value) is not bytes:
        raise StoreWireError("store-input-invalid")
    if not store_bytes_value.endswith(b"\n") or store_bytes_value.endswith(b"\n\n"):
        raise StoreWireError("store-newline-invalid")
    try:
        text = store_bytes_value.decode("utf-8", "strict")
        value = json.loads(text, object_pairs_hook=lambda pairs: OrderedDict(pairs),
                           parse_constant=_store_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, StoreWireError) as error:
        raise StoreWireError("store-parse") from error
    if not isinstance(value, OrderedDict):
        raise StoreWireError("store-object-invalid")
    _validate_store_profile(schema_id, value)
    if _store_dump(value) != store_bytes_value:
        raise StoreWireError("store-order-invalid")
    return value


def _store_reject_constant(value: str) -> None:
    raise StoreWireError(f"store-constant:{value}")


def store_bytes(record: Mapping[str, Any]) -> bytes:
    if not isinstance(record, Mapping) or not isinstance(record.get("schema"), str):
        raise StoreWireError("store-record-invalid")
    _validate_store_profile(record["schema"], record)
    encoded = _store_dump(record)
    validate_retained_store_bytes(record["schema"], encoded)
    return encoded


@dataclass(frozen=True)
class StoreWire:
    schema_id: str
    store_bytes: bytes

    def __post_init__(self) -> None:
        if self.schema_id not in STORE_PROFILES or type(self.store_bytes) is not bytes:
            raise StoreWireError("store-wire-input")
        validate_retained_store_bytes(self.schema_id, self.store_bytes)

    def envelope(self) -> list[Any]:
        return [STORE_MARKER, self.schema_id, self.store_bytes.decode("utf-8", "strict")]

    @classmethod
    def from_bytes(cls, schema_id: str, value: bytes) -> "StoreWire":
        return cls(schema_id, value)


def store_wire_record(schema_id: str, record: Mapping[str, Any]) -> StoreWire:
    return StoreWire(schema_id, store_bytes(record))


def encode_store_wire(schema_id: str, store_bytes_value: bytes) -> bytes:
    return managed_json(StoreWire(schema_id, store_bytes_value).envelope())


def decode_store_wire(value_or_payload: Any) -> StoreWire:
    value = parse_managed_json(value_or_payload) if type(value_or_payload) is bytes else value_or_payload
    if not isinstance(value, list) or len(value) != 3 or value[0] != STORE_MARKER or not isinstance(value[1], str) or not isinstance(value[2], str):
        raise StoreWireError("store-wire-envelope")
    try:
        store_raw = value[2].encode("utf-8", "strict")
    except UnicodeEncodeError as error:
        raise StoreWireError("store-wire-utf8") from error
    return StoreWire(value[1], store_raw)


def lp(value: bytes) -> bytes:
    if type(value) is not bytes or len(value) > 0xFFFFFFFF:
        raise BoundaryError("lp-input")
    return struct.pack("!I", len(value)) + value


def managed_hash(domain: str, *parts: bytes) -> bytes:
    if not isinstance(domain, str) or not domain or any(ord(char) > 0x7F for char in domain):
        raise IdentityError("managed-domain")
    preimage = lp(b"swz-managed.v1") + lp(domain.encode("ascii"))
    try:
        preimage += b"".join(lp(part) for part in parts)
    except BoundaryError as error:
        raise IdentityError("managed-part") from error
    return hashlib.sha256(preimage).digest()


def managed_hex(value: bytes) -> str:
    if type(value) is not bytes or len(value) != 32:
        raise BoundaryError("managed-hex-length")
    return value.hex()


def managed_digest(value: Any) -> bytes:
    if not isinstance(value, str) or MANAGED_HEX_RE.fullmatch(value) is None:
        raise BoundaryError("managed-digest-format")
    return bytes.fromhex(value)


def strict_store_digest(value: Any) -> bytes:
    if not isinstance(value, str) or STORE_COMMITMENT_RE.fullmatch(value) is None:
        raise BoundaryError("strict-store-digest-format")
    return bytes.fromhex(value[len(COMMITMENT_PREFIX):])


def store_commitment(domain: str, store_bytes_value: bytes) -> str:
    if not isinstance(domain, str) or not domain or any(ord(char) > 0x7F for char in domain):
        raise StoreWireError("store-domain-invalid")
    if type(store_bytes_value) is not bytes or len(store_bytes_value) > 0xFFFFFFFF:
        raise StoreWireError("store-bytes-invalid")
    preimage = lp(b"recovery-commitment.v1") + lp(domain.encode("ascii")) + lp(store_bytes_value)
    return COMMITMENT_PREFIX + hashlib.sha256(preimage).hexdigest()


def transition_id(store_transition_bytes: bytes) -> str:
    if type(store_transition_bytes) is not bytes or not store_transition_bytes:
        raise StoreWireError("transition-bytes-invalid")
    digest = hashlib.sha256(lp(b"restore-transition-id.v2") + lp(store_transition_bytes)).hexdigest()
    return "restore-v2-" + digest[:48]


def u8(value: int) -> bytes:
    if type(value) is not int or not 0 <= value <= 0xFF:
        raise IdentityError("u8-invalid")
    return struct.pack("!B", value)


def u16(value: int) -> bytes:
    if type(value) is not int or not 0 <= value <= 0xFFFF:
        raise IdentityError("u16-invalid")
    return struct.pack("!H", value)


def u32(value: int) -> bytes:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise IdentityError("u32-invalid")
    return struct.pack("!I", value)


def u64(value: int) -> bytes:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise IdentityError("u64-invalid")
    return struct.pack("!Q", value)


def _raw(value: Any, length: int, label: str) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise IdentityError(f"{label}-length")
    return value


def ed25519_public_blob(public_octets: bytes) -> bytes:
    key = _raw(public_octets, 32, "ed25519-public")
    return u32(11) + b"ssh-ed25519" + u32(32) + key


def validate_uuid_text(value: str) -> bytes:
    if not isinstance(value, str) or UUID_RE.fullmatch(value) is None:
        raise IdentityError("uuid-text")
    raw = bytes.fromhex(value.replace("-", ""))
    if raw == b"\0" * 16 or raw[6] >> 4 != 4 or raw[8] & 0xC0 != 0x80:
        raise IdentityError("uuid-version-variant")
    if str(uuid.UUID(bytes=raw)) != value:
        raise IdentityError("uuid-roundtrip")
    return raw


def literal_endpoint_record(endpoint_ipv4: str, port: int = 22222) -> bytes:
    if not isinstance(endpoint_ipv4, str):
        raise IdentityError("endpoint-text")
    try:
        address = ipaddress.IPv4Address(endpoint_ipv4)
    except ValueError as error:
        raise IdentityError("endpoint-text") from error
    if str(address) != endpoint_ipv4 or address.is_unspecified or address.is_multicast:
        raise IdentityError("endpoint-nonliteral")
    if port != 22222:
        raise IdentityError("endpoint-port")
    return u8(1) + u8(1) + u16(2) + address.packed + u16(port)


def installation_identity(
    installation_uuid_raw16: bytes,
    admission_root_public_blob51: bytes,
    recovery_host_public_blob51: bytes,
    controller_public_blob51: bytes,
    literal_endpoint_raw10: bytes,
    uidgid_map_raw: bytes,
    target_policy_commitment_raw32: bytes,
) -> bytes:
    return managed_hash(
        "installation.v1",
        _raw(installation_uuid_raw16, 16, "installation-uuid"),
        _raw(admission_root_public_blob51, 51, "admission-key-blob"),
        _raw(recovery_host_public_blob51, 51, "host-key-blob"),
        _raw(controller_public_blob51, 51, "controller-key-blob"),
        _raw(literal_endpoint_raw10, 10, "literal-endpoint"),
        uidgid_map_raw,
        _raw(target_policy_commitment_raw32, 32, "target-policy"),
    )


def endpoint_template_identity(installation_raw32: bytes, literal_endpoint_raw10: bytes) -> bytes:
    return managed_hash("endpoint-template.v1", _raw(installation_raw32, 32, "installation"), _raw(literal_endpoint_raw10, 10, "literal-endpoint"))


def endpoint_actual_identity(endpoint_template_raw32: bytes, boot_uuid_raw16: bytes, listener_netns_device: int, listener_netns_inode: int) -> bytes:
    return managed_hash("endpoint-actual.v1", _raw(endpoint_template_raw32, 32, "endpoint-template"), _raw(boot_uuid_raw16, 16, "boot-uuid"), u64(listener_netns_device), u64(listener_netns_inode))


def activation_identity(installation_raw32: bytes, generation_raw32: bytes, endpoint_actual_raw32: bytes, boot_uuid_raw16: bytes, activation_serial: int, activation_random32: bytes) -> bytes:
    return managed_hash("activation.v1", _raw(installation_raw32, 32, "installation"), _raw(generation_raw32, 32, "generation"), _raw(endpoint_actual_raw32, 32, "endpoint-actual"), _raw(boot_uuid_raw16, 16, "boot-uuid"), u64(activation_serial), _raw(activation_random32, 32, "activation-random"))


MANAGED_DOMAINS = (
    "admission-root.v1", "host-public-key.v1", "target-policy.v1", "dependency-closure.v1",
    "invocation-policy.v1", "execution-inventory.v1", "build-record.v1", "fd-inventory.v1",
    "runtime-argv.v1", "runtime-limits.v1", "policy.v1", "auth-account-config.v1", "n-local.v1",
    "installation.v1", "endpoint-template.v1", "endpoint-actual.v1", "launch-base.v1",
    "openssh-closure.v1", "component-supervisor.v1", "component-custodian.v1", "component-dispatcher.v1",
    "component-bootstrap.v1", "component-broker.v1", "component-agent.v1", "dm-verity.v1",
    "qualification-subject.v1", "build-qualification.v1", "generation.v1", "generation-manifest.v1",
    "generation-approval.v1", "activation.v1", "connection.v1", "request-context.v1",
    "authority-context.v1", "challenge.v1", "runtime.v1", "evidence.v1", "accept.v1",
    "accepted-session.v1", "accepted-receipt.v1", "discovery.v1", "proceed.v1", "result.v1",
)

IDENTITY_FORMULA_MAP: Mapping[str, str] = MappingProxyType({
    "AR": "admission-root.v1 = H(admission-root PublicKeyBlob)",
    "HK": "host-public-key.v1 = H(recovery-host PublicKeyBlob)",
    "TP": "target-policy.v1 = H(J(qualified target-policy))",
    "DI": "dependency-closure.v1 = H(dependency FileInventory)",
    "IP": "invocation-policy.v1 = H(InvocationRecord)",
    "X": "execution-inventory.v1 = H(complete execution FileInventory)",
    "B": "build-record.v1 = H(J(qualified build.lock))",
    "FD": "fd-inventory.v1 = H(FdInventory)",
    "AV": "runtime-argv.v1 = H(Vector(InvocationRecord...), role-sorted)",
    "LM": "runtime-limits.v1 = H(accepted numeric-limit inventory)",
    "P": "policy.v1 = H(raw source-policy digest, raw compiled-policy digest, LabelInventory, J(kernel-enforcement profile))",
    "Q": "auth-account-config.v1 = H(complete auth/account/config FileInventory)",
    "NC": "n-local.v1 = H(raw N_local[32])",
    "I": "installation.v1 = H(installation UUID raw16, admission-root blob51, host blob51, controller blob51, raw LER, raw UIDGIDMap, TP)",
    "ET": "endpoint-template.v1 = H(I, same raw LER)",
    "EA": "endpoint-actual.v1 = H(ET, boot UUID raw16, listener-netns U64(device), U64(inode))",
    "A": "activation.v1 = H(I,G,EA,boot UUID raw16,U64(activation serial),activation random[32])",
    "C": "connection.v1 = H(A,U64(connection serial),U64(socket cookie),local SocketAddress,peer SocketAddress,NamespaceInventory,ChildInventory,U64(connection cgroup id))",
    "RQ": "request-context.v1 = H(J(RequestRecord))",
    "U": "authority-context.v1 = H(ASCII(github),ASCII(Swooshz-com/swooshz-platform),U32(105),authority-ref,epoch-ref,barrier-UTC,ASCII(recovery-validation),RQ)",
    "CH": "challenge.v1 = H(BOOT frame hash[32],C,A,raw N_local[32],raw N_remote[32])",
    "EC": "evidence.v1 = H(raw header N_local[32],CHALLENGE frame hash[32],J(EvidenceBodyWithoutCommitment))",
    "AC": "accept.v1 = H(raw header N_local[32],J(AcceptBodyWithoutCommitment))",
    "S": "accepted-session.v1 = H(I,EA,A,G,C,raw N_local[32],U,EC,AC)",
    "REC": "accepted-receipt.v1 = H(S,ACCEPT frame hash[32],C,A)",
    "DC": "discovery.v1 = H(S,U64(execution row id),decoded filename octets,image commitment,target commitment,isolation commitment,artifact commitment,artifact-stream commitment)",
    "PC": "proceed.v1 = H(S,transition-ID ASCII,transition-data commitment[32],RESTORE_BEGIN frame hash[32])",
    "RC": "result.v1 = H(S,transition-ID ASCII,PC,exact canonical result-record bytes)",
})
IDENTITY_GRAPH: Mapping[str, Sequence[str]] = {
    "raw-endpoint": ("installation",), "installation": ("endpoint-template",),
    "endpoint-template": ("endpoint-actual",), "endpoint-actual": ("activation",),
    "qualification-subject": ("build-qualification", "generation"),
    "build-qualification": ("generation",), "generation": ("generation-manifest", "generation-approval", "activation"),
    "activation": ("connection", "challenge", "accepted-session"), "connection": ("challenge",),
    "challenge": ("evidence",), "evidence": ("accept", "accepted-session"),
    "accept": ("accepted-session",), "accepted-session": ("accepted-receipt", "discovery", "proceed", "result"),
    "discovery": ("proceed",), "proceed": ("result",), "result": (),
}


def assert_domain_uniqueness() -> None:
    if len(MANAGED_DOMAINS) != 43 or len(set(MANAGED_DOMAINS)) != 43:
        raise IdentityError("managed-domain-uniqueness")


def assert_identity_graph_acyclic(graph: Mapping[str, Sequence[str]] = IDENTITY_GRAPH) -> None:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visiting:
            raise IdentityError("identity-graph-cycle")
        if node in visited:
            return
        visiting.add(node)
        for child in graph.get(node, ()):
            visit(child)
        visiting.remove(node)
        visited.add(node)

    for node in graph:
        visit(node)


def reject_self_reference(graph: Mapping[str, Sequence[str]]) -> None:
    if any(node in children for node, children in graph.items()):
        raise IdentityError("identity-self-reference")
    assert_identity_graph_acyclic(graph)


def canonical_filename_octets(value: str) -> bytes:
    try:
        _strict_text(value, "filename", max_bytes=512)
        raw = value.encode("utf-8", "strict")
    except (CanonicalJSONError, UnicodeEncodeError) as error:
        raise IdentityError("filename-text") from error
    if not value or value in {".", ".."} or b"/" in raw or b"\\" in raw or b"\0" in raw:
        raise IdentityError("filename-path")
    if any(byte < 0x20 or byte == 0x7F for byte in raw):
        raise IdentityError("filename-control")
    return raw


BOOT_FIELDS = (
    "epoch_ref", "authority_ref", "barrier_utc", "installation",
    "endpoint_template", "generation", "launch_base", "authority_context",
    "request_context",
)
CHALLENGE_FIELDS = (
    "activation", "connection", "N_remote", "boot_frame_hash",
    "accepted_boottime_ns",
)
EVIDENCE_FIELDS_MANAGED = (
    "installation", "endpoint_template", "actual_endpoint", "activation",
    "generation", "launch_base", "policy", "verity", "openssh",
    "host_public_key", "auth_account_config", "dispatcher", "bootstrap",
    "custodian", "broker", "agent", "build_qualification",
    "accepted_connection", "n_local_commitment", "authority_context",
    "request_context", "challenge_commitment", "runtime_record",
    "evidence_commitment",
)
RUNTIME_FIELDS = (
    "boot_id", "listener_netns_dev", "listener_netns_ino",
    "accepted_socket_cookie", "chain_userns_dev", "chain_userns_ino",
    "chain_mountns_dev", "chain_mountns_ino", "chain_pidns_dev",
    "chain_pidns_ino", "chain_netns_dev", "chain_netns_ino",
    "connection_cgroup_id", "owner_start_time", "session_start_time",
    "selinux_enforcing", "immutable_root", "writable_closure_mount_count",
    "host_recovery_capability_mask", "channel_latch_consumed",
    "fd_inventory_commitment", "argv_commitment", "limits_commitment",
)
ACCEPT_FIELDS = (
    "connection", "generation", "authority_context", "evidence_commitment",
    "evidence_frame_hash", "accept_commitment",
)
ACCEPTED_FIELDS = (
    "connection", "activation", "accept_commitment", "accepted_session",
    "receipt_commitment",
)
MESSAGE_DIRECTIONS: Mapping[str, tuple[int, ...]] = MappingProxyType({
    "BOOT": (DIRECTION_LOCAL_TO_REMOTE,),
    "CHALLENGE": (DIRECTION_REMOTE_TO_LOCAL,),
    "EVIDENCE": (DIRECTION_REMOTE_TO_LOCAL,),
    "ACCEPT": (DIRECTION_LOCAL_TO_REMOTE,),
    "ACCEPTED": (DIRECTION_REMOTE_TO_LOCAL,),
    "DISCOVERY": (DIRECTION_REMOTE_TO_LOCAL,),
    "RESTORE_BEGIN": (DIRECTION_LOCAL_TO_REMOTE,),
    "PROCEED": (DIRECTION_LOCAL_TO_REMOTE,),
    "RESULT": (DIRECTION_REMOTE_TO_LOCAL,),
    "ABORT": (DIRECTION_LOCAL_TO_REMOTE, DIRECTION_REMOTE_TO_LOCAL),
})


def _hex32(value: bytes, label: str) -> str:
    try:
        return managed_hex(_raw(value, 32, label))
    except IdentityError as error:
        raise ProtocolError(f"{label}-digest") from error


def _wire_managed(value: Any, label: str) -> str:
    if isinstance(value, _WireBytes) and not isinstance(value, Managed32):
        raise ProtocolError(f"{label}-wrong-domain")
    if type(value) is bytes:
        return Managed32(value).wire
    return managed32(value).wire


def _wire_frame_hash(value: Any, label: str) -> str:
    if isinstance(value, _WireBytes) and not isinstance(value, FrameHash32):
        raise ProtocolError(f"{label}-wrong-domain")
    if type(value) is bytes:
        return FrameHash32(value).wire
    return frame_hash32(value).wire


def _wire_nonce(value: Any, label: str) -> str:
    if isinstance(value, _WireBytes) and not isinstance(value, RawNonce32):
        raise ProtocolError(f"{label}-wrong-domain")
    if type(value) is bytes:
        return RawNonce32(value).wire
    return raw_nonce32(value).wire


def _wire_plain(value: Any, label: str) -> str:
    if isinstance(value, _WireBytes) and not isinstance(value, PlainSHA256):
        raise ProtocolError(f"{label}-wrong-domain")
    return plain_sha256(value).wire


def _wire_previous(value: bytes | str) -> str:
    if type(value) is bytes:
        return _wire_frame_hash(value, "previous-frame")
    return _wire_frame_hash(value, "previous-frame")


def _protocol_text(value: Any, label: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or any(ord(char) > 0x7F for char in value):
        raise ProtocolError(f"{label}-ascii")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise ProtocolError(f"{label}-format")
    return value


def validate_ref(value: Any) -> str:
    return _protocol_text(value, "ref", REF_RE)


def validate_utc6(value: Any) -> str:
    return _protocol_text(value, "utc6", UTC6_RE)


def validate_u32_json(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ProtocolError("u32-json")
    return value


def validate_u64_json(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"(?:0|[1-9][0-9]{0,19})", value, re.ASCII):
        raise ProtocolError("u64-json")
    if int(value) > 0xFFFFFFFFFFFFFFFF:
        raise ProtocolError("u64-json-range")
    return value


def _validate_runtime_record(value: Any) -> None:
    if not isinstance(value, list) or len(value) != len(RUNTIME_FIELDS):
        raise ProtocolError("runtime-record-shape")
    validate_uuid_text(value[0])
    for index in range(1, 15):
        validate_u64_json(value[index])
    if type(value[15]) is not bool or type(value[16]) is not bool:
        raise ProtocolError("runtime-record-bool")
    if value[15] is not True or value[16] is not True:
        raise ProtocolError("runtime-record-enforcement")
    validate_u32_json(value[17])
    if value[17] != 0:
        raise ProtocolError("runtime-record-writable-mount")
    validate_u64_json(value[18])
    if value[18] != "0":
        raise ProtocolError("runtime-record-capability")
    if type(value[19]) is not bool or value[19] is not True:
        raise ProtocolError("runtime-record-latch")
    for index in range(20, 23):
        _wire_managed(value[index], RUNTIME_FIELDS[index])


def validate_message_payload(value: Any, *, expected_message: str | None = None) -> list[Any]:
    if not isinstance(value, list) or len(value) < 4:
        raise ProtocolError("message-array")
    message = value[0]
    if message not in MESSAGE_BY_NAME or message == "ABORT" and value[1] != 2:
        raise ProtocolError("message-name")
    if expected_message is not None and message != expected_message:
        raise ProtocolError("message-name-mismatch")
    if value[1] != 2 or value[2] != MANAGED_SCHEMA:
        raise ProtocolError("message-prefix")
    _wire_frame_hash(value[3], "previous-frame")
    fields = value[4:]
    if message == "BOOT":
        if len(fields) != len(BOOT_FIELDS):
            raise ProtocolError("boot-arity")
        validate_ref(fields[0]); validate_ref(fields[1]); validate_utc6(fields[2])
        for index, field in enumerate(fields[3:], 3):
            _wire_managed(field, BOOT_FIELDS[index])
    elif message == "CHALLENGE":
        if len(fields) != len(CHALLENGE_FIELDS):
            raise ProtocolError("challenge-arity")
        _wire_managed(fields[0], "activation"); _wire_managed(fields[1], "connection")
        _wire_nonce(fields[2], "N_remote"); _wire_frame_hash(fields[3], "boot-frame")
        validate_u64_json(fields[4])
    elif message == "EVIDENCE":
        if len(fields) != len(EVIDENCE_FIELDS_MANAGED):
            raise ProtocolError("evidence-arity")
        for index, value in enumerate(fields):
            if EVIDENCE_FIELDS_MANAGED[index] == "runtime_record":
                _validate_runtime_record(value)
            else:
                _wire_managed(value, EVIDENCE_FIELDS_MANAGED[index])
    elif message == "ACCEPT":
        if len(fields) != len(ACCEPT_FIELDS):
            raise ProtocolError("accept-arity")
        _wire_managed(fields[0], "connection"); _wire_managed(fields[1], "generation")
        _wire_managed(fields[2], "authority-context"); _wire_managed(fields[3], "evidence")
        _wire_frame_hash(fields[4], "evidence-frame"); _wire_managed(fields[5], "accept")
    elif message == "ACCEPTED":
        if len(fields) != len(ACCEPTED_FIELDS):
            raise ProtocolError("accepted-arity")
        for index, field in enumerate(fields):
            _wire_managed(field, ACCEPTED_FIELDS[index])
    elif message == "DISCOVERY":
        if len(fields) != 9:
            raise ProtocolError("discovery-arity")
        _wire_managed(fields[0], "session")
        validate_u64_json(fields[1])
        _protocol_text(fields[2], "filename-base64")
        for index, field in enumerate(fields[3:8]):
            _protocol_text(field, f"discovery-commitment-{index}", STORE_COMMITMENT_RE)
        _wire_managed(fields[8], "discovery-commitment")
    elif message == "RESTORE_BEGIN":
        if len(fields) != 5 or not isinstance(fields[2], list) or not isinstance(fields[3], list) or not isinstance(fields[4], str):
            raise ProtocolError("restore-begin-shape")
        _wire_frame_hash(fields[0], "discovery-frame"); _wire_managed(fields[1], "session")
        decode_store_wire(fields[2]); decode_store_wire(fields[3]); _protocol_text(fields[4], "consumed-record", STORE_COMMITMENT_RE)
    elif message == "PROCEED":
        if len(fields) != 5:
            raise ProtocolError("proceed-arity")
        _wire_managed(fields[0], "session")
        _protocol_text(fields[1], "transition-id", TRANSITION_ID_RE)
        _protocol_text(fields[2], "transition-commitment", STORE_COMMITMENT_RE)
        _wire_frame_hash(fields[3], "restore-begin-frame-repeat"); _wire_managed(fields[4], "proceed")
    elif message == "RESULT":
        if len(fields) != 5 or not isinstance(fields[3], list):
            raise ProtocolError("result-shape")
        _wire_managed(fields[0], "session")
        _protocol_text(fields[1], "transition-id", TRANSITION_ID_RE); _wire_managed(fields[2], "proceed")
        decode_store_wire(fields[3]); _wire_managed(fields[4], "result")
    elif message == "ABORT":
        if len(fields) != 4:
            raise ProtocolError("abort-arity")
        _protocol_text(fields[0], "abort-code", re.compile(r"[A-Z][A-Z0-9_-]{0,63}\Z", re.ASCII))
        _protocol_text(fields[1], "abort-stage", re.compile(r"[A-Z][A-Z0-9_-]{0,63}\Z", re.ASCII))
        _wire_managed(fields[2], "abort-evidence"); _wire_managed(fields[3], "abort-commitment")
    return value


def make_message(message: str, previous_frame_hash: bytes | str, fields: Sequence[Any]) -> bytes:
    if message not in MESSAGE_BY_NAME:
        raise ProtocolError("message-name")
    value = [message, 2, MANAGED_SCHEMA, _wire_previous(previous_frame_hash), *fields]
    validate_message_payload(value, expected_message=message)
    return managed_json(value)


def build_boot(previous_frame_hash: bytes | str, epoch_ref: str, authority_ref: str,
               barrier_utc: str, installation: Any, endpoint_template: Any,
               generation: Any, launch_base: Any, authority_context: Any,
               request_context: Any) -> bytes:
    return make_message("BOOT", previous_frame_hash, [
        epoch_ref, authority_ref, barrier_utc, installation, endpoint_template,
        generation, launch_base, authority_context, request_context,
    ])


def build_challenge(previous_frame_hash: bytes | str, activation: Any, connection: Any,
                    n_remote: Any, boot_frame_hash: Any,
                    accepted_boottime_ns: str) -> bytes:
    return make_message("CHALLENGE", previous_frame_hash,
                        [activation, connection, _wire_nonce(n_remote, "N_remote"),
                         _wire_frame_hash(boot_frame_hash, "boot-frame"),
                         accepted_boottime_ns])


def build_evidence(previous_frame_hash: bytes | str, fields: Sequence[Any]) -> bytes:
    return make_message("EVIDENCE", previous_frame_hash, fields)


def build_accept(previous_frame_hash: bytes | str, fields: Sequence[Any]) -> bytes:
    return make_message("ACCEPT", previous_frame_hash, fields)


def build_accepted(previous_frame_hash: bytes | str, fields: Sequence[Any]) -> bytes:
    return make_message("ACCEPTED", previous_frame_hash, fields)


def wire_kat_frames(n_local: bytes | None = None, *, session: bytes | None = None,
                    connection: bytes | None = None) -> tuple[bytes, ...]:
    """Return an independent, deterministic five-frame admission KAT.

    Native code carries its own literal payloads.  This helper is only used by
    the qualification harness to compare the complete encoded bytes and
    hashes after both implementations have produced them.
    """
    n_local = bytes(range(32)) if n_local is None else _raw(n_local, 32, "n-local")
    n_remote = bytes(range(32, 64))
    installation = bytes.fromhex("01" * 32)
    endpoint_template = bytes.fromhex("02" * 32)
    endpoint_actual = bytes.fromhex("03" * 32)
    activation = bytes.fromhex("07" * 32)
    generation = bytes.fromhex("03" * 32)
    connection = bytes.fromhex("08" * 32) if connection is None else _raw(connection, 32, "connection")
    launch_base = bytes.fromhex("04" * 32)
    policy = bytes.fromhex("09" * 32)
    verity = bytes.fromhex("0a" * 32)
    openssh = bytes.fromhex("0b" * 32)
    host_public_key = bytes.fromhex("0c" * 32)
    auth_account_config = bytes.fromhex("0d" * 32)
    supervisor = bytes.fromhex("0e" * 32)
    custodian = bytes.fromhex("0f" * 32)
    dispatcher = bytes.fromhex("10" * 32)
    bootstrap = bytes.fromhex("11" * 32)
    broker = bytes.fromhex("12" * 32)
    agent = bytes.fromhex("13" * 32)
    build_qualification = bytes.fromhex("14" * 32)
    accepted_connection = connection
    authority_context = bytes.fromhex("05" * 32)
    request_context = bytes.fromhex("06" * 32)
    accepted_session = bytes.fromhex("15" * 32) if session is None else _raw(session, 32, "session")
    runtime_commitment = bytes.fromhex("ab" * 32)
    fd_commitment = bytes.fromhex("17" * 32)
    limits_commitment = bytes.fromhex("18" * 32)
    boot = build_boot("0" * 64, "epoch-qualified-001", "authority-qualified-001",
                      "2026-09-07T00:00:00.000000Z", installation.hex(),
                      endpoint_template.hex(), generation.hex(), launch_base.hex(),
                      authority_context.hex(), request_context.hex())
    boot_frame = build_frame(DIRECTION_LOCAL_TO_REMOTE, "BOOT", 0, n_local, boot)
    boot_hash = frame_hash(boot_frame)
    challenge_commitment = managed_hash(
        "challenge.v1", boot_hash, connection, activation, n_local, n_remote)
    challenge = build_challenge(boot_hash, activation.hex(), connection.hex(), n_remote,
                                boot_hash, "123456789")
    challenge_frame = build_frame(DIRECTION_REMOTE_TO_LOCAL, "CHALLENGE", 1,
                                  n_local, challenge)
    evidence_fields: list[Any] = [
        installation.hex(), endpoint_template.hex(), endpoint_actual.hex(), activation.hex(),
        generation.hex(), launch_base.hex(), policy.hex(), verity.hex(), openssh.hex(), host_public_key.hex(),
        auth_account_config.hex(), supervisor.hex(), bootstrap.hex(), custodian.hex(), broker.hex(), agent.hex(),
        build_qualification.hex(), accepted_connection.hex(), runtime_commitment.hex(), authority_context.hex(),
        request_context.hex(), challenge_commitment.hex(), [
            "12345678-1234-4234-8234-123456789abc",
            "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11",
            "12", "13", "14", True, True, 0, "0", True, runtime_commitment.hex(),
            fd_commitment.hex(), limits_commitment.hex(),
        ], runtime_commitment,
    ]
    evidence_fields[-1] = managed_hash(
        "evidence.v1", n_local, frame_hash(challenge_frame),
        managed_json(evidence_fields[:-1])).hex()
    evidence = build_evidence(frame_hash(challenge_frame), evidence_fields)
    evidence_frame = build_frame(DIRECTION_REMOTE_TO_LOCAL, "EVIDENCE", 2,
                                 n_local, evidence)
    accept_without_commitment = [
        connection.hex(), generation.hex(), authority_context.hex(), evidence_fields[-1],
        frame_hash(evidence_frame).hex(),
    ]
    accept_commitment = managed_hash(
        "accept.v1", n_local, managed_json(accept_without_commitment)).hex()
    accept = build_accept(frame_hash(evidence_frame),
                          [*accept_without_commitment, accept_commitment])
    accept_frame = build_frame(DIRECTION_LOCAL_TO_REMOTE, "ACCEPT", 3, n_local,
                               accept)
    accepted = build_accepted(frame_hash(accept_frame), [
        connection.hex(), activation.hex(), accept_commitment, accepted_session.hex(),
        runtime_commitment.hex(),
    ])
    accepted_frame = build_frame(DIRECTION_REMOTE_TO_LOCAL, "ACCEPTED", 4,
                                 n_local, accepted)
    return boot_frame, challenge_frame, evidence_frame, accept_frame, accepted_frame


def build_restore_begin(session_raw32: bytes, discovery_frame_hash_raw32: bytes, transition_wire: StoreWire, evidence_wire: StoreWire, consumed_record_commitment: str) -> bytes:
    if transition_wire.schema_id != "restore-ledger-transition-data.v2" or evidence_wire.schema_id != "restore-begin-evidence.v2":
        raise ProtocolError("restore-begin-store-schema")
    strict_store_digest(consumed_record_commitment)
    discovery_hash = _wire_frame_hash(discovery_frame_hash_raw32, "discovery-frame")
    return managed_json(["RESTORE_BEGIN", 2, MANAGED_SCHEMA,
        discovery_hash, discovery_hash, _hex32(session_raw32, "session"),
        transition_wire.envelope(), evidence_wire.envelope(),
        consumed_record_commitment])


def build_proceed(session_raw32: bytes, transition_identifier: str, transition_data_commitment: str, restore_begin_frame_hash_raw32: bytes) -> tuple[bytes, bytes]:
    if not isinstance(transition_identifier, str) or TRANSITION_ID_RE.fullmatch(transition_identifier) is None:
        raise ProtocolError("transition-id-invalid")
    transition_digest = strict_store_digest(transition_data_commitment)
    frame_raw = _raw(restore_begin_frame_hash_raw32, 32, "restore-begin-frame")
    session = _raw(session_raw32, 32, "session")
    proceed = managed_hash("proceed.v1", session, transition_identifier.encode("ascii"), transition_digest, frame_raw)
    return managed_json(["PROCEED", 2, MANAGED_SCHEMA, frame_raw.hex(), session.hex(), transition_identifier, transition_data_commitment, frame_raw.hex(), proceed.hex()]), proceed


def build_result(session_raw32: bytes, transition_identifier: str, proceed_frame_hash_raw32: bytes, pc_raw32: bytes, result_wire: StoreWire) -> tuple[bytes, bytes]:
    if not isinstance(transition_identifier, str) or TRANSITION_ID_RE.fullmatch(transition_identifier) is None or result_wire.schema_id != "swz-recovery-result.v2":
        raise ProtocolError("result-input")
    session = _raw(session_raw32, 32, "session")
    proceed_hash = _raw(proceed_frame_hash_raw32, 32, "proceed-frame")
    pc = _raw(pc_raw32, 32, "proceed")
    result_commitment = managed_hash("result.v1", session, transition_identifier.encode("ascii"), pc, result_wire.store_bytes)
    return managed_json(["RESULT", 2, MANAGED_SCHEMA, proceed_hash.hex(), session.hex(), transition_identifier, pc.hex(), result_wire.envelope(), result_commitment.hex()]), result_commitment


def build_discovery(session_raw32: bytes, execution_row_id: int, artifact_filename: str, image_commitment: str, target_commitment: str, isolation_commitment: str, artifact_commitment: str, artifact_stream_commitment: str, previous_frame_hash_raw32: bytes | None = None) -> tuple[bytes, bytes]:
    if type(execution_row_id) is not int or not 0 < execution_row_id <= 0xFFFFFFFFFFFFFFFF:
        raise ProtocolError("execution-row-id-invalid")
    raw_filename = canonical_filename_octets(artifact_filename)
    commitments = tuple(strict_store_digest(value) for value in (image_commitment, target_commitment, isolation_commitment, artifact_commitment, artifact_stream_commitment))
    session = _raw(session_raw32, 32, "session")
    discovery = managed_hash("discovery.v1", session, u64(execution_row_id), raw_filename, *commitments)
    encoded_filename = base64.urlsafe_b64encode(raw_filename).rstrip(b"=").decode("ascii")
    previous = "0" * 64 if previous_frame_hash_raw32 is None else _wire_frame_hash(previous_frame_hash_raw32, "previous-frame")
    return managed_json(["DISCOVERY", 2, MANAGED_SCHEMA, previous, session.hex(), str(execution_row_id), encoded_filename, image_commitment, target_commitment, isolation_commitment, artifact_commitment, artifact_stream_commitment, discovery.hex()]), discovery


@dataclass(frozen=True)
class Frame:
    direction: int
    message: str
    sequence: int
    n_local: bytes
    payload: bytes
    raw: bytes

    @property
    def nonce(self) -> bytes:
        """Compatibility-free name for callers migrating to the fixed N_local field."""
        return self.n_local


def frame_hash(frame_bytes: bytes) -> bytes:
    if type(frame_bytes) is not bytes or not FRAME_HEADER_BYTES <= len(frame_bytes) <= MAX_FRAME_BYTES:
        raise ProtocolError("frame-hash-size")
    return hashlib.sha256(frame_bytes).digest()


def build_frame(direction: int, message_name: str, sequence: int, n_local: bytes, payload: bytes) -> bytes:
    if direction not in (DIRECTION_LOCAL_TO_REMOTE, DIRECTION_REMOTE_TO_LOCAL) or message_name not in MESSAGE_BY_NAME:
        raise ProtocolError("frame-route")
    if type(sequence) is not int or not 0 <= sequence < MAX_SESSION_FRAMES:
        raise ProtocolError("frame-sequence")
    n_local = _raw(n_local, 32, "n-local")
    if type(payload) is not bytes or not payload or len(payload) > MAX_CONTROL_PAYLOAD_BYTES:
        raise ProtocolError("frame-payload")
    try:
        parsed = parse_managed_json(payload)
        validate_message_payload(parsed, expected_message=message_name)
        if (sequence == 0 and parsed[3] != "0" * 64) or (sequence > 0 and parsed[3] == "0" * 64):
            raise ProtocolError("frame-predecessor-sequence")
    except BoundaryError as error:
        raise ProtocolError("frame-payload-message") from error
    if direction not in MESSAGE_DIRECTIONS[message_name]:
        raise ProtocolError("frame-direction")
    if FRAME_HEADER_BYTES + len(payload) > MAX_FRAME_BYTES:
        raise ProtocolError("frame-size")
    return FRAME_HEADER.pack(SWZFRM02_MAGIC, SWZFRM02_VERSION, direction,
                             MESSAGE_BY_NAME[message_name], SWZFRM02_FLAGS,
                             sequence, n_local, len(payload)) + payload


def decode_frame(frame_bytes: bytes, *, expected_n_local: bytes | None = None,
                 previous_frame: bytes | None = None,
                 expected_direction: int | None = None,
                 expected_message: str | None = None,
                 expected_sequence: int | None = None) -> Frame:
    if type(frame_bytes) is not bytes or len(frame_bytes) < FRAME_HEADER_BYTES:
        raise ProtocolError("frame-too-short")
    magic, version, direction, message_id, flags, sequence, n_local, payload_length = FRAME_HEADER.unpack(frame_bytes[:FRAME_HEADER_BYTES])
    if magic != SWZFRM02_MAGIC or version != SWZFRM02_VERSION or flags != SWZFRM02_FLAGS:
        raise ProtocolError("frame-header")
    if direction not in (DIRECTION_LOCAL_TO_REMOTE, DIRECTION_REMOTE_TO_LOCAL) or message_id not in MESSAGE_NAMES:
        raise ProtocolError("frame-route")
    if not 0 <= sequence < MAX_SESSION_FRAMES or payload_length > MAX_CONTROL_PAYLOAD_BYTES:
        raise ProtocolError("frame-limits")
    if len(frame_bytes) != FRAME_HEADER_BYTES + payload_length or payload_length == 0:
        raise ProtocolError("frame-trailing")
    if expected_n_local is not None and n_local != _raw(expected_n_local, 32, "expected-n-local"):
        raise ProtocolError("n-local-mismatch")
    payload = frame_bytes[FRAME_HEADER_BYTES:]
    parsed = parse_managed_json(payload)
    message = MESSAGE_NAMES[message_id]
    validate_message_payload(parsed, expected_message=message)
    if expected_message is not None and message != expected_message:
        raise ProtocolError("message-mismatch")
    if expected_direction is not None and direction != expected_direction:
        raise ProtocolError("direction-mismatch")
    if expected_sequence is not None and sequence != expected_sequence:
        raise ProtocolError("sequence-mismatch")
    if previous_frame is not None:
        previous_hash = frame_hash(_raw(previous_frame, len(previous_frame), "previous-frame"))
        if parsed[3] != previous_hash.hex():
            raise ProtocolError("previous-frame-mismatch")
    return Frame(direction, message, sequence, n_local, payload, bytes(frame_bytes))


class FrameSession:
    """A mechanical transcript gate for the single shared sequence/hash chain."""

    def __init__(self, n_local: bytes) -> None:
        self.n_local = _raw(n_local, 32, "n-local")
        self.next_sequence = 0
        self.previous: bytes | None = None

    def accept(self, frame_bytes: bytes, *, direction: int, message: str) -> Frame:
        frame = decode_frame(frame_bytes, expected_n_local=self.n_local,
                             previous_frame=self.previous,
                             expected_direction=direction,
                             expected_message=message,
                             expected_sequence=self.next_sequence)
        self.previous = frame.raw
        self.next_sequence += 1
        return frame


RESULT_CONTEXT_BIND_MAGIC = b"SWZRCB01"
RESULT_CONTEXT_FINAL_MAGIC = b"SWZRCF01"
RESULT_CONTEXT_VERSION = 1
RESULT_CONTEXT_BIND_KIND = 1
RESULT_CONTEXT_FINAL_KIND = 2
RESULT_CONTEXT_BIND_PAYLOAD_MAX_BYTES = 2048
RESULT_CONTEXT_FINAL_PAYLOAD_MAX_BYTES = 10144
RESULT_CONTEXT_CAPTURE_MAX_BYTES = 4096
RESULT_CONTEXT_COMBINED_PAYLOAD_MAX_BYTES = 12192
RESULT_CONTEXT_STREAM_MAX_BYTES = 12288
RESULT_CONTEXT_TRANSITION_ID_BYTES = 59
BIND_COMMITMENT_FIELDS = (
    "ssh_endpoint", "epoch", "authority", "barrier", "runner", "bundle",
    "launcher", "agent", "image", "target", "isolation", "artifact",
    "artifact_stream", "pre_cas_ledger", "transition_data",
    "consumed_record", "restore_begin",
)


@dataclass(frozen=True)
class ResultContextSourceDescriptor:
    dev: int
    ino: int
    size: int
    mode: int
    uid: int
    gid: int
    nlink: int
    offset: int
    content_sha256: bytes
    artifact_stream_digest: bytes

    def __post_init__(self) -> None:
        for label, value, upper in (
            ("dev", self.dev, 0xFFFFFFFFFFFFFFFF),
            ("ino", self.ino, 0xFFFFFFFFFFFFFFFF),
            ("size", self.size, 0xFFFFFFFFFFFFFFFF),
            ("mode", self.mode, 0xFFFFFFFF),
            ("uid", self.uid, 0xFFFFFFFF),
            ("gid", self.gid, 0xFFFFFFFF),
            ("nlink", self.nlink, 0xFFFFFFFFFFFFFFFF),
            ("offset", self.offset, 0xFFFFFFFFFFFFFFFF),
        ):
            if type(value) is not int or not 0 <= value <= upper:
                raise BoundaryError(f"source-descriptor-{label}")
        if self.nlink != 1 or self.offset != 0:
            raise BoundaryError("source-descriptor-fixed")
        if not stat.S_ISREG(self.mode):
            raise BoundaryError("source-descriptor-type")
        _raw(self.content_sha256, 32, "source-content")
        _raw(self.artifact_stream_digest, 32, "artifact-stream")
        if self.content_sha256 == b"\0" * 32 or self.artifact_stream_digest == b"\0" * 32:
            raise BoundaryError("source-descriptor-digest")


@dataclass(frozen=True)
class ResultContextTargetDescriptor:
    pipe_dev: int
    pipe_ino: int
    mode: int
    worker_registration_serial: int
    target_digest: bytes
    isolation_digest: bytes

    def __post_init__(self) -> None:
        for label, value, upper in (
            ("pipe-dev", self.pipe_dev, 0xFFFFFFFFFFFFFFFF),
            ("pipe-ino", self.pipe_ino, 0xFFFFFFFFFFFFFFFF),
            ("mode", self.mode, 0xFFFFFFFF),
            ("worker-serial", self.worker_registration_serial, 0xFFFFFFFF),
        ):
            if type(value) is not int or not 0 <= value <= upper:
                raise BoundaryError(f"target-descriptor-{label}")
        if self.worker_registration_serial == 0:
            raise BoundaryError("target-descriptor-worker-serial")
        if not stat.S_ISFIFO(self.mode) or stat.S_IMODE(self.mode) != 0o600:
            raise BoundaryError("target-descriptor-mode")
        _raw(self.target_digest, 32, "target-digest")
        _raw(self.isolation_digest, 32, "target-isolation")
        if self.target_digest == b"\0" * 32 or self.isolation_digest == b"\0" * 32:
            raise BoundaryError("target-descriptor-digest")


@dataclass(frozen=True)
class ResultContextBind:
    context_generation: int
    generation: bytes
    connection: bytes
    session: bytes
    n_local: bytes
    restore_begin_frame_hash: bytes
    transition_id: str
    epoch_ref: str
    authority_ref: str
    barrier_utc: str
    commitments: tuple[bytes, ...]
    source: ResultContextSourceDescriptor
    target: ResultContextTargetDescriptor

    def __post_init__(self) -> None:
        if type(self.context_generation) is not int or not 0 < self.context_generation <= 0xFFFFFFFFFFFFFFFF:
            raise BoundaryError("context-generation")
        for label, value in (
            ("generation", self.generation), ("connection", self.connection),
            ("session", self.session), ("n-local", self.n_local),
            ("restore-begin-frame", self.restore_begin_frame_hash),
        ):
            _raw(value, 32, label)
            if value == b"\0" * 32:
                raise BoundaryError(f"context-{label}-zero")
        if TRANSITION_ID_RE.fullmatch(self.transition_id) is None:
            raise BoundaryError("context-transition-id")
        validate_ref(self.epoch_ref)
        validate_ref(self.authority_ref)
        validate_utc6(self.barrier_utc)
        if len(self.commitments) != len(BIND_COMMITMENT_FIELDS):
            raise BoundaryError("context-commitment-count")
        for value in self.commitments:
            _raw(value, 32, "context-commitment")
            if value == b"\0" * 32:
                raise BoundaryError("context-commitment-zero")


@dataclass(frozen=True)
class ResultContextFinal:
    bind_envelope_sha256: bytes
    context_generation: int
    generation: bytes
    connection: bytes
    session: bytes
    transition_id: str
    finality_serial: int
    source_bytes_read: int
    sink_bytes_accepted: int
    source_sha256: bytes
    sink_ack_digest: bytes
    restore_count: int
    exit_status: int
    result_code: int
    source_eof: bool
    restore_stdin_eof: bool
    worker_stdout_eof: bool
    worker_stderr_eof: bool
    worker_pidfd_exited: bool
    worker_cgroup_empty: bool
    target_readback_verified: bool
    owned_cleanup_complete: bool
    cleanup_state: int
    stdout: bytes
    stderr: bytes
    cleanup_inventory_digest: bytes

    def __post_init__(self) -> None:
        for label, value in (
            ("bind-envelope", self.bind_envelope_sha256),
            ("generation", self.generation),
            ("connection", self.connection),
            ("session", self.session),
            ("source-sha256", self.source_sha256),
            ("sink-ack", self.sink_ack_digest),
            ("cleanup-inventory", self.cleanup_inventory_digest),
        ):
            _raw(value, 32, label)
            if value == b"\0" * 32:
                raise BoundaryError(f"final-{label}-zero")
        if type(self.context_generation) is not int or not 0 < self.context_generation <= 0xFFFFFFFFFFFFFFFF:
            raise BoundaryError("final-context-generation")
        if TRANSITION_ID_RE.fullmatch(self.transition_id) is None:
            raise BoundaryError("final-transition-id")
        for label, value, upper in (
            ("finality-serial", self.finality_serial, 0xFFFFFFFFFFFFFFFF),
            ("source-bytes", self.source_bytes_read, 0xFFFFFFFFFFFFFFFF),
            ("sink-bytes", self.sink_bytes_accepted, 0xFFFFFFFFFFFFFFFF),
            ("restore-count", self.restore_count, 0xFFFFFFFF),
            ("exit-status", self.exit_status, 0xFFFFFFFF),
            ("result-code", self.result_code, 0xFFFFFFFF),
            ("cleanup-state", self.cleanup_state, 0xFF),
        ):
            if type(value) is not int or not 0 <= value <= upper:
                raise BoundaryError(f"final-{label}")
        if self.finality_serial == 0:
            raise BoundaryError("final-finality-serial")
        flags = (
            self.source_eof, self.restore_stdin_eof, self.worker_stdout_eof,
            self.worker_stderr_eof, self.worker_pidfd_exited,
            self.worker_cgroup_empty, self.target_readback_verified,
            self.owned_cleanup_complete,
        )
        if any(type(value) is not bool for value in flags):
            raise BoundaryError("final-boolean")
        if type(self.stdout) is not bytes or type(self.stderr) is not bytes:
            raise BoundaryError("final-capture-type")
        if len(self.stdout) > RESULT_CONTEXT_CAPTURE_MAX_BYTES or len(self.stderr) > RESULT_CONTEXT_CAPTURE_MAX_BYTES:
            raise BoundaryError("final-capture-limit")


def _context_raw32(value: Any, label: str, *, store: bool = False) -> bytes:
    if isinstance(value, str):
        return strict_store_digest(value) if store else managed_digest(value)
    return _raw(value, 32, label)


def _context_ref_bytes(value: str, label: str) -> bytes:
    try:
        checked = validate_ref(value)
        encoded = checked.encode("ascii", "strict")
    except (BoundaryError, UnicodeEncodeError) as error:
        raise BoundaryError(f"{label}-ref") from error
    if len(encoded) > 0xFFFF:
        raise BoundaryError(f"{label}-ref-size")
    return u16(len(encoded)) + encoded


def _context_envelope(magic: bytes, kind: int, payload: bytes, maximum: int) -> bytes:
    if type(payload) is not bytes or len(payload) > maximum:
        raise BoundaryError("context-payload-limit")
    header = magic + struct.pack("!HHI", RESULT_CONTEXT_VERSION, kind, len(payload))
    return header + payload + hashlib.sha256(header + payload).digest()


def encode_result_context_bind(bind: ResultContextBind) -> bytes:
    if not isinstance(bind, ResultContextBind):
        raise BoundaryError("bind-type")
    payload = bytearray()
    payload.extend(u64(bind.context_generation))
    payload.extend(_raw(bind.generation, 32, "generation"))
    payload.extend(_raw(bind.connection, 32, "connection"))
    payload.extend(_raw(bind.session, 32, "session"))
    payload.extend(_raw(bind.n_local, 32, "n-local"))
    payload.extend(_raw(bind.restore_begin_frame_hash, 32, "restore-begin-frame"))
    transition = bind.transition_id.encode("ascii", "strict")
    if len(transition) != RESULT_CONTEXT_TRANSITION_ID_BYTES:
        raise BoundaryError("bind-transition-size")
    payload.extend(transition)
    payload.extend(_context_ref_bytes(bind.epoch_ref, "epoch"))
    payload.extend(_context_ref_bytes(bind.authority_ref, "authority"))
    barrier = validate_utc6(bind.barrier_utc).encode("ascii", "strict")
    if len(barrier) != 27:
        raise BoundaryError("bind-barrier-size")
    payload.extend(barrier)
    for value in bind.commitments:
        payload.extend(_raw(value, 32, "bind-commitment"))
    payload.extend(struct.pack(
        "!QQQIIIQQ32s32s",
        bind.source.dev, bind.source.ino, bind.source.size,
        bind.source.mode, bind.source.uid, bind.source.gid,
        bind.source.nlink, bind.source.offset,
        _raw(bind.source.content_sha256, 32, "source-content"),
        _raw(bind.source.artifact_stream_digest, 32, "artifact-stream"),
    ))
    payload.extend(struct.pack(
        "!QQII32s32s",
        bind.target.pipe_dev, bind.target.pipe_ino, bind.target.mode,
        bind.target.worker_registration_serial,
        _raw(bind.target.target_digest, 32, "target-digest"),
        _raw(bind.target.isolation_digest, 32, "target-isolation"),
    ))
    envelope = _context_envelope(RESULT_CONTEXT_BIND_MAGIC, RESULT_CONTEXT_BIND_KIND,
                                 bytes(payload), RESULT_CONTEXT_BIND_PAYLOAD_MAX_BYTES)
    if len(envelope) > RESULT_CONTEXT_STREAM_MAX_BYTES:
        raise BoundaryError("context-stream-limit")
    return envelope


def encode_result_context_final(final: ResultContextFinal) -> bytes:
    if not isinstance(final, ResultContextFinal):
        raise BoundaryError("final-type")
    payload = bytearray()
    payload.extend(_raw(final.bind_envelope_sha256, 32, "bind-envelope"))
    payload.extend(u64(final.context_generation))
    payload.extend(_raw(final.generation, 32, "generation"))
    payload.extend(_raw(final.connection, 32, "connection"))
    payload.extend(_raw(final.session, 32, "session"))
    transition = final.transition_id.encode("ascii", "strict")
    if len(transition) != RESULT_CONTEXT_TRANSITION_ID_BYTES:
        raise BoundaryError("final-transition-size")
    payload.extend(transition)
    payload.extend(struct.pack(
        "!QQQ32s32sIII",
        final.finality_serial, final.source_bytes_read,
        final.sink_bytes_accepted, _raw(final.source_sha256, 32, "source-sha256"),
        _raw(final.sink_ack_digest, 32, "sink-ack"),
        final.restore_count, final.exit_status, final.result_code,
    ))
    flags = (
        final.source_eof, final.restore_stdin_eof, final.worker_stdout_eof,
        final.worker_stderr_eof, final.worker_pidfd_exited,
        final.worker_cgroup_empty, final.target_readback_verified,
        final.owned_cleanup_complete,
    )
    if any(type(value) is not bool for value in flags):
        raise BoundaryError("final-boolean")
    payload.extend(bytes(1 if value else 0 for value in flags))
    payload.append(final.cleanup_state)
    for capture in (final.stdout, final.stderr):
        if type(capture) is not bytes or len(capture) > RESULT_CONTEXT_CAPTURE_MAX_BYTES:
            raise BoundaryError("final-capture-limit")
        payload.extend(u32(len(capture)))
        payload.extend(capture)
    payload.extend(_raw(final.cleanup_inventory_digest, 32, "cleanup-inventory"))
    envelope = _context_envelope(RESULT_CONTEXT_FINAL_MAGIC, RESULT_CONTEXT_FINAL_KIND,
                                 bytes(payload), RESULT_CONTEXT_FINAL_PAYLOAD_MAX_BYTES)
    if len(envelope) > RESULT_CONTEXT_STREAM_MAX_BYTES:
        raise BoundaryError("context-stream-limit")
    return envelope


def encode_result_context_stream(bind: ResultContextBind, final: ResultContextFinal) -> bytes:
    bind_envelope = encode_result_context_bind(bind)
    if final.bind_envelope_sha256 != hashlib.sha256(bind_envelope).digest():
        raise BoundaryError("final-bind-digest")
    final_envelope = encode_result_context_final(final)
    combined_payload = len(bind_envelope) + len(final_envelope) - 96
    if combined_payload > RESULT_CONTEXT_COMBINED_PAYLOAD_MAX_BYTES:
        raise BoundaryError("context-combined-limit")
    stream = bind_envelope + final_envelope
    if len(stream) > RESULT_CONTEXT_STREAM_MAX_BYTES:
        raise BoundaryError("context-stream-limit")
    return stream


def _context_take(data: bytes, offset: int, length: int, label: str) -> tuple[bytes, int]:
    end = offset + length
    if offset < 0 or end > len(data):
        raise BoundaryError(f"{label}-short")
    return data[offset:end], end


def _decode_context_envelope(data: bytes, offset: int, magic: bytes, kind: int,
                             maximum: int) -> tuple[bytes, bytes, int]:
    header, offset = _context_take(data, offset, 16, "context-header")
    if header[:8] != magic:
        raise BoundaryError("context-magic")
    version, actual_kind, payload_length = struct.unpack("!HHI", header[8:16])
    if version != RESULT_CONTEXT_VERSION or actual_kind != kind or payload_length > maximum:
        raise BoundaryError("context-header-fields")
    payload, offset = _context_take(data, offset, payload_length, "context-payload")
    digest, offset = _context_take(data, offset, 32, "context-digest")
    if digest != hashlib.sha256(header + payload).digest():
        raise BoundaryError("context-digest")
    return payload, header + payload + digest, offset


def _context_parse_ascii(value: bytes, label: str) -> str:
    try:
        text = value.decode("ascii", "strict")
    except UnicodeDecodeError as error:
        raise BoundaryError(f"{label}-ascii") from error
    return text


def decode_result_context_bind(payload: bytes) -> ResultContextBind:
    if type(payload) is not bytes or len(payload) > RESULT_CONTEXT_BIND_PAYLOAD_MAX_BYTES:
        raise BoundaryError("bind-payload")
    offset = 0
    raw, offset = _context_take(payload, offset, 8, "bind-generation")
    context_generation = struct.unpack("!Q", raw)[0]
    generation, offset = _context_take(payload, offset, 32, "bind-generation-raw")
    connection, offset = _context_take(payload, offset, 32, "bind-connection")
    session, offset = _context_take(payload, offset, 32, "bind-session")
    n_local, offset = _context_take(payload, offset, 32, "bind-n-local")
    restore_begin_frame_hash, offset = _context_take(payload, offset, 32, "bind-restore-begin")
    transition_raw, offset = _context_take(payload, offset, RESULT_CONTEXT_TRANSITION_ID_BYTES, "bind-transition")
    transition_id = _context_parse_ascii(transition_raw, "bind-transition")
    values: list[str] = []
    for label in ("epoch", "authority"):
        raw_length, offset = _context_take(payload, offset, 2, f"bind-{label}-length")
        length = struct.unpack("!H", raw_length)[0]
        raw_ref, offset = _context_take(payload, offset, length, f"bind-{label}")
        value = _context_parse_ascii(raw_ref, f"bind-{label}")
        validate_ref(value)
        values.append(value)
    barrier_raw, offset = _context_take(payload, offset, 27, "bind-barrier")
    barrier_utc = _context_parse_ascii(barrier_raw, "bind-barrier")
    validate_utc6(barrier_utc)
    commitments: list[bytes] = []
    for _ in BIND_COMMITMENT_FIELDS:
        raw_commitment, offset = _context_take(payload, offset, 32, "bind-commitment")
        commitments.append(raw_commitment)
    source_raw, offset = _context_take(payload, offset, struct.calcsize("!QQQIIIQQ32s32s"), "bind-source")
    source_values = struct.unpack("!QQQIIIQQ32s32s", source_raw)
    target_raw, offset = _context_take(payload, offset, struct.calcsize("!QQII32s32s"), "bind-target")
    target_values = struct.unpack("!QQII32s32s", target_raw)
    if offset != len(payload):
        raise BoundaryError("bind-trailing")
    return ResultContextBind(
        context_generation, generation, connection, session, n_local,
        restore_begin_frame_hash, transition_id, values[0], values[1],
        barrier_utc, tuple(commitments),
        ResultContextSourceDescriptor(*source_values),
        ResultContextTargetDescriptor(*target_values),
    )


def decode_result_context_final(payload: bytes) -> ResultContextFinal:
    if type(payload) is not bytes or len(payload) > RESULT_CONTEXT_FINAL_PAYLOAD_MAX_BYTES:
        raise BoundaryError("final-payload")
    offset = 0
    bind_digest, offset = _context_take(payload, offset, 32, "final-bind-digest")
    raw, offset = _context_take(payload, offset, 8, "final-generation")
    context_generation = struct.unpack("!Q", raw)[0]
    generation, offset = _context_take(payload, offset, 32, "final-generation-raw")
    connection, offset = _context_take(payload, offset, 32, "final-connection")
    session, offset = _context_take(payload, offset, 32, "final-session")
    transition_raw, offset = _context_take(payload, offset, RESULT_CONTEXT_TRANSITION_ID_BYTES, "final-transition")
    transition_id = _context_parse_ascii(transition_raw, "final-transition")
    numeric_raw, offset = _context_take(payload, offset, struct.calcsize("!QQQ32s32sIII"), "final-numeric")
    finality_serial, source_bytes_read, sink_bytes_accepted, source_sha256, sink_ack_digest, restore_count, exit_status, result_code = struct.unpack("!QQQ32s32sIII", numeric_raw)
    flags_raw, offset = _context_take(payload, offset, 8, "final-flags")
    if any(value not in (0, 1) for value in flags_raw):
        raise BoundaryError("final-boolean")
    cleanup_raw, offset = _context_take(payload, offset, 1, "final-cleanup-state")
    captures: list[bytes] = []
    for label in ("stdout", "stderr"):
        length_raw, offset = _context_take(payload, offset, 4, f"final-{label}-length")
        length = struct.unpack("!I", length_raw)[0]
        if length > RESULT_CONTEXT_CAPTURE_MAX_BYTES:
            raise BoundaryError(f"final-{label}-limit")
        capture, offset = _context_take(payload, offset, length, f"final-{label}")
        captures.append(capture)
    cleanup_inventory_digest, offset = _context_take(payload, offset, 32, "final-cleanup-inventory")
    if offset != len(payload):
        raise BoundaryError("final-trailing")
    return ResultContextFinal(
        bind_digest, context_generation, generation, connection, session,
        transition_id, finality_serial, source_bytes_read, sink_bytes_accepted,
        source_sha256, sink_ack_digest, restore_count, exit_status, result_code,
        *(bool(value) for value in flags_raw), cleanup_raw[0],
        captures[0], captures[1], cleanup_inventory_digest,
    )


def decode_result_context_stream(data: bytes) -> tuple[ResultContextBind, ResultContextFinal]:
    if type(data) is not bytes or len(data) > RESULT_CONTEXT_STREAM_MAX_BYTES:
        raise BoundaryError("context-stream-size")
    bind_payload, bind_envelope, offset = _decode_context_envelope(
        data, 0, RESULT_CONTEXT_BIND_MAGIC, RESULT_CONTEXT_BIND_KIND,
        RESULT_CONTEXT_BIND_PAYLOAD_MAX_BYTES,
    )
    final_payload, _, offset = _decode_context_envelope(
        data, offset, RESULT_CONTEXT_FINAL_MAGIC, RESULT_CONTEXT_FINAL_KIND,
        RESULT_CONTEXT_FINAL_PAYLOAD_MAX_BYTES,
    )
    if offset != len(data):
        raise BoundaryError("context-stream-trailing")
    bind = decode_result_context_bind(bind_payload)
    final = decode_result_context_final(final_payload)
    if final.bind_envelope_sha256 != hashlib.sha256(bind_envelope).digest():
        raise BoundaryError("context-bind-replay")
    if (
        final.context_generation != bind.context_generation
        or final.generation != bind.generation
        or final.connection != bind.connection
        or final.session != bind.session
        or final.transition_id != bind.transition_id
    ):
        raise BoundaryError("context-binding-mismatch")
    return bind, final


def _result_observation_bytes(final: ResultContextFinal) -> tuple[bytes, bytes, bytes]:
    process = {
        "exit_status": final.exit_status,
        "worker_cgroup_empty": final.worker_cgroup_empty,
        "worker_pidfd_exited": final.worker_pidfd_exited,
    }
    restore = {
        "restore_count": final.restore_count,
        "sink_ack_digest": final.sink_ack_digest.hex(),
        "sink_bytes_accepted": final.sink_bytes_accepted,
        "source_bytes_read": final.source_bytes_read,
        "source_eof": final.source_eof,
        "source_sha256": final.source_sha256.hex(),
        "target_readback_verified": final.target_readback_verified,
    }
    cleanup = {
        "cleanup_inventory_digest": final.cleanup_inventory_digest.hex(),
        "cleanup_state": final.cleanup_state,
        "finality_serial": final.finality_serial,
        "owned_cleanup_complete": final.owned_cleanup_complete,
    }
    return managed_json(process), managed_json(restore), managed_json(cleanup)


def result_observation_commitments(final: ResultContextFinal) -> tuple[str, str, str, str, str]:
    process, restore, cleanup = _result_observation_bytes(final)
    return (
        store_commitment("process-evidence", process),
        store_commitment("restore-evidence", restore),
        store_commitment("cleanup-evidence", cleanup),
        store_commitment("stdout-capture", final.stdout),
        store_commitment("stderr-capture", final.stderr),
    )


def native_result_record_for_validation(bind: ResultContextBind, final: ResultContextFinal,
                                        *, terminal_input_eof: bool = True,
                                        terminal_input_trailing_bytes: bool = False) -> OrderedDict[str, Any]:
    """Reconstruct the expected B_R only after native FINAL has been received.

    This helper is a controller-side oracle. It is never used as an input to a
    native process and cannot create a managed RESULT frame.
    """
    if final.bind_envelope_sha256 != hashlib.sha256(encode_result_context_bind(bind)).digest():
        raise BoundaryError("validation-bind-digest")
    if terminal_input_eof is not True or terminal_input_trailing_bytes is not False:
        raise BoundaryError("validation-terminal-input")
    observation = result_observation_commitments(final)
    by_name = dict(zip(BIND_COMMITMENT_FIELDS, bind.commitments))

    def tag(name: str) -> str:
        return COMMITMENT_PREFIX + by_name[name].hex()

    success = (
        final.source_eof and final.restore_stdin_eof and
        final.worker_stdout_eof and final.worker_stderr_eof and
        final.worker_pidfd_exited and final.worker_cgroup_empty and
        final.target_readback_verified and final.owned_cleanup_complete and
        final.cleanup_state == 1 and final.restore_count == 1 and
        final.exit_status == 0 and final.result_code == 0 and
        final.source_bytes_read == final.sink_bytes_accepted
    )
    record: OrderedDict[str, Any] = OrderedDict((
        ("schema", "swz-recovery-result.v2"),
        ("classification", "SUCCESS" if success else "FAILURE"),
        ("stage", "RESTORE"),
        ("epoch_ref", bind.epoch_ref),
        ("authority_ref", bind.authority_ref),
        ("barrier_utc", bind.barrier_utc),
        ("ssh_endpoint_commitment", tag("ssh_endpoint")),
        ("epoch_commitment", tag("epoch")),
        ("authority_commitment", tag("authority")),
        ("barrier_commitment", tag("barrier")),
        ("runner_commitment", tag("runner")),
        ("bundle_commitment", tag("bundle")),
        ("launcher_commitment", tag("launcher")),
        ("agent_commitment", tag("agent")),
        ("image_commitment", tag("image")),
        ("target_commitment", tag("target")),
        ("isolation_commitment", tag("isolation")),
        ("artifact_commitment", tag("artifact")),
        ("artifact_stream_commitment", tag("artifact_stream")),
        ("transition_id", bind.transition_id),
        ("pre_cas_ledger_digest", tag("pre_cas_ledger")),
        ("transition_data_commitment", tag("transition_data")),
        ("consumed_record_commitment", tag("consumed_record")),
        ("restore_begin_commitment", tag("restore_begin")),
        ("process_commitment", observation[0]),
        ("restore_commitment", observation[1]),
        ("cleanup_commitment", observation[2]),
        ("stdout_capture_commitment", observation[3]),
        ("stderr_capture_commitment", observation[4]),
        ("result_code", final.result_code),
        ("restore_count", final.restore_count),
        ("exit_status", final.exit_status),
        ("stdin_eof", final.restore_stdin_eof),
        ("stdout_eof", final.worker_stdout_eof),
        ("stderr_eof", final.worker_stderr_eof),
        ("trailing_unframed_bytes", False),
        ("terminal_input_eof", terminal_input_eof),
        ("terminal_input_trailing_bytes", terminal_input_trailing_bytes),
        ("cleanup_state", "CLEAN" if final.cleanup_state == 1 else "DIRTY"),
    ))
    return record


def validate_native_result_frame(frame_bytes: bytes, *, n_local: bytes,
                                 proceed_frame: bytes, session: bytes,
                                 transition_id: str, proceed_commitment: bytes,
                                 bind: ResultContextBind | None = None,
                                 final: ResultContextFinal | None = None) -> tuple[Frame, StoreWire, OrderedDict[str, Any], bytes]:
    proceed = decode_frame(
        proceed_frame, expected_n_local=n_local,
        expected_direction=DIRECTION_LOCAL_TO_REMOTE, expected_message="PROCEED",
        expected_sequence=7,
    )
    proceed_fields = parse_managed_json(proceed.payload)
    proceed_restore_begin = managed_digest(proceed_fields[3])
    proceed_transition_commitment = strict_store_digest(proceed_fields[6])
    expected_proceed = managed_hash(
        "proceed.v1", _raw(session, 32, "session"), transition_id.encode("ascii"),
        proceed_transition_commitment, proceed_restore_begin,
    )
    if (proceed_fields[0:3] != ["PROCEED", 2, MANAGED_SCHEMA] or
            proceed_fields[4] != _raw(session, 32, "session").hex() or
            proceed_fields[5] != transition_id or
            proceed_fields[7] != proceed_fields[3] or
            proceed_fields[8] != expected_proceed.hex() or
            expected_proceed != _raw(proceed_commitment, 32, "proceed")):
        raise ProtocolError("native-proceed-binding")
    frame = decode_frame(
        frame_bytes, expected_n_local=n_local, previous_frame=proceed_frame,
        expected_direction=DIRECTION_REMOTE_TO_LOCAL, expected_message="RESULT",
        expected_sequence=8,
    )
    fields = parse_managed_json(frame.payload)
    if fields[0:3] != ["RESULT", 2, MANAGED_SCHEMA]:
        raise ProtocolError("native-result-prefix")
    if fields[5] != transition_id or fields[6] != _raw(proceed_commitment, 32, "proceed").hex():
        raise ProtocolError("native-result-binding")
    if fields[4] != _raw(session, 32, "session").hex():
        raise ProtocolError("native-result-session")
    if fields[3] != frame_hash(proceed_frame).hex():
        raise ProtocolError("native-result-predecessor")
    result_wire = decode_store_wire(fields[7])
    result_record = validate_retained_store_bytes(result_wire.schema_id, result_wire.store_bytes)
    expected_rc = managed_hash(
        "result.v1", _raw(session, 32, "session"), transition_id.encode("ascii"),
        _raw(proceed_commitment, 32, "proceed"), result_wire.store_bytes,
    )
    if fields[8] != expected_rc.hex():
        raise ProtocolError("native-result-commitment")
    if result_record["transition_id"] != transition_id:
        raise ProtocolError("native-result-store-binding")
    if (result_record["terminal_input_eof"] is not True or
            result_record["terminal_input_trailing_bytes"] is not False):
        raise ProtocolError("native-result-terminal-input")
    if bind is not None and final is not None:
        if (bind.n_local != _raw(n_local, 32, "n-local") or
                bind.session != _raw(session, 32, "session") or
                bind.transition_id != transition_id or
                bind.restore_begin_frame_hash != proceed_restore_begin):
            raise ProtocolError("native-context-external-binding")
        expected_record = native_result_record_for_validation(
            bind, final,
            terminal_input_eof=result_record["terminal_input_eof"],
            terminal_input_trailing_bytes=result_record["terminal_input_trailing_bytes"],
        )
        if result_record != expected_record:
            raise ProtocolError("native-result-reconstruction")
    return frame, result_wire, result_record, expected_rc


class GenerationState(str, Enum):
    OFFLINE = "OFFLINE"
    QUALIFIED = "QUALIFIED"
    ACTIVE = "ACTIVE"
    DRAINING = "DRAINING"
    RETIRING = "RETIRING"


class GenerationLifecycle:
    _ALLOWED = {
        GenerationState.OFFLINE: (GenerationState.QUALIFIED,),
        GenerationState.QUALIFIED: (GenerationState.ACTIVE,),
        GenerationState.ACTIVE: (GenerationState.DRAINING,),
        GenerationState.DRAINING: (GenerationState.RETIRING,),
        GenerationState.RETIRING: (GenerationState.OFFLINE,),
    }

    def __init__(self) -> None:
        self.state = GenerationState.OFFLINE

    def advance(self, target: GenerationState) -> None:
        if target not in self._ALLOWED[self.state]:
            raise StateTransitionError(f"generation:{self.state}->{target}")
        self.state = target


class AdmissionState(str, Enum):
    ACCEPTED_SOCKET = "ACCEPTED_SOCKET"
    SSH_AUTHENTICATED = "SSH_AUTHENTICATED"
    BOOTSTRAP = "BOOTSTRAP"
    CHALLENGE = "CHALLENGE"
    EVIDENCE = "EVIDENCE"
    CONTROLLER_VALIDATED = "CONTROLLER_VALIDATED"
    ACCEPT_SENT = "ACCEPT_SENT"
    REMOTE_ACCEPTED = "REMOTE_ACCEPTED"
    OPERATIONAL = "OPERATIONAL"
    FAILED = "FAILED"


class AdmissionLifecycle:
    _ALLOWED = {
        AdmissionState.ACCEPTED_SOCKET: (AdmissionState.SSH_AUTHENTICATED, AdmissionState.FAILED),
        AdmissionState.SSH_AUTHENTICATED: (AdmissionState.BOOTSTRAP, AdmissionState.FAILED),
        AdmissionState.BOOTSTRAP: (AdmissionState.CHALLENGE, AdmissionState.FAILED),
        AdmissionState.CHALLENGE: (AdmissionState.EVIDENCE, AdmissionState.FAILED),
        AdmissionState.EVIDENCE: (AdmissionState.CONTROLLER_VALIDATED, AdmissionState.FAILED),
        AdmissionState.CONTROLLER_VALIDATED: (AdmissionState.ACCEPT_SENT, AdmissionState.FAILED),
        AdmissionState.ACCEPT_SENT: (AdmissionState.REMOTE_ACCEPTED, AdmissionState.FAILED),
        AdmissionState.REMOTE_ACCEPTED: (AdmissionState.OPERATIONAL, AdmissionState.FAILED),
        AdmissionState.OPERATIONAL: (AdmissionState.FAILED,), AdmissionState.FAILED: (),
    }

    def __init__(self) -> None:
        self.state = AdmissionState.ACCEPTED_SOCKET

    def advance(self, target: AdmissionState) -> None:
        if target not in self._ALLOWED[self.state]:
            raise StateTransitionError(f"admission:{self.state}->{target}")
        self.state = target

    def fail(self, code: str) -> None:
        if not isinstance(code, str) or not code:
            raise StateTransitionError("admission:failure-code")
        self.state = AdmissionState.FAILED


class BrokerState(str, Enum):
    PRE_ACCEPT = "PRE_ACCEPT"
    ACCEPTED = "ACCEPTED"
    DISCOVERY = "DISCOVERY"
    CAS_A = "CAS_A"
    RESTORE_BEGIN = "RESTORE_BEGIN"
    PROCEED = "PROCEED"
    EOF = "EOF"
    RESTORED = "RESTORED"
    RESULT = "RESULT"
    FINAL = "FINAL"
    CONSUMED_UNCERTAINTY = "CONSUMED_UNCERTAINTY"


class BrokerLifecycle:
    _ALLOWED = {
        BrokerState.PRE_ACCEPT: (BrokerState.ACCEPTED,), BrokerState.ACCEPTED: (BrokerState.DISCOVERY,),
        BrokerState.DISCOVERY: (BrokerState.CAS_A,), BrokerState.CAS_A: (BrokerState.RESTORE_BEGIN, BrokerState.CONSUMED_UNCERTAINTY),
        BrokerState.RESTORE_BEGIN: (BrokerState.PROCEED, BrokerState.CONSUMED_UNCERTAINTY), BrokerState.PROCEED: (BrokerState.EOF, BrokerState.CONSUMED_UNCERTAINTY),
        BrokerState.EOF: (BrokerState.RESTORED, BrokerState.CONSUMED_UNCERTAINTY), BrokerState.RESTORED: (BrokerState.RESULT,),
        BrokerState.RESULT: (BrokerState.FINAL,), BrokerState.FINAL: (), BrokerState.CONSUMED_UNCERTAINTY: (),
    }

    def __init__(self) -> None:
        self.state = BrokerState.PRE_ACCEPT

    def advance(self, target: BrokerState) -> None:
        if target not in self._ALLOWED[self.state]:
            raise StateTransitionError(f"broker:{self.state}->{target}")
        self.state = target

    def consumed_uncertainty(self) -> None:
        self.state = BrokerState.CONSUMED_UNCERTAINTY


@dataclass(frozen=True)
class IdentityVector:
    installation: bytes
    endpoint_template: bytes
    endpoint_actual: bytes


def test_identity_vector_inputs() -> dict[str, Any]:
    return {
        "installation_uuid": bytes.fromhex("00112233445546778899aabbccddeeff"),
        "boot_uuid": bytes.fromhex("102132435465476798a9bacbdcedfe0f"),
        "admission_key": bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
        "host_key": bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
        "controller_key": bytes.fromhex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"),
        "endpoint_ipv4": "192.0.2.10", "listener_netns_device": 7, "listener_netns_inode": 11,
        "activation_serial": 7,
        "uidgid_map": bytes.fromhex("01000000020100000000000186a0000100000200000000000186a000010000"),
        "target_policy": b"\x11" * 32,
    }


def identity_vector() -> IdentityVector:
    values = test_identity_vector_inputs()
    endpoint = literal_endpoint_record(values["endpoint_ipv4"])
    installation = installation_identity(values["installation_uuid"], ed25519_public_blob(values["admission_key"]), ed25519_public_blob(values["host_key"]), ed25519_public_blob(values["controller_key"]), endpoint, values["uidgid_map"], values["target_policy"])
    template = endpoint_template_identity(installation, endpoint)
    actual = endpoint_actual_identity(template, values["boot_uuid"], values["listener_netns_device"], values["listener_netns_inode"])
    return IdentityVector(installation, template, actual)


def restore_artifact(source: os.PathLike[str] | str, target: os.PathLike[str] | str) -> str:
    """Restore a bounded regular file through descriptor-checked atomic I/O."""
    source_path = Path(source)
    target_path = Path(target)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    source_fd = os.open(source_path, os.O_RDONLY | nofollow)
    parent_fd = -1
    output_fd = -1
    temporary_name = f".swz-restore-{os.getpid()}-{secrets.token_hex(8)}"
    try:
        source_stat = os.fstat(source_fd)
        if not stat.S_ISREG(source_stat.st_mode) or source_stat.st_size > 1024 * 1024:
            raise BoundaryError("restore-source-invalid")
        parent_fd = os.open(target_path.parent, os.O_RDONLY | directory_flag | nofollow)
        try:
            existing = os.stat(target_path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and (stat.S_ISLNK(existing.st_mode) or not stat.S_ISREG(existing.st_mode)):
            raise BoundaryError("restore-target-invalid")
        output_fd = os.open(temporary_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o600, dir_fd=parent_fd)
        remaining = source_stat.st_size
        digest = hashlib.sha256()
        while remaining:
            chunk = os.read(source_fd, min(65536, remaining))
            if not chunk:
                raise BoundaryError("restore-source-short")
            view = memoryview(chunk)
            while view:
                written = os.write(output_fd, view)
                if written <= 0:
                    raise BoundaryError("restore-write-short")
                view = view[written:]
            digest.update(chunk)
            remaining -= len(chunk)
        os.fsync(output_fd)
        os.close(output_fd)
        output_fd = -1
        os.rename(temporary_name, target_path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
        return digest.hexdigest()
    finally:
        if output_fd >= 0:
            os.close(output_fd)
        if parent_fd >= 0:
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            os.close(parent_fd)
        os.close(source_fd)


__all__ = [
    "AdmissionLifecycle", "AdmissionState", "BoundaryError", "BrokerLifecycle", "BrokerState",
    "CanonicalJSONError", "DIRECTION_LOCAL_TO_REMOTE", "DIRECTION_REMOTE_TO_LOCAL", "DURABILITY_FIELDS",
    "EVIDENCE_FIELDS", "FRAME_HEADER", "FRAME_HEADER_BYTES", "FrameHash32", "FrameSession", "GenerationLifecycle", "GenerationState",
    "IDENTITY_FORMULA_MAP", "IDENTITY_GRAPH", "IdentityError", "IdentityVector", "MANAGED_DOMAINS",
    "MANAGED_SCHEMA", "MESSAGE_BY_NAME", "MESSAGE_NAMES", "MAX_CONTROL_PAYLOAD_BYTES", "MAX_FRAME_BYTES",
    "MAX_SESSION_BYTES", "MAX_SESSION_FRAMES", "RESULT_FIELDS", "STORE_MARKER", "STORE_PROFILES", "StoreWire",
    "StoreWireError", "TRANSITION_FIELDS", "TRANSITION_ID_RE", "activation_identity", "assert_domain_uniqueness",
    "assert_identity_graph_acyclic", "build_accept", "build_accepted", "build_boot", "build_challenge", "build_discovery", "build_evidence", "build_frame", "build_proceed", "build_result",
    "build_restore_begin", "canonical_filename_octets", "decode_frame", "decode_store_wire", "ed25519_public_blob",
    "endpoint_actual_identity", "endpoint_template_identity", "frame_hash", "identity_vector", "installation_identity",
    "literal_endpoint_record", "lp", "managed32", "managed_digest", "managed_hash", "managed_hex", "managed_json",
    "parse_managed_json", "reject_self_reference", "restore_artifact", "store_bytes", "store_commitment",
    "store_wire_record", "strict_store_digest", "test_identity_vector_inputs", "transition_id", "u8", "u16", "u32", "u64",
    "validate_message_payload", "validate_ref", "validate_retained_store_bytes", "validate_u32_json", "validate_u64_json", "validate_utc6", "Managed32", "ManagedDigest", "PlainSHA256", "RawNonce32", "StoreDigest", "encode_store_wire", "frame_hash32", "plain_sha256", "raw_nonce32",
    "BIND_COMMITMENT_FIELDS", "RESULT_CONTEXT_BIND_MAGIC", "RESULT_CONTEXT_FINAL_MAGIC",
    "RESULT_CONTEXT_VERSION", "RESULT_CONTEXT_BIND_KIND", "RESULT_CONTEXT_FINAL_KIND",
    "RESULT_CONTEXT_BIND_PAYLOAD_MAX_BYTES", "RESULT_CONTEXT_FINAL_PAYLOAD_MAX_BYTES",
    "RESULT_CONTEXT_CAPTURE_MAX_BYTES", "RESULT_CONTEXT_COMBINED_PAYLOAD_MAX_BYTES",
    "RESULT_CONTEXT_STREAM_MAX_BYTES", "ResultContextSourceDescriptor",
    "ResultContextTargetDescriptor", "ResultContextBind", "ResultContextFinal",
    "encode_result_context_bind", "encode_result_context_final",
    "encode_result_context_stream", "decode_result_context_bind",
    "decode_result_context_final", "decode_result_context_stream",
    "result_observation_commitments", "native_result_record_for_validation",
    "validate_native_result_frame",
]
