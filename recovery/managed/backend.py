"""Managed recovery boundary primitives.

This module is the independent Python reference for the managed boundary. It
keeps the retained ControllerStore byte domain separate from managed JSON and
wire bytes. Runtime code is allowed to consume a validated value only together
with the exact bytes that authenticated that value.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import struct
import unicodedata
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
    2: "CHALLENGE",
    3: "EVIDENCE",
    4: "ACCEPT",
    5: "ACCEPTED",
    6: "DISCOVERY",
    7: "RESTORE_BEGIN",
    8: "PROCEED",
    9: "RESULT",
    10: "ABORT",
}
MESSAGE_BY_NAME = {value: key for key, value in MESSAGE_NAMES.items()}

COMMITMENT_PREFIX = "sha256:v1:"
MANAGED_HEX_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
STORE_COMMITMENT_RE = re.compile(r"sha256:v1:[0-9a-f]{64}\Z", re.ASCII)
TRANSITION_ID_RE = re.compile(r"restore-v2-[0-9a-f]{48}\Z", re.ASCII)
UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z",
    re.ASCII,
)


class BoundaryError(ValueError):
    """Base class for fail-closed managed boundary errors."""


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


def _strict_utf8(value: Any, label: str, *, max_bytes: int = MAX_CONTROL_PAYLOAD_BYTES) -> str:
    if not isinstance(value, str):
        raise BoundaryError(f"{label}:type")
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise BoundaryError(f"{label}:surrogate")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError as error:
        raise BoundaryError(f"{label}:utf8") from error
    if len(encoded) > max_bytes:
        raise BoundaryError(f"{label}:size")
    if not unicodedata.is_normalized("NFC", value):
        raise BoundaryError(f"{label}:normalization")
    return value


def _reject_constant(value: str) -> None:
    raise CanonicalJSONError("non-finite-number")


def _managed_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if not isinstance(key, str) or any(ord(char) > 0x7F for char in key):
            raise CanonicalJSONError("object-key-not-ascii")
        if key in result:
            raise CanonicalJSONError("duplicate-object-key")
        result[key] = value
    return result


def _validate_managed_tree(value: Any) -> None:
    if value is None:
        raise CanonicalJSONError("null-not-permitted")
    if isinstance(value, bool):
        return
    if type(value) is int:
        if value < 0 or value > 0xFFFFFFFF:
            raise CanonicalJSONError("managed-integer-out-of-range")
        return
    if isinstance(value, float):
        raise CanonicalJSONError("float-not-permitted")
    if isinstance(value, str):
        _strict_utf8(value, "managed-string")
        return
    if isinstance(value, Mapping):
        keys = list(value.keys())
        if any(not isinstance(key, str) for key in keys):
            raise CanonicalJSONError("object-key-type")
        if keys != sorted(keys):
            raise CanonicalJSONError("object-key-order")
        for key in keys:
            if not isinstance(key, str) or any(ord(char) > 0x7F for char in key):
                raise CanonicalJSONError("object-key-not-ascii")
            _validate_managed_tree(value[key])
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _validate_managed_tree(item)
        return
    raise CanonicalJSONError("unsupported-managed-value")


def managed_json(value: Any) -> bytes:
    """Return exact J(value) bytes, without a final LF."""

    _validate_managed_tree(value)
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise CanonicalJSONError("managed-json-encoding") from error
    if not encoded or b"\n" in encoded or b"\r" in encoded:
        raise CanonicalJSONError("managed-json-whitespace")
    if len(encoded) > MAX_CONTROL_PAYLOAD_BYTES:
        raise CanonicalJSONError("managed-payload-too-large")
    return encoded


def parse_managed_json(payload: bytes) -> Any:
    if not isinstance(payload, bytes) or not payload:
        raise CanonicalJSONError("managed-payload-type")
    if len(payload) > MAX_CONTROL_PAYLOAD_BYTES:
        raise CanonicalJSONError("managed-payload-too-large")
    try:
        text = payload.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise CanonicalJSONError("managed-payload-utf8") from error
    if text.startswith("\ufeff") or text != text.strip():
        raise CanonicalJSONError("managed-payload-whitespace")
    decoder = json.JSONDecoder(object_pairs_hook=_managed_pairs, parse_constant=_reject_constant)
    try:
        value, end = decoder.raw_decode(text)
    except (json.JSONDecodeError, CanonicalJSONError) as error:
        raise CanonicalJSONError("managed-payload-json") from error
    if end != len(text) or managed_json(value) != payload:
        raise CanonicalJSONError("managed-payload-not-canonical")
    return value


def _store_pairs(pairs: list[tuple[str, Any]]) -> OrderedDict[str, Any]:
    result: OrderedDict[str, Any] = OrderedDict()
    for key, value in pairs:
        if not isinstance(key, str) or key in result:
            raise StoreWireError("store-duplicate-or-invalid-key")
        result[key] = value
    return result


def _store_reject_constant(value: str) -> None:
    raise StoreWireError("store-non-finite-number")


def _store_dump(record: OrderedDict[str, Any]) -> bytes:
    try:
        return (
            json.dumps(record, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=False)
            + "\n"
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise StoreWireError("store-serialization") from error


def _validate_store_tree(value: Any) -> None:
    if value is None:
        raise StoreWireError("store-null-not-permitted")
    if isinstance(value, bool):
        return
    if type(value) is int:
        if value < 0:
            raise StoreWireError("store-negative-integer")
        return
    if isinstance(value, float):
        raise StoreWireError("store-float-not-permitted")
    if isinstance(value, str):
        _strict_utf8(value, "store-string")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise StoreWireError("store-key-type")
            _validate_store_tree(item)
        return
    if isinstance(value, list):
        for item in value:
            _validate_store_tree(item)
        return
    raise StoreWireError("store-value-type")


TRANSITION_FIELDS = (
    "schema", "version", "epoch_ref", "authority_ref", "barrier_utc", "barrier_commitment",
    "runner_commitment", "bundle_commitment", "image_commitment", "target_commitment",
    "isolation_commitment", "artifact_commitment", "artifact_stream_commitment", "pre_cas_ledger_digest",
)
EVIDENCE_FIELDS = (
    "schema", "epoch_ref", "transition_id", "transition_data_commitment", "artifact_commitment",
    "artifact_stream_commitment", "ledger_state", "record_state", "spool_previous_stage", "frame_sequence",
    "previous_frame_hash", "frame_hash", "spool_commitment", "ledger_after_digest", "durability",
)
DURABILITY_FIELDS = ("file_flush_verified", "readback_verified", "atomic_authority_transition", "directory_flush_verified")
RESULT_FIELDS = (
    "schema", "classification", "stage", "epoch_ref", "authority_ref", "barrier_utc",
    "ssh_endpoint_commitment", "epoch_commitment", "authority_commitment", "barrier_commitment",
    "runner_commitment", "bundle_commitment", "launcher_commitment", "agent_commitment", "image_commitment",
    "target_commitment", "isolation_commitment", "artifact_commitment", "artifact_stream_commitment",
    "transition_id", "pre_cas_ledger_digest", "transition_data_commitment", "consumed_record_commitment",
    "restore_begin_commitment", "process_commitment", "restore_commitment", "cleanup_commitment",
    "stdout_capture_commitment", "stderr_capture_commitment", "result_code", "restore_count", "exit_status",
    "stdin_eof", "stdout_eof", "stderr_eof", "trailing_unframed_bytes", "terminal_input_eof",
    "terminal_input_trailing_bytes", "cleanup_state",
)
STORE_PROFILES: Mapping[str, tuple[str, ...]] = {
    "restore-ledger-transition-data.v2": TRANSITION_FIELDS,
    "restore-begin-evidence.v2": EVIDENCE_FIELDS,
    "swz-recovery-result.v2": RESULT_FIELDS,
}


def validate_retained_store_bytes(schema_id: str, store_bytes: bytes) -> OrderedDict[str, Any]:
    """Validate retained Store bytes without changing their representation."""

    if schema_id not in STORE_PROFILES or not isinstance(store_bytes, bytes):
        raise StoreWireError("store-profile-or-bytes-invalid")
    if not store_bytes or len(store_bytes) > MAX_CONTROL_PAYLOAD_BYTES:
        raise StoreWireError("store-size-invalid")
    try:
        text = store_bytes.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise StoreWireError("store-utf8-invalid") from error
    if not text.endswith("\n") or text.endswith("\n\n"):
        raise StoreWireError("store-terminal-lf-invalid")
    decoder = json.JSONDecoder(object_pairs_hook=_store_pairs, parse_constant=_store_reject_constant)
    try:
        value, end = decoder.raw_decode(text[:-1])
    except (json.JSONDecodeError, StoreWireError) as error:
        raise StoreWireError("store-json-invalid") from error
    if end != len(text) - 1 or not isinstance(value, OrderedDict):
        raise StoreWireError("store-document-shape-invalid")
    if tuple(value.keys()) != STORE_PROFILES[schema_id] or value.get("schema") != schema_id:
        raise StoreWireError("store-schema-order-invalid")
    try:
        _validate_store_tree(value)
    except BoundaryError as error:
        raise StoreWireError("store-tree-invalid") from error
    if schema_id == "restore-ledger-transition-data.v2" and value.get("version") != 2:
        raise StoreWireError("store-transition-version-invalid")
    if schema_id == "restore-begin-evidence.v2":
        durability = value.get("durability")
        if not isinstance(durability, OrderedDict) or tuple(durability.keys()) != DURABILITY_FIELDS:
            raise StoreWireError("store-durability-order-invalid")
        if any(type(durability[key]) is not bool for key in DURABILITY_FIELDS):
            raise StoreWireError("store-durability-value-invalid")
    if _store_dump(value) != store_bytes:
        raise StoreWireError("store-bytes-not-canonical")
    _validate_store_profile(schema_id, value)
    return value


def _store_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise StoreWireError(f"{label}-text-invalid")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError as error:
        raise StoreWireError(f"{label}-utf8-invalid") from error
    return value


def _store_tagged(value: Any, label: str) -> str:
    if not isinstance(value, str) or STORE_COMMITMENT_RE.fullmatch(value) is None:
        raise StoreWireError(f"{label}-commitment-invalid")
    return value


def _store_profile(schema_id: str, value: OrderedDict[str, Any]) -> None:
    if schema_id == "restore-ledger-transition-data.v2":
        if value["version"] != 2:
            raise StoreWireError("store-transition-version-invalid")
        for field in (
            "epoch_ref", "authority_ref", "barrier_utc", "barrier_commitment",
            "runner_commitment", "bundle_commitment", "image_commitment",
            "target_commitment", "isolation_commitment", "artifact_commitment",
            "artifact_stream_commitment",
        ):
            _store_tagged(value[field], field) if field.endswith("_commitment") else _store_text(value[field], field)
        _store_tagged(value["pre_cas_ledger_digest"], "pre-cas-ledger")
        return
    if schema_id == "restore-begin-evidence.v2":
        for field in ("epoch_ref", "transition_id", "ledger_state", "record_state", "spool_previous_stage"):
            _store_text(value[field], field)
        _store_tagged(value["transition_data_commitment"], "transition-data")
        for field in (
            "artifact_commitment", "artifact_stream_commitment", "previous_frame_hash",
            "frame_hash", "spool_commitment", "ledger_after_digest",
        ):
            _store_tagged(value[field], field)
        if type(value["frame_sequence"]) is not int or not 1 <= value["frame_sequence"] <= MAX_SESSION_FRAMES:
            raise StoreWireError("store-frame-sequence-invalid")
        if value["ledger_state"] != "CONSUMED" or value["record_state"] != "ACTIVE":
            raise StoreWireError("store-evidence-state-invalid")
        if value["spool_previous_stage"] != "RUNNER_STARTED":
            raise StoreWireError("store-evidence-stage-invalid")
        return
    if schema_id == "swz-recovery-result.v2":
        for field in (
            "classification", "stage", "epoch_ref", "authority_ref", "barrier_utc",
            "ssh_endpoint_commitment", "epoch_commitment", "authority_commitment",
            "barrier_commitment", "runner_commitment", "bundle_commitment",
            "launcher_commitment", "agent_commitment", "image_commitment",
            "target_commitment", "isolation_commitment", "artifact_commitment",
            "artifact_stream_commitment", "transition_id", "pre_cas_ledger_digest",
            "transition_data_commitment", "consumed_record_commitment",
            "restore_begin_commitment", "process_commitment", "restore_commitment",
            "cleanup_commitment", "stdout_capture_commitment", "stderr_capture_commitment",
            "cleanup_state",
        ):
            _store_text(value[field], field)
        for field in (
            "ssh_endpoint_commitment", "epoch_commitment", "authority_commitment",
            "barrier_commitment", "runner_commitment", "bundle_commitment",
            "launcher_commitment", "agent_commitment", "image_commitment",
            "target_commitment", "isolation_commitment", "artifact_commitment",
            "artifact_stream_commitment", "pre_cas_ledger_digest",
            "transition_data_commitment", "consumed_record_commitment",
            "restore_begin_commitment", "process_commitment", "restore_commitment",
            "cleanup_commitment", "stdout_capture_commitment", "stderr_capture_commitment",
        ):
            _store_tagged(value[field], field)
        if type(value["result_code"]) is not int or type(value["restore_count"]) is not int or type(value["exit_status"]) is not int:
            raise StoreWireError("store-result-integer-invalid")
        if value["result_code"] != 0 or value["restore_count"] != 1 or value["exit_status"] != 0:
            raise StoreWireError("store-result-state-invalid")
        for field in (
            "stdin_eof", "stdout_eof", "stderr_eof", "trailing_unframed_bytes",
            "terminal_input_eof", "terminal_input_trailing_bytes",
        ):
            if type(value[field]) is not bool:
                raise StoreWireError("store-result-boolean-invalid")
        if not all(value[field] is True for field in (
            "stdin_eof", "stdout_eof", "stderr_eof", "terminal_input_eof",
        )) or value["trailing_unframed_bytes"] is not False or value["terminal_input_trailing_bytes"] is not False:
            raise StoreWireError("store-result-finality-invalid")
        return
    raise StoreWireError("store-profile-invalid")


def _validate_store_profile(schema_id: str, value: OrderedDict[str, Any]) -> None:
    _store_profile(schema_id, value)


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


@dataclass(frozen=True)
class StoreWire:
    schema_id: str
    store_bytes: bytes
    semantic: Mapping[str, Any]

    @classmethod
    def from_bytes(cls, schema_id: str, store_bytes: bytes) -> "StoreWire":
        semantic = validate_retained_store_bytes(schema_id, store_bytes)
        return cls(schema_id, bytes(store_bytes), _freeze(semantic))

    def envelope(self) -> list[Any]:
        return [STORE_MARKER, self.schema_id, self.store_bytes.decode("utf-8", "strict")]

    def payload(self) -> bytes:
        return managed_json(self.envelope())


def encode_store_wire(schema_id: str, store_bytes: bytes) -> bytes:
    return StoreWire.from_bytes(schema_id, store_bytes).payload()


def decode_store_wire(value_or_payload: Any) -> StoreWire:
    value = parse_managed_json(value_or_payload) if isinstance(value_or_payload, bytes) else value_or_payload
    if not isinstance(value, list) or len(value) != 3:
        raise StoreWireError("store-wire-arity-invalid")
    marker, schema_id, store_text = value
    if marker != STORE_MARKER or not isinstance(schema_id, str) or schema_id not in STORE_PROFILES:
        raise StoreWireError("store-wire-marker-or-schema-invalid")
    if not isinstance(store_text, str):
        raise StoreWireError("store-wire-must-carry-string")
    try:
        raw = store_text.encode("utf-8", "strict")
    except UnicodeEncodeError as error:
        raise StoreWireError("store-wire-string-invalid") from error
    return StoreWire.from_bytes(schema_id, raw)


def lp(value: bytes) -> bytes:
    if not isinstance(value, bytes) or len(value) > 0xFFFFFFFF:
        raise BoundaryError("length-prefix-invalid")
    return struct.pack("!I", len(value)) + value


def managed_hash(domain: str, *parts: bytes) -> bytes:
    if not isinstance(domain, str) or not domain:
        raise IdentityError("managed-domain-invalid")
    try:
        domain_bytes = domain.encode("ascii", "strict")
    except UnicodeEncodeError as error:
        raise IdentityError("managed-domain-not-ascii") from error
    if any(not isinstance(part, bytes) for part in parts):
        raise IdentityError("managed-preimage-invalid")
    preimage = lp(MANAGED_SCHEMA.encode("ascii")) + lp(domain_bytes) + b"".join(lp(part) for part in parts)
    return hashlib.sha256(preimage).digest()


def managed_hex(value: bytes) -> str:
    if not isinstance(value, bytes) or len(value) != 32:
        raise BoundaryError("managed-digest-length")
    return value.hex()


def managed_digest(value: Any) -> bytes:
    if not isinstance(value, str) or MANAGED_HEX_RE.fullmatch(value) is None:
        raise BoundaryError("managed-digest-text-invalid")
    return bytes.fromhex(value)


def store_commitment(domain: str, store_bytes: bytes) -> str:
    if not isinstance(domain, str) or not domain:
        raise StoreWireError("store-domain-invalid")
    try:
        domain_bytes = domain.encode("ascii", "strict")
    except UnicodeEncodeError as error:
        raise StoreWireError("store-domain-not-ascii") from error
    digest = hashlib.sha256(lp(b"recovery-commitment.v1") + lp(domain_bytes) + lp(store_bytes)).hexdigest()
    return COMMITMENT_PREFIX + digest


def strict_store_digest(value: Any) -> bytes:
    if not isinstance(value, str) or STORE_COMMITMENT_RE.fullmatch(value) is None:
        raise BoundaryError("strict-store-digest-invalid")
    return bytes.fromhex(value[len(COMMITMENT_PREFIX):])


def store_bytes(record: Mapping[str, Any]) -> bytes:
    if not isinstance(record, Mapping):
        raise StoreWireError("store-record-type-invalid")
    return _store_dump(OrderedDict(record.items()))


def store_wire_record(schema_id: str, record: Mapping[str, Any]) -> StoreWire:
    return StoreWire.from_bytes(schema_id, store_bytes(record))


def transition_id(store_transition_bytes: bytes) -> str:
    digest = hashlib.sha256(lp(b"restore-transition-id.v2") + lp(store_transition_bytes)).hexdigest()
    return "restore-v2-" + digest[:48]


def _raw(value: Any, length: int, label: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != length:
        raise IdentityError(f"{label}-length")
    return bytes(value)


def u8(value: int) -> bytes:
    if type(value) is not int or not 0 <= value <= 0xFF:
        raise IdentityError("u8-range")
    return struct.pack("!B", value)


def u16(value: int) -> bytes:
    if type(value) is not int or not 0 <= value <= 0xFFFF:
        raise IdentityError("u16-range")
    return struct.pack("!H", value)


def u32(value: int) -> bytes:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise IdentityError("u32-range")
    return struct.pack("!I", value)


def u64(value: int) -> bytes:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise IdentityError("u64-range")
    return struct.pack("!Q", value)


def ed25519_public_blob(public_octets: bytes) -> bytes:
    public_octets = _raw(public_octets, 32, "ed25519-public")
    return u32(11) + b"ssh-ed25519" + u32(32) + public_octets


def validate_uuid_text(value: str) -> bytes:
    if not isinstance(value, str) or UUID_RE.fullmatch(value) is None:
        raise IdentityError("uuid-not-canonical")
    raw = bytes.fromhex(value.replace("-", ""))
    if raw == b"\x00" * 16 or raw[8] & 0xC0 != 0x80:
        raise IdentityError("uuid-invalid")
    return raw


def literal_endpoint_record(endpoint_ipv4: str, port: int = 22222) -> bytes:
    if not isinstance(endpoint_ipv4, str):
        raise IdentityError("endpoint-text-type")
    octets = endpoint_ipv4.split(".")
    if (
        len(octets) != 4
        or any(
            not part.isascii()
            or not part.isdecimal()
            or (len(part) > 1 and part.startswith("0"))
            or int(part) > 255
            for part in octets
        )
    ):
        raise IdentityError("endpoint-ipv4-invalid")
    try:
        address = ipaddress.IPv4Address(endpoint_ipv4)
    except ipaddress.AddressValueError as error:
        raise IdentityError("endpoint-ipv4-invalid") from error
    if str(address) != endpoint_ipv4 or port != 22222:
        raise IdentityError("endpoint-not-enrolled")
    return b"\x01\x01" + u16(2) + address.packed + u16(port)


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
        _raw(admission_root_public_blob51, 51, "admission-root-key"),
        _raw(recovery_host_public_blob51, 51, "recovery-host-key"),
        _raw(controller_public_blob51, 51, "controller-key"),
        _raw(literal_endpoint_raw10, 10, "literal-endpoint"),
        uidgid_map_raw,
        _raw(target_policy_commitment_raw32, 32, "target-policy"),
    )


def endpoint_template_identity(installation_raw32: bytes, literal_endpoint_raw10: bytes) -> bytes:
    return managed_hash("endpoint-template.v1", _raw(installation_raw32, 32, "installation"), _raw(literal_endpoint_raw10, 10, "literal-endpoint"))


def endpoint_actual_identity(
    endpoint_template_raw32: bytes,
    boot_uuid_raw16: bytes,
    listener_netns_device: int,
    listener_netns_inode: int,
) -> bytes:
    return managed_hash(
        "endpoint-actual.v1",
        _raw(endpoint_template_raw32, 32, "endpoint-template"),
        _raw(boot_uuid_raw16, 16, "boot-uuid"),
        u64(listener_netns_device),
        u64(listener_netns_inode),
    )


def activation_identity(
    installation_raw32: bytes,
    generation_raw32: bytes,
    endpoint_actual_raw32: bytes,
    boot_uuid_raw16: bytes,
    activation_serial: int,
    activation_random32: bytes,
) -> bytes:
    return managed_hash(
        "activation.v1",
        _raw(installation_raw32, 32, "installation"),
        _raw(generation_raw32, 32, "generation"),
        _raw(endpoint_actual_raw32, 32, "endpoint-actual"),
        _raw(boot_uuid_raw16, 16, "boot-uuid"),
        u64(activation_serial),
        _raw(activation_random32, 32, "activation-random"),
    )


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


IDENTITY_GRAPH: Mapping[str, Sequence[str]] = {
    "raw-endpoint": ("installation",),
    "installation": ("endpoint-template",),
    "endpoint-template": ("endpoint-actual",),
    "endpoint-actual": ("activation",),
    "qualification-subject": ("build-qualification", "generation"),
    "build-qualification": ("generation",),
    "generation": ("generation-manifest", "generation-approval", "activation"),
    "activation": ("connection", "challenge", "accepted-session"),
    "connection": ("challenge",),
    "challenge": ("evidence",),
    "evidence": ("accept", "accepted-session"),
    "accept": ("accepted-session",),
    "accepted-session": ("accepted-receipt", "discovery", "proceed", "result"),
    "discovery": ("proceed",),
    "proceed": ("result",),
    "result": (),
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
    for node, children in graph.items():
        if node in children:
            raise IdentityError("identity-self-reference")
    assert_identity_graph_acyclic(graph)


def canonical_filename_octets(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise IdentityError("filename-empty")
    if not unicodedata.is_normalized("NFC", value):
        raise IdentityError("filename-normalization")
    try:
        raw = value.encode("utf-8", "strict")
    except UnicodeEncodeError as error:
        raise IdentityError("filename-utf8") from error
    if base64.urlsafe_b64encode(base64.urlsafe_b64decode(base64.urlsafe_b64encode(raw))).rstrip(b"=") != base64.urlsafe_b64encode(raw).rstrip(b"="):
        raise IdentityError("filename-encoding")
    if b"/" in raw or b"\\" in raw or b"\x00" in raw or raw in (b".", b".."):
        raise IdentityError("filename-path")
    return raw


def _hex32(value: bytes, label: str) -> str:
    return managed_hex(_raw(value, 32, label))


def build_restore_begin(
    session_raw32: bytes,
    discovery_frame_hash_raw32: bytes,
    transition_wire: StoreWire,
    evidence_wire: StoreWire,
    consumed_record_commitment: str,
) -> bytes:
    strict_store_digest(consumed_record_commitment)
    value = [
        "RESTORE_BEGIN", 2, MANAGED_SCHEMA, _hex32(discovery_frame_hash_raw32, "discovery-frame"),
        _hex32(session_raw32, "session"), transition_wire.envelope(), evidence_wire.envelope(),
        consumed_record_commitment,
    ]
    return managed_json(value)


def build_proceed(
    session_raw32: bytes,
    transition_identifier: str,
    transition_data_commitment: str,
    restore_begin_frame_hash_raw32: bytes,
) -> tuple[bytes, bytes]:
    if TRANSITION_ID_RE.fullmatch(transition_identifier) is None:
        raise ProtocolError("transition-id-invalid")
    transition_digest = strict_store_digest(transition_data_commitment)
    pc = managed_hash(
        "proceed.v1", _raw(session_raw32, 32, "session"), transition_identifier.encode("ascii"),
        transition_digest, _raw(restore_begin_frame_hash_raw32, 32, "restore-begin-frame"),
    )
    payload = managed_json([
        "PROCEED", 2, MANAGED_SCHEMA, _hex32(restore_begin_frame_hash_raw32, "restore-begin-frame"),
        _hex32(session_raw32, "session"), transition_identifier, transition_data_commitment,
        _hex32(restore_begin_frame_hash_raw32, "restore-begin-frame"), _hex32(pc, "proceed"),
    ])
    return payload, pc


def build_result(
    session_raw32: bytes,
    transition_identifier: str,
    proceed_frame_hash_raw32: bytes,
    pc_raw32: bytes,
    result_wire: StoreWire,
) -> tuple[bytes, bytes]:
    if TRANSITION_ID_RE.fullmatch(transition_identifier) is None:
        raise ProtocolError("transition-id-invalid")
    proceed_frame_hash_raw32 = _raw(proceed_frame_hash_raw32, 32, "proceed-frame")
    pc_raw32 = _raw(pc_raw32, 32, "proceed")
    rc = managed_hash("result.v1", _raw(session_raw32, 32, "session"), transition_identifier.encode("ascii"), pc_raw32, result_wire.store_bytes)
    payload = managed_json([
        "RESULT", 2, MANAGED_SCHEMA, _hex32(proceed_frame_hash_raw32, "proceed-frame"), _hex32(session_raw32, "session"),
        transition_identifier, _hex32(pc_raw32, "proceed"), result_wire.envelope(), _hex32(rc, "result"),
    ])
    return payload, rc


def build_discovery(
    session_raw32: bytes,
    execution_row_id: int,
    artifact_filename: str,
    image_commitment: str,
    target_commitment: str,
    isolation_commitment: str,
    artifact_commitment: str,
    artifact_stream_commitment: str,
) -> tuple[bytes, bytes]:
    if type(execution_row_id) is not int or not 0 < execution_row_id <= 0xFFFFFFFFFFFFFFFF:
        raise ProtocolError("execution-row-id-invalid")
    raw_filename = canonical_filename_octets(artifact_filename)
    tagged = tuple(
        strict_store_digest(value)
        for value in (
            image_commitment, target_commitment, isolation_commitment,
            artifact_commitment, artifact_stream_commitment,
        )
    )
    dc = managed_hash("discovery.v1", _raw(session_raw32, 32, "session"), u64(execution_row_id), raw_filename, *tagged)
    encoded_filename = base64.urlsafe_b64encode(raw_filename).rstrip(b"=").decode("ascii")
    payload = managed_json([
        "DISCOVERY", 2, MANAGED_SCHEMA, _hex32(session_raw32, "session"),
        str(execution_row_id), encoded_filename, image_commitment, target_commitment,
        isolation_commitment, artifact_commitment, artifact_stream_commitment, _hex32(dc, "discovery"),
    ])
    return payload, dc


@dataclass(frozen=True)
class Frame:
    direction: int
    message: str
    sequence: int
    nonce: bytes
    payload: bytes
    raw: bytes


def frame_hash(frame_bytes: bytes) -> bytes:
    if not isinstance(frame_bytes, bytes) or len(frame_bytes) < FRAME_HEADER_BYTES:
        raise ProtocolError("frame-too-short")
    return hashlib.sha256(frame_bytes).digest()


def build_frame(direction: int, message_name: str, sequence: int, nonce: bytes, payload: bytes) -> bytes:
    if direction not in (DIRECTION_LOCAL_TO_REMOTE, DIRECTION_REMOTE_TO_LOCAL):
        raise ProtocolError("frame-direction")
    if message_name not in MESSAGE_BY_NAME:
        raise ProtocolError("frame-message")
    if type(sequence) is not int or not 1 <= sequence <= MAX_SESSION_FRAMES:
        raise ProtocolError("frame-sequence")
    nonce = _raw(nonce, 32, "frame-nonce")
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_CONTROL_PAYLOAD_BYTES:
        raise ProtocolError("frame-payload")
    if FRAME_HEADER_BYTES + len(payload) > MAX_FRAME_BYTES:
        raise ProtocolError("frame-size")
    header = FRAME_HEADER.pack(SWZFRM02_MAGIC, SWZFRM02_VERSION, direction, MESSAGE_BY_NAME[message_name], SWZFRM02_FLAGS, sequence, nonce, len(payload))
    return header + payload


def decode_frame(frame_bytes: bytes) -> Frame:
    if not isinstance(frame_bytes, bytes) or len(frame_bytes) < FRAME_HEADER_BYTES:
        raise ProtocolError("frame-too-short")
    magic, version, direction, message_id, flags, sequence, nonce, payload_len = FRAME_HEADER.unpack(frame_bytes[:FRAME_HEADER_BYTES])
    if magic != SWZFRM02_MAGIC or version != SWZFRM02_VERSION or flags != SWZFRM02_FLAGS:
        raise ProtocolError("frame-header")
    if direction not in (DIRECTION_LOCAL_TO_REMOTE, DIRECTION_REMOTE_TO_LOCAL) or message_id not in MESSAGE_NAMES:
        raise ProtocolError("frame-route")
    if not 1 <= sequence <= MAX_SESSION_FRAMES or payload_len > MAX_CONTROL_PAYLOAD_BYTES:
        raise ProtocolError("frame-limits")
    if len(frame_bytes) != FRAME_HEADER_BYTES + payload_len or payload_len == 0:
        raise ProtocolError("frame-trailing")
    payload = frame_bytes[FRAME_HEADER_BYTES:]
    if payload:
        parse_managed_json(payload)
    return Frame(direction, MESSAGE_NAMES[message_id], sequence, nonce, payload, bytes(frame_bytes))


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
        AdmissionState.OPERATIONAL: (AdmissionState.FAILED,),
        AdmissionState.FAILED: (),
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
        if self.state != AdmissionState.FAILED:
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
        BrokerState.PRE_ACCEPT: (BrokerState.ACCEPTED,),
        BrokerState.ACCEPTED: (BrokerState.DISCOVERY,),
        BrokerState.DISCOVERY: (BrokerState.CAS_A,),
        BrokerState.CAS_A: (BrokerState.RESTORE_BEGIN, BrokerState.CONSUMED_UNCERTAINTY),
        BrokerState.RESTORE_BEGIN: (BrokerState.PROCEED, BrokerState.CONSUMED_UNCERTAINTY),
        BrokerState.PROCEED: (BrokerState.EOF, BrokerState.CONSUMED_UNCERTAINTY),
        BrokerState.EOF: (BrokerState.RESTORED, BrokerState.CONSUMED_UNCERTAINTY),
        BrokerState.RESTORED: (BrokerState.RESULT,),
        BrokerState.RESULT: (BrokerState.FINAL,),
        BrokerState.FINAL: (),
        BrokerState.CONSUMED_UNCERTAINTY: (),
    }

    def __init__(self) -> None:
        self.state = BrokerState.PRE_ACCEPT

    def advance(self, target: BrokerState) -> None:
        if target not in self._ALLOWED[self.state]:
            raise StateTransitionError(f"broker:{self.state}->{target}")
        self.state = target

    def consumed_uncertainty(self) -> None:
        if self.state != BrokerState.CONSUMED_UNCERTAINTY:
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
        "endpoint_ipv4": "192.0.2.10",
        "listener_netns_device": 7,
        "listener_netns_inode": 11,
        "activation_serial": 7,
        "uidgid_map": bytes.fromhex("01000000020100000000000186a0000100000200000000000186a000010000"),
        "target_policy": b"\x11" * 32,
    }


def identity_vector() -> IdentityVector:
    values = test_identity_vector_inputs()
    ler = literal_endpoint_record(values["endpoint_ipv4"])
    installation = installation_identity(
        values["installation_uuid"],
        ed25519_public_blob(values["admission_key"]),
        ed25519_public_blob(values["host_key"]),
        ed25519_public_blob(values["controller_key"]),
        ler,
        values["uidgid_map"],
        values["target_policy"],
    )
    template = endpoint_template_identity(installation, ler)
    actual = endpoint_actual_identity(template, values["boot_uuid"], values["listener_netns_device"], values["listener_netns_inode"])
    return IdentityVector(installation, template, actual)


def restore_artifact(source: os.PathLike[str] | str, target: os.PathLike[str] | str) -> str:
    """Copy one qualified disposable artifact using descriptor-based I/O."""

    source_path = Path(source)
    target_path = Path(target)
    if source_path.is_symlink() or target_path.is_symlink():
        raise BoundaryError("restore-symlink")
    source_fd = os.open(source_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        source_stat = os.fstat(source_fd)
        if not os.path.isfile(source_path) or source_stat.st_size > 1024 * 1024:
            raise BoundaryError("restore-source-invalid")
        parent_fd = os.open(target_path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            temporary_name = f".swz-restore-{os.getpid()}"
            temporary_path = target_path.parent / temporary_name
            output_fd = os.open(temporary_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                remaining = source_stat.st_size
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
                    remaining -= len(chunk)
                os.fsync(output_fd)
            finally:
                os.close(output_fd)
            os.replace(temporary_path, target_path)
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        os.close(source_fd)
    return hashlib.sha256(target_path.read_bytes()).hexdigest()


__all__ = [
    "AdmissionLifecycle", "AdmissionState", "BoundaryError", "BrokerLifecycle", "BrokerState",
    "CanonicalJSONError", "DIRECTION_LOCAL_TO_REMOTE", "DIRECTION_REMOTE_TO_LOCAL", "EVIDENCE_FIELDS",
    "FRAME_HEADER", "FRAME_HEADER_BYTES", "GenerationLifecycle", "GenerationState", "IDENTITY_GRAPH",
    "IdentityError", "IdentityVector", "MANAGED_DOMAINS", "MANAGED_SCHEMA", "MESSAGE_BY_NAME", "MESSAGE_NAMES",
    "MAX_CONTROL_PAYLOAD_BYTES", "MAX_FRAME_BYTES", "MAX_SESSION_BYTES", "MAX_SESSION_FRAMES", "RESULT_FIELDS",
    "STORE_MARKER", "STORE_PROFILES", "StoreWire", "StoreWireError", "TRANSITION_FIELDS", "TRANSITION_ID_RE",
    "activation_identity", "assert_domain_uniqueness", "assert_identity_graph_acyclic", "build_frame", "build_proceed",
    "build_discovery", "build_restore_begin", "build_result", "canonical_filename_octets", "decode_frame", "decode_store_wire",
    "ed25519_public_blob", "endpoint_actual_identity", "endpoint_template_identity", "frame_hash", "identity_vector",
    "installation_identity", "literal_endpoint_record", "lp", "managed_digest", "managed_hash", "managed_hex",
    "managed_json", "parse_managed_json", "reject_self_reference", "restore_artifact", "store_commitment",
    "store_bytes", "store_wire_record", "strict_store_digest", "test_identity_vector_inputs", "transition_id", "u8", "u16", "u32", "u64",
    "validate_retained_store_bytes", "validate_uuid_text",
]
