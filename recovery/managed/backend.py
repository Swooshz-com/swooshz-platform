"""Managed recovery boundary primitives.

This module is deliberately dependency-free and has two separate byte
domains.  Managed records use ``J``/``H``.  Retained controller Store records
use ``SB``/``SC`` and are carried across the managed boundary only by
``StoreWire``.  The distinction is structural in the API: a StoreWire keeps
the original bytes and exposes immutable semantic values only after the byte
round-trip has been proven.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import ipaddress
import json
import os
import re
import struct
from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence


MANAGED_SCHEMA = "swz-managed.v1"
STORE_MARKER = "store-json.v1"
MAX_CONTROL_PAYLOAD_BYTES = 4096
MAX_FRAME_BYTES = 65536
MAX_SESSION_FRAMES = 16
MAX_SESSION_BYTES = 1048576
FRAME_HEADER_BYTES = 56
SWZFRM02_MAGIC = b"SWZFRM02"
SWZFRM02_VERSION = 2
SWZFRM02_FLAGS = 0
FRAME_HEADER = struct.Struct("!8sBBBBQ32sI")

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
SCHEMA_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z", re.ASCII)
TRANSITION_ID_RE = re.compile(r"restore-v2-[0-9a-f]{48}\Z", re.ASCII)


class BoundaryError(ValueError):
    """Base class for fail-closed managed-boundary errors."""


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


def _strict_text(value: Any, label: str, *, max_bytes: int = MAX_CONTROL_PAYLOAD_BYTES) -> str:
    if not isinstance(value, str):
        raise BoundaryError(f"{label}:type")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError as error:
        raise BoundaryError(f"{label}:utf8") from error
    if len(encoded) > max_bytes:
        raise BoundaryError(f"{label}:size")
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise BoundaryError(f"{label}:surrogate")
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
        _strict_text(value, "managed-string")
        return
    if isinstance(value, Mapping):
        keys = list(value.keys())
        if any(not isinstance(key, str) for key in keys):
            raise CanonicalJSONError("object-key-type")
        if keys != sorted(keys):
            raise CanonicalJSONError("object-key-order")
        for key in keys:
            if any(ord(char) > 0x7F for char in key):
                raise CanonicalJSONError("object-key-not-ascii")
            _validate_managed_tree(value[key])
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _validate_managed_tree(item)
        return
    raise CanonicalJSONError("unsupported-managed-value")


def managed_json(value: Any) -> bytes:
    """Return exact Run-374 ``J(value)`` bytes with no final LF."""

    _validate_managed_tree(value)
    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        result = text.encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise CanonicalJSONError("managed-json-encoding") from error
    if not result or b"\n" in result or b"\r" in result:
        raise CanonicalJSONError("managed-json-whitespace")
    if len(result) > MAX_CONTROL_PAYLOAD_BYTES:
        raise CanonicalJSONError("managed-payload-too-large")
    return result


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
    decoder = json.JSONDecoder(
        object_pairs_hook=_managed_pairs,
        parse_constant=_reject_constant,
    )
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
        text = json.dumps(
            record,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=False,
        )
        return (text + "\n").encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise StoreWireError("store-serialization") from error


def _validate_store_values(value: Any) -> None:
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
        try:
            value.encode("utf-8", "strict")
        except UnicodeEncodeError as error:
            raise StoreWireError("store-invalid-utf8") from error
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise StoreWireError("store-key-type")
            _validate_store_values(item)
        return
    if isinstance(value, list):
        for item in value:
            _validate_store_values(item)
        return
    raise StoreWireError("store-value-type")


TRANSITION_FIELDS = (
    "schema",
    "version",
    "epoch_ref",
    "authority_ref",
    "barrier_utc",
    "barrier_commitment",
    "runner_commitment",
    "bundle_commitment",
    "image_commitment",
    "target_commitment",
    "isolation_commitment",
    "artifact_commitment",
    "artifact_stream_commitment",
    "pre_cas_ledger_digest",
)
EVIDENCE_FIELDS = (
    "schema",
    "epoch_ref",
    "transition_id",
    "transition_data_commitment",
    "artifact_commitment",
    "artifact_stream_commitment",
    "ledger_state",
    "record_state",
    "spool_previous_stage",
    "frame_sequence",
    "previous_frame_hash",
    "frame_hash",
    "spool_commitment",
    "ledger_after_digest",
    "durability",
)
DURABILITY_FIELDS = (
    "file_flush_verified",
    "readback_verified",
    "atomic_authority_transition",
    "directory_flush_verified",
)
RESULT_FIELDS = (
    "schema",
    "classification",
    "stage",
    "epoch_ref",
    "authority_ref",
    "barrier_utc",
    "ssh_endpoint_commitment",
    "epoch_commitment",
    "authority_commitment",
    "barrier_commitment",
    "runner_commitment",
    "bundle_commitment",
    "launcher_commitment",
    "agent_commitment",
    "image_commitment",
    "target_commitment",
    "isolation_commitment",
    "artifact_commitment",
    "artifact_stream_commitment",
    "transition_id",
    "pre_cas_ledger_digest",
    "transition_data_commitment",
    "consumed_record_commitment",
    "restore_begin_commitment",
    "process_commitment",
    "restore_commitment",
    "cleanup_commitment",
    "stdout_capture_commitment",
    "stderr_capture_commitment",
    "result_code",
    "restore_count",
    "exit_status",
    "stdin_eof",
    "stdout_eof",
    "stderr_eof",
    "trailing_unframed_bytes",
    "terminal_input_eof",
    "terminal_input_trailing_bytes",
    "cleanup_state",
)
STORE_PROFILES: Mapping[str, tuple[str, ...]] = {
    "restore-ledger-transition-data.v2": TRANSITION_FIELDS,
    "restore-begin-evidence.v2": EVIDENCE_FIELDS,
    "swz-recovery-result.v2": RESULT_FIELDS,
}


def validate_retained_store_bytes(schema_id: str, store_bytes: bytes) -> OrderedDict[str, Any]:
    """Validate without constructing a new Store record or changing bytes."""

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
    document = text[:-1]
    decoder = json.JSONDecoder(
        object_pairs_hook=_store_pairs,
        parse_constant=_store_reject_constant,
    )
    try:
        value, end = decoder.raw_decode(document)
    except (json.JSONDecodeError, StoreWireError) as error:
        raise StoreWireError("store-json-invalid") from error
    if end != len(document) or not isinstance(value, OrderedDict):
        raise StoreWireError("store-document-shape-invalid")
    if tuple(value.keys()) != STORE_PROFILES[schema_id]:
        raise StoreWireError("store-schema-order-invalid")
    if value.get("schema") != schema_id:
        raise StoreWireError("store-schema-id-invalid")
    _validate_store_values(value)
    if schema_id == "restore-ledger-transition-data.v2":
        if type(value.get("version")) is not int or value["version"] != 2:
            raise StoreWireError("store-transition-version-invalid")
    if schema_id == "restore-begin-evidence.v2":
        durability = value.get("durability")
        if not isinstance(durability, OrderedDict) or tuple(durability.keys()) != DURABILITY_FIELDS:
            raise StoreWireError("store-durability-order-invalid")
        if any(type(durability[key]) is not bool for key in DURABILITY_FIELDS):
            raise StoreWireError("store-durability-value-invalid")
    if _store_dump(value) != store_bytes:
        raise StoreWireError("store-bytes-not-canonical")
    return value


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
        try:
            store_text = self.store_bytes.decode("utf-8", "strict")
        except UnicodeDecodeError as error:  # defensive: constructor already proved it
            raise StoreWireError("store-wire-utf8-invalid") from error
        return [STORE_MARKER, self.schema_id, store_text]

    def payload(self) -> bytes:
        encoded = managed_json(self.envelope())
        if len(encoded) > MAX_CONTROL_PAYLOAD_BYTES:
            raise StoreWireError("store-wire-payload-too-large")
        return encoded


def encode_store_wire(schema_id: str, store_bytes: bytes) -> bytes:
    return StoreWire.from_bytes(schema_id, store_bytes).payload()


def decode_store_wire(value_or_payload: Any) -> StoreWire:
    if isinstance(value_or_payload, bytes):
        value = parse_managed_json(value_or_payload)
    else:
        value = value_or_payload
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


def _lp(value: bytes) -> bytes:
    if not isinstance(value, bytes) or len(value) > 0xFFFFFFFF:
        raise BoundaryError("length-prefix-invalid")
    return struct.pack("!I", len(value)) + value


def lp(value: bytes) -> bytes:
    return _lp(value)


def managed_hash(domain: str, *parts: bytes) -> bytes:
    try:
        domain_bytes = domain.encode("ascii", "strict")
    except UnicodeEncodeError as error:
        raise IdentityError("managed-domain-not-ascii") from error
    if not domain or any(not isinstance(part, bytes) for part in parts):
        raise IdentityError("managed-preimage-invalid")
    return hashlib.sha256(_lp(MANAGED_SCHEMA.encode("ascii")) + _lp(domain_bytes) + b"".join(_lp(part) for part in parts)).digest()


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
    digest = hashlib.sha256(
        _lp(b"recovery-commitment.v1") + _lp(domain_bytes) + _lp(store_bytes)
    ).hexdigest()
    return COMMITMENT_PREFIX + digest


def strict_store_digest(value: Any) -> bytes:
    if not isinstance(value, str) or STORE_COMMITMENT_RE.fullmatch(value) is None:
        raise BoundaryError("strict-store-digest-invalid")
    return bytes.fromhex(value[len(COMMITMENT_PREFIX) :])


def transition_id(store_transition_bytes: bytes) -> str:
    digest = hashlib.sha256(_lp(b"restore-transition-id.v2") + _lp(store_transition_bytes)).hexdigest()
    return "restore-v2-" + digest[:48]


def _raw_bytes(value: Any, length: int, label: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != length:
        raise IdentityError(f"{label}-length")
    return bytes(value)


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


def ed25519_public_blob(public_octets: bytes) -> bytes:
    key = _raw_bytes(public_octets, 32, "ed25519-public-key")
    algorithm = b"ssh-ed25519"
    return u32(len(algorithm)) + algorithm + u32(len(key)) + key


def literal_endpoint_record(
    enrolled_ipv4: str,
    *,
    namespace_role: int = 1,
    address_family: int = 2,
    port: int = 22222,
) -> bytes:
    if type(namespace_role) is not int or not 0 <= namespace_role <= 0xFF:
        raise IdentityError("endpoint-namespace-role")
    if type(address_family) is not int or not 0 <= address_family <= 0xFFFF:
        raise IdentityError("endpoint-address-family")
    if type(port) is not int or not 0 <= port <= 0xFFFF:
        raise IdentityError("endpoint-port")
    if not isinstance(enrolled_ipv4, str) or enrolled_ipv4 != enrolled_ipv4.strip():
        raise IdentityError("endpoint-ipv4-whitespace")
    try:
        address = ipaddress.IPv4Address(enrolled_ipv4)
    except ipaddress.AddressValueError as error:
        raise IdentityError("endpoint-ipv4-invalid") from error
    if str(address) != enrolled_ipv4:
        raise IdentityError("endpoint-ipv4-not-canonical")
    return u8(1) + u8(namespace_role) + u16(address_family) + address.packed + u16(port)


def validate_uuid_text(value: str) -> bytes:
    if not isinstance(value, str) or len(value) != 36 or value.lower() != value:
        raise IdentityError("uuid-text-invalid")
    if value[8] != "-" or value[13] != "-" or value[18] != "-" or value[23] != "-":
        raise IdentityError("uuid-shape-invalid")
    raw = value.replace("-", "")
    if not re.fullmatch(r"[0-9a-f]{32}", raw, re.ASCII):
        raise IdentityError("uuid-hex-invalid")
    decoded = bytes.fromhex(raw)
    if decoded == b"\0" * 16:
        raise IdentityError("uuid-nil")
    if (decoded[6] >> 4) != 4 or (decoded[8] & 0xC0) != 0x80:
        raise IdentityError("uuid-version-or-variant-invalid")
    return decoded


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
        _raw_bytes(installation_uuid_raw16, 16, "installation-uuid"),
        _raw_bytes(admission_root_public_blob51, 51, "admission-root-key"),
        _raw_bytes(recovery_host_public_blob51, 51, "recovery-host-key"),
        _raw_bytes(controller_public_blob51, 51, "controller-key"),
        _raw_bytes(literal_endpoint_raw10, 10, "literal-endpoint"),
        bytes(uidgid_map_raw),
        _raw_bytes(target_policy_commitment_raw32, 32, "target-policy"),
    )


def endpoint_template_identity(installation_raw32: bytes, literal_endpoint_raw10: bytes) -> bytes:
    return managed_hash(
        "endpoint-template.v1",
        _raw_bytes(installation_raw32, 32, "installation-identity"),
        _raw_bytes(literal_endpoint_raw10, 10, "literal-endpoint"),
    )


def endpoint_actual_identity(
    endpoint_template_raw32: bytes,
    boot_uuid_raw16: bytes,
    listener_netns_device: int,
    listener_netns_inode: int,
) -> bytes:
    return managed_hash(
        "endpoint-actual.v1",
        _raw_bytes(endpoint_template_raw32, 32, "endpoint-template"),
        _raw_bytes(boot_uuid_raw16, 16, "boot-uuid"),
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
        _raw_bytes(installation_raw32, 32, "installation-identity"),
        _raw_bytes(generation_raw32, 32, "generation-identity"),
        _raw_bytes(endpoint_actual_raw32, 32, "endpoint-actual"),
        _raw_bytes(boot_uuid_raw16, 16, "boot-uuid"),
        u64(activation_serial),
        _raw_bytes(activation_random32, 32, "activation-random"),
    )


MANAGED_DOMAINS = (
    ("AR", "admission-root.v1"),
    ("HK", "host-public-key.v1"),
    ("TP", "target-policy.v1"),
    ("DI", "dependency-closure.v1"),
    ("IP", "invocation-policy.v1"),
    ("X", "execution-inventory.v1"),
    ("B", "build-record.v1"),
    ("FD", "fd-inventory.v1"),
    ("AV", "runtime-argv.v1"),
    ("LM", "runtime-limits.v1"),
    ("P", "policy.v1"),
    ("Q", "auth-account-config.v1"),
    ("NC", "n-local.v1"),
    ("I", "installation.v1"),
    ("ET", "endpoint-template.v1"),
    ("EA", "endpoint-actual.v1"),
    ("L", "launch-base.v1"),
    ("O", "openssh-closure.v1"),
    ("SUP", "component-supervisor.v1"),
    ("CUS", "component-custodian.v1"),
    ("DIS", "component-dispatcher.v1"),
    ("BST", "component-bootstrap.v1"),
    ("BRK", "component-broker.v1"),
    ("AGT", "component-agent.v1"),
    ("V", "dm-verity.v1"),
    ("QS", "qualification-subject.v1"),
    ("BQ", "build-qualification.v1"),
    ("G", "generation.v1"),
    ("M", "generation-manifest.v1"),
    ("APP", "generation-approval.v1"),
    ("A", "activation.v1"),
    ("C", "connection.v1"),
    ("RQ", "request-context.v1"),
    ("U", "authority-context.v1"),
    ("CH", "challenge.v1"),
    ("RT", "runtime.v1"),
    ("EC", "evidence.v1"),
    ("AC", "accept.v1"),
    ("S", "accepted-session.v1"),
    ("REC", "accepted-receipt.v1"),
    ("DC", "discovery.v1"),
    ("PC", "proceed.v1"),
    ("RC", "result.v1"),
)
MANAGED_DOMAIN_MAP = dict(MANAGED_DOMAINS)

IDENTITY_GRAPH: Mapping[str, tuple[str, ...]] = {
    "AR": (),
    "HK": (),
    "TP": (),
    "DI": (),
    "IP": (),
    "X": (),
    "B": (),
    "FD": (),
    "AV": (),
    "LM": (),
    "P": (),
    "Q": (),
    "NC": (),
    "I": ("TP",),
    "ET": ("I",),
    "EA": ("ET",),
    "L": ("P", "AR"),
    "O": ("B",),
    "SUP": ("DI", "IP"),
    "CUS": ("DI", "IP"),
    "DIS": ("DI", "IP"),
    "BST": ("DI", "IP"),
    "BRK": ("DI", "IP"),
    "AGT": ("DI", "IP"),
    "V": (),
    "QS": ("I", "V", "X", "Q", "P", "L", "O", "B", "SUP", "CUS", "DIS", "BST", "BRK", "AGT"),
    "BQ": ("B", "QS"),
    "G": ("I", "V", "X", "Q", "P", "L", "BQ"),
    "M": (),
    "APP": ("I", "G", "L"),
    "A": ("I", "G", "EA"),
    "C": ("A",),
    "RQ": (),
    "U": ("RQ",),
    "CH": ("C", "A"),
    "RT": (),
    "EC": ("CH",),
    "AC": (),
    "S": ("I", "EA", "A", "G", "C", "U", "EC", "AC"),
    "REC": ("S", "AC"),
    "DC": ("S",),
    "PC": ("S",),
    "RC": ("S", "PC"),
}


def assert_domain_uniqueness() -> None:
    domains = [domain for _, domain in MANAGED_DOMAINS]
    if len(domains) != 43 or len(set(domains)) != len(domains):
        raise IdentityError("managed-domain-uniqueness")


def assert_identity_graph_acyclic(graph: Mapping[str, Sequence[str]] = IDENTITY_GRAPH) -> None:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visiting:
            raise IdentityError("identity-cycle")
        if node in visited:
            return
        visiting.add(node)
        for dependency in graph.get(node, ()):
            if dependency == node:
                raise IdentityError("identity-self-reference")
            visit(dependency)
        visiting.remove(node)
        visited.add(node)

    for node in graph:
        visit(node)


def reject_self_reference(graph: Mapping[str, Sequence[str]]) -> None:
    assert_identity_graph_acyclic(graph)


def canonical_filename_octets(value: str) -> bytes:
    if not isinstance(value, str) or not value or value.endswith("="):
        raise BoundaryError("filename-base64url-shape")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value, re.ASCII):
        raise BoundaryError("filename-base64url-alphabet")
    try:
        padded = value + "=" * ((4 - len(value) % 4) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as error:
        raise BoundaryError("filename-base64url-invalid") from error
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise BoundaryError("filename-base64url-not-canonical")
    return raw


def _hex32(value: bytes, label: str) -> str:
    try:
        return _raw_bytes(value, 32, label).hex()
    except IdentityError:
        raise


def build_restore_begin(
    discovery_frame_hash_raw32: bytes,
    accepted_session_raw32: bytes,
    transition_store: StoreWire,
    evidence_store: StoreWire,
    consumed_record_commitment: str,
) -> bytes:
    if transition_store.schema_id != "restore-ledger-transition-data.v2":
        raise ProtocolError("restore-begin-transition-schema")
    if evidence_store.schema_id != "restore-begin-evidence.v2":
        raise ProtocolError("restore-begin-evidence-schema")
    strict_store_digest(consumed_record_commitment)
    value = [
        "RESTORE_BEGIN",
        2,
        MANAGED_SCHEMA,
        _hex32(discovery_frame_hash_raw32, "discovery-frame-hash"),
        _hex32(accepted_session_raw32, "accepted-session"),
        transition_store.envelope(),
        evidence_store.envelope(),
        consumed_record_commitment,
    ]
    return managed_json(value)


def build_proceed(
    accepted_session_raw32: bytes,
    transition_id_text: str,
    transition_data_commitment: str,
    restore_begin_frame_hash_raw32: bytes,
) -> tuple[bytes, bytes]:
    if TRANSITION_ID_RE.fullmatch(transition_id_text) is None:
        raise ProtocolError("proceed-transition-id")
    transition_digest = strict_store_digest(transition_data_commitment)
    restore_hash = _raw_bytes(restore_begin_frame_hash_raw32, 32, "restore-begin-frame-hash")
    session = _raw_bytes(accepted_session_raw32, 32, "accepted-session")
    pc = managed_hash("proceed.v1", session, transition_id_text.encode("ascii"), transition_digest, restore_hash)
    value = [
        "PROCEED",
        2,
        MANAGED_SCHEMA,
        restore_hash.hex(),
        session.hex(),
        transition_id_text,
        transition_data_commitment,
        restore_hash.hex(),
        pc.hex(),
    ]
    return managed_json(value), pc


def build_result(
    accepted_session_raw32: bytes,
    transition_id_text: str,
    proceed_frame_hash_raw32: bytes,
    proceed_commitment_raw32: bytes,
    result_store: StoreWire,
) -> tuple[bytes, bytes]:
    if result_store.schema_id != "swz-recovery-result.v2":
        raise ProtocolError("result-schema")
    if TRANSITION_ID_RE.fullmatch(transition_id_text) is None:
        raise ProtocolError("result-transition-id")
    session = _raw_bytes(accepted_session_raw32, 32, "accepted-session")
    proceed_hash = _raw_bytes(proceed_frame_hash_raw32, 32, "proceed-frame-hash")
    pc = _raw_bytes(proceed_commitment_raw32, 32, "proceed-commitment")
    rc = managed_hash("result.v1", session, transition_id_text.encode("ascii"), pc, result_store.store_bytes)
    value = [
        "RESULT",
        2,
        MANAGED_SCHEMA,
        proceed_hash.hex(),
        session.hex(),
        transition_id_text,
        pc.hex(),
        result_store.envelope(),
        rc.hex(),
    ]
    return managed_json(value), rc


@dataclass(frozen=True)
class Frame:
    direction: int
    message: int
    sequence: int
    nonce: bytes
    payload: bytes
    raw: bytes

    @property
    def name(self) -> str:
        return MESSAGE_NAMES[self.message]


def frame_hash(frame_bytes: bytes) -> bytes:
    if not isinstance(frame_bytes, bytes) or len(frame_bytes) < FRAME_HEADER_BYTES:
        raise ProtocolError("frame-hash-input")
    return hashlib.sha256(frame_bytes).digest()


def build_frame(direction: int, message_name: str, sequence: int, nonce: bytes, payload: bytes) -> bytes:
    if direction not in {DIRECTION_LOCAL_TO_REMOTE, DIRECTION_REMOTE_TO_LOCAL}:
        raise ProtocolError("frame-direction")
    if message_name not in MESSAGE_BY_NAME:
        raise ProtocolError("frame-message")
    if type(sequence) is not int or sequence < 0:
        raise ProtocolError("frame-sequence")
    nonce = _raw_bytes(nonce, 32, "frame-nonce")
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_CONTROL_PAYLOAD_BYTES:
        raise ProtocolError("frame-payload")
    if FRAME_HEADER_BYTES + len(payload) > MAX_FRAME_BYTES:
        raise ProtocolError("frame-size")
    message = MESSAGE_BY_NAME[message_name]
    header = FRAME_HEADER.pack(
        SWZFRM02_MAGIC,
        SWZFRM02_VERSION,
        direction,
        message,
        SWZFRM02_FLAGS,
        sequence,
        nonce,
        len(payload),
    )
    return header + payload


def decode_frame(frame: bytes) -> Frame:
    if not isinstance(frame, bytes) or len(frame) < FRAME_HEADER_BYTES or len(frame) > MAX_FRAME_BYTES:
        raise ProtocolError("frame-size")
    try:
        magic, version, direction, message, flags, sequence, nonce, length = FRAME_HEADER.unpack(frame[:FRAME_HEADER_BYTES])
    except struct.error as error:
        raise ProtocolError("frame-header") from error
    if (
        magic != SWZFRM02_MAGIC
        or version != SWZFRM02_VERSION
        or direction not in {DIRECTION_LOCAL_TO_REMOTE, DIRECTION_REMOTE_TO_LOCAL}
        or message not in MESSAGE_NAMES
        or flags != SWZFRM02_FLAGS
        or length > MAX_CONTROL_PAYLOAD_BYTES
        or FRAME_HEADER_BYTES + length != len(frame)
    ):
        raise ProtocolError("frame-header")
    payload = frame[FRAME_HEADER_BYTES:]
    parse_managed_json(payload)
    return Frame(direction, message, sequence, nonce, payload, frame)


def validate_store_position(value: Any, *, managed: bool) -> bytes:
    if managed:
        return managed_digest(value)
    return strict_store_digest(value)


class GenerationState(str, Enum):
    OFFLINE = "OFFLINE"
    QUALIFIED = "QUALIFIED"
    ACTIVE = "ACTIVE"
    DRAINING = "DRAINING"
    RETIRING = "RETIRING"


GENERATION_TRANSITIONS: Mapping[GenerationState, frozenset[GenerationState]] = {
    GenerationState.OFFLINE: frozenset({GenerationState.QUALIFIED}),
    GenerationState.QUALIFIED: frozenset({GenerationState.ACTIVE}),
    GenerationState.ACTIVE: frozenset({GenerationState.DRAINING}),
    GenerationState.DRAINING: frozenset({GenerationState.RETIRING}),
    GenerationState.RETIRING: frozenset({GenerationState.OFFLINE}),
}


@dataclass
class GenerationLifecycle:
    state: GenerationState = GenerationState.OFFLINE

    def advance(self, target: GenerationState) -> None:
        if target not in GENERATION_TRANSITIONS[self.state]:
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


ADMISSION_TRANSITIONS: Mapping[AdmissionState, frozenset[AdmissionState]] = {
    AdmissionState.ACCEPTED_SOCKET: frozenset({AdmissionState.SSH_AUTHENTICATED, AdmissionState.FAILED}),
    AdmissionState.SSH_AUTHENTICATED: frozenset({AdmissionState.BOOTSTRAP, AdmissionState.FAILED}),
    AdmissionState.BOOTSTRAP: frozenset({AdmissionState.CHALLENGE, AdmissionState.FAILED}),
    AdmissionState.CHALLENGE: frozenset({AdmissionState.EVIDENCE, AdmissionState.FAILED}),
    AdmissionState.EVIDENCE: frozenset({AdmissionState.CONTROLLER_VALIDATED, AdmissionState.FAILED}),
    AdmissionState.CONTROLLER_VALIDATED: frozenset({AdmissionState.ACCEPT_SENT, AdmissionState.FAILED}),
    AdmissionState.ACCEPT_SENT: frozenset({AdmissionState.REMOTE_ACCEPTED, AdmissionState.FAILED}),
    AdmissionState.REMOTE_ACCEPTED: frozenset({AdmissionState.OPERATIONAL, AdmissionState.FAILED}),
    AdmissionState.OPERATIONAL: frozenset({AdmissionState.FAILED}),
    AdmissionState.FAILED: frozenset(),
}


@dataclass
class AdmissionLifecycle:
    state: AdmissionState = AdmissionState.ACCEPTED_SOCKET
    failure_code: str | None = None

    def advance(self, target: AdmissionState) -> None:
        if target not in ADMISSION_TRANSITIONS[self.state]:
            raise StateTransitionError(f"admission:{self.state}->{target}")
        self.state = target

    def fail(self, code: str) -> None:
        if self.state == AdmissionState.FAILED:
            raise StateTransitionError("admission:already-failed")
        self.failure_code = code
        self.state = AdmissionState.FAILED


class BrokerState(str, Enum):
    REMOTE_ACCEPTED = "REMOTE_ACCEPTED"
    DISCOVERY = "DISCOVERY"
    CAS_A = "CAS_A"
    RESTORE_BEGIN_DURABLE = "RESTORE_BEGIN_DURABLE"
    PROCEED = "PROCEED"
    HALF_CLOSED = "HALF_CLOSED"
    REMOTE_EOF = "REMOTE_EOF"
    RESTORE_AUTHORIZED = "RESTORE_AUTHORIZED"
    RESULT = "RESULT"
    FINAL = "FINAL"
    CONSUMED_UNCERTAINTY = "CONSUMED_UNCERTAINTY"


BROKER_TRANSITIONS: Mapping[BrokerState, frozenset[BrokerState]] = {
    BrokerState.REMOTE_ACCEPTED: frozenset({BrokerState.DISCOVERY, BrokerState.CONSUMED_UNCERTAINTY}),
    BrokerState.DISCOVERY: frozenset({BrokerState.CAS_A, BrokerState.CONSUMED_UNCERTAINTY}),
    BrokerState.CAS_A: frozenset({BrokerState.RESTORE_BEGIN_DURABLE, BrokerState.CONSUMED_UNCERTAINTY}),
    BrokerState.RESTORE_BEGIN_DURABLE: frozenset({BrokerState.PROCEED, BrokerState.CONSUMED_UNCERTAINTY}),
    BrokerState.PROCEED: frozenset({BrokerState.HALF_CLOSED, BrokerState.CONSUMED_UNCERTAINTY}),
    BrokerState.HALF_CLOSED: frozenset({BrokerState.REMOTE_EOF, BrokerState.CONSUMED_UNCERTAINTY}),
    BrokerState.REMOTE_EOF: frozenset({BrokerState.RESTORE_AUTHORIZED, BrokerState.CONSUMED_UNCERTAINTY}),
    BrokerState.RESTORE_AUTHORIZED: frozenset({BrokerState.RESULT, BrokerState.CONSUMED_UNCERTAINTY}),
    BrokerState.RESULT: frozenset({BrokerState.FINAL, BrokerState.CONSUMED_UNCERTAINTY}),
    BrokerState.FINAL: frozenset(),
    BrokerState.CONSUMED_UNCERTAINTY: frozenset(),
}


@dataclass
class BrokerLifecycle:
    state: BrokerState = BrokerState.REMOTE_ACCEPTED
    half_close_count: int = 0

    def advance(self, target: BrokerState) -> None:
        if target not in BROKER_TRANSITIONS[self.state]:
            raise StateTransitionError(f"broker:{self.state}->{target}")
        if target == BrokerState.HALF_CLOSED:
            self.half_close_count += 1
            if self.half_close_count != 1:
                raise StateTransitionError("broker:duplicate-half-close")
        self.state = target

    def consumed_uncertainty(self) -> None:
        if self.state in {BrokerState.FINAL, BrokerState.CONSUMED_UNCERTAINTY}:
            raise StateTransitionError("broker:terminal")
        self.state = BrokerState.CONSUMED_UNCERTAINTY


def test_identity_vector_inputs() -> dict[str, Any]:
    installation_uuid = bytes.fromhex("00112233445546778899aabbccddeeff")
    boot_uuid = bytes.fromhex("102132435465476798a9bacbdcedfe0f")
    admission = ed25519_public_blob(bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))
    host = ed25519_public_blob(bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"))
    controller = ed25519_public_blob(bytes.fromhex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"))
    endpoint = literal_endpoint_record("192.0.2.10")
    uidgid = bytes.fromhex("01000000020100000000000186a0000100000200000000000186a000010000")
    target_policy = bytes.fromhex("11" * 32)
    installation = installation_identity(installation_uuid, admission, host, controller, endpoint, uidgid, target_policy)
    endpoint_template = endpoint_template_identity(installation, endpoint)
    endpoint_actual = endpoint_actual_identity(endpoint_template, boot_uuid, 7, 11)
    return {
        "installation": installation,
        "endpoint_template": endpoint_template,
        "endpoint_actual": endpoint_actual,
        "endpoint_record": endpoint,
        "admission_blob": admission,
        "host_blob": host,
        "controller_blob": controller,
        "boot_uuid": boot_uuid,
        "uidgid_map": uidgid,
    }


assert_domain_uniqueness()
assert_identity_graph_acyclic()
