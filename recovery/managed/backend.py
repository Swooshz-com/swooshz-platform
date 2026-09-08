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
MESSAGE_BY_NAME = {name: number for number, name in MESSAGE_NAMES.items()}
COMMITMENT_PREFIX = "sha256:v1:"
MANAGED_HEX_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
STORE_COMMITMENT_RE = re.compile(r"sha256:v1:[0-9a-f]{64}\Z", re.ASCII)
TRANSITION_ID_RE = re.compile(r"restore-v2-[0-9a-f]{48}\Z", re.ASCII)
UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z",
    re.ASCII,
)


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
    for key, value in pairs:
        if key in result:
            raise CanonicalJSONError("duplicate-key")
        result[key] = value
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
    elif value is not None and type(value) not in (bool, int):
        raise CanonicalJSONError("value-type")


def managed_json(value: Any) -> bytes:
    _validate_managed_tree(value)
    try:
        encoded = (json.dumps(value, ensure_ascii=False, allow_nan=False,
                              separators=(",", ":")) + "\n").encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise CanonicalJSONError("json-encode") from error
    if len(encoded) > MAX_CONTROL_PAYLOAD_BYTES:
        raise CanonicalJSONError("json-size")
    return encoded


def parse_managed_json(payload: bytes) -> Any:
    if type(payload) is not bytes or not payload or len(payload) > MAX_CONTROL_PAYLOAD_BYTES:
        raise CanonicalJSONError("json-size")
    if not payload.endswith(b"\n") or payload.endswith(b"\n\n"):
        raise CanonicalJSONError("json-newline")
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


def _hex32(value: bytes, label: str) -> str:
    try:
        return managed_hex(_raw(value, 32, label))
    except IdentityError as error:
        raise ProtocolError(f"{label}-digest") from error


def build_restore_begin(session_raw32: bytes, discovery_frame_hash_raw32: bytes, transition_wire: StoreWire, evidence_wire: StoreWire, consumed_record_commitment: str) -> bytes:
    if transition_wire.schema_id != "restore-ledger-transition-data.v2" or evidence_wire.schema_id != "restore-begin-evidence.v2":
        raise ProtocolError("restore-begin-store-schema")
    strict_store_digest(consumed_record_commitment)
    return managed_json(["RESTORE_BEGIN", 2, MANAGED_SCHEMA, _hex32(discovery_frame_hash_raw32, "discovery-frame"), _hex32(session_raw32, "session"), transition_wire.envelope(), evidence_wire.envelope(), consumed_record_commitment])


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


def build_discovery(session_raw32: bytes, execution_row_id: int, artifact_filename: str, image_commitment: str, target_commitment: str, isolation_commitment: str, artifact_commitment: str, artifact_stream_commitment: str) -> tuple[bytes, bytes]:
    if type(execution_row_id) is not int or not 0 < execution_row_id <= 0xFFFFFFFFFFFFFFFF:
        raise ProtocolError("execution-row-id-invalid")
    raw_filename = canonical_filename_octets(artifact_filename)
    commitments = tuple(strict_store_digest(value) for value in (image_commitment, target_commitment, isolation_commitment, artifact_commitment, artifact_stream_commitment))
    session = _raw(session_raw32, 32, "session")
    discovery = managed_hash("discovery.v1", session, u64(execution_row_id), raw_filename, *commitments)
    encoded_filename = base64.urlsafe_b64encode(raw_filename).rstrip(b"=").decode("ascii")
    return managed_json(["DISCOVERY", 2, MANAGED_SCHEMA, session.hex(), str(execution_row_id), encoded_filename, image_commitment, target_commitment, isolation_commitment, artifact_commitment, artifact_stream_commitment, discovery.hex()]), discovery


@dataclass(frozen=True)
class Frame:
    direction: int
    message: str
    sequence: int
    nonce: bytes
    payload: bytes
    raw: bytes


def frame_hash(frame_bytes: bytes) -> bytes:
    if type(frame_bytes) is not bytes or not FRAME_HEADER_BYTES <= len(frame_bytes) <= MAX_FRAME_BYTES:
        raise ProtocolError("frame-hash-size")
    return hashlib.sha256(frame_bytes).digest()


def build_frame(direction: int, message_name: str, sequence: int, nonce: bytes, payload: bytes) -> bytes:
    if direction not in (DIRECTION_LOCAL_TO_REMOTE, DIRECTION_REMOTE_TO_LOCAL) or message_name not in MESSAGE_BY_NAME:
        raise ProtocolError("frame-route")
    if type(sequence) is not int or not 1 <= sequence <= MAX_SESSION_FRAMES:
        raise ProtocolError("frame-sequence")
    nonce = _raw(nonce, 32, "frame-nonce")
    if type(payload) is not bytes or not payload or len(payload) > MAX_CONTROL_PAYLOAD_BYTES:
        raise ProtocolError("frame-payload")
    if FRAME_HEADER_BYTES + len(payload) > MAX_FRAME_BYTES:
        raise ProtocolError("frame-size")
    return FRAME_HEADER.pack(SWZFRM02_MAGIC, SWZFRM02_VERSION, direction, MESSAGE_BY_NAME[message_name], SWZFRM02_FLAGS, sequence, nonce, len(payload)) + payload


def decode_frame(frame_bytes: bytes) -> Frame:
    if type(frame_bytes) is not bytes or len(frame_bytes) < FRAME_HEADER_BYTES:
        raise ProtocolError("frame-too-short")
    magic, version, direction, message_id, flags, sequence, nonce, payload_length = FRAME_HEADER.unpack(frame_bytes[:FRAME_HEADER_BYTES])
    if magic != SWZFRM02_MAGIC or version != SWZFRM02_VERSION or flags != SWZFRM02_FLAGS:
        raise ProtocolError("frame-header")
    if direction not in (DIRECTION_LOCAL_TO_REMOTE, DIRECTION_REMOTE_TO_LOCAL) or message_id not in MESSAGE_NAMES:
        raise ProtocolError("frame-route")
    if not 1 <= sequence <= MAX_SESSION_FRAMES or payload_length > MAX_CONTROL_PAYLOAD_BYTES:
        raise ProtocolError("frame-limits")
    if len(frame_bytes) != FRAME_HEADER_BYTES + payload_length or payload_length == 0:
        raise ProtocolError("frame-trailing")
    payload = frame_bytes[FRAME_HEADER_BYTES:]
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
    "EVIDENCE_FIELDS", "FRAME_HEADER", "FRAME_HEADER_BYTES", "GenerationLifecycle", "GenerationState",
    "IDENTITY_FORMULA_MAP", "IDENTITY_GRAPH", "IdentityError", "IdentityVector", "MANAGED_DOMAINS",
    "MANAGED_SCHEMA", "MESSAGE_BY_NAME", "MESSAGE_NAMES", "MAX_CONTROL_PAYLOAD_BYTES", "MAX_FRAME_BYTES",
    "MAX_SESSION_BYTES", "MAX_SESSION_FRAMES", "RESULT_FIELDS", "STORE_MARKER", "STORE_PROFILES", "StoreWire",
    "StoreWireError", "TRANSITION_FIELDS", "TRANSITION_ID_RE", "activation_identity", "assert_domain_uniqueness",
    "assert_identity_graph_acyclic", "build_discovery", "build_frame", "build_proceed", "build_result",
    "build_restore_begin", "canonical_filename_octets", "decode_frame", "decode_store_wire", "ed25519_public_blob",
    "endpoint_actual_identity", "endpoint_template_identity", "frame_hash", "identity_vector", "installation_identity",
    "literal_endpoint_record", "lp", "managed_digest", "managed_hash", "managed_hex", "managed_json",
    "parse_managed_json", "reject_self_reference", "restore_artifact", "store_bytes", "store_commitment",
    "store_wire_record", "strict_store_digest", "test_identity_vector_inputs", "transition_id", "u8", "u16", "u32", "u64",
    "validate_retained_store_bytes", "ManagedDigest", "StoreDigest", "encode_store_wire",
]

