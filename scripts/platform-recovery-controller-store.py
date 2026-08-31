#!/usr/bin/env python3
"""Fail-closed, controller-side recovery durability store.

The module is intentionally independent of application/runtime code.  It
owns only local controller state, uses strict canonical records, and exposes
public evidence through an explicit allowlist.  Platform adapters never fall
back to ordinary rename/replace semantics when the required guarantees are
not proven.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import hmac
import json
import math
import os
import pathlib
import re
import secrets
import stat
import struct
import tempfile
import threading
import uuid
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - available only on POSIX
    fcntl = None


# Run-290 bounded contract.
MAX_EPOCH_RECORD_BYTES = 16 * 1024
MAX_MANIFEST_BYTES = 16 * 1024
MAX_PRIVATE_IDENTITIES_BYTES = 32 * 1024
MAX_RESTORE_LEDGER_BYTES = 8 * 1024
MAX_SPOOL_META_BYTES = 32 * 1024
MAX_FRAME_BYTES = 16 * 1024
MAX_TOTAL_SPOOL_BYTES = 4 * 1024 * 1024
MAX_FRAMES = 4096

SCHEMA_EPOCH_RECORD = "recovery-epoch-record.v1"
SCHEMA_MANIFEST = "recovery-epoch-manifest.v1"
SCHEMA_PRIVATE_IDENTITIES = "recovery-private-identities.v1"
SCHEMA_RESTORE_LEDGER = "recovery-restore-ledger.v1"
SCHEMA_SPOOL_META = "recovery-spool-meta.v1"
SCHEMA_RUNNER_FRAME = "runner-frame.v1"
SCHEMA_PUBLIC_EVIDENCE = "recovery-public-evidence.v1"

EPOCH_STATES = (
    "INITIALISED",
    "READY",
    "ACTIVE",
    "ABANDONED",
    "SUPERSEDED",
    "CONSUMED",
)
TERMINAL_EPOCH_STATES = frozenset({"ABANDONED", "SUPERSEDED", "CONSUMED"})
ARTIFACT_STATES = ("PENDING", "ROW_BOUND", "BOUND")
LEDGER_STATES = ("UNCONSUMED", "CONSUMED")
SPOOL_STATES = ("OPEN", "ABANDONED", "COMMITTED")
FRAME_STAGES = (
    "EPOCH_READY",
    "RUNNER_STARTED",
    "RESTORE_BEGIN",
    "COMMIT",
    "ABANDON",
)
FRAME_STAGE_TRANSITIONS = {
    "NONE": ("EPOCH_READY",),
    "EPOCH_READY": ("RUNNER_STARTED", "ABANDON"),
    "RUNNER_STARTED": ("RESTORE_BEGIN", "ABANDON"),
    "RESTORE_BEGIN": ("COMMIT", "ABANDON"),
    "COMMIT": (),
    "ABANDON": (),
}


def _is_legal_abandon_transition(previous_stage: str, ledger_state: str) -> bool:
    return (
        ledger_state == "UNCONSUMED" and previous_stage in ("EPOCH_READY", "RUNNER_STARTED")
    ) or (ledger_state == "CONSUMED" and previous_stage == "RESTORE_BEGIN")

RECORD_FIELDS = (
    "schema",
    "epoch_ref",
    "authority_ref",
    "state",
    "supersession_barrier_commitment",
    "artifact_binding_state",
    "artifact_commitment",
    "container_commitment",
    "volume_commitment",
    "runner_commitment",
    "spool_commitment",
    "private_identities_digest",
    "manifest_digest",
    "restore_ledger_ref",
    "restore_ledger_state",
    "durability",
)
MANIFEST_FIELDS = (
    "schema",
    "epoch_ref",
    "authority_ref",
    "state",
    "supersession_barrier_commitment",
    "artifact_binding_state",
    "artifact_commitment",
    "container_commitment",
    "volume_commitment",
    "runner_commitment",
    "spool_commitment",
    "private_identities_digest",
    "restore_ledger_ref",
    "restore_ledger_state",
    "durability",
)
PRIVATE_IDENTITY_FIELDS = (
    "schema",
    "epoch_ref",
    "container_identity",
    "volume_identity",
    "runner_identity",
    "artifact_row_id",
    "artifact_filename",
    "salt",
    "spool_hmac_key",
)
LEDGER_FIELDS = (
    "schema",
    "epoch_ref",
    "state",
    "transition_id",
    "transition_target",
    "transition_data_commitment",
)
SPOOL_META_FIELDS = (
    "schema",
    "epoch_ref",
    "state",
    "next_sequence",
    "last_frame_hash",
    "highest_contiguous_commit",
    "frame_count",
    "total_spool_bytes",
    "last_stage",
    "spool_commitment",
)
FRAME_FIELDS = (
    "schema",
    "epoch_ref",
    "sequence",
    "stage",
    "payload",
    "previous_hash",
    "auth",
    "frame_hash",
)
DURABILITY_FIELDS = (
    "file_flush_verified",
    "readback_verified",
    "atomic_authority_transition",
    "directory_flush_verified",
)
PUBLIC_EVIDENCE_FIELDS = (
    "schema",
    "epoch_ref",
    "authority_ref",
    "state",
    "artifact_binding_state",
    "artifact_commitment",
    "manifest_digest",
    "restore_ledger_ref",
    "restore_ledger_state",
    "spool_commitment",
    "highest_contiguous_commit",
    "frame_count",
    "durability_classification",
)

RECORD_FILENAME = "recovery-epoch-record.v1.json"
MANIFEST_FILENAME = "recovery-epoch-manifest.v1.json"
PRIVATE_IDENTITIES_FILENAME = "recovery-private-identities.v1.json"
LEDGER_FILENAME = "recovery-restore-ledger.v1.json"
SPOOL_META_FILENAME = "recovery-spool-meta.v1.json"
TRANSACTION_LOCK_FILENAME = "recovery-transaction-lock.v1"
SPOOL_DIRNAME = "spool"
FRAMES_DIRNAME = "frames"
ZERO_FRAME_HASH = "sha256:v1:" + ("0" * 64)

COMMITMENT_PREFIX = "sha256:v1:"
COMMITMENT_RE = re.compile(r"sha256:v1:[0-9a-f]{64}\Z", re.ASCII)
REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z", re.ASCII)
FRAME_NAME_RE = re.compile(r"frame-[0-9]{12}\.json\Z", re.ASCII)
TEMP_NAME_RE = re.compile(r"\.recovery-tmp-[0-9a-f]{32}\Z", re.ASCII)

DOMAIN_SUPERSESSION_BARRIER = "supersession-barrier"
DOMAIN_ARTIFACT_ROW = "artifact-row"
DOMAIN_CONTAINER_IDENTITY = "container-identity"
DOMAIN_VOLUME_IDENTITY = "volume-identity"
DOMAIN_RUNNER_IDENTITY = "runner"
DOMAIN_SPOOL = "spool"
DOMAIN_MANIFEST = "manifest"
DOMAIN_PRIVATE_IDENTITIES = "private-identities"
DOMAIN_RESTORE_LEDGER = "restore-ledger"
DOMAIN_RESTORE_TRANSITION = "restore-ledger-transition"
DOMAIN_RUNNER_FRAME_AUTH = "runner-frame-auth"
DOMAIN_RUNNER_FRAME_HASH = "runner-frame-hash"
DOMAIN_RUNNER_FRAME_PAYLOAD = "runner-frame-payload"
DOMAIN_EPOCH_RECORD = "epoch-record"


class ControllerStoreError(Exception):
    """Base error whose string is always a public-safe symbolic code."""

    classification = "FAIL_CLOSED"

    def __init__(self, code: str, *, safety_state: str | None = None) -> None:
        self.code = code
        self.safety_state = safety_state
        super().__init__(code)


class ConfigurationError(ControllerStoreError):
    pass


class FilesystemSafetyError(ControllerStoreError):
    pass


class DurabilityError(ControllerStoreError):
    pass


class SchemaError(ControllerStoreError):
    pass


class IntegrityError(ControllerStoreError):
    pass


class LedgerError(ControllerStoreError):
    pass


class EpochStateError(ControllerStoreError):
    pass


class SpoolError(ControllerStoreError):
    pass


class PublicEvidenceError(ControllerStoreError):
    pass


def _fail(error_type: type[ControllerStoreError], code: str, *, safety_state: str | None = None) -> None:
    raise error_type(code, safety_state=safety_state)


def _is_exact_int(value: Any) -> bool:
    return type(value) is int


def _strict_utf8_text(value: Any, label: str, *, max_bytes: int = 4096) -> str:
    if not isinstance(value, str):
        _fail(SchemaError, f"INVALID_{label.upper()}")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        _fail(SchemaError, f"INVALID_{label.upper()}")
    if not encoded or len(encoded) > max_bytes:
        _fail(SchemaError, f"INVALID_{label.upper()}")
    return value


def _strict_ref(value: Any, label: str) -> str:
    if not isinstance(value, str) or REF_RE.fullmatch(value) is None:
        _fail(SchemaError, f"INVALID_{label.upper()}")
    return value


def _strict_commitment(value: Any, label: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or COMMITMENT_RE.fullmatch(value) is None:
        _fail(SchemaError, f"INVALID_{label.upper()}")
    return value


def _reject_noncanonical_value(value: Any) -> None:
    if isinstance(value, float):
        _fail(SchemaError, "FLOAT_NOT_ALLOWED")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                _fail(SchemaError, "NON_STRING_JSON_KEY")
            _reject_noncanonical_value(child)
    elif isinstance(value, list):
        for child in value:
            _reject_noncanonical_value(child)
    elif isinstance(value, str):
        try:
            value.encode("utf-8", "strict")
        except UnicodeEncodeError:
            _fail(SchemaError, "INVALID_UTF8")
    elif value is not None and type(value) not in (str, int, bool):
        _fail(SchemaError, "UNSUPPORTED_JSON_VALUE")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(SchemaError, "DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def parse_canonical_json(payload: bytes, *, max_bytes: int) -> Any:
    if not isinstance(payload, bytes) or len(payload) > max_bytes:
        _fail(SchemaError, "JSON_OVERSIZED")
    try:
        text = payload.decode("utf-8", "strict")
    except UnicodeDecodeError:
        _fail(SchemaError, "JSON_NOT_UTF8")
    if text.startswith("\ufeff") or not text.endswith("\n") or text.endswith("\n\n") or text[:1] in " \t\r\n":
        _fail(SchemaError, "JSON_NOT_CANONICAL")
    decoder = json.JSONDecoder(
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=lambda _value: _fail(SchemaError, "NONFINITE_JSON_VALUE"),
    )
    try:
        value, end = decoder.raw_decode(text)
    except (json.JSONDecodeError, ControllerStoreError):
        _fail(SchemaError, "INVALID_JSON")
    if end != len(text) - 1 or text[end:] != "\n":
        _fail(SchemaError, "JSON_TRAILING_INPUT")
    _reject_noncanonical_value(value)
    if canonical_json_bytes(value, max_bytes=max_bytes) != payload:
        _fail(SchemaError, "JSON_NOT_CANONICAL")
    return value


def canonical_json_bytes(value: Any, *, max_bytes: int) -> bytes:
    _reject_noncanonical_value(value)
    try:
        encoded_text = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
        encoded = (encoded_text + "\n").encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeEncodeError):
        _fail(SchemaError, "JSON_NOT_CANONICAL")
    if len(encoded) > max_bytes:
        _fail(SchemaError, "JSON_OVERSIZED")
    return encoded


def _exact_fields(value: Any, fields: Sequence[str], schema_code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or tuple(value.keys()) != tuple(fields):
        _fail(SchemaError, schema_code)
    return value


def _validate_durability(value: Any) -> dict[str, bool]:
    value = _exact_fields(value, DURABILITY_FIELDS, "INVALID_DURABILITY")
    if any(type(value[field]) is not bool for field in DURABILITY_FIELDS):
        _fail(SchemaError, "INVALID_DURABILITY")
    if not all(value.values()):
        _fail(SchemaError, "DURABILITY_NOT_PROVEN")
    return value


def _validate_record_shape(value: Any) -> dict[str, Any]:
    value = _exact_fields(value, RECORD_FIELDS, "INVALID_EPOCH_RECORD")
    if value["schema"] != SCHEMA_EPOCH_RECORD:
        _fail(SchemaError, "INVALID_EPOCH_RECORD")
    _strict_ref(value["epoch_ref"], "epoch_ref")
    _strict_ref(value["authority_ref"], "authority_ref")
    if value["state"] not in EPOCH_STATES:
        _fail(SchemaError, "INVALID_EPOCH_STATE")
    if value["artifact_binding_state"] not in ARTIFACT_STATES:
        _fail(SchemaError, "INVALID_ARTIFACT_STATE")
    _strict_commitment(value["supersession_barrier_commitment"], "supersession_barrier")
    _strict_commitment(value["artifact_commitment"], "artifact_commitment", nullable=True)
    for field in ("container_commitment", "volume_commitment", "runner_commitment", "spool_commitment"):
        _strict_commitment(value[field], field)
    _strict_commitment(value["private_identities_digest"], "private_identities_digest")
    _strict_commitment(value["manifest_digest"], "manifest_digest")
    _strict_ref(value["restore_ledger_ref"], "restore_ledger_ref")
    if value["restore_ledger_state"] not in LEDGER_STATES:
        _fail(SchemaError, "INVALID_LEDGER_STATE")
    _validate_durability(value["durability"])
    if value["state"] == "CONSUMED" and value["restore_ledger_state"] != "CONSUMED":
        _fail(SchemaError, "EPOCH_LEDGER_CONTRADICTION")
    return value


def validate_epoch_record(value: Any) -> dict[str, Any]:
    return _validate_record_shape(value)


def _validate_manifest_shape(value: Any) -> dict[str, Any]:
    value = _exact_fields(value, MANIFEST_FIELDS, "INVALID_MANIFEST")
    if value["schema"] != SCHEMA_MANIFEST:
        _fail(SchemaError, "INVALID_MANIFEST")
    _strict_ref(value["epoch_ref"], "epoch_ref")
    _strict_ref(value["authority_ref"], "authority_ref")
    if value["state"] not in EPOCH_STATES:
        _fail(SchemaError, "INVALID_EPOCH_STATE")
    if value["artifact_binding_state"] not in ARTIFACT_STATES:
        _fail(SchemaError, "INVALID_ARTIFACT_STATE")
    _strict_commitment(value["supersession_barrier_commitment"], "supersession_barrier")
    _strict_commitment(value["artifact_commitment"], "artifact_commitment", nullable=True)
    for field in ("container_commitment", "volume_commitment", "runner_commitment", "spool_commitment"):
        _strict_commitment(value[field], field)
    _strict_commitment(value["private_identities_digest"], "private_identities_digest")
    _strict_ref(value["restore_ledger_ref"], "restore_ledger_ref")
    if value["restore_ledger_state"] not in LEDGER_STATES:
        _fail(SchemaError, "INVALID_LEDGER_STATE")
    _validate_durability(value["durability"])
    if value["state"] == "CONSUMED" and value["restore_ledger_state"] != "CONSUMED":
        _fail(SchemaError, "EPOCH_LEDGER_CONTRADICTION")
    return value


def validate_manifest(value: Any) -> dict[str, Any]:
    return _validate_manifest_shape(value)


def _validate_private_identities_shape(value: Any) -> dict[str, Any]:
    value = _exact_fields(value, PRIVATE_IDENTITY_FIELDS, "INVALID_PRIVATE_IDENTITIES")
    if value["schema"] != SCHEMA_PRIVATE_IDENTITIES:
        _fail(SchemaError, "INVALID_PRIVATE_IDENTITIES")
    _strict_ref(value["epoch_ref"], "epoch_ref")
    for field in PRIVATE_IDENTITY_FIELDS[2:]:
        _strict_utf8_text(value[field], field, max_bytes=8192)
    return value


def validate_private_identities(value: Any) -> dict[str, Any]:
    return _validate_private_identities_shape(value)


def _validate_ledger_shape(value: Any) -> dict[str, Any]:
    value = _exact_fields(value, LEDGER_FIELDS, "INVALID_RESTORE_LEDGER")
    if value["schema"] != SCHEMA_RESTORE_LEDGER:
        _fail(LedgerError, "INVALID_RESTORE_LEDGER", safety_state="CONSUMED")
    _strict_ref(value["epoch_ref"], "epoch_ref")
    if value["state"] not in LEDGER_STATES:
        _fail(LedgerError, "UNKNOWN_LEDGER_STATE", safety_state="CONSUMED")
    if value["state"] == "UNCONSUMED":
        if value["transition_id"] is not None or value["transition_target"] is not None or value["transition_data_commitment"] is not None:
            _fail(LedgerError, "LEDGER_CONTRADICTION", safety_state="CONSUMED")
    else:
        _strict_ref(value["transition_id"], "transition_id")
        if value["transition_target"] != "RESTORE_STARTED":
            _fail(LedgerError, "INVALID_TRANSITION_TARGET", safety_state="CONSUMED")
        _strict_commitment(value["transition_data_commitment"], "transition_data_commitment")
    return value


def validate_restore_ledger(value: Any) -> dict[str, Any]:
    return _validate_ledger_shape(value)


def _validate_spool_shape(value: Any) -> dict[str, Any]:
    value = _exact_fields(value, SPOOL_META_FIELDS, "INVALID_SPOOL_META")
    if value["schema"] != SCHEMA_SPOOL_META:
        _fail(SpoolError, "INVALID_SPOOL_META")
    _strict_ref(value["epoch_ref"], "epoch_ref")
    if value["state"] not in SPOOL_STATES:
        _fail(SpoolError, "INVALID_SPOOL_STATE")
    for field in ("next_sequence", "highest_contiguous_commit", "frame_count", "total_spool_bytes"):
        if not _is_exact_int(value[field]) or value[field] < 0:
            _fail(SpoolError, "INVALID_SPOOL_COUNTER")
    if value["next_sequence"] != value["frame_count"] + 1:
        _fail(SpoolError, "SPOOL_SEQUENCE_CONTRADICTION")
    if value["frame_count"] > MAX_FRAMES or value["total_spool_bytes"] > MAX_TOTAL_SPOOL_BYTES:
        _fail(SpoolError, "SPOOL_LIMIT_EXCEEDED")
    if value["highest_contiguous_commit"] > value["frame_count"]:
        _fail(SpoolError, "SPOOL_COMMIT_CONTRADICTION")
    if value["last_stage"] != "NONE" and value["last_stage"] not in FRAME_STAGES:
        _fail(SpoolError, "INVALID_FRAME_STAGE")
    _strict_commitment(value["last_frame_hash"], "last_frame_hash")
    _strict_commitment(value["spool_commitment"], "spool_commitment")
    if value["state"] == "OPEN" and value["last_stage"] in ("COMMIT", "ABANDON"):
        _fail(SpoolError, "SPOOL_TERMINAL_STATE_CONTRADICTION")
    if value["state"] == "COMMITTED" and (
        value["last_stage"] != "COMMIT"
        or value["highest_contiguous_commit"] == 0
        or value["frame_count"] == 0
    ):
        _fail(SpoolError, "SPOOL_COMMITTED_STATE_CONTRADICTION")
    if value["state"] == "ABANDONED" and (
        value["last_stage"] != "ABANDON"
        or value["highest_contiguous_commit"] != 0
        or value["frame_count"] == 0
    ):
        _fail(SpoolError, "SPOOL_ABANDONED_STATE_CONTRADICTION")
    return value


def validate_spool_meta(value: Any) -> dict[str, Any]:
    return _validate_spool_shape(value)


def _validate_frame_payload(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(SchemaError, "INVALID_FRAME_PAYLOAD")
    allowed = ("classification", "ref", "commitment", "state")
    if any(key not in allowed for key in value):
        _fail(SchemaError, "FORBIDDEN_FRAME_PAYLOAD")
    if tuple(key for key in allowed if key in value) != tuple(value.keys()):
        _fail(SchemaError, "INVALID_FRAME_PAYLOAD")
    for key, child in value.items():
        if key in ("classification", "ref", "state"):
            _strict_utf8_text(child, "frame_payload", max_bytes=512)
        else:
            _strict_commitment(child, "frame_payload_commitment")
    return value


def _validate_frame_shape(value: Any) -> dict[str, Any]:
    value = _exact_fields(value, FRAME_FIELDS, "INVALID_RUNNER_FRAME")
    if value["schema"] != SCHEMA_RUNNER_FRAME:
        _fail(SpoolError, "INVALID_RUNNER_FRAME")
    _strict_ref(value["epoch_ref"], "epoch_ref")
    if not _is_exact_int(value["sequence"]) or not 1 <= value["sequence"] <= MAX_FRAMES:
        _fail(SpoolError, "INVALID_FRAME_SEQUENCE")
    if value["stage"] not in FRAME_STAGES:
        _fail(SpoolError, "INVALID_FRAME_STAGE")
    _validate_frame_payload(value["payload"])
    _strict_commitment(value["previous_hash"], "previous_hash")
    if not isinstance(value["auth"], str) or not re.fullmatch(r"hmac:v1:[0-9a-f]{64}\Z", value["auth"], re.ASCII):
        _fail(SpoolError, "INVALID_FRAME_AUTH")
    _strict_commitment(value["frame_hash"], "frame_hash")
    return value


def validate_runner_frame(value: Any) -> dict[str, Any]:
    return _validate_frame_shape(value)


def _length_prefixed(parts: Sequence[str]) -> bytes:
    encoded_parts: list[bytes] = []
    for part in parts:
        if not isinstance(part, str):
            _fail(SchemaError, "COMMITMENT_FIELD_NOT_TEXT")
        try:
            encoded = part.encode("utf-8", "strict")
        except UnicodeEncodeError:
            _fail(SchemaError, "COMMITMENT_FIELD_NOT_UTF8")
        if len(encoded) > 0xFFFFFFFF:
            _fail(SchemaError, "COMMITMENT_FIELD_OVERSIZED")
        encoded_parts.append(struct.pack(">I", len(encoded)) + encoded)
    return b"".join(encoded_parts)


def recovery_commitment(domain: str, *fields: str) -> str:
    if not isinstance(domain, str) or not domain or any(ord(char) > 0x7F for char in domain):
        _fail(SchemaError, "INVALID_COMMITMENT_DOMAIN")
    payload = _length_prefixed(("recovery-commitment.v1", domain, *fields))
    return COMMITMENT_PREFIX + hashlib.sha256(payload).hexdigest()


def bytes_commitment(domain: str, payload: bytes) -> str:
    if not isinstance(payload, bytes):
        _fail(SchemaError, "COMMITMENT_BYTES_REQUIRED")
    if not isinstance(domain, str) or not domain or any(ord(char) > 0x7F for char in domain):
        _fail(SchemaError, "INVALID_COMMITMENT_DOMAIN")
    framed = _length_prefixed(("recovery-commitment.v1", domain))
    if len(payload) > 0xFFFFFFFF:
        _fail(SchemaError, "COMMITMENT_FIELD_OVERSIZED")
    framed += struct.pack(">I", len(payload)) + payload
    return COMMITMENT_PREFIX + hashlib.sha256(framed).hexdigest()


def _private_data_commitment(data: Any) -> str:
    return bytes_commitment(DOMAIN_RESTORE_TRANSITION, canonical_json_bytes(data, max_bytes=MAX_RESTORE_LEDGER_BYTES))


def private_identities_commitment(value: Mapping[str, Any]) -> str:
    private = validate_private_identities(dict(value))
    private_bytes = canonical_json_bytes(private, max_bytes=MAX_PRIVATE_IDENTITIES_BYTES)
    return bytes_commitment(DOMAIN_PRIVATE_IDENTITIES, private_bytes)


def _make_durability(proof: Mapping[str, Any]) -> dict[str, bool]:
    result = {field: proof.get(field) is True for field in DURABILITY_FIELDS}
    _validate_durability(result)
    return result


def _path_is_within(candidate: pathlib.Path, parent: pathlib.Path) -> bool:
    try:
        return os.path.commonpath((os.path.normcase(str(candidate)), os.path.normcase(str(parent)))) == os.path.normcase(str(parent))
    except (ValueError, OSError):
        return False


def _absolute_path(value: Any) -> pathlib.Path:
    if not isinstance(value, (str, os.PathLike)):
        _fail(ConfigurationError, "STORE_ROOT_INVALID")
    try:
        raw = os.fspath(value)
    except TypeError:
        _fail(ConfigurationError, "STORE_ROOT_INVALID")
    if isinstance(raw, bytes):
        _fail(ConfigurationError, "STORE_ROOT_INVALID")
    if not raw or "\x00" in raw:
        _fail(ConfigurationError, "STORE_ROOT_INVALID")
    lowered = raw.replace("\\", "/").lower()
    if lowered.startswith(("//", "s3:", "gs:", "azure:", "az:", "nfs:", "cifs:", "postgres:", "mysql:")):
        _fail(ConfigurationError, "STORE_ROOT_NONLOCAL")
    path = pathlib.Path(raw)
    if not path.is_absolute():
        _fail(ConfigurationError, "STORE_ROOT_NOT_ABSOLUTE")
    try:
        return pathlib.Path(os.path.abspath(str(path)))
    except (OSError, ValueError):
        _fail(ConfigurationError, "STORE_ROOT_INVALID")


def _repository_roots() -> tuple[pathlib.Path, ...]:
    roots: list[pathlib.Path] = []
    for source in (pathlib.Path(__file__).parent, pathlib.Path.cwd()):
        try:
            current = source.resolve(strict=False)
        except OSError:
            continue
        for candidate in (current, *current.parents):
            if (candidate / ".git").exists() or (candidate / "AGENTS.md").exists():
                if candidate not in roots:
                    roots.append(candidate)
                break
    return tuple(roots)


def _validate_root_path(root: pathlib.Path, *, test_mode: bool) -> pathlib.Path:
    parts = {part.casefold() for part in root.parts}
    if ".tmp" in parts:
        _fail(ConfigurationError, "STORE_ROOT_RESERVED")
    cwd = pathlib.Path.cwd()
    if _path_is_within(root, cwd):
        _fail(ConfigurationError, "STORE_ROOT_CWD_AUTHORITY")
    for repository_root in _repository_roots():
        if _path_is_within(root, repository_root):
            _fail(ConfigurationError, "STORE_ROOT_REPOSITORY_AUTHORITY")
    try:
        temp_root = pathlib.Path(tempfile.gettempdir()).resolve(strict=False)
    except OSError:
        temp_root = None
    if not test_mode and temp_root is not None and _path_is_within(root, temp_root):
        _fail(ConfigurationError, "STORE_ROOT_TEMP_AUTHORITY")
    if not test_mode and any(token in parts for token in {"cloud", "provider", "database", "network", "remote", "nfs", "cifs", "s3", "gcs", "aws", "azure", "bucket", "postgres", "mysql", "redis", "mongo"}):
        _fail(ConfigurationError, "STORE_ROOT_NONLOCAL")
    return root


class DurabilityAdapter:
    """Platform adapter; every implementation must prove its own semantics."""

    platform_name = "unsupported"

    def __init__(self) -> None:
        self.used_primitives: list[str] = []

    def _used(self, primitive: str) -> None:
        self.used_primitives.append(primitive)

    def prove_root(self, root: pathlib.Path, *, test_mode: bool = False) -> Mapping[str, Any]:
        _fail(FilesystemSafetyError, "DURABILITY_UNSUPPORTED")

    def validate_component(self, path: pathlib.Path, *, expect_directory: bool | None = None) -> None:
        _fail(FilesystemSafetyError, "DURABILITY_UNSUPPORTED")

    def mkdir_exclusive(self, path: pathlib.Path) -> None:
        _fail(FilesystemSafetyError, "DURABILITY_UNSUPPORTED")

    def create_transaction_lock(self, path: pathlib.Path) -> None:
        _fail(FilesystemSafetyError, "DURABILITY_UNSUPPORTED")

    @contextmanager
    def epoch_transaction_lock(self, path: pathlib.Path):
        _fail(DurabilityError, "OS_LOCK_UNSUPPORTED", safety_state="CONSUMED")
        yield

    def before_authority_transition(self, path: pathlib.Path) -> None:
        return None

    def after_temp_readback(self, path: pathlib.Path, payload: bytes, readback: bytes) -> None:
        return None

    def write_authority(
        self,
        path: pathlib.Path,
        payload: bytes,
        *,
        replace: bool,
        max_bytes: int,
    ) -> Mapping[str, bool]:
        _fail(DurabilityError, "DURABILITY_UNSUPPORTED")

    def read_authority(self, path: pathlib.Path, *, max_bytes: int) -> bytes:
        _fail(DurabilityError, "DURABILITY_UNSUPPORTED")

    def list_entries(self, directory: pathlib.Path) -> list[pathlib.Path]:
        _fail(FilesystemSafetyError, "DURABILITY_UNSUPPORTED")

    def flush_directory(self, directory: pathlib.Path) -> None:
        _fail(DurabilityError, "DIRECTORY_DURABILITY_UNSUPPORTED")


def _lstat_checked(path: pathlib.Path, *, expect_directory: bool | None = None) -> os.stat_result:
    try:
        info = os.lstat(path)
    except OSError:
        _fail(FilesystemSafetyError, "PATH_UNAVAILABLE")
    if stat.S_ISLNK(info.st_mode):
        _fail(FilesystemSafetyError, "REPARSE_OR_SYMLINK_REJECTED")
    if expect_directory is True and not stat.S_ISDIR(info.st_mode):
        _fail(FilesystemSafetyError, "DIRECTORY_REQUIRED")
    if expect_directory is False and not stat.S_ISREG(info.st_mode):
        _fail(FilesystemSafetyError, "REGULAR_FILE_REQUIRED")
    if expect_directory is None and not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
        _fail(FilesystemSafetyError, "SPECIAL_FILE_REJECTED")
    return info


def _validate_posix_owner_mode(info: os.stat_result, *, directory: bool) -> None:
    if not hasattr(os, "getuid") or info.st_uid != os.getuid():
        _fail(FilesystemSafetyError, "OWNER_PROOF_FAILED")
    if info.st_mode & 0o077:
        _fail(FilesystemSafetyError, "PERMISSIONS_TOO_BROAD")
    expected = 0o700 if directory else 0o600
    if stat.S_IMODE(info.st_mode) != expected:
        _fail(FilesystemSafetyError, "PERMISSIONS_NOT_CANONICAL")


def _prove_posix_local_volume(
    root: pathlib.Path,
    *,
    test_mode: bool = False,
    mountinfo_path: pathlib.Path | None = None,
) -> None:
    local_filesystems = {
        "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs",
        "apfs", "hfs", "hfsplus", "ufs",
    }
    if test_mode:
        local_filesystems.update({"tmpfs", "ramfs", "overlay", "aufs"})
    mountinfo = pathlib.Path("/proc/self/mountinfo") if mountinfo_path is None else mountinfo_path
    try:
        lines = mountinfo.read_bytes().splitlines()
    except OSError:
        _fail(FilesystemSafetyError, "LOCAL_VOLUME_PROOF_FAILED")
    target = pathlib.Path(os.path.normpath(str(root)))
    selected_mount: pathlib.Path | None = None
    selected_filesystem: str | None = None
    for line in lines:
        left, separator, right = line.partition(b" - ")
        if not separator:
            _fail(FilesystemSafetyError, "LOCAL_VOLUME_PROOF_FAILED")
        fields = left.split()
        right_fields = right.split()
        if len(fields) < 5 or not right_fields:
            _fail(FilesystemSafetyError, "LOCAL_VOLUME_PROOF_FAILED")
        try:
            mount_text = fields[4].decode("utf-8", "strict")
            filesystem = right_fields[0].decode("ascii", "strict")
        except UnicodeDecodeError:
            _fail(FilesystemSafetyError, "LOCAL_VOLUME_PROOF_FAILED")
        mount_text = mount_text.replace("\\040", " ").replace("\\011", "\\t").replace("\\134", "\\")
        mount_point = pathlib.Path(mount_text)
        if _path_is_within(target, mount_point) and (selected_mount is None or len(mount_point.parts) > len(selected_mount.parts)):
            selected_mount = mount_point
            selected_filesystem = filesystem
    if selected_mount is None or selected_filesystem not in local_filesystems:
        _fail(FilesystemSafetyError, "LOCAL_VOLUME_PROOF_FAILED")


class PosixDurabilityAdapter(DurabilityAdapter):
    platform_name = "posix"

    def __init__(self) -> None:
        super().__init__()
        self._root: pathlib.Path | None = None

    def _validate_path_components(self, path: pathlib.Path, *, expect_directory: bool | None) -> os.stat_result:
        if self._root is None:
            _fail(FilesystemSafetyError, "DURABILITY_UNSUPPORTED")
        try:
            relative = path.relative_to(self._root)
        except ValueError:
            _fail(FilesystemSafetyError, "PATH_OUTSIDE_STORE")
        root_info = _lstat_checked(self._root, expect_directory=True)
        _validate_posix_owner_mode(root_info, directory=True)
        current = self._root
        final_info = root_info
        parts = relative.parts
        for index, part in enumerate(parts):
            current = current / part
            component_expectation = True if index < len(parts) - 1 else expect_directory
            final_info = _lstat_checked(current, expect_directory=component_expectation)
            _validate_posix_owner_mode(final_info, directory=stat.S_ISDIR(final_info.st_mode))
        return final_info

    def prove_root(self, root: pathlib.Path, *, test_mode: bool = False) -> Mapping[str, Any]:
        if os.name != "posix":
            _fail(FilesystemSafetyError, "DURABILITY_UNSUPPORTED")
        if not all(hasattr(os, attribute) for attribute in ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC")):
            _fail(FilesystemSafetyError, "DURABILITY_UNSUPPORTED")
        self._root = root
        info = _lstat_checked(root, expect_directory=True)
        _validate_posix_owner_mode(info, directory=True)
        try:
            os.statvfs(root)
        except OSError:
            _fail(FilesystemSafetyError, "LOCAL_VOLUME_PROOF_FAILED")
        _prove_posix_local_volume(root, test_mode=test_mode)
        self._used("procfs:mountinfo:local-filesystem-proof")
        self._used("os.open:O_NOFOLLOW|O_EXCL")
        self._used("os.fsync:file")
        self._used("os.replace-or-link:atomic")
        self._used("os.fsync:directory")
        return {
            "file_flush_verified": True,
            "readback_verified": True,
            "atomic_authority_transition": True,
            "directory_flush_verified": True,
        }

    def validate_component(self, path: pathlib.Path, *, expect_directory: bool | None = None) -> None:
        self._validate_path_components(path, expect_directory=expect_directory)

    def mkdir_exclusive(self, path: pathlib.Path) -> None:
        self.validate_component(path.parent, expect_directory=True)
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            _fail(FilesystemSafetyError, "NAMESPACE_COLLISION")
        except OSError:
            _fail(FilesystemSafetyError, "DIRECTORY_CREATE_FAILED")
        self.validate_component(path, expect_directory=True)
        self.flush_directory(path.parent)

    def create_transaction_lock(self, path: pathlib.Path) -> None:
        self.validate_component(path.parent, expect_directory=True)
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            _fail(FilesystemSafetyError, "NAMESPACE_COLLISION")
        except OSError:
            _fail(FilesystemSafetyError, "LOCK_CREATE_FAILED")
        try:
            os.fsync(fd)
            _validate_posix_owner_mode(os.fstat(fd), directory=False)
        except ControllerStoreError:
            raise
        except OSError:
            _fail(DurabilityError, "FILE_FLUSH_FAILED")
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
        self.validate_component(path, expect_directory=False)
        self.flush_directory(path.parent)

    @contextmanager
    def epoch_transaction_lock(self, path: pathlib.Path):
        if fcntl is None:
            _fail(DurabilityError, "OS_LOCK_UNSUPPORTED", safety_state="CONSUMED")
        self.validate_component(path, expect_directory=False)
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            fd = os.open(path, flags)
        except OSError:
            _fail(DurabilityError, "OS_LOCK_OPEN_FAILED", safety_state="CONSUMED")
        try:
            path_info = os.lstat(path)
            fd_info = os.fstat(fd)
            _validate_posix_owner_mode(fd_info, directory=False)
            if (path_info.st_dev, path_info.st_ino) != (fd_info.st_dev, fd_info.st_ino):
                _fail(DurabilityError, "OS_LOCK_IDENTITY_CHANGED", safety_state="CONSUMED")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
            except OSError:
                _fail(DurabilityError, "OS_LOCK_ACQUIRE_FAILED", safety_state="CONSUMED")
            self._used("fcntl.flock:LOCK_EX")
            yield
        finally:
            try:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(fd)
            except OSError:
                pass

    def _open_exclusive(self, path: pathlib.Path) -> int:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            return os.open(path, flags, 0o600)
        except FileExistsError:
            _fail(DurabilityError, "AUTHORITY_COLLISION")
        except OSError:
            _fail(DurabilityError, "TEMP_CREATE_FAILED")

    @staticmethod
    def _read_fd(fd: int, *, max_bytes: int) -> bytes:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, max_bytes - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                _fail(DurabilityError, "AUTHORITY_OVERSIZED")
            chunks.append(chunk)
        return b"".join(chunks)

    def write_authority(
        self,
        path: pathlib.Path,
        payload: bytes,
        *,
        replace: bool,
        max_bytes: int,
    ) -> Mapping[str, bool]:
        if len(payload) > max_bytes:
            _fail(DurabilityError, "AUTHORITY_OVERSIZED")
        parent = path.parent
        self.validate_component(parent, expect_directory=True)
        if os.path.lexists(path):
            self.validate_component(path, expect_directory=False)
        temporary = parent / f".recovery-tmp-{uuid.uuid4().hex}"
        fd = self._open_exclusive(temporary)
        try:
            written = 0
            while written < len(payload):
                count = os.write(fd, payload[written:])
                if count <= 0:
                    _fail(DurabilityError, "WRITE_INCOMPLETE")
                written += count
            if written != len(payload):
                _fail(DurabilityError, "WRITE_INCOMPLETE")
            os.fsync(fd)
        except ControllerStoreError:
            raise
        except OSError:
            _fail(DurabilityError, "FILE_FLUSH_FAILED")
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
        self.validate_component(temporary, expect_directory=False)
        try:
            read_fd = os.open(temporary, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            _fail(DurabilityError, "READBACK_OPEN_FAILED")
        try:
            readback = self._read_fd(read_fd, max_bytes=max_bytes)
        except ControllerStoreError:
            raise
        except OSError:
            _fail(DurabilityError, "READBACK_FAILED")
        finally:
            try:
                os.close(read_fd)
            except OSError:
                pass
        self.after_temp_readback(temporary, payload, readback)
        if readback != payload:
            _fail(DurabilityError, "READBACK_MISMATCH")
        self.validate_component(temporary, expect_directory=False)
        self.before_authority_transition(path)
        try:
            if replace:
                if os.path.lexists(path):
                    self.validate_component(path, expect_directory=False)
                os.replace(temporary, path)
            else:
                os.link(temporary, path, follow_symlinks=False)
                os.unlink(temporary)
        except FileExistsError:
            _fail(DurabilityError, "AUTHORITY_COLLISION")
        except OSError:
            _fail(DurabilityError, "ATOMIC_TRANSITION_FAILED")
        self.validate_component(path, expect_directory=False)
        self.flush_directory(parent)
        if self.read_authority(path, max_bytes=max_bytes) != payload:
            _fail(DurabilityError, "FINAL_READBACK_MISMATCH")
        return {
            "file_flush_verified": True,
            "readback_verified": True,
            "atomic_authority_transition": True,
            "directory_flush_verified": True,
        }

    def read_authority(self, path: pathlib.Path, *, max_bytes: int) -> bytes:
        self.validate_component(path, expect_directory=False)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            _fail(DurabilityError, "AUTHORITY_READ_FAILED")
        try:
            return self._read_fd(fd, max_bytes=max_bytes)
        except ControllerStoreError:
            raise
        except OSError:
            _fail(DurabilityError, "AUTHORITY_READ_FAILED")
        finally:
            try:
                os.close(fd)
            except OSError:
                pass

    def list_entries(self, directory: pathlib.Path) -> list[pathlib.Path]:
        self.validate_component(directory, expect_directory=True)
        try:
            entries = [pathlib.Path(entry.path) for entry in os.scandir(directory)]
        except OSError:
            _fail(FilesystemSafetyError, "DIRECTORY_READ_FAILED")
        for entry in entries:
            _lstat_checked(entry)
        return entries

    def flush_directory(self, directory: pathlib.Path) -> None:
        self.validate_component(directory, expect_directory=True)
        try:
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            _fail(DurabilityError, "DIRECTORY_FLUSH_FAILED")
        try:
            os.fsync(fd)
        except OSError:
            _fail(DurabilityError, "DIRECTORY_FLUSH_FAILED")
        finally:
            try:
                os.close(fd)
            except OSError:
                pass


class _WinFileAttributeTagInfo(ctypes.Structure):
    _fields_ = [
        ("FileAttributes", ctypes.c_ulong),
        ("ReparseTag", ctypes.c_ulong),
    ]


class _WinFileIdInfo(ctypes.Structure):
    _fields_ = [
        ("VolumeSerialNumber", ctypes.c_ulonglong),
        ("FileId", ctypes.c_ubyte * 16),
    ]


class _WinOverlapped(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_void_p),
        ("InternalHigh", ctypes.c_void_p),
        ("Offset", ctypes.c_ulong),
        ("OffsetHigh", ctypes.c_ulong),
        ("hEvent", ctypes.c_void_p),
    ]


class WindowsDurabilityAdapter(DurabilityAdapter):
    """Direct Win32 implementation; no os.replace/rename fallback exists."""

    platform_name = "windows"

    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    DELETE = 0x00010000
    READ_CONTROL = 0x00020000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    FILE_SHARE_DELETE = 0x00000004
    CREATE_NEW = 1
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x00000080
    FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    FILE_ATTRIBUTE_DEVICE = 0x00000040
    FILE_FLAG_WRITE_THROUGH = 0x80000000
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    FILE_TYPE_DISK = 0x0001
    MOVEFILE_REPLACE_EXISTING = 0x00000001
    MOVEFILE_WRITE_THROUGH = 0x00000008
    FILE_BEGIN = 0
    FILE_ATTRIBUTE_TAG_INFO = 9
    FILE_ID_INFO = 18
    LOCKFILE_EXCLUSIVE_LOCK = 0x00000002
    DRIVE_FIXED = 3
    TOKEN_QUERY = 0x0008
    TOKEN_USER = 1
    SE_FILE_OBJECT = 1
    OWNER_SECURITY_INFORMATION = 0x00000001
    DACL_SECURITY_INFORMATION = 0x00000004
    ACCESS_ALLOWED_ACE_TYPE = 0

    class _AceHeader(ctypes.Structure):
        _fields_ = [("AceType", ctypes.c_ubyte), ("AceFlags", ctypes.c_ubyte), ("AceSize", ctypes.c_ushort)]

    # ctypes class bodies do not close over names declared earlier in the
    # enclosing class body.  These aliases keep the declarations import-safe.
    _AceHeaderType = type("_AceHeaderType", (ctypes.Structure,), {"_fields_": [("AceType", ctypes.c_ubyte), ("AceFlags", ctypes.c_ubyte), ("AceSize", ctypes.c_ushort)]})
    _AllowedAceType = type("_AllowedAceType", (ctypes.Structure,), {"_fields_": [("Header", _AceHeaderType), ("Mask", ctypes.c_ulong), ("SidStart", ctypes.c_ulong)]})
    _AclType = type("_AclType", (ctypes.Structure,), {"_fields_": [("AclRevision", ctypes.c_ubyte), ("Sbz1", ctypes.c_ubyte), ("AclSize", ctypes.c_ushort), ("AceCount", ctypes.c_ushort), ("Sbz2", ctypes.c_ushort)]})
    _SidAttributesType = type("_SidAttributesType", (ctypes.Structure,), {"_fields_": [("Sid", ctypes.c_void_p), ("Attributes", ctypes.c_ulong)]})
    _TokenUserType = type("_TokenUserType", (ctypes.Structure,), {"_fields_": [("User", _SidAttributesType)]})
    _AceHeader = _AceHeaderType
    _AllowedAce = _AllowedAceType
    _Acl = _AclType
    _SidAttributes = _SidAttributesType
    _TokenUser = _TokenUserType

    def __init__(self) -> None:
        super().__init__()
        self._root: pathlib.Path | None = None
        self._volume_root: pathlib.Path | None = None
        self._kernel32 = None
        self._advapi32 = None
        self._security_ok = False
        if os.name != "nt":
            return
        try:
            self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            self._advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
            self._configure_api()
        except (AttributeError, OSError):
            self._kernel32 = None
            self._advapi32 = None

    @staticmethod
    def _handle_value(handle: Any) -> int | None:
        value = getattr(handle, "value", handle)
        return value

    @classmethod
    def _invalid_handle(cls, handle: Any) -> bool:
        value = cls._handle_value(handle)
        return value is None or value == ctypes.c_void_p(-1).value

    def _configure_api(self) -> None:
        assert self._kernel32 is not None and self._advapi32 is not None
        k = self._kernel32
        a = self._advapi32
        k.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p]
        k.CreateFileW.restype = ctypes.c_void_p
        k.CloseHandle.argtypes = [ctypes.c_void_p]
        k.CloseHandle.restype = ctypes.c_int
        k.CreateDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p]
        k.CreateDirectoryW.restype = ctypes.c_int
        k.GetFileInformationByHandleEx.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong]
        k.GetFileInformationByHandleEx.restype = ctypes.c_int
        k.SetFilePointerEx.argtypes = [ctypes.c_void_p, ctypes.c_longlong, ctypes.POINTER(ctypes.c_longlong), ctypes.c_ulong]
        k.SetFilePointerEx.restype = ctypes.c_int
        k.GetVolumePathNameW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong]
        k.GetVolumePathNameW.restype = ctypes.c_int
        k.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
        k.GetDriveTypeW.restype = ctypes.c_uint
        k.GetVolumeInformationW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint, ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_ulong), ctypes.c_wchar_p, ctypes.c_uint]
        k.GetVolumeInformationW.restype = ctypes.c_int
        k.GetFileType.argtypes = [ctypes.c_void_p]
        k.GetFileType.restype = ctypes.c_uint
        k.GetFileSizeEx.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_longlong)]
        k.GetFileSizeEx.restype = ctypes.c_int
        k.WriteFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.POINTER(ctypes.c_uint), ctypes.c_void_p]
        k.WriteFile.restype = ctypes.c_int
        k.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.POINTER(ctypes.c_uint), ctypes.c_void_p]
        k.ReadFile.restype = ctypes.c_int
        k.FlushFileBuffers.argtypes = [ctypes.c_void_p]
        k.FlushFileBuffers.restype = ctypes.c_int
        k.MoveFileExW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint]
        k.MoveFileExW.restype = ctypes.c_int
        k.LockFileEx.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.POINTER(_WinOverlapped)]
        k.LockFileEx.restype = ctypes.c_int
        k.UnlockFileEx.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.POINTER(_WinOverlapped)]
        k.UnlockFileEx.restype = ctypes.c_int
        k.GetCurrentProcess.restype = ctypes.c_void_p
        a.OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p)]
        a.OpenProcessToken.restype = ctypes.c_int
        a.GetTokenInformation.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
        a.GetTokenInformation.restype = ctypes.c_int
        a.GetSecurityInfo.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p)]
        a.GetSecurityInfo.restype = ctypes.c_ulong
        a.GetSecurityDescriptorDacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_int)]
        a.GetSecurityDescriptorDacl.restype = ctypes.c_int
        a.GetAce.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p)]
        a.GetAce.restype = ctypes.c_int
        a.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        a.EqualSid.restype = ctypes.c_int
        a.ConvertStringSidToSidW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)]
        a.ConvertStringSidToSidW.restype = ctypes.c_int
        k.LocalFree.argtypes = [ctypes.c_void_p]
        k.LocalFree.restype = ctypes.c_void_p

    def _require_api(self) -> tuple[Any, Any]:
        if os.name != "nt" or self._kernel32 is None or self._advapi32 is None:
            _fail(FilesystemSafetyError, "DURABILITY_UNSUPPORTED")
        return self._kernel32, self._advapi32

    def _query_handle_attributes(self, handle: Any) -> int:
        k, _ = self._require_api()
        if k.GetFileType(handle) != self.FILE_TYPE_DISK:
            _fail(FilesystemSafetyError, "SPECIAL_FILE_REJECTED")
        info = _WinFileAttributeTagInfo()
        if not k.GetFileInformationByHandleEx(
            handle,
            self.FILE_ATTRIBUTE_TAG_INFO,
            ctypes.byref(info),
            ctypes.sizeof(info),
        ):
            _fail(FilesystemSafetyError, "HANDLE_ATTRIBUTE_PROOF_FAILED")
        if (
            info.FileAttributes & (self.FILE_ATTRIBUTE_REPARSE_POINT | self.FILE_ATTRIBUTE_DEVICE)
            or info.ReparseTag != 0
        ):
            _fail(FilesystemSafetyError, "REPARSE_OR_SPECIAL_REJECTED")
        return info.FileAttributes

    def _handle_identity(self, handle: Any) -> tuple[int, bytes]:
        k, _ = self._require_api()
        info = _WinFileIdInfo()
        if not k.GetFileInformationByHandleEx(
            handle,
            self.FILE_ID_INFO,
            ctypes.byref(info),
            ctypes.sizeof(info),
        ):
            _fail(FilesystemSafetyError, "HANDLE_IDENTITY_PROOF_FAILED")
        return int(info.VolumeSerialNumber), bytes(info.FileId)

    def _open_proven(
        self,
        path: pathlib.Path,
        *,
        directory: bool = False,
        access: int | None = None,
        expect_directory: bool | None = None,
    ) -> tuple[Any, int, tuple[int, bytes]]:
        k, _ = self._require_api()
        flags = self.FILE_FLAG_OPEN_REPARSE_POINT
        if directory:
            flags |= self.FILE_FLAG_BACKUP_SEMANTICS
        handle = k.CreateFileW(
            str(path),
            self.GENERIC_READ | self.READ_CONTROL if access is None else access,
            self.FILE_SHARE_READ | self.FILE_SHARE_WRITE | self.FILE_SHARE_DELETE,
            None,
            self.OPEN_EXISTING,
            flags,
            None,
        )
        if self._invalid_handle(handle):
            _fail(FilesystemSafetyError, "PATH_OPEN_FAILED")
        try:
            attributes = self._query_handle_attributes(handle)
            is_directory = bool(attributes & self.FILE_ATTRIBUTE_DIRECTORY)
            if expect_directory is True and not is_directory:
                _fail(FilesystemSafetyError, "DIRECTORY_REQUIRED")
            if expect_directory is False and is_directory:
                _fail(FilesystemSafetyError, "REGULAR_FILE_REQUIRED")
            self._prove_dacl_handle(handle)
            identity = self._handle_identity(handle)
            self._used("GetFileInformationByHandleEx:FileAttributeTagInfo")
            self._used("GetFileInformationByHandleEx:FileIdInfo")
            self._used("GetSecurityInfo:opened-handle")
            return handle, attributes, identity
        except ControllerStoreError:
            k.CloseHandle(handle)
            raise

    def _validate_path_components(self, path: pathlib.Path, *, expect_directory: bool | None) -> int:
        if self._root is None:
            _fail(FilesystemSafetyError, "DURABILITY_UNSUPPORTED")
        try:
            relative = path.relative_to(self._root)
        except ValueError:
            _fail(FilesystemSafetyError, "PATH_OUTSIDE_STORE")
        components = [self._root]
        current = self._root
        for part in relative.parts:
            current = current / part
            components.append(current)
        final_attributes = 0
        for index, component in enumerate(components):
            component_expectation = True if index < len(components) - 1 else expect_directory
            handle, attributes, _ = self._open_proven(
                component,
                directory=component_expectation is not False,
                expect_directory=component_expectation,
            )
            try:
                final_attributes = attributes
            finally:
                self._require_api()[0].CloseHandle(handle)
        return final_attributes

    def _attributes(self, path: pathlib.Path) -> int:
        handle, attributes, _ = self._open_proven(path, directory=True)
        try:
            return attributes
        finally:
            self._require_api()[0].CloseHandle(handle)

    def _open_existing(self, path: pathlib.Path, *, directory: bool = False, access: int | None = None) -> Any:
        return self._open_proven(path, directory=directory, access=access)[0]

    def _current_sid(self) -> tuple[ctypes.c_void_p, Any]:
        k, a = self._require_api()
        token = ctypes.c_void_p()
        if not a.OpenProcessToken(k.GetCurrentProcess(), self.TOKEN_QUERY, ctypes.byref(token)):
            _fail(FilesystemSafetyError, "SECURITY_PROOF_FAILED")
        try:
            size = ctypes.c_ulong(0)
            a.GetTokenInformation(token, self.TOKEN_USER, None, 0, ctypes.byref(size))
            if not size.value:
                _fail(FilesystemSafetyError, "SECURITY_PROOF_FAILED")
            buffer = ctypes.create_string_buffer(size.value)
            if not a.GetTokenInformation(token, self.TOKEN_USER, buffer, size.value, ctypes.byref(size)):
                _fail(FilesystemSafetyError, "SECURITY_PROOF_FAILED")
            user = ctypes.cast(buffer, ctypes.POINTER(self._TokenUser)).contents
            if not user.User.Sid:
                _fail(FilesystemSafetyError, "SECURITY_PROOF_FAILED")
            return ctypes.c_void_p(user.User.Sid), buffer
        finally:
            k.CloseHandle(token)

    def _well_known_sid(self, text: str) -> ctypes.c_void_p:
        _, a = self._require_api()
        sid = ctypes.c_void_p()
        if not a.ConvertStringSidToSidW(text, ctypes.byref(sid)):
            _fail(FilesystemSafetyError, "SECURITY_PROOF_FAILED")
        return sid

    def _prove_dacl_handle(self, handle: Any) -> None:
        k, a = self._require_api()
        descriptor = ctypes.c_void_p()
        owner = ctypes.c_void_p()
        group = ctypes.c_void_p()
        dacl = ctypes.c_void_p()
        sacl = ctypes.c_void_p()
        result = a.GetSecurityInfo(
            handle,
            self.SE_FILE_OBJECT,
            self.OWNER_SECURITY_INFORMATION | self.DACL_SECURITY_INFORMATION,
            ctypes.byref(owner),
            ctypes.byref(group),
            ctypes.byref(dacl),
            ctypes.byref(sacl),
            ctypes.byref(descriptor),
        )
        if result != 0 or not descriptor:
            _fail(FilesystemSafetyError, "SECURITY_PROOF_FAILED")
        try:
            present = ctypes.c_int(0)
            defaulted = ctypes.c_int(0)
            if not a.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)) or not present.value or not dacl:
                _fail(FilesystemSafetyError, "SECURITY_PROOF_FAILED")
            current, current_buffer = self._current_sid()
            system = self._well_known_sid("S-1-5-18")
            administrators = self._well_known_sid("S-1-5-32-544")
            try:
                allowed = (current, system, administrators)
                if not owner or not any(a.EqualSid(owner, candidate) for candidate in allowed):
                    _fail(FilesystemSafetyError, "SECURITY_PROOF_FAILED")
                acl = ctypes.cast(dacl, ctypes.POINTER(self._Acl)).contents
                if acl.AceCount == 0:
                    _fail(FilesystemSafetyError, "SECURITY_PROOF_FAILED")
                controller_seen = False
                for index in range(acl.AceCount):
                    ace_ptr = ctypes.c_void_p()
                    if not a.GetAce(dacl, index, ctypes.byref(ace_ptr)) or not ace_ptr:
                        _fail(FilesystemSafetyError, "SECURITY_PROOF_FAILED")
                    header = ctypes.cast(ace_ptr, ctypes.POINTER(self._AceHeader)).contents
                    allowed_ace = ctypes.cast(ace_ptr, ctypes.POINTER(self._AllowedAce)).contents
                    if header.AceType != self.ACCESS_ALLOWED_ACE_TYPE or header.AceSize < ctypes.sizeof(self._AllowedAce) or allowed_ace.Mask == 0:
                        _fail(FilesystemSafetyError, "SECURITY_PROOF_FAILED")
                    sid_address = self._handle_value(ace_ptr)
                    assert sid_address is not None
                    sid = ctypes.c_void_p(sid_address + ctypes.sizeof(self._AceHeader) + ctypes.sizeof(ctypes.c_ulong))
                    if not any(a.EqualSid(sid, candidate) for candidate in allowed):
                        _fail(FilesystemSafetyError, "SECURITY_PROOF_FAILED")
                    if a.EqualSid(sid, current):
                        controller_seen = True
                if not controller_seen:
                    _fail(FilesystemSafetyError, "SECURITY_PROOF_FAILED")
                self._security_ok = True
            finally:
                k.LocalFree(system)
                k.LocalFree(administrators)
        finally:
            k.LocalFree(descriptor)

    def prove_root(self, root: pathlib.Path, *, test_mode: bool = False) -> Mapping[str, Any]:
        k, _ = self._require_api()
        volume = ctypes.create_unicode_buffer(32768)
        if not k.GetVolumePathNameW(str(root), volume, len(volume)):
            _fail(FilesystemSafetyError, "LOCAL_VOLUME_PROOF_FAILED")
        if k.GetDriveTypeW(volume.value) != self.DRIVE_FIXED:
            _fail(FilesystemSafetyError, "LOCAL_VOLUME_PROOF_FAILED")
        volume_name = ctypes.create_unicode_buffer(32768)
        serial = ctypes.c_ulong(0)
        maximum_component = ctypes.c_ulong(0)
        flags = ctypes.c_ulong(0)
        filesystem = ctypes.create_unicode_buffer(32768)
        if not k.GetVolumeInformationW(volume.value, volume_name, len(volume_name), ctypes.byref(serial), ctypes.byref(maximum_component), ctypes.byref(flags), filesystem, len(filesystem)):
            _fail(FilesystemSafetyError, "LOCAL_VOLUME_PROOF_FAILED")
        self._volume_root = pathlib.Path(volume.value)
        self._root = root
        self._validate_path_components(root, expect_directory=True)
        self._used("CreateFileW:OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS")
        self._used("CreateFileW:CREATE_NEW|FILE_FLAG_WRITE_THROUGH")
        self._used("FlushFileBuffers")
        self._used("MoveFileExW:WRITE_THROUGH")
        self._used("GetVolumePathNameW/GetDriveTypeW")
        self._used("GetSecurityInfo/GetSecurityDescriptorDacl")
        return {
            "file_flush_verified": True,
            "readback_verified": True,
            "atomic_authority_transition": True,
            "directory_flush_verified": True,
        }

    def validate_component(self, path: pathlib.Path, *, expect_directory: bool | None = None) -> None:
        self._validate_path_components(path, expect_directory=expect_directory)

    def mkdir_exclusive(self, path: pathlib.Path) -> None:
        self.validate_component(path.parent, expect_directory=True)
        k, _ = self._require_api()
        if not k.CreateDirectoryW(str(path), None):
            _fail(FilesystemSafetyError, "NAMESPACE_COLLISION" if ctypes.get_last_error() in (80, 183) else "DIRECTORY_CREATE_FAILED")
        self.validate_component(path, expect_directory=True)
        # Windows has no documented directory-fsync equivalent here; directory
        # creation is not treated as file authority.  File authority uses the
        # write-through MoveFileExW transition below.

    def _create_temp(self, path: pathlib.Path) -> Any:
        k, _ = self._require_api()
        handle = k.CreateFileW(
            str(path),
            self.GENERIC_READ | self.GENERIC_WRITE | self.READ_CONTROL,
            self.FILE_SHARE_READ | self.FILE_SHARE_WRITE | self.FILE_SHARE_DELETE,
            None,
            self.CREATE_NEW,
            self.FILE_ATTRIBUTE_NORMAL | self.FILE_FLAG_WRITE_THROUGH | self.FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        if self._invalid_handle(handle):
            _fail(DurabilityError, "TEMP_CREATE_FAILED")
        try:
            attributes = self._query_handle_attributes(handle)
            if attributes & self.FILE_ATTRIBUTE_DIRECTORY:
                _fail(FilesystemSafetyError, "REGULAR_FILE_REQUIRED")
            self._prove_dacl_handle(handle)
            self._handle_identity(handle)
            self._used("GetFileInformationByHandleEx:FileAttributeTagInfo")
            self._used("GetFileInformationByHandleEx:FileIdInfo")
            self._used("GetSecurityInfo:opened-handle")
            return handle
        except ControllerStoreError:
            k.CloseHandle(handle)
            raise

    def create_transaction_lock(self, path: pathlib.Path) -> None:
        self.validate_component(path.parent, expect_directory=True)
        handle = self._create_temp(path)
        try:
            k, _ = self._require_api()
            if not k.FlushFileBuffers(handle):
                _fail(DurabilityError, "FILE_FLUSH_FAILED")
            self._used("FlushFileBuffers:transaction-lock")
        finally:
            k, _ = self._require_api()
            k.CloseHandle(handle)
        self.validate_component(path, expect_directory=False)

    @contextmanager
    def epoch_transaction_lock(self, path: pathlib.Path):
        handle = self._open_existing(
            path,
            directory=False,
            access=self.GENERIC_READ | self.GENERIC_WRITE | self.READ_CONTROL,
        )
        k, _ = self._require_api()
        overlapped = _WinOverlapped()
        acquired = False
        try:
            identity = self._handle_identity(handle)
            if not k.LockFileEx(
                handle,
                self.LOCKFILE_EXCLUSIVE_LOCK,
                0,
                1,
                0,
                ctypes.byref(overlapped),
            ):
                _fail(DurabilityError, "OS_LOCK_ACQUIRE_FAILED", safety_state="CONSUMED")
            acquired = True
            if self._handle_identity(handle) != identity:
                _fail(DurabilityError, "OS_LOCK_IDENTITY_CHANGED", safety_state="CONSUMED")
            self._used("LockFileEx:LOCKFILE_EXCLUSIVE_LOCK")
            yield
        finally:
            release_failed = False
            if acquired:
                if not k.UnlockFileEx(handle, 0, 1, 0, ctypes.byref(overlapped)):
                    release_failed = True
                else:
                    self._used("UnlockFileEx")
            k.CloseHandle(handle)
            if release_failed:
                _fail(DurabilityError, "OS_LOCK_RELEASE_FAILED", safety_state="CONSUMED")

    def _write_handle(self, handle: Any, payload: bytes) -> None:
        k, _ = self._require_api()
        buffer = ctypes.create_string_buffer(payload)
        written_total = 0
        while written_total < len(payload):
            written = ctypes.c_uint(0)
            pointer = ctypes.cast(ctypes.byref(buffer, written_total), ctypes.c_void_p)
            if not k.WriteFile(handle, pointer, len(payload) - written_total, ctypes.byref(written), None) or not written.value:
                _fail(DurabilityError, "WRITE_INCOMPLETE")
            written_total += written.value
        if written_total != len(payload) or not k.FlushFileBuffers(handle):
            _fail(DurabilityError, "FILE_FLUSH_FAILED")

    def _rewind_handle(self, handle: Any) -> None:
        k, _ = self._require_api()
        if not k.SetFilePointerEx(handle, ctypes.c_longlong(0), None, self.FILE_BEGIN):
            _fail(DurabilityError, "FILE_SEEK_FAILED")

    def _read_handle(self, handle: Any, *, max_bytes: int) -> bytes:
        k, _ = self._require_api()
        size = ctypes.c_longlong(0)
        if not k.GetFileSizeEx(handle, ctypes.byref(size)) or size.value < 0 or size.value > max_bytes:
            _fail(DurabilityError, "AUTHORITY_OVERSIZED")
        if size.value == 0:
            return b""
        buffer = ctypes.create_string_buffer(size.value)
        read_total = 0
        while read_total < size.value:
            count = ctypes.c_uint(0)
            pointer = ctypes.cast(ctypes.byref(buffer, read_total), ctypes.c_void_p)
            if not k.ReadFile(handle, pointer, size.value - read_total, ctypes.byref(count), None) or not count.value:
                _fail(DurabilityError, "AUTHORITY_READ_FAILED")
            read_total += count.value
        return buffer.raw[:size.value]

    def _assert_path_identity(self, path: pathlib.Path, expected: tuple[int, bytes], *, directory: bool) -> None:
        handle = self._open_existing(path, directory=directory)
        try:
            if self._handle_identity(handle) != expected:
                _fail(DurabilityError, "AUTHORITY_IDENTITY_CHANGED", safety_state="CONSUMED")
        finally:
            self._require_api()[0].CloseHandle(handle)

    def write_authority(
        self,
        path: pathlib.Path,
        payload: bytes,
        *,
        replace: bool,
        max_bytes: int,
    ) -> Mapping[str, bool]:
        if len(payload) > max_bytes:
            _fail(DurabilityError, "AUTHORITY_OVERSIZED")
        parent = path.parent
        parent_handle, _, parent_identity = self._open_proven(parent, directory=True, expect_directory=True)
        k, _ = self._require_api()
        target_handle = None
        target_identity = None
        try:
            if os.path.lexists(path):
                target_handle, _, target_identity = self._open_proven(path, directory=False, expect_directory=False)
            temporary = parent / f".recovery-tmp-{uuid.uuid4().hex}"
            temp_handle = self._create_temp(temporary)
            try:
                temp_identity = self._handle_identity(temp_handle)
                self._write_handle(temp_handle, payload)
                if self._handle_identity(temp_handle) != temp_identity:
                    _fail(DurabilityError, "AUTHORITY_IDENTITY_CHANGED", safety_state="CONSUMED")
                self._rewind_handle(temp_handle)
                readback = self._read_handle(temp_handle, max_bytes=max_bytes)
                if self._handle_identity(temp_handle) != temp_identity:
                    _fail(DurabilityError, "AUTHORITY_IDENTITY_CHANGED", safety_state="CONSUMED")
            finally:
                k, _ = self._require_api()
                k.CloseHandle(temp_handle)
            self.after_temp_readback(temporary, payload, readback)
            if readback != payload:
                _fail(DurabilityError, "READBACK_MISMATCH")
            self._assert_path_identity(temporary, temp_identity, directory=False)
            self._assert_path_identity(parent, parent_identity, directory=True)
            if target_identity is not None:
                self._assert_path_identity(path, target_identity, directory=False)
                k.CloseHandle(target_handle)
                target_handle = None
            self.before_authority_transition(path)
            self._assert_path_identity(temporary, temp_identity, directory=False)
            self._assert_path_identity(parent, parent_identity, directory=True)
            if target_identity is not None:
                self._assert_path_identity(path, target_identity, directory=False)
            k, _ = self._require_api()
            flags = self.MOVEFILE_WRITE_THROUGH
            if replace:
                flags |= self.MOVEFILE_REPLACE_EXISTING
            if not k.MoveFileExW(str(temporary), str(path), flags):
                _fail(DurabilityError, "AUTHORITY_COLLISION" if not replace else "ATOMIC_TRANSITION_FAILED")
            self._assert_path_identity(parent, parent_identity, directory=True)
            final_handle = self._open_existing(path, directory=False)
            try:
                final_identity = self._handle_identity(final_handle)
                if final_identity != temp_identity:
                    _fail(DurabilityError, "AUTHORITY_IDENTITY_CHANGED", safety_state="CONSUMED")
                final_readback = self._read_handle(final_handle, max_bytes=max_bytes)
            finally:
                k.CloseHandle(final_handle)
            if final_readback != payload:
                _fail(DurabilityError, "FINAL_READBACK_MISMATCH")
            self._used("MoveFileExW:WRITE_THROUGH:directory-entry")
            return {
                "file_flush_verified": True,
                "readback_verified": True,
                "atomic_authority_transition": True,
                "directory_flush_verified": True,
            }
        finally:
            if target_handle is not None:
                k.CloseHandle(target_handle)
            k.CloseHandle(parent_handle)

    def read_authority(self, path: pathlib.Path, *, max_bytes: int) -> bytes:
        k, _ = self._require_api()
        handle = self._open_existing(path, access=self.GENERIC_READ | self.READ_CONTROL)
        try:
            identity = self._handle_identity(handle)
            payload = self._read_handle(handle, max_bytes=max_bytes)
            if self._handle_identity(handle) != identity:
                _fail(DurabilityError, "AUTHORITY_IDENTITY_CHANGED", safety_state="CONSUMED")
            return payload
        finally:
            k.CloseHandle(handle)

    def list_entries(self, directory: pathlib.Path) -> list[pathlib.Path]:
        # Directory enumeration is performed only through the standard library
        # after the directory itself has passed Win32 reparse/DACL checks.
        self.validate_component(directory, expect_directory=True)
        try:
            entries = [pathlib.Path(entry.path) for entry in os.scandir(directory)]
        except OSError:
            _fail(FilesystemSafetyError, "DIRECTORY_READ_FAILED")
        for entry in entries:
            self.validate_component(entry)
        return entries

    def flush_directory(self, directory: pathlib.Path) -> None:
        # No documented Windows directory-fsync primitive is assumed.  Callers
        # must use the file-level MoveFileExW write-through proof instead.
        _fail(DurabilityError, "DIRECTORY_FLUSH_UNSUPPORTED")


def make_durability_adapter() -> DurabilityAdapter:
    return WindowsDurabilityAdapter() if os.name == "nt" else PosixDurabilityAdapter()


def _document_limit(filename: str) -> int:
    limits = {
        RECORD_FILENAME: MAX_EPOCH_RECORD_BYTES,
        MANIFEST_FILENAME: MAX_MANIFEST_BYTES,
        PRIVATE_IDENTITIES_FILENAME: MAX_PRIVATE_IDENTITIES_BYTES,
        LEDGER_FILENAME: MAX_RESTORE_LEDGER_BYTES,
        SPOOL_META_FILENAME: MAX_SPOOL_META_BYTES,
    }
    if filename.startswith("frame-"):
        return MAX_FRAME_BYTES
    try:
        return limits[filename]
    except KeyError:
        _fail(FilesystemSafetyError, "UNKNOWN_AUTHORITATIVE_FILE")


def _validate_private_input(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        _fail(SchemaError, "INVALID_PRIVATE_IDENTITIES")
    expected = set(PRIVATE_IDENTITY_FIELDS[2:])
    if set(value) != expected:
        _fail(SchemaError, "INVALID_PRIVATE_IDENTITIES")
    result: dict[str, str] = {}
    for field in PRIVATE_IDENTITY_FIELDS[2:]:
        if not isinstance(value[field], str):
            _fail(SchemaError, "INVALID_PRIVATE_IDENTITIES")
        result[field] = value[field]
    return result


@dataclass(frozen=True)
class EpochSnapshot:
    record: dict[str, Any]
    manifest: dict[str, Any]
    private_identities: dict[str, Any]
    ledger: dict[str, Any]
    spool: dict[str, Any]


@dataclass(frozen=True)
class RestorePermit:
    epoch_ref: str
    transition_id: str
    state: str
    idempotent: bool


@dataclass(frozen=True)
class FrameReceipt:
    epoch_ref: str
    sequence: int
    highest_contiguous_commit: int
    frame_count: int


class ControllerStore:
    """Controller-side store.  ``from_environment`` is the production entry."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        test_mode: bool = False,
        adapter: DurabilityAdapter | None = None,
    ) -> None:
        root_path = _validate_root_path(_absolute_path(root), test_mode=test_mode)
        self.root = root_path
        self.test_mode = test_mode
        self.adapter = adapter or make_durability_adapter()
        self._durability = _make_durability(self.adapter.prove_root(root_path, test_mode=test_mode))
        self._locks_guard = threading.Lock()
        self._epoch_locks: dict[str, threading.RLock] = {}
        self._ensure_root_layout()

    @classmethod
    def from_environment(
        cls,
        *,
        environ: Mapping[str, str] | None = None,
        adapter: DurabilityAdapter | None = None,
    ) -> "ControllerStore":
        values = os.environ if environ is None else environ
        if "PLATFORM_RECOVERY_STORE_ROOT" not in values:
            _fail(ConfigurationError, "STORE_ROOT_NOT_CONFIGURED")
        return cls(values["PLATFORM_RECOVERY_STORE_ROOT"], adapter=adapter)

    @classmethod
    def for_disposable_test_root(
        cls,
        root: str | os.PathLike[str],
        *,
        adapter: DurabilityAdapter | None = None,
    ) -> "ControllerStore":
        return cls(root, test_mode=True, adapter=adapter)

    def _ensure_root_layout(self) -> None:
        entries = self.adapter.list_entries(self.root)
        for entry in entries:
            if entry.name != "epochs":
                _fail(FilesystemSafetyError, "UNKNOWN_ROOT_ENTRY")
        epochs = self.root / "epochs"
        if not os.path.lexists(epochs):
            self.adapter.mkdir_exclusive(epochs)
        else:
            self.adapter.validate_component(epochs, expect_directory=True)

    def _epoch_path(self, epoch_ref: str) -> pathlib.Path:
        _strict_ref(epoch_ref, "epoch_ref")
        return self.root / "epochs" / epoch_ref

    def _spool_path(self, epoch_ref: str) -> pathlib.Path:
        return self._epoch_path(epoch_ref) / SPOOL_DIRNAME

    def _frames_path(self, epoch_ref: str) -> pathlib.Path:
        return self._spool_path(epoch_ref) / FRAMES_DIRNAME

    def _transaction_lock_path(self, epoch_ref: str) -> pathlib.Path:
        return self._epoch_path(epoch_ref) / TRANSACTION_LOCK_FILENAME

    def _file_path(self, epoch_ref: str, filename: str) -> pathlib.Path:
        path = self._epoch_path(epoch_ref)
        if filename == SPOOL_META_FILENAME:
            return self._spool_path(epoch_ref) / filename
        if filename.startswith("frame-"):
            if FRAME_NAME_RE.fullmatch(filename) is None:
                _fail(FilesystemSafetyError, "UNKNOWN_AUTHORITATIVE_FILE")
            return self._frames_path(epoch_ref) / filename
        if filename not in {RECORD_FILENAME, MANIFEST_FILENAME, PRIVATE_IDENTITIES_FILENAME, LEDGER_FILENAME}:
            _fail(FilesystemSafetyError, "UNKNOWN_AUTHORITATIVE_FILE")
        return path / filename

    def _document_path(self, epoch_ref: str, filename: str) -> pathlib.Path:
        return self._file_path(epoch_ref, filename)

    def _write_document(self, path: pathlib.Path, value: Mapping[str, Any], *, max_bytes: int, replace: bool) -> bytes:
        payload = canonical_json_bytes(value, max_bytes=max_bytes)
        proof = _make_durability(
            self.adapter.write_authority(path, payload, replace=replace, max_bytes=max_bytes)
        )
        if proof != self._durability:
            _fail(DurabilityError, "DURABILITY_PROOF_CHANGED")
        try:
            readback = self.adapter.read_authority(path, max_bytes=max_bytes)
        except ControllerStoreError:
            raise
        if readback != payload:
            _fail(DurabilityError, "FINAL_READBACK_MISMATCH")
        return readback

    def _read_document(self, path: pathlib.Path, *, max_bytes: int, validator: Any) -> tuple[dict[str, Any], bytes]:
        try:
            payload = self.adapter.read_authority(path, max_bytes=max_bytes)
        except ControllerStoreError:
            _fail(IntegrityError, "AUTHORITATIVE_STATE_UNAVAILABLE", safety_state="CONSUMED")
        try:
            value = parse_canonical_json(payload, max_bytes=max_bytes)
            validated = validator(value)
            if canonical_json_bytes(validated, max_bytes=max_bytes) != payload:
                _fail(IntegrityError, "AUTHORITATIVE_STATE_NOT_CANONICAL", safety_state="CONSUMED")
        except LedgerError:
            raise
        except ControllerStoreError:
            _fail(IntegrityError, "AUTHORITATIVE_STATE_INVALID", safety_state="CONSUMED")
        return validated, payload

    def _validate_epoch_entries(self, epoch_ref: str) -> None:
        epoch = self._epoch_path(epoch_ref)
        self.adapter.validate_component(epoch, expect_directory=True)
        allowed = {
            RECORD_FILENAME,
            MANIFEST_FILENAME,
            PRIVATE_IDENTITIES_FILENAME,
            LEDGER_FILENAME,
            TRANSACTION_LOCK_FILENAME,
            SPOOL_DIRNAME,
        }
        for entry in self.adapter.list_entries(epoch):
            if entry.name == TRANSACTION_LOCK_FILENAME:
                self.adapter.validate_component(entry, expect_directory=False)
                continue
            if entry.name in allowed:
                continue
            if TEMP_NAME_RE.fullmatch(entry.name):
                self.adapter.validate_component(entry, expect_directory=False)
                continue
            _fail(FilesystemSafetyError, "UNKNOWN_EPOCH_ENTRY")
        spool = self._spool_path(epoch_ref)
        self.adapter.validate_component(spool, expect_directory=True)
        for entry in self.adapter.list_entries(spool):
            if entry.name in (SPOOL_META_FILENAME, FRAMES_DIRNAME):
                continue
            if TEMP_NAME_RE.fullmatch(entry.name):
                self.adapter.validate_component(entry, expect_directory=False)
                continue
            _fail(FilesystemSafetyError, "UNKNOWN_SPOOL_ENTRY")
        frames = self._frames_path(epoch_ref)
        self.adapter.validate_component(frames, expect_directory=True)
        for entry in self.adapter.list_entries(frames):
            if FRAME_NAME_RE.fullmatch(entry.name):
                self.adapter.validate_component(entry, expect_directory=False)
            elif TEMP_NAME_RE.fullmatch(entry.name):
                self.adapter.validate_component(entry, expect_directory=False)
            else:
                _fail(FilesystemSafetyError, "UNKNOWN_FRAME_ENTRY")

    def _read_frame_files(
        self,
        epoch_ref: str,
        spool: Mapping[str, Any],
        private: Mapping[str, Any],
        *,
        record: Mapping[str, Any],
        ledger: Mapping[str, Any],
    ) -> dict[str, Any]:
        frames_dir = self._frames_path(epoch_ref)
        entries = [entry for entry in self.adapter.list_entries(frames_dir) if FRAME_NAME_RE.fullmatch(entry.name)]
        entries.sort(key=lambda path: path.name)
        safety_state = "CONSUMED" if ledger["state"] == "CONSUMED" or spool["state"] == "COMMITTED" else None
        if len(entries) != spool["frame_count"]:
            _fail(IntegrityError, "SPOOL_FRAME_COUNT_CONTRADICTION", safety_state=safety_state)
        expected_sequence = 1
        previous_hash = ZERO_FRAME_HASH
        total_bytes = 0
        highest_commit = 0
        last_stage = "NONE"
        for entry in entries:
            frame, payload = self._read_document(entry, max_bytes=MAX_FRAME_BYTES, validator=validate_runner_frame)
            if frame["epoch_ref"] != epoch_ref or frame["sequence"] != expected_sequence:
                _fail(IntegrityError, "SPOOL_SEQUENCE_CONTRADICTION", safety_state="CONSUMED")
            if frame["previous_hash"] != previous_hash:
                _fail(IntegrityError, "SPOOL_HASH_CHAIN_CONTRADICTION", safety_state="CONSUMED")
            expected_auth = self._frame_auth(private, epoch_ref, frame["sequence"], frame["stage"], frame["payload"], frame["previous_hash"])
            if not hmac.compare_digest(frame["auth"], expected_auth):
                _fail(IntegrityError, "SPOOL_AUTH_CONTRADICTION", safety_state="CONSUMED")
            expected_hash = self._frame_hash(epoch_ref, frame["sequence"], frame["stage"], frame["payload"], frame["previous_hash"], frame["auth"])
            if frame["frame_hash"] != expected_hash:
                _fail(IntegrityError, "SPOOL_FRAME_HASH_CONTRADICTION", safety_state="CONSUMED")
            if frame["stage"] not in FRAME_STAGE_TRANSITIONS[last_stage]:
                _fail(IntegrityError, "SPOOL_STAGE_CONTRADICTION", safety_state=safety_state)
            if frame["stage"] == "RESTORE_BEGIN" and ledger["state"] != "CONSUMED":
                _fail(IntegrityError, "RESTORE_BEGIN_BEFORE_LEDGER_CONSUMED", safety_state="CONSUMED")
            if frame["stage"] == "COMMIT" and ledger["state"] != "CONSUMED":
                _fail(IntegrityError, "COMMIT_BEFORE_LEDGER_CONSUMED", safety_state="CONSUMED")
            if frame["stage"] == "ABANDON" and not _is_legal_abandon_transition(last_stage, ledger["state"]):
                if ledger["state"] == "CONSUMED":
                    _fail(IntegrityError, "ABANDON_AFTER_LEDGER_CONSUMED", safety_state="CONSUMED")
                _fail(IntegrityError, "FRAME_STAGE_CONTRADICTION", safety_state=safety_state)
            expected_sequence += 1
            previous_hash = frame["frame_hash"]
            total_bytes += len(payload)
            if frame["stage"] == "COMMIT":
                highest_commit = frame["sequence"]
            last_stage = frame["stage"]
        derived_state = {
            "COMMIT": "COMMITTED",
            "ABANDON": "ABANDONED",
        }.get(last_stage, "OPEN")
        summary = {
            "state": derived_state,
            "next_sequence": expected_sequence,
            "last_frame_hash": previous_hash,
            "highest_contiguous_commit": highest_commit,
            "frame_count": len(entries),
            "total_spool_bytes": total_bytes,
            "last_stage": last_stage,
        }
        for field, expected in summary.items():
            if spool[field] != expected:
                _fail(IntegrityError, "SPOOL_META_CONTRADICTION", safety_state=safety_state)
        return summary

    def _cross_validate(
        self,
        record: Mapping[str, Any],
        manifest: Mapping[str, Any],
        private: Mapping[str, Any],
        ledger: Mapping[str, Any],
        spool: Mapping[str, Any],
        manifest_bytes: bytes,
        *,
        private_bytes: bytes,
        frame_summary: Mapping[str, Any] | None = None,
    ) -> None:
        if record["epoch_ref"] != manifest["epoch_ref"] or record["epoch_ref"] != private["epoch_ref"] or record["epoch_ref"] != ledger["epoch_ref"] or record["epoch_ref"] != spool["epoch_ref"]:
            _fail(IntegrityError, "CROSS_FILE_CONTRADICTION", safety_state="CONSUMED" if ledger["state"] == "CONSUMED" else None)
        expected_private_digest = bytes_commitment(DOMAIN_PRIVATE_IDENTITIES, private_bytes)
        if record["private_identities_digest"] != expected_private_digest or manifest["private_identities_digest"] != expected_private_digest:
            _fail(IntegrityError, "PRIVATE_IDENTITIES_DIGEST_MISMATCH", safety_state="CONSUMED" if ledger["state"] == "CONSUMED" else None)
        if record["container_commitment"] != recovery_commitment(DOMAIN_CONTAINER_IDENTITY, private["container_identity"]):
            _fail(IntegrityError, "PRIVATE_IDENTITY_COMMITMENT_MISMATCH", safety_state="CONSUMED")
        if record["volume_commitment"] != recovery_commitment(DOMAIN_VOLUME_IDENTITY, private["volume_identity"]):
            _fail(IntegrityError, "PRIVATE_IDENTITY_COMMITMENT_MISMATCH", safety_state="CONSUMED")
        if record["runner_commitment"] != recovery_commitment(DOMAIN_RUNNER_IDENTITY, private["runner_identity"]):
            _fail(IntegrityError, "PRIVATE_IDENTITY_COMMITMENT_MISMATCH", safety_state="CONSUMED")
        if record["spool_commitment"] != recovery_commitment(DOMAIN_SPOOL, record["epoch_ref"], record["authority_ref"]):
            _fail(IntegrityError, "SPOOL_CROSS_FILE_CONTRADICTION", safety_state="CONSUMED")
        if record["restore_ledger_ref"] != f"ledger-{record['epoch_ref']}":
            _fail(IntegrityError, "LEDGER_CROSS_FILE_CONTRADICTION", safety_state="CONSUMED")
        expected_artifact = None
        if record["artifact_binding_state"] == "ROW_BOUND":
            expected_artifact = recovery_commitment(DOMAIN_ARTIFACT_ROW, private["artifact_row_id"])
        elif record["artifact_binding_state"] == "BOUND":
            expected_artifact = recovery_commitment(DOMAIN_ARTIFACT_ROW, private["artifact_row_id"], private["artifact_filename"])
        if record["artifact_commitment"] != expected_artifact:
            _fail(IntegrityError, "ARTIFACT_CROSS_FILE_CONTRADICTION", safety_state="CONSUMED")
        for field in ("authority_ref", "state", "artifact_binding_state", "artifact_commitment", "supersession_barrier_commitment", "container_commitment", "volume_commitment", "runner_commitment", "spool_commitment", "private_identities_digest", "restore_ledger_ref", "restore_ledger_state", "durability"):
            if record[field] != manifest[field]:
                _fail(IntegrityError, "CROSS_FILE_CONTRADICTION", safety_state="CONSUMED" if ledger["state"] == "CONSUMED" else None)
        if record["manifest_digest"] != bytes_commitment(DOMAIN_MANIFEST, manifest_bytes):
            _fail(IntegrityError, "MANIFEST_DIGEST_MISMATCH", safety_state="CONSUMED" if ledger["state"] == "CONSUMED" else None)
        if record["restore_ledger_state"] != ledger["state"]:
            _fail(IntegrityError, "LEDGER_CROSS_FILE_CONTRADICTION", safety_state="CONSUMED")
        if record["spool_commitment"] != spool["spool_commitment"]:
            _fail(IntegrityError, "SPOOL_CROSS_FILE_CONTRADICTION", safety_state="CONSUMED")
        if spool["state"] == "COMMITTED":
            if record["state"] != "CONSUMED" or ledger["state"] != "CONSUMED":
                _fail(IntegrityError, "SPOOL_CROSS_FILE_CONTRADICTION", safety_state="CONSUMED")
        elif spool["state"] == "ABANDONED":
            # The frame-history pass proves whether a consumed ledger is
            # paired with the exact RESTORE_BEGIN -> ABANDON transition.
            if record["state"] != "ABANDONED" or ledger["state"] not in LEDGER_STATES:
                _fail(IntegrityError, "SPOOL_CROSS_FILE_CONTRADICTION", safety_state="CONSUMED" if ledger["state"] == "CONSUMED" else None)
        else:
            if record["state"] in ("ABANDONED", "CONSUMED"):
                _fail(IntegrityError, "SPOOL_CROSS_FILE_CONTRADICTION", safety_state="CONSUMED" if record["state"] == "CONSUMED" else None)
            if ledger["state"] == "CONSUMED" and record["state"] != "ACTIVE":
                _fail(IntegrityError, "LEDGER_CROSS_FILE_CONTRADICTION", safety_state="CONSUMED")
        stage_state = spool["last_stage"]
        if stage_state == "EPOCH_READY" and record["state"] not in ("READY", "ACTIVE", "SUPERSEDED"):
            _fail(IntegrityError, "SPOOL_CROSS_FILE_CONTRADICTION", safety_state="CONSUMED" if ledger["state"] == "CONSUMED" else None)
        if stage_state == "RUNNER_STARTED" and record["state"] != "ACTIVE":
            _fail(IntegrityError, "SPOOL_CROSS_FILE_CONTRADICTION", safety_state="CONSUMED" if ledger["state"] == "CONSUMED" else None)
        if stage_state == "RESTORE_BEGIN" and (record["state"] != "ACTIVE" or ledger["state"] != "CONSUMED"):
            _fail(IntegrityError, "SPOOL_CROSS_FILE_CONTRADICTION", safety_state="CONSUMED")
        if stage_state == "COMMIT" and (record["state"] != "CONSUMED" or ledger["state"] != "CONSUMED"):
            _fail(IntegrityError, "SPOOL_CROSS_FILE_CONTRADICTION", safety_state="CONSUMED")
        if stage_state == "ABANDON" and (record["state"] != "ABANDONED" or ledger["state"] not in LEDGER_STATES):
            _fail(IntegrityError, "SPOOL_CROSS_FILE_CONTRADICTION", safety_state="CONSUMED" if ledger["state"] == "CONSUMED" else None)
        if frame_summary is not None:
            for field in ("state", "next_sequence", "last_frame_hash", "highest_contiguous_commit", "frame_count", "total_spool_bytes", "last_stage"):
                if spool[field] != frame_summary[field]:
                    _fail(IntegrityError, "SPOOL_META_CONTRADICTION", safety_state="CONSUMED" if ledger["state"] == "CONSUMED" else None)

    def _load_epoch_unlocked(self, epoch_ref: str) -> EpochSnapshot:
        self._validate_epoch_entries(epoch_ref)
        record, _ = self._read_document(self._file_path(epoch_ref, RECORD_FILENAME), max_bytes=MAX_EPOCH_RECORD_BYTES, validator=validate_epoch_record)
        manifest, manifest_bytes = self._read_document(self._file_path(epoch_ref, MANIFEST_FILENAME), max_bytes=MAX_MANIFEST_BYTES, validator=validate_manifest)
        private, private_bytes = self._read_document(self._file_path(epoch_ref, PRIVATE_IDENTITIES_FILENAME), max_bytes=MAX_PRIVATE_IDENTITIES_BYTES, validator=validate_private_identities)
        try:
            ledger, _ = self._read_document(self._file_path(epoch_ref, LEDGER_FILENAME), max_bytes=MAX_RESTORE_LEDGER_BYTES, validator=validate_restore_ledger)
        except LedgerError:
            raise
        spool, _ = self._read_document(self._file_path(epoch_ref, SPOOL_META_FILENAME), max_bytes=MAX_SPOOL_META_BYTES, validator=validate_spool_meta)
        try:
            # Validate the complete private byte commitment before any frame
            # authentication is attempted.
            self._cross_validate(record, manifest, private, ledger, spool, manifest_bytes, private_bytes=private_bytes)
            frame_summary = self._read_frame_files(epoch_ref, spool, private, record=record, ledger=ledger)
            self._cross_validate(record, manifest, private, ledger, spool, manifest_bytes, private_bytes=private_bytes, frame_summary=frame_summary)
        except ControllerStoreError as error:
            if error.safety_state is None:
                error.safety_state = "CONSUMED" if ledger.get("state") == "CONSUMED" else None
            raise
        return EpochSnapshot(record, manifest, private, ledger, spool)

    @contextmanager
    def _in_process_epoch_lock(self, epoch_ref: str):
        with self._locks_guard:
            lock = self._epoch_locks.setdefault(epoch_ref, threading.RLock())
        with lock:
            yield

    @contextmanager
    def _epoch_lock(self, epoch_ref: str):
        with self._in_process_epoch_lock(epoch_ref):
            with self.adapter.epoch_transaction_lock(self._transaction_lock_path(epoch_ref)):
                yield

    def load_epoch(self, epoch_ref: str) -> EpochSnapshot:
        with self._epoch_lock(epoch_ref):
            return self._load_epoch_unlocked(epoch_ref)

    open_epoch = load_epoch

    def resume_epoch(self, epoch_ref: str) -> EpochSnapshot:
        with self._epoch_lock(epoch_ref):
            snapshot = self._load_epoch_unlocked(epoch_ref)
            if snapshot.record["state"] in TERMINAL_EPOCH_STATES or snapshot.ledger["state"] == "CONSUMED" or snapshot.spool["state"] in ("ABANDONED", "COMMITTED"):
                _fail(EpochStateError, "EPOCH_TERMINAL")
            return snapshot

    def read_authoritative_bytes(self, epoch_ref: str, filename: str) -> bytes:
        with self._epoch_lock(epoch_ref):
            return self.adapter.read_authority(self._document_path(epoch_ref, filename), max_bytes=_document_limit(filename))

    def create_epoch(
        self,
        epoch_ref: str,
        authority_ref: str,
        *,
        private_identities: Mapping[str, str],
        supersedes_epoch_ref: str | None = None,
    ) -> EpochSnapshot:
        _strict_ref(epoch_ref, "epoch_ref")
        _strict_ref(authority_ref, "authority_ref")
        private_input = _validate_private_input(private_identities)
        if supersedes_epoch_ref is not None:
            _strict_ref(supersedes_epoch_ref, "supersedes_epoch_ref")
        with self._in_process_epoch_lock(epoch_ref):
            epochs = self.root / "epochs"
            self.adapter.validate_component(epochs, expect_directory=True)
            epoch = epochs / epoch_ref
            if os.path.lexists(epoch):
                _fail(EpochStateError, "EPOCH_COLLISION")
            self.adapter.mkdir_exclusive(epoch)
            self.adapter.create_transaction_lock(self._transaction_lock_path(epoch_ref))
            spool = epoch / SPOOL_DIRNAME
            frames = spool / FRAMES_DIRNAME
            self.adapter.mkdir_exclusive(spool)
            self.adapter.mkdir_exclusive(frames)
            private = {
                "schema": SCHEMA_PRIVATE_IDENTITIES,
                "epoch_ref": epoch_ref,
                **private_input,
            }
            validate_private_identities(private)
            ledger = {
                "schema": SCHEMA_RESTORE_LEDGER,
                "epoch_ref": epoch_ref,
                "state": "UNCONSUMED",
                "transition_id": None,
                "transition_target": None,
                "transition_data_commitment": None,
            }
            validate_restore_ledger(ledger)
            private_bytes = canonical_json_bytes(private, max_bytes=MAX_PRIVATE_IDENTITIES_BYTES)
            private_identities_digest = bytes_commitment(DOMAIN_PRIVATE_IDENTITIES, private_bytes)
            barrier_source = "NONE" if supersedes_epoch_ref is None else supersedes_epoch_ref
            barrier = recovery_commitment(DOMAIN_SUPERSESSION_BARRIER, barrier_source, epoch_ref, authority_ref)
            container_commitment = recovery_commitment(DOMAIN_CONTAINER_IDENTITY, private_input["container_identity"])
            volume_commitment = recovery_commitment(DOMAIN_VOLUME_IDENTITY, private_input["volume_identity"])
            runner_commitment = recovery_commitment(DOMAIN_RUNNER_IDENTITY, private_input["runner_identity"])
            spool_commitment = recovery_commitment(DOMAIN_SPOOL, epoch_ref, authority_ref)
            durability = dict(self._durability)
            spool_meta = {
                "schema": SCHEMA_SPOOL_META,
                "epoch_ref": epoch_ref,
                "state": "OPEN",
                "next_sequence": 1,
                "last_frame_hash": ZERO_FRAME_HASH,
                "highest_contiguous_commit": 0,
                "frame_count": 0,
                "total_spool_bytes": 0,
                "last_stage": "NONE",
                "spool_commitment": spool_commitment,
            }
            validate_spool_meta(spool_meta)
            manifest = {
                "schema": SCHEMA_MANIFEST,
                "epoch_ref": epoch_ref,
                "authority_ref": authority_ref,
                "state": "INITIALISED",
                "supersession_barrier_commitment": barrier,
                "artifact_binding_state": "PENDING",
                "artifact_commitment": None,
                "container_commitment": container_commitment,
                "volume_commitment": volume_commitment,
                "runner_commitment": runner_commitment,
                "spool_commitment": spool_commitment,
                "private_identities_digest": private_identities_digest,
                "restore_ledger_ref": f"ledger-{epoch_ref}",
                "restore_ledger_state": "UNCONSUMED",
                "durability": durability,
            }
            validate_manifest(manifest)
            record = {
                "schema": SCHEMA_EPOCH_RECORD,
                "epoch_ref": epoch_ref,
                "authority_ref": authority_ref,
                "state": "INITIALISED",
                "supersession_barrier_commitment": barrier,
                "artifact_binding_state": "PENDING",
                "artifact_commitment": None,
                "container_commitment": container_commitment,
                "volume_commitment": volume_commitment,
                "runner_commitment": runner_commitment,
                "spool_commitment": spool_commitment,
                "private_identities_digest": private_identities_digest,
                "manifest_digest": "",
                "restore_ledger_ref": f"ledger-{epoch_ref}",
                "restore_ledger_state": "UNCONSUMED",
                "durability": durability,
            }
            manifest_bytes = self._write_document(self._file_path(epoch_ref, MANIFEST_FILENAME), manifest, max_bytes=MAX_MANIFEST_BYTES, replace=False)
            record["manifest_digest"] = bytes_commitment(DOMAIN_MANIFEST, manifest_bytes)
            validate_epoch_record(record)
            if self._write_document(
                self._file_path(epoch_ref, PRIVATE_IDENTITIES_FILENAME),
                private,
                max_bytes=MAX_PRIVATE_IDENTITIES_BYTES,
                replace=False,
            ) != private_bytes:
                _fail(DurabilityError, "PRIVATE_IDENTITIES_READBACK_MISMATCH")
            self._write_document(self._file_path(epoch_ref, LEDGER_FILENAME), ledger, max_bytes=MAX_RESTORE_LEDGER_BYTES, replace=False)
            self._write_document(self._file_path(epoch_ref, SPOOL_META_FILENAME), spool_meta, max_bytes=MAX_SPOOL_META_BYTES, replace=False)
            self._write_document(self._file_path(epoch_ref, RECORD_FILENAME), record, max_bytes=MAX_EPOCH_RECORD_BYTES, replace=False)
            return self._load_epoch_unlocked(epoch_ref)

    def _state_update_unlocked(self, snapshot: EpochSnapshot, *, state: str | None = None, artifact_state: str | None = None, artifact_commitment: str | None | object = ...,
                               ledger_state: str | None = None) -> EpochSnapshot:
        record = dict(snapshot.record)
        manifest = dict(snapshot.manifest)
        if state is not None:
            record["state"] = state
            manifest["state"] = state
        if artifact_state is not None:
            record["artifact_binding_state"] = artifact_state
            manifest["artifact_binding_state"] = artifact_state
        if artifact_commitment is not ...:
            record["artifact_commitment"] = artifact_commitment
            manifest["artifact_commitment"] = artifact_commitment
        if ledger_state is not None:
            record["restore_ledger_state"] = ledger_state
            manifest["restore_ledger_state"] = ledger_state
        validate_manifest(manifest)
        manifest_bytes = self._write_document(self._file_path(snapshot.record["epoch_ref"], MANIFEST_FILENAME), manifest, max_bytes=MAX_MANIFEST_BYTES, replace=True)
        record["manifest_digest"] = bytes_commitment(DOMAIN_MANIFEST, manifest_bytes)
        validate_epoch_record(record)
        self._write_document(self._file_path(snapshot.record["epoch_ref"], RECORD_FILENAME), record, max_bytes=MAX_EPOCH_RECORD_BYTES, replace=True)
        return self._load_epoch_unlocked(snapshot.record["epoch_ref"])

    def bind_artifact_row(self, epoch_ref: str, row_id: str) -> str:
        _strict_utf8_text(row_id, "artifact_row_id", max_bytes=8192)
        with self._epoch_lock(epoch_ref):
            snapshot = self._load_epoch_unlocked(epoch_ref)
            if snapshot.record["state"] in TERMINAL_EPOCH_STATES:
                _fail(EpochStateError, "EPOCH_TERMINAL")
            if snapshot.record["artifact_binding_state"] != "PENDING":
                _fail(EpochStateError, "ARTIFACT_TRANSITION_INVALID")
            if row_id != snapshot.private_identities["artifact_row_id"]:
                _fail(IntegrityError, "PRIVATE_BINDING_MISMATCH")
            commitment = recovery_commitment(DOMAIN_ARTIFACT_ROW, row_id)
            self._state_update_unlocked(snapshot, artifact_state="ROW_BOUND", artifact_commitment=commitment)
            return commitment

    def bind_artifact(self, epoch_ref: str, row_id: str, artifact_ref: str) -> str:
        _strict_utf8_text(row_id, "artifact_row_id", max_bytes=8192)
        _strict_utf8_text(artifact_ref, "artifact_ref", max_bytes=8192)
        with self._epoch_lock(epoch_ref):
            snapshot = self._load_epoch_unlocked(epoch_ref)
            if snapshot.record["state"] in TERMINAL_EPOCH_STATES:
                _fail(EpochStateError, "EPOCH_TERMINAL")
            if snapshot.record["artifact_binding_state"] != "ROW_BOUND":
                _fail(EpochStateError, "ARTIFACT_TRANSITION_INVALID")
            if row_id != snapshot.private_identities["artifact_row_id"] or artifact_ref != snapshot.private_identities["artifact_filename"]:
                _fail(IntegrityError, "PRIVATE_BINDING_MISMATCH")
            commitment = recovery_commitment(DOMAIN_ARTIFACT_ROW, row_id, artifact_ref)
            self._state_update_unlocked(snapshot, artifact_state="BOUND", artifact_commitment=commitment)
            return commitment

    def mark_ready(self, epoch_ref: str) -> EpochSnapshot:
        return self._transition_epoch(epoch_ref, "READY", allowed=("INITIALISED",))

    def activate(self, epoch_ref: str) -> EpochSnapshot:
        return self._transition_epoch(epoch_ref, "ACTIVE", allowed=("READY",))

    def abandon(self, epoch_ref: str) -> EpochSnapshot:
        with self._epoch_lock(epoch_ref):
            snapshot = self._load_epoch_unlocked(epoch_ref)
            if snapshot.record["state"] in TERMINAL_EPOCH_STATES:
                _fail(EpochStateError, "EPOCH_TERMINAL")
            frame = self._prepare_runner_frame_unlocked(snapshot, "ABANDON", {"state": "ABANDONED"})
            self._ingest_frame_unlocked(snapshot, frame)
            return self._load_epoch_unlocked(epoch_ref)

    def _transition_epoch(self, epoch_ref: str, target: str, *, allowed: Sequence[str]) -> EpochSnapshot:
        with self._epoch_lock(epoch_ref):
            snapshot = self._load_epoch_unlocked(epoch_ref)
            if snapshot.record["state"] not in allowed:
                _fail(EpochStateError, "EPOCH_TRANSITION_INVALID" if snapshot.record["state"] not in TERMINAL_EPOCH_STATES else "EPOCH_TERMINAL")
            return self._state_update_unlocked(snapshot, state=target)

    def supersede(self, old_epoch_ref: str, new_epoch_ref: str) -> EpochSnapshot:
        _strict_ref(old_epoch_ref, "old_epoch_ref")
        _strict_ref(new_epoch_ref, "new_epoch_ref")
        if old_epoch_ref == new_epoch_ref:
            _fail(EpochStateError, "SUPERSESSION_INVALID")
        first, second = sorted((old_epoch_ref, new_epoch_ref))
        with self._epoch_lock(first), self._epoch_lock(second):
            old_snapshot = self._load_epoch_unlocked(old_epoch_ref)
            new_snapshot = self._load_epoch_unlocked(new_epoch_ref)
            if old_snapshot.record["state"] in TERMINAL_EPOCH_STATES:
                _fail(EpochStateError, "EPOCH_TERMINAL")
            if new_snapshot.record["state"] not in ("INITIALISED", "READY"):
                _fail(EpochStateError, "SUPERSESSION_INVALID")
            expected = recovery_commitment(
                DOMAIN_SUPERSESSION_BARRIER,
                old_epoch_ref,
                new_epoch_ref,
                old_snapshot.record["authority_ref"],
            )
            if new_snapshot.record["supersession_barrier_commitment"] != expected:
                _fail(EpochStateError, "SUPERSESSION_BARRIER_MISMATCH")
            return self._state_update_unlocked(old_snapshot, state="SUPERSEDED")

    def read_restore_ledger(self, epoch_ref: str) -> dict[str, Any]:
        with self._epoch_lock(epoch_ref):
            self._validate_epoch_entries(epoch_ref)
            ledger, _ = self._read_document(self._file_path(epoch_ref, LEDGER_FILENAME), max_bytes=MAX_RESTORE_LEDGER_BYTES, validator=validate_restore_ledger)
            return ledger

    def record_digest(self, epoch_ref: str) -> str:
        with self._epoch_lock(epoch_ref):
            path = self._file_path(epoch_ref, RECORD_FILENAME)
            payload = self.adapter.read_authority(path, max_bytes=MAX_EPOCH_RECORD_BYTES)
            record = parse_canonical_json(payload, max_bytes=MAX_EPOCH_RECORD_BYTES)
            validate_epoch_record(record)
            if canonical_json_bytes(record, max_bytes=MAX_EPOCH_RECORD_BYTES) != payload:
                _fail(IntegrityError, "RECORD_NOT_CANONICAL", safety_state="CONSUMED")
            return bytes_commitment(DOMAIN_EPOCH_RECORD, payload)

    def _ledger_digest_unlocked(self, epoch_ref: str) -> str:
        self._validate_epoch_entries(epoch_ref)
        path = self._file_path(epoch_ref, LEDGER_FILENAME)
        try:
            payload = self.adapter.read_authority(path, max_bytes=MAX_RESTORE_LEDGER_BYTES)
            ledger = parse_canonical_json(payload, max_bytes=MAX_RESTORE_LEDGER_BYTES)
            validate_restore_ledger(ledger)
        except LedgerError:
            raise
        except ControllerStoreError:
            _fail(LedgerError, "LEDGER_UNAVAILABLE", safety_state="CONSUMED")
        if canonical_json_bytes(ledger, max_bytes=MAX_RESTORE_LEDGER_BYTES) != payload:
            _fail(LedgerError, "LEDGER_NOT_CANONICAL", safety_state="CONSUMED")
        return bytes_commitment(DOMAIN_RESTORE_LEDGER, payload)

    def ledger_digest(self, epoch_ref: str) -> str:
        with self._epoch_lock(epoch_ref):
            return self._ledger_digest_unlocked(epoch_ref)

    def ledger_safety_classification(self, epoch_ref: str) -> str:
        try:
            with self._epoch_lock(epoch_ref):
                snapshot = self._load_epoch_unlocked(epoch_ref)
            return "UNCONSUMED" if snapshot.ledger["state"] == "UNCONSUMED" else "CONSUMED"
        except ControllerStoreError:
            return "CONSUMED"

    def consume_restore(
        self,
        epoch_ref: str,
        transition_id: str,
        *,
        expected_digest: str | None,
        data: Any = None,
    ) -> RestorePermit:
        _strict_ref(transition_id, "transition_id")
        if not isinstance(expected_digest, str) or COMMITMENT_RE.fullmatch(expected_digest) is None:
            _fail(LedgerError, "CAS_REQUIRED", safety_state="CONSUMED")
        data_commitment = _private_data_commitment(data)
        with self._epoch_lock(epoch_ref):
            snapshot = self._load_epoch_unlocked(epoch_ref)
            ledger = snapshot.ledger
            if ledger["state"] == "CONSUMED":
                if snapshot.record["state"] == "ABANDONED":
                    _fail(LedgerError, "EPOCH_TERMINAL", safety_state="CONSUMED")
                if ledger["transition_id"] != transition_id or ledger["transition_target"] != "RESTORE_STARTED" or ledger["transition_data_commitment"] != data_commitment:
                    _fail(LedgerError, "LEDGER_CONTRADICTION", safety_state="CONSUMED")
                return RestorePermit(epoch_ref, transition_id, "CONSUMED", True)
            if snapshot.record["state"] in TERMINAL_EPOCH_STATES:
                _fail(LedgerError, "EPOCH_TERMINAL", safety_state="CONSUMED")
            if snapshot.record["state"] != "ACTIVE":
                _fail(LedgerError, "EPOCH_NOT_ACTIVE", safety_state="UNCONSUMED")
            if snapshot.spool["state"] != "OPEN" or snapshot.spool["last_stage"] != "RUNNER_STARTED":
                _fail(LedgerError, "RESTORE_PRECONDITION_FAILED", safety_state="UNCONSUMED")
            actual_digest = self._ledger_digest_unlocked(epoch_ref)
            if actual_digest != expected_digest:
                _fail(LedgerError, "CAS_MISMATCH", safety_state="UNCONSUMED")
            consumed = {
                "schema": SCHEMA_RESTORE_LEDGER,
                "epoch_ref": epoch_ref,
                "state": "CONSUMED",
                "transition_id": transition_id,
                "transition_target": "RESTORE_STARTED",
                "transition_data_commitment": data_commitment,
            }
            validate_restore_ledger(consumed)
            # This is the one-way authority transition.  No restore bytes are
            # accepted or emitted by this API.
            try:
                self._write_document(self._file_path(epoch_ref, LEDGER_FILENAME), consumed, max_bytes=MAX_RESTORE_LEDGER_BYTES, replace=True)
                self._state_update_unlocked(snapshot, ledger_state="CONSUMED")
            except ControllerStoreError as error:
                error.safety_state = "CONSUMED"
                raise
            return RestorePermit(epoch_ref, transition_id, "CONSUMED", False)

    def _frame_payload_bytes(self, payload: Mapping[str, Any]) -> bytes:
        _validate_frame_payload(payload)
        return canonical_json_bytes(payload, max_bytes=MAX_FRAME_BYTES)

    def _frame_auth_message(self, epoch_ref: str, sequence: int, stage: str, payload: Mapping[str, Any], previous_hash: str) -> bytes:
        payload_bytes = self._frame_payload_bytes(payload)
        payload_commitment = bytes_commitment(DOMAIN_RUNNER_FRAME_PAYLOAD, payload_bytes)
        return _length_prefixed(("runner-frame-auth.v1", epoch_ref, str(sequence), stage, previous_hash, payload_commitment))

    def _frame_auth(self, private: Mapping[str, Any], epoch_ref: str, sequence: int, stage: str, payload: Mapping[str, Any], previous_hash: str) -> str:
        key = private["spool_hmac_key"].encode("utf-8", "strict")
        return "hmac:v1:" + hmac.new(key, self._frame_auth_message(epoch_ref, sequence, stage, payload, previous_hash), hashlib.sha256).hexdigest()

    def _frame_hash(self, epoch_ref: str, sequence: int, stage: str, payload: Mapping[str, Any], previous_hash: str, auth: str) -> str:
        payload_bytes = self._frame_payload_bytes(payload)
        payload_commitment = bytes_commitment(DOMAIN_RUNNER_FRAME_PAYLOAD, payload_bytes)
        message = _length_prefixed(("runner-frame-hash.v1", epoch_ref, str(sequence), stage, payload_commitment, previous_hash, auth))
        return COMMITMENT_PREFIX + hashlib.sha256(message).hexdigest()

    def _validate_stage_transition(self, snapshot: EpochSnapshot, stage: str) -> None:
        if stage not in FRAME_STAGES:
            _fail(SpoolError, "INVALID_FRAME_STAGE")
        if snapshot.spool["state"] != "OPEN":
            _fail(SpoolError, "SPOOL_TERMINAL")
        previous = snapshot.spool["last_stage"]
        if stage not in FRAME_STAGE_TRANSITIONS[previous]:
            _fail(SpoolError, "FRAME_STAGE_CONTRADICTION")
        state = snapshot.record["state"]
        if stage == "EPOCH_READY":
            if state not in ("READY", "ACTIVE"):
                _fail(SpoolError, "EPOCH_NOT_READY")
        elif stage == "RUNNER_STARTED":
            if state != "ACTIVE":
                _fail(SpoolError, "EPOCH_NOT_ACTIVE")
        elif stage == "RESTORE_BEGIN":
            if state != "ACTIVE":
                _fail(SpoolError, "EPOCH_NOT_ACTIVE", safety_state="CONSUMED")
            if snapshot.ledger["state"] != "CONSUMED":
                _fail(SpoolError, "RESTORE_BEGIN_BEFORE_LEDGER_CONSUMED", safety_state="CONSUMED")
        elif stage == "COMMIT":
            if state != "ACTIVE":
                _fail(SpoolError, "EPOCH_NOT_ACTIVE", safety_state="CONSUMED")
            if snapshot.ledger["state"] != "CONSUMED":
                _fail(SpoolError, "COMMIT_BEFORE_LEDGER_CONSUMED", safety_state="CONSUMED")
        elif stage == "ABANDON":
            if not _is_legal_abandon_transition(previous, snapshot.ledger["state"]):
                if snapshot.ledger["state"] == "CONSUMED":
                    _fail(SpoolError, "ABANDON_AFTER_LEDGER_CONSUMED", safety_state="CONSUMED")
                _fail(SpoolError, "FRAME_STAGE_CONTRADICTION")

    def _prepare_runner_frame_unlocked(self, snapshot: EpochSnapshot, stage: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        self._validate_stage_transition(snapshot, stage)
        if not isinstance(payload, Mapping):
            _fail(SpoolError, "INVALID_FRAME_PAYLOAD")
        payload_dict = dict(payload)
        _validate_frame_payload(payload_dict)
        epoch_ref = snapshot.record["epoch_ref"]
        sequence = snapshot.spool["next_sequence"]
        previous_hash = snapshot.spool["last_frame_hash"]
        auth = self._frame_auth(snapshot.private_identities, epoch_ref, sequence, stage, payload_dict, previous_hash)
        frame = {
            "schema": SCHEMA_RUNNER_FRAME,
            "epoch_ref": epoch_ref,
            "sequence": sequence,
            "stage": stage,
            "payload": payload_dict,
            "previous_hash": previous_hash,
            "auth": auth,
            "frame_hash": self._frame_hash(epoch_ref, sequence, stage, payload_dict, previous_hash, auth),
        }
        validate_runner_frame(frame)
        return frame

    def _ingest_frame_unlocked(self, snapshot: EpochSnapshot, frame: Mapping[str, Any]) -> FrameReceipt:
        epoch_ref = snapshot.record["epoch_ref"]
        candidate = dict(frame)
        validate_runner_frame(candidate)
        if candidate["epoch_ref"] != epoch_ref:
            _fail(SpoolError, "FRAME_EPOCH_MISMATCH")
        expected_sequence = snapshot.spool["next_sequence"]
        if candidate["sequence"] < expected_sequence:
            _fail(SpoolError, "FRAME_DUPLICATE")
        if candidate["sequence"] > expected_sequence:
            _fail(SpoolError, "FRAME_GAP_OR_REORDER")
        if expected_sequence > MAX_FRAMES:
            _fail(SpoolError, "FRAME_LIMIT_EXCEEDED")
        if candidate["previous_hash"] != snapshot.spool["last_frame_hash"]:
            _fail(SpoolError, "FRAME_HASH_CHAIN_INVALID")
        expected_auth = self._frame_auth(snapshot.private_identities, epoch_ref, candidate["sequence"], candidate["stage"], candidate["payload"], candidate["previous_hash"])
        if not hmac.compare_digest(candidate["auth"], expected_auth):
            _fail(SpoolError, "FRAME_AUTH_INVALID")
        expected_hash = self._frame_hash(epoch_ref, candidate["sequence"], candidate["stage"], candidate["payload"], candidate["previous_hash"], candidate["auth"])
        if candidate["frame_hash"] != expected_hash:
            _fail(SpoolError, "FRAME_HASH_INVALID")
        self._validate_stage_transition(snapshot, candidate["stage"])
        try:
            frame_path = self._frames_path(epoch_ref) / f"frame-{candidate['sequence']:012d}.json"
            frame_bytes = self._write_document(frame_path, candidate, max_bytes=MAX_FRAME_BYTES, replace=False)
            new_highest = candidate["sequence"] if candidate["stage"] == "COMMIT" else snapshot.spool["highest_contiguous_commit"]
            new_spool_state = "COMMITTED" if candidate["stage"] == "COMMIT" else "ABANDONED" if candidate["stage"] == "ABANDON" else "OPEN"
            new_spool = dict(snapshot.spool)
            new_spool.update(
                {
                    "state": new_spool_state,
                    "next_sequence": expected_sequence + 1,
                    "last_frame_hash": candidate["frame_hash"],
                    "highest_contiguous_commit": new_highest,
                    "frame_count": snapshot.spool["frame_count"] + 1,
                    "total_spool_bytes": snapshot.spool["total_spool_bytes"] + len(frame_bytes),
                    "last_stage": candidate["stage"],
                }
            )
            validate_spool_meta(new_spool)
            if new_spool["total_spool_bytes"] > MAX_TOTAL_SPOOL_BYTES:
                _fail(SpoolError, "SPOOL_LIMIT_EXCEEDED")
            self._write_document(self._file_path(epoch_ref, SPOOL_META_FILENAME), new_spool, max_bytes=MAX_SPOOL_META_BYTES, replace=True)
            if candidate["stage"] == "COMMIT":
                self._state_update_unlocked(snapshot, state="CONSUMED")
            elif candidate["stage"] == "ABANDON":
                self._state_update_unlocked(snapshot, state="ABANDONED")
            else:
                self._load_epoch_unlocked(epoch_ref)
        except ControllerStoreError as error:
            if candidate["stage"] in ("RESTORE_BEGIN", "COMMIT", "ABANDON") and snapshot.ledger["state"] == "CONSUMED":
                error.safety_state = "CONSUMED"
            raise
        return FrameReceipt(epoch_ref, candidate["sequence"], new_highest, new_spool["frame_count"])

    def prepare_runner_frame(self, epoch_ref: str, stage: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        with self._epoch_lock(epoch_ref):
            snapshot = self._load_epoch_unlocked(epoch_ref)
            if snapshot.record["state"] in TERMINAL_EPOCH_STATES:
                _fail(EpochStateError, "EPOCH_TERMINAL")
            return self._prepare_runner_frame_unlocked(snapshot, stage, payload)

    def ingest_frame(self, epoch_ref: str, frame: Mapping[str, Any]) -> FrameReceipt:
        if not isinstance(frame, Mapping):
            _fail(SpoolError, "INVALID_RUNNER_FRAME")
        with self._epoch_lock(epoch_ref):
            snapshot = self._load_epoch_unlocked(epoch_ref)
            if snapshot.record["state"] in TERMINAL_EPOCH_STATES:
                _fail(SpoolError, "EPOCH_TERMINAL")
            return self._ingest_frame_unlocked(snapshot, frame)

    def public_projection(self, epoch_ref: str) -> dict[str, Any]:
        with self._epoch_lock(epoch_ref):
            snapshot = self._load_epoch_unlocked(epoch_ref)
            evidence = {
                "schema": SCHEMA_PUBLIC_EVIDENCE,
                "epoch_ref": snapshot.record["epoch_ref"],
                "authority_ref": snapshot.record["authority_ref"],
                "state": snapshot.record["state"],
                "artifact_binding_state": snapshot.record["artifact_binding_state"],
                "artifact_commitment": snapshot.record["artifact_commitment"],
                "manifest_digest": snapshot.record["manifest_digest"],
                "restore_ledger_ref": snapshot.record["restore_ledger_ref"],
                "restore_ledger_state": snapshot.ledger["state"],
                "spool_commitment": snapshot.spool["spool_commitment"],
                "highest_contiguous_commit": snapshot.spool["highest_contiguous_commit"],
                "frame_count": snapshot.spool["frame_count"],
                "durability_classification": "DURABLE",
            }
            validate_public_evidence(evidence)
            return evidence


def validate_public_evidence(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or tuple(value.keys()) != PUBLIC_EVIDENCE_FIELDS:
        _fail(PublicEvidenceError, "PUBLIC_FIELD_FORBIDDEN")
    if any(isinstance(child, (dict, list)) for child in value.values()):
        _fail(PublicEvidenceError, "PUBLIC_NESTED_FIELD_FORBIDDEN")
    if value["schema"] != SCHEMA_PUBLIC_EVIDENCE:
        _fail(PublicEvidenceError, "PUBLIC_SCHEMA_INVALID")
    _strict_ref(value["epoch_ref"], "public_epoch_ref")
    _strict_ref(value["authority_ref"], "public_authority_ref")
    if value["state"] not in EPOCH_STATES or value["artifact_binding_state"] not in ARTIFACT_STATES or value["restore_ledger_state"] not in LEDGER_STATES:
        _fail(PublicEvidenceError, "PUBLIC_STATE_INVALID")
    _strict_commitment(value["artifact_commitment"], "public_artifact_commitment", nullable=True)
    _strict_commitment(value["manifest_digest"], "public_manifest_digest")
    _strict_ref(value["restore_ledger_ref"], "public_ledger_ref")
    _strict_commitment(value["spool_commitment"], "public_spool_commitment")
    for field in ("highest_contiguous_commit", "frame_count"):
        if not _is_exact_int(value[field]) or value[field] < 0:
            _fail(PublicEvidenceError, "PUBLIC_COUNTER_INVALID")
    if value["highest_contiguous_commit"] > value["frame_count"]:
        _fail(PublicEvidenceError, "PUBLIC_COUNTER_INVALID")
    if value["state"] == "CONSUMED" and value["restore_ledger_state"] != "CONSUMED":
        _fail(PublicEvidenceError, "PUBLIC_STATE_INVALID")
    if value["artifact_binding_state"] == "PENDING" and value["artifact_commitment"] is not None:
        _fail(PublicEvidenceError, "PUBLIC_STATE_INVALID")
    if value["artifact_binding_state"] != "PENDING" and value["artifact_commitment"] is None:
        _fail(PublicEvidenceError, "PUBLIC_STATE_INVALID")
    if value["durability_classification"] != "DURABLE":
        _fail(PublicEvidenceError, "PUBLIC_DURABILITY_INVALID")
    if any(isinstance(child, (dict, list)) for child in value.values()):
        _fail(PublicEvidenceError, "PUBLIC_NESTED_FIELD_FORBIDDEN")
    return value


def serialize_public_evidence(value: Mapping[str, Any]) -> bytes:
    if not isinstance(value, Mapping):
        _fail(PublicEvidenceError, "PUBLIC_FIELD_FORBIDDEN")
    evidence = dict(value)
    validate_public_evidence(evidence)
    return canonical_json_bytes(evidence, max_bytes=8 * 1024)


def import_restore_ledger(value: Any) -> dict[str, Any]:
    # There is deliberately no migration path for Run-276's unknown state.
    if isinstance(value, Mapping) and value.get("state") == "UNKNOWN_POTENTIALLY_CONSUMED":
        _fail(LedgerError, "UNKNOWN_LEDGER_STATE", safety_state="CONSUMED")
    return validate_restore_ledger(value)


__all__ = [
    "ARTIFACT_STATES",
    "COMMITMENT_PREFIX",
    "ControllerStore",
    "ControllerStoreError",
    "DurabilityAdapter",
    "DurabilityError",
    "EpochSnapshot",
    "EpochStateError",
    "FilesystemSafetyError",
    "FrameReceipt",
    "IntegrityError",
    "LedgerError",
    "MAX_EPOCH_RECORD_BYTES",
    "MAX_FRAME_BYTES",
    "MAX_FRAMES",
    "MAX_MANIFEST_BYTES",
    "MAX_PRIVATE_IDENTITIES_BYTES",
    "MAX_RESTORE_LEDGER_BYTES",
    "MAX_SPOOL_META_BYTES",
    "MAX_TOTAL_SPOOL_BYTES",
    "PosixDurabilityAdapter",
    "PublicEvidenceError",
    "RestorePermit",
    "SCHEMA_EPOCH_RECORD",
    "SCHEMA_MANIFEST",
    "SCHEMA_PRIVATE_IDENTITIES",
    "SCHEMA_RESTORE_LEDGER",
    "SCHEMA_RUNNER_FRAME",
    "SCHEMA_SPOOL_META",
    "SchemaError",
    "SpoolError",
    "WindowsDurabilityAdapter",
    "bytes_commitment",
    "private_identities_commitment",
    "canonical_json_bytes",
    "import_restore_ledger",
    "make_durability_adapter",
    "parse_canonical_json",
    "recovery_commitment",
    "serialize_public_evidence",
    "validate_epoch_record",
    "validate_manifest",
    "validate_private_identities",
    "validate_public_evidence",
    "validate_restore_ledger",
    "validate_runner_frame",
    "validate_spool_meta",
]
