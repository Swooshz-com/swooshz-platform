#!/usr/bin/python3 -I
"""Fixed, repository-only recovery agent for the SWZFRM02 contract.

The installed agent has two deliberately small trust boundaries: a fixed
descriptor entrypoint and a single framed session.  Docker and locator
operations are admitted only after their public evidence is bound.  All
failure states are symbolic and fail closed; this module never contains live
provider credentials or a restore target.
"""

from __future__ import annotations

import base64
import builtins
import ctypes
import dataclasses
import datetime
import errno
import hashlib
import io
import json
import os
import pathlib
import queue
import re
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import types
import urllib.parse
import zlib
from dataclasses import dataclass
from typing import Any, BinaryIO, Callable, Mapping


CANONICAL_REVISION = "c59446ecc57b8100efd84fbd8405317f4fe7978f"
CANONICAL_LOCATOR_PATH = "scripts/platform-persisted-locator-adapter.py"
CANONICAL_LOCATOR_BLOB = "c0b46e18bf75fcc31c4154e9dc53adac45b7fd91"
CANONICAL_LOCATOR_SOURCE_BYTES = 35994
CANONICAL_LOCATOR_SOURCE_LINES = 1019
CANONICAL_LOCATOR_SOURCE_SHA256 = "17925f1364565edbb39fa0f776e25d6f0410d8408d9bdce214143edf1d6f34d5"
CANONICAL_LOCATOR_COMPRESSED_BYTES = 8398
CANONICAL_LOCATOR_COMPRESSED_SHA256 = "5913fd800e89eff823cef6c08753154e5447eb0ff04eca68dac1668999d002ee"
CANONICAL_LOCATOR_ENCODED_BYTES = 11198
CANONICAL_LOCATOR_ENCODED_SHA256 = "44fba3ed738e696e83e72d0a406cb1d8652c21aaa49f583debb4d907fae05321"
LOCATOR_PACKAGE_ATTESTATION = "49ff535562d62c7b06b02638685c8962e24714d873b8c75a2602a05d84ded386"

COMMITMENT_PREFIX = "sha256:v1:"
COMMITMENT_RE = re.compile(r"sha256:v1:[0-9a-f]{64}\Z", re.ASCII)
REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z", re.ASCII)
IMAGE_ID_RE = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
CANONICAL_UTC_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z", re.ASCII
)

MAX_FRAME_BYTES = 65536
FRAME_HEADER_BYTES = 56
MAX_CONTROL_PAYLOAD_BYTES = 4096
MAX_SESSION_FRAMES = 16
MAX_SESSION_BYTES = 1024 * 1024
MAX_CAPTURE_BYTES = 4096
MAX_FILENAME_BYTES = 2048
MAX_AGENT_BYTES = 524288
READ_CHUNK_BYTES = 4096
MAX_HTTP_HEADER_BYTES = 16384
MAX_HTTP_BODY_BYTES = 65536
MAX_EFFECTIVE_CONFIG_BYTES = 65536
ENGINE_EVENT_QUEUE_MAX = 16
ENGINE_QUEUE_TIMEOUT_SECONDS = 0.25
ENGINE_IO_DEADLINE_SECONDS = 17.0
METADATA_SOURCE_CONTAINER_NAME = "coolify-db"
PRODUCTION_ARTIFACT_ROOT = "/opt/swooshz/recovery/artifacts"
PRODUCTION_IMAGE_ID_PATH = "/opt/swooshz/recovery/postgres-image-id"
PRODUCTION_AGENT_COMMITMENT_PATH = "/opt/swooshz/recovery/recovery-agent-v1.commitment"

SWZFRM02_MAGIC = b"SWZFRM02"
SWZFRM02_VERSION = 2
SWZFRM02_FLAGS = 0
SWZFRM02_HEADER = struct.Struct("!8sBBBBQ32sI")
assert SWZFRM02_HEADER.size == FRAME_HEADER_BYTES

DIRECTION_LOCAL_TO_REMOTE = 1
DIRECTION_REMOTE_TO_LOCAL = 2
MESSAGE_BOOT = 1
MESSAGE_READY = 2
MESSAGE_DISCOVERY = 3
MESSAGE_PROCEED = 4
MESSAGE_RESULT = 5
MESSAGE_ABORT = 6
MESSAGE_NAMES = {
    MESSAGE_BOOT: "BOOT",
    MESSAGE_READY: "READY",
    MESSAGE_DISCOVERY: "DISCOVERY",
    MESSAGE_PROCEED: "PROCEED",
    MESSAGE_RESULT: "RESULT",
    MESSAGE_ABORT: "ABORT",
}
MESSAGE_BY_NAME = {value: key for key, value in MESSAGE_NAMES.items()}

SCHEMA_WIRE = "swz-recovery-wire.v2"
SCHEMA_RESULT = "swz-recovery-result.v2"
SCHEMA_ABORT = "swz-recovery-abort.v2"
SCHEMA_IMAGE_EVIDENCE = "swz-recovery-image-evidence.v2"
SCHEMA_TARGET_EVIDENCE = "swz-recovery-target-evidence.v2"
SCHEMA_ISOLATION_EVIDENCE = "swz-recovery-isolation-evidence.v2"
SCHEMA_ARTIFACT_STREAM = "swz-recovery-artifact-stream.v2"
SCHEMA_PROCESS_EVIDENCE = "swz-recovery-process-evidence.v2"
SCHEMA_RESTORE_EVIDENCE = "swz-recovery-restore-evidence.v2"
SCHEMA_CLEANUP_EVIDENCE = "swz-recovery-cleanup-evidence.v2"

BOOT_FIELDS = (
    "type", "version", "schema", "n_local", "epoch_ref", "authority_ref",
    "barrier_utc", "epoch_commitment", "authority_commitment",
    "barrier_commitment", "runner_commitment", "bundle_commitment",
    "launcher_commitment", "agent_commitment", "ssh_endpoint_commitment",
)
READY_FIELDS = (
    "type", "version", "schema", "n_local", "epoch_ref", "authority_ref",
    "barrier_utc", "epoch_commitment", "authority_commitment",
    "barrier_commitment", "runner_commitment", "bundle_commitment",
    "launcher_commitment", "agent_commitment",
)
DISCOVERY_FIELDS = (
    "type", "version", "schema", "epoch_ref", "authority_ref",
    "execution_row_id", "artifact_filename", "image_commitment",
    "target_commitment", "isolation_commitment", "artifact_commitment",
    "artifact_stream_commitment",
)
PROCEED_FIELDS = (
    "type", "version", "schema", "epoch_ref", "authority_ref", "barrier_utc",
    "epoch_commitment", "authority_commitment", "barrier_commitment",
    "runner_commitment", "bundle_commitment", "launcher_commitment",
    "agent_commitment", "image_commitment", "target_commitment",
    "isolation_commitment", "artifact_commitment", "artifact_stream_commitment",
    "transition_id", "pre_cas_ledger_digest", "transition_data_commitment",
    "consumed_record_commitment", "restore_begin_commitment",
)
RESULT_FIELDS = (
    "type", "version", "schema", "classification", "result_evidence",
    "result_commitment",
)
ABORT_FIELDS = (
    "type", "version", "schema", "code", "stage", "direction", "evidence",
    "evidence_commitment",
)
WIRE_FIELDS = {
    "BOOT": BOOT_FIELDS,
    "READY": READY_FIELDS,
    "DISCOVERY": DISCOVERY_FIELDS,
    "PROCEED": PROCEED_FIELDS,
    "RESULT": RESULT_FIELDS,
    "ABORT": ABORT_FIELDS,
}
ABORT_STAGES = (
    "BOOT", "READY", "DISCOVERY", "PRE_CAS", "CAS_B", "RESTORE_BEGIN",
    "PROCEED", "RESTORE", "CLEANUP", "PROCESS",
)
LOCAL_ABORT_STAGES = frozenset({"BOOT", "READY", "DISCOVERY", "PRE_CAS", "CAS_B", "RESTORE_BEGIN"})
REMOTE_ABORT_STAGES = frozenset({"BOOT", "READY", "DISCOVERY", "PROCEED", "RESTORE", "CLEANUP", "PROCESS"})
RESULT_CLASSIFICATIONS = frozenset({"SUCCESS", "FAILURE"})
DIRECTION_NAMES = {DIRECTION_LOCAL_TO_REMOTE: "LOCAL_TO_REMOTE", DIRECTION_REMOTE_TO_LOCAL: "REMOTE_TO_LOCAL"}


class RecoveryError(RuntimeError):
    """Public-safe symbolic recovery failure."""

    def __init__(self, code: str, *, safety_state: str = "UNCONSUMED") -> None:
        self.code = code
        self.safety_state = safety_state
        super().__init__(code)


class ProtocolError(RecoveryError):
    pass


class LoaderIntegrityError(RecoveryError):
    pass


class DescriptorAdmissionError(RecoveryError):
    pass


class DockerAdmissionError(RecoveryError):
    pass


class FinalityError(RecoveryError):
    pass


def _length_prefixed(parts: tuple[str | bytes, ...]) -> bytes:
    output = bytearray()
    for part in parts:
        value = part.encode("utf-8") if isinstance(part, str) else part
        if not isinstance(value, bytes) or len(value) > 0xFFFFFFFF:
            raise RecoveryError("COMMITMENT_INPUT_INVALID")
        output.extend(struct.pack(">I", len(value)))
        output.extend(value)
    return bytes(output)


def text_commitment(domain: str, *fields: str) -> str:
    if not isinstance(domain, str) or not domain.isascii() or not domain:
        raise RecoveryError("COMMITMENT_DOMAIN_INVALID")
    if any(not isinstance(field, str) for field in fields):
        raise RecoveryError("COMMITMENT_FIELD_INVALID")
    return COMMITMENT_PREFIX + hashlib.sha256(
        _length_prefixed(("recovery-commitment.v1", domain, *fields))
    ).hexdigest()


def bytes_commitment(domain: str, payload: bytes) -> str:
    if not isinstance(payload, bytes):
        raise RecoveryError("COMMITMENT_BYTES_INVALID")
    if not isinstance(domain, str) or not domain.isascii() or not domain:
        raise RecoveryError("COMMITMENT_DOMAIN_INVALID")
    return COMMITMENT_PREFIX + hashlib.sha256(
        _length_prefixed(("recovery-commitment.v1", domain))
        + struct.pack(">I", len(payload))
        + payload
    ).hexdigest()


def _reject_json_values(value: Any) -> None:
    if type(value) is float:
        raise ProtocolError("JSON_FLOAT_FORBIDDEN")
    if isinstance(value, Mapping):
        for key, child in value.items():
            if type(key) is not str:
                raise ProtocolError("JSON_KEY_INVALID")
            _reject_json_values(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _reject_json_values(child)
    elif isinstance(value, (str, int, bool)) or value is None:
        return
    else:
        raise ProtocolError("JSON_VALUE_INVALID")


def canonical_json(value: Any, *, limit: int = MAX_CONTROL_PAYLOAD_BYTES, terminal_lf: bool = False) -> bytes:
    _reject_json_values(value)
    try:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        payload = encoded.encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ProtocolError("CANONICAL_JSON_INVALID") from error
    if terminal_lf:
        payload += b"\n"
    if len(payload) > limit:
        raise ProtocolError("CANONICAL_JSON_OVERSIZE")
    return payload


def _reject_constant(_value: str) -> None:
    raise ProtocolError("JSON_CONSTANT_FORBIDDEN")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ProtocolError("JSON_DUPLICATE_KEY")
        result[key] = value
    return result


def parse_wire_json(payload: bytes) -> dict[str, Any]:
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_CONTROL_PAYLOAD_BYTES:
        raise ProtocolError("FRAME_PAYLOAD_INVALID")
    if payload.startswith((b"\xef\xbb\xbf", b" ", b"\t", b"\r", b"\n")) or payload.endswith((b" ", b"\t", b"\r", b"\n")):
        raise ProtocolError("CANONICAL_JSON_INVALID")
    try:
        value = json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
            parse_float=lambda _value: (_ for _ in ()).throw(ProtocolError("JSON_FLOAT_FORBIDDEN")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ProtocolError) as error:
        if isinstance(error, ProtocolError):
            raise
        raise ProtocolError("FRAME_PAYLOAD_INVALID") from error
    if not isinstance(value, dict) or canonical_json(value) != payload:
        raise ProtocolError("CANONICAL_JSON_INVALID")
    return value


def _is_commitment(value: Any) -> bool:
    return isinstance(value, str) and COMMITMENT_RE.fullmatch(value) is not None


def _validate_ref(value: Any, label: str) -> str:
    if not isinstance(value, str) or REF_RE.fullmatch(value) is None:
        raise ProtocolError(f"{label}_INVALID")
    return value


def _validate_commitment(value: Any, label: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not _is_commitment(value):
        raise ProtocolError(f"{label}_INVALID")
    return value


def validate_barrier_utc(value: Any) -> str:
    if not isinstance(value, str) or CANONICAL_UTC_RE.fullmatch(value) is None:
        raise ProtocolError("BARRIER_INVALID")
    try:
        parsed = datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except (ValueError, OverflowError) as error:
        raise ProtocolError("BARRIER_INVALID") from error
    if parsed.year < 1970 or parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ") != value:
        raise ProtocolError("BARRIER_INVALID")
    return value


def _validate_filename(value: Any) -> str:
    if not isinstance(value, str):
        raise ProtocolError("FILENAME_INVALID")
    encoded = value.encode("utf-8", "strict")
    if (
        not encoded or len(encoded) > MAX_FILENAME_BYTES or value in (".", "..")
        or "/" in value or "\\" in value
        or any(ord(char) <= 0x1F or ord(char) == 0x7F for char in value)
    ):
        raise ProtocolError("FILENAME_INVALID")
    return value


def _validate_image_id(value: Any) -> str:
    if not isinstance(value, str) or IMAGE_ID_RE.fullmatch(value) is None:
        raise ProtocolError("IMAGE_ID_INVALID")
    return value


def _validate_field_value(name: str, value: Any, *, n_local: bytes | None = None) -> None:
    if name in {"type", "schema", "epoch_ref", "authority_ref", "transition_id", "code", "stage", "direction"}:
        if not isinstance(value, str):
            raise ProtocolError("FIELD_TYPE_INVALID")
    elif name == "version":
        if type(value) is not int or value != SWZFRM02_VERSION:
            raise ProtocolError("VERSION_INVALID")
    elif name == "n_local":
        if not isinstance(value, str) or len(value) != 64 or value != value.lower():
            raise ProtocolError("N_LOCAL_INVALID")
        try:
            decoded = bytes.fromhex(value)
        except ValueError as error:
            raise ProtocolError("N_LOCAL_INVALID") from error
        if len(decoded) != 32 or (n_local is not None and decoded != n_local):
            raise ProtocolError("N_LOCAL_INVALID")
    elif name == "barrier_utc":
        validate_barrier_utc(value)
    elif name.endswith("_commitment") or name.endswith("_digest"):
        _validate_commitment(value, name)
    elif name == "execution_row_id":
        if type(value) is not int or not 0 < value <= 0x7FFFFFFFFFFFFFFF:
            raise ProtocolError("DISCOVERY_INVALID")
    elif name == "artifact_filename":
        _validate_filename(value)
    elif name == "classification":
        if value not in RESULT_CLASSIFICATIONS:
            raise ProtocolError("CLASSIFICATION_INVALID")
    elif name in {"result_evidence", "evidence"}:
        if not isinstance(value, dict):
            raise ProtocolError(f"{name.upper()}_INVALID")
    elif name not in {"type", "version", "schema"} and value is None:
        raise ProtocolError("FIELD_VALUE_INVALID")


def validate_wire_payload(value: Mapping[str, Any], expected_type: str, *, n_local: bytes | None = None) -> dict[str, Any]:
    if expected_type not in WIRE_FIELDS or not isinstance(value, Mapping):
        raise ProtocolError("PAYLOAD_INVALID")
    if tuple(value.keys()) != WIRE_FIELDS[expected_type]:
        raise ProtocolError("PAYLOAD_FIELDS_INVALID")
    result = dict(value)
    if result["type"] != expected_type or result["schema"] != SCHEMA_WIRE:
        raise ProtocolError("PAYLOAD_HEADER_INVALID")
    for name, child in result.items():
        _validate_field_value(name, child, n_local=n_local)
    if expected_type == "ABORT" and (result["stage"] not in ABORT_STAGES or result["direction"] not in DIRECTION_NAMES.values()):
        raise ProtocolError("ABORT_INVALID")
    if expected_type == "READY" and n_local is None:
        raise ProtocolError("READY_NONCE_MISSING")
    return result


def encode_frame(direction: int, message: int, sequence: int, n_local: bytes, payload: Mapping[str, Any]) -> bytes:
    if direction not in DIRECTION_NAMES or message not in MESSAGE_NAMES:
        raise ProtocolError("FRAME_HEADER_INVALID")
    if type(sequence) is not int or not 0 <= sequence <= 0xFFFFFFFFFFFFFFFF:
        raise ProtocolError("FRAME_SEQUENCE_INVALID")
    if not isinstance(n_local, bytes) or len(n_local) != 32:
        raise ProtocolError("N_LOCAL_INVALID")
    expected = MESSAGE_NAMES[message]
    value = validate_wire_payload(payload, expected, n_local=n_local if expected in {"BOOT", "READY"} else None)
    payload_bytes = canonical_json(value)
    if len(payload_bytes) > MAX_CONTROL_PAYLOAD_BYTES or FRAME_HEADER_BYTES + len(payload_bytes) > MAX_FRAME_BYTES:
        raise ProtocolError("FRAME_LIMIT_EXCEEDED")
    return SWZFRM02_HEADER.pack(
        SWZFRM02_MAGIC, SWZFRM02_VERSION, direction, message, SWZFRM02_FLAGS,
        sequence, n_local, len(payload_bytes),
    ) + payload_bytes


@dataclass(frozen=True)
class DecodedFrame:
    direction: int
    message: int
    sequence: int
    n_local: bytes
    payload: dict[str, Any]


def decode_frame(frame: bytes) -> DecodedFrame:
    if not isinstance(frame, bytes) or len(frame) < FRAME_HEADER_BYTES:
        raise ProtocolError("FRAME_TRUNCATED")
    try:
        magic, version, direction, message, flags, sequence, n_local, payload_length = SWZFRM02_HEADER.unpack(frame[:FRAME_HEADER_BYTES])
    except struct.error as error:
        raise ProtocolError("FRAME_HEADER_INVALID") from error
    if (
        magic != SWZFRM02_MAGIC or version != SWZFRM02_VERSION or direction not in DIRECTION_NAMES
        or message not in MESSAGE_NAMES or flags != SWZFRM02_FLAGS
        or payload_length > MAX_CONTROL_PAYLOAD_BYTES
        or payload_length != len(frame) - FRAME_HEADER_BYTES or len(frame) > MAX_FRAME_BYTES
    ):
        raise ProtocolError("FRAME_HEADER_INVALID")
    payload = parse_wire_json(frame[FRAME_HEADER_BYTES:])
    expected = MESSAGE_NAMES[message]
    validate_wire_payload(payload, expected, n_local=n_local if expected in {"BOOT", "READY"} else None)
    return DecodedFrame(direction, message, sequence, n_local, payload)


def _read_exact(stream: BinaryIO, length: int, *, eof_ok: bool = False) -> bytes | None:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        try:
            chunk = stream.read(remaining)
        except Exception as error:
            raise ProtocolError("FRAME_READ_FAILED") from error
        if not chunk:
            if eof_ok and not chunks:
                return None
            raise ProtocolError("FRAME_TRUNCATED")
        if not isinstance(chunk, bytes) or len(chunk) > remaining:
            raise ProtocolError("FRAME_READ_INVALID")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_frame(stream: BinaryIO, *, eof_ok: bool = False) -> DecodedFrame | None:
    header = _read_exact(stream, FRAME_HEADER_BYTES, eof_ok=eof_ok)
    if header is None:
        return None
    try:
        magic, version, direction, message, flags, sequence, n_local, payload_length = SWZFRM02_HEADER.unpack(header)
    except struct.error as error:
        raise ProtocolError("FRAME_HEADER_INVALID") from error
    if (
        magic != SWZFRM02_MAGIC or version != SWZFRM02_VERSION or direction not in DIRECTION_NAMES
        or message not in MESSAGE_NAMES or flags != SWZFRM02_FLAGS
        or payload_length > MAX_CONTROL_PAYLOAD_BYTES or payload_length + FRAME_HEADER_BYTES > MAX_FRAME_BYTES
    ):
        raise ProtocolError("FRAME_HEADER_INVALID")
    payload = _read_exact(stream, payload_length)
    assert payload is not None
    value = parse_wire_json(payload)
    expected = MESSAGE_NAMES[message]
    validate_wire_payload(value, expected, n_local=n_local if expected in {"BOOT", "READY"} else None)
    return DecodedFrame(direction, message, sequence, n_local, value)


def _write_all(stream: BinaryIO, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        try:
            written = stream.write(payload[offset:])
        except Exception as error:
            raise ProtocolError("FRAME_WRITE_FAILED") from error
        if type(written) is not int or written <= 0:
            raise ProtocolError("FRAME_WRITE_FAILED")
        offset += written
    try:
        stream.flush()
    except Exception as error:
        raise ProtocolError("FRAME_FLUSH_FAILED") from error


def write_frame(stream: BinaryIO, frame: bytes) -> None:
    if not isinstance(frame, bytes) or len(frame) < FRAME_HEADER_BYTES or len(frame) > MAX_FRAME_BYTES:
        raise ProtocolError("FRAME_WRITE_INVALID")
    _write_all(stream, frame)


class SessionMachine:
    """Strict one-session state machine with one local nonce."""

    def __init__(self, *, local_role: bool, n_local: bytes) -> None:
        if not isinstance(n_local, bytes) or len(n_local) != 32:
            raise ProtocolError("N_LOCAL_INVALID")
        self.local_role = local_role
        self.n_local = n_local
        self.next_sequence = 0
        self.frame_count = 0
        self.total_bytes = 0
        self.state = "START"
        self.terminal = False

    def _expected(self) -> tuple[int, tuple[int, ...]]:
        table = {
            "START": (DIRECTION_LOCAL_TO_REMOTE, (MESSAGE_BOOT, MESSAGE_ABORT)),
            "BOOT": (DIRECTION_REMOTE_TO_LOCAL, (MESSAGE_READY, MESSAGE_ABORT)),
            "READY": (DIRECTION_REMOTE_TO_LOCAL, (MESSAGE_DISCOVERY, MESSAGE_ABORT)),
            "DISCOVERY": (DIRECTION_LOCAL_TO_REMOTE, (MESSAGE_PROCEED, MESSAGE_ABORT)),
            "PROCEED": (DIRECTION_REMOTE_TO_LOCAL, (MESSAGE_RESULT, MESSAGE_ABORT)),
        }
        if self.state not in table:
            raise ProtocolError("SESSION_TERMINAL")
        return table[self.state]

    def accept(self, frame: DecodedFrame) -> None:
        if self.terminal:
            raise ProtocolError("POST_TERMINAL_FRAME")
        if not isinstance(frame, DecodedFrame):
            raise ProtocolError("FRAME_INVALID")
        if frame.sequence != self.next_sequence or frame.n_local != self.n_local:
            raise ProtocolError("SESSION_BINDING_INVALID")
        direction, messages = self._expected()
        if frame.direction != direction or frame.message not in messages:
            raise ProtocolError("SESSION_STATE_INVALID")
        frame_bytes = FRAME_HEADER_BYTES + len(canonical_json(frame.payload))
        if self.frame_count >= MAX_SESSION_FRAMES or self.total_bytes + frame_bytes > MAX_SESSION_BYTES:
            raise ProtocolError("SESSION_LIMIT_EXCEEDED")
        validate_wire_payload(frame.payload, MESSAGE_NAMES[frame.message], n_local=self.n_local if frame.message in {MESSAGE_BOOT, MESSAGE_READY} else None)
        self.next_sequence += 1
        self.frame_count += 1
        self.total_bytes += frame_bytes
        if frame.message == MESSAGE_ABORT:
            self.state = "TERMINAL"
            self.terminal = True
        elif frame.message == MESSAGE_BOOT:
            self.state = "BOOT"
        elif frame.message == MESSAGE_READY:
            self.state = "READY"
        elif frame.message == MESSAGE_DISCOVERY:
            self.state = "DISCOVERY"
        elif frame.message == MESSAGE_PROCEED:
            self.state = "PROCEED"
        elif frame.message == MESSAGE_RESULT:
            self.state = "TERMINAL"
            self.terminal = True

    def mark_terminal(self) -> None:
        self.state = "TERMINAL"
        self.terminal = True


@dataclass(frozen=True)
class RuntimeAdmission:
    mode: str
    argv: tuple[str, ...]
    environment: Mapping[str, str]


def assert_isolated_runtime(flags: Any | None = None) -> None:
    selected = sys.flags if flags is None else flags
    if (
        getattr(selected, "isolated", None) != 1
        or getattr(selected, "ignore_environment", None) != 1
        or getattr(selected, "no_user_site", None) != 1
        or getattr(selected, "safe_path", None) is not True
    ):
        raise RecoveryError("ISOLATED_RUNTIME_REQUIRED")


def classify_dispatch(argv: list[str] | tuple[str, ...], environment: Mapping[str, str], *, fd3_present: bool) -> str:
    if not isinstance(argv, (list, tuple)) or not argv or not all(isinstance(item, str) for item in argv):
        raise DescriptorAdmissionError("ARGV_INVALID")
    if tuple(argv[1:]) == ("--protocol-v2",) and not fd3_present and environment.get("SSH_ORIGINAL_COMMAND", "") == "":
        return "supervisor"
    if tuple(argv) == ("/dev/fd/3", "--agent-v1", "--protocol-v2") and fd3_present and environment.get("SWZ_RECOVERY_AGENT_FD") == "3":
        return "agent"
    raise DescriptorAdmissionError("DISPATCH_INVALID")


def validate_supervisor_entry(argv: list[str] | tuple[str, ...], environment: Mapping[str, str]) -> RuntimeAdmission:
    if classify_dispatch(argv, environment, fd3_present=False) != "supervisor":
        raise DescriptorAdmissionError("SUPERVISOR_ENTRY_INVALID")
    return RuntimeAdmission("supervisor", tuple(argv), dict(environment))


def validate_agent_entry(argv: list[str] | tuple[str, ...], environment: Mapping[str, str], *, fd3_present: bool = True) -> RuntimeAdmission:
    if classify_dispatch(argv, environment, fd3_present=fd3_present) != "agent":
        raise DescriptorAdmissionError("AGENT_ENTRY_INVALID")
    return RuntimeAdmission("agent", tuple(argv), dict(environment))


def _linux_syscall_number(name: str) -> int:
    numbers = {"openat2": 437, "execveat": 322}
    if name not in numbers:
        raise DescriptorAdmissionError("SYSCALL_UNSUPPORTED")
    return numbers[name]


def openat2(dirfd: int, path: str, flags: int, resolve: int) -> int:
    if sys.platform != "linux":
        raise DescriptorAdmissionError("OPENAT2_UNAVAILABLE")
    libc = ctypes.CDLL(None, use_errno=True)
    class OpenHow(ctypes.Structure):
        _fields_ = [("flags", ctypes.c_ulonglong), ("mode", ctypes.c_ulonglong), ("resolve", ctypes.c_ulonglong)]
    how = OpenHow(flags, 0, resolve)
    result = libc.syscall(_linux_syscall_number("openat2"), ctypes.c_int(dirfd), ctypes.c_char_p(path.encode("ascii")), ctypes.byref(how), ctypes.sizeof(how))
    if result < 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))
    return int(result)


def _stat_identity(value: Any) -> tuple[int, int, int, int, int, int]:
    return (int(value.st_dev), int(value.st_ino), int(value.st_size), int(value.st_mode), int(value.st_uid), int(value.st_gid))


def _require_mode(value: Any, expected_mode: int, label: str) -> Any:
    mode = int(value.st_mode)
    if not stat.S_ISDIR(mode) or int(value.st_uid) != 0 or int(value.st_gid) != 0 or stat.S_IMODE(mode) != expected_mode:
        raise DescriptorAdmissionError(f"{label}_UNSAFE")
    return value


RECOVERY_RESOLVE_FLAGS = 0x08 | 0x02 | 0x04 | 0x01
RECOVERY_OPEN_FLAGS = getattr(os, "O_PATH", os.O_RDONLY) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)


def admit_recovery_directory(directory_fd: int, *, fstat_fn: Callable[[int], Any] = os.fstat) -> Any:
    try:
        return _require_mode(fstat_fn(directory_fd), 0o755, "RECOVERY_DIRECTORY")
    except (OSError, ValueError, TypeError) as error:
        raise DescriptorAdmissionError("RECOVERY_DIRECTORY_READBACK_FAILED") from error


def open_recovery_directory(*, open_root_fn: Callable[..., int] | None = None, openat2_fn: Callable[..., int] = openat2, fstat_fn: Callable[[int], Any] = os.fstat, close_fn: Callable[[int], Any] = os.close) -> tuple[int, Any]:
    opener = open_root_fn or (lambda path, flags: os.open(path, flags))
    root_fd: int | None = None
    try:
        root_fd = opener("/", getattr(os, "O_PATH", os.O_RDONLY) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
        directory_fd = openat2_fn(root_fd, "opt/swooshz/recovery", RECOVERY_OPEN_FLAGS, RECOVERY_RESOLVE_FLAGS)
        metadata = admit_recovery_directory(directory_fd, fstat_fn=fstat_fn)
        return directory_fd, metadata
    except (OSError, ValueError, TypeError, DescriptorAdmissionError) as error:
        raise DescriptorAdmissionError("RECOVERY_DIRECTORY_OPEN_FAILED") from error
    finally:
        if root_fd is not None:
            try:
                close_fn(root_fd)
            except OSError:
                pass


@dataclass(frozen=True)
class AttestedAgent:
    fd: int
    bytes: bytes
    identity_before: tuple[int, int, int, int, int, int]
    identity_after: tuple[int, int, int, int, int, int]
    commitment: str


def build_execveat_plan() -> tuple[int, str, tuple[str, ...], Mapping[str, str], int]:
    return (3, "", ("/dev/fd/3", "--agent-v1", "--protocol-v2"), {"SWZ_RECOVERY_AGENT_FD": "3"}, 0x1000)


def execveat(fd: int, path: str, argv: tuple[str, ...], environment: Mapping[str, str], flags: int) -> None:
    if (fd, path, argv, dict(environment), flags) != build_execveat_plan():
        raise DescriptorAdmissionError("EXECVEAT_PLAN_INVALID")
    if sys.platform != "linux":
        raise DescriptorAdmissionError("EXECVEAT_UNAVAILABLE")
    libc = ctypes.CDLL(None, use_errno=True)
    args = (ctypes.c_char_p * (len(argv) + 1))(*[item.encode("ascii") for item in argv], None)
    env_values = tuple(f"{key}={value}".encode("ascii") for key, value in environment.items())
    envp = (ctypes.c_char_p * (len(env_values) + 1))(*env_values, None)
    result = libc.syscall(_linux_syscall_number("execveat"), ctypes.c_int(fd), ctypes.c_char_p(path.encode("ascii")), ctypes.byref(args), ctypes.byref(envp), ctypes.c_int(0x1000))
    if result < 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def write_exec_error(error_fd: int, error_number: int, *, write_fn: Callable[[int, bytes], int] = os.write) -> None:
    if type(error_number) is not int or not 0 <= error_number <= 0xFFFFFFFF:
        raise DescriptorAdmissionError("EXEC_ERROR_INVALID")
    payload = struct.pack(">I", error_number)
    offset = 0
    while offset < len(payload):
        written = write_fn(error_fd, payload[offset:])
        if type(written) is not int or written <= 0:
            raise DescriptorAdmissionError("EXEC_ERROR_WRITE_FAILED")
        offset += written


@dataclass(frozen=True)
class LaunchPlan:
    agent: AttestedAgent
    directory_fd: int
    error_read_fd: int
    error_write_fd: int
    pid: int | None
    pidfd: int | None
    argv: tuple[str, ...]
    env: Mapping[str, str]

    @property
    def execveat_argv(self) -> tuple[str, ...]:
        return self.argv

    @property
    def execveat_environment(self) -> Mapping[str, str]:
        return self.env

    @property
    def execveat_fd(self) -> int:
        return 3

    @property
    def execveat_path(self) -> str:
        return ""

    @property
    def execveat_flags(self) -> int:
        return 0x1000


class BoundedCapture:
    def __init__(self, limit: int = MAX_CAPTURE_BYTES) -> None:
        self.limit = limit
        self._data = bytearray()

    def append(self, chunk: bytes) -> None:
        if not isinstance(chunk, bytes) or len(self._data) + len(chunk) > self.limit:
            raise FinalityError("CAPTURE_LIMIT_EXCEEDED")
        self._data.extend(chunk)

    def snapshot(self) -> bytes:
        return bytes(self._data)


@dataclass(frozen=True)
class ProcessFinality:
    exec_error: int | None
    pidfd_observed: bool
    exit_status: int | None
    stdin_eof: bool
    stdout_eof: bool
    stderr_eof: bool
    trailing_unframed_bytes: int
    stdout_capture_commitment: str
    stderr_capture_commitment: str

    @property
    def success(self) -> bool:
        return (
            self.exec_error is None and self.pidfd_observed and self.exit_status == 0
            and self.stdin_eof and self.stdout_eof and self.stderr_eof
            and self.trailing_unframed_bytes == 0
            and _is_commitment(self.stdout_capture_commitment)
            and _is_commitment(self.stderr_capture_commitment)
        )


def validate_process_finality(value: ProcessFinality) -> ProcessFinality:
    if not isinstance(value, ProcessFinality) or type(value.pidfd_observed) is not bool:
        raise FinalityError("PROCESS_FINALITY_INVALID")
    if value.exit_status is not None and (type(value.exit_status) is not int or not -1 <= value.exit_status <= 255):
        raise FinalityError("PROCESS_FINALITY_INVALID")
    if any(type(item) is not bool for item in (value.stdin_eof, value.stdout_eof, value.stderr_eof)):
        raise FinalityError("PROCESS_FINALITY_INVALID")
    if type(value.trailing_unframed_bytes) is not int or value.trailing_unframed_bytes < 0:
        raise FinalityError("PROCESS_FINALITY_INVALID")
    return value


@dataclass(frozen=True)
class ArtifactIdentity:
    st_dev: int
    st_ino: int
    st_size: int
    st_mode: int
    st_uid: int
    st_gid: int


def _artifact_identity(value: Any) -> ArtifactIdentity:
    return ArtifactIdentity(*_stat_identity(value))


def _artifact_identity_object(identity: ArtifactIdentity) -> dict[str, int]:
    return dataclasses.asdict(identity)


@dataclass(frozen=True)
class QualifiedArtifact:
    fd: int
    identity: ArtifactIdentity
    bytes_commitment: str
    byte_length: int
    descriptor_commitment: str
    reopen_count: int = 0
    no_follow_verified: bool = False
    stdin_same_descriptor: bool = False


def qualify_artifact_descriptor(fd: int, *, no_follow_verified: bool = False, fstat_fn: Callable[[int], Any] = os.fstat, lseek_fn: Callable[[int, int, int], int] = os.lseek, read_fn: Callable[[int, int], bytes] = os.read) -> QualifiedArtifact:
    if not no_follow_verified:
        return QualifiedArtifact(fd, _artifact_identity(fstat_fn(fd)), "", 0, "", 0, False, False)
    before = fstat_fn(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0 or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID):
        raise DescriptorAdmissionError("ARTIFACT_ADMISSION_FAILED")
    lseek_fn(fd, 0, os.SEEK_SET)
    pieces: list[bytes] = []
    total = 0
    while True:
        chunk = read_fn(fd, READ_CHUNK_BYTES)
        if not isinstance(chunk, bytes) or len(chunk) > READ_CHUNK_BYTES:
            raise DescriptorAdmissionError("ARTIFACT_READ_INVALID")
        if not chunk:
            break
        pieces.append(chunk)
        total += len(chunk)
        if total > MAX_HTTP_BODY_BYTES * 256:
            raise DescriptorAdmissionError("ARTIFACT_OVERSIZE")
    after = fstat_fn(fd)
    identity = _artifact_identity(before)
    if identity != _artifact_identity(after) or total != identity.st_size:
        raise DescriptorAdmissionError("ARTIFACT_SUBSTITUTED")
    data = b"".join(pieces)
    return QualifiedArtifact(
        fd, identity, bytes_commitment("artifact-bytes", data), len(data),
        bytes_commitment("artifact-descriptor", data), 0, True, True,
    )


def stream_qualified_artifact(artifact: QualifiedArtifact, destination: BinaryIO, *, fstat_fn: Callable[[int], Any] = os.fstat, read_fn: Callable[[int, int], bytes] = os.read, lseek_fn: Callable[[int, int, int], int] = os.lseek, write_fn: Callable[[bytes], int] | None = None) -> int:
    if not isinstance(artifact, QualifiedArtifact) or not artifact.no_follow_verified or not artifact.stdin_same_descriptor or artifact.reopen_count != 0:
        raise DescriptorAdmissionError("ARTIFACT_DESCRIPTOR_NOT_QUALIFIED")
    if _artifact_identity(fstat_fn(artifact.fd)) != artifact.identity:
        raise DescriptorAdmissionError("ARTIFACT_SUBSTITUTED")
    if write_fn is None:
        def write_fn(value: bytes) -> int:
            return destination.write(value)
    lseek_fn(artifact.fd, 0, os.SEEK_SET)
    total = 0
    streamed = bytearray()
    while True:
        chunk = read_fn(artifact.fd, READ_CHUNK_BYTES)
        if not chunk:
            break
        if not isinstance(chunk, bytes) or len(chunk) > READ_CHUNK_BYTES:
            raise DescriptorAdmissionError("ARTIFACT_READ_INVALID")
        offset = 0
        while offset < len(chunk):
            written = write_fn(chunk[offset:])
            if type(written) is not int or written <= 0:
                raise DescriptorAdmissionError("ARTIFACT_WRITE_FAILED")
            offset += written
        streamed.extend(chunk)
        total += len(chunk)
        if total > MAX_HTTP_BODY_BYTES * 256:
            raise DescriptorAdmissionError("ARTIFACT_STREAM_OVERSIZE")
    if total != artifact.byte_length or bytes_commitment("artifact-bytes", bytes(streamed)) != artifact.bytes_commitment:
        raise DescriptorAdmissionError("ARTIFACT_STREAM_DRIFT")
    if _artifact_identity(fstat_fn(artifact.fd)) != artifact.identity:
        raise DescriptorAdmissionError("ARTIFACT_SUBSTITUTED")
    return total


def build_artifact_stream_evidence(artifact: QualifiedArtifact, artifact_commitment: str) -> dict[str, Any]:
    if not isinstance(artifact_commitment, str) or not _is_commitment(artifact_commitment):
        raise DescriptorAdmissionError("ARTIFACT_COMMITMENT_INVALID")
    return {
        "schema": SCHEMA_ARTIFACT_STREAM,
        "artifact_commitment": artifact_commitment,
        "descriptor_identity": _artifact_identity_object(artifact.identity),
        "byte_length": artifact.byte_length,
        "bytes_commitment": artifact.bytes_commitment,
        "stdin_same_descriptor": artifact.stdin_same_descriptor,
        "reopen_count": artifact.reopen_count,
        "no_follow_verified": artifact.no_follow_verified,
    }


def validate_artifact_stream_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    fields = ("schema", "artifact_commitment", "descriptor_identity", "byte_length", "bytes_commitment", "stdin_same_descriptor", "reopen_count", "no_follow_verified")
    if not isinstance(value, Mapping) or tuple(value.keys()) != fields or value["schema"] != SCHEMA_ARTIFACT_STREAM:
        raise ProtocolError("ARTIFACT_STREAM_EVIDENCE_INVALID")
    if not _is_commitment(value["artifact_commitment"]) or not _is_commitment(value["bytes_commitment"]):
        raise ProtocolError("ARTIFACT_STREAM_EVIDENCE_INVALID")
    if type(value["byte_length"]) is not int or value["byte_length"] < 0 or value["stdin_same_descriptor"] is not True or value["reopen_count"] != 0 or value["no_follow_verified"] is not True:
        raise ProtocolError("ARTIFACT_STREAM_EVIDENCE_INVALID")
    if not isinstance(value["descriptor_identity"], Mapping):
        raise ProtocolError("ARTIFACT_STREAM_EVIDENCE_INVALID")
    return dict(value)


def artifact_stream_evidence_commitment(value: Mapping[str, Any]) -> str:
    return bytes_commitment("artifact-stream-evidence", canonical_json(validate_artifact_stream_evidence(value), terminal_lf=True))


# The loader text is itself an admitted artifact.  It has one marker replaced
# by the fixed raw-deflate locator package below; there is no runtime import
# or path lookup in the installed payload.
_LOADER_TEMPLATE = b"""import base64 as _b64
import builtins as _builtins
import importlib as _importlib
import sys as _sys
import types as _types
import zlib as _zlib

_NAME = "__canonical_locator_payload__"
_FILE = "scripts/platform-persisted-locator-adapter.py"
_PACKAGE = "@P@"
_ALLOWED_ROOTS = ("__future__", "dataclasses", "datetime", "json", "queue", "re", "selectors", "struct", "subprocess", "sys", "threading", "time", "typing", "_strptime")
_ALLOWED_FROM = {"__future__": ("annotations",), "dataclasses": ("dataclass", "field"), "datetime": ("datetime",), "typing": ("Any", "BinaryIO", "Callable")}

def _restricted_import(name, globals=None, locals=None, fromlist=(), level=0):
    if level != 0 or type(name) is not str or "." in name or name not in _ALLOWED_ROOTS:
        raise ImportError("restricted import")
    if fromlist:
        allowed = _ALLOWED_FROM.get(name, ())
        for item in fromlist:
            if type(item) is not str or item not in allowed:
                raise ImportError("restricted from-list")
    return _importlib.import_module(name)

_BUILTINS = {
    "__build_class__": _builtins.__build_class__,
    "Exception": _builtins.Exception,
    "OSError": _builtins.OSError,
    "TypeError": _builtins.TypeError,
    "UnicodeDecodeError": _builtins.UnicodeDecodeError,
    "UnicodeEncodeError": _builtins.UnicodeEncodeError,
    "ValueError": _builtins.ValueError,
    "any": _builtins.any,
    "bool": _builtins.bool,
    "bytearray": _builtins.bytearray,
    "bytes": _builtins.bytes,
    "callable": _builtins.callable,
    "dict": _builtins.dict,
    "float": _builtins.float,
    "getattr": _builtins.getattr,
    "id": _builtins.id,
    "int": _builtins.int,
    "isinstance": _builtins.isinstance,
    "len": _builtins.len,
    "list": _builtins.list,
    "max": _builtins.max,
    "min": _builtins.min,
    "property": _builtins.property,
    "set": _builtins.set,
    "str": _builtins.str,
    "tuple": _builtins.tuple,
    "type": _builtins.type,
    "__import__": _restricted_import,
}
_MODULE = _types.ModuleType(_NAME)
_MODULE.__file__ = _FILE
_MODULE.__package__ = None
_MODULE.__loader__ = None
_MODULE.__spec__ = None
_MODULE.__builtins__ = _BUILTINS
_sys.modules[_NAME] = _MODULE
_PAYLOAD = _zlib.decompress(_b64.urlsafe_b64decode(_PACKAGE + "==="), -15)
_CODE = compile(_PAYLOAD.decode("ascii"), _FILE, "exec", dont_inherit=True)
exec(_CODE, _MODULE.__dict__, _MODULE.__dict__)
if (_MODULE.__name__ != _NAME or _MODULE.__file__ != _FILE or
        _MODULE.__package__ is not None or
        not callable(_MODULE.__dict__.get("execute_operation"))):
    raise RuntimeError("locator admission failed")
"""

CANONICAL_LOCATOR_PACKAGE_B64 = (
    "7T1_d9tGjv_rU7C85llqaUVx0jbVrvJWkZXEW9tyJDlp6vj4aJGKuZEllaSSuFnfZz8A83s4lGQne7e3e-5rRHFmMBgMBoPBANB_fHN_lWf3L9L5_WT-wVte"
    "F5eL-cOa7_uD6XSWzpPdPJom3ujk8KX34YG3TLI8zYsk3p0tJlGxyLwojpZFkjVrtfFl4i1XF7N04i2zRbGYLGZemntxMksvkiwqktm1lyfLCB-9aba48gps"
    "kaUf8MXJIi_eZcno5aG3vIzypEnwFnNoFMVXaZ6ni7m3jIpLbwq96i2pOvbUFfVGBbxvAprLeiPwPl6mk8salEezfOEln5JskuZJ7MVplkwKgH9xTfAWbMDe"
    "ZDEvsmhSeNP0U7HKkryJ5KjVCOUwnK7wZRh66dVykRVeNJ8voD_oNq_V-Lu_5Yu5eP59lawS8SWTT3kyg94XWS5fFNlqUshvqwsg4iTJVfm1fCwusySK0_k7"
    "-SK9Shh-cVREk1mU50kuEJSvAhhRMotlxQSbabUSBaa4XgJ4UdadXwfe03QeZdcHg8DrRbNZdDFLarXaC8AjybwOx745oo-6_82j_OnTFwd-o3YUvQOG6HgX"
    "PvKQX3uFHART2fEe1Ib9l6f90Tgc9V70j7rhq_5wdDA4hqKHtVqvezw4Puh1D8PTcS98NhgedcdQ4t97s3vvavdePL73on3vqH1v1Lw3_c23qp90x-P-ECFl"
    "SXOyuFqms6Re8-Av889auz-ff350s8se9tTDWDy0Sw9vm-zpxxvoq1ETmNMoRuPucNzfh-c9eD86PRzTCJ51Dw7p7SOqftT9FWu39h7VTrpv2LdHrZ9_rL3U"
    "ngfac1977rHnxw9-3qsds-e91qPHtf6r_vE4BFRO-yHv4Mda7WTYDzmkHx_Rt778VhvC5w-1A8J2BP_-VDvqDp8fHNNQTp73BsfH_d44HB8c9QenY6o2Dl8M"
    "aKxD73tvz_vOO4DPEfzPWtaQ24BLRDUA9BMOubt_cNwfjcLe4Oioe7xPPPD2bTK5XJA4CU9Onx4e9EKs-CZ89eDt3K-xZwD7S38oecZVsfZ6eAAzHJ70j6GX"
    "58gYy2SOS8IXRYNf8O3ivXwxejEYEgvll8DU8nV_OBxgZ36SZYsMQHf3jw5GyIjh6-4BNcBPX3vf7fX6J1TCnvQynHYswU_9fe9wMCJ28NkTdPRbfzgIh4PX"
    "MOBx7wUWmW_82hEw08HJYd-sVX7rwywfvOqO--HhoNcdD4YhdcsIU1Hk1_q_dnvjwzfh4LiP9bSvgBww1fBNeDwYh_1f-71TxuB--a3Pa0p29_XvAOjk-eBk"
    "DBQYha-6h6fU0-4E5AXIm6tkXoQodBarovNTq9XyoCSNZ0kI4gulhCzc44Vj-P7bYp50YJUD7NroRf_wMHw97J6cEMdkOzs7eVJ4u8mqlk69M2_3D8__9vMJ"
    "MOZzWJvh6ag_bO_e-N75n1Dmz2E7SAtYF38C0cga6LX3n1LdbwDlyWIxS6fXdsMfqOGS7V15uIKF0PnW6K22miNCJ89pcbCP7v7-EB5PkB9Pnu93x92n3VEf"
    "HrEBFnRHo9eD4T5_fAaUlGCgxquDXl89YakniYzvR4dHg_0-ezruPx-MD7pYpkCMDnt96hqefum_YQ_DwWCsXveGh_Jh_0CNAgXfAYxthMXj3_AfEAL98ahP"
    "bA5yd4g49F50QY4cPj1gy_PkOUzQcfdIDQNA9497HM9fhk9Hw1dYTj10D49UT93T8QtPmxHPpG7yiXaoF4Ojfuf-HDjjE6on80IUKAp27sfJh_vz1Wymyixp"
    "19lTRZyenZ2vw6w7ADmZeKRsoeo0I5Vrmf8-897CxrT7K_v4yD7m7ON39tFlHwX7-OCBNCGhFY7Gg5POA_Z69xKYsHP_Q5Tdz1YAmbOkgL-Lw-r88OjhHv-O"
    "rDqPrpKO_63Bvj4vjy-olPO9AAKT11lG74DLQVtiL6febg1WHSxGUjJACyOFsI_StN7_NEmWqBs12rT9giL1FLU1VhU1OVQvAw9mblfoc1yj9KZROiP1i7Qv"
    "Dv2Ea5YMvN4X72EJtWTtl6sku-6BZkZqCaCxXbMR180Gq2K5Kja1iZOpF36IZimqUOEkgrGkMMHhqpgwnQPKVkmbtCj6ThtNCCoWvMR_z3TY56wOKFjJrI1q"
    "VVBreLtP8In1ClIKFE7Qd1MYVjSfJHWCH2CNhgcUdapCzSkw_lVUTC5Z9QYqzMfAnAwoqUYRqMUacvWp_5nQuMG62Kccm4fit0Eti-xagQDlHjXrjtQmQQnP"
    "lvggkHSpdQxQQqzivcJ6RAkvyhk2t0ExAo0P8MP-72O_foMdNagNwVGD6Hh1CRkAMeSb10mUtVuP4ptd8eYKDgSX7dae9iqOrumFrwEYi8LLxSqj0raEkM5X"
    "RWK-yxM4aMQlKE3VZpItRKUfY1Q8sUZDMIEaB-xPjMXuMpV0KMtSYF_olM9plsARZ67qcCaXPH4RZVmaZMThirlNNuUwqhYGZwdjOQeezyFz_rLXFgiqtEg_"
    "JGEaa_0GmxaUtpgIx3ReyKVE1FErglbWvMBlhI8t78-MtPD5897ew4c_7bUe_vj4h0c__fTD49bjbQmezmkIJnUJrk3ZfHKZxKuZNUIT6xJlS2Qp01XA9QgL"
    "m67iLGrTtYpu22DgkKEcYLn_KRzPcLepZKa1Ms-eBZf09sUQPdGXEhgAA88NDnEm6oZ5-kcC4gK-sY6byXyyiJO6vyqmu4_9hiHBToHLobBPVdZLstuhSvSC"
    "pfEMu7TFGpDIQrfjte7eX3K1LK79hhv0Ew8PoXcHvviARoA_kjUrQjEH6k0r3LvDCYh2MD2FUfGFUsfJm77siMwpwGdXS7VWsuRv0CScLIgBJQJiaaidlNHC"
    "VFN8VG-m6TwF7eavI7BwCDAl-PFqCfYzRPx9cp3Xl1Ga5W0PZHNxVkBRcoYKAQ77_Jz6jdNJod4JGuSrWdG2yoB9P99QOWpdAD3gki1Fsxp2I6cT5hvKsYCD"
    "kiWVA5R4s_FBcz61CqEzeIlYsFnWJosVc0LQ5hfikgRqoBkNaHA9W0RxG8x0RZLTqGE8VXKB1w54bZtHLbQJWd7Eu1rlhXeRsJYucVAknwoYAK_fjBNDBjhE"
    "wH6yWQSsw4iv--oVj6WEFZpE8RNUAfxEtSsF4-dtOgMrKlgdoWBFdhSYflgbfFhsqGjnwylpYjs2tkxpUIsL4mDipfBysXjfcTN1YGqLckl17DUWaPqOMQ98"
    "FYO9BzVNhkcziz6GfEaQAsZ01C2s-Yo3qNHYdob4Zu7pxHNODuL3Dds0CKPbTgYYodOZPRMOUcnImCVgaM6R_gTBtWxcwuJLVxDvdu0igj6QCLxKA7YPbg8F"
    "rrUKmGn0ln06dhQm2jrV4qSxXq9AUtFhCg68Qj2Eufzso3Lnw2bxgZmxfaWz4gbj32yJOlssXn4ZLZOyhgho1U1uP2Mdn5Mtihuf1akBV7_UY88kbue6SqtX"
    "tushVLctni3BLQfF4Ql0yuPSKMU2gorjxJlB03OD8_kUtBUZtNloVwzDmqW2jskNX0ZMeMh1NM1QIaV_b7-GqJlYQYLN6WUDThLs0qSJ_LolZakpoyfeZsyS"
    "IuEkvcLrlUCQPvBAccnBPkOHELjvmUXv4NqH83wIWLyDC7SOwGA1X0aT9wyxs7aG1rnkQ4KP_MHucZB5-CzDu1dqwvV-NXbCIkIC37VuNdpLdrXkWhzWeHR5"
    "Uiq6lURhPa-RK2AehHWblElJevH3Vve69OOzD2SwYNyOKPq-gGTHC0_3FuHeFthc6xx4rumggHm-ALYHBk-iq7Z258dxRUlC64BYW-ibUfwAKPEuATNpkfHG"
    "sOSoAJYnKsea2YJdHtapVBctQhuE13XWnTEeBraJ5bJYRzz5BHe2TGyW0GcmNTWEgGs1UYw3vm1g0UXEX16sptMkS_jGCWIiuvb-TkOAIeIHt8cZBEAFFu-r"
    "RIs6w5xfSWEJh4oUUM9MOBPsZJYnpfby8MR6LmtCcLUNZ3pkL4YDShebq8SaYbiY7wlg9B6HBiYqTlZvV4cYsC2atW40Ss1ZtSYoOFBF1DtrI9Tzcm1wBvDM"
    "OqUqeP0O5rLEHoAkRslwKf40csnb9eZ-Mo0AQXHkqzcqmwFrvcPLA8XBCgq7aMUbSLN9llxFcK6jORbsBPQj0yeYDWElw0nA6hPGopr92RCLW0kC5HbqIfYW"
    "ctFrwJGn5JjYQ1122PianU0uV_P3MPKS5Agsscjl8_feAye2BOeWiDF5CKwEmMGimV1buG3F1tRxw55SnaGphpOdORubFbFe-9w8fCiLduDBze-tDhvmaCeL"
    "1SwmioGGjTQvnzvAyoA2XeMwr68cIXBMakt2mczA5Fw35C4JOkE2y1yRXgFjpKjDiU0ppJ2otIFYRpJbrFRD3t11qVasipa1GtiIa1uw9wMDtoN_b7uX6xv4"
    "PwfjlHiCTT3RwlSSy9oCvwmlvRb9RipVZykzOyWZCdKCgzH2Zcc2eymckHRFwCGIAtldIMF9PS2aYfH_irNbcRZF7kkyO6-eJ017urvarC-1LQXZFoq1tCtw"
    "CYnGhpDJTm4rNvkfNqD0Ki2cGrUh89hVQyxsb_HqapnXpQksR1_EKJ-kaecZ-DfilQhzsQRR2Kn7AZ6O2z5sd7C4Fx_DeTRn9Rr2FYYhecbAjFzw6EKofLOx"
    "tTzijqG2eVNyqMN-hhs0Hzyahhi57tRLxX0DB85n7GKVzmIu0fRFyQ4M3sZJhAliS8aeTY31babg7Q2suFQhmXLE5NIrt1xqBYb5rKHOn3xIYI3I8KDJBlU-"
    "trD9XRs3d2UMNCsLf2VaWThCN2pTQO2AA2G37OhIkU7R7AsVuSODfqdGr-yTFe076gqU0dVRR90JbVVJXRw5e7UJgzu6gT63oXmfTf-8wCt74oFV2e1uF3ia"
    "f93NljZmfrI0sdFNnK5bHs1Ahs6ozpmDdxbQttULuyviPjkhXT6hw4Q2O4ExDYGT3oGc70YFaWF70whj6K3R_LoOV2ZXxkEZb6_Yy7mJXWMLBQzv4dBeMksk"
    "acl9G-1qs1WsfMrTGLy90sK8xSotF0ZgLhvkAHW0t0bZiS5tkgLTeZLE4MPuCQOgxJVA-VX3JGe-NmU-Moj72t6YWPcFqelEYPWi88KabkyW2XQRu74jxWZW"
    "hw4fLLmbupjUqOHCyajgvChWVUoIixVgISmdHswVwrdgBxbbbrUG1xhMsnbH3czfTNajW57cUxxifntpWnYmDjzdeXhbKckdBd1i0jEsBl3f5Liz8h0lpaDM"
    "xyxFbicdpPJoVLpRUKdibA-2BBZNgbZOAsgtx4KWohK_WWSF26lFTBcmoN5HvO0lP_iGZjJtTmer_JLOen-RYSPSr1OPrpHunCMSp-hO6rGgFFBRtIidGboc"
    "eiv0CuRhNhDWEjNnTG-2WCyZdye7Xs-u8BAKxAGnU6ACKarGNiThhgTXqslPlKj3QOSPfpCdquU5Ac8wYBY4zxcxHVFpJlQ5kScL0eV3lWt6C_7NFx8NW7Gw"
    "ftOgQ6c5Gf--U4_QKay4kK0hE31VCdXVKWrr66vx-KANteA-H4VNZR3Tf0ZZjKZNOR8OG4lnBzbYphbtMsyiePliWUyS7BEwHGeWBbjUL65ZA2edtHiitchI"
    "h1yDZPjGIM9XxshgJSn1zMiVwJPhKvKRAlXkN3L1vvnH4qbh9T_RucUR6KqmR_6Y3V1F2XvAlO1qVm8QWjg1mjbpyJN_TItLm-8aa8EqWcPg5snXHjQID-9J"
    "xyUvvnpHhTk6YHNzuoHeJhduWOIY_1QSDxUyudzbNx3F4191rGvRsKCt7arUDQvr4tu6gqz2FYoIaVt7YlDbtMFUbS72xrJhU_nuu3erKItzJs_tAAF5XyqD"
    "YEsS2MADoy8-Bo4-A9mRUyF4ip5iSdxjwFnfyhzCNmNool-kdlgEaj1mpn6Qu6jjXndkDaaMCMldtb9HS7x8qdPGzo3vToWqYj_CBmt2IdF7NUPqwFEJo2Y4"
    "VjTBqHslMFpRiWW52rIjdbF4FX2qtwINFr_KUt02ysDxvXWJJWGeN9YNyt28oalX82gJumNBCNjqfunmSGHpYiLOPaOEE0gsGpO5KhlnFl1dxJFdvY7Rrw2h"
    "2KJa8KUA-wognL8hdAsXE3pPcMtfyyy6JQODDUIE-2zBzrw-SnGfkct3MBcrafKe-BQa-6YFB6hUAQdKKuHY-yQ7fyijMdiX5-9BvsyFXBTdagd76scgq_d9"
    "R19HgGzV-mWOE63S7mSCe-L1jLuMcq_2WtRPdAvstXySc3hYShkMh5oTALjIrjyyAEHw1S4Bu08nLA8cZdDDHmxFcC2XQN-4ZjLwuS6085Dh6eE-GxrejO4T"
    "oqji3ON1pU87pBhnQXeTwS-6uULG-bUrqpMiyakKYgXzK4TRFDch3HeuQ6aw1N2bp8OkwGKYjMq67qfrhNsFiKjDK0MFbSXcu8qOijJ6PUMam92dGzcKPFFG"
    "-DvGItY1x0NlLZFsY0z5Ft6S2rNhPTLO_5V2o4roSF-k9hDBWOusRjQqDLyeAt--PoBYXWlIBCtcTCiD7WBEDq2j_iFE23p5M43h27Ph4EjWjkPcGS4gNhQG"
    "OHm_WlKjHKq9ftEf9qkNLGO20DGbQA4XWOhHFnsHI288PO1rJRJUGkvZbJXQdWvH2-kul2-P4BZolr8FHW4eRzNYrycyeHZHazulK7_5BIe70_IePIZMCPCf"
    "XiWPwMqZP3ShlOaILXHDjA8Rqz3rHo76Nbif08iWxaikgvXZpBtB62GgOJAEY0hWEIfyHWoZD7wxvtnz-gBMFYBuT0SUkLEgqALTEWBQ3Ujhyo2AHZ8eHpYA"
    "ladPm2wcjGZlrWACxq04qfDaMAqzhbAIYZ_I6pC9Q5ppPUgAgoHa3m-YsGAHg6oDb-cN_O0eHe3u7_tj_8WLvUfto4P2aNQ8Hfm_-TsNE7xt802awvi6kR9V"
    "HBKNBBv8dQBpMyrYPSf4cA0JKnglSGJPvhoYmyeKQylYCjiNR2ArNkOlnh3jvJ18NUGDhl6oEewJ0Qtu8I5OIFR_57Pu9ayaIC9oewNxRcI8t_7L2_lPSnzy"
    "_bc7WpWxqtJuz1dXED-KIurxw1br8Z5WjzhoapysgZX0gTwMwS4Nu5NjGau5wSKwEhMvasVsKeUgqfBKFJYwXIrExprS2fArLyoN9ParSudzx_oqL4PtAapZ"
    "XwvYXgCbOpB3E2Wg9spxrXlIlcNlPrv5pg2RxT7gFOyYomkncMiqHU3q7AQ2s5pca7amkRCrmHOlRmgKtNKfHHK5EGhAyFmgdwIXY-zoE_u1x6DD_vJBSPZY"
    "g-bXwld1traXNQMojUTwZBX2d8JYY_TtMBMyDiNn2hj6VbP3SimMar3hYDRiO4lTWv0JjwOaG5DyPkO9k7QvdzAyBaAZTZ54Lx0OXZuUQKbgVTvRULmIRMNM"
    "bHvSJYqKnHeCLgenUKiSzkHdMcB669Gtj7PUXJEYmo1_EDVNWnyPGbPmb9_-TimvNOMJXPst_kjmHTyqNqykJfsQhpHOOKEd97OVXjjcegl3dareemecbXxx"
    "buOKgwmdIG5r_xQ8atDVBnNFGS98VS5cb4w64iXmtsIbZbTlCkDmG72GDqr81hcefTJLgrY8jXQJZFG6bZoJFqkoLofAzPcg8PZutjmyTlVw_WfqertcE5wl"
    "rtV4YsYxdlC9k6FuHTEpB-KbclfzmDA8VLTXlkR2F1U2Uc4hWrn0xWDvbm6Xw2BBb6uiNkv7yhqOObOpca7717BXDXvpbAPWptm54U-jA9aILqLyLV-h0vJW"
    "9Uxvn8o17mqge-0YskhVVh4z_ygnNHuuDB_rr-N65mQlzQHN5ir0Ud7sfmYtyrrtkUgejZ4hNNcMeu__5qBdbpfWwEUVpQzZ6-hfbMrN7W3dsP_lJr28Z9_F"
    "F9PTk9TgnYh2GyJa8QxG2PjMIIQpkkxPSdN70PKAtJwdK-vq0sydqUY1PS8Ff9oTXI61QyVXDO2zgb-N403beRBzZ5PSiFYOvCzfHpWBObP_IFTjykPOm9Cj"
    "GGP4NrIbvS_X8F-lXzfrq6LYtde6SbWGg1wbsRvIWuZat01voLjT0GTv3hupW0FZZRxUjuBBKQlXsL6aTr5a2dvX_dY2hzUqdWRutLJUZC0nkzrMyNA2Gh3Q"
    "ZYPGbdCGlzTNg1sg30tjhJEuSWJJArbOPvTLsy11edbQTlzB3uKRd8CDxbAZewvn9JhdueFR1W_cSaFGx1SKzLJV6rI7uzOnCwNz1t59cH6Ha7CtUKSQoi3c"
    "pzfOtXKixsgtc5qZxSTkYTvMecDp22OkXIZpNNqxK_Gyc7XL_WKwxMz80HUPtQPOF_FiwpzHkkluOjjkl8lsFn7M0Bsgs8owl61IhWsVzRbvyBuf0cRuh0aj"
    "ByHdZ7uK9pxFeF2e2i_hqmGGVyva63VjHrHLk7taShjFbBL-75hNqgf5jHFaW93Wmvy1dixU-BfwmoX3YKwU7isW10o3IMONmLNqBaeT94WBjlga0Nc85CzI"
    "_XVZ6Jr6SYTmCVY6Iyl1bjq9WXXU3nLmM5hCn8HP3RT_5RdskPEYv1Fe5vySirGSkWH83PDkTucdvb-Dk75RjKmg15WD7KguhzBXNA92WubGRN4SQJiPC-Yu"
    "YbgOlV1UwLOE5pV-g6L5Ev915xFUSqEjvwhaGdvOxA96Thb8oYLbZHdguDVxv8JsqXwoN-1kMRU5Y1zZRgxXNRsOB8I3MJHeoeH0VHHsB5Uo0S8D8DyzDTkX"
    "3IuSz8X7dB5XToTpK3SnidGRw76CsneS7KehkJzMkmgOd81iKfFPbrIkLlaIcrli9QxXED3MAeDRjStGFkGCYwBCv86C6fBxX8y5H5O4v94VzrZ45QqdLqbK"
    "s4lhi6rRGSEQyNxBHLtAerZxTqiogT5rvMY5TyyRoJsugW-jKfIMJOs5pZkouCsTJR2nGnhSEHXNSAJWyo-MePaLRSA4tdE7qa3NXaNXbUYxHIgkJMXcxpLT"
    "HLD0ZBzrfa1kNvISOAz65wJmuZjN6g13-hxRh09akVg5a0oo6o0-RmlRF8nvW829hhVxtw5rHc77FBG8ZTfV4PX07NxpKyR35pDvScLbDDhFuaEG5O9dmPoX"
    "W5rkbE0vVeI3WVl1u8DEGDwkrSPcxXLhkCkdDYGt9DJ0snSWlVwU7R2Wx_3r_XKzaaLhoXZCcqy0sGLOy5D0gf90jJ4t0K6PmOr1-1b9qhFX1dFH7qzjpoAZ"
    "3geT4kYy0Okg2AGXglMiarNN8lGbbGMJiFQQxtIKtCiSjX6RzGqg-ZqGyN8h_LTTYvXuUnMVQkdkiLME5aUtf3np7Ow8YAEB50EpjdldNhd03oPuPd49Beqp"
    "X-TaBXJC_C6E8CEyHh73MGwHpVSB57bJLIUe2U-ikG3PkPZMiaAR1DFBWTnupSRd-F4HMl8ueEzk1Gq2fgiYO3yzFegJtzj0RqMkLRkR-pjO2iEvhUMq6tmw"
    "lQr1t26nq9RiNXg0nwolI8dxa254LL5Dl-VBIpXzWcqEE6jdP6TBVHS5brbPnSkP7IMQVHIfG9jxABpb5wNXiqYv8FrVs_aX1ouNWZ2LPYYbR6RF1hZihYo4"
    "GiRvCzOS6ZNIS99x_nJrR3oN8-Cth5GZmaNtBucdozXD5CNr_2Oja-oncvqhLkcd82xeVcs4pZcq0YAVUk36XsokqApRCmhqklYC8lcvYYArM_cxQ4zxyzG-"
    "INEyXYKqGcEmtppHH2DykeP9bbWiLbnHOgIY-2XF8itn9XNU0o3uNdv2rS_ZOkg1OvBZP-nWcOQVkD__1xzTUx3YD0RlxzwcgiKTvcMcQFKTNidO7BOwbcVR"
    "AuKGeZMwL_r6l_TGtHKTGbbtTbCpbhQy2LQSHeM0JtFhgHx-0gm80s_SbULMDhxHbJS2qGGuYt47VlygVsmKw7TCMLXQbjRw6vHMdoQq1rADnMt1jGhnuzia"
    "4IpxFDD-COEg7ipCpPQiy1hAv6nBIZtLcU7RNbp4vn10LE9Gn3I6u0Iz7T9ZJ3AW29qqDG5ruOuboZPOKhhO6SxwhFg66xlT3ykxg7uRxQ0dB4e4G5ps0jG_"
    "lps0XHeHck7A5ccOo21X0GLrbb0yJhKVQMcWv4szsMX5lRZ-IO8VKpRO2Ssk3AL9s-E83VZqmesy2lKH1WF8Bnfy-DslzLWrIyOqzwBajumrAspk9magXJ6W"
    "gdqSTf3MRzV6GOGF5j5HKl9dBJWCY53CrVTLSY7q_pRcWweJXY9z1LlZUIKm7zftO-Dq5E-n7ab6Cn9LqmxrjlkDoyyRKvajDXYXfmA2Ge4W4n2NaL-NWN8g"
    "0vmOFdTuIs5vLcrvJMZvIcJLO6-i9zaiW1Ma3MtEgsOVYiZuCEpZYxxr5bYKu_Aa3xBs2dDMgiIdo8tdvWEC1o52xnC5mmpdbBqKqq7J7rk0WV4iJaZhzidl"
    "tRTdK2zqpeMs--3lKhuk2ZOej8NS3pSRptST61iFvupoeIRzp1ryLtualTnbwk7_iqdIBa-cN110a7irYRR1nVysVQXbz1prihl1HXnQLbRK7M1yDIltCfvU"
    "dg386sIAe8cyrXv0PGSB34Cd3mkZpQsQMe-_liJjWc_KvOQ0o_07KjlfoJr8Eykdm9nZZTBfZ8G_-53F7dH7d5MwlCaRSd8nnU3idx2gOxMO1U2tvvhRqa0H"
    "vD2K1FOV3KtSAIz9uHxAZMc0lgd-c4IJh1645j5WufK5_e1k3yWrpPGz0TKLv5lVWybbtjhm84WQQ4hLc9bXoanZjN8T1F3EsT0WnXXKvpxKU3K3cLp16hXc"
    "Lp7uGq6Ur2bi8ztO1x3o6_qhDmHyrjzmVXlzcPOmcPoAvxX8Xfold39k80X57EP3TyMxPq4o5Bde8nJMv3eCFnD1tMVF0jktS-uajd9DGdeQoyT7AL_rgonr"
    "4KepUfby7KUioz-K4gSTYPHM5N4S8tRQRZnejRKdViTSEWA6rl-y0GkEtuJNHgaOhK8GJQMzWW7ZJbNhr7XadmCtxO4NMYmw7ybs2pHfY_LhOX9Qz8yqxFuX"
    "J7Ox5hpLih-WWrbjSARvnG1ZH2tFhV7PLS70GpXiQa9ULSLctaoyQ28t3Z0_n9DYQDoHqzAHX86FRrDE-tZuOje2ZC4TtpApuMPVreVqy5n8ml8ZNtmvdACj"
    "Xsudlr1CcMB4IaU3CUNSksMQgYchV5FZT7X_Bg"
)


def build_fixed_loader_source() -> bytes:
    if CANONICAL_LOCATOR_PACKAGE_B64.count("@") != 0:
        raise LoaderIntegrityError("PACKAGE_MARKER_INVALID")
    source = _LOADER_TEMPLATE.replace(b"@P@", CANONICAL_LOCATOR_PACKAGE_B64.encode("ascii"), 1)
    if len(source) != 13832 or hashlib.sha256(source).hexdigest() != "8a51925e559907cefde4a0944893a9886d4178a8e244a0b916e73708b9783915":
        raise LoaderIntegrityError("FIXED_LOADER_KAT_FAILED")
    return source


def _load_fixed_locator_artifacts() -> tuple[bytes, bytes]:
    try:
        compressed = base64.urlsafe_b64decode(CANONICAL_LOCATOR_PACKAGE_B64 + "===")
        source = __import__("zlib").decompress(compressed, -15)
    except (ValueError, TypeError, OSError, zlib.error) as error:  # type: ignore[name-defined]
        raise LoaderIntegrityError("LOCATOR_PACKAGE_DECODE_FAILED") from error
    if (
        len(compressed) != CANONICAL_LOCATOR_COMPRESSED_BYTES
        or hashlib.sha256(compressed).hexdigest() != CANONICAL_LOCATOR_COMPRESSED_SHA256
        or len(source) != CANONICAL_LOCATOR_SOURCE_BYTES
        or len(source.splitlines()) != CANONICAL_LOCATOR_SOURCE_LINES
        or hashlib.sha256(source).hexdigest() != CANONICAL_LOCATOR_SOURCE_SHA256
    ):
        raise LoaderIntegrityError("LOCATOR_PACKAGE_KAT_FAILED")
    return compressed, source


CANONICAL_LOCATOR_PACKAGE, CANONICAL_LOCATOR_SOURCE = _load_fixed_locator_artifacts()
CANONICAL_LOCATOR_SOURCE_COMMITMENT = COMMITMENT_PREFIX + CANONICAL_LOCATOR_SOURCE_SHA256
CANONICAL_LOCATOR_PACKAGE_COMMITMENT = bytes_commitment("locator-package", CANONICAL_LOCATOR_PACKAGE_B64.encode("ascii"))
if CANONICAL_LOCATOR_PACKAGE_COMMITMENT != "sha256:v1:a28e039377ce58c7b7cdf57f19a020d83e8ccdc4cb5b02f94041b822a72880ad":
    raise LoaderIntegrityError("LOCATOR_PACKAGE_COMMITMENT_KAT_FAILED")
FIXED_LOADER_SOURCE = build_fixed_loader_source()
FIXED_LOADER_COMMITMENT = bytes_commitment("fixed-loader", FIXED_LOADER_SOURCE)


def compile_restricted_locator() -> types.ModuleType:
    trusted = {"__builtins__": builtins.__dict__, "__name__": "__fixed_loader__"}
    try:
        exec(compile(FIXED_LOADER_SOURCE, "<fixed-recovery-loader>", "exec", dont_inherit=True), trusted, trusted)
        module = sys.modules.get("__canonical_locator_payload__")
    except (SyntaxError, TypeError, ValueError, ImportError, MemoryError, RuntimeError) as error:
        raise LoaderIntegrityError("LOCATOR_LOAD_FAILED") from error
    if not isinstance(module, types.ModuleType) or module.__name__ != "__canonical_locator_payload__" or module.__file__ != CANONICAL_LOCATOR_PATH or module.__package__ is not None or not callable(module.__dict__.get("execute_operation")):
        raise LoaderIntegrityError("LOCATOR_MODULE_INVALID")
    if len(module.__dict__.get("__builtins__", {})) != 28:
        raise LoaderIntegrityError("LOCATOR_BUILTINS_INVALID")
    return module


def locator_source_commitment() -> str:
    return CANONICAL_LOCATOR_SOURCE_COMMITMENT


def compute_production_commitments(source_bytes: bytes) -> Mapping[str, str]:
    if not isinstance(source_bytes, bytes) or not 1 <= len(source_bytes) <= MAX_AGENT_BYTES:
        raise LoaderIntegrityError("AGENT_SOURCE_INVALID")
    launcher = bytes_commitment("recovery-launcher-bytes", source_bytes)
    agent = bytes_commitment("recovery-agent-bytes", source_bytes)
    return {
        "launcher_commitment": launcher,
        "agent_commitment": agent,
        "bundle_commitment": compute_bundle_commitment(launcher, agent),
    }


def fixed_clock() -> float:
    return time.monotonic()


def fixed_event_queue_factory() -> Any:
    return queue.Queue(maxsize=ENGINE_EVENT_QUEUE_MAX)


BUNDLE_KAT_BYTES = b"RUN352-BUNDLE-KAT\n"
BUNDLE_KAT_RAW_SHA256 = "4e0378b336ed0cad409a304eeb365fd222a2e729ff9f2a927342b873fa430789"
BUNDLE_KAT_LAUNCHER_COMMITMENT = "sha256:v1:8da1265e86c12e16374ca7b116a44383d8e45bc6735c4f51850b3791d3621e58"
BUNDLE_KAT_AGENT_COMMITMENT = "sha256:v1:ced6e5e4c626706a6568a3d602a4a0bdb6c522a2ceec8af3893c65afb391b4e8"
BUNDLE_KAT_COMMITMENT = "sha256:v1:4d9963a466e680260121d0a8ce38127f8989846c9189e29d57f89f70f76435b5"


def compute_bundle_commitment(launcher_commitment: str, agent_commitment: str) -> str:
    if any(not isinstance(value, str) or COMMITMENT_RE.fullmatch(value) is None for value in (launcher_commitment, agent_commitment)):
        raise LoaderIntegrityError("BUNDLE_COMMITMENT_INPUT_INVALID")
    return text_commitment(
        "recovery-agent-bundle", "swz-recovery-bundle.v2", CANONICAL_LOCATOR_SOURCE_COMMITMENT,
        LOCATOR_PACKAGE_ATTESTATION, CANONICAL_LOCATOR_PACKAGE_COMMITMENT,
        FIXED_LOADER_COMMITMENT, launcher_commitment, agent_commitment,
    )


if hashlib.sha256(BUNDLE_KAT_BYTES).hexdigest() != BUNDLE_KAT_RAW_SHA256 or compute_bundle_commitment(BUNDLE_KAT_LAUNCHER_COMMITMENT, BUNDLE_KAT_AGENT_COMMITMENT) != BUNDLE_KAT_COMMITMENT:
    raise LoaderIntegrityError("BUNDLE_KAT_FAILED")


_ACTIVE_PRODUCTION_BACKEND: Any | None = None


def fixed_process_factory() -> Any:
    backend = _ACTIVE_PRODUCTION_BACKEND
    if backend is None or not isinstance(backend, ProductionDockerBackend):
        raise DockerAdmissionError("PRODUCTION_DOCKER_BINDING_REQUIRED")
    return backend.open_locator_process()


def build_production_bundle_commitment_from_file(path: str | os.PathLike[str]) -> Mapping[str, str]:
    if not isinstance(path, (str, os.PathLike)):
        raise LoaderIntegrityError("SOURCE_PATH_INVALID")
    return compute_production_commitments(pathlib.Path(path).read_bytes())


def invoke_canonical_locator_once(
    barrier_utc: str,
    *,
    process_factory: Callable[[], Any] | None = None,
    clock: Callable[[], float] | None = None,
    event_queue_factory: Callable[[], Any] | None = None,
    test_mode: bool = False,
) -> Any:
    validate_barrier_utc(barrier_utc)
    if not test_mode and any(item is not None for item in (process_factory, clock, event_queue_factory)):
        raise LoaderIntegrityError("TEST_SEAM_NOT_PRODUCTION")
    module = compile_restricted_locator()
    process = process_factory or fixed_process_factory if test_mode else fixed_process_factory
    selected_clock = clock or fixed_clock if test_mode else fixed_clock
    selected_queue = event_queue_factory or fixed_event_queue_factory if test_mode else fixed_event_queue_factory
    outcome = module.execute_operation(barrier_utc, process_factory=process, clock=selected_clock, event_queue_factory=selected_queue)
    if test_mode and getattr(outcome, "classification", None) == "SUCCESS":
        raise LoaderIntegrityError("TEST_SUCCESS_NOT_OPERATIONAL")
    return outcome


@dataclass(frozen=True)
class ImageEvidence:
    schema: str
    image_ref: str
    image_id: str
    inspect_count: int
    pull_count: int
    tag_resolution_count: int
    image_os: str
    image_architecture: str


def validate_image_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    fields = ("schema", "image_ref", "image_id", "inspect_count", "pull_count", "tag_resolution_count", "image_os", "image_architecture")
    if not isinstance(value, Mapping) or tuple(value.keys()) != fields or value["schema"] != SCHEMA_IMAGE_EVIDENCE:
        raise DockerAdmissionError("IMAGE_EVIDENCE_INVALID")
    if value["image_ref"] != "postgres:17-alpine" or not IMAGE_ID_RE.fullmatch(str(value["image_id"])):
        raise DockerAdmissionError("IMAGE_EVIDENCE_INVALID")
    if value["inspect_count"] != 1 or value["pull_count"] != 0 or value["tag_resolution_count"] != 0 or value["image_os"] != "linux" or value["image_architecture"] not in {"amd64", "x86_64"}:
        raise DockerAdmissionError("IMAGE_EVIDENCE_INVALID")
    return dict(value)


def validate_target_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or value.get("schema") != SCHEMA_TARGET_EVIDENCE:
        raise DockerAdmissionError("TARGET_EVIDENCE_INVALID")
    required = ("schema", "container_id", "container_name", "image_id", "volume_name", "volume_destination", "run_owned", "preexisting_target", "preexisting_volume", "readback_count")
    if tuple(value.keys()) != required or not isinstance(value["container_id"], str) or not value["run_owned"] or value["preexisting_target"] or value["preexisting_volume"] or value["volume_destination"] != "/var/lib/postgresql/data" or value["readback_count"] != 1:
        raise DockerAdmissionError("TARGET_EVIDENCE_INVALID")
    _validate_image_id(value["image_id"])
    return dict(value)


def validate_isolation_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    fields = ("schema", "target_commitment", "image_commitment", "effective_image_id", "network_mode", "privileged", "rootfs_read_only", "cap_drop", "cap_add", "extra_mounts", "volume_destination", "volume_read_only", "readback_count")
    if not isinstance(value, Mapping) or tuple(value.keys()) != fields or value["schema"] != SCHEMA_ISOLATION_EVIDENCE:
        raise DockerAdmissionError("ISOLATION_EVIDENCE_INVALID")
    if value["network_mode"] != "none" or value["privileged"] is not False or value["rootfs_read_only"] is not True or value["cap_drop"] != ["ALL"] or value["cap_add"] != [] or value["extra_mounts"] != 0 or value["volume_destination"] != "/var/lib/postgresql/data" or value["volume_read_only"] is not False or value["readback_count"] != 1:
        raise DockerAdmissionError("ISOLATION_EVIDENCE_INVALID")
    _validate_image_id(value["effective_image_id"])
    _validate_commitment(value["image_commitment"], "image_commitment")
    _validate_commitment(value["target_commitment"], "target_commitment")
    return dict(value)


RESULT_EVIDENCE_FIELDS = (
    "schema", "classification", "stage", "epoch_ref", "authority_ref", "barrier_utc", "ssh_endpoint_commitment", "epoch_commitment", "authority_commitment", "barrier_commitment", "runner_commitment", "bundle_commitment", "launcher_commitment", "agent_commitment", "image_commitment", "target_commitment", "isolation_commitment", "artifact_commitment", "artifact_stream_commitment", "transition_id", "pre_cas_ledger_digest", "transition_data_commitment", "consumed_record_commitment", "restore_begin_commitment", "process_commitment", "restore_commitment", "cleanup_commitment", "stdout_capture_commitment", "stderr_capture_commitment", "result_code", "restore_count", "exit_status", "stdin_eof", "stdout_eof", "stderr_eof", "trailing_unframed_bytes", "terminal_input_eof", "terminal_input_trailing_bytes", "cleanup_state",
)
ABORT_EVIDENCE_FIELDS = (
    "schema", "epoch_ref", "authority_ref", "ssh_endpoint_commitment", "stage", "direction", "code", "classification", "epoch_commitment", "authority_commitment", "barrier_commitment", "transition_id", "transition_data_commitment", "restore_begin_commitment", "consumed_state", "record_state", "ledger_state", "spool_last_stage", "store_readback_commitment", "process_finality", "transport_finality", "cleanup_state", "retry_allowed", "reconnect_allowed", "proceed_allowed", "restore_allowed", "commit_allowed", "abandon_allowed",
)


def _validate_evidence_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise ProtocolError(f"{label}_INVALID")
    return value


def validate_result_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or tuple(value.keys()) != RESULT_EVIDENCE_FIELDS or value["schema"] != SCHEMA_RESULT or value["classification"] not in RESULT_CLASSIFICATIONS:
        raise ProtocolError("RESULT_EVIDENCE_INVALID")
    for key, child in value.items():
        if key.endswith("_commitment") or key.endswith("_digest"):
            _validate_commitment(child, key)
    for key in ("stage", "epoch_ref", "authority_ref", "result_code", "cleanup_state"):
        _validate_evidence_text(value[key], key)
    validate_barrier_utc(value["barrier_utc"])
    if type(value["restore_count"]) is not int or value["restore_count"] < 0 or type(value["exit_status"]) is not int or not -1 <= value["exit_status"] <= 255:
        raise ProtocolError("RESULT_EVIDENCE_INVALID")
    if any(type(value[key]) is not bool for key in ("stdin_eof", "stdout_eof", "stderr_eof", "terminal_input_eof")):
        raise ProtocolError("RESULT_EVIDENCE_INVALID")
    if type(value["trailing_unframed_bytes"]) is not int or value["trailing_unframed_bytes"] < 0 or type(value["terminal_input_trailing_bytes"]) is not int or value["terminal_input_trailing_bytes"] < 0:
        raise ProtocolError("RESULT_EVIDENCE_INVALID")
    if value["classification"] == "SUCCESS" and (not value["stdin_eof"] or not value["stdout_eof"] or not value["stderr_eof"] or not value["terminal_input_eof"] or value["trailing_unframed_bytes"] != 0 or value["terminal_input_trailing_bytes"] != 0 or value["cleanup_state"] != "COMPLETE"):
        raise ProtocolError("RESULT_EVIDENCE_INVALID")
    return dict(value)


def validate_abort_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or tuple(value.keys()) != ABORT_EVIDENCE_FIELDS or value["schema"] != SCHEMA_ABORT or value["classification"] != "FAILURE":
        raise ProtocolError("ABORT_EVIDENCE_INVALID")
    for key, child in value.items():
        if key.endswith("_commitment") or key.endswith("_digest"):
            _validate_commitment(child, key)
    if any(type(value[key]) is not bool for key in ("retry_allowed", "reconnect_allowed", "proceed_allowed", "restore_allowed", "commit_allowed", "abandon_allowed")):
        raise ProtocolError("ABORT_EVIDENCE_INVALID")
    if any(value[key] for key in ("retry_allowed", "reconnect_allowed", "proceed_allowed", "restore_allowed", "commit_allowed")):
        raise ProtocolError("ABORT_EVIDENCE_INVALID")
    return dict(value)


def result_commitment(result_evidence: Mapping[str, Any]) -> str:
    if tuple(result_evidence.keys()) != RESULT_EVIDENCE_FIELDS:
        raise ProtocolError("RESULT_EVIDENCE_FIELDS_INVALID")
    return bytes_commitment("result-evidence", canonical_json(dict(result_evidence), terminal_lf=True))


def abort_commitment(abort_evidence: Mapping[str, Any]) -> str:
    if tuple(abort_evidence.keys()) != ABORT_EVIDENCE_FIELDS:
        raise ProtocolError("ABORT_EVIDENCE_FIELDS_INVALID")
    return bytes_commitment("abort-evidence", canonical_json(dict(abort_evidence), terminal_lf=True))


def _docker_commitment(domain: str, value: Mapping[str, Any]) -> str:
    return bytes_commitment(domain, canonical_json(dict(value), terminal_lf=True))


@dataclass(frozen=True)
class DockerDiscovery:
    image_commitment: str
    target_commitment: str
    isolation_commitment: str
    execution_row_id: int
    artifact_filename: str
    artifact_commitment: str | None = None
    artifact_stream_commitment: str | None = None


@dataclass(frozen=True)
class DockerInstallationConfig:
    socket_path: str
    image_ref: str
    image_id: str
    run_id: str
    volume_id: str
    target_id: str
    metadata_source_name: str = METADATA_SOURCE_CONTAINER_NAME

    def __post_init__(self) -> None:
        if self.socket_path != "/var/run/docker.sock" or self.image_ref != "postgres:17-alpine" or not IMAGE_ID_RE.fullmatch(self.image_id) or not REF_RE.fullmatch(self.run_id) or not REF_RE.fullmatch(self.volume_id) or not REF_RE.fullmatch(self.target_id) or self.metadata_source_name != METADATA_SOURCE_CONTAINER_NAME:
            raise DockerAdmissionError("DOCKER_INSTALLATION_INVALID")

    @property
    def epoch_ref(self) -> str:
        return self.run_id

    @classmethod
    def from_installed(cls, epoch_ref: str) -> "DockerInstallationConfig":
        return cls("/var/run/docker.sock", "postgres:17-alpine", _read_admitted_image_id(PRODUCTION_IMAGE_ID_PATH), epoch_ref, "volume-" + epoch_ref, "target-" + epoch_ref)


class UnixSocketHTTPClient:
    def __init__(self, socket_path: str = "/var/run/docker.sock", *, timeout: float = 5.0) -> None:
        if socket_path != "/var/run/docker.sock" or timeout <= 0:
            raise DockerAdmissionError("DOCKER_SOCKET_INVALID")
        self.socket_path = socket_path
        self.timeout = timeout

    def request(self, method: str, path: str, body: Mapping[str, Any] | None = None) -> tuple[int, Mapping[str, Any]]:
        if method not in {"GET", "POST", "DELETE"} or not isinstance(path, str) or not path.startswith("/") or ".." in path or "\x00" in path:
            raise DockerAdmissionError("DOCKER_REQUEST_INVALID")
        payload = b"" if body is None else canonical_json(dict(body))
        request = (f"{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {len(payload)}\r\n\r\n").encode("ascii") + payload
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
                channel.settimeout(self.timeout)
                channel.connect(self.socket_path)
                channel.sendall(request)
                data = bytearray()
                while len(data) <= MAX_HTTP_HEADER_BYTES + MAX_HTTP_BODY_BYTES:
                    chunk = channel.recv(READ_CHUNK_BYTES)
                    if not chunk:
                        break
                    data.extend(chunk)
                    if b"\r\n\r\n" in data and len(data) > MAX_HTTP_HEADER_BYTES + MAX_HTTP_BODY_BYTES:
                        break
        except (OSError, ValueError) as error:
            raise DockerAdmissionError("DOCKER_SOCKET_FAILED") from error
        head, separator, raw_body = bytes(data).partition(b"\r\n\r\n")
        if not separator or len(head) > MAX_HTTP_HEADER_BYTES or len(raw_body) > MAX_HTTP_BODY_BYTES:
            raise DockerAdmissionError("DOCKER_RESPONSE_INVALID")
        first = head.splitlines()[0].split()
        if len(first) < 2:
            raise DockerAdmissionError("DOCKER_RESPONSE_INVALID")
        try:
            status = int(first[1])
            decoded = json.loads(raw_body.decode("utf-8")) if raw_body else {}
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise DockerAdmissionError("DOCKER_RESPONSE_INVALID") from error
        if not isinstance(decoded, dict):
            raise DockerAdmissionError("DOCKER_RESPONSE_INVALID")
        return status, decoded

    def open_exec_process(self, container_id: str, command: tuple[str, ...], *, environment: tuple[str, ...]) -> "_DockerEngineProcess":
        return _client_open_exec_process(self, container_id, command, environment=environment)


class TestOnlyDockerBackend:
    test_only = True
    synthetic_provenance = True

    def __init__(self, *, discovery: DockerDiscovery) -> None:
        self.discovery = discovery

    def bind_boot(self, _boot: Mapping[str, Any]) -> None:
        return None

    def mark_discovery_emitted(self) -> None:
        return None

    def record_proceed_boundary(self) -> None:
        return None

    def discover(self, _epoch_ref: str, _barrier_utc: str) -> DockerDiscovery:
        return self.discovery

    def operation(self, _barrier_utc: str) -> Mapping[str, Any]:
        raise DockerAdmissionError("TEST_BACKEND_CANNOT_PRODUCE_SUCCESS")

    def restore(self, *_args: Any, **_kwargs: Any) -> Mapping[str, Any]:
        raise DockerAdmissionError("TEST_BACKEND_CANNOT_PRODUCE_SUCCESS")


def _read_admitted_line(path: str, *, label: str) -> str:
    if sys.platform != "linux" or not isinstance(path, str) or not path.startswith("/") or "\x00" in path or not getattr(os, "O_NOFOLLOW", 0):
        raise DescriptorAdmissionError("INSTALLATION_NO_FOLLOW_UNAVAILABLE")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except (OSError, ValueError) as error:
        raise DescriptorAdmissionError(f"{label.upper()}_OPEN_FAILED") from error
    try:
        before = os.fstat(fd)
        mode = int(before.st_mode)
        if not stat.S_ISREG(mode) or int(before.st_uid) != 0 or int(before.st_gid) != 0 or stat.S_IMODE(mode) != 0o444:
            raise DescriptorAdmissionError(f"{label.upper()}_ADMISSION_FAILED")
        raw = bytearray()
        while True:
            chunk = os.read(fd, READ_CHUNK_BYTES)
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > 4096:
                raise DescriptorAdmissionError(f"{label.upper()}_OVERSIZE")
        after = os.fstat(fd)
        if _stat_identity(before) != _stat_identity(after):
            raise DescriptorAdmissionError(f"{label.upper()}_SUBSTITUTED")
    except (OSError, ValueError) as error:
        raise DescriptorAdmissionError(f"{label.upper()}_READ_FAILED") from error
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    raw_bytes = bytes(raw)
    if not raw_bytes.endswith(b"\n") or raw_bytes.count(b"\n") != 1:
        raise DescriptorAdmissionError(f"{label.upper()}_INVALID")
    try:
        value = raw_bytes[:-1].decode("ascii", "strict")
    except UnicodeDecodeError as error:
        raise DescriptorAdmissionError(f"{label.upper()}_INVALID") from error
    if not value:
        raise DescriptorAdmissionError(f"{label.upper()}_INVALID")
    return value


def _read_admitted_recovery_commitment(path: str, *, label: str) -> str:
    value = _read_admitted_line(path, label=label)
    if not _is_commitment(value):
        raise DescriptorAdmissionError(f"{label.upper()}_FORMAT_INVALID")
    return value


def _read_admitted_image_id(path: str, *, label: str = "docker_image_id") -> str:
    value = _read_admitted_line(path, label=label)
    if IMAGE_ID_RE.fullmatch(value) is None:
        raise DescriptorAdmissionError("DOCKER_IMAGE_ID_FORMAT_INVALID")
    return value


def open_artifact_descriptor(root: str, filename: str) -> int:
    _validate_filename(filename)
    if sys.platform != "linux" or not isinstance(root, str) or not root.startswith("/") or "\x00" in root or not getattr(os, "O_NOFOLLOW", 0):
        raise DescriptorAdmissionError("ARTIFACT_ROOT_INVALID")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    root_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        directory = os.open(root, root_flags)
        try:
            root_stat = os.fstat(directory)
            if not stat.S_ISDIR(root_stat.st_mode) or int(root_stat.st_uid) != 0 or int(root_stat.st_gid) != 0 or int(root_stat.st_mode) & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID):
                raise DescriptorAdmissionError("ARTIFACT_ROOT_ADMISSION_FAILED")
            return os.open(filename, flags, dir_fd=directory)
        finally:
            os.close(directory)
    except (OSError, ValueError) as error:
        raise DescriptorAdmissionError("ARTIFACT_OPEN_FAILED") from error


class _EngineInput(io.RawIOBase):
    def __init__(self, sock: socket.socket, lock: threading.Lock) -> None:
        self.sock = sock
        self.lock = lock
        self.closed_by_user = False

    def writable(self) -> bool:
        return True

    def write(self, value: bytes) -> int:
        if self.closed_by_user:
            raise OSError("closed")
        with self.lock:
            self.sock.sendall(value)
        return len(value)

    def close(self) -> None:
        if self.closed_by_user:
            return
        self.closed_by_user = True
        try:
            self.sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class _EngineOutput(io.RawIOBase):
    def __init__(self, events: queue.Queue[bytes | None], *, done_event: threading.Event | None = None) -> None:
        self.events = events
        self.done_event = done_event
        self._pending = b""
        self._eof = False

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        if self._eof:
            return b""
        if size == 0:
            return b""
        while not self._pending:
            try:
                item = self.events.get(timeout=ENGINE_QUEUE_TIMEOUT_SECONDS if self.done_event is not None else ENGINE_IO_DEADLINE_SECONDS)
            except queue.Empty as error:
                if self.done_event is not None and self.done_event.is_set():
                    self._eof = True
                    return b""
                raise DockerAdmissionError("DOCKER_STREAM_FINALITY_TIMEOUT") from error
            if item is None:
                self._eof = True
                return b""
            self._pending = item
        if size < 0 or len(self._pending) <= size:
            item = self._pending
            self._pending = b""
            return item
        item, self._pending = self._pending[:size], self._pending[size:]
        return item


def _put_engine_event(events: queue.Queue[bytes | None], item: bytes | None) -> None:
    deadline = time.monotonic() + ENGINE_IO_DEADLINE_SECONDS
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DockerAdmissionError("DOCKER_STREAM_BACKPRESSURE")
        try:
            events.put(item, timeout=min(ENGINE_QUEUE_TIMEOUT_SECONDS, remaining))
            return
        except queue.Full:
            continue


class _DockerEngineProcess:
    """Bounded Docker attach process; it has no OS child to reap."""

    def __init__(self, client: Any, exec_id: str, sock: socket.socket) -> None:
        self.client = client
        self.exec_id = exec_id
        self.sock = sock
        self._write_lock = threading.Lock()
        self._events: queue.Queue[bytes | None] = queue.Queue(maxsize=ENGINE_EVENT_QUEUE_MAX)
        self._done = threading.Event()
        self._reader_done = self._done
        self._reader_error: Exception | None = None
        self._stream_eof = False
        self.returncode: int | None = None
        self.stdin = _EngineInput(sock, self._write_lock)
        self.stdout = _EngineOutput(self._events, done_event=self._done)
        self.stderr = _EngineOutput(queue.Queue(maxsize=ENGINE_EVENT_QUEUE_MAX), done_event=self._done)
        self._stderr_events: queue.Queue[bytes | None] = self.stderr.events
        self._reader = threading.Thread(target=self._read_multiplexed, daemon=True)
        self._reader.start()

    def _read_multiplexed(self) -> None:
        try:
            while True:
                header = b""
                while len(header) < 8:
                    chunk = self.sock.recv(8 - len(header))
                    if not chunk:
                        if header:
                            raise DockerAdmissionError("DOCKER_STREAM_TRUNCATED")
                        self._stream_eof = True
                        _put_engine_event(self._events, None)
                        _put_engine_event(self._stderr_events, None)
                        return
                    header += chunk
                stream_id, reserved1, reserved2, reserved3, length = header[0], header[1], header[2], header[3], struct.unpack(">I", header[4:])[0]
                if reserved1 or reserved2 or reserved3:
                    raise DockerAdmissionError("DOCKER_STREAM_HEADER_INVALID")
                if stream_id not in (1, 2):
                    raise DockerAdmissionError("DOCKER_STREAM_ID_INVALID")
                if length > MAX_HTTP_BODY_BYTES:
                    raise DockerAdmissionError("DOCKER_STREAM_FRAME_OVERSIZE")
                payload = bytearray()
                while len(payload) < length:
                    chunk = self.sock.recv(length - len(payload))
                    if not chunk:
                        raise DockerAdmissionError("DOCKER_STREAM_TRUNCATED")
                    payload.extend(chunk)
                _put_engine_event(self._events if stream_id == 1 else self._stderr_events, bytes(payload))
        except Exception as error:
            self._reader_error = error
            try:
                _put_engine_event(self._events, None)
                _put_engine_event(self._stderr_events, None)
            except Exception:
                pass
        finally:
            self._done.set()

    def poll(self) -> int | None:
        if self.returncode is not None:
            return self.returncode
        if not self._done.is_set():
            return None
        if self._reader_error is not None:
            raise DockerAdmissionError("DOCKER_STREAM_FINALITY_FAILED") from self._reader_error
        try:
            status, payload = self.client.request("GET", f"/exec/{urllib.parse.quote(self.exec_id, safe='')}/json")
            if status != 200 or not isinstance(payload, Mapping) or type(payload.get("Running")) is not bool:
                raise DockerAdmissionError("DOCKER_EXEC_STATUS_INVALID")
            if payload["Running"]:
                return None
            exit_code = payload.get("ExitCode")
            if type(exit_code) is not int or not 0 <= exit_code <= 255:
                raise DockerAdmissionError("DOCKER_EXEC_EXIT_INVALID")
            self.returncode = exit_code
            return exit_code
        except DockerAdmissionError:
            raise
        except Exception as error:
            raise DockerAdmissionError("DOCKER_EXEC_STATUS_FAILED") from error

    def wait(self, timeout: float | None = None) -> int:
        if timeout is None:
            raise FinalityError("DOCKER_WAIT_UNBOUNDED")
        if not self._done.wait(timeout=max(0.0, timeout)):
            raise TimeoutError("docker process timeout")
        if self._reader_error is not None:
            raise DockerAdmissionError("DOCKER_STREAM_FINALITY_FAILED") from self._reader_error
        status, payload = self.client.request("GET", f"/exec/{urllib.parse.quote(self.exec_id, safe='')}/json")
        if status != 200 or not isinstance(payload, Mapping) or payload.get("Running") is not False:
            raise DockerAdmissionError("DOCKER_EXEC_STATUS_INVALID")
        exit_code = payload.get("ExitCode")
        if type(exit_code) is not int or not 0 <= exit_code <= 255:
            raise DockerAdmissionError("DOCKER_EXEC_EXIT_INVALID")
        self.returncode = exit_code
        return exit_code

    def terminate(self) -> None:
        self.kill()

    def kill(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class _PrefetchedSocket:
    def __init__(self, sock: socket.socket, prefix: bytes) -> None:
        self._sock = sock
        self._prefix = bytearray(prefix)

    def recv(self, size: int, *args: Any) -> bytes:
        if self._prefix:
            chunk = bytes(self._prefix[:size])
            del self._prefix[:size]
            return chunk
        return self._sock.recv(size, *args)

    def sendall(self, value: bytes) -> None:
        self._sock.sendall(value)

    def shutdown(self, how: int) -> None:
        self._sock.shutdown(how)

    def close(self) -> None:
        self._sock.close()


def _open_hijacked_socket(client: UnixSocketHTTPClient, path: str, body: Mapping[str, Any]) -> Any:
    if not isinstance(client, UnixSocketHTTPClient):
        raise DockerAdmissionError("DOCKER_CLIENT_INVALID")
    channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        channel.settimeout(client.timeout)
        channel.connect(client.socket_path)
        payload = canonical_json(dict(body))
        request = (f"POST {path}?hijack=1 HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Type: application/json\r\nContent-Length: {len(payload)}\r\n\r\n").encode("ascii") + payload
        channel.sendall(request)
        response = bytearray()
        while b"\r\n\r\n" not in response and len(response) <= MAX_HTTP_HEADER_BYTES:
            chunk = channel.recv(min(READ_CHUNK_BYTES, MAX_HTTP_HEADER_BYTES + 4 - len(response)))
            if not chunk:
                break
            response.extend(chunk)
        header_end = response.find(b"\r\n\r\n")
        if header_end <= 0 or header_end > MAX_HTTP_HEADER_BYTES:
            raise DockerAdmissionError("DOCKER_HIJACK_FAILED")
        status_line = bytes(response[:header_end]).splitlines()[0].split()
        if len(status_line) < 2 or status_line[1] not in {b"101", b"200"}:
            raise DockerAdmissionError("DOCKER_HIJACK_FAILED")
        return _PrefetchedSocket(channel, bytes(response[header_end + 4:]))
    except Exception:
        channel.close()
        raise


def _client_open_exec_process(client: Any, container_id: str, command: tuple[str, ...], *, environment: tuple[str, ...]) -> _DockerEngineProcess:
    if not isinstance(client, UnixSocketHTTPClient) or not isinstance(container_id, str) or not container_id or not isinstance(command, tuple) or not command or any(not isinstance(item, str) or not item for item in command):
        raise DockerAdmissionError("DOCKER_EXEC_COMMAND_INVALID")
    if tuple(environment) != DOCKER_EXEC_ENVIRONMENT:
        raise DockerAdmissionError("DOCKER_EXEC_ENVIRONMENT_INVALID")
    body = {"AttachStdin": True, "AttachStdout": True, "AttachStderr": True, "Tty": False, "Cmd": list(command), "Env": list(environment)}
    status, response = client.request("POST", f"/containers/{urllib.parse.quote(container_id, safe='')}/exec", body)
    if status != 201 or not isinstance(response, Mapping) or not isinstance(response.get("Id"), str) or not response["Id"]:
        raise DockerAdmissionError("DOCKER_EXEC_CREATE_FAILED")
    sock = _open_hijacked_socket(client, f"/exec/{response['Id']}/start", {"Detach": False, "Tty": False})
    return _DockerEngineProcess(client, response["Id"], sock)


_INSTALL_ROOT = "/opt/swooshz/recovery"
DOCKER_EXEC_ENVIRONMENT = ("HOME=/nonexistent", "LANG=C", "LC_ALL=C")
RESTORE_COMMAND = ("/usr/local/bin/pg_restore", "--exit-on-error", "--no-owner", "--no-privileges", "--dbname=coolify", "-")


@dataclass(frozen=True)
class _OwnedDockerResources:
    target_id: str
    target_name: str
    volume_name: str
    run_id: str


def _validate_not_preexisting(client: Any, method: str, path: str, code: str) -> None:
    status, _payload = client.request(method, path)
    if status != 404:
        raise DockerAdmissionError(code)


def _require_owned_volume(value: Any, volume_name: str, run_id: str, code: str) -> None:
    if not isinstance(value, Mapping) or value.get("Name") != volume_name:
        raise DockerAdmissionError(code)
    labels = value.get("Labels")
    if not isinstance(labels, Mapping) or labels.get("com.swooshz.recovery.run") != run_id:
        raise DockerAdmissionError(code)


def _target_inspection(value: Mapping[str, Any], image_id: str | None = None, volume_name: str | None = None, epoch_ref: str | None = None, *, target_id: str | None = None, target_name: str | None = None, run_id: str | None = None, require_running: bool = False) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(value, Mapping) or value.get("Id") is None:
        raise DockerAdmissionError("TARGET_READBACK_INVALID")
    if image_id is None or volume_name is None:
        raise DockerAdmissionError("TARGET_READBACK_INVALID")
    if run_id is None:
        run_id = epoch_ref
    if target_id is not None and value.get("Id") != target_id:
        raise DockerAdmissionError("TARGET_IDENTITY_MISMATCH")
    if target_name is not None and value.get("Name") not in {target_name, "/" + target_name}:
        raise DockerAdmissionError("TARGET_IDENTITY_MISMATCH")
    if require_running and (not isinstance(value.get("State"), Mapping) or value["State"].get("Running") is not True):
        raise DockerAdmissionError("TARGET_NOT_RUNNING")
    config = value.get("Config")
    host = value.get("HostConfig")
    mounts = value.get("Mounts")
    network = value.get("NetworkSettings")
    if not isinstance(config, Mapping) or not isinstance(host, Mapping) or not isinstance(mounts, list) or not isinstance(network, Mapping):
        raise DockerAdmissionError("TARGET_READBACK_INVALID")
    labels = config.get("Labels")
    if config.get("Image") != image_id or config.get("Env") != ["POSTGRES_DB=coolify"] or not isinstance(labels, Mapping) or labels.get("com.swooshz.recovery.run") != run_id:
        raise DockerAdmissionError("TARGET_ISOLATION_FAILED")
    if host.get("NetworkMode") != "none" or host.get("Privileged") is not False or host.get("ReadonlyRootfs") is not True or host.get("CapDrop") != ["ALL"] or host.get("CapAdd") != [] or host.get("PublishAllPorts") is not False or host.get("PortBindings") != {} or host.get("ExtraHosts") != [] or host.get("SecurityOpt") != [] or host.get("Binds") != [f"{volume_name}:/var/lib/postgresql/data:rw"]:
        raise DockerAdmissionError("TARGET_ISOLATION_FAILED")
    if network.get("Networks") != {} or len(mounts) != 1 or mounts[0].get("Destination") != "/var/lib/postgresql/data" or mounts[0].get("RW") is not True or mounts[0].get("Name") != volume_name or mounts[0].get("Type") != "volume":
        raise DockerAdmissionError("TARGET_ISOLATION_FAILED")
    target = {
        "schema": SCHEMA_TARGET_EVIDENCE,
        "container_id": str(value["Id"]),
        "container_name": str(value.get("Name", "")),
        "image_id": image_id,
        "volume_name": volume_name,
        "volume_destination": "/var/lib/postgresql/data",
        "run_owned": True,
        "preexisting_target": False,
        "preexisting_volume": False,
        "readback_count": 1,
    }
    isolation = {
        "schema": SCHEMA_ISOLATION_EVIDENCE,
        "target_commitment": _docker_commitment("target-evidence", target),
        "image_commitment": "",
        "effective_image_id": image_id,
        "network_mode": "none",
        "privileged": False,
        "rootfs_read_only": True,
        "cap_drop": ["ALL"],
        "cap_add": [],
        "extra_mounts": 0,
        "volume_destination": "/var/lib/postgresql/data",
        "volume_read_only": False,
        "readback_count": 1,
    }
    return target, isolation


def _canonical_locator_shell_wrapper() -> str:
    module = compile_restricted_locator()
    wrapper = module.__dict__.get("SHELL_WRAPPER")
    if not isinstance(wrapper, str) or not wrapper.endswith("\n"):
        raise LoaderIntegrityError("LOCATOR_WRAPPER_INVALID")
    return wrapper


class ProductionDockerBackend:
    """Docker Engine-only production backend with run-owned resources."""

    test_only = False
    synthetic_provenance = False

    @classmethod
    def from_installed(cls, epoch_ref: str) -> "ProductionDockerBackend":
        return cls(DockerInstallationConfig.from_installed(epoch_ref), client=UnixSocketHTTPClient(), provenance="operational")

    def __init__(self, config: DockerInstallationConfig, *, client: Any, provenance: str = "test-double") -> None:
        if not isinstance(config, DockerInstallationConfig):
            raise DockerAdmissionError("DOCKER_CONFIG_INVALID")
        if provenance == "operational" and not isinstance(client, UnixSocketHTTPClient):
            raise DockerAdmissionError("DOCKER_PROVENANCE_INVALID")
        self.config = config
        self.client = client
        self.provenance = provenance
        self._resources: _OwnedDockerResources | None = None
        self._metadata_source: Mapping[str, Any] | None = None
        self._image: Mapping[str, Any] | None = None
        self._target: Mapping[str, Any] | None = None
        self._isolation: Mapping[str, Any] | None = None
        self._artifact: QualifiedArtifact | None = None
        self._artifact_fd: int | None = None
        self._artifact_evidence: Mapping[str, Any] | None = None
        self._boot: Mapping[str, Any] | None = None
        self._discovery_emitted = False
        self._proceed_received = False
        self._cleanup_done = False
        self.pull_count = 0
        self.tag_resolution_count = 0

    def _close_artifact_descriptor(self) -> None:
        if self._artifact_fd is not None:
            try:
                os.close(self._artifact_fd)
            except OSError:
                pass
            self._artifact_fd = None

    def bind_boot(self, boot: Mapping[str, Any]) -> None:
        if not isinstance(boot, Mapping):
            raise DockerAdmissionError("BOOT_BINDING_INVALID")
        self._boot = dict(boot)

    def _admit_metadata_source(self) -> Mapping[str, Any]:
        path = f"/containers/{urllib.parse.quote(self.config.metadata_source_name, safe='')}/json"
        status, payload = self.client.request("GET", path)
        if status != 200 or not isinstance(payload, Mapping) or payload.get("Name") not in {self.config.metadata_source_name, f"/{self.config.metadata_source_name}"} or not isinstance(payload.get("State"), Mapping) or payload["State"].get("Running") is not True:
            raise DockerAdmissionError("METADATA_SOURCE_INVALID")
        result = {"source_id": payload.get("Id"), "source_name": self.config.metadata_source_name, "readback_count": 1}
        if not isinstance(result["source_id"], str):
            raise DockerAdmissionError("METADATA_SOURCE_INVALID")
        self._metadata_source = result
        return result

    def mark_discovery_emitted(self) -> None:
        if self._operation_state != "DISCOVERY_READY":
            raise DockerAdmissionError("DISCOVERY_STATE_INVALID", safety_state="CONSUMED")
        self._discovery_emitted = True
        self._operation_state = "DISCOVERY_EMITTED"

    def record_proceed_boundary(self) -> None:
        if not self._discovery_emitted or self._operation_state != "DISCOVERY_EMITTED":
            raise DockerAdmissionError("PROCEED_BEFORE_DISCOVERY", safety_state="CONSUMED")
        self._proceed_received = True
        self._operation_state = "PROCEED_RECEIVED"

    def inspect_image(self) -> Mapping[str, Any]:
        status, payload = self.client.request("GET", f"/images/{urllib.parse.quote(self.config.image_ref, safe='')}/json")
        if status != 200 or not isinstance(payload, Mapping) or payload.get("Id") != self.config.image_id or payload.get("Os") != "linux" or payload.get("Architecture") not in {"amd64", "x86_64"}:
            raise DockerAdmissionError("IMAGE_ADMISSION_FAILED")
        image = {
            "schema": SCHEMA_IMAGE_EVIDENCE,
            "image_ref": self.config.image_ref,
            "image_id": self.config.image_id,
            "inspect_count": 1,
            "pull_count": 0,
            "tag_resolution_count": 0,
            "image_os": payload["Os"],
            "image_architecture": payload["Architecture"],
        }
        self._image = validate_image_evidence(image)
        return self._image

    def create_isolated_target(self, image: Mapping[str, Any]) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        if not self._metadata_source or not isinstance(image, Mapping):
            raise DockerAdmissionError("TARGET_PRECONDITION_FAILED")
        checked_image = validate_image_evidence(image)
        if checked_image["image_id"] != self.config.image_id or checked_image["image_ref"] != self.config.image_ref:
            raise DockerAdmissionError("IMAGE_BINDING_INVALID")
        volume_name = f"swooshz-recovery-volume-{self.config.volume_id}"
        target_name = f"swooshz-recovery-target-{self.config.target_id}"
        volume_created = False
        try:
            volume_path = f"/volumes/{urllib.parse.quote(volume_name, safe='')}"
            target_name_path = f"/containers/{urllib.parse.quote(target_name, safe='')}/json"
            _validate_not_preexisting(self.client, "GET", volume_path, "RECOVERY_VOLUME_PREEXISTING")
            _validate_not_preexisting(self.client, "GET", target_name_path, "RECOVERY_TARGET_PREEXISTING")
            labels = {"com.swooshz.recovery.run": self.config.run_id}
            status, volume = self.client.request("POST", "/volumes/create", {"Name": volume_name, "Labels": labels})
            if status != 201 or not isinstance(volume, Mapping) or volume.get("Name") != volume_name:
                raise DockerAdmissionError("RECOVERY_VOLUME_CREATE_FAILED")
            volume_created = True
            status, volume_readback = self.client.request("GET", volume_path)
            if status != 200:
                raise DockerAdmissionError("RECOVERY_VOLUME_READBACK_FAILED")
            _require_owned_volume(volume_readback, volume_name, self.config.run_id, "RECOVERY_VOLUME_OWNERSHIP_UNPROVEN")
            host_config = {
                "NetworkMode": "none",
                "Privileged": False,
                "ReadonlyRootfs": True,
                "CapDrop": ["ALL"],
                "CapAdd": [],
                "PublishAllPorts": False,
                "PortBindings": {},
                "ExtraHosts": [],
                "SecurityOpt": [],
                "Binds": [f"{volume_name}:/var/lib/postgresql/data:rw"],
            }
            body = {"Image": checked_image["image_id"], "Env": ["POSTGRES_DB=coolify"], "Labels": labels, "HostConfig": host_config}
            create_path = f"/containers/create?name={urllib.parse.quote(target_name, safe='')}"
            status, created = self.client.request("POST", create_path, body)
            if status != 201 or not isinstance(created, Mapping) or not isinstance(created.get("Id"), str) or not created["Id"]:
                raise DockerAdmissionError("RECOVERY_TARGET_CREATE_FAILED")
            container_id = created["Id"]
            resources = _OwnedDockerResources(container_id, target_name, volume_name, self.config.run_id)
            self._resources = resources
            if self._metadata_source["source_id"] == container_id or self._metadata_source["source_name"] in {target_name, "/" + target_name}:
                raise DockerAdmissionError("METADATA_RESTORE_TARGET_NOT_DISTINCT")
            container_path = f"/containers/{urllib.parse.quote(container_id, safe='')}"
            status, readback = self.client.request("GET", f"{container_path}/json")
            if status != 200 or not isinstance(readback, Mapping):
                raise DockerAdmissionError("TARGET_READBACK_FAILED")
            target, isolation = _target_inspection(readback, checked_image["image_id"], volume_name, self.config.run_id, target_id=container_id, target_name=target_name, run_id=self.config.run_id)
            isolation["image_commitment"] = _docker_commitment("image-evidence", checked_image)
            isolation = validate_isolation_evidence(isolation)
            target = validate_target_evidence(target)
            self._target, self._isolation = target, isolation
            status, _started = self.client.request("POST", f"{container_path}/start")
            if status != 204:
                raise DockerAdmissionError("RECOVERY_TARGET_START_FAILED")
            status, running_readback = self.client.request("GET", f"{container_path}/json")
            if status != 200 or not isinstance(running_readback, Mapping):
                raise DockerAdmissionError("TARGET_RUNNING_READBACK_FAILED")
            _target_inspection(running_readback, checked_image["image_id"], volume_name, self.config.run_id, target_id=container_id, target_name=target_name, run_id=self.config.run_id, require_running=True)
            return target, isolation
        except Exception as error:
            if self._resources is not None and not self._cleanup_done:
                try:
                    if self._target is not None:
                        self.cleanup(self._target, self._resources.volume_name)
                    else:
                        self._cleanup_unqualified_resources()
                except Exception as cleanup_error:
                    raise DockerAdmissionError("TARGET_CLEANUP_FAILED", safety_state="CONSUMED") from cleanup_error
            elif volume_created:
                try:
                    self._cleanup_created_volume(volume_name)
                except Exception as cleanup_error:
                    raise DockerAdmissionError("VOLUME_CLEANUP_FAILED", safety_state="UNCONSUMED") from cleanup_error
            raise error

    def _cleanup_created_volume(self, volume_name: str) -> None:
        path = f"/volumes/{urllib.parse.quote(volume_name, safe='')}"
        status, value = self.client.request("GET", path)
        if status == 404:
            return
        if status != 200:
            raise DockerAdmissionError("VOLUME_CLEANUP_READBACK_FAILED")
        _require_owned_volume(value, volume_name, self.config.run_id, "VOLUME_CLEANUP_OWNERSHIP_UNPROVEN")
        status, _ = self.client.request("DELETE", path)
        if status not in {200, 204, 404}:
            raise DockerAdmissionError("VOLUME_CLEANUP_FAILED")
        status, _ = self.client.request("GET", path)
        if status != 404:
            raise DockerAdmissionError("VOLUME_CLEANUP_FINALITY_UNCERTAIN")

    def _cleanup_unqualified_resources(self) -> None:
        resources = self._resources
        if resources is None:
            return
        target_path = f"/containers/{urllib.parse.quote(resources.target_id, safe='')}/json"
        target_delete_path = f"/containers/{urllib.parse.quote(resources.target_id, safe='')}?force=true"
        volume_path = f"/volumes/{urllib.parse.quote(resources.volume_name, safe='')}"
        status, target = self.client.request("GET", target_path)
        if status not in {200, 404}:
            raise DockerAdmissionError("PARTIAL_TARGET_READBACK_FAILED")
        if status == 200:
            if not isinstance(target, Mapping):
                raise DockerAdmissionError("PARTIAL_TARGET_READBACK_FAILED")
            _target_inspection(target, self.config.image_id, resources.volume_name, resources.run_id, target_id=resources.target_id, target_name=resources.target_name, run_id=resources.run_id)
        volume_status, volume = self.client.request("GET", volume_path)
        if volume_status not in {200, 404}:
            raise DockerAdmissionError("PARTIAL_VOLUME_READBACK_FAILED")
        if volume_status == 200:
            _require_owned_volume(volume, resources.volume_name, resources.run_id, "PARTIAL_VOLUME_OWNERSHIP_UNPROVEN")
        if status == 200:
            status, _ = self.client.request("DELETE", target_delete_path)
            if status not in {200, 204, 404}:
                raise DockerAdmissionError("PARTIAL_TARGET_CLEANUP_FAILED")
        if volume_status == 200:
            status, _ = self.client.request("DELETE", volume_path)
            if status not in {200, 204, 404}:
                raise DockerAdmissionError("PARTIAL_VOLUME_CLEANUP_FAILED")
        target_status, _ = self.client.request("GET", target_path)
        volume_status, _ = self.client.request("GET", volume_path)
        if target_status != 404 or volume_status != 404:
            raise DockerAdmissionError("PARTIAL_CLEANUP_FINALITY_UNCERTAIN")
        self._cleanup_done = True

    def open_locator_process(self) -> Any:
        if self._resources is None or self._metadata_source is None:
            raise DockerAdmissionError("METADATA_SOURCE_NOT_ADMITTED")
        opener = getattr(self.client, "open_exec_process", None)
        if not callable(opener):
            raise DockerAdmissionError("PRODUCTION_DOCKER_ENGINE_REQUIRED")
        return opener(self._metadata_source["source_id"], ("/bin/sh", "-c", _canonical_locator_shell_wrapper()), environment=DOCKER_EXEC_ENVIRONMENT)

    def _open_restore_process(self) -> Any:
        if self._resources is None:
            raise DockerAdmissionError("PRODUCTION_DOCKER_ENGINE_REQUIRED", safety_state="CONSUMED")
        opener = getattr(self.client, "open_exec_process", None)
        if not callable(opener):
            raise DockerAdmissionError("PRODUCTION_DOCKER_ENGINE_REQUIRED", safety_state="CONSUMED")
        return opener(self._resources.target_id, RESTORE_COMMAND, environment=DOCKER_EXEC_ENVIRONMENT)

    def discover(self, epoch_ref: str, barrier_utc: str) -> DockerDiscovery:
        """Bind metadata, target, locator output and one artifact descriptor."""
        _validate_ref(epoch_ref, "epoch_ref")
        validate_barrier_utc(barrier_utc)
        self._metadata_source = self._admit_metadata_source()
        image = self.inspect_image()
        target, isolation = self.create_isolated_target(image)

        def cleanup_after_failure() -> None:
            if self._cleanup_done:
                return
            if self._resources is None:
                raise DockerAdmissionError("CLEANUP_OWNERSHIP_INVALID", safety_state="CONSUMED")
            try:
                self.cleanup(target, self._resources.volume_name)
            except RecoveryError:
                raise
            except Exception as error:
                raise DockerAdmissionError("DISCOVERY_CLEANUP_FAILED", safety_state="CONSUMED") from error

        global _ACTIVE_PRODUCTION_BACKEND
        _ACTIVE_PRODUCTION_BACKEND = self
        try:
            outcome = invoke_canonical_locator_once(barrier_utc)
        except Exception as error:
            _ACTIVE_PRODUCTION_BACKEND = None
            # A failure after locator query consumption is ambiguous and must
            # remain sticky.  Before query consumption, compensate only the
            # run-owned target and volume after readback-bound cleanup.
            if getattr(error, "safety_state", None) != "CONSUMED":
                cleanup_after_failure()
            raise
        finally:
            _ACTIVE_PRODUCTION_BACKEND = None

        if getattr(outcome, "classification", None) != "EXACTLY_ONE":
            if getattr(outcome, "query_started", False):
                raise DockerAdmissionError("LOCATOR_FINALITY_UNCERTAIN", safety_state="CONSUMED")
            cleanup_after_failure()
            raise DockerAdmissionError("LOCATOR_NOT_FOUND", safety_state="UNCONSUMED")

        execution_id = getattr(outcome, "execution_id", None)
        filename = getattr(outcome, "filename", None)
        if type(execution_id) is not int or execution_id <= 0 or not isinstance(filename, str):
            cleanup_after_failure()
            raise DockerAdmissionError("LOCATOR_OUTPUT_INVALID", safety_state="UNCONSUMED")

        descriptor: int | None = None
        try:
            filename = _validate_filename(filename)
            artifact_commitment = text_commitment("artifact-row", str(execution_id), filename)
            descriptor = open_artifact_descriptor(PRODUCTION_ARTIFACT_ROOT, filename)
            artifact = qualify_artifact_descriptor(descriptor, no_follow_verified=True)
            artifact_evidence = build_artifact_stream_evidence(artifact, artifact_commitment)
        except Exception:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            cleanup_after_failure()
            raise

        self._artifact_fd = descriptor
        self._artifact = artifact
        self._artifact_evidence = artifact_evidence
        stream_commitment = artifact_stream_evidence_commitment(artifact_evidence)
        self._operation_state = "DISCOVERY_READY"
        return DockerDiscovery(
            _docker_commitment("image-evidence", image),
            _docker_commitment("target-evidence", target),
            _docker_commitment("isolation-evidence", isolation),
            execution_id,
            filename,
            artifact_commitment,
            stream_commitment,
        )

    def _verify_proceed_bindings(self, proceed: Mapping[str, Any]) -> None:
        if not all(item is not None for item in (self._boot, self._resources, self._metadata_source, self._image, self._target, self._isolation, self._artifact, self._artifact_evidence)):
            raise DockerAdmissionError("RESTORE_BINDING_UNAVAILABLE", safety_state="CONSUMED")
        assert self._resources is not None and self._metadata_source is not None and self._image is not None and self._target is not None and self._isolation is not None and self._artifact_evidence is not None
        if self._metadata_source["source_id"] == self._resources.target_id or self._metadata_source["source_name"] in {self._resources.target_name, "/" + self._resources.target_name}:
            raise DockerAdmissionError("METADATA_RESTORE_TARGET_NOT_DISTINCT", safety_state="CONSUMED")
        expected = {
            "image_commitment": _docker_commitment("image-evidence", self._image),
            "target_commitment": _docker_commitment("target-evidence", self._target),
            "isolation_commitment": _docker_commitment("isolation-evidence", self._isolation),
            "artifact_commitment": self._artifact_evidence["artifact_commitment"],
            "artifact_stream_commitment": artifact_stream_evidence_commitment(self._artifact_evidence),
        }
        if any(proceed.get(key) != value for key, value in expected.items()):
            raise DockerAdmissionError("RESTORE_BINDING_MISMATCH", safety_state="CONSUMED")
        data, data_bytes = _transition_data_from_proceed(proceed)
        expected_id = "restore-v2-" + hashlib.sha256(_length_prefixed(("restore-transition-id.v2", data_bytes))).hexdigest()[:48]
        if proceed.get("transition_id") != expected_id or proceed.get("transition_data_commitment") != bytes_commitment("restore-ledger-transition", data_bytes):
            raise DockerAdmissionError("TRANSITION_BINDING_MISMATCH", safety_state="CONSUMED")

    def _kill_and_reap_restore_process(self, process: Any, *, deadline: float | None = None) -> None:
        """Terminate once, then wait only with bounded exit readiness."""
        end = time.monotonic() + ENGINE_IO_DEADLINE_SECONDS if deadline is None else deadline
        killed = False
        kill = getattr(process, "kill", None)
        while True:
            poll = getattr(process, "poll", None)
            ready = False
            if callable(poll):
                try:
                    ready = poll() is not None
                except Exception:
                    ready = False
            if ready:
                return
            if not killed:
                if callable(kill):
                    try:
                        kill()
                    except Exception:
                        pass
                else:
                    terminate = getattr(process, "terminate", None)
                    if callable(terminate):
                        try:
                            terminate()
                        except Exception:
                            pass
                killed = True
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise FinalityError("DOCKER_PROCESS_REAP_DEADLINE", safety_state="CONSUMED")
            wait = getattr(process, "wait", None)
            if not callable(wait):
                raise FinalityError("DOCKER_PROCESS_REAP_UNAVAILABLE", safety_state="CONSUMED")
            try:
                wait(timeout=min(0.25, remaining))
                return
            except (TimeoutError, subprocess.TimeoutExpired):
                continue
            except Exception as error:
                raise FinalityError("DOCKER_PROCESS_REAP_FAILED", safety_state="CONSUMED") from error

    def _supervise_restore_process(self, process: Any) -> tuple[ProcessFinality, int]:
        if self._artifact is None:
            raise FinalityError("ARTIFACT_NOT_QUALIFIED", safety_state="CONSUMED")
        stdout_capture, stderr_capture = BoundedCapture(), BoundedCapture()
        stdout_eof = stderr_eof = stdin_eof = False
        streamed = 0
        errors: list[Exception] = []
        deadline = time.monotonic() + ENGINE_IO_DEADLINE_SECONDS

        def drain(stream: Any, capture: BoundedCapture, which: str) -> None:
            nonlocal stdout_eof, stderr_eof
            try:
                while True:
                    chunk = stream.read(READ_CHUNK_BYTES)
                    if not chunk:
                        break
                    capture.append(bytes(chunk))
                if which == "stdout":
                    stdout_eof = True
                else:
                    stderr_eof = True
            except Exception as error:
                errors.append(error)

        def send_artifact() -> None:
            nonlocal streamed, stdin_eof
            try:
                streamed = stream_qualified_artifact(self._artifact, process.stdin)
                process.stdin.close()
                stdin_eof = True
            except Exception as error:
                errors.append(error)

        threads = [threading.Thread(target=drain, args=(process.stdout, stdout_capture, "stdout"), daemon=True), threading.Thread(target=drain, args=(process.stderr, stderr_capture, "stderr"), daemon=True), threading.Thread(target=send_artifact, daemon=True)]
        for thread in threads:
            thread.start()
        wait_error: Exception | None = None
        exit_status: int | None = None
        try:
            wait = getattr(process, "wait", None)
            if not callable(wait):
                raise FinalityError("DOCKER_PROCESS_REAP_UNAVAILABLE", safety_state="CONSUMED")
            exit_status = wait(timeout=max(0.0, deadline - time.monotonic()))
        except Exception as error:
            wait_error = error
        while time.monotonic() < deadline and any(thread.is_alive() for thread in threads):
            for thread in threads:
                thread.join(timeout=min(0.05, max(0.0, deadline - time.monotonic())))
        reader_error = getattr(process, "_reader_error", None)
        reader_done = getattr(process, "_reader_done", None)
        complete = wait_error is None and type(exit_status) is int and 0 <= exit_status <= 255 and not errors and reader_error is None and getattr(process, "_stream_eof", True) is True and stdin_eof and stdout_eof and stderr_eof and not any(thread.is_alive() for thread in threads) and (reader_done is None or reader_done.is_set())
        if not complete:
            self._kill_and_reap_restore_process(process, deadline=deadline)
            raise FinalityError("DOCKER_PROCESS_FINALITY_FAILED", safety_state="CONSUMED")
        finality = validate_process_finality(ProcessFinality(None, True, exit_status, stdin_eof, stdout_eof, stderr_eof, 0, bytes_commitment("stdout-capture", stdout_capture.snapshot()), bytes_commitment("stderr-capture", stderr_capture.snapshot())))
        return finality, streamed

    def restore(self, proceed: Mapping[str, Any], *, terminal_input_eof: bool, terminal_input_trailing_bytes: int) -> Mapping[str, Any]:
        if terminal_input_eof is not True or type(terminal_input_trailing_bytes) is not int or terminal_input_trailing_bytes < 0:
            raise FinalityError("TERMINAL_INPUT_FINALITY_INVALID", safety_state="CONSUMED")
        self._verify_proceed_bindings(proceed)
        process = self._open_restore_process()
        try:
            finality, streamed = self._supervise_restore_process(process)
        finally:
            try:
                process.close()
            except Exception:
                pass
            self._close_artifact_descriptor()
        process_evidence = {"schema": SCHEMA_PROCESS_EVIDENCE, "exec_error": finality.exec_error, "pidfd_observed": finality.pidfd_observed, "exit_status": finality.exit_status, "stdin_eof": finality.stdin_eof, "stdout_eof": finality.stdout_eof, "stderr_eof": finality.stderr_eof, "trailing_unframed_bytes": finality.trailing_unframed_bytes, "stdout_capture_commitment": finality.stdout_capture_commitment, "stderr_capture_commitment": finality.stderr_capture_commitment, "engine_readback": True}
        restore_evidence = {"schema": SCHEMA_RESTORE_EVIDENCE, "artifact_commitment": proceed["artifact_commitment"], "artifact_stream_commitment": proceed["artifact_stream_commitment"], "bytes_streamed": streamed, "stdin_same_descriptor": True, "status": "COMPLETE" if finality.success else "FAILED"}
        cleanup = self.cleanup(self._target, self._resources.volume_name) if self._target is not None and self._resources is not None else {"schema": SCHEMA_CLEANUP_EVIDENCE, "status": "FAILED"}
        success = finality.success and cleanup.get("status") == "COMPLETE"
        result = {"schema": SCHEMA_RESULT, "classification": "SUCCESS" if success else "FAILURE", "stage": "CLEANUP", "epoch_ref": proceed["epoch_ref"], "authority_ref": proceed["authority_ref"], "barrier_utc": proceed["barrier_utc"], "ssh_endpoint_commitment": self._boot["ssh_endpoint_commitment"], "epoch_commitment": proceed["epoch_commitment"], "authority_commitment": proceed["authority_commitment"], "barrier_commitment": proceed["barrier_commitment"], "runner_commitment": proceed["runner_commitment"], "bundle_commitment": proceed["bundle_commitment"], "launcher_commitment": proceed["launcher_commitment"], "agent_commitment": proceed["agent_commitment"], "image_commitment": proceed["image_commitment"], "target_commitment": proceed["target_commitment"], "isolation_commitment": proceed["isolation_commitment"], "artifact_commitment": proceed["artifact_commitment"], "artifact_stream_commitment": proceed["artifact_stream_commitment"], "transition_id": proceed["transition_id"], "pre_cas_ledger_digest": proceed["pre_cas_ledger_digest"], "transition_data_commitment": proceed["transition_data_commitment"], "consumed_record_commitment": proceed["consumed_record_commitment"], "restore_begin_commitment": proceed["restore_begin_commitment"], "process_commitment": _docker_commitment("process-evidence", process_evidence), "restore_commitment": _docker_commitment("restore-evidence", restore_evidence), "cleanup_commitment": _docker_commitment("cleanup-evidence", cleanup), "stdout_capture_commitment": finality.stdout_capture_commitment, "stderr_capture_commitment": finality.stderr_capture_commitment, "result_code": "RESTORE_SUCCEEDED" if success else "RESTORE_PROCESS_FAILED", "restore_count": 1 if success else 0, "exit_status": finality.exit_status if finality.exit_status is not None else 1, "stdin_eof": finality.stdin_eof, "stdout_eof": finality.stdout_eof, "stderr_eof": finality.stderr_eof, "trailing_unframed_bytes": finality.trailing_unframed_bytes, "terminal_input_eof": terminal_input_eof, "terminal_input_trailing_bytes": terminal_input_trailing_bytes, "cleanup_state": cleanup.get("status", "FAILED")}
        return validate_result_evidence(result)

    def cleanup(self, target_evidence: Mapping[str, Any] | None, volume_id: str) -> Mapping[str, Any]:
        if self._cleanup_done:
            raise DockerAdmissionError("CLEANUP_DUPLICATE", safety_state="CONSUMED")
        if self._resources is None or not isinstance(target_evidence, Mapping):
            raise DockerAdmissionError("CLEANUP_OWNERSHIP_INVALID", safety_state="CONSUMED")
        if volume_id != self._resources.volume_name:
            raise DockerAdmissionError("CLEANUP_OWNERSHIP_INVALID", safety_state="CONSUMED")
        checked = validate_target_evidence(target_evidence)
        if checked["container_id"] != self._resources.target_id or checked["volume_name"] != self._resources.volume_name or checked["run_owned"] is not True:
            raise DockerAdmissionError("CLEANUP_OWNERSHIP_INVALID", safety_state="CONSUMED")
        target_path = f"/containers/{urllib.parse.quote(self._resources.target_id, safe='')}/json"
        volume_path = f"/volumes/{urllib.parse.quote(self._resources.volume_name, safe='')}"
        status, current_target = self.client.request("GET", target_path)
        if status == 200:
            if not isinstance(current_target, Mapping):
                raise DockerAdmissionError("CLEANUP_TARGET_READBACK_FAILED", safety_state="CONSUMED")
            _target_inspection(current_target, self.config.image_id, self._resources.volume_name, self._resources.run_id, target_id=self._resources.target_id, target_name=self._resources.target_name, run_id=self._resources.run_id)
            status, _ = self.client.request("DELETE", f"/containers/{urllib.parse.quote(self._resources.target_id, safe='')}?force=true")
            if status not in {200, 204}:
                raise DockerAdmissionError("CLEANUP_TARGET_FAILED", safety_state="CONSUMED")
        elif status != 404:
            raise DockerAdmissionError("CLEANUP_TARGET_READBACK_FAILED", safety_state="CONSUMED")
        status, current_volume = self.client.request("GET", volume_path)
        if status == 200:
            _require_owned_volume(current_volume, self._resources.volume_name, self._resources.run_id, "CLEANUP_VOLUME_OWNERSHIP_UNPROVEN")
            status, _ = self.client.request("DELETE", volume_path)
            if status not in {200, 204, 404}:
                raise DockerAdmissionError("CLEANUP_VOLUME_FAILED", safety_state="CONSUMED")
        elif status != 404:
            raise DockerAdmissionError("CLEANUP_VOLUME_READBACK_FAILED", safety_state="CONSUMED")
        target_status, _ = self.client.request("GET", target_path)
        volume_status, _ = self.client.request("GET", volume_path)
        if target_status != 404 or volume_status != 404:
            raise DockerAdmissionError("CLEANUP_FINALITY_UNCERTAIN", safety_state="CONSUMED")
        self._cleanup_done = True
        return validate_cleanup_evidence({"schema": SCHEMA_CLEANUP_EVIDENCE, "target_id": self._resources.target_id, "volume_id": self._resources.volume_name, "run_owned": True, "prune": False, "target_deleted": target_status != 200, "volume_deleted": volume_status != 200, "status": "COMPLETE"})


CLEANUP_EVIDENCE_FIELDS = ("schema", "target_id", "volume_id", "run_owned", "prune", "target_deleted", "volume_deleted", "status")


def validate_cleanup_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or tuple(value.keys()) != CLEANUP_EVIDENCE_FIELDS or value["schema"] != SCHEMA_CLEANUP_EVIDENCE or not isinstance(value["target_id"], str) or not isinstance(value["volume_id"], str) or value["run_owned"] is not True or value["prune"] is not False or type(value["target_deleted"]) is not bool or type(value["volume_deleted"]) is not bool or value["status"] != "COMPLETE":
        raise DockerAdmissionError("CLEANUP_EVIDENCE_INVALID")
    return dict(value)


def _transition_data_from_proceed(proceed: Mapping[str, Any]) -> tuple[dict[str, Any], bytes]:
    fields = ("schema", "version", "epoch_ref", "authority_ref", "barrier_utc", "barrier_commitment", "runner_commitment", "bundle_commitment", "image_commitment", "target_commitment", "isolation_commitment", "artifact_commitment", "artifact_stream_commitment", "pre_cas_ledger_digest")
    data = {field: ("restore-ledger-transition-data.v2" if field == "schema" else 2 if field == "version" else proceed[field]) for field in fields}
    return data, canonical_json(data, terminal_lf=True)


def build_discovery_payload(epoch_ref: str, authority_ref: str, discovery: DockerDiscovery) -> dict[str, Any]:
    _validate_ref(epoch_ref, "epoch_ref")
    _validate_ref(authority_ref, "authority_ref")
    if not isinstance(discovery, DockerDiscovery) or type(discovery.execution_row_id) is not int or discovery.execution_row_id <= 0:
        raise ProtocolError("DISCOVERY_INVALID")
    if discovery.artifact_commitment is None:
        artifact_commitment = text_commitment("artifact-row", str(discovery.execution_row_id), _validate_filename(discovery.artifact_filename))
    else:
        artifact_commitment = discovery.artifact_commitment
    if discovery.artifact_stream_commitment is None:
        artifact_stream_commitment = bytes_commitment("artifact-stream", artifact_commitment.encode("ascii"))
    else:
        artifact_stream_commitment = discovery.artifact_stream_commitment
    value = {"type": "DISCOVERY", "version": SWZFRM02_VERSION, "schema": SCHEMA_WIRE, "epoch_ref": epoch_ref, "authority_ref": authority_ref, "execution_row_id": discovery.execution_row_id, "artifact_filename": _validate_filename(discovery.artifact_filename), "image_commitment": discovery.image_commitment, "target_commitment": discovery.target_commitment, "isolation_commitment": discovery.isolation_commitment, "artifact_commitment": artifact_commitment, "artifact_stream_commitment": artifact_stream_commitment}
    for field in ("image_commitment", "target_commitment", "isolation_commitment", "artifact_commitment", "artifact_stream_commitment"):
        _validate_commitment(value[field], field)
    return validate_wire_payload(value, "DISCOVERY")


def _validate_remote_proceed(boot: Mapping[str, Any], discovery: Mapping[str, Any], proceed: Mapping[str, Any]) -> None:
    value = validate_wire_payload(proceed, "PROCEED")
    for field in ("epoch_ref", "authority_ref", "barrier_utc", "epoch_commitment", "authority_commitment", "barrier_commitment", "runner_commitment", "bundle_commitment", "launcher_commitment", "agent_commitment"):
        if value[field] != boot[field]:
            raise ProtocolError("PROCEED_BOOT_MISMATCH")
    for field in ("image_commitment", "target_commitment", "isolation_commitment", "artifact_commitment", "artifact_stream_commitment"):
        if value[field] != discovery[field]:
            raise ProtocolError("PROCEED_DISCOVERY_MISMATCH")
    data, data_bytes = _transition_data_from_proceed(value)
    expected_id = "restore-v2-" + hashlib.sha256(_length_prefixed(("restore-transition-id.v2", data_bytes))).hexdigest()[:48]
    if value["transition_id"] != expected_id or value["transition_data_commitment"] != bytes_commitment("restore-ledger-transition", data_bytes):
        raise ProtocolError("PROCEED_TRANSITION_MISMATCH")


def attest_agent_descriptor(agent_fd: int, *, expected_commitment: str | None = None, fstat_fn: Callable[[int], Any] = os.fstat, read_fn: Callable[[int, int], bytes] = os.read, lseek_fn: Callable[[int, int, int], int] = os.lseek) -> AttestedAgent:
    try:
        before_stat = fstat_fn(agent_fd)
    except (OSError, ValueError, TypeError) as error:
        raise DescriptorAdmissionError("AGENT_STAT_FAILED") from error
    mode = int(before_stat.st_mode)
    if not stat.S_ISREG(mode) or int(before_stat.st_uid) != 0 or int(before_stat.st_gid) != 0 or stat.S_IMODE(mode) != 0o555 or not 1 <= int(before_stat.st_size) <= MAX_AGENT_BYTES:
        raise DescriptorAdmissionError("AGENT_ADMISSION_FAILED")
    before = _stat_identity(before_stat)
    try:
        lseek_fn(agent_fd, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = read_fn(agent_fd, READ_CHUNK_BYTES)
            if not isinstance(chunk, bytes) or len(chunk) > READ_CHUNK_BYTES:
                raise DescriptorAdmissionError("AGENT_READ_INVALID")
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_AGENT_BYTES:
                raise DescriptorAdmissionError("AGENT_SIZE_INVALID")
        after = _stat_identity(fstat_fn(agent_fd))
    except DescriptorAdmissionError:
        raise
    except (OSError, ValueError, TypeError) as error:
        raise DescriptorAdmissionError("AGENT_READ_FAILED") from error
    source = b"".join(chunks)
    commitment = bytes_commitment("recovery-agent-bytes", source)
    if before != after or total != before[2]:
        raise DescriptorAdmissionError("AGENT_SUBSTITUTED")
    if expected_commitment is not None and commitment != expected_commitment:
        raise DescriptorAdmissionError("AGENT_COMMITMENT_MISMATCH")
    return AttestedAgent(agent_fd, source, before, after, commitment)


def _park_distinct_fd(fd: int, used: set[int], *, minimum: int = 5) -> int:
    if type(fd) is not int or fd < 0:
        raise DescriptorAdmissionError("FD_INVALID")
    if fd >= minimum and fd not in used:
        used.add(fd)
        return fd
    try:
        import fcntl
        floor = max(minimum, (max(used) + 1) if used else minimum)
        parked = int(fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, floor))
    except (ImportError, OSError, ValueError) as error:
        raise DescriptorAdmissionError("FD_PARK_FAILED") from error
    if parked < floor or parked in used:
        raise DescriptorAdmissionError("FD_ALLOCATION_CONTRADICTION")
    used.add(parked)
    os.close(fd)
    return parked


def normalize_child_fds(agent_fd: int, error_fd: int, *, expected_identity: tuple[int, int, int, int, int, int] | None = None, dup2_fn: Callable[..., Any] | None = None, set_inheritable_fn: Callable[[int, bool], Any] | None = None, fstat_fn: Callable[[int], Any] = os.fstat, close_fn: Callable[[int], Any] = os.close) -> tuple[int, int]:
    if agent_fd == error_fd or agent_fd < 0 or error_fd < 0:
        raise DescriptorAdmissionError("FD_COLLISION")
    dup2 = os.dup2 if dup2_fn is None else dup2_fn
    inherit = os.set_inheritable if set_inheritable_fn is None else set_inheritable_fn
    if agent_fd == 4:
        agent_fd = _park_distinct_fd(agent_fd, set())
    if error_fd == 3:
        error_fd = _park_distinct_fd(error_fd, {agent_fd})
    if agent_fd != 3:
        dup2(agent_fd, 3, inheritable=True)
    else:
        inherit(3, True)
    if error_fd != 4:
        dup2(error_fd, 4, inheritable=False)
    else:
        inherit(4, False)
    inherit(3, True)
    inherit(4, False)
    if expected_identity is not None and _stat_identity(fstat_fn(3)) != expected_identity:
        raise DescriptorAdmissionError("AGENT_HANDOFF_MISMATCH")
    if agent_fd not in (3, 4):
        try:
            close_fn(agent_fd)
        except OSError:
            pass
    if error_fd not in (3, 4):
        try:
            close_fn(error_fd)
        except OSError:
            pass
    return 3, 4


def build_launch_plan(directory_fd: int, agent: AttestedAgent, *, error_read_fd: int = 5, error_write_fd: int = 6, pid: int | None = None, pidfd: int | None = None) -> LaunchPlan:
    if not isinstance(agent, AttestedAgent) or min(directory_fd, agent.fd, error_read_fd, error_write_fd) < 0:
        raise DescriptorAdmissionError("FD_INVALID")
    if len({agent.fd, error_read_fd, error_write_fd}) != 3:
        raise DescriptorAdmissionError("FD_COLLISION")
    if pidfd is not None and (type(pidfd) is not int or pidfd < 5 or pidfd in {agent.fd, error_read_fd, error_write_fd, directory_fd}):
        raise DescriptorAdmissionError("PIDFD_NOT_PARKED")
    _fd, _path, argv, environment, _flags = build_execveat_plan()
    return LaunchPlan(agent, directory_fd, error_read_fd, error_write_fd, pid, pidfd, argv, dict(environment))


def spawn_descriptor_agent(*, expected_agent_commitment: str | None = None, open_directory_fn: Callable[[], tuple[int, Any]] = open_recovery_directory, open_agent_fn: Callable[[int], int] | None = None, fstat_fn: Callable[[int], Any] = os.fstat, read_fn: Callable[[int, int], bytes] = os.read, lseek_fn: Callable[[int, int, int], int] = os.lseek, fork_fn: Callable[[], int] | None = None, pidfd_fn: Callable[[int], int] | None = None) -> LaunchPlan:
    if sys.platform != "linux" or not _is_commitment(expected_agent_commitment):
        raise DescriptorAdmissionError("AGENT_COMMITMENT_REQUIRED")
    directory_fd, _directory_metadata = open_directory_fn()
    agent_fd: int | None = None
    error_read_fd: int | None = None
    error_write_fd: int | None = None
    child_pid: int | None = None
    pidfd: int | None = None
    try:
        agent_fd = open_agent_fn(directory_fd) if open_agent_fn is not None else openat2(directory_fd, "recovery-agent-v1", getattr(os, "O_RDONLY", 0) | getattr(os, "O_CLOEXEC", 0), RECOVERY_RESOLVE_FLAGS)
        agent = attest_agent_descriptor(agent_fd, expected_commitment=expected_agent_commitment, fstat_fn=fstat_fn, read_fn=read_fn, lseek_fn=lseek_fn)
        error_read_fd, error_write_fd = os.pipe2(getattr(os, "O_CLOEXEC", 0))
        used: set[int] = set()
        directory_fd = _park_distinct_fd(directory_fd, used)
        agent_fd = _park_distinct_fd(agent_fd, used)
        error_read_fd = _park_distinct_fd(error_read_fd, used)
        error_write_fd = _park_distinct_fd(error_write_fd, used)
        fork = os.fork if fork_fn is None else fork_fn
        child_pid = fork()
        if child_pid == 0:
            try:
                os.close(error_read_fd)
                normalize_child_fds(agent_fd, error_write_fd, expected_identity=agent.identity_before)
                if directory_fd not in (3, 4):
                    os.close(directory_fd)
                os.closerange(5, 1 << 20)
                execveat(3, "", ("/dev/fd/3", "--agent-v1", "--protocol-v2"), {"SWZ_RECOVERY_AGENT_FD": "3"}, 0x1000)
            except OSError as error:
                write_exec_error(4, int(getattr(error, "errno", errno.EIO) or errno.EIO))
            except Exception:
                write_exec_error(4, errno.EFAULT)
            os._exit(126)
        os.close(error_write_fd)
        error_write_fd = None
        os.close(directory_fd)
        os.close(agent_fd)
        pidfd_opener = os.pidfd_open if pidfd_fn is None else pidfd_fn
        try:
            pidfd = pidfd_opener(child_pid, 0)
        except Exception as error:
            # The child has not entered the protocol.  A bounded poll/reap
            # helper is intentionally not used here: pidfd admission itself
            # failed, so no continuation is safe.
            try:
                os.kill(child_pid, signal.SIGKILL)
            except OSError:
                pass
            deadline = time.monotonic() + ENGINE_IO_DEADLINE_SECONDS
            while time.monotonic() < deadline:
                try:
                    waited, _status = os.waitpid(child_pid, os.WNOHANG)
                except OSError:
                    waited = child_pid
                if waited == child_pid:
                    break
                time.sleep(0.01)
            raise DescriptorAdmissionError("PIDFD_UNAVAILABLE") from error
        # The parent has already closed its directory/agent/write descriptors.
        # Keep the plan's descriptor fields as admitted, non-negative metadata;
        # supervision owns only error_read_fd and pidfd from this point.
        return build_launch_plan(directory_fd=0, agent=agent, error_read_fd=error_read_fd, error_write_fd=6, pid=child_pid, pidfd=pidfd)
    except Exception:
        for fd in (error_read_fd, error_write_fd, agent_fd, directory_fd, pidfd):
            if isinstance(fd, int) and fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
        raise


def _default_poller() -> Any:
    poll = getattr(select, "poll", None)
    if not callable(poll):
        raise FinalityError("PIDFD_POLL_UNAVAILABLE", safety_state="UNCONSUMED")
    return poll()


def supervise_descriptor_agent(plan: LaunchPlan, *, timeout: float = ENGINE_IO_DEADLINE_SECONDS, poll_factory: Callable[[], Any] = _default_poller, waitpid_fn: Callable[[int, int], tuple[int, int]] = os.waitpid, read_fn: Callable[[int, int], bytes] = os.read, close_fn: Callable[[int], Any] = os.close, clock_fn: Callable[[], float] = time.monotonic, kill_fn: Callable[[int, int], Any] = os.kill) -> ProcessFinality:
    if not isinstance(plan, LaunchPlan) or plan.pid is None or plan.pidfd is None:
        raise FinalityError("LAUNCH_PLAN_INVALID", safety_state="UNCONSUMED")
    poller = poll_factory()
    poll_mask = int(getattr(select, "POLLIN", 1)) | int(getattr(select, "POLLHUP", 16)) | int(getattr(select, "POLLERR", 8))
    poller.register(plan.error_read_fd, poll_mask)
    poller.register(plan.pidfd, poll_mask)
    deadline = clock_fn() + timeout
    error_bytes = bytearray()
    error_eof = False
    pidfd_ready = False
    reaped = False
    reap_attempted = False
    exit_status: int | None = None
    killed = False

    def reap_after_pidfd_ready() -> None:
        nonlocal reaped, reap_attempted, exit_status
        if not pidfd_ready:
            raise FinalityError("AGENT_REAP_BEFORE_PIDFD", safety_state="UNCONSUMED")
        if reaped or reap_attempted:
            return
        reap_attempted = True
        child, raw_status = waitpid_fn(plan.pid, 0)
        if child != plan.pid:
            raise FinalityError("AGENT_REAP_INVALID", safety_state="UNCONSUMED")
        reaped = True
        if callable(getattr(os, "WIFEXITED", None)) and os.WIFEXITED(raw_status):
            exit_status = os.WEXITSTATUS(raw_status)
        elif type(raw_status) is int and 0 <= raw_status <= 255:
            exit_status = raw_status
        else:
            exit_status = -1

    try:
        while not (error_eof and reaped):
            remaining = deadline - clock_fn()
            if remaining <= 0:
                if not reaped and not killed:
                    try:
                        kill_fn(plan.pid, getattr(signal, "SIGKILL", 9))
                    except OSError:
                        pass
                    killed = True
                raise FinalityError("AGENT_SUPERVISION_TIMEOUT", safety_state="UNCONSUMED")
            events = poller.poll(int(min(remaining, 0.25) * 1000))
            if not events:
                continue
            for fd, _event in events:
                if fd == plan.error_read_fd and not error_eof:
                    chunk = read_fn(plan.error_read_fd, 4 - len(error_bytes) if len(error_bytes) < 4 else 1)
                    if chunk:
                        error_bytes.extend(chunk)
                        if len(error_bytes) > 4:
                            raise FinalityError("EXEC_ERROR_PIPE_INVALID", safety_state="UNCONSUMED")
                    else:
                        error_eof = True
                if fd == plan.pidfd and not pidfd_ready:
                    pidfd_ready = True
                    reap_after_pidfd_ready()
        if len(error_bytes) not in {0, 4}:
            raise FinalityError("EXEC_ERROR_PIPE_INVALID", safety_state="UNCONSUMED")
        exec_error = struct.unpack(">I", bytes(error_bytes))[0] if len(error_bytes) == 4 else None
        if exec_error == 0:
            raise FinalityError("EXEC_ERROR_PIPE_INVALID", safety_state="UNCONSUMED")
        empty = bytes_commitment("stdout-capture", b"")
        empty_err = bytes_commitment("stderr-capture", b"")
        return validate_process_finality(ProcessFinality(exec_error, pidfd_ready, exit_status, True, True, True, 0, empty, empty_err))
    except Exception:
        if not reaped and pidfd_ready and not reap_attempted:
            reap_after_pidfd_ready()
        elif not reaped:
            # Poll/readiness is not available; never issue a blocking wait.
            if not pidfd_ready and not killed:
                try:
                    kill_fn(plan.pid, getattr(signal, "SIGKILL", 9))
                except OSError:
                    pass
                killed = True
            raise
        raise
    finally:
        for fd in (plan.error_read_fd, plan.pidfd):
            try:
                close_fn(fd)
            except OSError:
                pass


def read_admitted_agent_commitment() -> str:
    return _read_admitted_recovery_commitment(PRODUCTION_AGENT_COMMITMENT_PATH, label="agent_commitment")


def observe_terminal_input(input_stream: BinaryIO, *, timeout: float = ENGINE_IO_DEADLINE_SECONDS) -> tuple[bool, int]:
    trailing = 0
    caught: Exception | None = None

    def drain() -> None:
        nonlocal trailing, caught
        try:
            while True:
                chunk = input_stream.read(READ_CHUNK_BYTES)
                if not chunk:
                    return
                if not isinstance(chunk, bytes) or len(chunk) > READ_CHUNK_BYTES:
                    raise FinalityError("TERMINAL_INPUT_READ_INVALID", safety_state="CONSUMED")
                trailing += len(chunk)
                if trailing > MAX_SESSION_BYTES:
                    raise FinalityError("TERMINAL_INPUT_OVERSIZE", safety_state="CONSUMED")
        except Exception as error:
            caught = error

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    reader.join(timeout=max(0.0, timeout))
    if reader.is_alive():
        raise FinalityError("TERMINAL_INPUT_EOF_UNOBSERVED", safety_state="CONSUMED")
    if caught is not None:
        if isinstance(caught, RecoveryError):
            raise caught
        raise FinalityError("TERMINAL_INPUT_READ_FAILED", safety_state="CONSUMED") from caught
    return True, trailing


def build_production_bundle_commitment(source_bytes: bytes) -> str:
    return compute_production_commitments(source_bytes)["bundle_commitment"]


def fixed_source_commitments() -> Mapping[str, str]:
    return compute_production_commitments(pathlib.Path(__file__).read_bytes())


def _build_result_from_backend(value: Mapping[str, Any], proceed: Mapping[str, Any], boot: Mapping[str, Any], terminal_eof: bool, trailing: int) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise DockerAdmissionError("RESTORE_RESULT_INVALID", safety_state="CONSUMED")
    result = dict(value)
    if "terminal_input_eof" not in result:
        result["terminal_input_eof"] = terminal_eof
    if "terminal_input_trailing_bytes" not in result:
        result["terminal_input_trailing_bytes"] = trailing
    for key, fallback in (
        ("schema", SCHEMA_RESULT), ("classification", "FAILURE"), ("stage", "PROCESS"),
        ("epoch_ref", boot["epoch_ref"]), ("authority_ref", boot["authority_ref"]),
        ("barrier_utc", boot["barrier_utc"]), ("ssh_endpoint_commitment", boot["ssh_endpoint_commitment"]),
        ("epoch_commitment", boot["epoch_commitment"]), ("authority_commitment", boot["authority_commitment"]),
        ("barrier_commitment", boot["barrier_commitment"]), ("runner_commitment", boot["runner_commitment"]),
        ("bundle_commitment", boot["bundle_commitment"]), ("launcher_commitment", boot["launcher_commitment"]),
        ("agent_commitment", boot["agent_commitment"]), ("image_commitment", proceed["image_commitment"]),
        ("target_commitment", proceed["target_commitment"]), ("isolation_commitment", proceed["isolation_commitment"]),
        ("artifact_commitment", proceed["artifact_commitment"]), ("artifact_stream_commitment", proceed["artifact_stream_commitment"]),
        ("transition_id", proceed["transition_id"]), ("pre_cas_ledger_digest", proceed["pre_cas_ledger_digest"]),
        ("transition_data_commitment", proceed["transition_data_commitment"]), ("consumed_record_commitment", proceed["consumed_record_commitment"]),
        ("restore_begin_commitment", proceed["restore_begin_commitment"]),
    ):
        result.setdefault(key, fallback)
    return validate_result_evidence(result)


def run_agent_protocol(input_stream: BinaryIO, output_stream: BinaryIO, *, backend: Any | None = None, environment: Mapping[str, str] | None = None, argv: tuple[str, ...] = ("/dev/fd/3", "--agent-v1", "--protocol-v2"), test_mode: bool = False) -> None:
    env = dict(os.environ if environment is None else environment)
    if not test_mode:
        assert_isolated_runtime()
        if env != {"SWZ_RECOVERY_AGENT_FD": "3"}:
            raise DescriptorAdmissionError("AGENT_ENVIRONMENT_INVALID")
    validate_agent_entry(argv, env, fd3_present=True)
    boot_frame = read_frame(input_stream)
    if boot_frame is None or boot_frame.direction != DIRECTION_LOCAL_TO_REMOTE or boot_frame.message != MESSAGE_BOOT:
        raise ProtocolError("BOOT_INVALID")
    n_local = boot_frame.n_local
    session = SessionMachine(local_role=False, n_local=n_local)
    session.accept(boot_frame)
    boot = boot_frame.payload
    source = fixed_source_commitments() if test_mode else compute_production_commitments(attest_agent_descriptor(3, expected_commitment=boot["agent_commitment"]).bytes)
    if any(boot[key] != source[key] for key in ("bundle_commitment", "launcher_commitment", "agent_commitment")):
        raise LoaderIntegrityError("AGENT_COMMITMENT_MISMATCH")
    if backend is None:
        backend = ProductionDockerBackend.from_installed(boot["epoch_ref"])
    elif not test_mode:
        raise DockerAdmissionError("PRODUCTION_BACKEND_INJECTION_FORBIDDEN")
    if getattr(backend, "test_only", False) and not test_mode:
        raise DockerAdmissionError("TEST_BACKEND_FORBIDDEN")
    if not test_mode and not isinstance(backend, ProductionDockerBackend):
        raise DockerAdmissionError("PRODUCTION_BACKEND_INJECTION_FORBIDDEN")
    binder = getattr(backend, "bind_boot", None)
    if callable(binder):
        binder(boot)
    ready = {"type": "READY", "version": SWZFRM02_VERSION, "schema": SCHEMA_WIRE, "n_local": n_local.hex(), "epoch_ref": boot["epoch_ref"], "authority_ref": boot["authority_ref"], "barrier_utc": boot["barrier_utc"], "epoch_commitment": boot["epoch_commitment"], "authority_commitment": boot["authority_commitment"], "barrier_commitment": boot["barrier_commitment"], "runner_commitment": boot["runner_commitment"], "bundle_commitment": boot["bundle_commitment"], "launcher_commitment": boot["launcher_commitment"], "agent_commitment": boot["agent_commitment"]}
    ready_frame = decode_frame(encode_frame(DIRECTION_REMOTE_TO_LOCAL, MESSAGE_READY, session.next_sequence, n_local, ready))
    session.accept(ready_frame)
    write_frame(output_stream, encode_frame(DIRECTION_REMOTE_TO_LOCAL, MESSAGE_READY, ready_frame.sequence, n_local, ready))
    discovery: DockerDiscovery | None = None
    discovery_emitted = False
    proceed_received = False
    try:
        try:
            discovery = backend.discover(boot["epoch_ref"], boot["barrier_utc"])
        except RecoveryError:
            raise
        except Exception as error:
            raise DockerAdmissionError("DISCOVERY_FAILED", safety_state="UNCONSUMED") from error
        discovery_payload = build_discovery_payload(boot["epoch_ref"], boot["authority_ref"], discovery)
        discovery_frame = decode_frame(encode_frame(DIRECTION_REMOTE_TO_LOCAL, MESSAGE_DISCOVERY, session.next_sequence, n_local, discovery_payload))
        session.accept(discovery_frame)
        marker = getattr(backend, "mark_discovery_emitted", None)
        if callable(marker):
            marker()
        discovery_emitted = True
        write_frame(output_stream, encode_frame(DIRECTION_REMOTE_TO_LOCAL, MESSAGE_DISCOVERY, discovery_frame.sequence, n_local, discovery_payload))
        proceed_frame = read_frame(input_stream)
        if proceed_frame is None or proceed_frame.direction != DIRECTION_LOCAL_TO_REMOTE or proceed_frame.message != MESSAGE_PROCEED:
            raise ProtocolError("PROCEED_INVALID")
        session.accept(proceed_frame)
        record = getattr(backend, "record_proceed_boundary", None)
        if callable(record):
            record()
        proceed_received = True
        _validate_remote_proceed(boot, discovery_payload, proceed_frame.payload)
        terminal_eof, terminal_trailing = observe_terminal_input(input_stream)
        if terminal_trailing != 0:
            raise FinalityError("TERMINAL_INPUT_TRAILING_BYTES", safety_state="CONSUMED")
        if getattr(backend, "test_only", False):
            raise DockerAdmissionError("TEST_SUCCESS_NOT_OPERATIONAL", safety_state="CONSUMED")
        restore = getattr(backend, "restore", None)
        if not callable(restore):
            raise DockerAdmissionError("PRODUCTION_RESTORE_BINDING_REQUIRED", safety_state="CONSUMED")
        evidence = restore(proceed_frame.payload, terminal_input_eof=terminal_eof, terminal_input_trailing_bytes=terminal_trailing)
        if getattr(backend, "synthetic_provenance", False) and isinstance(evidence, Mapping) and evidence.get("classification") == "SUCCESS":
            raise DockerAdmissionError("SYNTHETIC_BACKEND_OPERATIONAL_SUCCESS_FORBIDDEN", safety_state="CONSUMED")
        evidence = _build_result_from_backend(evidence, proceed_frame.payload, boot, terminal_eof, terminal_trailing)
        result_value = {"type": "RESULT", "version": SWZFRM02_VERSION, "schema": SCHEMA_WIRE, "classification": evidence["classification"], "result_evidence": evidence, "result_commitment": result_commitment(evidence)}
        result_frame = decode_frame(encode_frame(DIRECTION_REMOTE_TO_LOCAL, MESSAGE_RESULT, session.next_sequence, n_local, result_value))
        session.accept(result_frame)
        # This is the first remote frame after PROCEED, and it is reachable
        # only after observe_terminal_input has seen the controller EOF.
        write_frame(output_stream, encode_frame(DIRECTION_REMOTE_TO_LOCAL, MESSAGE_RESULT, result_frame.sequence, n_local, result_value))
    except Exception:
        if discovery is not None and not discovery_emitted and not proceed_received and isinstance(backend, ProductionDockerBackend):
            # Discovery may have created run-owned resources, but a failed
            # discovery query is never allowed to continue into restore.
            try:
                if backend._resources is not None and backend._target is not None:
                    backend.cleanup(backend._target, backend._resources.volume_name)
            except Exception as error:
                raise DockerAdmissionError("CLEANUP_FINALITY_UNCERTAIN", safety_state="CONSUMED") from error
        raise


def _fd_present(fd: int) -> bool:
    try:
        os.fstat(fd)
        return True
    except OSError:
        return False


def run_supervisor(argv: list[str]) -> None:
    assert_isolated_runtime()
    validate_supervisor_entry(argv, dict(os.environ))
    expected = read_admitted_agent_commitment()
    plan = spawn_descriptor_agent(expected_agent_commitment=expected)
    finality = supervise_descriptor_agent(plan)
    if not finality.success:
        raise DescriptorAdmissionError("AGENT_PROCESS_FAILED")


def agent_main(argv: list[str] | None = None) -> int:
    assert_isolated_runtime()
    values = list(sys.argv if argv is None else argv)
    mode = classify_dispatch(values, dict(os.environ), fd3_present=_fd_present(3))
    if mode == "agent":
        run_agent_protocol(sys.stdin.buffer, sys.stdout.buffer)
        return 0
    if mode == "supervisor":
        run_supervisor(values)
        return 0
    raise DescriptorAdmissionError("DISPATCH_INVALID")


if __name__ == "__main__":
    agent_main()
