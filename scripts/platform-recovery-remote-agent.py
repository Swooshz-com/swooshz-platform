#!/usr/bin/python3 -I
"""Repository-only recovery agent for the Web-accepted G2 contract.

The production role is a fixed installed script.  It accepts only the
descriptor-qualified agent argv and the SWZFRM02 protocol.  All test seams are
explicit and fail closed before they can claim operational success.
"""

from __future__ import annotations

import base64
import builtins
import ctypes
import dataclasses
import datetime
import errno
import hashlib
import json
import os
import pathlib
import queue
import re
import socket
import stat
import struct
import sys
import time
import types
import urllib.parse
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
    "target_commitment", "isolation_commitment",
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
WIRE_MESSAGE_TYPES = frozenset(WIRE_FIELDS)
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


def canonical_json(value: Any, *, limit: int = MAX_CONTROL_PAYLOAD_BYTES, terminal_lf: bool = False) -> bytes:
    _reject_json_values(value)
    try:
        text = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        payload = text.encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ProtocolError("CANONICAL_JSON_INVALID") from error
    if terminal_lf:
        payload += b"\n"
    if len(payload) > limit:
        raise ProtocolError("CANONICAL_JSON_OVERSIZE")
    return payload


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
        text = payload.decode("utf-8", "strict")
        value = json.loads(
            text,
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
    canonical = (
        f"{parsed.year:04d}-{parsed.month:02d}-{parsed.day:02d}"
        f"T{parsed.hour:02d}:{parsed.minute:02d}:{parsed.second:02d}"
        f".{parsed.microsecond:06d}Z"
    )
    if canonical != value or parsed.year < 1970:
        raise ProtocolError("BARRIER_INVALID")
    return value


def _validate_filename(value: Any) -> str:
    if not isinstance(value, str):
        raise ProtocolError("FILENAME_INVALID")
    encoded = value.encode("utf-8", "strict")
    if (
        not encoded
        or len(encoded) > MAX_FILENAME_BYTES
        or value in (".", "..")
        or "/" in value
        or "\\" in value
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
            raw = bytes.fromhex(value)
        except ValueError as error:
            raise ProtocolError("N_LOCAL_INVALID") from error
        if len(raw) != 32 or n_local is not None and raw != n_local:
            raise ProtocolError("N_LOCAL_INVALID")
    elif name == "barrier_utc":
        validate_barrier_utc(value)
    elif name.endswith("_commitment") or name.endswith("_digest"):
        _validate_commitment(value, name)
    elif name == "ssh_endpoint_commitment":
        _validate_commitment(value, name)
    elif name == "execution_row_id":
        if type(value) is not int or not 0 < value <= 0x7FFFFFFFFFFFFFFF:
            raise ProtocolError("DISCOVERY_INVALID")
    elif name == "artifact_filename":
        _validate_filename(value)
    elif name == "classification":
        if value not in RESULT_CLASSIFICATIONS:
            raise ProtocolError("CLASSIFICATION_INVALID")
    elif name == "result_evidence":
        if not isinstance(value, dict):
            raise ProtocolError("RESULT_EVIDENCE_INVALID")
    elif name == "evidence":
        if not isinstance(value, dict):
            raise ProtocolError("ABORT_EVIDENCE_INVALID")
    else:
        if name not in {"type", "version", "schema"} and value is None:
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
    if expected_type == "ABORT":
        if result["stage"] not in ABORT_STAGES or result["direction"] not in DIRECTION_NAMES.values():
            raise ProtocolError("ABORT_INVALID")
    if expected_type == "READY" and n_local is None:
        raise ProtocolError("READY_NONCE_MISSING")
    return result


def encode_frame(
    direction: int,
    message: int,
    sequence: int,
    n_local: bytes,
    payload: Mapping[str, Any],
) -> bytes:
    if direction not in DIRECTION_NAMES or message not in MESSAGE_NAMES:
        raise ProtocolError("FRAME_HEADER_INVALID")
    if type(sequence) is not int or not 0 <= sequence <= 0xFFFFFFFFFFFFFFFF:
        raise ProtocolError("FRAME_SEQUENCE_INVALID")
    if not isinstance(n_local, bytes) or len(n_local) != 32:
        raise ProtocolError("N_LOCAL_INVALID")
    expected_type = MESSAGE_NAMES[message]
    value = validate_wire_payload(payload, expected_type, n_local=n_local if expected_type in {"BOOT", "READY"} else None)
    payload_bytes = canonical_json(value)
    if len(payload_bytes) > MAX_CONTROL_PAYLOAD_BYTES or FRAME_HEADER_BYTES + len(payload_bytes) > MAX_FRAME_BYTES:
        raise ProtocolError("FRAME_LIMIT_EXCEEDED")
    return SWZFRM02_HEADER.pack(
        SWZFRM02_MAGIC, SWZFRM02_VERSION, direction, message, SWZFRM02_FLAGS,
        sequence, n_local, len(payload_bytes)
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
        magic, version, direction, message, flags, sequence, n_local, payload_length = SWZFRM02_HEADER.unpack(
            frame[:FRAME_HEADER_BYTES]
        )
    except struct.error as error:
        raise ProtocolError("FRAME_HEADER_INVALID") from error
    if (
        magic != SWZFRM02_MAGIC
        or version != SWZFRM02_VERSION
        or direction not in DIRECTION_NAMES
        or message not in MESSAGE_NAMES
        or flags != SWZFRM02_FLAGS
        or payload_length > MAX_CONTROL_PAYLOAD_BYTES
        or payload_length != len(frame) - FRAME_HEADER_BYTES
        or len(frame) > MAX_FRAME_BYTES
    ):
        raise ProtocolError("FRAME_HEADER_INVALID")
    payload = parse_wire_json(frame[FRAME_HEADER_BYTES:])
    expected_type = MESSAGE_NAMES[message]
    validate_wire_payload(payload, expected_type, n_local=n_local if expected_type in {"BOOT", "READY"} else None)
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
    magic, version, direction, message, flags, sequence, n_local, payload_length = SWZFRM02_HEADER.unpack(header)
    if (
        magic != SWZFRM02_MAGIC or version != SWZFRM02_VERSION
        or direction not in DIRECTION_NAMES or message not in MESSAGE_NAMES
        or flags != SWZFRM02_FLAGS or payload_length > MAX_CONTROL_PAYLOAD_BYTES
        or payload_length + FRAME_HEADER_BYTES > MAX_FRAME_BYTES
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
    """Strict one-session, one-binding state machine with no retry path."""

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
        if self.local_role:
            table = {
                "START": (DIRECTION_LOCAL_TO_REMOTE, (MESSAGE_BOOT,)),
                "BOOT": (DIRECTION_REMOTE_TO_LOCAL, (MESSAGE_READY, MESSAGE_ABORT)),
                "READY": (DIRECTION_REMOTE_TO_LOCAL, (MESSAGE_DISCOVERY, MESSAGE_ABORT)),
                "DISCOVERY": (DIRECTION_LOCAL_TO_REMOTE, (MESSAGE_PROCEED, MESSAGE_ABORT)),
                "PROCEED": (DIRECTION_REMOTE_TO_LOCAL, (MESSAGE_RESULT, MESSAGE_ABORT)),
            }
        else:
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
        if self.frame_count >= MAX_SESSION_FRAMES or self.total_bytes + FRAME_HEADER_BYTES > MAX_SESSION_BYTES:
            raise ProtocolError("SESSION_LIMIT_EXCEEDED")
        expected = MESSAGE_NAMES[frame.message]
        validate_wire_payload(frame.payload, expected, n_local=self.n_local if expected in {"BOOT", "READY"} else None)
        self.next_sequence += 1
        self.frame_count += 1
        self.total_bytes += FRAME_HEADER_BYTES + len(canonical_json(frame.payload))
        if frame.message == MESSAGE_ABORT:
            self.terminal = True
            self.state = "TERMINAL"
        elif frame.message == MESSAGE_BOOT:
            self.state = "BOOT"
        elif frame.message == MESSAGE_READY:
            self.state = "READY"
        elif frame.message == MESSAGE_DISCOVERY:
            self.state = "DISCOVERY"
        elif frame.message == MESSAGE_PROCEED:
            self.state = "PROCEED"
        elif frame.message == MESSAGE_RESULT:
            self.terminal = True
            self.state = "TERMINAL"

    def mark_terminal(self) -> None:
        self.terminal = True
        self.state = "TERMINAL"


@dataclass(frozen=True)
class RuntimeAdmission:
    mode: str
    argv: tuple[str, ...]
    environment: Mapping[str, str]


def assert_isolated_runtime(flags: Any | None = None) -> None:
    flags = sys.flags if flags is None else flags
    if (
        getattr(flags, "isolated", None) != 1
        or getattr(flags, "ignore_environment", None) != 1
        or getattr(flags, "no_user_site", None) != 1
        or getattr(flags, "safe_path", None) is not True
    ):
        raise RecoveryError("ISOLATED_RUNTIME_REQUIRED")


def classify_dispatch(argv: list[str] | tuple[str, ...], environment: Mapping[str, str], *, fd3_present: bool) -> str:
    if not isinstance(argv, (list, tuple)) or not argv or not all(isinstance(item, str) for item in argv):
        raise DescriptorAdmissionError("ARGV_INVALID")
    if tuple(argv[1:]) == ("--agent-v1", "--protocol-v2"):
        if not fd3_present or environment.get("SWZ_RECOVERY_AGENT_FD") != "3":
            raise DescriptorAdmissionError("AGENT_DESCRIPTOR_REQUIRED")
        return "agent"
    if tuple(argv[1:]) == ("--protocol-v2",):
        if fd3_present or environment.get("SWZ_RECOVERY_AGENT_FD") is not None:
            raise DescriptorAdmissionError("SUPERVISOR_DESCRIPTOR_CONTRADICTION")
        if environment.get("SSH_ORIGINAL_COMMAND", "") != "":
            raise DescriptorAdmissionError("REMOTE_COMMAND_FORBIDDEN")
        return "supervisor"
    raise DescriptorAdmissionError("ARGV_INVALID")


def validate_supervisor_entry(argv: list[str] | tuple[str, ...], environment: Mapping[str, str]) -> RuntimeAdmission:
    mode = classify_dispatch(argv, environment, fd3_present=False)
    return RuntimeAdmission(mode, tuple(argv), dict(environment))


def validate_agent_entry(argv: list[str] | tuple[str, ...], environment: Mapping[str, str], *, fd3_present: bool = True) -> RuntimeAdmission:
    mode = classify_dispatch(argv, environment, fd3_present=fd3_present)
    if mode != "agent" or tuple(argv) != ("/dev/fd/3", "--agent-v1", "--protocol-v2"):
        raise DescriptorAdmissionError("AGENT_ARGV_INVALID")
    return RuntimeAdmission(mode, tuple(argv), dict(environment))


def _linux_syscall_number(name: str) -> int:
    values = {"openat2": 437, "execveat": 322}
    if sys.platform != "linux" or name not in values:
        raise DescriptorAdmissionError("LINUX_PRIMITIVE_UNAVAILABLE")
    return values[name]


def openat2(dirfd: int, path: str, flags: int, resolve: int) -> int:
    if sys.platform != "linux" or type(dirfd) is not int or type(path) is not str:
        raise DescriptorAdmissionError("OPENAT2_UNAVAILABLE")
    if "\x00" in path or not path:
        raise DescriptorAdmissionError("OPENAT2_PATH_INVALID")
    class OpenHow(ctypes.Structure):
        _fields_ = [
            ("flags", ctypes.c_ulonglong),
            ("mode", ctypes.c_ulonglong),
            ("resolve", ctypes.c_ulonglong),
        ]
    how = OpenHow(flags, 0, resolve)
    libc = ctypes.CDLL(None, use_errno=True)
    syscall = libc.syscall
    syscall.restype = ctypes.c_long
    fd = syscall(
        _linux_syscall_number("openat2"),
        ctypes.c_int(dirfd),
        ctypes.c_char_p(path.encode("ascii", "strict")),
        ctypes.byref(how),
        ctypes.sizeof(how),
    )
    if fd < 0:
        error_number = ctypes.get_errno()
        raise DescriptorAdmissionError(f"OPENAT2_FAILED_{error_number}")
    return int(fd)


O_PATH = getattr(os, "O_PATH", 0o10000000)
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0o2000000)
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0o200000)
RESOLVE_NO_XDEV = 0x01
RESOLVE_NO_MAGICLINKS = 0x02
RESOLVE_NO_SYMLINKS = 0x04
RESOLVE_BENEATH = 0x08
RECOVERY_RESOLVE_FLAGS = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV
RECOVERY_DIR_FLAGS = O_PATH | O_DIRECTORY | O_CLOEXEC
AGENT_OPEN_FLAGS = getattr(os, "O_RDONLY", 0) | O_CLOEXEC


def _stat_identity(value: Any) -> tuple[int, int, int, int, int, int]:
    return (
        int(value.st_dev), int(value.st_ino), int(value.st_size),
        int(value.st_mode), int(value.st_uid), int(value.st_gid),
    )


def _require_mode(value: Any, expected_mode: int, label: str) -> None:
    mode = stat.S_IMODE(int(value.st_mode))
    if mode != expected_mode or int(value.st_mode) & (stat.S_ISUID | stat.S_ISGID):
        raise DescriptorAdmissionError(f"{label}_MODE_INVALID")


def admit_recovery_directory(directory_fd: int, *, fstat_fn: Callable[[int], Any] = os.fstat) -> Any:
    metadata = fstat_fn(directory_fd)
    if not stat.S_ISDIR(int(metadata.st_mode)) or int(metadata.st_uid) != 0 or int(metadata.st_gid) != 0:
        raise DescriptorAdmissionError("RECOVERY_DIRECTORY_OWNER_INVALID")
    _require_mode(metadata, 0o755, "RECOVERY_DIRECTORY")
    return metadata


def open_recovery_directory(*, open_root_fn: Callable[..., int] | None = None, openat2_fn: Callable[..., int] = openat2, fstat_fn: Callable[[int], Any] = os.fstat) -> tuple[int, Any]:
    opener = os.open if open_root_fn is None else open_root_fn
    root_fd = opener("/", RECOVERY_DIR_FLAGS)
    try:
        directory_fd = openat2_fn(root_fd, "opt/swooshz/recovery", RECOVERY_DIR_FLAGS, RECOVERY_RESOLVE_FLAGS)
        metadata = admit_recovery_directory(directory_fd, fstat_fn=fstat_fn)
    except Exception:
        try:
            os.close(root_fd)
        except OSError:
            pass
        raise
    try:
        os.close(root_fd)
    except OSError:
        pass
    return directory_fd, metadata


@dataclass(frozen=True)
class AttestedAgent:
    fd: int
    bytes: bytes
    identity_before: tuple[int, int, int, int, int, int]
    identity_after: tuple[int, int, int, int, int, int]
    commitment: str


def attest_agent_descriptor(
    agent_fd: int,
    *,
    fstat_fn: Callable[[int], Any] = os.fstat,
    read_fn: Callable[[int, int], bytes] = os.read,
    lseek_fn: Callable[[int, int, int], int] = os.lseek,
) -> AttestedAgent:
    before_stat = fstat_fn(agent_fd)
    if not stat.S_ISREG(int(before_stat.st_mode)) or int(before_stat.st_uid) != 0 or int(before_stat.st_gid) != 0:
        raise DescriptorAdmissionError("AGENT_OWNER_INVALID")
    _require_mode(before_stat, 0o555, "AGENT")
    if not 1 <= int(before_stat.st_size) <= MAX_AGENT_BYTES:
        raise DescriptorAdmissionError("AGENT_SIZE_INVALID")
    before = _stat_identity(before_stat)
    try:
        lseek_fn(agent_fd, 0, os.SEEK_SET)
    except OSError as error:
        raise DescriptorAdmissionError("AGENT_SEEK_FAILED") from error
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = read_fn(agent_fd, READ_CHUNK_BYTES)
        if not isinstance(chunk, bytes) or len(chunk) > READ_CHUNK_BYTES:
            raise DescriptorAdmissionError("AGENT_READ_INVALID")
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_AGENT_BYTES:
            raise DescriptorAdmissionError("AGENT_SIZE_INVALID")
        chunks.append(chunk)
    after_stat = fstat_fn(agent_fd)
    after = _stat_identity(after_stat)
    if after != before or total != before[2]:
        raise DescriptorAdmissionError("AGENT_SUBSTITUTED")
    source = b"".join(chunks)
    return AttestedAgent(agent_fd, source, before, after, bytes_commitment("recovery-agent-bytes", source))


def park_fd(fd: int, *, minimum: int = 5, dup_fn: Callable[..., int] | None = None) -> int:
    if type(fd) is not int or fd < 0:
        raise DescriptorAdmissionError("FD_INVALID")
    if fd >= minimum:
        return fd
    if dup_fn is not None:
        return int(dup_fn(fd, minimum))
    import fcntl
    return int(fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, minimum))


def normalize_child_fds(
    agent_fd: int,
    error_fd: int,
    *,
    dup2_fn: Callable[..., Any] | None = None,
    set_inheritable_fn: Callable[[int, bool], Any] | None = None,
    close_fn: Callable[[int], Any] = os.close,
) -> tuple[int, int]:
    if agent_fd == error_fd or agent_fd < 0 or error_fd < 0:
        raise DescriptorAdmissionError("FD_COLLISION")
    dup2 = os.dup2 if dup2_fn is None else dup2_fn
    set_inheritable = os.set_inheritable if set_inheritable_fn is None else set_inheritable_fn
    sources = {agent_fd, error_fd}
    if 3 in sources or 4 in sources:
        import fcntl
        parked: dict[int, int] = {}
        for value in sources:
            if value in (3, 4):
                parked[value] = int(fcntl.fcntl(value, fcntl.F_DUPFD_CLOEXEC, 5))
        agent_fd = parked.get(agent_fd, agent_fd)
        error_fd = parked.get(error_fd, error_fd)
    dup2(agent_fd, 3, inheritable=True)
    dup2(error_fd, 4, inheritable=False)
    set_inheritable(3, True)
    set_inheritable(4, False)
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


def build_execveat_plan() -> tuple[int, str, tuple[str, ...], Mapping[str, str], int]:
    return (
        3,
        "",
        ("/dev/fd/3", "--agent-v1", "--protocol-v2"),
        {"SWZ_RECOVERY_AGENT_FD": "3"},
        0x1000,
    )


def execveat(
    agent_fd: int,
    argv: tuple[str, ...],
    environment: Mapping[str, str],
    *,
    syscall_fn: Callable[..., int] | None = None,
) -> None:
    if sys.platform != "linux":
        raise DescriptorAdmissionError("EXECVEAT_UNAVAILABLE")
    if agent_fd != 3 or argv != ("/dev/fd/3", "--agent-v1", "--protocol-v2") or dict(environment) != {"SWZ_RECOVERY_AGENT_FD": "3"}:
        raise DescriptorAdmissionError("EXECVEAT_ARGUMENT_INVALID")
    raw_argv = (ctypes.c_char_p * (len(argv) + 1))(*[item.encode("ascii") for item in argv], None)
    raw_env = (ctypes.c_char_p * 2)(b"SWZ_RECOVERY_AGENT_FD=3", None)
    call = syscall_fn or ctypes.CDLL(None, use_errno=True).syscall
    call.restype = ctypes.c_long
    result = call(_linux_syscall_number("execveat"), ctypes.c_int(agent_fd), ctypes.c_char_p(b""), raw_argv, raw_env, ctypes.c_int(0x1000))
    if result < 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, "execveat")


def write_exec_error(error_fd: int, error_number: int, *, write_fn: Callable[[int, bytes], int] = os.write) -> None:
    if type(error_number) is not int or not 0 <= error_number <= 0xFFFFFFFF:
        raise DescriptorAdmissionError("EXEC_ERROR_INVALID")
    payload = struct.pack(">I", error_number)
    offset = 0
    while offset < len(payload):
        written = write_fn(error_fd, payload[offset:])
        if type(written) is not int or written <= 0:
            raise DescriptorAdmissionError("EXEC_ERROR_PIPE_FAILED")
        offset += written


@dataclass(frozen=True)
class LaunchPlan:
    agent: AttestedAgent
    directory_fd: int
    error_read_fd: int
    error_write_fd: int
    pid: int | None
    pidfd: int | None
    execveat_argv: tuple[str, ...]
    execveat_environment: Mapping[str, str]


def build_launch_plan(
    directory_fd: int,
    agent: AttestedAgent,
    *,
    error_read_fd: int = 5,
    error_write_fd: int = 6,
    pid: int | None = None,
    pidfd: int | None = None,
) -> LaunchPlan:
    if directory_fd < 0 or agent.fd < 0:
        raise DescriptorAdmissionError("FD_INVALID")
    if agent.fd < 5 or error_read_fd < 5 or error_write_fd < 5:
        raise DescriptorAdmissionError("FD_NOT_PARKED")
    if len({agent.fd, error_read_fd, error_write_fd}) != 3:
        raise DescriptorAdmissionError("FD_COLLISION")
    _, _, argv, environment, _ = build_execveat_plan()
    return LaunchPlan(agent, directory_fd, error_read_fd, error_write_fd, pid, pidfd, argv, environment)


def spawn_descriptor_agent(
    *,
    open_directory_fn: Callable[[], tuple[int, Any]] = open_recovery_directory,
    open_agent_fn: Callable[[int], int] | None = None,
    fstat_fn: Callable[[int], Any] = os.fstat,
    read_fn: Callable[[int, int], bytes] = os.read,
    fork_fn: Callable[[], int] | None = None,
    pidfd_fn: Callable[[int], int] | None = None,
) -> LaunchPlan:
    directory_fd, _ = open_directory_fn()
    opener = openat2 if open_agent_fn is None else open_agent_fn
    agent_fd = opener(directory_fd, "recovery-agent-v1", AGENT_OPEN_FLAGS, RECOVERY_RESOLVE_FLAGS) if open_agent_fn is None else opener(directory_fd)
    agent = attest_agent_descriptor(agent_fd, fstat_fn=fstat_fn, read_fn=read_fn)
    error_read_fd, error_write_fd = os.pipe2(O_CLOEXEC)
    agent_fd = park_fd(agent.fd)
    error_read_fd = park_fd(error_read_fd)
    error_write_fd = park_fd(error_write_fd)
    pid = (os.fork if fork_fn is None else fork_fn)()
    if pid == 0:
        try:
            os.close(error_read_fd)
            normalize_child_fds(agent_fd, error_write_fd)
            execveat(3, build_execveat_plan()[2], build_execveat_plan()[3])
        except OSError as error:
            write_exec_error(4, int(getattr(error, "errno", errno.EIO) or errno.EIO))
            os._exit(126)
        except Exception:
            write_exec_error(4, errno.EFAULT)
            os._exit(126)
        raise AssertionError("child did not exit")
    pidfd_opener = os.pidfd_open if pidfd_fn is None else pidfd_fn
    try:
        pidfd = pidfd_opener(pid, 0)
    except Exception as error:
        raise DescriptorAdmissionError("PIDFD_UNAVAILABLE") from error
    try:
        os.close(error_write_fd)
        os.close(directory_fd)
        os.close(agent_fd)
    except OSError:
        pass
    return build_launch_plan(directory_fd, agent, error_read_fd=error_read_fd, error_write_fd=error_write_fd, pid=pid, pidfd=pidfd)


class BoundedCapture:
    def __init__(self, limit: int = MAX_CAPTURE_BYTES) -> None:
        if type(limit) is not int or limit <= 0:
            raise ValueError("capture limit")
        self.limit = limit
        self.data = bytearray()
        self.overflow = False

    def append(self, chunk: bytes) -> None:
        if not isinstance(chunk, bytes):
            raise FinalityError("CAPTURE_INVALID")
        if len(self.data) + len(chunk) > self.limit:
            self.overflow = True
            raise FinalityError("CAPTURE_OVERFLOW")
        self.data.extend(chunk)

    def snapshot(self) -> bytes:
        return bytes(self.data)


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
            self.exec_error is None
            and self.pidfd_observed
            and self.exit_status == 0
            and self.stdin_eof
            and self.stdout_eof
            and self.stderr_eof
            and self.trailing_unframed_bytes == 0
        )


def validate_process_finality(value: ProcessFinality) -> ProcessFinality:
    if not isinstance(value, ProcessFinality) or value.trailing_unframed_bytes < 0:
        raise FinalityError("PROCESS_FINALITY_INVALID")
    if value.success and (not _is_commitment(value.stdout_capture_commitment) or not _is_commitment(value.stderr_capture_commitment)):
        raise FinalityError("PROCESS_FINALITY_INVALID")
    return value


@dataclass(frozen=True)
class ArtifactIdentity:
    dev: int
    ino: int
    size: int
    mode: int
    uid: int
    gid: int


@dataclass(frozen=True)
class QualifiedArtifact:
    fd: int
    identity_before: ArtifactIdentity
    identity_after: ArtifactIdentity
    bytes_read: int
    stream_sha256: str
    reopen_count: int
    reselection_count: int
    stdin_same_descriptor: bool


def _artifact_identity(value: Any) -> ArtifactIdentity:
    return ArtifactIdentity(int(value.st_dev), int(value.st_ino), int(value.st_size), int(value.st_mode), int(value.st_uid), int(value.st_gid))


def qualify_artifact_descriptor(
    fd: int,
    *,
    fstat_fn: Callable[[int], Any] = os.fstat,
    read_fn: Callable[[int, int], bytes] = os.read,
    lseek_fn: Callable[[int, int, int], int] = os.lseek,
) -> QualifiedArtifact:
    before = _artifact_identity(fstat_fn(fd))
    if not stat.S_ISREG(before.mode) or before.size < 1 or before.size > 64 * 1024 * 1024:
        raise DescriptorAdmissionError("ARTIFACT_ADMISSION_FAILED")
    try:
        lseek_fn(fd, 0, os.SEEK_SET)
    except OSError as error:
        raise DescriptorAdmissionError("ARTIFACT_SEEK_FAILED") from error
    digest = hashlib.sha256()
    count = 0
    while True:
        chunk = read_fn(fd, READ_CHUNK_BYTES)
        if not isinstance(chunk, bytes) or len(chunk) > READ_CHUNK_BYTES:
            raise DescriptorAdmissionError("ARTIFACT_READ_FAILED")
        if not chunk:
            break
        count += len(chunk)
        digest.update(chunk)
        if count > before.size:
            raise DescriptorAdmissionError("ARTIFACT_SIZE_CHANGED")
    after = _artifact_identity(fstat_fn(fd))
    if before != after or count != before.size:
        raise DescriptorAdmissionError("ARTIFACT_SUBSTITUTED")
    return QualifiedArtifact(fd, before, after, count, digest.hexdigest(), 0, 0, True)


def stream_qualified_artifact(
    artifact: QualifiedArtifact,
    output: BinaryIO,
    *,
    fstat_fn: Callable[[int], Any] = os.fstat,
    read_fn: Callable[[int, int], bytes] = os.read,
    lseek_fn: Callable[[int, int, int], int] = os.lseek,
) -> int:
    if artifact.reopen_count != 0 or artifact.reselection_count != 0 or not artifact.stdin_same_descriptor:
        raise DescriptorAdmissionError("ARTIFACT_CONTINUITY_INVALID")
    if _artifact_identity(fstat_fn(artifact.fd)) != artifact.identity_after:
        raise DescriptorAdmissionError("ARTIFACT_SUBSTITUTED")
    lseek_fn(artifact.fd, 0, os.SEEK_SET)
    total = 0
    digest = hashlib.sha256()
    while True:
        chunk = read_fn(artifact.fd, READ_CHUNK_BYTES)
        if not chunk:
            break
        _write_all(output, chunk)
        total += len(chunk)
        digest.update(chunk)
    if total != artifact.bytes_read:
        raise DescriptorAdmissionError("ARTIFACT_CONTINUITY_INVALID")
    if _artifact_identity(fstat_fn(artifact.fd)) != artifact.identity_after:
        raise DescriptorAdmissionError("ARTIFACT_SUBSTITUTED")
    if digest.hexdigest() != artifact.stream_sha256:
        raise DescriptorAdmissionError("ARTIFACT_CONTENT_CHANGED")
    return total


ARTIFACT_STREAM_FIELDS = (
    "schema", "artifact_commitment", "fd_before", "fd_after", "bytes_read",
    "stream_sha256", "read_chunk_bytes", "no_follow", "fstat_equal",
    "reopen_count", "reselection_count", "stdin_same_descriptor",
)
ARTIFACT_IDENTITY_FIELDS = ("dev", "ino", "size", "mode", "uid", "gid")


def _artifact_identity_object(identity: ArtifactIdentity) -> dict[str, int]:
    value = {
        "dev": identity.dev,
        "ino": identity.ino,
        "size": identity.size,
        "mode": identity.mode,
        "uid": identity.uid,
        "gid": identity.gid,
    }
    if tuple(value.keys()) != ARTIFACT_IDENTITY_FIELDS:
        raise DescriptorAdmissionError("ARTIFACT_IDENTITY_FIELDS_INVALID")
    return value


def build_artifact_stream_evidence(artifact: QualifiedArtifact, artifact_commitment: str) -> dict[str, Any]:
    if not isinstance(artifact, QualifiedArtifact) or not _is_commitment(artifact_commitment):
        raise DescriptorAdmissionError("ARTIFACT_EVIDENCE_INVALID")
    value = {
        "schema": SCHEMA_ARTIFACT_STREAM,
        "artifact_commitment": artifact_commitment,
        "fd_before": _artifact_identity_object(artifact.identity_before),
        "fd_after": _artifact_identity_object(artifact.identity_after),
        "bytes_read": artifact.bytes_read,
        "stream_sha256": artifact.stream_sha256,
        "read_chunk_bytes": READ_CHUNK_BYTES,
        "no_follow": True,
        "fstat_equal": artifact.identity_before == artifact.identity_after,
        "reopen_count": artifact.reopen_count,
        "reselection_count": artifact.reselection_count,
        "stdin_same_descriptor": artifact.stdin_same_descriptor,
    }
    if tuple(value.keys()) != ARTIFACT_STREAM_FIELDS or not value["fstat_equal"] or value["reopen_count"] != 0 or value["reselection_count"] != 0 or value["stdin_same_descriptor"] is not True:
        raise DescriptorAdmissionError("ARTIFACT_EVIDENCE_INVALID")
    if type(value["bytes_read"]) is not int or value["bytes_read"] < 1 or not re.fullmatch(r"[0-9a-f]{64}", value["stream_sha256"]):
        raise DescriptorAdmissionError("ARTIFACT_EVIDENCE_INVALID")
    return value


def validate_artifact_stream_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or tuple(value.keys()) != ARTIFACT_STREAM_FIELDS:
        raise DescriptorAdmissionError("ARTIFACT_EVIDENCE_INVALID")
    if value["schema"] != SCHEMA_ARTIFACT_STREAM or value["no_follow"] is not True or value["fstat_equal"] is not True:
        raise DescriptorAdmissionError("ARTIFACT_EVIDENCE_INVALID")
    if value["read_chunk_bytes"] != READ_CHUNK_BYTES or value["reopen_count"] != 0 or value["reselection_count"] != 0 or value["stdin_same_descriptor"] is not True:
        raise DescriptorAdmissionError("ARTIFACT_EVIDENCE_INVALID")
    _validate_commitment(value["artifact_commitment"], "artifact_commitment")
    for identity in (value["fd_before"], value["fd_after"]):
        if not isinstance(identity, Mapping) or tuple(identity.keys()) != ARTIFACT_IDENTITY_FIELDS:
            raise DescriptorAdmissionError("ARTIFACT_EVIDENCE_INVALID")
        if any(type(identity[field]) is not int or identity[field] < 0 for field in ARTIFACT_IDENTITY_FIELDS):
            raise DescriptorAdmissionError("ARTIFACT_EVIDENCE_INVALID")
    if value["fd_before"] != value["fd_after"] or type(value["bytes_read"]) is not int or value["bytes_read"] < 1 or not re.fullmatch(r"[0-9a-f]{64}", value["stream_sha256"]):
        raise DescriptorAdmissionError("ARTIFACT_EVIDENCE_INVALID")
    return dict(value)


def artifact_stream_evidence_commitment(value: Mapping[str, Any]) -> str:
    checked = validate_artifact_stream_evidence(value)
    return bytes_commitment("artifact-stream-evidence", canonical_json(checked, terminal_lf=True))

@dataclass(frozen=True)
class DockerInstallationConfig:
    socket_path: str
    image_ref: str
    image_id: str
    run_id: str
    volume_id: str
    target_id: str

    def __post_init__(self) -> None:
        if self.socket_path != "/var/run/docker.sock":
            raise DockerAdmissionError("DOCKER_SOCKET_INVALID")
        if self.image_ref != "postgres:17-alpine":
            raise DockerAdmissionError("DOCKER_IMAGE_REF_INVALID")
        _validate_image_id(self.image_id)
        _validate_ref(self.run_id, "run_id")
        _validate_ref(self.volume_id, "volume_id")
        _validate_ref(self.target_id, "target_id")


class UnixSocketHTTPClient:
    """The only production Docker transport: a fixed Unix-domain socket."""

    def __init__(self, socket_path: str = "/var/run/docker.sock", *, timeout: float = 5.0) -> None:
        if socket_path != "/var/run/docker.sock":
            raise DockerAdmissionError("DOCKER_SOCKET_INVALID")
        self.socket_path = socket_path
        self.timeout = timeout

    def request(self, method: str, path: str, body: Mapping[str, Any] | None = None) -> tuple[int, Mapping[str, Any]]:
        if method not in {"GET", "POST", "DELETE"} or not isinstance(path, str) or not path.startswith("/") or "\x00" in path:
            raise DockerAdmissionError("DOCKER_REQUEST_INVALID")
        payload = b"" if body is None else canonical_json(dict(body), limit=MAX_HTTP_BODY_BYTES)
        request = (
            f"{method} {path} HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Connection: close\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n\r\n"
        ).encode("ascii") + payload
        if sys.platform != "linux":
            raise DockerAdmissionError("DOCKER_UNIX_SOCKET_UNAVAILABLE")
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(self.timeout)
        try:
            client.connect(self.socket_path)
            client.sendall(request)
            response = bytearray()
            while len(response) <= MAX_HTTP_HEADER_BYTES + MAX_HTTP_BODY_BYTES:
                chunk = client.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
        finally:
            client.close()
        header_end = response.find(b"\r\n\r\n")
        if header_end <= 0:
            raise DockerAdmissionError("DOCKER_RESPONSE_INVALID")
        header = bytes(response[:header_end]).split(b"\r\n")
        try:
            status = int(header[0].split()[1])
            fields = {
                item.split(b":", 1)[0].strip().lower(): item.split(b":", 1)[1].strip()
                for item in header[1:] if b":" in item
            }
            length = int(fields.get(b"content-length", b"0"))
        except (ValueError, IndexError):
            raise DockerAdmissionError("DOCKER_RESPONSE_INVALID")
        body_bytes = bytes(response[header_end + 4:])
        if length != len(body_bytes) or length > MAX_HTTP_BODY_BYTES:
            raise DockerAdmissionError("DOCKER_RESPONSE_INVALID")
        if not body_bytes:
            return status, {}
        try:
            value = json.loads(body_bytes.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant)
        except (ValueError, UnicodeDecodeError, ProtocolError) as error:
            raise DockerAdmissionError("DOCKER_RESPONSE_INVALID") from error
        if not isinstance(value, Mapping):
            raise DockerAdmissionError("DOCKER_RESPONSE_INVALID")
        return status, value


@dataclass(frozen=True)
class DockerDiscovery:
    image_commitment: str
    target_commitment: str
    isolation_commitment: str
    execution_row_id: int
    artifact_filename: str


def _docker_commitment(domain: str, value: Mapping[str, Any]) -> str:
    return bytes_commitment(domain, canonical_json(dict(value), limit=MAX_CONTROL_PAYLOAD_BYTES))


class ProductionDockerBackend:
    """Fixed-image, one-run Docker boundary with no CLI or network fallback."""

    def __init__(self, config: DockerInstallationConfig, *, client: UnixSocketHTTPClient | None = None) -> None:
        self.config = config
        self.client = client or UnixSocketHTTPClient(config.socket_path)
        self.inspect_count = 0
        self.pull_count = 0
        self.tag_resolution_count = 0
        self.target_create_count = 0
        self.volume_create_count = 0

    def inspect_image(self) -> Mapping[str, Any]:
        self.inspect_count += 1
        status, value = self.client.request("GET", "/images/" + urllib.parse.quote(self.config.image_ref, safe="") + "/json")
        if status != 200:
            raise DockerAdmissionError("IMAGE_INSPECT_FAILED")
        image_id = value.get("Id")
        if image_id != self.config.image_id or IMAGE_ID_RE.fullmatch(str(image_id)) is None:
            raise DockerAdmissionError("IMAGE_ID_MISMATCH")
        if value.get("Os") != "linux" or value.get("Architecture") not in {"amd64", "x86_64"}:
            raise DockerAdmissionError("IMAGE_PLATFORM_INVALID")
        image = {
            "schema": SCHEMA_IMAGE_EVIDENCE,
            "image_ref": self.config.image_ref,
            "image_id": self.config.image_id,
            "inspect_count": self.inspect_count,
            "pull_count": self.pull_count,
            "tag_resolution_count": self.tag_resolution_count,
            "image_os": value["Os"],
            "image_architecture": value["Architecture"],
        }
        return image

    def create_isolated_target(self, image: Mapping[str, Any]) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        if image.get("image_id") != self.config.image_id or image.get("image_ref") != self.config.image_ref:
            raise DockerAdmissionError("IMAGE_BINDING_INVALID")
        volume_name = "swooshz-recovery-volume-" + self.config.volume_id
        status, volume = self.client.request(
            "POST",
            "/volumes/create",
            {"Name": volume_name, "Labels": {"com.swooshz.recovery.run": self.config.run_id}},
        )
        if status != 201:
            raise DockerAdmissionError("VOLUME_CREATE_FAILED")
        self.volume_create_count += 1
        volume_name = str(volume.get("Name", volume_name))
        target_name = "swooshz-recovery-target-" + self.config.target_id
        host_config = {
            "NetworkMode": "none",
            "Privileged": False,
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "CapAdd": [],
            "Binds": [f"{volume_name}:/var/lib/postgresql/data:rw"],
            "PublishAllPorts": False,
            "PortBindings": {},
            "ExtraHosts": [],
            "SecurityOpt": [],
        }
        if host_config["NetworkMode"] != "none" or host_config["Privileged"] or host_config["CapDrop"] != ["ALL"] or host_config["CapAdd"] != []:
            raise DockerAdmissionError("ISOLATION_INVALID")
        status, target = self.client.request(
            "POST",
            "/containers/create?name=" + urllib.parse.quote(target_name, safe=""),
            {
                "Image": self.config.image_id,
                "Env": ["POSTGRES_DB=coolify"],
                "HostConfig": host_config,
                "Labels": {"com.swooshz.recovery.run": self.config.run_id},
            },
        )
        if status != 201:
            raise DockerAdmissionError("TARGET_CREATE_FAILED")
        self.target_create_count += 1
        target_id = target.get("Id", self.config.target_id)
        target_evidence = {
            "schema": SCHEMA_TARGET_EVIDENCE,
            "epoch_ref": self.config.run_id,
            "image_commitment": _docker_commitment("image-evidence", image),
            "target_id": self.config.target_id,
            "volume_id": self.config.volume_id,
            "preexisting_target": False,
            "preexisting_volume": False,
            "target_create_count": self.target_create_count,
            "volume_create_count": self.volume_create_count,
            "run_owned": isinstance(target_id, str) and bool(target_id),
        }
        isolation = {
            "schema": SCHEMA_ISOLATION_EVIDENCE,
            "target_commitment": _docker_commitment("target-evidence", target_evidence),
            "image_commitment": target_evidence["image_commitment"],
            "effective_image_id": self.config.image_id,
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
        return target_evidence, isolation

    def open_locator_process(self) -> Any:
        """Return one Engine-attached process or fail closed when not bound."""
        raise DockerAdmissionError("PRODUCTION_DOCKER_PROCESS_BINDING_REQUIRED")

    def discover(self, epoch_ref: str, barrier_utc: str) -> DockerDiscovery:
        _validate_ref(epoch_ref, "epoch_ref")
        validate_barrier_utc(barrier_utc)
        image = self.inspect_image()
        target, isolation = self.create_isolated_target(image)
        global _ACTIVE_PRODUCTION_BACKEND
        _ACTIVE_PRODUCTION_BACKEND = self
        try:
            outcome = invoke_canonical_locator_once(barrier_utc)
        finally:
            _ACTIVE_PRODUCTION_BACKEND = None
        if getattr(outcome, "classification", None) != "EXACTLY_ONE":
            raise DockerAdmissionError("LOCATOR_NOT_FOUND", safety_state="UNCONSUMED")
        execution_id = getattr(outcome, "execution_id", None)
        filename = getattr(outcome, "filename", None)
        if type(execution_id) is not int or execution_id <= 0 or not isinstance(filename, str):
            raise DockerAdmissionError("LOCATOR_OUTPUT_INVALID", safety_state="UNCONSUMED")
        return DockerDiscovery(
            _docker_commitment("image-evidence", image),
            _docker_commitment("target-evidence", target),
            _docker_commitment("isolation-evidence", isolation),
            execution_id,
            _validate_filename(filename),
        )
    def cleanup(self, target_evidence: Mapping[str, Any], volume_id: str) -> Mapping[str, Any]:
        if target_evidence.get("run_owned") is not True or target_evidence.get("target_id") != self.config.target_id or volume_id != self.config.volume_id:
            raise DockerAdmissionError("CLEANUP_OWNERSHIP_INVALID", safety_state="CONSUMED")
        if target_evidence.get("preexisting_target") or target_evidence.get("preexisting_volume"):
            raise DockerAdmissionError("CLEANUP_PREEXISTING_INVALID", safety_state="CONSUMED")
        target_name = "swooshz-recovery-target-" + self.config.target_id
        volume_name = "swooshz-recovery-volume-" + self.config.volume_id
        target_status, _ = self.client.request("DELETE", "/containers/" + urllib.parse.quote(target_name, safe="") + "?force=true")
        volume_status, _ = self.client.request("DELETE", "/volumes/" + urllib.parse.quote(volume_name, safe=""))
        if target_status not in {204, 404} or volume_status not in {204, 404}:
            raise DockerAdmissionError("CLEANUP_FAILED", safety_state="CONSUMED")
        return {
            "schema": SCHEMA_CLEANUP_EVIDENCE,
            "target_id": self.config.target_id,
            "volume_id": self.config.volume_id,
            "run_owned": True,
            "prune": False,
            "target_deleted": target_status == 204,
            "volume_deleted": volume_status == 204,
            "status": "COMPLETE",
        }


class TestOnlyDockerBackend:
    """Synthetic seam; it is never a production default and cannot claim SUCCESS."""

    test_only = True

    def __init__(self, *, discovery: DockerDiscovery) -> None:
        self.discovery = discovery

    def discover(self, _epoch_ref: str, _barrier_utc: str) -> DockerDiscovery:
        return self.discovery
    def operation(self, _barrier_utc: str) -> Mapping[str, Any]:
        raise DockerAdmissionError("TEST_BACKEND_CANNOT_PRODUCE_SUCCESS")


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


CANONICAL_LOCATOR_PACKAGE, CANONICAL_LOCATOR_SOURCE = (lambda encoded: (
    base64.urlsafe_b64decode(encoded + "==="),
    __import__("zlib").decompress(base64.urlsafe_b64decode(encoded + "==="), -15),
))(CANONICAL_LOCATOR_PACKAGE_B64)
if (
    len(CANONICAL_LOCATOR_PACKAGE) != CANONICAL_LOCATOR_COMPRESSED_BYTES
    or hashlib.sha256(CANONICAL_LOCATOR_PACKAGE).hexdigest() != CANONICAL_LOCATOR_COMPRESSED_SHA256
    or len(CANONICAL_LOCATOR_SOURCE) != CANONICAL_LOCATOR_SOURCE_BYTES
    or len(CANONICAL_LOCATOR_SOURCE.splitlines()) != CANONICAL_LOCATOR_SOURCE_LINES
    or hashlib.sha256(CANONICAL_LOCATOR_SOURCE).hexdigest() != CANONICAL_LOCATOR_SOURCE_SHA256
):
    raise LoaderIntegrityError("LOCATOR_PACKAGE_KAT_FAILED")
CANONICAL_LOCATOR_SOURCE_COMMITMENT = COMMITMENT_PREFIX + CANONICAL_LOCATOR_SOURCE_SHA256
CANONICAL_LOCATOR_PACKAGE_COMMITMENT = bytes_commitment("locator-package", CANONICAL_LOCATOR_PACKAGE_B64.encode("ascii"))
if CANONICAL_LOCATOR_PACKAGE_COMMITMENT != "sha256:v1:a28e039377ce58c7b7cdf57f19a020d83e8ccdc4cb5b02f94041b822a72880ad":
    raise LoaderIntegrityError("LOCATOR_PACKAGE_COMMITMENT_KAT_FAILED")
FIXED_LOADER_SOURCE = build_fixed_loader_source()
FIXED_LOADER_COMMITMENT = bytes_commitment("fixed-loader", FIXED_LOADER_SOURCE)


def compile_restricted_locator() -> types.ModuleType:
    source = FIXED_LOADER_SOURCE
    trusted = {"__builtins__": builtins.__dict__, "__name__": "__fixed_loader__"}
    try:
        exec(compile(source, "<fixed-recovery-loader>", "exec", dont_inherit=True), trusted, trusted)
        module = sys.modules.get("__canonical_locator_payload__")
    except (SyntaxError, TypeError, ValueError, ImportError, MemoryError, RuntimeError) as error:
        raise LoaderIntegrityError("LOCATOR_LOAD_FAILED") from error
    if not isinstance(module, types.ModuleType):
        raise LoaderIntegrityError("LOCATOR_MODULE_INVALID")
    if (
        module.__name__ != "__canonical_locator_payload__"
        or module.__file__ != CANONICAL_LOCATOR_PATH
        or module.__package__ is not None
        or not callable(module.__dict__.get("execute_operation"))
    ):
        raise LoaderIntegrityError("LOCATOR_ADMISSION_FAILED")
    if tuple(module.__dict__.get("__builtins__", {}).keys()) != (
        "__build_class__", "Exception", "OSError", "TypeError",
        "UnicodeDecodeError", "UnicodeEncodeError", "ValueError", "any",
        "bool", "bytearray", "bytes", "callable", "dict", "float", "getattr",
        "id", "int", "isinstance", "len", "list", "max", "min", "property",
        "set", "str", "tuple", "type", "__import__",
    ):
        raise LoaderIntegrityError("LOCATOR_BUILTINS_INVALID")
    return module


def locator_source_commitment() -> str:
    return CANONICAL_LOCATOR_SOURCE_COMMITMENT


def compute_production_commitments(source_bytes: bytes) -> Mapping[str, str]:
    if not isinstance(source_bytes, bytes) or not 1 <= len(source_bytes) <= MAX_AGENT_BYTES:
        raise LoaderIntegrityError("AGENT_SOURCE_INVALID")
    launcher = bytes_commitment("recovery-launcher-bytes", source_bytes)
    agent = bytes_commitment("recovery-agent-bytes", source_bytes)
    bundle = text_commitment(
        "recovery-agent-bundle",
        "swz-recovery-bundle.v2",
        CANONICAL_LOCATOR_SOURCE_COMMITMENT,
        LOCATOR_PACKAGE_ATTESTATION,
        CANONICAL_LOCATOR_PACKAGE_COMMITMENT,
        FIXED_LOADER_COMMITMENT,
        launcher,
        agent,
    )
    return {
        "launcher_commitment": launcher,
        "agent_commitment": agent,
        "bundle_commitment": bundle,
    }


def fixed_clock() -> float:
    """The production locator clock is fixed to the monotonic runtime clock."""
    return time.monotonic()


def fixed_event_queue_factory() -> Any:
    """The production locator receives one bounded queue and no caller seam."""
    return queue.Queue(maxsize=16)

BUNDLE_KAT_BYTES = b"RUN352-BUNDLE-KAT\n"
BUNDLE_KAT_RAW_SHA256 = "4e0378b336ed0cad409a304eeb365fd222a2e729ff9f2a927342b873fa430789"
BUNDLE_KAT_LAUNCHER_COMMITMENT = "sha256:v1:8da1265e86c12e16374ca7b116a44383d8e45bc6735c4f51850b3791d3621e58"
BUNDLE_KAT_AGENT_COMMITMENT = "sha256:v1:ced6e5e4c626706a6568a3d602a4a0bdb6c522a2ceec8af3893c65afb391b4e8"
BUNDLE_KAT_COMMITMENT = "sha256:v1:4d9963a466e680260121d0a8ce38127f8989846c9189e29d57f89f70f76435b5"


def compute_bundle_commitment(launcher_commitment: str, agent_commitment: str) -> str:
    values = (launcher_commitment, agent_commitment)
    if any(not isinstance(value, str) or COMMITMENT_RE.fullmatch(value) is None for value in values):
        raise LoaderIntegrityError("BUNDLE_COMMITMENT_INPUT_INVALID")
    return text_commitment(
        "recovery-agent-bundle",
        "swz-recovery-bundle.v2",
        CANONICAL_LOCATOR_SOURCE_COMMITMENT,
        LOCATOR_PACKAGE_ATTESTATION,
        CANONICAL_LOCATOR_PACKAGE_COMMITMENT,
        FIXED_LOADER_COMMITMENT,
        launcher_commitment,
        agent_commitment,
    )


if hashlib.sha256(BUNDLE_KAT_BYTES).hexdigest() != BUNDLE_KAT_RAW_SHA256:
    raise LoaderIntegrityError("BUNDLE_KAT_RAW_FAILED")
if compute_bundle_commitment(BUNDLE_KAT_LAUNCHER_COMMITMENT, BUNDLE_KAT_AGENT_COMMITMENT) != BUNDLE_KAT_COMMITMENT:
    raise LoaderIntegrityError("BUNDLE_KAT_COMMITMENT_FAILED")

def invoke_canonical_locator_once(
    barrier_utc: str,
    *,
    process_factory: Callable[[], Any] | None = None,
    clock: Callable[[], float] | None = None,
    event_queue_factory: Callable[[], Any] | None = None,
    test_mode: bool = False,
) -> Any:
    validate_barrier_utc(barrier_utc)
    if test_mode is False and any(value is not None for value in (process_factory, clock, event_queue_factory)):
        raise LoaderIntegrityError("TEST_SEAM_NOT_PRODUCTION")
    module = compile_restricted_locator()
    if test_mode:
        selected_process_factory = process_factory if process_factory is not None else fixed_process_factory
        selected_clock = clock if clock is not None else fixed_clock
        selected_event_queue_factory = event_queue_factory if event_queue_factory is not None else fixed_event_queue_factory
    else:
        selected_process_factory = fixed_process_factory
        selected_clock = fixed_clock
        selected_event_queue_factory = fixed_event_queue_factory
    outcome = module.execute_operation(
        barrier_utc,
        process_factory=selected_process_factory,
        clock=selected_clock,
        event_queue_factory=selected_event_queue_factory,
    )
    if test_mode and getattr(outcome, "classification", None) == "SUCCESS":
        raise LoaderIntegrityError("TEST_SUCCESS_NOT_OPERATIONAL")
    return outcome


_ACTIVE_PRODUCTION_BACKEND: Any | None = None


def fixed_process_factory() -> Any:
    backend = _ACTIVE_PRODUCTION_BACKEND
    if backend is None or not isinstance(backend, ProductionDockerBackend):
        raise DockerAdmissionError("PRODUCTION_DOCKER_BINDING_REQUIRED")
    return backend.open_locator_process()


def build_production_bundle_commitment_from_file(path: str | os.PathLike[str]) -> Mapping[str, str]:
    if not isinstance(path, (str, os.PathLike)):
        raise LoaderIntegrityError("SOURCE_PATH_INVALID")
    source_bytes = pathlib.Path(path).read_bytes()
    return compute_production_commitments(source_bytes)


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


def validate_image_evidence(value: Mapping[str, Any]) -> Mapping[str, Any]:
    required = (
        "schema", "image_ref", "image_id", "inspect_count", "pull_count",
        "tag_resolution_count", "image_os", "image_architecture",
    )
    if tuple(value.keys()) != required or value["schema"] != SCHEMA_IMAGE_EVIDENCE:
        raise DockerAdmissionError("IMAGE_EVIDENCE_INVALID")
    if value["image_ref"] != "postgres:17-alpine":
        raise DockerAdmissionError("IMAGE_EVIDENCE_INVALID")
    _validate_image_id(value["image_id"])
    if value["inspect_count"] != 1 or value["pull_count"] != 0 or value["tag_resolution_count"] != 0:
        raise DockerAdmissionError("IMAGE_EVIDENCE_INVALID")
    if value["image_os"] != "linux" or value["image_architecture"] not in {"amd64", "x86_64"}:
        raise DockerAdmissionError("IMAGE_EVIDENCE_INVALID")
    return dict(value)


def validate_isolation_evidence(value: Mapping[str, Any]) -> Mapping[str, Any]:
    required = (
        "schema", "target_commitment", "image_commitment", "effective_image_id",
        "network_mode", "privileged", "rootfs_read_only", "cap_drop", "cap_add",
        "extra_mounts", "volume_destination", "volume_read_only", "readback_count",
    )
    if tuple(value.keys()) != required or value["schema"] != SCHEMA_ISOLATION_EVIDENCE:
        raise DockerAdmissionError("ISOLATION_EVIDENCE_INVALID")
    if value["network_mode"] != "none" or value["privileged"] is not False or value["rootfs_read_only"] is not True:
        raise DockerAdmissionError("ISOLATION_EVIDENCE_INVALID")
    if value["cap_drop"] != ["ALL"] or value["cap_add"] != [] or value["extra_mounts"] != 0:
        raise DockerAdmissionError("ISOLATION_EVIDENCE_INVALID")
    if value["volume_destination"] != "/var/lib/postgresql/data" or value["volume_read_only"] is not False or value["readback_count"] != 1:
        raise DockerAdmissionError("ISOLATION_EVIDENCE_INVALID")
    _validate_image_id(value["effective_image_id"])
    _validate_commitment(value["image_commitment"], "image_commitment")
    _validate_commitment(value["target_commitment"], "target_commitment")
    return dict(value)


def result_commitment(result_evidence: Mapping[str, Any]) -> str:
    if tuple(result_evidence.keys()) != RESULT_EVIDENCE_FIELDS:
        raise ProtocolError("RESULT_EVIDENCE_FIELDS_INVALID")
    return bytes_commitment("result-evidence", canonical_json(dict(result_evidence), limit=MAX_CONTROL_PAYLOAD_BYTES, terminal_lf=True))


def abort_commitment(abort_evidence: Mapping[str, Any]) -> str:
    if tuple(abort_evidence.keys()) != ABORT_EVIDENCE_FIELDS:
        raise ProtocolError("ABORT_EVIDENCE_FIELDS_INVALID")
    return bytes_commitment("abort-evidence", canonical_json(dict(abort_evidence), limit=MAX_CONTROL_PAYLOAD_BYTES, terminal_lf=True))


RESULT_EVIDENCE_FIELDS = (
    "schema", "classification", "stage", "epoch_ref", "authority_ref",
    "barrier_utc", "ssh_endpoint_commitment", "epoch_commitment",
    "authority_commitment", "barrier_commitment", "runner_commitment",
    "bundle_commitment", "launcher_commitment", "agent_commitment",
    "image_commitment", "target_commitment", "isolation_commitment",
    "artifact_commitment", "artifact_stream_commitment", "transition_id",
    "pre_cas_ledger_digest", "transition_data_commitment",
    "consumed_record_commitment", "restore_begin_commitment",
    "process_commitment", "restore_commitment", "cleanup_commitment",
    "stdout_capture_commitment", "stderr_capture_commitment", "result_code",
    "restore_count", "exit_status", "stdin_eof", "stdout_eof", "stderr_eof",
    "trailing_unframed_bytes", "cleanup_state",
)
ABORT_EVIDENCE_FIELDS = (
    "schema", "epoch_ref", "authority_ref", "ssh_endpoint_commitment",
    "stage", "direction", "code", "classification", "epoch_commitment",
    "authority_commitment", "barrier_commitment", "transition_id",
    "transition_data_commitment", "restore_begin_commitment", "consumed_state",
    "record_state", "ledger_state", "spool_last_stage", "store_readback_commitment",
    "process_finality", "transport_finality", "cleanup_state", "retry_allowed",
    "reconnect_allowed", "proceed_allowed", "restore_allowed", "commit_allowed",
    "abandon_allowed",
)


def _validate_evidence_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ProtocolError(f"{label}_INVALID")
    return value


def validate_result_evidence(value: Mapping[str, Any]) -> Mapping[str, Any]:
    if tuple(value.keys()) != RESULT_EVIDENCE_FIELDS or value["schema"] != SCHEMA_RESULT:
        raise ProtocolError("RESULT_EVIDENCE_INVALID")
    if value["classification"] not in RESULT_CLASSIFICATIONS:
        raise ProtocolError("RESULT_EVIDENCE_INVALID")
    for key, child in value.items():
        if key.endswith("_commitment") or key.endswith("_digest"):
            _validate_commitment(child, key)
    if type(value["restore_count"]) is not int or value["restore_count"] < 0:
        raise ProtocolError("RESULT_EVIDENCE_INVALID")
    if type(value["exit_status"]) is not int or not -1 <= value["exit_status"] <= 255:
        raise ProtocolError("RESULT_EVIDENCE_INVALID")
    for key in ("stdin_eof", "stdout_eof", "stderr_eof"):
        if type(value[key]) is not bool:
            raise ProtocolError("RESULT_EVIDENCE_INVALID")
    if type(value["trailing_unframed_bytes"]) is not int or value["trailing_unframed_bytes"] < 0:
        raise ProtocolError("RESULT_EVIDENCE_INVALID")
    return dict(value)


def validate_abort_evidence(value: Mapping[str, Any]) -> Mapping[str, Any]:
    if tuple(value.keys()) != ABORT_EVIDENCE_FIELDS or value["schema"] != SCHEMA_ABORT:
        raise ProtocolError("ABORT_EVIDENCE_INVALID")
    if value["classification"] != "FAILURE":
        raise ProtocolError("ABORT_EVIDENCE_INVALID")
    for key in value:
        if key.endswith("_commitment") or key.endswith("_digest"):
            _validate_commitment(value[key], key)
    for key in ("retry_allowed", "reconnect_allowed", "proceed_allowed", "restore_allowed", "commit_allowed", "abandon_allowed"):
        if type(value[key]) is not bool:
            raise ProtocolError("ABORT_EVIDENCE_INVALID")
    if any(value[key] for key in ("retry_allowed", "reconnect_allowed", "proceed_allowed", "restore_allowed", "commit_allowed")):
        raise ProtocolError("ABORT_EVIDENCE_INVALID")
    return dict(value)


def build_production_bundle_commitment(source_bytes: bytes) -> str:
    return compute_production_commitments(source_bytes)["bundle_commitment"]


def fixed_source_commitments() -> Mapping[str, str]:
    return compute_production_commitments(pathlib.Path(__file__).read_bytes())




def build_discovery_payload(epoch_ref: str, authority_ref: str, discovery: DockerDiscovery) -> dict[str, Any]:
    _validate_ref(epoch_ref, "epoch_ref")
    _validate_ref(authority_ref, "authority_ref")
    if not isinstance(discovery, DockerDiscovery) or type(discovery.execution_row_id) is not int or discovery.execution_row_id <= 0:
        raise ProtocolError("DISCOVERY_INVALID")
    value = {
        "type": "DISCOVERY",
        "version": SWZFRM02_VERSION,
        "schema": SCHEMA_WIRE,
        "epoch_ref": epoch_ref,
        "authority_ref": authority_ref,
        "execution_row_id": discovery.execution_row_id,
        "artifact_filename": _validate_filename(discovery.artifact_filename),
        "image_commitment": discovery.image_commitment,
        "target_commitment": discovery.target_commitment,
        "isolation_commitment": discovery.isolation_commitment,
    }
    for field in ("image_commitment", "target_commitment", "isolation_commitment"):
        _validate_commitment(value[field], field)
    return validate_wire_payload(value, "DISCOVERY")


def _validate_remote_proceed(boot: Mapping[str, Any], discovery: Mapping[str, Any], proceed: Mapping[str, Any]) -> None:
    required = (
        "epoch_ref", "authority_ref", "barrier_utc", "epoch_commitment",
        "authority_commitment", "barrier_commitment", "runner_commitment",
        "bundle_commitment", "launcher_commitment", "agent_commitment",
    )
    for field in required:
        if proceed[field] != boot[field]:
            raise ProtocolError("PROCEED_MISMATCH")
    for field in ("image_commitment", "target_commitment", "isolation_commitment"):
        if proceed[field] != discovery[field]:
            raise ProtocolError("PROCEED_MISMATCH")
    if proceed["artifact_commitment"] is None or proceed["artifact_stream_commitment"] is None:
        raise ProtocolError("PROCEED_MISMATCH")

def run_agent_protocol(
    input_stream: BinaryIO,
    output_stream: BinaryIO,
    *,
    backend: Any | None = None,
    environment: Mapping[str, str] | None = None,
    argv: tuple[str, ...] = ("/dev/fd/3", "--agent-v1", "--protocol-v2"),
    test_mode: bool = False,
) -> None:
    env = dict(os.environ if environment is None else environment)
    if not test_mode:
        assert_isolated_runtime()
    validate_agent_entry(argv, env, fd3_present=True)
    if backend is None or not callable(getattr(backend, "discover", None)):
        raise DockerAdmissionError("PRODUCTION_BACKEND_REQUIRED")
    if getattr(backend, "test_only", False) and not test_mode:
        raise DockerAdmissionError("TEST_BACKEND_FORBIDDEN")
    boot_frame = read_frame(input_stream)
    if boot_frame is None or boot_frame.message != MESSAGE_BOOT or boot_frame.direction != DIRECTION_LOCAL_TO_REMOTE:
        raise ProtocolError("BOOT_INVALID")
    n_local = boot_frame.n_local
    session = SessionMachine(local_role=False, n_local=n_local)
    session.accept(boot_frame)
    boot = boot_frame.payload
    source_commitments = fixed_source_commitments()
    if (
        boot["bundle_commitment"] != source_commitments["bundle_commitment"]
        or boot["launcher_commitment"] != source_commitments["launcher_commitment"]
        or boot["agent_commitment"] != source_commitments["agent_commitment"]
    ):
        raise LoaderIntegrityError("AGENT_COMMITMENT_MISMATCH")
    ready = {field: boot[field] for field in READY_FIELDS}
    ready_frame = decode_frame(encode_frame(DIRECTION_REMOTE_TO_LOCAL, MESSAGE_READY, session.next_sequence, n_local, ready))
    session.accept(ready_frame)
    write_frame(output_stream, encode_frame(DIRECTION_REMOTE_TO_LOCAL, MESSAGE_READY, ready_frame.sequence, n_local, ready))
    try:
        discovery = backend.discover(boot["epoch_ref"], boot["barrier_utc"])
    except RecoveryError:
        raise
    except Exception as error:
        raise DockerAdmissionError("DISCOVERY_FAILED") from error
    discovery_payload = build_discovery_payload(boot["epoch_ref"], boot["authority_ref"], discovery)
    discovery_frame = decode_frame(encode_frame(DIRECTION_REMOTE_TO_LOCAL, MESSAGE_DISCOVERY, session.next_sequence, n_local, discovery_payload))
    session.accept(discovery_frame)
    write_frame(output_stream, encode_frame(DIRECTION_REMOTE_TO_LOCAL, MESSAGE_DISCOVERY, discovery_frame.sequence, n_local, discovery_payload))
    proceed_frame = read_frame(input_stream)
    if proceed_frame is None or proceed_frame.message != MESSAGE_PROCEED or proceed_frame.direction != DIRECTION_LOCAL_TO_REMOTE:
        raise ProtocolError("PROCEED_INVALID")
    session.accept(proceed_frame)
    _validate_remote_proceed(boot, discovery_payload, proceed_frame.payload)
    if getattr(backend, "test_only", False):
        raise DockerAdmissionError("TEST_BACKEND_CANNOT_PRODUCE_SUCCESS", safety_state="UNCONSUMED")
    restore = getattr(backend, "restore", None)
    if not callable(restore):
        raise DockerAdmissionError("PRODUCTION_RESTORE_BINDING_REQUIRED", safety_state="CONSUMED")
    evidence = restore(proceed_frame.payload)
    checked = validate_result_evidence(evidence)
    result_value = {
        "type": "RESULT",
        "version": SWZFRM02_VERSION,
        "schema": SCHEMA_WIRE,
        "classification": checked["classification"],
        "result_evidence": checked,
        "result_commitment": result_commitment(checked),
    }
    result_frame = decode_frame(encode_frame(DIRECTION_REMOTE_TO_LOCAL, MESSAGE_RESULT, session.next_sequence, n_local, result_value))
    session.accept(result_frame)
    write_frame(output_stream, encode_frame(DIRECTION_REMOTE_TO_LOCAL, MESSAGE_RESULT, result_frame.sequence, n_local, result_value))

def agent_main(argv: list[str] | None = None) -> int:
    values = list(sys.argv if argv is None else argv)
    mode = classify_dispatch(values, dict(os.environ), fd3_present=(mode_fd := 3) is not None and _fd_present(mode_fd))
    if mode == "agent":
        run_agent_protocol(sys.stdin.buffer, sys.stdout.buffer)
        return 0
    if mode == "supervisor":
        run_supervisor(values)
        return 0
    raise DescriptorAdmissionError("DISPATCH_INVALID")


def _fd_present(fd: int) -> bool:
    try:
        os.fstat(fd)
        return True
    except OSError:
        return False


def run_supervisor(argv: list[str]) -> None:
    if tuple(argv[1:]) != ("--protocol-v2",):
        raise DescriptorAdmissionError("SUPERVISOR_ARGV_INVALID")
    if os.environ.get("SSH_ORIGINAL_COMMAND", "") != "":
        raise DescriptorAdmissionError("REMOTE_COMMAND_FORBIDDEN")
    spawn_descriptor_agent()


if __name__ == "__main__":
    agent_main()
