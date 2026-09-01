#!/usr/bin/env python3
"""Single-session recovery-controller bridge.

This module contains the repository-side protocol and its local dummy-loader
proof surface.  It deliberately has no live launcher, provider client, SSH
client, database client, Docker client, or recovery runner.  A future live
authority supplies one complete trusted ``RunnerBundle`` in memory.

The remote side is trusted run-authorised code after authenticated BOOT.  The
guarded import and subprocess surfaces prevent accidental protocol corruption
and module escape; they are not a malicious-code sandbox.
"""

from __future__ import annotations

import base64
import binascii
import builtins
import contextlib
import dataclasses
import hashlib
import hmac
import importlib.util
import inspect
import io
import json
import os
import pathlib
import queue
import re
import struct
import subprocess as _subprocess
import sys
import threading
import time
import types
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, BinaryIO, Callable, Mapping, Sequence


# The allowlist is deliberately exact. ``subprocess`` is replaced with the
# guarded proxy below; it is not the raw imported module surface.
RUNNER_IMPORT_ROOTS = frozenset(
    {
        "base64",
        "binascii",
        "collections",
        "contextlib",
        "dataclasses",
        "datetime",
        "hashlib",
        "hmac",
        "io",
        "json",
        "math",
        "os",
        "pathlib",
        "queue",
        "re",
        "selectors",
        "shlex",
        "signal",
        "stat",
        "struct",
        "subprocess",
        "sys",
        "threading",
        "time",
        "typing",
        "uuid",
    }
)


class RunnerAbortCode(str, Enum):
    """The ten runner-requested pre-DISCOVERY abort reasons."""

    ZERO_ROW_MATCH = "ZERO_ROW_MATCH"
    MULTIPLE_ROW_MATCH = "MULTIPLE_ROW_MATCH"
    PRIVATE_LOCATOR_MISSING = "PRIVATE_LOCATOR_MISSING"
    QUERY_NOT_EXECUTED = "QUERY_NOT_EXECUTED"
    QUERY_FAILED = "QUERY_FAILED"
    ARTIFACT_MISSING = "ARTIFACT_MISSING"
    ARTIFACT_CHANGED = "ARTIFACT_CHANGED"
    RESOURCE_COLLISION = "RESOURCE_COLLISION"
    ISOLATION_FAILED = "ISOLATION_FAILED"
    CLEANUP_FAILED = "CLEANUP_FAILED"


class RunnerControlCode(str, Enum):
    """Finite public-safe control/error codes."""

    ZERO_ROW_MATCH = RunnerAbortCode.ZERO_ROW_MATCH.value
    MULTIPLE_ROW_MATCH = RunnerAbortCode.MULTIPLE_ROW_MATCH.value
    PRIVATE_LOCATOR_MISSING = RunnerAbortCode.PRIVATE_LOCATOR_MISSING.value
    QUERY_NOT_EXECUTED = RunnerAbortCode.QUERY_NOT_EXECUTED.value
    QUERY_FAILED = RunnerAbortCode.QUERY_FAILED.value
    ARTIFACT_MISSING = RunnerAbortCode.ARTIFACT_MISSING.value
    ARTIFACT_CHANGED = RunnerAbortCode.ARTIFACT_CHANGED.value
    RESOURCE_COLLISION = RunnerAbortCode.RESOURCE_COLLISION.value
    ISOLATION_FAILED = RunnerAbortCode.ISOLATION_FAILED.value
    CLEANUP_FAILED = RunnerAbortCode.CLEANUP_FAILED.value

    DECISION_EOF = "DECISION_EOF"
    DECISION_TIMEOUT = "DECISION_TIMEOUT"
    DECISION_BROKEN_PIPE = "DECISION_BROKEN_PIPE"
    PROTOCOL_BROKEN_PIPE = "PROTOCOL_BROKEN_PIPE"
    PROCEED_INVALID = "PROCEED_INVALID"
    PROTOCOL_FAILURE = "PROTOCOL_FAILURE"
    LOCAL_ABORT = "LOCAL_ABORT"
    RUNTIME_TERMINAL = "RUNTIME_TERMINAL"
    RUNNER_STDOUT_FORBIDDEN = "RUNNER_STDOUT_FORBIDDEN"
    RUNNER_STDERR_FORBIDDEN = "RUNNER_STDERR_FORBIDDEN"
    RUNNER_INPUT_FORBIDDEN = "RUNNER_INPUT_FORBIDDEN"
    SUBPROCESS_STDIO_REQUIRED = "SUBPROCESS_STDIO_REQUIRED"
    DISCOVERY_DUPLICATE = "DISCOVERY_DUPLICATE"
    RESULT_BEFORE_PROCEED = "RESULT_BEFORE_PROCEED"
    RESULT_DUPLICATE = "RESULT_DUPLICATE"
    RUNNER_MISSING = "RUNNER_MISSING"
    RUNNER_NOT_CALLABLE = "RUNNER_NOT_CALLABLE"
    RUNNER_SIGNATURE_INVALID = "RUNNER_SIGNATURE_INVALID"
    RUNNER_TOP_LEVEL_EXCEPTION = "RUNNER_TOP_LEVEL_EXCEPTION"
    RUNNER_NO_RESULT = "RUNNER_NO_RESULT"
    RUNNER_NON_NONE_RETURN = "RUNNER_NON_NONE_RETURN"


RUNNER_ABORT_VALUES = tuple(code.value for code in RunnerAbortCode)
RUNNER_CONTROL_VALUES = tuple(code.value for code in RunnerControlCode)
assert len(RUNNER_ABORT_VALUES) == 10
assert len(RUNNER_CONTROL_VALUES) == 31


class ResultClassification(str, Enum):
    COMMITTED = "COMMITTED"
    ABANDONED = "ABANDONED"


PUBLIC_ERROR_CODES = frozenset(
    set(RUNNER_CONTROL_VALUES)
    | {
        "STORE_IMPORT_FAILED",
        "STORE_STATE_INVALID",
        "LOCATOR_IMPORT_FAILED",
        "BUNDLE_INVALID",
        "BUNDLE_NOT_UTF8",
        "BUNDLE_OVERSIZED",
        "BUNDLE_COMPILE_FAILED",
        "BUNDLE_COMMITMENT_MISMATCH",
        "BARRIER_INVALID",
        "DISCOVERY_INVALID",
        "FRAME_INVALID",
        "PREAMBLE_INVALID",
        "HELLO_INVALID",
        "PROCESS_TIMEOUT",
        "PROCESS_EOF",
        "PROCESS_STDERR_FORBIDDEN",
        "STORE_TRANSITION_FAILED",
        "POST_CAS_UNCERTAIN",
    }
)


class BridgeError(Exception):
    """Base error whose public string is always a symbolic code."""

    def __init__(self, code: str | Enum):
        value = code.value if isinstance(code, Enum) else code
        if value not in PUBLIC_ERROR_CODES:
            value = RunnerControlCode.PROTOCOL_FAILURE.value
        self.code = value
        super().__init__(value)


class ProtocolError(BridgeError):
    pass


class BundleError(BridgeError):
    pass


class RunnerControlError(BridgeError):
    """Public error delivered to trusted runner code."""

    def __init__(self, code: RunnerControlCode | RunnerAbortCode | str):
        if isinstance(code, RunnerAbortCode):
            code = RunnerControlCode(code.value)
        elif not isinstance(code, RunnerControlCode):
            try:
                code = RunnerControlCode(code)
            except ValueError:
                code = RunnerControlCode.PROTOCOL_FAILURE
        super().__init__(code.value)
        # BridgeError keeps its public string representation deliberately
        # terse. The runner-facing contract additionally requires the typed
        # control enum on ``.code``.
        self.code = code


def _raise(error_type: type[BridgeError], code: str | Enum) -> None:
    raise error_type(code)


# ---------------------------------------------------------------------------
# Fixed protocol wire formats

PROTOCOL_VERSION = 1
HELLO_TYPE = 1
PREAMBLE_TYPE = 2

HELLO_MAGIC = b"SWZBRDG1"
HELLO_STRUCT = struct.Struct("!8sBB32s")
HELLO_SIZE = HELLO_STRUCT.size

PREAMBLE_MAGIC = b"SWZPRE01"
PREAMBLE_HEADER_STRUCT = struct.Struct("!8sBBHI")
PREAMBLE_BODY_STRUCT = struct.Struct("!32s32s32s32s32s32s32s32s")
PREAMBLE_BODY_SIZE = PREAMBLE_BODY_STRUCT.size
PREAMBLE_SIZE = PREAMBLE_HEADER_STRUCT.size + PREAMBLE_BODY_SIZE
PREAMBLE_FIELDS = (
    "n_remote",
    "n_local",
    "n_session",
    "epoch_digest",
    "authority_digest",
    "runner_digest",
    "bundle_digest",
    "bootstrap_seed",
)
assert PREAMBLE_BODY_SIZE == 256
assert PREAMBLE_SIZE == 272

AUTH_FRAME_MAGIC = b"SWZFRM01"
AUTH_FRAME_HEADER_STRUCT = struct.Struct("!8sBBBBQ32s16sI")
AUTH_FRAME_TAG_SIZE = hashlib.sha256().digest_size
AUTH_FRAME_OVERHEAD = AUTH_FRAME_HEADER_STRUCT.size + AUTH_FRAME_TAG_SIZE
MAX_AUTH_FRAME_BYTES = 64 * 1024
MAX_AUTH_PAYLOAD_BYTES = MAX_AUTH_FRAME_BYTES - AUTH_FRAME_OVERHEAD
MAX_SESSION_FRAMES = 4096
MAX_SESSION_BYTES = 4 * 1024 * 1024
FRAME_FLAGS = 0

DIRECTION_LOCAL_TO_REMOTE = 1
DIRECTION_REMOTE_TO_LOCAL = 2

MESSAGE_BOOT = 1
MESSAGE_READY = 2
MESSAGE_DISCOVERY = 3
MESSAGE_PROCEED = 4
MESSAGE_ABORT = 5
MESSAGE_RESULT = 6
MESSAGE_VALUES = frozenset(
    {
        MESSAGE_BOOT,
        MESSAGE_READY,
        MESSAGE_DISCOVERY,
        MESSAGE_PROCEED,
        MESSAGE_ABORT,
        MESSAGE_RESULT,
    }
)

BOOT_MAGIC = b"SWZBOOT1"
BOOT_HEADER_STRUCT = struct.Struct("!8sBBH27s32sI")
BOOT_HEADER_SIZE = BOOT_HEADER_STRUCT.size
MAX_RUNNER_BUNDLE_BYTES = 65536

CONTROL_MAX_BYTES = 4096
CAPABILITY_BYTES = 32
FRAME_NONCE_BYTES = 16
SESSION_NONCE_BYTES = 32
KEY_BYTES = 32
COMMITMENT_RE = re.compile(r"sha256:v1:[0-9a-f]{64}\Z", re.ASCII)
CANONICAL_BARRIER_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z",
    re.ASCII,
)

EXIT_SUCCESS = 0
EXIT_RUNNER_ABORT = 65
EXIT_PROTOCOL_FAILURE = 66


def _as_bytes(value: str | bytes, *, label: str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        try:
            return value.encode("utf-8", "strict")
        except UnicodeEncodeError:
            _raise(ProtocolError, "PROTOCOL_FAILURE")
    _raise(ProtocolError, "PROTOCOL_FAILURE")
    raise AssertionError(label)


def LP(*parts: str | bytes) -> bytes:
    """Exact length-prefixed bytes/text helper used by bridge commitments."""

    result = bytearray()
    for part in parts:
        encoded = _as_bytes(part, label="length-prefixed field")
        if len(encoded) > 0xFFFFFFFF:
            _raise(ProtocolError, "FRAME_INVALID")
        result.extend(struct.pack("!I", len(encoded)))
        result.extend(encoded)
    return bytes(result)


def _bridge_digest(domain: str, *parts: str | bytes) -> bytes:
    return hashlib.sha256(LP("single-session-controller-bridge.v1", domain, *parts)).digest()


def bridge_commitment(domain: str, *parts: str | bytes) -> str:
    return "sha256:v1:" + _bridge_digest(domain, *parts).hex()


def _is_commitment(value: Any) -> bool:
    return isinstance(value, str) and COMMITMENT_RE.fullmatch(value) is not None


def _validate_key(value: Any, _label: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != KEY_BYTES or not any(value):
        _raise(ProtocolError, "FRAME_INVALID")
    return value


def _validate_nonce(value: Any, _label: str, size: int) -> bytes:
    if not isinstance(value, bytes) or len(value) != size or not any(value):
        _raise(ProtocolError, "FRAME_INVALID")
    return value


def _canonical_json_bytes(value: Any, *, max_bytes: int) -> bytes:
    def reject(child: Any) -> None:
        if isinstance(child, float):
            _raise(ProtocolError, "FRAME_INVALID")
        if isinstance(child, dict):
            for key, item in child.items():
                if not isinstance(key, str):
                    _raise(ProtocolError, "FRAME_INVALID")
                reject(item)
        elif isinstance(child, list):
            for item in child:
                reject(item)
        elif isinstance(child, str):
            try:
                child.encode("utf-8", "strict")
            except UnicodeEncodeError:
                _raise(ProtocolError, "FRAME_INVALID")
        elif child is not None and type(child) not in (str, int, bool):
            _raise(ProtocolError, "FRAME_INVALID")

    reject(value)
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeEncodeError):
        _raise(ProtocolError, "FRAME_INVALID")
    if len(encoded) > max_bytes:
        _raise(ProtocolError, "FRAME_INVALID")
    return encoded


def _parse_canonical_json(payload: bytes, *, max_bytes: int) -> Any:
    if not isinstance(payload, bytes) or not payload or len(payload) > max_bytes:
        _raise(ProtocolError, "FRAME_INVALID")
    try:
        text = payload.decode("utf-8", "strict")
    except UnicodeDecodeError:
        _raise(ProtocolError, "FRAME_INVALID")
    if text[:1] in " \t\r\n" or text[-1:] in " \t\r\n":
        _raise(ProtocolError, "FRAME_INVALID")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                _raise(ProtocolError, "FRAME_INVALID")
            result[key] = value
        return result

    try:
        decoder = json.JSONDecoder(
            object_pairs_hook=pairs,
            parse_constant=lambda _value: _raise(ProtocolError, "FRAME_INVALID"),
        )
        value, end = decoder.raw_decode(text)
    except (json.JSONDecodeError, RecursionError, ValueError, BridgeError):
        _raise(ProtocolError, "FRAME_INVALID")
    if end != len(text) or _canonical_json_bytes(value, max_bytes=max_bytes) != payload:
        _raise(ProtocolError, "FRAME_INVALID")
    return value


def validate_barrier_utc(value: Any) -> str:
    if not isinstance(value, str) or CANONICAL_BARRIER_RE.fullmatch(value) is None:
        _raise(ProtocolError, "BARRIER_INVALID")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        _raise(ProtocolError, "BARRIER_INVALID")
    canonical = parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if canonical != value or len(value.encode("ascii", "strict")) != 27:
        _raise(ProtocolError, "BARRIER_INVALID")
    return value


def _validate_discovery_tuple(execution_row_id: Any, artifact_filename: Any) -> tuple[int, str]:
    if type(execution_row_id) is not int or not 0 < execution_row_id <= 0x7FFFFFFFFFFFFFFF:
        _raise(ProtocolError, "DISCOVERY_INVALID")
    if type(artifact_filename) is not str:
        _raise(ProtocolError, "DISCOVERY_INVALID")
    try:
        encoded = artifact_filename.encode("utf-8", "strict")
    except UnicodeEncodeError:
        _raise(ProtocolError, "DISCOVERY_INVALID")
    if (
        not encoded
        or len(encoded) > 2048
        or artifact_filename in (".", "..")
        or "/" in artifact_filename
        or "\\" in artifact_filename
        or any(ord(char) <= 0x1F or ord(char) == 0x7F for char in artifact_filename)
    ):
        _raise(ProtocolError, "DISCOVERY_INVALID")
    return execution_row_id, artifact_filename


def _validate_control(value: Any, expected_type: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _raise(ProtocolError, "FRAME_INVALID")
    fields = {
        "READY": ("type", "version", "barrier_utc"),
        "DISCOVERY": (
            "type",
            "version",
            "execution_row_id",
            "artifact_filename",
            "isolation_state",
            "isolation_commitment",
        ),
        "PROCEED": ("type", "version", "artifact_commitment", "isolation_commitment", "grant"),
        "ABORT": ("type", "version", "code"),
        "RESULT": ("type", "version", "classification", "result_commitment"),
    }[expected_type]
    if tuple(value.keys()) != fields or value.get("type") != expected_type or value.get("version") != 1:
        _raise(ProtocolError, "FRAME_INVALID")
    if expected_type == "READY":
        validate_barrier_utc(value["barrier_utc"])
    elif expected_type == "DISCOVERY":
        _validate_discovery_tuple(value["execution_row_id"], value["artifact_filename"])
        if value["isolation_state"] != "PASS" or not _is_commitment(value["isolation_commitment"]):
            _raise(ProtocolError, "DISCOVERY_INVALID")
    elif expected_type == "PROCEED":
        if not _is_commitment(value["artifact_commitment"]) or not _is_commitment(value["isolation_commitment"]):
            _raise(ProtocolError, "PROCEED_INVALID")
        if not isinstance(value["grant"], str):
            _raise(ProtocolError, "PROCEED_INVALID")
        try:
            raw = base64.urlsafe_b64decode(value["grant"] + "===")
        except (ValueError, TypeError, binascii.Error):
            _raise(ProtocolError, "PROCEED_INVALID")
        if len(raw) != CAPABILITY_BYTES or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value["grant"]:
            _raise(ProtocolError, "PROCEED_INVALID")
    elif expected_type == "ABORT":
        try:
            RunnerControlCode(value["code"])
        except ValueError:
            _raise(ProtocolError, "FRAME_INVALID")
    elif expected_type == "RESULT":
        try:
            ResultClassification(value["classification"])
        except ValueError:
            _raise(ProtocolError, "FRAME_INVALID")
        if not _is_commitment(value["result_commitment"]):
            _raise(ProtocolError, "FRAME_INVALID")
    return value


def encode_hello(n_remote: bytes) -> bytes:
    n_remote = _validate_nonce(n_remote, "n_remote", SESSION_NONCE_BYTES)
    return HELLO_STRUCT.pack(HELLO_MAGIC, PROTOCOL_VERSION, HELLO_TYPE, n_remote)


def decode_hello(payload: bytes) -> bytes:
    if not isinstance(payload, bytes) or len(payload) != HELLO_SIZE:
        _raise(ProtocolError, "HELLO_INVALID")
    magic, version, kind, n_remote = HELLO_STRUCT.unpack(payload)
    if magic != HELLO_MAGIC or version != PROTOCOL_VERSION or kind != HELLO_TYPE:
        _raise(ProtocolError, "HELLO_INVALID")
    return _validate_nonce(n_remote, "n_remote", SESSION_NONCE_BYTES)


def encode_preamble(
    n_remote: bytes,
    n_local: bytes,
    n_session: bytes,
    epoch_digest: bytes,
    authority_digest: bytes,
    runner_digest: bytes,
    bundle_digest: bytes,
    bootstrap_seed: bytes,
) -> bytes:
    values = (
        _validate_nonce(n_remote, "n_remote", 32),
        _validate_nonce(n_local, "n_local", 32),
        _validate_nonce(n_session, "n_session", 32),
        _validate_nonce(epoch_digest, "epoch_digest", 32),
        _validate_nonce(authority_digest, "authority_digest", 32),
        _validate_nonce(runner_digest, "runner_digest", 32),
        _validate_nonce(bundle_digest, "bundle_digest", 32),
        _validate_nonce(bootstrap_seed, "bootstrap_seed", 32),
    )
    header = PREAMBLE_HEADER_STRUCT.pack(PREAMBLE_MAGIC, PROTOCOL_VERSION, PREAMBLE_TYPE, 0, PREAMBLE_BODY_SIZE)
    return header + PREAMBLE_BODY_STRUCT.pack(*values)


def decode_preamble(payload: bytes) -> dict[str, bytes]:
    if not isinstance(payload, bytes) or len(payload) != PREAMBLE_SIZE:
        _raise(ProtocolError, "PREAMBLE_INVALID")
    magic, version, kind, flags, body_size = PREAMBLE_HEADER_STRUCT.unpack(payload[: PREAMBLE_HEADER_STRUCT.size])
    if magic != PREAMBLE_MAGIC or version != PROTOCOL_VERSION or kind != PREAMBLE_TYPE or flags != 0 or body_size != PREAMBLE_BODY_SIZE:
        _raise(ProtocolError, "PREAMBLE_INVALID")
    raw = PREAMBLE_BODY_STRUCT.unpack(payload[PREAMBLE_HEADER_STRUCT.size :])
    values = dict(zip(PREAMBLE_FIELDS, raw))
    for name, value in values.items():
        _validate_nonce(value, name, 32)
    return values


def encode_boot_payload(bundle: "RunnerBundle", barrier_utc: str) -> bytes:
    validate_barrier_utc(barrier_utc)
    source = bundle.source
    digest = _bundle_digest_bytes(source)
    return BOOT_HEADER_STRUCT.pack(
        BOOT_MAGIC,
        PROTOCOL_VERSION,
        0,
        0,
        barrier_utc.encode("ascii", "strict"),
        digest,
        len(source),
    ) + source


def decode_boot_payload(payload: bytes, *, expected_barrier: str, expected_digest: bytes) -> bytes:
    if not isinstance(payload, bytes) or len(payload) < BOOT_HEADER_SIZE:
        _raise(ProtocolError, "FRAME_INVALID")
    try:
        magic, version, flags, reserved, barrier_bytes, digest, source_length = BOOT_HEADER_STRUCT.unpack(payload[:BOOT_HEADER_SIZE])
    except struct.error:
        _raise(ProtocolError, "FRAME_INVALID")
    if magic != BOOT_MAGIC or version != 1 or flags != 0 or reserved != 0:
        _raise(ProtocolError, "FRAME_INVALID")
    try:
        barrier = barrier_bytes.decode("ascii", "strict")
    except UnicodeDecodeError:
        _raise(ProtocolError, "FRAME_INVALID")
    validate_barrier_utc(barrier)
    if barrier != expected_barrier or digest != expected_digest:
        _raise(ProtocolError, "FRAME_INVALID")
    if source_length <= 0 or source_length > MAX_RUNNER_BUNDLE_BYTES or len(payload) != BOOT_HEADER_SIZE + source_length:
        _raise(ProtocolError, "FRAME_INVALID")
    source = payload[BOOT_HEADER_SIZE:]
    if _bundle_digest_bytes(source) != digest:
        _raise(ProtocolError, "FRAME_INVALID")
    return source


def encode_control(control: Mapping[str, Any]) -> bytes:
    if not isinstance(control, Mapping):
        _raise(ProtocolError, "FRAME_INVALID")
    message_type = control.get("type")
    if message_type not in ("READY", "DISCOVERY", "PROCEED", "ABORT", "RESULT"):
        _raise(ProtocolError, "FRAME_INVALID")
    value = dict(control)
    _validate_control(value, message_type)
    return _canonical_json_bytes(value, max_bytes=CONTROL_MAX_BYTES)


def decode_control(payload: bytes, expected_type: str | None = None) -> dict[str, Any]:
    value = _parse_canonical_json(payload, max_bytes=CONTROL_MAX_BYTES)
    if not isinstance(value, dict) or value.get("type") not in ("READY", "DISCOVERY", "PROCEED", "ABORT", "RESULT"):
        _raise(ProtocolError, "FRAME_INVALID")
    if expected_type is not None and value["type"] != expected_type:
        _raise(ProtocolError, "FRAME_INVALID")
    return _validate_control(value, value["type"])


def _frame_auth(key: bytes, header: bytes, payload: bytes) -> bytes:
    return hmac.new(_validate_key(key, "frame key"), header + payload, hashlib.sha256).digest()


def encode_authenticated_frame(
    key: bytes,
    direction: int,
    message: int,
    sequence: int,
    session_nonce: bytes,
    payload: bytes,
    *,
    frame_nonce: bytes | None = None,
) -> bytes:
    _validate_key(key, "frame key")
    if direction not in (DIRECTION_LOCAL_TO_REMOTE, DIRECTION_REMOTE_TO_LOCAL):
        _raise(ProtocolError, "FRAME_INVALID")
    if message not in MESSAGE_VALUES or type(sequence) is not int or not 1 <= sequence <= MAX_SESSION_FRAMES:
        _raise(ProtocolError, "FRAME_INVALID")
    session_nonce = _validate_nonce(session_nonce, "session nonce", SESSION_NONCE_BYTES)
    if not isinstance(payload, bytes) or len(payload) > MAX_AUTH_PAYLOAD_BYTES:
        _raise(ProtocolError, "FRAME_INVALID")
    if frame_nonce is None:
        frame_nonce = os.urandom(FRAME_NONCE_BYTES)
    frame_nonce = _validate_nonce(frame_nonce, "frame nonce", FRAME_NONCE_BYTES)
    header = AUTH_FRAME_HEADER_STRUCT.pack(
        AUTH_FRAME_MAGIC,
        PROTOCOL_VERSION,
        direction,
        message,
        FRAME_FLAGS,
        sequence,
        session_nonce,
        frame_nonce,
        len(payload),
    )
    frame = header + payload + _frame_auth(key, header, payload)
    if len(frame) > MAX_AUTH_FRAME_BYTES:
        _raise(ProtocolError, "FRAME_INVALID")
    return frame


@dataclass(frozen=True, repr=False)
class AuthenticatedFrame:
    direction: int
    message: int
    sequence: int
    session_nonce: bytes = field(repr=False)
    frame_nonce: bytes = field(repr=False)
    payload: bytes = field(repr=False)

    def __repr__(self) -> str:
        return f"AuthenticatedFrame(direction={self.direction}, message={self.message}, sequence={self.sequence}, payload_bytes={len(self.payload)})"


def decode_authenticated_frame(
    frame: bytes,
    key: bytes,
    *,
    expected_direction: int,
    expected_sequence: int,
    expected_session_nonce: bytes,
) -> AuthenticatedFrame:
    if not isinstance(frame, bytes) or len(frame) < AUTH_FRAME_OVERHEAD:
        _raise(ProtocolError, "FRAME_INVALID")
    try:
        header = frame[: AUTH_FRAME_HEADER_STRUCT.size]
        magic, version, direction, message, flags, sequence, session_nonce, frame_nonce, payload_length = AUTH_FRAME_HEADER_STRUCT.unpack(header)
    except struct.error:
        _raise(ProtocolError, "FRAME_INVALID")
    if (
        magic != AUTH_FRAME_MAGIC
        or version != PROTOCOL_VERSION
        or flags != FRAME_FLAGS
        or direction != expected_direction
        or message not in MESSAGE_VALUES
        or sequence != expected_sequence
        or session_nonce != expected_session_nonce
        or payload_length > MAX_AUTH_PAYLOAD_BYTES
        or len(frame) != AUTH_FRAME_OVERHEAD + payload_length
    ):
        _raise(ProtocolError, "FRAME_INVALID")
    payload_start = AUTH_FRAME_HEADER_STRUCT.size
    payload = frame[payload_start : payload_start + payload_length]
    if not hmac.compare_digest(frame[-AUTH_FRAME_TAG_SIZE:], _frame_auth(key, header, payload)):
        _raise(ProtocolError, "FRAME_INVALID")
    return AuthenticatedFrame(direction, message, sequence, session_nonce, frame_nonce, payload)


def _bundle_digest_bytes(source: bytes) -> bytes:
    return hashlib.sha256(LP("runner-bundle.v1", source)).digest()


def runner_bundle_commitment(source: bytes | str) -> str:
    if isinstance(source, str):
        source = source.encode("utf-8", "strict")
    return "sha256:v1:" + _bundle_digest_bytes(source).hex()


@dataclass(frozen=True, repr=False)
class RunnerBundle:
    source: bytes | str
    expected_commitment: str | None = None

    def __post_init__(self) -> None:
        source = self.source
        if isinstance(source, str):
            try:
                source = source.encode("utf-8", "strict")
            except UnicodeEncodeError:
                _raise(BundleError, "BUNDLE_NOT_UTF8")
        if not isinstance(source, bytes):
            _raise(BundleError, "BUNDLE_INVALID")
        if not source or len(source) > MAX_RUNNER_BUNDLE_BYTES:
            _raise(BundleError, "BUNDLE_OVERSIZED" if len(source) > MAX_RUNNER_BUNDLE_BYTES else "BUNDLE_INVALID")
        try:
            source.decode("utf-8", "strict")
        except UnicodeDecodeError:
            _raise(BundleError, "BUNDLE_NOT_UTF8")
        if self.expected_commitment is not None and (
            not _is_commitment(self.expected_commitment) or self.expected_commitment != runner_bundle_commitment(source)
        ):
            _raise(BundleError, "BUNDLE_COMMITMENT_MISMATCH")
        object.__setattr__(self, "source", source)

    @property
    def commitment(self) -> str:
        return runner_bundle_commitment(self.source)

    def __repr__(self) -> str:
        return f"RunnerBundle(commitment={self.commitment!r}, bytes={len(self.source)})"


def validate_runner_bundle(bundle: RunnerBundle) -> RunnerBundle:
    if not isinstance(bundle, RunnerBundle):
        _raise(BundleError, "BUNDLE_INVALID")
    try:
        compile(bundle.source.decode("utf-8", "strict"), "<runner-bundle>", "exec", dont_inherit=True)
    except (SyntaxError, ValueError, TypeError, UnicodeDecodeError):
        _raise(BundleError, "BUNDLE_COMPILE_FAILED")
    return bundle


def _derive_key(seed: bytes, domain: str, *parts: bytes) -> bytes:
    # Sibling derivations intentionally all use the same bootstrap seed. In
    # particular K_proceed is never derived from K_session.
    return hmac.new(seed, LP("bridge-key.v1", domain, *parts), hashlib.sha256).digest()


def _session_transcript(
    n_remote: bytes,
    n_local: bytes,
    n_session: bytes,
    epoch_digest: bytes,
    authority_digest: bytes,
    runner_digest: bytes,
    bundle_digest: bytes,
) -> tuple[bytes, ...]:
    return (n_remote, n_local, n_session, epoch_digest, authority_digest, runner_digest, bundle_digest)


@dataclass(frozen=True, repr=False)
class BridgeKeyGraph:
    n_remote: bytes = field(repr=False)
    n_local: bytes = field(repr=False)
    n_session: bytes = field(repr=False)
    epoch_digest: bytes = field(repr=False)
    authority_digest: bytes = field(repr=False)
    runner_digest: bytes = field(repr=False)
    bundle_digest: bytes = field(repr=False)
    bootstrap_seed: bytes = field(repr=False)
    k_boot: bytes = field(repr=False)
    k_session: bytes = field(repr=False)
    k_proceed: bytes = field(repr=False)

    def __repr__(self) -> str:
        return "BridgeKeyGraph(session_bound=True, secrets=opaque)"


def derive_key_graph_from_preamble(preamble: Mapping[str, bytes]) -> BridgeKeyGraph:
    values = {name: preamble[name] for name in PREAMBLE_FIELDS}
    for name, value in values.items():
        _validate_nonce(value, name, 32)
    transcript = _session_transcript(
        values["n_remote"], values["n_local"], values["n_session"], values["epoch_digest"],
        values["authority_digest"], values["runner_digest"], values["bundle_digest"],
    )
    seed = values["bootstrap_seed"]
    return BridgeKeyGraph(
        **values,
        k_boot=_derive_key(seed, "boot", *transcript),
        k_session=_derive_key(seed, "session", *transcript),
        k_proceed=_derive_key(seed, "proceed", *transcript),
    )


def derive_local_key_graph(
    *,
    spool_hmac_key: str,
    salt: str,
    epoch_ref: str,
    authority_ref: str,
    runner_identity: str,
    bundle: RunnerBundle,
    n_remote: bytes,
    n_local: bytes,
) -> BridgeKeyGraph:
    validate_runner_bundle(bundle)
    try:
        spool_key = spool_hmac_key.encode("utf-8", "strict")
    except UnicodeEncodeError:
        _raise(ProtocolError, "STORE_STATE_INVALID")
    if not spool_key:
        _raise(ProtocolError, "STORE_STATE_INVALID")
    n_remote = _validate_nonce(n_remote, "n_remote", 32)
    n_local = _validate_nonce(n_local, "n_local", 32)
    epoch_digest = _bridge_digest("epoch", epoch_ref)
    authority_digest = _bridge_digest("authority", authority_ref)
    runner_digest = _bridge_digest("runner", runner_identity)
    bundle_digest = _bundle_digest_bytes(bundle.source)
    seed = hmac.new(
        spool_key,
        LP(
            "bridge-bootstrap-seed.v1", salt, epoch_ref, authority_ref, n_remote, n_local,
            epoch_digest, authority_digest, runner_digest, bundle_digest,
        ),
        hashlib.sha256,
    ).digest()
    n_session = hmac.new(seed, LP("bridge-session-nonce.v1", n_remote, n_local), hashlib.sha256).digest()
    preamble = {
        "n_remote": n_remote,
        "n_local": n_local,
        "n_session": n_session,
        "epoch_digest": epoch_digest,
        "authority_digest": authority_digest,
        "runner_digest": runner_digest,
        "bundle_digest": bundle_digest,
        "bootstrap_seed": seed,
    }
    return derive_key_graph_from_preamble(preamble)


def proceed_commitment(graph: BridgeKeyGraph, artifact_commitment: str, isolation_commitment: str) -> str:
    if not _is_commitment(artifact_commitment) or not _is_commitment(isolation_commitment):
        _raise(ProtocolError, "PROCEED_INVALID")
    return bridge_commitment(
        "proceed-capability",
        *_session_transcript(
            graph.n_remote, graph.n_local, graph.n_session, graph.epoch_digest,
            graph.authority_digest, graph.runner_digest, graph.bundle_digest,
        ),
        artifact_commitment,
        isolation_commitment,
    )


def _grant_token(graph: BridgeKeyGraph, capability_commitment: str) -> bytes:
    return hmac.new(graph.k_proceed, LP("proceed-grant.v1", capability_commitment), hashlib.sha256).digest()


class ProceedGrant:
    """Opaque, session-bound, one-use runner capability."""

    __slots__ = ("_seal",)
    _SEAL = object()

    def __init__(self, seal: object | None = None):
        if seal is not self._SEAL:
            raise TypeError("opaque capability")
        self._seal = seal

    def __repr__(self) -> str:
        return "<ProceedGrant opaque>"

    def __str__(self) -> str:
        return "<ProceedGrant opaque>"

    def __copy__(self) -> "ProceedGrant":
        raise TypeError("opaque capability")

    def __deepcopy__(self, _memo: dict[int, Any]) -> "ProceedGrant":
        raise TypeError("opaque capability")

    def __reduce__(self) -> Any:
        raise TypeError("opaque capability")


@dataclass(frozen=True)
class DummyDecision:
    proceed: bool
    abort_code: RunnerControlCode | None = None

    def __post_init__(self) -> None:
        if type(self.proceed) is not bool:
            raise TypeError("proceed must be bool")
        code = self.abort_code
        if code is not None and not isinstance(code, RunnerControlCode):
            code = RunnerControlCode(code)
            object.__setattr__(self, "abort_code", code)
        if self.proceed and code is not None:
            raise ValueError("proceed decision cannot contain abort")
        if not self.proceed and code is None:
            object.__setattr__(self, "abort_code", RunnerControlCode.LOCAL_ABORT)

    @classmethod
    def allow(cls) -> "DummyDecision":
        return cls(True)

    @classmethod
    def deny(cls, code: RunnerControlCode = RunnerControlCode.LOCAL_ABORT) -> "DummyDecision":
        return cls(False, code)


@dataclass(frozen=True)
class DummyOutcome:
    classification: ResultClassification
    result_commitment: str

    def __post_init__(self) -> None:
        classification = self.classification
        if not isinstance(classification, ResultClassification):
            classification = ResultClassification(classification)
            object.__setattr__(self, "classification", classification)
        if not _is_commitment(self.result_commitment):
            raise ValueError("result commitment must be opaque")


@dataclass
class BridgeCounters:
    ssh_launches: int = 0
    network_connections: int = 0
    provider_calls: int = 0
    backup_calls: int = 0
    restore_attempts: int = 0
    bind_calls: int = 0
    proceed_messages: int = 0
    discovery_messages: int = 0
    result_messages: int = 0

    def public(self) -> dict[str, int]:
        return dataclasses.asdict(self)


@dataclass(frozen=True, repr=False)
class BridgeResult:
    classification: str
    state: str
    error_code: str | None
    projection: Mapping[str, Any] | None
    counters: BridgeCounters
    post_cas_uncertain: bool = False

    def __repr__(self) -> str:
        return f"BridgeResult(classification={self.classification!r}, state={self.state!r}, error_code={self.error_code!r}, post_cas_uncertain={self.post_cas_uncertain})"


# ---------------------------------------------------------------------------
# Explicit sibling imports. No path-search fallback is permitted.

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_STORE_PATH = _REPO_ROOT / "scripts" / "platform-recovery-controller-store.py"
_LOCATOR_PATH = _REPO_ROOT / "scripts" / "platform-persisted-locator-adapter.py"
STORE_IMPORT_SYMBOLS = ("ControllerStore", "ControllerStoreError", "V2EpochSnapshot", "recovery_commitment")
LOCATOR_IMPORT_SYMBOLS = ("validate_barrier_utc",)


def _load_sibling(path: pathlib.Path, module_name: str, symbols: Sequence[str]) -> types.ModuleType:
    if path not in (_STORE_PATH, _LOCATOR_PATH) or not path.is_file():
        _raise(BridgeError, "STORE_IMPORT_FAILED")
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        _raise(BridgeError, "STORE_IMPORT_FAILED")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
        for symbol in symbols:
            if not hasattr(module, symbol):
                _raise(BridgeError, "STORE_IMPORT_FAILED")
    except BridgeError:
        raise
    except Exception:
        _raise(BridgeError, "STORE_IMPORT_FAILED")
    return module


STORE = _load_sibling(_STORE_PATH, "platform_recovery_controller_store_bridge", STORE_IMPORT_SYMBOLS)
LOCATOR = _load_sibling(_LOCATOR_PATH, "platform_persisted_locator_adapter_bridge", LOCATOR_IMPORT_SYMBOLS)


def _validate_canonical_barrier(value: str) -> str:
    try:
        sibling_value = LOCATOR.validate_barrier_utc(value)
    except Exception:
        _raise(ProtocolError, "BARRIER_INVALID")
    if sibling_value != validate_barrier_utc(value):
        _raise(ProtocolError, "BARRIER_INVALID")
    return sibling_value


# ---------------------------------------------------------------------------
# Runner runtime and guarded loader

class _ForbiddenTextStream(io.TextIOBase):
    def __init__(self, code: RunnerControlCode):
        self._code = code
        self.buffer = self

    def write(self, _value: Any) -> int:
        raise RunnerControlError(self._code)

    def flush(self) -> None:
        raise RunnerControlError(self._code)

    def read(self, _size: int = -1) -> str:
        raise RunnerControlError(self._code)

    def fileno(self) -> int:
        raise RunnerControlError(self._code)

    @property
    def encoding(self) -> str:
        return "utf-8"


class _FDOutputCapture:
    def __init__(self, limit: int):
        self.limit = limit
        self.bytes_seen = 0
        self.overflow = False
        self._lock = threading.Lock()

    def add(self, payload: bytes) -> None:
        with self._lock:
            self.bytes_seen += len(payload)
            if self.bytes_seen > self.limit:
                self.overflow = True


def _drain_fd(fd: int, capture: _FDOutputCapture) -> None:
    try:
        while True:
            payload = os.read(fd, 4096)
            if not payload:
                return
            capture.add(payload)
    except OSError:
        return
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


@contextlib.contextmanager
def runner_stdio_isolation(*, capture_fds: bool) -> Any:
    old_stdout, old_stderr, old_stdin = sys.stdout, sys.stderr, sys.stdin
    saved: list[int] = []
    reader_threads: list[threading.Thread] = []
    captures = (_FDOutputCapture(4096), _FDOutputCapture(4096))
    try:
        if capture_fds:
            saved = [os.dup(0), os.dup(1), os.dup(2)]
            out_read, out_write = os.pipe()
            err_read, err_write = os.pipe()
            for fd, capture in ((out_read, captures[0]), (err_read, captures[1])):
                thread = threading.Thread(target=_drain_fd, args=(fd, capture), daemon=True)
                thread.start()
                reader_threads.append(thread)
            null_fd = os.open(os.devnull, os.O_RDONLY)
            os.dup2(null_fd, 0)
            os.close(null_fd)
            os.dup2(out_write, 1)
            os.dup2(err_write, 2)
            os.close(out_write)
            os.close(err_write)
        sys.stdout = _ForbiddenTextStream(RunnerControlCode.RUNNER_STDOUT_FORBIDDEN)
        sys.stderr = _ForbiddenTextStream(RunnerControlCode.RUNNER_STDERR_FORBIDDEN)
        sys.stdin = _ForbiddenTextStream(RunnerControlCode.RUNNER_INPUT_FORBIDDEN)
        yield
    finally:
        sys.stdout, sys.stderr, sys.stdin = old_stdout, old_stderr, old_stdin
        if capture_fds and saved:
            for target, source in ((0, saved[0]), (1, saved[1]), (2, saved[2])):
                try:
                    os.dup2(source, target)
                except OSError:
                    pass
            for source in saved:
                try:
                    os.close(source)
                except OSError:
                    pass
            for thread in reader_threads:
                thread.join(timeout=1.0)
            if captures[0].bytes_seen or captures[0].overflow:
                raise RunnerControlError(RunnerControlCode.RUNNER_STDOUT_FORBIDDEN)
            if captures[1].bytes_seen or captures[1].overflow:
                raise RunnerControlError(RunnerControlCode.RUNNER_STDERR_FORBIDDEN)


def _validate_subprocess_options(options: dict[str, Any], *, check_output: bool = False) -> None:
    required = ("stdin", "stderr") if check_output else ("stdin", "stdout", "stderr")
    if any(name not in options or options[name] is None for name in required):
        _raise(RunnerControlError, RunnerControlCode.SUBPROCESS_STDIO_REQUIRED)
    if options.get("shell", False) is not False or options.get("close_fds", True) is not True:
        _raise(RunnerControlError, RunnerControlCode.SUBPROCESS_STDIO_REQUIRED)
    if options.get("pass_fds", ()) not in ((), []):
        _raise(RunnerControlError, RunnerControlCode.SUBPROCESS_STDIO_REQUIRED)
    if options.get("capture_output", False):
        _raise(RunnerControlError, RunnerControlCode.SUBPROCESS_STDIO_REQUIRED)


class _GuardedSubprocessModule:
    PIPE = _subprocess.PIPE
    DEVNULL = _subprocess.DEVNULL
    STDOUT = _subprocess.STDOUT
    TimeoutExpired = _subprocess.TimeoutExpired
    CompletedProcess = _subprocess.CompletedProcess

    @staticmethod
    def Popen(args: Any, *positional: Any, **options: Any) -> Any:
        if positional:
            _raise(RunnerControlError, RunnerControlCode.SUBPROCESS_STDIO_REQUIRED)
        _validate_subprocess_options(options)
        return _subprocess.Popen(args, **options)

    @staticmethod
    def run(args: Any, *positional: Any, **options: Any) -> Any:
        if positional:
            _raise(RunnerControlError, RunnerControlCode.SUBPROCESS_STDIO_REQUIRED)
        _validate_subprocess_options(options)
        return _subprocess.run(args, **options)

    @staticmethod
    def check_output(args: Any, *positional: Any, **options: Any) -> Any:
        if positional:
            _raise(RunnerControlError, RunnerControlCode.SUBPROCESS_STDIO_REQUIRED)
        _validate_subprocess_options(options, check_output=True)
        options["stdout"] = _subprocess.PIPE
        return _subprocess.check_output(args, **options)


_GUARDED_SUBPROCESS = _GuardedSubprocessModule()


def _guarded_import(name: str, globals_: Any = None, locals_: Any = None, fromlist: Any = (), level: int = 0) -> Any:
    if level != 0 or not isinstance(name, str) or name.split(".", 1)[0] not in RUNNER_IMPORT_ROOTS:
        raise ImportError("RUNNER_IMPORT_FORBIDDEN")
    if name.split(".", 1)[0] == "subprocess":
        return _GUARDED_SUBPROCESS
    return builtins.__import__(name, globals_, locals_, fromlist, level)


def _runner_namespace() -> dict[str, Any]:
    runner_builtins = dict(vars(builtins))
    runner_builtins["__import__"] = _guarded_import
    return {
        "__name__": "__runner_bundle__",
        "__builtins__": runner_builtins,
        "RunnerAbortCode": RunnerAbortCode,
        "RunnerControlCode": RunnerControlCode,
        "ResultClassification": ResultClassification,
    }


def _validate_run_callable(value: Any) -> None:
    if value is None:
        _raise(RunnerControlError, RunnerControlCode.RUNNER_MISSING)
    if not callable(value):
        _raise(RunnerControlError, RunnerControlCode.RUNNER_NOT_CALLABLE)
    if inspect.iscoroutinefunction(value) or inspect.isasyncgenfunction(value):
        _raise(RunnerControlError, RunnerControlCode.RUNNER_SIGNATURE_INVALID)
    try:
        signature = inspect.signature(value)
    except (TypeError, ValueError):
        _raise(RunnerControlError, RunnerControlCode.RUNNER_SIGNATURE_INVALID)
    parameters = list(signature.parameters.values())
    if (
        len(parameters) != 1
        or parameters[0].kind not in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        or parameters[0].default is not inspect.Parameter.empty
    ):
        _raise(RunnerControlError, RunnerControlCode.RUNNER_SIGNATURE_INVALID)


class _RemoteChannel:
    def __init__(self, reader: BinaryIO, writer: BinaryIO, graph: BridgeKeyGraph):
        self.reader = reader
        self.writer = writer
        self.graph = graph
        self.sequence = 1
        self.bytes_seen = 0
        self._read_lock = threading.Lock()

    def _read_chunk_with_timeout(self, size: int, timeout: float | None) -> bytes:
        if timeout is None:
            return self.reader.read(size)
        if timeout <= 0:
            _raise(RunnerControlError, RunnerControlCode.DECISION_TIMEOUT)
        result: queue.Queue[tuple[bytes | None, BaseException | None]] = queue.Queue(maxsize=1)

        def read_once() -> None:
            try:
                result.put((self.reader.read(size), None))
            except BaseException as error:
                result.put((None, error))

        thread = threading.Thread(target=read_once, daemon=True)
        thread.start()
        try:
            chunk, error = result.get(timeout=timeout)
        except queue.Empty:
            _raise(RunnerControlError, RunnerControlCode.DECISION_TIMEOUT)
        if error is not None:
            raise error
        return chunk or b""

    def _read_exact(self, size: int, *, timeout: float | None = None) -> bytes:
        chunks = bytearray()
        deadline = None if timeout is None else time.monotonic() + timeout
        while len(chunks) < size:
            remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
            chunk = self._read_chunk_with_timeout(size - len(chunks), remaining)
            if not chunk:
                _raise(RunnerControlError, RunnerControlCode.DECISION_EOF)
            chunks.extend(chunk)
        return bytes(chunks)

    def _read_frame(self, key: bytes, direction: int, timeout: float | None = None) -> AuthenticatedFrame:
        with self._read_lock:
            header = self._read_exact(AUTH_FRAME_HEADER_STRUCT.size, timeout=timeout)
        try:
            values = AUTH_FRAME_HEADER_STRUCT.unpack(header)
        except struct.error:
            _raise(RunnerControlError, RunnerControlCode.PROTOCOL_FAILURE)
        length = values[-1]
        if length > MAX_AUTH_PAYLOAD_BYTES:
            _raise(RunnerControlError, RunnerControlCode.PROTOCOL_FAILURE)
        raw = header + self._read_exact(length + AUTH_FRAME_TAG_SIZE, timeout=timeout)
        try:
            frame = decode_authenticated_frame(
                raw, key, expected_direction=direction, expected_sequence=self.sequence,
                expected_session_nonce=self.graph.n_session,
            )
        except BridgeError:
            _raise(RunnerControlError, RunnerControlCode.PROTOCOL_FAILURE)
        self.sequence += 1
        self.bytes_seen += len(raw)
        if self.bytes_seen > MAX_SESSION_BYTES:
            _raise(RunnerControlError, RunnerControlCode.PROTOCOL_FAILURE)
        return frame

    def send(self, key: bytes, direction: int, message: int, payload: bytes) -> None:
        frame = encode_authenticated_frame(key, direction, message, self.sequence, self.graph.n_session, payload)
        try:
            self.writer.write(frame)
            self.writer.flush()
        except (BrokenPipeError, OSError):
            _raise(RunnerControlError, RunnerControlCode.PROTOCOL_BROKEN_PIPE)
        self.sequence += 1
        self.bytes_seen += len(frame)
        if self.bytes_seen > MAX_SESSION_BYTES:
            _raise(RunnerControlError, RunnerControlCode.PROTOCOL_FAILURE)

    def receive(self, key: bytes, direction: int, *, timeout: float | None = None) -> AuthenticatedFrame:
        return self._read_frame(key, direction, timeout=timeout)


class RunnerRuntime:
    """Exact capability surface visible to ``run(runtime)``."""

    INITIAL = "INITIAL"
    RUNNING = "RUNNING"
    WAITING_DECISION = "WAITING_DECISION"
    PROCEED_GRANTED = "PROCEED_GRANTED"
    RESULT_SENT = "RESULT_SENT"
    TERMINAL = "TERMINAL"

    def __init__(self, channel: _RemoteChannel, barrier_utc: str, *, decision_timeout: float = 5.0):
        self._channel = channel
        self._barrier_utc = _validate_canonical_barrier(barrier_utc)
        self._decision_timeout = decision_timeout
        self._state = self.INITIAL
        self._owner_marker = object()
        self._grant_records: dict[int, tuple[ProceedGrant, bytes, str, str]] = {}
        self._terminal_frame_sent = False
        self._discovery_sent = False

    @property
    def state(self) -> str:
        return self._state

    @property
    def barrier_utc(self) -> str:
        return self._barrier_utc

    def _send_abort(self, code: RunnerControlCode) -> None:
        if self._terminal_frame_sent:
            return
        self._channel.send(
            self._channel.graph.k_session,
            DIRECTION_REMOTE_TO_LOCAL,
            MESSAGE_ABORT,
            encode_control({"type": "ABORT", "version": 1, "code": code.value}),
        )
        self._terminal_frame_sent = True
        self._state = self.TERMINAL

    def send_discovery(self, execution_row_id: int, artifact_filename: str, isolation_state: str, isolation_commitment: str) -> None:
        if self._discovery_sent:
            _raise(RunnerControlError, RunnerControlCode.DISCOVERY_DUPLICATE)
        if self._state not in (self.INITIAL, self.RUNNING):
            _raise(RunnerControlError, RunnerControlCode.RUNTIME_TERMINAL)
        try:
            execution_row_id, artifact_filename = _validate_discovery_tuple(execution_row_id, artifact_filename)
        except BridgeError:
            _raise(RunnerControlError, RunnerControlCode.PROTOCOL_FAILURE)
        if isolation_state != "PASS" or not _is_commitment(isolation_commitment):
            _raise(RunnerControlError, RunnerControlCode.PROTOCOL_FAILURE)
        payload = encode_control(
            {
                "type": "DISCOVERY",
                "version": 1,
                "execution_row_id": execution_row_id,
                "artifact_filename": artifact_filename,
                "isolation_state": isolation_state,
                "isolation_commitment": isolation_commitment,
            }
        )
        try:
            self._channel.send(self._channel.graph.k_session, DIRECTION_REMOTE_TO_LOCAL, MESSAGE_DISCOVERY, payload)
        except (BrokenPipeError, OSError):
            _raise(RunnerControlError, RunnerControlCode.PROTOCOL_BROKEN_PIPE)
        self._discovery_sent = True
        self._state = self.WAITING_DECISION

    def wait_for_decision(self) -> ProceedGrant:
        if not self._discovery_sent or self._state != self.WAITING_DECISION:
            _raise(RunnerControlError, RunnerControlCode.RUNTIME_TERMINAL)
        try:
            frame = self._channel.receive(
                self._channel.graph.k_session,
                DIRECTION_LOCAL_TO_REMOTE,
                timeout=self._decision_timeout,
            )
        except RunnerControlError:
            raise
        except (BrokenPipeError, OSError):
            _raise(RunnerControlError, RunnerControlCode.DECISION_BROKEN_PIPE)
        except TimeoutError:
            _raise(RunnerControlError, RunnerControlCode.DECISION_TIMEOUT)
        if frame.message == MESSAGE_ABORT:
            value = decode_control(frame.payload, "ABORT")
            code = RunnerControlCode(value["code"])
            self._terminal_frame_sent = True
            self._state = self.TERMINAL
            raise RunnerControlError(code)
        if frame.message != MESSAGE_PROCEED:
            _raise(RunnerControlError, RunnerControlCode.PROCEED_INVALID)
        value = decode_control(frame.payload, "PROCEED")
        capability = proceed_commitment(self._channel.graph, value["artifact_commitment"], value["isolation_commitment"])
        raw_token = base64.urlsafe_b64decode(value["grant"] + "===")
        if not hmac.compare_digest(raw_token, _grant_token(self._channel.graph, capability)):
            _raise(RunnerControlError, RunnerControlCode.PROCEED_INVALID)
        grant = ProceedGrant(ProceedGrant._SEAL)
        self._grant_records[id(grant)] = (grant, raw_token, value["artifact_commitment"], value["isolation_commitment"])
        self._state = self.PROCEED_GRANTED
        return grant

    def send_result(self, grant: ProceedGrant, classification: ResultClassification | str, result_commitment: str) -> None:
        if self._state == self.RESULT_SENT:
            _raise(RunnerControlError, RunnerControlCode.RESULT_DUPLICATE)
        if self._state != self.PROCEED_GRANTED:
            _raise(RunnerControlError, RunnerControlCode.RESULT_BEFORE_PROCEED)
        if type(grant) is not ProceedGrant or id(grant) not in self._grant_records or self._grant_records[id(grant)][0] is not grant:
            _raise(RunnerControlError, RunnerControlCode.PROCEED_INVALID)
        try:
            classification = ResultClassification(classification)
        except (ValueError, TypeError):
            _raise(RunnerControlError, RunnerControlCode.PROTOCOL_FAILURE)
        if not _is_commitment(result_commitment):
            _raise(RunnerControlError, RunnerControlCode.PROTOCOL_FAILURE)
        del self._grant_records[id(grant)]
        try:
            self._channel.send(
                self._channel.graph.k_session,
                DIRECTION_REMOTE_TO_LOCAL,
                MESSAGE_RESULT,
                encode_control({"type": "RESULT", "version": 1, "classification": classification.value, "result_commitment": result_commitment}),
            )
        except (BrokenPipeError, OSError):
            _raise(RunnerControlError, RunnerControlCode.PROTOCOL_BROKEN_PIPE)
        self._terminal_frame_sent = True
        self._state = self.RESULT_SENT

    def abort(self, code: RunnerAbortCode) -> None:
        if not isinstance(code, RunnerAbortCode):
            raise TypeError("RunnerRuntime.abort accepts RunnerAbortCode")
        if self._terminal_frame_sent:
            _raise(RunnerControlError, RunnerControlCode.RUNTIME_TERMINAL)
        control = RunnerControlCode(code.value)
        self._send_abort(control)
        raise RunnerControlError(control)


class RemoteLoader:
    """Fixed loader state machine used by the local dummy child."""

    def __init__(self, reader: BinaryIO, writer: BinaryIO, *, capture_fds: bool = False):
        self._raw_reader = reader
        self._raw_writer = writer
        self._capture_fds = capture_fds
        self._protocol_reader = reader
        self._protocol_writer = writer
        self._owned_streams: list[BinaryIO] = []
        if capture_fds:
            try:
                reader_fd = os.dup(reader.fileno())
                writer_fd = os.dup(writer.fileno())
                self._protocol_reader = os.fdopen(reader_fd, "rb", buffering=0)
                self._protocol_writer = os.fdopen(writer_fd, "wb", buffering=0)
                self._owned_streams = [self._protocol_reader, self._protocol_writer]
            except (AttributeError, OSError):
                _raise(ProtocolError, "PROTOCOL_FAILURE")
        self._terminal_sent = False

    def _read_exact(self, size: int) -> bytes:
        payload = bytearray()
        while len(payload) < size:
            chunk = self._protocol_reader.read(size - len(payload))
            if not chunk:
                _raise(ProtocolError, "PROCESS_EOF")
            payload.extend(chunk)
        return bytes(payload)

    def _send_raw(self, payload: bytes) -> None:
        try:
            self._protocol_writer.write(payload)
            self._protocol_writer.flush()
        except (BrokenPipeError, OSError):
            _raise(ProtocolError, "PROTOCOL_BROKEN_PIPE")

    def _send_abort(self, channel: _RemoteChannel, code: RunnerControlCode) -> None:
        if self._terminal_sent:
            return
        try:
            channel.send(
                channel.graph.k_session,
                DIRECTION_REMOTE_TO_LOCAL,
                MESSAGE_ABORT,
                encode_control({"type": "ABORT", "version": 1, "code": code.value}),
            )
        except BridgeError:
            pass
        self._terminal_sent = True

    def run(self) -> int:
        n_remote = os.urandom(32)
        self._send_raw(encode_hello(n_remote))
        channel: _RemoteChannel | None = None
        try:
            preamble = decode_preamble(self._read_exact(PREAMBLE_SIZE))
            graph = derive_key_graph_from_preamble(preamble)
            channel = _RemoteChannel(self._protocol_reader, self._protocol_writer, graph)
            boot_frame = channel.receive(graph.k_boot, DIRECTION_LOCAL_TO_REMOTE)
            if boot_frame.message != MESSAGE_BOOT:
                _raise(ProtocolError, "FRAME_INVALID")
            barrier = self._extract_barrier(boot_frame.payload)
            source = decode_boot_payload(boot_frame.payload, expected_barrier=barrier, expected_digest=graph.bundle_digest)
            bundle = RunnerBundle(source, expected_commitment="sha256:v1:" + graph.bundle_digest.hex())
            validate_runner_bundle(bundle)
            runtime = RunnerRuntime(channel, barrier)
            namespace = _runner_namespace()
            pending_error: RunnerControlError | None = None
            try:
                with runner_stdio_isolation(capture_fds=self._capture_fds):
                    try:
                        # BOOT authentication and commitment verification completed
                        # before this source execution.
                        exec(compile(source.decode("utf-8", "strict"), "<runner-bundle>", "exec", dont_inherit=True), namespace, namespace)
                        if "run" not in namespace:
                            _raise(RunnerControlError, RunnerControlCode.RUNNER_MISSING)
                        _validate_run_callable(namespace["run"])
                        channel.send(
                            graph.k_session,
                            DIRECTION_REMOTE_TO_LOCAL,
                            MESSAGE_READY,
                            encode_control({"type": "READY", "version": 1, "barrier_utc": runtime.barrier_utc}),
                        )
                        runtime._state = RunnerRuntime.RUNNING
                        returned = namespace["run"](runtime)
                        if runtime._state == RunnerRuntime.RESULT_SENT:
                            if returned is not None:
                                _raise(RunnerControlError, RunnerControlCode.RUNNER_NON_NONE_RETURN)
                            self._terminal_sent = True
                        elif runtime._state != RunnerRuntime.TERMINAL:
                            _raise(RunnerControlError, RunnerControlCode.RUNNER_NO_RESULT if returned is None else RunnerControlCode.RUNNER_NON_NONE_RETURN)
                    except RunnerControlError as error:
                        pending_error = error
                    except BaseException:
                        pending_error = RunnerControlError(RunnerControlCode.RUNNER_TOP_LEVEL_EXCEPTION)
            except RunnerControlError as error:
                pending_error = error
            if pending_error is not None:
                if not runtime._terminal_frame_sent:
                    self._send_abort(channel, pending_error.code)
                return EXIT_RUNNER_ABORT
            return EXIT_SUCCESS if self._terminal_sent or runtime._state == RunnerRuntime.RESULT_SENT else EXIT_RUNNER_ABORT
        except RunnerControlError as error:
            if channel is not None and not self._terminal_sent:
                self._send_abort(channel, error.code)
            return EXIT_RUNNER_ABORT
        except BridgeError:
            return EXIT_PROTOCOL_FAILURE
        except Exception:
            return EXIT_PROTOCOL_FAILURE
        finally:
            for stream in self._owned_streams:
                try:
                    stream.close()
                except OSError:
                    pass

    @staticmethod
    def _extract_barrier(payload: bytes) -> str:
        if len(payload) < BOOT_HEADER_SIZE:
            _raise(ProtocolError, "FRAME_INVALID")
        try:
            barrier = BOOT_HEADER_STRUCT.unpack(payload[:BOOT_HEADER_SIZE])[4].decode("ascii", "strict")
        except (struct.error, UnicodeDecodeError):
            _raise(ProtocolError, "FRAME_INVALID")
        return _validate_canonical_barrier(barrier)


# A fixed loader is public source only. It contains no private store values,
# runner bytes, paths, credentials, keys, or transport target. It is an
# in-memory entrypoint that the bridge module can embed; the dummy child uses
# the same RemoteLoader directly. A future live authority may use the fixed
# command only under its own separately authorised launch wrapper.
FIXED_LOADER_SOURCE = (
    "def fixed_loader_entrypoint(reader, writer):\n"
    "    return RemoteLoader(reader, writer, capture_fds=True).run()\n"
)
FIXED_LOADER_MAX_BYTES = 4096


def build_fixed_loader_source() -> bytes:
    source = FIXED_LOADER_SOURCE.encode("ascii", "strict")
    if len(source) > FIXED_LOADER_MAX_BYTES:
        _raise(ProtocolError, "FRAME_INVALID")
    return source


def build_fixed_loader_command() -> tuple[str, str, str]:
    return (sys.executable, str(pathlib.Path(__file__).resolve()), "--dummy-child")


# ---------------------------------------------------------------------------
# Windows-safe local process supervision and controller/store integration

class _BoundedCapture:
    def __init__(self, limit: int):
        self.limit = limit
        self.data_seen = 0
        self.overflow = False
        self._lock = threading.Lock()

    def add(self, payload: bytes) -> None:
        with self._lock:
            self.data_seen += len(payload)
            if self.data_seen > self.limit:
                self.overflow = True


class ProcessSupervisor:
    """Dedicated reader threads + queue, safe for Windows anonymous pipes."""

    def __init__(self, process: Any, *, max_capture_bytes: int = 4096):
        self.process = process
        self.stdout_queue: queue.Queue[tuple[str, bytes | None]] = queue.Queue(maxsize=32)
        self.stderr_capture = _BoundedCapture(max_capture_bytes)
        self.stderr_done = threading.Event()
        self.stdout_done = threading.Event()
        self._stdout_buffer = bytearray()
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        for name, stream, done in (("stdout", self.process.stdout, self.stdout_done), ("stderr", self.process.stderr, self.stderr_done)):
            thread = threading.Thread(target=self._reader, args=(name, stream, done), daemon=True)
            thread.start()
            self._threads.append(thread)

    def _reader(self, name: str, stream: Any, done: threading.Event) -> None:
        try:
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    if name == "stdout":
                        self.stdout_queue.put((name, None))
                    return
                if name == "stderr":
                    self.stderr_capture.add(chunk)
                else:
                    self.stdout_queue.put((name, chunk))
        except (OSError, ValueError):
            if name == "stdout":
                try:
                    self.stdout_queue.put((name, None))
                except Exception:
                    pass
        finally:
            done.set()

    def read_exact(self, size: int, deadline: float) -> bytes:
        while len(self._stdout_buffer) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _raise(BridgeError, "PROCESS_TIMEOUT")
            try:
                name, chunk = self.stdout_queue.get(timeout=min(remaining, 0.25))
            except queue.Empty:
                if self.process.poll() is not None and self.stdout_done.is_set():
                    _raise(BridgeError, "PROCESS_EOF")
                continue
            if name != "stdout":
                continue
            if chunk is None:
                _raise(BridgeError, "PROCESS_EOF")
            self._stdout_buffer.extend(chunk)
        result = bytes(self._stdout_buffer[:size])
        del self._stdout_buffer[:size]
        return result

    def write_all(self, payload: bytes, deadline: float) -> None:
        if not isinstance(payload, bytes):
            _raise(BridgeError, "PROTOCOL_FAILURE")
        written = 0
        while written < len(payload):
            if time.monotonic() >= deadline:
                _raise(BridgeError, "PROCESS_TIMEOUT")
            try:
                count = self.process.stdin.write(payload[written:])
                if count is None or count <= 0:
                    _raise(BridgeError, "PROTOCOL_BROKEN_PIPE")
                written += count
            except (BrokenPipeError, OSError, ValueError):
                _raise(BridgeError, "PROTOCOL_BROKEN_PIPE")
        try:
            self.process.stdin.flush()
        except (BrokenPipeError, OSError, ValueError):
            _raise(BridgeError, "PROTOCOL_BROKEN_PIPE")

    def stop(self) -> None:
        try:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=0.5)
                except (_subprocess.TimeoutExpired, OSError):
                    self.process.kill()
        except (OSError, ValueError):
            pass
        for stream in (getattr(self.process, "stdin", None), getattr(self.process, "stdout", None), getattr(self.process, "stderr", None)):
            try:
                if stream is not None:
                    stream.close()
            except (OSError, ValueError):
                pass
        for thread in self._threads:
            thread.join(timeout=1.0)


def spawn_dummy_child() -> Any:
    """Spawn only the repository-local synthetic loader; never SSH."""

    return _subprocess.Popen(
        [sys.executable, str(pathlib.Path(__file__).resolve()), "--dummy-child"],
        stdin=_subprocess.PIPE,
        stdout=_subprocess.PIPE,
        stderr=_subprocess.PIPE,
        close_fds=True,
        bufsize=0,
        shell=False,
    )


class ControllerBridge:
    def __init__(
        self,
        store: Any,
        epoch_ref: str,
        barrier_utc: str,
        runner_bundle: RunnerBundle,
        *,
        process_factory: Callable[[], Any] | None = None,
        decision: DummyDecision | None = None,
        counters: BridgeCounters | None = None,
        timeout_seconds: float = 5.0,
    ):
        self.store = store
        self.epoch_ref = epoch_ref
        self.barrier_utc = _validate_canonical_barrier(barrier_utc)
        self.runner_bundle = validate_runner_bundle(runner_bundle)
        self.process_factory = process_factory or spawn_dummy_child
        self.decision = decision or DummyDecision.allow()
        self.counters = counters or BridgeCounters()
        self.timeout_seconds = timeout_seconds
        self._graph: BridgeKeyGraph | None = None
        self._supervisor: ProcessSupervisor | None = None
        self._session_cursor = 1
        self._post_cas = False

    def _load_initial_snapshot(self) -> Any:
        try:
            snapshot = self.store.load_epoch(self.epoch_ref)
        except Exception:
            _raise(BridgeError, "STORE_STATE_INVALID")
        if not isinstance(snapshot, STORE.V2EpochSnapshot):
            _raise(BridgeError, "STORE_STATE_INVALID")
        if (
            snapshot.record["state"] != "INITIALISED"
            or snapshot.record["artifact_binding_state"] != "PENDING"
            or snapshot.ledger["state"] != "UNCONSUMED"
            or snapshot.spool["state"] != "OPEN"
            or snapshot.spool["last_stage"] != "NONE"
        ):
            _raise(BridgeError, "STORE_STATE_INVALID")
        return snapshot

    def _send(self, key: bytes, direction: int, message: int, payload: bytes, deadline: float) -> None:
        assert self._supervisor is not None and self._graph is not None
        frame = encode_authenticated_frame(key, direction, message, self._session_cursor, self._graph.n_session, payload)
        self._supervisor.write_all(frame, deadline)
        self._session_cursor += 1

    def _receive(self, key: bytes, direction: int, deadline: float) -> AuthenticatedFrame:
        assert self._supervisor is not None and self._graph is not None
        header = self._supervisor.read_exact(AUTH_FRAME_HEADER_STRUCT.size, deadline)
        try:
            length = AUTH_FRAME_HEADER_STRUCT.unpack(header)[-1]
        except struct.error:
            _raise(BridgeError, "FRAME_INVALID")
        if length > MAX_AUTH_PAYLOAD_BYTES:
            _raise(BridgeError, "FRAME_INVALID")
        raw = header + self._supervisor.read_exact(length + AUTH_FRAME_TAG_SIZE, deadline)
        frame = decode_authenticated_frame(
            raw, key, expected_direction=direction, expected_sequence=self._session_cursor,
            expected_session_nonce=self._graph.n_session,
        )
        self._session_cursor += 1
        return frame

    def _ingest_stage(self, stage: str, payload: Mapping[str, Any]) -> None:
        try:
            frame = self.store.prepare_runner_frame(self.epoch_ref, stage, dict(payload))
            self.store.ingest_frame(self.epoch_ref, frame)
        except Exception:
            _raise(BridgeError, "STORE_TRANSITION_FAILED")

    def _abandon(self) -> None:
        try:
            snapshot = self.store.load_epoch(self.epoch_ref)
            if snapshot.record["state"] not in getattr(STORE, "TERMINAL_EPOCH_STATES", frozenset()):
                self.store.abandon(self.epoch_ref)
        except Exception:
            pass

    def _projection(self) -> Mapping[str, Any] | None:
        try:
            return self.store.public_projection(self.epoch_ref)
        except Exception:
            return None

    def run(self) -> BridgeResult:
        snapshot = self._load_initial_snapshot()
        try:
            process = self.process_factory()
            self._supervisor = ProcessSupervisor(process)
            self._supervisor.start()
            deadline = time.monotonic() + self.timeout_seconds
            hello = decode_hello(self._supervisor.read_exact(HELLO_SIZE, deadline))
            n_local = os.urandom(32)
            self._graph = derive_local_key_graph(
                spool_hmac_key=snapshot.private_identities["spool_hmac_key"],
                salt=snapshot.private_identities["salt"],
                epoch_ref=snapshot.record["epoch_ref"],
                authority_ref=snapshot.record["authority_ref"],
                runner_identity=snapshot.private_identities["runner_identity"],
                bundle=self.runner_bundle,
                n_remote=hello,
                n_local=n_local,
            )
            self._supervisor.write_all(
                encode_preamble(
                    self._graph.n_remote, self._graph.n_local, self._graph.n_session,
                    self._graph.epoch_digest, self._graph.authority_digest,
                    self._graph.runner_digest, self._graph.bundle_digest,
                    self._graph.bootstrap_seed,
                ),
                deadline,
            )
            self._send(self._graph.k_boot, DIRECTION_LOCAL_TO_REMOTE, MESSAGE_BOOT, encode_boot_payload(self.runner_bundle, self.barrier_utc), deadline)
            ready = self._receive(self._graph.k_session, DIRECTION_REMOTE_TO_LOCAL, deadline)
            if ready.message != MESSAGE_READY:
                if ready.message == MESSAGE_ABORT:
                    value = decode_control(ready.payload, "ABORT")
                    self._abandon()
                    return BridgeResult("ABANDONED", "ABANDONED", value["code"], self._projection(), self.counters)
                _raise(BridgeError, "FRAME_INVALID")
            ready_value = decode_control(ready.payload, "READY")
            if ready_value["barrier_utc"] != self.barrier_utc:
                _raise(BridgeError, "FRAME_INVALID")
            discovery = self._receive(self._graph.k_session, DIRECTION_REMOTE_TO_LOCAL, deadline)
            if discovery.message == MESSAGE_ABORT:
                value = decode_control(discovery.payload, "ABORT")
                self._abandon()
                return BridgeResult("ABANDONED", "ABANDONED", value["code"], self._projection(), self.counters)
            if discovery.message != MESSAGE_DISCOVERY:
                _raise(BridgeError, "FRAME_INVALID")
            value = decode_control(discovery.payload, "DISCOVERY")
            self.counters.discovery_messages += 1
            row_id, filename = _validate_discovery_tuple(value["execution_row_id"], value["artifact_filename"])
            isolation_commitment = value["isolation_commitment"]
            if value["isolation_state"] != "PASS" or not _is_commitment(isolation_commitment):
                _raise(BridgeError, "DISCOVERY_INVALID")

            # The only canonical artifact-binding mutation. All tuple checks
            # happen above, before this call.
            expected_artifact = STORE.recovery_commitment("artifact-row", str(row_id), filename)
            self.counters.bind_calls += 1
            if self.counters.bind_calls > 1:
                _raise(BridgeError, "STORE_TRANSITION_FAILED")
            actual_artifact = self.store.bind_artifact_v2(self.epoch_ref, row_id, filename)
            if actual_artifact != expected_artifact:
                _raise(BridgeError, "STORE_TRANSITION_FAILED")
            self.store.mark_ready(self.epoch_ref)
            self._ingest_stage("EPOCH_READY", {"state": "READY"})
            self.store.activate(self.epoch_ref)
            self._ingest_stage("RUNNER_STARTED", {"state": "RUNNER_STARTED"})

            cas_data = {
                "artifact_commitment": actual_artifact,
                "isolation_commitment": isolation_commitment,
                "runner_bundle_commitment": self.runner_bundle.commitment,
            }
            try:
                expected_ledger_digest = self.store.ledger_digest(self.epoch_ref)
                self.store.consume_restore(
                    self.epoch_ref,
                    "bridge-restore-" + uuid.uuid4().hex,
                    expected_digest=expected_ledger_digest,
                    data=cas_data,
                )
            except Exception:
                _raise(BridgeError, "STORE_TRANSITION_FAILED")
            self._post_cas = True
            consumed = self.store.load_epoch(self.epoch_ref)
            if consumed.ledger["state"] != "CONSUMED":
                _raise(BridgeError, "POST_CAS_UNCERTAIN")
            self._ingest_stage(
                "RESTORE_BEGIN",
                {"commitment": bridge_commitment("restore-begin", actual_artifact, isolation_commitment)},
            )

            if self.decision.proceed:
                capability = proceed_commitment(self._graph, actual_artifact, isolation_commitment)
                token = _grant_token(self._graph, capability)
                self._send(
                    self._graph.k_session,
                    DIRECTION_LOCAL_TO_REMOTE,
                    MESSAGE_PROCEED,
                    encode_control(
                        {
                            "type": "PROCEED",
                            "version": 1,
                            "artifact_commitment": actual_artifact,
                            "isolation_commitment": isolation_commitment,
                            "grant": base64.urlsafe_b64encode(token).decode("ascii").rstrip("="),
                        }
                    ),
                    deadline,
                )
                self.counters.proceed_messages += 1
                terminal = self._receive(self._graph.k_session, DIRECTION_REMOTE_TO_LOCAL, deadline)
                if terminal.message == MESSAGE_ABORT:
                    abort_value = decode_control(terminal.payload, "ABORT")
                    self._abandon()
                    return BridgeResult("ABANDONED", "ABANDONED", abort_value["code"], self._projection(), self.counters, True)
                if terminal.message != MESSAGE_RESULT:
                    _raise(BridgeError, "FRAME_INVALID")
                result_value = decode_control(terminal.payload, "RESULT")
                self.counters.result_messages += 1
                classification = ResultClassification(result_value["classification"])
                if classification is ResultClassification.COMMITTED:
                    self._ingest_stage("COMMIT", {"classification": classification.value, "commitment": result_value["result_commitment"]})
                else:
                    self._abandon()
                final = self._projection()
                final_state = final["state"] if final is not None else classification.value
                return BridgeResult(classification.value, final_state, None, final, self.counters)

            abort_code = self.decision.abort_code or RunnerControlCode.LOCAL_ABORT
            self._send(
                self._graph.k_session,
                DIRECTION_LOCAL_TO_REMOTE,
                MESSAGE_ABORT,
                encode_control({"type": "ABORT", "version": 1, "code": abort_code.value}),
                deadline,
            )
            self._abandon()
            return BridgeResult("ABANDONED", "ABANDONED", abort_code.value, self._projection(), self.counters, True)
        except BridgeError as error:
            self._abandon()
            return BridgeResult("ABANDONED", "ABANDONED", error.code, self._projection(), self.counters, self._post_cas)
        except Exception:
            self._abandon()
            return BridgeResult("ABANDONED", "ABANDONED", "PROTOCOL_FAILURE", self._projection(), self.counters, self._post_cas)
        finally:
            if self._supervisor is not None:
                self._supervisor.stop()


def run_controller_bridge(
    store: Any,
    epoch_ref: str,
    barrier_utc: str,
    runner_bundle: RunnerBundle,
    *,
    process_factory: Callable[[], Any] | None = None,
    decision: DummyDecision | None = None,
    counters: BridgeCounters | None = None,
    timeout_seconds: float = 5.0,
) -> BridgeResult:
    return ControllerBridge(
        store,
        epoch_ref,
        barrier_utc,
        runner_bundle,
        process_factory=process_factory,
        decision=decision,
        counters=counters,
        timeout_seconds=timeout_seconds,
    ).run()


def _dummy_child_main() -> int:
    return RemoteLoader(sys.stdin.buffer, sys.stdout.buffer, capture_fds=True).run()


def main(argv: Sequence[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    if values == ["--dummy-child"]:
        return _dummy_child_main()
    return EXIT_PROTOCOL_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())
