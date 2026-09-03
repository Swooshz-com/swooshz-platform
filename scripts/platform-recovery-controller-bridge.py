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
import lzma
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


RUNNER_ABORT_VALUES = (
    "PRESTATE_FAILED",
    "BACKUP_NOT_QUALIFYING",
    "LOCATOR_NOT_FOUND",
    "LOCATOR_AMBIGUOUS",
    "RESOURCE_COLLISION",
    "RESOURCE_CREATE_FAILED",
    "ISOLATION_FAILED",
    "CLEANUP_UNPROVEN",
    "RESTORE_PRECONDITION_FAILED",
    "RUNNER_ABORTED",
)
RUNNER_CONTROL_VALUES = RUNNER_ABORT_VALUES + (
    "DECISION_EOF",
    "DECISION_TIMEOUT",
    "DECISION_BROKEN_PIPE",
    "PROCEED_INVALID",
    "PROTOCOL_BROKEN_PIPE",
    "PROTOCOL_FAILURE",
    "LOCAL_ABORT",
    "RUNTIME_TERMINAL",
    "RUNNER_STDOUT_FORBIDDEN",
    "RUNNER_STDERR_FORBIDDEN",
    "RUNNER_INPUT_FORBIDDEN",
    "SUBPROCESS_STDIO_REQUIRED",
    "DISCOVERY_DUPLICATE",
    "RESULT_BEFORE_PROCEED",
    "RESULT_DUPLICATE",
    "RUNNER_MISSING",
    "RUNNER_NOT_CALLABLE",
    "RUNNER_SIGNATURE_INVALID",
    "RUNNER_TOP_LEVEL_EXCEPTION",
    "RUNNER_NO_RESULT",
    "RUNNER_NON_NONE_RETURN",
)
assert len(RUNNER_ABORT_VALUES) == 10
assert len(RUNNER_CONTROL_VALUES) == 31


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
        "PROCESS_STDOUT_FORBIDDEN",
        "PROCESS_CAPTURE_OVERFLOW",
        "PROCESS_TRAILING_OUTPUT",
        "PROCESS_EXIT_NONZERO",
        "PROCESS_TERMINATION_UNCERTAIN",
        "PROCESS_FINALITY_FAILED",
        "STORE_TRANSITION_FAILED",
        "POST_CAS_UNCERTAIN",
    }
)


class BridgeError(Exception):
    """Base error whose public string is always a symbolic code."""

    def __init__(self, code: str | Enum):
        value = code.value if isinstance(code, Enum) else code
        if value not in PUBLIC_ERROR_CODES:
            value = "PROTOCOL_FAILURE"
        self.code = value
        super().__init__(value)


class ProtocolError(BridgeError):
    pass


class BundleError(BridgeError):
    pass


def _raise(error_type: type[BridgeError], code: str | Enum) -> None:
    raise error_type(code)


# ---------------------------------------------------------------------------
# Fixed protocol wire formats

PROTOCOL_VERSION = 1
HELLO_TYPE = 1
PREAMBLE_TYPE = 2

HELLO_MAGIC = b"SWZBRDG1"
HELLO_STRUCT = struct.Struct("!8sBBH32s")
HELLO_SIZE = HELLO_STRUCT.size
HELLO_FLAGS = 0

PREAMBLE_MAGIC = b"SWZPRE01"
PREAMBLE_HEADER_STRUCT = struct.Struct("!8sBBHHH")
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
MAX_SESSION_FRAMES = 16
MAX_SESSION_BYTES = 1048576
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

BOOT_BARRIER_BYTES = 27
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

# All phase bounds use one injected monotonic clock. The whole-session bound
# is the outer cap for a single process/session.
HELLO_TIMEOUT_SECONDS = 5.0
BOOT_TIMEOUT_SECONDS = 5.0
READY_TIMEOUT_SECONDS = 5.0
DISCOVERY_TIMEOUT_SECONDS = 5.0
PROCEED_TIMEOUT_SECONDS = 5.0
RESULT_TIMEOUT_SECONDS = 5.0
WHOLE_SESSION_TIMEOUT_SECONDS = 30.0
MAX_STDERR_CAPTURE_BYTES = 4096


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
    return _commitment_bytes(bridge_commitment(domain, *parts))


def bridge_commitment(domain: str, *parts: str | bytes) -> str:
    return STORE.bytes_commitment("bridge-" + domain, LP(*parts))


def _commitment_bytes(value: str) -> bytes:
    if not _is_commitment(value):
        _raise(ProtocolError, "FRAME_INVALID")
    try:
        return bytes.fromhex(value[len("sha256:v1:") :])
    except ValueError:
        _raise(ProtocolError, "FRAME_INVALID")
    raise AssertionError("unreachable")


def _digest_commitment(value: bytes) -> str:
    _validate_nonce(value, "commitment digest", 32)
    return "sha256:v1:" + value.hex()


def _store_json_commitment(domain: str, value: Mapping[str, Any], *, max_bytes: int) -> str:
    try:
        payload = STORE.canonical_json_bytes(dict(value), max_bytes=max_bytes)
        return STORE.bytes_commitment(domain, payload)
    except Exception:
        _raise(ProtocolError, "STORE_TRANSITION_FAILED")
    raise AssertionError("unreachable")


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
        "PROCEED": (
            "type",
            "version",
            "epoch_digest",
            "authority_digest",
            "runner_digest",
            "bundle_digest",
            "barrier_utc",
            "artifact_commitment",
            "isolation_commitment",
            "transition_id",
            "pre_cas_ledger_digest",
            "transition_data_commitment",
            "consumed_record_digest",
            "grant",
        ),
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
        commitments = (
            "epoch_digest",
            "authority_digest",
            "runner_digest",
            "bundle_digest",
            "artifact_commitment",
            "isolation_commitment",
            "pre_cas_ledger_digest",
            "transition_data_commitment",
            "consumed_record_digest",
        )
        if any(not _is_commitment(value[name]) for name in commitments):
            _raise(ProtocolError, "PROCEED_INVALID")
        validate_barrier_utc(value["barrier_utc"])
        if (
            type(value["transition_id"]) is not str
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value["transition_id"], re.ASCII)
        ):
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
        except (TypeError, ValueError):
            _raise(ProtocolError, "FRAME_INVALID")
    elif expected_type == "RESULT":
        try:
            ResultClassification(value["classification"])
        except (TypeError, ValueError):
            _raise(ProtocolError, "FRAME_INVALID")
        if not _is_commitment(value["result_commitment"]):
            _raise(ProtocolError, "FRAME_INVALID")
    return value


def encode_hello(n_remote: bytes) -> bytes:
    n_remote = _validate_nonce(n_remote, "n_remote", SESSION_NONCE_BYTES)
    return HELLO_STRUCT.pack(HELLO_MAGIC, PROTOCOL_VERSION, HELLO_TYPE, HELLO_FLAGS, n_remote)


def decode_hello(payload: bytes) -> bytes:
    if not isinstance(payload, bytes) or len(payload) != HELLO_SIZE:
        _raise(ProtocolError, "HELLO_INVALID")
    magic, version, kind, flags, n_remote = HELLO_STRUCT.unpack(payload)
    if magic != HELLO_MAGIC or version != PROTOCOL_VERSION or kind != HELLO_TYPE or flags != HELLO_FLAGS:
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
    header = PREAMBLE_HEADER_STRUCT.pack(
        PREAMBLE_MAGIC,
        PROTOCOL_VERSION,
        PREAMBLE_TYPE,
        FRAME_FLAGS,
        PREAMBLE_BODY_SIZE,
        0,
    )
    return header + PREAMBLE_BODY_STRUCT.pack(*values)


def decode_preamble(payload: bytes) -> dict[str, bytes]:
    if not isinstance(payload, bytes) or len(payload) != PREAMBLE_SIZE:
        _raise(ProtocolError, "PREAMBLE_INVALID")
    magic, version, kind, flags, body_size, reserved = PREAMBLE_HEADER_STRUCT.unpack(
        payload[: PREAMBLE_HEADER_STRUCT.size]
    )
    if (
        magic != PREAMBLE_MAGIC
        or version != PROTOCOL_VERSION
        or kind != PREAMBLE_TYPE
        or flags != FRAME_FLAGS
        or body_size != PREAMBLE_BODY_SIZE
        or reserved != 0
    ):
        _raise(ProtocolError, "PREAMBLE_INVALID")
    raw = PREAMBLE_BODY_STRUCT.unpack(payload[PREAMBLE_HEADER_STRUCT.size :])
    values = dict(zip(PREAMBLE_FIELDS, raw))
    for name, value in values.items():
        _validate_nonce(value, name, 32)
    return values


def encode_boot_payload(bundle: "RunnerBundle", barrier_utc: str) -> bytes:
    validate_barrier_utc(barrier_utc)
    if not isinstance(bundle, RunnerBundle):
        _raise(ProtocolError, "FRAME_INVALID")
    validate_runner_bundle(bundle)
    source = bundle.source
    if type(source) is not bytes or not 1 <= len(source) <= MAX_RUNNER_BUNDLE_BYTES:
        _raise(ProtocolError, "FRAME_INVALID")
    return barrier_utc.encode("ascii", "strict") + source


def decode_boot_payload(
    payload: bytes,
    *,
    expected_barrier: str | None = None,
    expected_digest: bytes,
) -> bytes:
    if not isinstance(payload, bytes) or len(payload) <= BOOT_BARRIER_BYTES:
        _raise(ProtocolError, "FRAME_INVALID")
    if not isinstance(expected_digest, bytes) or len(expected_digest) != 32:
        _raise(ProtocolError, "FRAME_INVALID")
    barrier_bytes = payload[:BOOT_BARRIER_BYTES]
    source = payload[BOOT_BARRIER_BYTES:]
    try:
        barrier = barrier_bytes.decode("ascii", "strict")
    except UnicodeDecodeError:
        _raise(ProtocolError, "FRAME_INVALID")
    validate_barrier_utc(barrier)
    if expected_barrier is not None and barrier != expected_barrier:
        _raise(ProtocolError, "FRAME_INVALID")
    if not 1 <= len(source) <= MAX_RUNNER_BUNDLE_BYTES:
        _raise(ProtocolError, "FRAME_INVALID")
    if _bundle_digest_bytes(source) != expected_digest:
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
    _validate_nonce(frame_nonce, "frame nonce", FRAME_NONCE_BYTES)
    payload_start = AUTH_FRAME_HEADER_STRUCT.size
    payload = frame[payload_start : payload_start + payload_length]
    if not hmac.compare_digest(frame[-AUTH_FRAME_TAG_SIZE:], _frame_auth(key, header, payload)):
        _raise(ProtocolError, "FRAME_INVALID")
    return AuthenticatedFrame(direction, message, sequence, session_nonce, frame_nonce, payload)


def _bundle_digest_bytes(source: bytes) -> bytes:
    if type(source) is not bytes:
        _raise(BundleError, "BUNDLE_INVALID")
    return _commitment_bytes(STORE.bytes_commitment("bridge-runner-bundle", source))


def runner_bundle_commitment(source: bytes) -> str:
    if type(source) is not bytes:
        _raise(BundleError, "BUNDLE_INVALID")
    return STORE.bytes_commitment("bridge-runner-bundle", source)


@dataclass(frozen=True, slots=True, repr=False)
class RunnerBundle:
    source: bytes
    expected_commitment: str

    def __post_init__(self) -> None:
        source = self.source
        expected = self.expected_commitment
        if type(source) is not bytes:
            _raise(BundleError, "BUNDLE_INVALID")
        if not 1 <= len(source) <= MAX_RUNNER_BUNDLE_BYTES:
            _raise(BundleError, "BUNDLE_OVERSIZED" if len(source) > MAX_RUNNER_BUNDLE_BYTES else "BUNDLE_INVALID")
        if source.startswith(b"\xef\xbb\xbf") or b"\x00" in source:
            _raise(BundleError, "BUNDLE_INVALID")
        try:
            source.decode("utf-8", "strict")
        except UnicodeDecodeError:
            _raise(BundleError, "BUNDLE_NOT_UTF8")
        if type(expected) is not str or not _is_commitment(expected) or expected != runner_bundle_commitment(source):
            _raise(BundleError, "BUNDLE_COMMITMENT_MISMATCH")

    @property
    def commitment(self) -> str:
        return self.expected_commitment

    def __repr__(self) -> str:
        return f"RunnerBundle(commitment={self.expected_commitment!r}, bytes={len(self.source)})"


def validate_runner_bundle(bundle: RunnerBundle) -> RunnerBundle:
    if not isinstance(bundle, RunnerBundle):
        _raise(BundleError, "BUNDLE_INVALID")
    try:
        # This is the only local source operation. It compiles but never
        # executes caller-supplied runner code.
        compile(bundle.source.decode("utf-8", "strict"), "<runner-bundle>", "exec", dont_inherit=True)
    except (SyntaxError, ValueError, TypeError, UnicodeDecodeError):
        _raise(BundleError, "BUNDLE_COMPILE_FAILED")
    return bundle


K_BRIDGE_ROOT_DOMAIN = "K_bridge_root.v1"
K_BOOTSTRAP_SEED_DOMAIN = "K_bootstrap_seed.v1"
K_SESSION_NONCE_DOMAIN = "N_session.v1"
K_BOOT_DOMAIN = "K_boot.v1"
K_SESSION_DOMAIN = "K_session.v1"
K_PROCEED_DOMAIN = "K_proceed.v1"
CAPABILITY_DOMAIN = "C_proceed.v1"


def _derive_key(seed: bytes, domain: str, *parts: str | bytes) -> bytes:
    _validate_key(seed, "key derivation seed")
    return hmac.new(seed, LP(domain, *parts), hashlib.sha256).digest()


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
    k_bridge_root: bytes | None = field(repr=False)
    epoch_commitment: str = field(repr=False)
    authority_commitment: str = field(repr=False)
    runner_commitment: str = field(repr=False)
    bundle_commitment: str = field(repr=False)
    loader_commitment: str | None = field(repr=False)
    barrier_utc: str | None = field(repr=False)
    barrier_commitment: str | None = field(repr=False)
    k_boot: bytes = field(repr=False)
    k_session: bytes = field(repr=False)
    k_proceed: bytes = field(repr=False)

    def __repr__(self) -> str:
        return "BridgeKeyGraph(session_bound=True, bindings=opaque, secrets=opaque)"

    def with_barrier(self, barrier_utc: str) -> "BridgeKeyGraph":
        return derive_key_graph_from_preamble(
            {
                "n_remote": self.n_remote,
                "n_local": self.n_local,
                "n_session": self.n_session,
                "epoch_digest": self.epoch_digest,
                "authority_digest": self.authority_digest,
                "runner_digest": self.runner_digest,
                "bundle_digest": self.bundle_digest,
                "bootstrap_seed": self.bootstrap_seed,
            },
            barrier_utc=barrier_utc,
            loader_commitment=self.loader_commitment,
            record_commitment=self.epoch_commitment,
            runner_commitment=self.runner_commitment,
            authority_commitment=self.authority_commitment,
            k_bridge_root=self.k_bridge_root,
        )


def derive_key_graph_from_preamble(
    preamble: Mapping[str, bytes],
    *,
    barrier_utc: str | None = None,
    loader_commitment: str | None = None,
    record_commitment: str | None = None,
    runner_commitment: str | None = None,
    authority_commitment: str | None = None,
    k_bridge_root: bytes | None = None,
) -> BridgeKeyGraph:
    try:
        values = {name: preamble[name] for name in PREAMBLE_FIELDS}
    except (KeyError, TypeError):
        _raise(ProtocolError, "PREAMBLE_INVALID")
    for name, value in values.items():
        _validate_nonce(value, name, 32)
    transcript = _session_transcript(
        values["n_remote"], values["n_local"], values["n_session"], values["epoch_digest"],
        values["authority_digest"], values["runner_digest"], values["bundle_digest"],
    )
    seed = values["bootstrap_seed"]
    expected_session_nonce = _derive_key(
        seed,
        K_SESSION_NONCE_DOMAIN,
        values["n_remote"],
        values["n_local"],
        values["epoch_digest"],
        values["authority_digest"],
        values["runner_digest"],
        values["bundle_digest"],
    )
    if not hmac.compare_digest(expected_session_nonce, values["n_session"]):
        _raise(ProtocolError, "PREAMBLE_INVALID")
    if barrier_utc is not None:
        barrier_utc = _validate_canonical_barrier(barrier_utc)
        barrier_commitment = STORE.bytes_commitment(
            "bridge-barrier",
            barrier_utc.encode("ascii", "strict"),
        )
        barrier_digest = _commitment_bytes(barrier_commitment)
    else:
        barrier_commitment = None
        barrier_digest = b"\x00" * 32
    epoch_commitment = (
        _digest_commitment(values["epoch_digest"])
        if record_commitment is None
        else record_commitment
    )
    authority_commitment = (
        _digest_commitment(values["authority_digest"])
        if authority_commitment is None
        else authority_commitment
    )
    runner_commitment = (
        _digest_commitment(values["runner_digest"])
        if runner_commitment is None
        else runner_commitment
    )
    bundle_commitment = _digest_commitment(values["bundle_digest"])
    loader_commitment = (
        fixed_loader_commitment()
        if loader_commitment is None
        else loader_commitment
    )
    for commitment, digest in (
        (epoch_commitment, values["epoch_digest"]),
        (authority_commitment, values["authority_digest"]),
        (runner_commitment, values["runner_digest"]),
        (bundle_commitment, values["bundle_digest"]),
    ):
        if not _is_commitment(commitment) or _commitment_bytes(commitment) != digest:
            _raise(ProtocolError, "PREAMBLE_INVALID")
    if not _is_commitment(loader_commitment):
        _raise(ProtocolError, "PREAMBLE_INVALID")
    if k_bridge_root is not None:
        _validate_key(k_bridge_root, "bridge root")
    return BridgeKeyGraph(
        **values,
        k_bridge_root=k_bridge_root,
        epoch_commitment=epoch_commitment,
        authority_commitment=authority_commitment,
        runner_commitment=runner_commitment,
        bundle_commitment=bundle_commitment,
        loader_commitment=loader_commitment,
        barrier_utc=barrier_utc,
        barrier_commitment=barrier_commitment,
        k_boot=_derive_key(seed, K_BOOT_DOMAIN, *transcript),
        k_session=_derive_key(seed, K_SESSION_DOMAIN, *transcript, barrier_digest),
        k_proceed=_derive_key(seed, K_PROCEED_DOMAIN, *transcript, barrier_digest),
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
    record_commitment: str | None = None,
    loader_commitment: str | None = None,
    barrier_utc: str | None = None,
    runner_commitment: str | None = None,
    authority_commitment: str | None = None,
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
    barrier_value = None if barrier_utc is None else _validate_canonical_barrier(barrier_utc)
    barrier_wire = "" if barrier_value is None else barrier_value
    record_commitment = record_commitment or bridge_commitment("record", epoch_ref, authority_ref)
    loader_commitment = loader_commitment or fixed_loader_commitment()
    runner_commitment = runner_commitment or bridge_commitment("runner", runner_identity)
    authority_commitment = authority_commitment or bridge_commitment("authority", authority_ref)
    for commitment in (record_commitment, loader_commitment, runner_commitment, authority_commitment):
        if not _is_commitment(commitment):
            _raise(ProtocolError, "STORE_STATE_INVALID")
    epoch_digest = _commitment_bytes(record_commitment)
    authority_digest = _commitment_bytes(authority_commitment)
    runner_digest = _commitment_bytes(runner_commitment)
    bundle_digest = _bundle_digest_bytes(bundle.source)
    barrier_commitment = STORE.bytes_commitment("bridge-barrier", barrier_wire.encode("ascii", "strict"))
    root = hmac.new(
        spool_key,
        LP(
            K_BRIDGE_ROOT_DOMAIN,
            salt,
            epoch_ref,
            authority_ref,
            record_commitment,
            authority_commitment,
            runner_commitment,
            loader_commitment,
            bundle.commitment,
            barrier_commitment,
        ),
        hashlib.sha256,
    ).digest()
    seed = hmac.new(
        root,
        LP(
            K_BOOTSTRAP_SEED_DOMAIN,
            n_remote,
            n_local,
            epoch_digest,
            authority_digest,
            runner_digest,
            bundle_digest,
            _commitment_bytes(loader_commitment),
            _commitment_bytes(barrier_commitment),
        ),
        hashlib.sha256,
    ).digest()
    n_session = _derive_key(
        seed,
        K_SESSION_NONCE_DOMAIN,
        n_remote,
        n_local,
        epoch_digest,
        authority_digest,
        runner_digest,
        bundle_digest,
    )
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
    return derive_key_graph_from_preamble(
        preamble,
        barrier_utc=barrier_value,
        loader_commitment=loader_commitment,
        record_commitment=record_commitment,
        runner_commitment=runner_commitment,
        authority_commitment=authority_commitment,
        k_bridge_root=root,
    )


def proceed_commitment(
    graph: BridgeKeyGraph,
    artifact_commitment: str,
    isolation_commitment: str,
    transition_id: str,
    pre_cas_ledger_digest: str,
    transition_data_commitment: str,
    consumed_record_digest: str,
) -> str:
    if (
        not _is_commitment(artifact_commitment)
        or not _is_commitment(isolation_commitment)
        or not _is_commitment(pre_cas_ledger_digest)
        or not _is_commitment(transition_data_commitment)
        or not _is_commitment(consumed_record_digest)
        or type(transition_id) is not str
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", transition_id, re.ASCII)
        or graph.barrier_utc is None
    ):
        _raise(ProtocolError, "PROCEED_INVALID")
    return bridge_commitment(
        "proceed-capability",
        *_session_transcript(
            graph.n_remote, graph.n_local, graph.n_session, graph.epoch_digest,
            graph.authority_digest, graph.runner_digest, graph.bundle_digest,
        ),
        graph.barrier_utc,
        graph.epoch_commitment,
        graph.authority_commitment,
        graph.runner_commitment,
        graph.bundle_commitment,
        graph.loader_commitment or "",
        graph.barrier_commitment or "",
        artifact_commitment,
        isolation_commitment,
        transition_id,
        pre_cas_ledger_digest,
        transition_data_commitment,
        consumed_record_digest,
    )


def _grant_token(graph: BridgeKeyGraph, capability_commitment: str) -> bytes:
    return hmac.new(graph.k_proceed, LP(CAPABILITY_DOMAIN, capability_commitment), hashlib.sha256).digest()


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
    def deny(cls, code: RunnerControlCode | None = None) -> "DummyDecision":
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
# Remote runtime, channel, and import boundary are the canonical payload exports below.
def spawn_dummy_child() -> Any:
    """Test-only local child; the operational API never selects this default."""

    return _subprocess.Popen(
        [sys.executable, str(pathlib.Path(__file__).resolve()), "--dummy-child"],
        stdin=_subprocess.PIPE,
        stdout=_subprocess.PIPE,
        stderr=_subprocess.PIPE,
        close_fds=True,
        bufsize=0,
        shell=False,
    )


def _transition_id(base: Mapping[str, Any]) -> str:
    payload = STORE.canonical_json_bytes(
        dict(base),
        max_bytes=STORE.MAX_RESTORE_LEDGER_BYTES,
    )
    digest = _commitment_bytes(
        STORE.bytes_commitment("bridge-restore-transition-id", payload)
    ).hex()
    return "bridge-restore-" + digest


def build_restore_transition(
    *,
    epoch_ref: str,
    authority_ref: str,
    runner_commitment: str,
    runner_bundle_commitment: str,
    barrier_utc: str,
    artifact_commitment: str,
    isolation_commitment: str,
    pre_cas_ledger_digest: str,
) -> tuple[dict[str, Any], str, str]:
    base = {
        "schema": "bridge-restore-transition.v1",
        "version": 1,
        "epoch_ref": epoch_ref,
        "authority_ref": authority_ref,
        "runner_commitment": runner_commitment,
        "runner_bundle_commitment": runner_bundle_commitment,
        "barrier_utc": _validate_canonical_barrier(barrier_utc),
        "artifact_commitment": artifact_commitment,
        "isolation_commitment": isolation_commitment,
        "pre_cas_ledger_digest": pre_cas_ledger_digest,
    }
    if any(
        not _is_commitment(value)
        for value in (
            runner_commitment,
            runner_bundle_commitment,
            artifact_commitment,
            isolation_commitment,
            pre_cas_ledger_digest,
        )
    ):
        _raise(ProtocolError, "STORE_TRANSITION_FAILED")
    transition_id = _transition_id(base)
    transition = dict(base)
    transition["transition_id"] = transition_id
    transition_commitment = _store_json_commitment(
        "restore-ledger-transition",
        transition,
        max_bytes=STORE.MAX_RESTORE_LEDGER_BYTES,
    )
    return transition, transition_id, transition_commitment


class ControllerBridge:
    def __init__(
        self,
        store: Any,
        epoch_ref: str,
        barrier_utc: str,
        runner_bundle: RunnerBundle,
        *,
        launcher: Callable[[], Any],
        clock: Callable[[], float] = time.monotonic,
        randomness: Callable[[int], bytes] = os.urandom,
        counters: BridgeCounters | None = None,
        timeout_seconds: float = WHOLE_SESSION_TIMEOUT_SECONDS,
    ):
        if not callable(launcher) or not callable(clock) or not callable(randomness):
            raise TypeError("launcher, clock and randomness must be callable")
        if type(timeout_seconds) not in (int, float) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.store = store
        self.epoch_ref = epoch_ref
        self.barrier_utc = _validate_canonical_barrier(barrier_utc)
        self.runner_bundle = validate_runner_bundle(runner_bundle)
        self.launcher = launcher
        self.clock = clock
        self.randomness = randomness
        self.counters = counters or BridgeCounters()
        self.timeout_seconds = float(timeout_seconds)
        self._graph: BridgeKeyGraph | None = None
        self._supervisor: ProcessSupervisor | None = None
        self._next_sequence = 1
        self._session_nonces: set[bytes] = set()
        self._session_bytes = 0
        self._terminal = False
        self._abort_sent = False
        self._proceed_sent = False
        self._post_cas = False
        self._post_cas_uncertain = False
        self._pre_cas_abandon_allowed = False
        self._restore_begin_durable = False
        self._abandon_attempted = False
        self._cas_classification_reload_count = 0
        self._cas_classification_snapshot: STORE.V2EpochSnapshot | None = None
        self._finality_evidence: ProcessTerminalEvidence | None = None

    def _load_initial_snapshot(self) -> STORE.V2EpochSnapshot:
        try:
            snapshot = self.store.load_epoch(self.epoch_ref)
        except Exception:
            _raise(BridgeError, "STORE_STATE_INVALID")
        if not isinstance(snapshot, STORE.V2EpochSnapshot):
            _raise(BridgeError, "STORE_STATE_INVALID")
        if (
            snapshot.record["state"] != "INITIALISED"
            or snapshot.record["artifact_binding_state"] != "PENDING"
            or snapshot.artifact_binding.artifact_binding_state != "PENDING"
            or snapshot.ledger["state"] != "UNCONSUMED"
            or snapshot.spool["state"] != "OPEN"
            or snapshot.spool["last_stage"] != "NONE"
        ):
            _raise(BridgeError, "STORE_STATE_INVALID")
        self._pre_cas_abandon_allowed = True
        return snapshot

    def _random_bytes(self, size: int) -> bytes:
        try:
            value = self.randomness(size)
            return _validate_nonce(value, "randomness", size)
        except Exception:
            _raise(BridgeError, "PROTOCOL_FAILURE")
        raise AssertionError("unreachable")

    def _phase_deadline(self, outer_deadline: float, seconds: float) -> float:
        return min(outer_deadline, self.clock() + seconds)

    def _track_frame(self, frame: AuthenticatedFrame) -> None:
        if frame.frame_nonce in self._session_nonces:
            _raise(BridgeError, "PROTOCOL_FAILURE")
        if len(self._session_nonces) >= MAX_SESSION_FRAMES:
            _raise(BridgeError, "PROTOCOL_FAILURE")
        new_bytes = self._session_bytes + AUTH_FRAME_OVERHEAD + len(frame.payload)
        if new_bytes > MAX_SESSION_BYTES:
            _raise(BridgeError, "PROTOCOL_FAILURE")
        self._session_nonces.add(frame.frame_nonce)
        self._session_bytes = new_bytes

    def _new_frame_nonce(self) -> bytes:
        value = self._random_bytes(FRAME_NONCE_BYTES)
        if value in self._session_nonces:
            _raise(BridgeError, "PROTOCOL_FAILURE")
        return value

    def _send(
        self,
        key: bytes,
        direction: int,
        message: int,
        payload: bytes,
        deadline: float,
    ) -> None:
        if self._terminal:
            _raise(BridgeError, "PROTOCOL_FAILURE")
        assert self._supervisor is not None and self._graph is not None
        nonce = self._new_frame_nonce()
        frame = encode_authenticated_frame(
            key,
            direction,
            message,
            self._next_sequence,
            self._graph.n_session,
            payload,
            frame_nonce=nonce,
        )
        self._supervisor.write_all(frame, deadline)
        self._track_frame(
            AuthenticatedFrame(
                direction,
                message,
                self._next_sequence,
                self._graph.n_session,
                nonce,
                payload,
            )
        )
        self._next_sequence += 1

    def _receive(self, key: bytes, direction: int, deadline: float) -> AuthenticatedFrame:
        if self._terminal:
            _raise(BridgeError, "PROTOCOL_FAILURE")
        assert self._supervisor is not None and self._graph is not None
        header = self._supervisor.read_exact(AUTH_FRAME_HEADER_STRUCT.size, deadline)
        try:
            length = AUTH_FRAME_HEADER_STRUCT.unpack(header)[-1]
        except struct.error:
            _raise(BridgeError, "FRAME_INVALID")
        if length > MAX_AUTH_PAYLOAD_BYTES:
            _raise(BridgeError, "FRAME_INVALID")
        raw = header + self._supervisor.read_exact(length + AUTH_FRAME_TAG_SIZE, deadline)
        try:
            frame = decode_authenticated_frame(
                raw,
                key,
                expected_direction=direction,
                expected_sequence=self._next_sequence,
                expected_session_nonce=self._graph.n_session,
            )
        except BridgeError:
            _raise(BridgeError, "FRAME_INVALID")
        self._track_frame(frame)
        self._next_sequence += 1
        return frame

    def _ingest_stage(self, stage: str, payload: Mapping[str, Any]) -> None:
        try:
            frame = self.store.prepare_runner_frame(self.epoch_ref, stage, dict(payload))
            self.store.ingest_frame(self.epoch_ref, frame)
        except Exception:
            _raise(BridgeError, "STORE_TRANSITION_FAILED")

    def _safe_abandon(self) -> None:
        if self._abandon_attempted:
            return
        if not (self._pre_cas_abandon_allowed or self._restore_begin_durable):
            return
        self._abandon_attempted = True
        try:
            self.store.abandon(self.epoch_ref)
        except BaseException:
            pass

    def _projection(self) -> Mapping[str, Any] | None:
        try:
            return self.store.public_projection(self.epoch_ref)
        except Exception:
            return None

    def _result(
        self,
        classification: str,
        error_code: str | None,
        *,
        post_cas_uncertain: bool | None = None,
    ) -> BridgeResult:
        projection = self._projection()
        state = projection["state"] if projection is not None else "UNKNOWN"
        return BridgeResult(
            classification,
            state,
            error_code,
            projection,
            self.counters,
            self._post_cas if post_cas_uncertain is None else post_cas_uncertain,
        )

    def _close_and_collect(self, outer_deadline: float, *, expected_exit: int) -> str | None:
        if self._supervisor is None:
            return "PROCESS_TERMINATION_UNCERTAIN"
        self._supervisor.close_stdin()
        evidence = self._supervisor.await_natural(
            self._phase_deadline(outer_deadline, RESULT_TIMEOUT_SECONDS)
        )
        self._finality_evidence = evidence
        return ProcessSupervisor.finality_error(evidence, expected_exit=expected_exit)

    def _send_abort_once(self, code: RunnerControlCode) -> None:
        if self._abort_sent or self._terminal or self._graph is None:
            return
        try:
            self._send(
                self._graph.k_session,
                DIRECTION_LOCAL_TO_REMOTE,
                MESSAGE_ABORT,
                encode_control({"type": "ABORT", "version": 1, "code": code.value}),
                self.clock() + RESULT_TIMEOUT_SECONDS,
            )
        except BridgeError:
            pass
        self._abort_sent = True
        self._terminal = True

    def _assert_bound_reload(
        self,
        *,
        row_id: int,
        filename: str,
        artifact_commitment: str,
    ) -> STORE.V2EpochSnapshot:
        try:
            snapshot = self.store.load_epoch(self.epoch_ref)
        except Exception:
            _raise(BridgeError, "STORE_STATE_INVALID")
        if not isinstance(snapshot, STORE.V2EpochSnapshot):
            _raise(BridgeError, "STORE_STATE_INVALID")
        binding = snapshot.artifact_binding
        if not (
            snapshot.record["state"] == "INITIALISED"
            and snapshot.record["artifact_binding_state"] == "BOUND"
            and binding.artifact_binding_state == "BOUND"
            and binding.execution_row_id == str(row_id)
            and binding.artifact_filename == filename
            and binding.artifact_commitment == artifact_commitment
            and snapshot.record["artifact_commitment"] == artifact_commitment
            and snapshot.ledger["state"] == "UNCONSUMED"
            and snapshot.spool["state"] == "OPEN"
            and snapshot.spool["last_stage"] == "NONE"
        ):
            _raise(BridgeError, "STORE_STATE_INVALID")
        return snapshot

    def _assert_runner_started_reload(self) -> STORE.V2EpochSnapshot:
        try:
            snapshot = self.store.load_epoch(self.epoch_ref)
        except Exception:
            _raise(BridgeError, "STORE_STATE_INVALID")
        if not (
            isinstance(snapshot, STORE.V2EpochSnapshot)
            and snapshot.record["state"] == "ACTIVE"
            and snapshot.record["artifact_binding_state"] == "BOUND"
            and snapshot.artifact_binding.artifact_binding_state == "BOUND"
            and snapshot.ledger["state"] == "UNCONSUMED"
            and snapshot.spool["state"] == "OPEN"
            and snapshot.spool["last_stage"] == "RUNNER_STARTED"
        ):
            _raise(BridgeError, "STORE_STATE_INVALID")
        return snapshot

    def _same_captured_snapshot(
        self,
        actual: Any,
        started: STORE.V2EpochSnapshot,
        *,
        ledger_state: str,
        transition_id: str | None = None,
        transition_commitment: str | None = None,
    ) -> bool:
        if not isinstance(actual, STORE.V2EpochSnapshot):
            return False
        expected_record = dict(started.record)
        expected_manifest = dict(started.manifest)
        expected_ledger = dict(started.ledger)
        if ledger_state == "CONSUMED":
            expected_record["restore_ledger_state"] = "CONSUMED"
            expected_manifest["restore_ledger_state"] = "CONSUMED"
            try:
                manifest_bytes = STORE.canonical_json_bytes(
                    actual.manifest,
                    max_bytes=STORE.MAX_MANIFEST_BYTES,
                )
                expected_record["manifest_digest"] = STORE.bytes_commitment(
                    "manifest",
                    manifest_bytes,
                )
            except BaseException:
                return False
            expected_ledger.update(
                {
                    "state": "CONSUMED",
                    "transition_id": transition_id,
                    "transition_target": "RESTORE_STARTED",
                    "transition_data_commitment": transition_commitment,
                }
            )
        elif ledger_state != "UNCONSUMED":
            return False
        return (
            actual.record == expected_record
            and actual.manifest == expected_manifest
            and actual.private_identities == started.private_identities
            and actual.artifact_binding == started.artifact_binding
            and actual.ledger == expected_ledger
            and actual.spool == started.spool
        )

    def _same_consumed_proof(
        self,
        actual: Any,
        started: STORE.V2EpochSnapshot,
        *,
        transition_id: str,
        transition_commitment: str,
    ) -> bool:
        return self._same_captured_snapshot(
            actual,
            started,
            ledger_state="CONSUMED",
            transition_id=transition_id,
            transition_commitment=transition_commitment,
        )

    def _same_unconsumed_proof(
        self,
        actual: Any,
        started: STORE.V2EpochSnapshot,
    ) -> bool:
        return self._same_captured_snapshot(
            actual,
            started,
            ledger_state="UNCONSUMED",
        )

    def _returned_consumed_proof(
        self,
        value: Any,
        *,
        transition_id: str,
    ) -> bool:
        permit_type = getattr(STORE, "RestorePermit", None)
        return (
            permit_type is not None
            and isinstance(value, permit_type)
            and value.epoch_ref == self.epoch_ref
            and value.transition_id == transition_id
            and value.state == "CONSUMED"
            and value.idempotent is False
        )

    def _classify_cas(
        self,
        started: STORE.V2EpochSnapshot,
        *,
        transition_id: str,
        transition_commitment: str,
        cas_result: Any,
        cas_error: BaseException | None,
    ) -> tuple[str, STORE.V2EpochSnapshot | None]:
        self._cas_classification_reload_count += 1
        try:
            observed = self.store.load_epoch(self.epoch_ref)
        except BaseException:
            return "C", None
        if self._same_consumed_proof(
            observed,
            started,
            transition_id=transition_id,
            transition_commitment=transition_commitment,
        ) and (
            cas_error is not None
            or self._returned_consumed_proof(
                cas_result,
                transition_id=transition_id,
            )
        ):
            return "A", observed
        if (
            cas_error is not None
            and getattr(cas_error, "safety_state", None) == "UNCONSUMED"
            and self._same_unconsumed_proof(observed, started)
        ):
            return "B", observed
        return "C", observed

    def _resolve_cas(
        self,
        started: STORE.V2EpochSnapshot,
        *,
        transition_id: str,
        transition_commitment: str,
        cas_result: Any,
        cas_error: BaseException | None,
    ) -> STORE.V2EpochSnapshot:
        classification, observed = self._classify_cas(
            started,
            transition_id=transition_id,
            transition_commitment=transition_commitment,
            cas_result=cas_result,
            cas_error=cas_error,
        )
        self._cas_classification_snapshot = observed
        if classification == "A" and observed is not None:
            self._post_cas = True
            self._pre_cas_abandon_allowed = False
            return observed
        if classification == "B":
            self._pre_cas_abandon_allowed = True
            _raise(BridgeError, "STORE_TRANSITION_FAILED")
        self._post_cas = True
        self._post_cas_uncertain = True
        self._pre_cas_abandon_allowed = False
        _raise(BridgeError, "POST_CAS_UNCERTAIN")

    def _should_proceed(self) -> bool:
        return True

    def _handle_remote_abort(
        self,
        frame: AuthenticatedFrame,
        outer_deadline: float,
    ) -> BridgeResult:
        value = decode_control(frame.payload, "ABORT")
        self._terminal = True
        finality_error = self._close_and_collect(
            outer_deadline,
            expected_exit=EXIT_RUNNER_ABORT,
        )
        self._safe_abandon()
        return self._result("FAILURE", finality_error or value["code"])

    def _bind_and_consume(
        self,
        discovery: AuthenticatedFrame,
        snapshot: STORE.V2EpochSnapshot,
        outer_deadline: float,
    ) -> tuple[str, str, str, str, str, str]:
        value = decode_control(discovery.payload, "DISCOVERY")
        self.counters.discovery_messages += 1
        row_id, filename = _validate_discovery_tuple(
            value["execution_row_id"],
            value["artifact_filename"],
        )
        isolation_commitment = value["isolation_commitment"]
        if value["isolation_state"] != "PASS" or not _is_commitment(isolation_commitment):
            self._send_abort_once(RunnerControlCode.ISOLATION_FAILED)
            self._close_and_collect(outer_deadline, expected_exit=EXIT_RUNNER_ABORT)
            self._safe_abandon()
            raise BridgeError("ISOLATION_FAILED")
        expected_artifact = STORE.recovery_commitment(
            "artifact-row",
            str(row_id),
            filename,
        )
        self.counters.bind_calls += 1
        if self.counters.bind_calls != 1:
            _raise(BridgeError, "STORE_TRANSITION_FAILED")
        try:
            actual_artifact = self.store.bind_artifact_v2(
                self.epoch_ref,
                row_id,
                filename,
            )
        except Exception:
            self._send_abort_once(RunnerControlCode.LOCAL_ABORT)
            self._close_and_collect(outer_deadline, expected_exit=EXIT_RUNNER_ABORT)
            self._safe_abandon()
            raise BridgeError("LOCAL_ABORT")
        if actual_artifact != expected_artifact:
            self._send_abort_once(RunnerControlCode.LOCAL_ABORT)
            self._close_and_collect(outer_deadline, expected_exit=EXIT_RUNNER_ABORT)
            self._safe_abandon()
            raise BridgeError("LOCAL_ABORT")
        self._assert_bound_reload(
            row_id=row_id,
            filename=filename,
            artifact_commitment=actual_artifact,
        )
        self.store.mark_ready(self.epoch_ref)
        self._ingest_stage("EPOCH_READY", {"state": "READY"})
        self.store.activate(self.epoch_ref)
        self._ingest_stage("RUNNER_STARTED", {"state": "RUNNER_STARTED"})
        started = self._assert_runner_started_reload()
        pre_cas_ledger_digest = self.store.ledger_digest(self.epoch_ref)
        transition, transition_id, transition_commitment = build_restore_transition(
            epoch_ref=started.record["epoch_ref"],
            authority_ref=started.record["authority_ref"],
            runner_commitment=started.record["runner_commitment"],
            runner_bundle_commitment=self.runner_bundle.commitment,
            barrier_utc=self.barrier_utc,
            artifact_commitment=actual_artifact,
            isolation_commitment=isolation_commitment,
            pre_cas_ledger_digest=pre_cas_ledger_digest,
        )
        cas_result = None
        cas_error: BaseException | None = None
        try:
            cas_result = self.store.consume_restore(
                self.epoch_ref,
                transition_id,
                expected_digest=pre_cas_ledger_digest,
                data=transition,
            )
        except BaseException as error:
            cas_error = error
        self._resolve_cas(
            started,
            transition_id=transition_id,
            transition_commitment=transition_commitment,
            cas_result=cas_result,
            cas_error=cas_error,
        )
        self._ingest_stage(
            "RESTORE_BEGIN",
            {"ref": transition_id, "commitment": transition_commitment},
        )
        self._restore_begin_durable = True
        consumed_record_digest = self.store.record_digest(self.epoch_ref)
        return (
            actual_artifact,
            isolation_commitment,
            transition_id,
            pre_cas_ledger_digest,
            transition_commitment,
            consumed_record_digest,
        )

    def _proceed_and_finalize(
        self,
        values: tuple[str, str, str, str, str, str],
        outer_deadline: float,
    ) -> BridgeResult:
        (
            actual_artifact,
            isolation_commitment,
            transition_id,
            pre_cas_ledger_digest,
            transition_commitment,
            consumed_record_digest,
        ) = values
        assert self._graph is not None
        capability = proceed_commitment(
            self._graph,
            actual_artifact,
            isolation_commitment,
            transition_id,
            pre_cas_ledger_digest,
            transition_commitment,
            consumed_record_digest,
        )
        token = _grant_token(self._graph, capability)
        proceed_payload = {
            "type": "PROCEED",
            "version": 1,
            "epoch_digest": _digest_commitment(self._graph.epoch_digest),
            "authority_digest": _digest_commitment(self._graph.authority_digest),
            "runner_digest": _digest_commitment(self._graph.runner_digest),
            "bundle_digest": _digest_commitment(self._graph.bundle_digest),
            "barrier_utc": self.barrier_utc,
            "artifact_commitment": actual_artifact,
            "isolation_commitment": isolation_commitment,
            "transition_id": transition_id,
            "pre_cas_ledger_digest": pre_cas_ledger_digest,
            "transition_data_commitment": transition_commitment,
            "consumed_record_digest": consumed_record_digest,
            "grant": base64.urlsafe_b64encode(token).decode("ascii").rstrip("="),
        }
        if not self._should_proceed():
            self._send_abort_once(RunnerControlCode.LOCAL_ABORT)
            self._close_and_collect(outer_deadline, expected_exit=EXIT_RUNNER_ABORT)
            self._safe_abandon()
            return self._result("FAILURE", "LOCAL_ABORT", post_cas_uncertain=True)
        self._send(
            self._graph.k_session,
            DIRECTION_LOCAL_TO_REMOTE,
            MESSAGE_PROCEED,
            encode_control(proceed_payload),
            self._phase_deadline(outer_deadline, PROCEED_TIMEOUT_SECONDS),
        )
        self._proceed_sent = True
        self.counters.proceed_messages += 1
        terminal = self._receive(
            self._graph.k_session,
            DIRECTION_REMOTE_TO_LOCAL,
            self._phase_deadline(outer_deadline, RESULT_TIMEOUT_SECONDS),
        )
        self._terminal = True
        if terminal.message == MESSAGE_ABORT:
            abort_value = decode_control(terminal.payload, "ABORT")
            self._close_and_collect(outer_deadline, expected_exit=EXIT_RUNNER_ABORT)
            self._safe_abandon()
            return self._result(
                "FAILURE",
                abort_value["code"],
                post_cas_uncertain=True,
            )
        if terminal.message != MESSAGE_RESULT:
            _raise(BridgeError, "FRAME_INVALID")
        result_value = decode_control(terminal.payload, "RESULT")
        self.counters.result_messages += 1
        classification = ResultClassification(result_value["classification"])
        finality_error = self._close_and_collect(
            outer_deadline,
            expected_exit=EXIT_SUCCESS,
        )
        if finality_error is not None:
            self._safe_abandon()
            return self._result(
                "FAILURE",
                finality_error,
                post_cas_uncertain=True,
            )
        if classification is ResultClassification.FAILURE:
            self._safe_abandon()
            return self._result("FAILURE", None, post_cas_uncertain=False)
        # A remote SUCCESS is evidence only.  The local canonical store is
        # allowed to COMMIT only after process finality has passed.
        self._ingest_stage(
            "COMMIT",
            {
                "classification": ResultClassification.SUCCESS.value,
                "commitment": result_value["result_commitment"],
            },
        )
        return self._result("SUCCESS", None, post_cas_uncertain=False)

    def run(self) -> BridgeResult:
        outer_deadline = self.clock() + self.timeout_seconds
        try:
            snapshot = self._load_initial_snapshot()
            process = self.launcher()
            if process is None:
                _raise(BridgeError, "PROTOCOL_FAILURE")
            self._supervisor = ProcessSupervisor(process, clock=self.clock)
            self._supervisor.start()
            hello = decode_hello(
                self._supervisor.read_exact(
                    HELLO_SIZE,
                    self._phase_deadline(outer_deadline, HELLO_TIMEOUT_SECONDS),
                )
            )
            n_local = self._random_bytes(SESSION_NONCE_BYTES)
            record_commitment = self.store.record_digest(self.epoch_ref)
            authority_commitment = bridge_commitment(
                "authority",
                snapshot.record["authority_ref"],
            )
            self._graph = derive_local_key_graph(
                spool_hmac_key=snapshot.private_identities["spool_hmac_key"],
                salt=snapshot.private_identities["salt"],
                epoch_ref=snapshot.record["epoch_ref"],
                authority_ref=snapshot.record["authority_ref"],
                runner_identity=snapshot.private_identities["runner_identity"],
                bundle=self.runner_bundle,
                n_remote=hello,
                n_local=n_local,
                record_commitment=record_commitment,
                loader_commitment=fixed_loader_commitment(),
                runner_commitment=snapshot.record["runner_commitment"],
                authority_commitment=authority_commitment,
                barrier_utc=self.barrier_utc,
            )
            self._supervisor.write_all(
                encode_preamble(
                    self._graph.n_remote,
                    self._graph.n_local,
                    self._graph.n_session,
                    self._graph.epoch_digest,
                    self._graph.authority_digest,
                    self._graph.runner_digest,
                    self._graph.bundle_digest,
                    self._graph.bootstrap_seed,
                ),
                self._phase_deadline(outer_deadline, BOOT_TIMEOUT_SECONDS),
            )
            self._send(
                self._graph.k_boot,
                DIRECTION_LOCAL_TO_REMOTE,
                MESSAGE_BOOT,
                encode_boot_payload(self.runner_bundle, self.barrier_utc),
                self._phase_deadline(outer_deadline, BOOT_TIMEOUT_SECONDS),
            )
            ready = self._receive(
                self._graph.k_session,
                DIRECTION_REMOTE_TO_LOCAL,
                self._phase_deadline(outer_deadline, READY_TIMEOUT_SECONDS),
            )
            if ready.message == MESSAGE_ABORT:
                return self._handle_remote_abort(ready, outer_deadline)
            if ready.message != MESSAGE_READY:
                _raise(BridgeError, "FRAME_INVALID")
            ready_value = decode_control(ready.payload, "READY")
            if ready_value["barrier_utc"] != self.barrier_utc:
                _raise(BridgeError, "FRAME_INVALID")
            discovery = self._receive(
                self._graph.k_session,
                DIRECTION_REMOTE_TO_LOCAL,
                self._phase_deadline(outer_deadline, DISCOVERY_TIMEOUT_SECONDS),
            )
            if discovery.message == MESSAGE_ABORT:
                return self._handle_remote_abort(discovery, outer_deadline)
            if discovery.message != MESSAGE_DISCOVERY:
                _raise(BridgeError, "FRAME_INVALID")
            lifecycle_values = self._bind_and_consume(
                discovery,
                snapshot,
                outer_deadline,
            )
            return self._proceed_and_finalize(lifecycle_values, outer_deadline)
        except BridgeError as error:
            if self._graph is not None and not self._terminal:
                self._send_abort_once(RunnerControlCode.LOCAL_ABORT)
            self._safe_abandon()
            return self._result(
                "FAILURE",
                error.code,
                post_cas_uncertain=self._post_cas,
            )
        except Exception:
            if self._graph is not None and not self._terminal:
                self._send_abort_once(RunnerControlCode.LOCAL_ABORT)
            self._safe_abandon()
            return self._result(
                "FAILURE",
                "PROTOCOL_FAILURE",
                post_cas_uncertain=self._post_cas,
            )
        finally:
            if self._supervisor is not None:
                self._supervisor.stop()


_Run318ControllerBridge = ControllerBridge


class _DummyControllerBridge(ControllerBridge):
    """Test-only decision injection kept outside the operational API."""

    def __init__(self, *args: Any, decision: DummyDecision, **kwargs: Any):
        super().__init__(*args, launcher=spawn_dummy_child, **kwargs)
        self._test_decision = decision

    def _should_proceed(self) -> bool:
        return self._test_decision.proceed


_Run318DummyControllerBridge = _DummyControllerBridge


# Canonical remote exports are loaded from CANONICAL_LOADER_PAYLOAD_BYTES below.
# RunnerRuntime is exported by the canonical payload.
# RemoteLoader is exported by the canonical payload.
CANONICAL_LOADER_PAYLOAD_BYTES = (
    b"import base64 as _b64\n"
    b"import binascii as _bin\n"
    b"import builtins as _builtins\n"
    b"import contextlib as _ctx\n"
    b"import datetime as _datetime\n"
    b"import hashlib as _hashlib\n"
    b"import hmac as _hmac\n"
    b"import inspect as _inspect\n"
    b"import io as _io\n"
    b"import json as _json\n"
    b"import os as _os\n"
    b"import queue as _queue\n"
    b"import re as _re\n"
    b"import signal as _signal\n"
    b"import struct as _struct\n"
    b"import subprocess as _subprocess\n"
    b"import sys as _sys\n"
    b"import threading as _threading\n"
    b"import time as _time\n"
    b"import types as _types\n"
    b"from enum import Enum as _Enum\n"
    b"\n"
    b"_VERSION = 1\n"
    b"_HELLO_MAGIC = b\"SWZBRDG1\"\n"
    b"_HELLO = _struct.Struct(\"!8sBBH32s\")\n"
    b"_PREAMBLE_MAGIC = b\"SWZPRE01\"\n"
    b"_PREAMBLE_HEADER = _struct.Struct(\"!8sBBHHH\")\n"
    b"_PREAMBLE_BODY = _struct.Struct(\"!32s32s32s32s32s32s32s32s\")\n"
    b"_FRAME_MAGIC = b\"SWZFRM01\"\n"
    b"_FRAME = _struct.Struct(\"!8sBBBBQ32s16sI\")\n"
    b"_TAG_BYTES = 32\n"
    b"_FRAME_OVERHEAD = _FRAME.size + _TAG_BYTES\n"
    b"_MAX_FRAME = 64 * 1024\n"
    b"_MAX_PAYLOAD = _MAX_FRAME - _FRAME_OVERHEAD\n"
    b"_MAX_FRAMES = 16\n"
    b"_MAX_SESSION_BYTES = 1048576\n"
    b"_FRAME_FLAGS = 0\n"
    b"_LOCAL_TO_REMOTE = 1\n"
    b"_REMOTE_TO_LOCAL = 2\n"
    b"_BOOT = 1\n"
    b"_READY = 2\n"
    b"_DISCOVERY = 3\n"
    b"_PROCEED = 4\n"
    b"_ABORT = 5\n"
    b"_RESULT = 6\n"
    b"_BOOT_BARRIER_BYTES = 27\n"
    b"_MAX_BUNDLE_BYTES = 65536\n"
    b"_CONTROL_MAX_BYTES = 4096\n"
    b"_COMMITMENT_RE = _re.compile(r\"sha256:v1:[0-9a-f]{64}\\Z\", _re.ASCII)\n"
    b"_BARRIER_RE = _re.compile(\n"
    b"    r\"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{6}Z\",\n"
    b"    _re.ASCII,\n"
    b")\n"
    b"_ROOTS = frozenset({\n"
    b"    \"base64\", \"binascii\", \"collections\", \"contextlib\", \"dataclasses\",\n"
    b"    \"datetime\", \"hashlib\", \"hmac\", \"io\", \"json\", \"math\", \"os\",\n"
    b"    \"pathlib\", \"queue\", \"re\", \"selectors\", \"shlex\", \"signal\", \"stat\",\n"
    b"    \"struct\", \"subprocess\", \"sys\", \"threading\", \"time\", \"typing\", \"uuid\",\n"
    b"})\n"
    b"\n"
    b"class RunnerAbortCode(str, _Enum):\n"
    b"    PRESTATE_FAILED = \"PRESTATE_FAILED\"\n"
    b"    BACKUP_NOT_QUALIFYING = \"BACKUP_NOT_QUALIFYING\"\n"
    b"    LOCATOR_NOT_FOUND = \"LOCATOR_NOT_FOUND\"\n"
    b"    LOCATOR_AMBIGUOUS = \"LOCATOR_AMBIGUOUS\"\n"
    b"    RESOURCE_COLLISION = \"RESOURCE_COLLISION\"\n"
    b"    RESOURCE_CREATE_FAILED = \"RESOURCE_CREATE_FAILED\"\n"
    b"    ISOLATION_FAILED = \"ISOLATION_FAILED\"\n"
    b"    CLEANUP_UNPROVEN = \"CLEANUP_UNPROVEN\"\n"
    b"    RESTORE_PRECONDITION_FAILED = \"RESTORE_PRECONDITION_FAILED\"\n"
    b"    RUNNER_ABORTED = \"RUNNER_ABORTED\"\n"
    b"\n"
    b"class RunnerControlCode(str, _Enum):\n"
    b"    PRESTATE_FAILED = RunnerAbortCode.PRESTATE_FAILED.value\n"
    b"    BACKUP_NOT_QUALIFYING = RunnerAbortCode.BACKUP_NOT_QUALIFYING.value\n"
    b"    LOCATOR_NOT_FOUND = RunnerAbortCode.LOCATOR_NOT_FOUND.value\n"
    b"    LOCATOR_AMBIGUOUS = RunnerAbortCode.LOCATOR_AMBIGUOUS.value\n"
    b"    RESOURCE_COLLISION = RunnerAbortCode.RESOURCE_COLLISION.value\n"
    b"    RESOURCE_CREATE_FAILED = RunnerAbortCode.RESOURCE_CREATE_FAILED.value\n"
    b"    ISOLATION_FAILED = RunnerAbortCode.ISOLATION_FAILED.value\n"
    b"    CLEANUP_UNPROVEN = RunnerAbortCode.CLEANUP_UNPROVEN.value\n"
    b"    RESTORE_PRECONDITION_FAILED = RunnerAbortCode.RESTORE_PRECONDITION_FAILED.value\n"
    b"    RUNNER_ABORTED = RunnerAbortCode.RUNNER_ABORTED.value\n"
    b"    DECISION_EOF = \"DECISION_EOF\"\n"
    b"    DECISION_TIMEOUT = \"DECISION_TIMEOUT\"\n"
    b"    DECISION_BROKEN_PIPE = \"DECISION_BROKEN_PIPE\"\n"
    b"    PROTOCOL_BROKEN_PIPE = \"PROTOCOL_BROKEN_PIPE\"\n"
    b"    PROCEED_INVALID = \"PROCEED_INVALID\"\n"
    b"    PROTOCOL_FAILURE = \"PROTOCOL_FAILURE\"\n"
    b"    LOCAL_ABORT = \"LOCAL_ABORT\"\n"
    b"    RUNTIME_TERMINAL = \"RUNTIME_TERMINAL\"\n"
    b"    RUNNER_STDOUT_FORBIDDEN = \"RUNNER_STDOUT_FORBIDDEN\"\n"
    b"    RUNNER_STDERR_FORBIDDEN = \"RUNNER_STDERR_FORBIDDEN\"\n"
    b"    RUNNER_INPUT_FORBIDDEN = \"RUNNER_INPUT_FORBIDDEN\"\n"
    b"    SUBPROCESS_STDIO_REQUIRED = \"SUBPROCESS_STDIO_REQUIRED\"\n"
    b"    DISCOVERY_DUPLICATE = \"DISCOVERY_DUPLICATE\"\n"
    b"    RESULT_BEFORE_PROCEED = \"RESULT_BEFORE_PROCEED\"\n"
    b"    RESULT_DUPLICATE = \"RESULT_DUPLICATE\"\n"
    b"    RUNNER_MISSING = \"RUNNER_MISSING\"\n"
    b"    RUNNER_NOT_CALLABLE = \"RUNNER_NOT_CALLABLE\"\n"
    b"    RUNNER_SIGNATURE_INVALID = \"RUNNER_SIGNATURE_INVALID\"\n"
    b"    RUNNER_TOP_LEVEL_EXCEPTION = \"RUNNER_TOP_LEVEL_EXCEPTION\"\n"
    b"    RUNNER_NO_RESULT = \"RUNNER_NO_RESULT\"\n"
    b"    RUNNER_NON_NONE_RETURN = \"RUNNER_NON_NONE_RETURN\"\n"
    b"\n"
    b"class ResultClassification(str, _Enum):\n"
    b"    SUCCESS = \"SUCCESS\"\n"
    b"    FAILURE = \"FAILURE\"\n"
    b"\n"
    b"class RunnerControlError(Exception):\n"
    b"    def __init__(self, code):\n"
    b"        if isinstance(code, RunnerAbortCode):\n"
    b"            code = RunnerControlCode(code.value)\n"
    b"        elif not isinstance(code, RunnerControlCode):\n"
    b"            try:\n"
    b"                code = RunnerControlCode(code)\n"
    b"            except (TypeError, ValueError):\n"
    b"                code = RunnerControlCode.PROTOCOL_FAILURE\n"
    b"        self.code = code\n"
    b"        super().__init__(code.value)\n"
    b"\n"
    b"def _fail(code):\n"
    b"    raise RunnerControlError(code)\n"
    b"\n"
    b"def _lp(*parts):\n"
    b"    result = bytearray()\n"
    b"    for part in parts:\n"
    b"        if isinstance(part, bytes):\n"
    b"            value = part\n"
    b"        elif isinstance(part, str):\n"
    b"            value = part.encode(\"utf-8\", \"strict\")\n"
    b"        else:\n"
    b"            _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"        if len(value) > 0xffffffff:\n"
    b"            _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"        result.extend(_struct.pack(\"!I\", len(value)))\n"
    b"        result.extend(value)\n"
    b"    return bytes(result)\n"
    b"\n"
    b"def _recovery_commitment(domain, *parts):\n"
    b"    return \"sha256:v1:\" + _hashlib.sha256(\n"
    b"        _lp(\"recovery-commitment.v1\", domain, *parts)\n"
    b"    ).hexdigest()\n"
    b"\n"
    b"def _bytes_commitment(domain, payload):\n"
    b"    if not isinstance(payload, bytes):\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    framed = _lp(\"recovery-commitment.v1\", domain)\n"
    b"    return \"sha256:v1:\" + _hashlib.sha256(\n"
    b"        framed + _struct.pack(\"!I\", len(payload)) + payload\n"
    b"    ).hexdigest()\n"
    b"\n"
    b"def _bridge_commitment(domain, *parts):\n"
    b"    return _bytes_commitment(\"bridge-\" + domain, _lp(*parts))\n"
    b"\n"
    b"def _is_commitment(value):\n"
    b"    return isinstance(value, str) and _COMMITMENT_RE.fullmatch(value) is not None\n"
    b"\n"
    b"def _commitment_bytes(value):\n"
    b"    if not _is_commitment(value):\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    try:\n"
    b"        return bytes.fromhex(value[10:])\n"
    b"    except ValueError:\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"\n"
    b"def _digest_commitment(value):\n"
    b"    if not isinstance(value, bytes) or len(value) != 32:\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    return \"sha256:v1:\" + value.hex()\n"
    b"\n"
    b"def _nonce(value, size):\n"
    b"    if not isinstance(value, bytes) or len(value) != size or not any(value):\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    return value\n"
    b"\n"
    b"def _derive(seed, domain, *parts):\n"
    b"    return _hmac.new(_nonce(seed, 32), _lp(domain, *parts), _hashlib.sha256).digest()\n"
    b"\n"
    b"def _json_bytes(value, limit):\n"
    b"    def check(child):\n"
    b"        if isinstance(child, float):\n"
    b"            _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"        if isinstance(child, dict):\n"
    b"            for key, item in child.items():\n"
    b"                if not isinstance(key, str):\n"
    b"                    _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"                check(item)\n"
    b"        elif isinstance(child, list):\n"
    b"            for item in child:\n"
    b"                check(item)\n"
    b"        elif isinstance(child, str):\n"
    b"            child.encode(\"utf-8\", \"strict\")\n"
    b"        elif child is not None and type(child) not in (int, bool):\n"
    b"            _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    check(value)\n"
    b"    try:\n"
    b"        result = _json.dumps(\n"
    b"            value, ensure_ascii=False, allow_nan=False, separators=(\",\", \":\")\n"
    b"        ).encode(\"utf-8\", \"strict\")\n"
    b"    except (TypeError, ValueError, UnicodeError, OverflowError):\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    if len(result) > limit:\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    return result\n"
    b"\n"
    b"def _parse_json(payload, limit):\n"
    b"    if not isinstance(payload, bytes) or not payload or len(payload) > limit:\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    try:\n"
    b"        text = payload.decode(\"utf-8\", \"strict\")\n"
    b"    except UnicodeDecodeError:\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    if text[:1] in \" \\t\\r\\n\" or text[-1:] in \" \\t\\r\\n\":\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    def pairs(items):\n"
    b"        result = {}\n"
    b"        for key, value in items:\n"
    b"            if key in result:\n"
    b"                _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"            result[key] = value\n"
    b"        return result\n"
    b"    try:\n"
    b"        decoder = _json.JSONDecoder(\n"
    b"            object_pairs_hook=pairs,\n"
    b"            parse_constant=lambda _value: _fail(RunnerControlCode.PROTOCOL_FAILURE),\n"
    b"        )\n"
    b"        value, end = decoder.raw_decode(text)\n"
    b"    except (_json.JSONDecodeError, RecursionError, ValueError, RunnerControlError):\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    if end != len(text) or _json_bytes(value, limit) != payload:\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    return value\n"
    b"\n"
    b"def _barrier(value):\n"
    b"    if not isinstance(value, str) or _BARRIER_RE.fullmatch(value) is None:\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    try:\n"
    b"        parsed = _datetime.datetime.strptime(value, \"%Y-%m-%dT%H:%M:%S.%fZ\")\n"
    b"    except ValueError:\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    if parsed.strftime(\"%Y-%m-%dT%H:%M:%S.%fZ\") != value:\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    if len(value.encode(\"ascii\", \"strict\")) != 27:\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    return value\n"
    b"\n"
    b"def _discovery_tuple(row, filename):\n"
    b"    if type(row) is not int or not 0 < row <= 0x7fffffffffffffff:\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    if not isinstance(filename, str):\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    encoded = filename.encode(\"utf-8\", \"strict\")\n"
    b"    if (\n"
    b"        not encoded or len(encoded) > 2048 or filename in (\".\", \"..\")\n"
    b"        or \"/\" in filename or \"\\\\\" in filename\n"
    b"        or any(ord(char) <= 0x1f or ord(char) == 0x7f for char in filename)\n"
    b"    ):\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    return row, filename\n"
    b"\n"
    b"def _validate_control(value, expected):\n"
    b"    fields = {\n"
    b"        \"READY\": (\"type\", \"version\", \"barrier_utc\"),\n"
    b"        \"DISCOVERY\": (\n"
    b"            \"type\", \"version\", \"execution_row_id\", \"artifact_filename\",\n"
    b"            \"isolation_state\", \"isolation_commitment\",\n"
    b"        ),\n"
    b"        \"PROCEED\": (\n"
    b"            \"type\", \"version\", \"epoch_digest\", \"authority_digest\",\n"
    b"            \"runner_digest\", \"bundle_digest\", \"barrier_utc\",\n"
    b"            \"artifact_commitment\", \"isolation_commitment\", \"transition_id\",\n"
    b"            \"pre_cas_ledger_digest\", \"transition_data_commitment\",\n"
    b"            \"consumed_record_digest\", \"grant\",\n"
    b"        ),\n"
    b"        \"ABORT\": (\"type\", \"version\", \"code\"),\n"
    b"        \"RESULT\": (\"type\", \"version\", \"classification\", \"result_commitment\"),\n"
    b"    }[expected]\n"
    b"    if (\n"
    b"        not isinstance(value, dict)\n"
    b"        or tuple(value.keys()) != fields\n"
    b"        or value.get(\"type\") != expected\n"
    b"        or value.get(\"version\") != 1\n"
    b"    ):\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    if expected == \"READY\":\n"
    b"        _barrier(value[\"barrier_utc\"])\n"
    b"    elif expected == \"DISCOVERY\":\n"
    b"        _discovery_tuple(value[\"execution_row_id\"], value[\"artifact_filename\"])\n"
    b"        if value[\"isolation_state\"] != \"PASS\" or not _is_commitment(value[\"isolation_commitment\"]):\n"
    b"            _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    elif expected == \"PROCEED\":\n"
    b"        for name in (\n"
    b"            \"epoch_digest\", \"authority_digest\", \"runner_digest\", \"bundle_digest\",\n"
    b"            \"artifact_commitment\", \"isolation_commitment\",\n"
    b"            \"pre_cas_ledger_digest\", \"transition_data_commitment\",\n"
    b"            \"consumed_record_digest\",\n"
    b"        ):\n"
    b"            if not _is_commitment(value[name]):\n"
    b"                _fail(RunnerControlCode.PROCEED_INVALID)\n"
    b"        _barrier(value[\"barrier_utc\"])\n"
    b"        if (\n"
    b"            type(value[\"transition_id\"]) is not str\n"
    b"            or _re.fullmatch(\n"
    b"                r\"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\",\n"
    b"                value[\"transition_id\"],\n"
    b"                _re.ASCII,\n"
    b"            ) is None\n"
    b"        ):\n"
    b"            _fail(RunnerControlCode.PROCEED_INVALID)\n"
    b"        if not isinstance(value[\"grant\"], str):\n"
    b"            _fail(RunnerControlCode.PROCEED_INVALID)\n"
    b"        try:\n"
    b"            raw = _b64.urlsafe_b64decode(value[\"grant\"] + \"===\")\n"
    b"        except (ValueError, TypeError, _bin.Error):\n"
    b"            _fail(RunnerControlCode.PROCEED_INVALID)\n"
    b"        if (\n"
    b"            len(raw) != 32\n"
    b"            or _b64.urlsafe_b64encode(raw).decode(\"ascii\").rstrip(\"=\")\n"
    b"            != value[\"grant\"]\n"
    b"        ):\n"
    b"            _fail(RunnerControlCode.PROCEED_INVALID)\n"
    b"    elif expected == \"ABORT\":\n"
    b"        try:\n"
    b"            RunnerControlCode(value[\"code\"])\n"
    b"        except (TypeError, ValueError):\n"
    b"            _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    else:\n"
    b"        try:\n"
    b"            ResultClassification(value[\"classification\"])\n"
    b"        except (TypeError, ValueError):\n"
    b"            _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"        if not _is_commitment(value[\"result_commitment\"]):\n"
    b"            _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    return value\n"
    b"\n"
    b"def _encode_control(value):\n"
    b"    return _json_bytes(value, _CONTROL_MAX_BYTES)\n"
    b"\n"
    b"def _decode_control(payload, expected=None):\n"
    b"    value = _parse_json(payload, _CONTROL_MAX_BYTES)\n"
    b"    if not isinstance(value, dict) or value.get(\"type\") not in (\n"
    b"        \"READY\", \"DISCOVERY\", \"PROCEED\", \"ABORT\", \"RESULT\"\n"
    b"    ):\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    if expected is not None and value[\"type\"] != expected:\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    return _validate_control(value, value[\"type\"])\n"
    b"\n"
    b"def _decode_preamble(payload):\n"
    b"    if not isinstance(payload, bytes) or len(payload) != 272:\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    try:\n"
    b"        header = _PREAMBLE_HEADER.unpack(payload[:_PREAMBLE_HEADER.size])\n"
    b"        body = _PREAMBLE_BODY.unpack(payload[_PREAMBLE_HEADER.size:])\n"
    b"    except _struct.error:\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    if header != (_PREAMBLE_MAGIC, 1, 2, 0, 256, 0):\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    return dict(zip(\n"
    b"        (\n"
    b"            \"n_remote\", \"n_local\", \"n_session\", \"epoch_digest\",\n"
    b"            \"authority_digest\", \"runner_digest\", \"bundle_digest\",\n"
    b"            \"bootstrap_seed\",\n"
    b"        ),\n"
    b"        body,\n"
    b"    ))\n"
    b"\n"
    b"def _decode_boot(payload, expected_digest):\n"
    b"    if not isinstance(payload, bytes) or len(payload) <= _BOOT_BARRIER_BYTES:\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    try:\n"
    b"        barrier = payload[:_BOOT_BARRIER_BYTES].decode(\"ascii\", \"strict\")\n"
    b"    except UnicodeDecodeError:\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    _barrier(barrier)\n"
    b"    source = payload[_BOOT_BARRIER_BYTES:]\n"
    b"    if not 1 <= len(source) <= _MAX_BUNDLE_BYTES:\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    if _commitment_bytes(_bytes_commitment(\"bridge-runner-bundle\", source)) != expected_digest:\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    return barrier, source\n"
    b"\n"
    b"def _frame_auth(key, header, payload):\n"
    b"    return _hmac.new(_nonce(key, 32), header + payload, _hashlib.sha256).digest()\n"
    b"\n"
    b"class _Frame:\n"
    b"    __slots__ = (\"direction\", \"message\", \"sequence\", \"session_nonce\", \"frame_nonce\", \"payload\")\n"
    b"    def __init__(self, direction, message, sequence, session_nonce, frame_nonce, payload):\n"
    b"        self.direction = direction\n"
    b"        self.message = message\n"
    b"        self.sequence = sequence\n"
    b"        self.session_nonce = session_nonce\n"
    b"        self.frame_nonce = frame_nonce\n"
    b"        self.payload = payload\n"
    b"    def __repr__(self):\n"
    b"        return (\n"
    b"            f\"AuthenticatedFrame(direction={self.direction}, message={self.message}, \"\n"
    b"            f\"sequence={self.sequence}, payload_bytes={len(self.payload)})\"\n"
    b"        )\n"
    b"\n"
    b"def _encode_frame(key, direction, message, sequence, session_nonce, payload, nonce):\n"
    b"    if direction not in (1, 2) or message not in (1, 2, 3, 4, 5, 6):\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    if type(sequence) is not int or not 1 <= sequence <= _MAX_FRAMES:\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    _nonce(key, 32)\n"
    b"    _nonce(session_nonce, 32)\n"
    b"    _nonce(nonce, 16)\n"
    b"    if not isinstance(payload, bytes) or len(payload) > _MAX_PAYLOAD:\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    header = _FRAME.pack(\n"
    b"        _FRAME_MAGIC, 1, direction, message, 0, sequence,\n"
    b"        session_nonce, nonce, len(payload)\n"
    b"    )\n"
    b"    return header + payload + _frame_auth(key, header, payload)\n"
    b"\n"
    b"def _decode_frame(payload, key, direction, sequence, session_nonce):\n"
    b"    if not isinstance(payload, bytes) or len(payload) < _FRAME_OVERHEAD:\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    try:\n"
    b"        header = payload[:_FRAME.size]\n"
    b"        magic, version, actual_direction, message, flags, actual_sequence, actual_session, nonce, length = _FRAME.unpack(header)\n"
    b"    except _struct.error:\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    if (\n"
    b"        magic != _FRAME_MAGIC or version != 1 or flags != 0\n"
    b"        or actual_direction != direction or message not in (1, 2, 3, 4, 5, 6)\n"
    b"        or actual_sequence != sequence or actual_session != session_nonce\n"
    b"        or length > _MAX_PAYLOAD or len(payload) != _FRAME_OVERHEAD + length\n"
    b"    ):\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    _nonce(nonce, 16)\n"
    b"    body = payload[_FRAME.size:_FRAME.size + length]\n"
    b"    if not _hmac.compare_digest(payload[-32:], _frame_auth(key, header, body)):\n"
    b"        _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"    return _Frame(actual_direction, message, actual_sequence, actual_session, nonce, body)\n"
    b"\n"
    b"def _read_once(stream, size, timeout):\n"
    b"    if timeout is None:\n"
    b"        return stream.read(size) or b\"\"\n"
    b"    if timeout <= 0:\n"
    b"        _fail(RunnerControlCode.DECISION_TIMEOUT)\n"
    b"    result = _queue.Queue(maxsize=1)\n"
    b"    def read():\n"
    b"        try:\n"
    b"            result.put((stream.read(size) or b\"\", None))\n"
    b"        except BaseException as error:\n"
    b"            result.put((None, error))\n"
    b"    thread = _threading.Thread(target=read, daemon=True)\n"
    b"    thread.start()\n"
    b"    try:\n"
    b"        value, error = result.get(timeout=timeout)\n"
    b"    except _queue.Empty:\n"
    b"        _fail(RunnerControlCode.DECISION_TIMEOUT)\n"
    b"    if error is not None:\n"
    b"        if isinstance(error, (BrokenPipeError, OSError, ValueError)):\n"
    b"            _fail(RunnerControlCode.DECISION_BROKEN_PIPE)\n"
    b"        raise error\n"
    b"    return value\n"
    b"\n"
    b"def _read_exact(stream, size, timeout=None, clock=_time.monotonic):\n"
    b"    result = bytearray()\n"
    b"    deadline = None if timeout is None else clock() + timeout\n"
    b"    while len(result) < size:\n"
    b"        remaining = None if deadline is None else max(0.0, deadline - clock())\n"
    b"        chunk = _read_once(stream, size - len(result), remaining)\n"
    b"        if not chunk:\n"
    b"            _fail(RunnerControlCode.DECISION_EOF)\n"
    b"        result.extend(chunk)\n"
    b"    return bytes(result)\n"
    b"\n"
    b"class _Graph:\n"
    b"    __slots__ = (\n"
    b"        \"n_remote\", \"n_local\", \"n_session\", \"epoch_digest\",\n"
    b"        \"authority_digest\", \"runner_digest\", \"bundle_digest\",\n"
    b"        \"bootstrap_seed\", \"epoch_commitment\", \"authority_commitment\",\n"
    b"        \"runner_commitment\", \"bundle_commitment\", \"loader_commitment\",\n"
    b"        \"barrier_utc\", \"barrier_commitment\", \"k_boot\", \"k_session\",\n"
    b"        \"k_proceed\",\n"
    b"    )\n"
    b"    def __init__(self, values, barrier=None):\n"
    b"        self.n_remote = _nonce(values[\"n_remote\"], 32)\n"
    b"        self.n_local = _nonce(values[\"n_local\"], 32)\n"
    b"        self.n_session = _nonce(values[\"n_session\"], 32)\n"
    b"        self.epoch_digest = _nonce(values[\"epoch_digest\"], 32)\n"
    b"        self.authority_digest = _nonce(values[\"authority_digest\"], 32)\n"
    b"        self.runner_digest = _nonce(values[\"runner_digest\"], 32)\n"
    b"        self.bundle_digest = _nonce(values[\"bundle_digest\"], 32)\n"
    b"        self.bootstrap_seed = _nonce(values[\"bootstrap_seed\"], 32)\n"
    b"        transcript = (\n"
    b"            self.n_remote, self.n_local, self.n_session, self.epoch_digest,\n"
    b"            self.authority_digest, self.runner_digest, self.bundle_digest,\n"
    b"        )\n"
    b"        expected = _derive(\n"
    b"            self.bootstrap_seed, \"N_session.v1\", self.n_remote, self.n_local,\n"
    b"            self.epoch_digest, self.authority_digest, self.runner_digest,\n"
    b"            self.bundle_digest,\n"
    b"        )\n"
    b"        if not _hmac.compare_digest(expected, self.n_session):\n"
    b"            _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"        self.epoch_commitment = _digest_commitment(self.epoch_digest)\n"
    b"        self.authority_commitment = _digest_commitment(self.authority_digest)\n"
    b"        self.runner_commitment = _digest_commitment(self.runner_digest)\n"
    b"        self.bundle_commitment = _digest_commitment(self.bundle_digest)\n"
    b"        self.loader_commitment = _bytes_commitment(\"bridge-loader\", p)\n"
    b"        if barrier is None:\n"
    b"            self.barrier_utc = None\n"
    b"            self.barrier_commitment = None\n"
    b"            barrier_digest = b\"\\0\" * 32\n"
    b"        else:\n"
    b"            self.barrier_utc = _barrier(barrier)\n"
    b"            self.barrier_commitment = _bytes_commitment(\n"
    b"                \"bridge-barrier\", barrier.encode(\"ascii\", \"strict\")\n"
    b"            )\n"
    b"            barrier_digest = _commitment_bytes(self.barrier_commitment)\n"
    b"        self.k_boot = _derive(self.bootstrap_seed, \"K_boot.v1\", *transcript)\n"
    b"        self.k_session = _derive(\n"
    b"            self.bootstrap_seed, \"K_session.v1\", *transcript, barrier_digest\n"
    b"        )\n"
    b"        self.k_proceed = _derive(\n"
    b"            self.bootstrap_seed, \"K_proceed.v1\", *transcript, barrier_digest\n"
    b"        )\n"
    b"\n"
    b"def _proceed_commitment(graph, artifact, isolation, transition_id, pre_cas, transition, consumed):\n"
    b"    if (\n"
    b"        not all(_is_commitment(value) for value in (\n"
    b"            artifact, isolation, pre_cas, transition, consumed\n"
    b"        ))\n"
    b"        or type(transition_id) is not str\n"
    b"        or _re.fullmatch(r\"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\", transition_id, _re.ASCII) is None\n"
    b"        or graph.barrier_utc is None\n"
    b"    ):\n"
    b"        _fail(RunnerControlCode.PROCEED_INVALID)\n"
    b"    return _bridge_commitment(\n"
    b"        \"proceed-capability\",\n"
    b"        graph.n_remote, graph.n_local, graph.n_session,\n"
    b"        graph.epoch_digest, graph.authority_digest, graph.runner_digest,\n"
    b"        graph.bundle_digest, graph.barrier_utc, graph.epoch_commitment,\n"
    b"        graph.authority_commitment, graph.runner_commitment,\n"
    b"        graph.bundle_commitment, graph.loader_commitment or \"\",\n"
    b"        graph.barrier_commitment or \"\", artifact, isolation, transition_id,\n"
    b"        pre_cas, transition, consumed,\n"
    b"    )\n"
    b"\n"
    b"def _grant_token(graph, capability):\n"
    b"    return _hmac.new(\n"
    b"        graph.k_proceed, _lp(\"C_proceed.v1\", capability), _hashlib.sha256\n"
    b"    ).digest()\n"
    b"\n"
    b"class _ForbiddenTextStream:\n"
    b"    __slots__ = (\"_code\",)\n"
    b"    def __init__(self, code):\n"
    b"        self._code = code\n"
    b"    @property\n"
    b"    def buffer(self):\n"
    b"        return self\n"
    b"    def write(self, _value):\n"
    b"        raise RunnerControlError(self._code)\n"
    b"    def flush(self):\n"
    b"        raise RunnerControlError(self._code)\n"
    b"    def read(self, _size=-1):\n"
    b"        raise RunnerControlError(self._code)\n"
    b"    def readline(self, _size=-1):\n"
    b"        raise RunnerControlError(self._code)\n"
    b"    def fileno(self):\n"
    b"        raise RunnerControlError(self._code)\n"
    b"    def close(self):\n"
    b"        return None\n"
    b"    @property\n"
    b"    def encoding(self):\n"
    b"        return \"utf-8\"\n"
    b"\n"
    b"class _GuardedSysProxy:\n"
    b"    __slots__ = (\"_raw\", \"_streams\")\n"
    b"    _NAMES = (\n"
    b"        \"executable\", \"stdin\", \"stdout\", \"stderr\",\n"
    b"        \"__stdin__\", \"__stdout__\", \"__stderr__\",\n"
    b"    )\n"
    b"    def __init__(self, raw):\n"
    b"        object.__setattr__(self, \"_raw\", raw)\n"
    b"        object.__setattr__(self, \"_streams\", {})\n"
    b"    def __getattribute__(self, name):\n"
    b"        if name in _GuardedSysProxy._NAMES:\n"
    b"            raw = object.__getattribute__(self, \"_raw\")\n"
    b"            streams = object.__getattribute__(self, \"_streams\")\n"
    b"            if name == \"executable\":\n"
    b"                return raw.executable\n"
    b"            return streams.get(name, getattr(raw, name))\n"
    b"        raise AttributeError(name)\n"
    b"    def __setattr__(self, _name, _value):\n"
    b"        raise AttributeError(\"sealed sys\")\n"
    b"    def __delattr__(self, _name):\n"
    b"        raise AttributeError(\"sealed sys\")\n"
    b"    def __dir__(self):\n"
    b"        return list(_GuardedSysProxy._NAMES)\n"
    b"    def __repr__(self):\n"
    b"        return \"<GuardedSysProxy>\"\n"
    b"\n"
    b"_CAPABILITY_DENY = \"DENY\"\n"
    b"_CAPABILITY_RETAIN_SAFE = \"RETAIN_SAFE\"\n"
    b"_CAPABILITY_GUARDED_SAFE = \"GUARDED_SAFE\"\n"
    b"_CAPABILITY_INVENTORY_ROOTS = (\"os\", \"contextlib\", \"signal\", \"subprocess\", \"sys\")\n"
    b"_CAPABILITY_OS_NAMES = frozenset({\n"
    b"    \"system\", \"popen\", \"startfile\",\n"
    b"    \"fork\", \"forkpty\", \"vfork\",\n"
    b"    \"posix_spawn\", \"posix_spawnp\",\n"
    b"    \"execl\", \"execle\", \"execlp\", \"execlpe\",\n"
    b"    \"execv\", \"execve\", \"execvp\", \"execvpe\",\n"
    b"    \"spawnl\", \"spawnle\", \"spawnlp\", \"spawnlpe\",\n"
    b"    \"spawnv\", \"spawnve\", \"spawnvp\", \"spawnvpe\",\n"
    b"    \"P_WAIT\", \"P_NOWAIT\", \"P_NOWAITO\", \"P_OVERLAY\",\n"
    b"    \"P_DETACH\", \"P_DETACHED\",\n"
    b"    \"dup\", \"dup2\", \"dup3\", \"pipe\", \"pipe2\",\n"
    b"    \"openpty\", \"posix_openpt\", \"grantpt\", \"unlockpt\",\n"
    b"    \"login_tty\",\n"
    b"    \"get_inheritable\", \"set_inheritable\",\n"
    b"    \"get_handle_inheritable\", \"set_handle_inheritable\",\n"
    b"    \"get_blocking\", \"set_blocking\", \"pidfd_getfd\",\n"
    b"    \"O_CLOEXEC\", \"O_CLOFORK\", \"O_NOINHERIT\",\n"
    b"    \"register_at_fork\",\n"
    b"})\n"
    b"\n"
    b"def _capability_entries(root, default, overrides):\n"
    b"    module = _builtins.__import__(root)\n"
    b"    names = tuple(name for name in dir(module) if isinstance(name, str) and not name.startswith(\"_\"))\n"
    b"    entries = {name: default for name in names}\n"
    b"    entries.update(overrides)\n"
    b"    return _types.MappingProxyType(entries)\n"
    b"\n"
    b"_CAPABILITY_CLASSIFICATION_ROOTS = {\n"
    b"    \"os\": _capability_entries(\"os\", _CAPABILITY_RETAIN_SAFE, {**{name: _CAPABILITY_DENY for name in _CAPABILITY_OS_NAMES}, \"getenv\": _CAPABILITY_RETAIN_SAFE, \"reload_environ\": _CAPABILITY_RETAIN_SAFE}),\n"
    b"    \"contextlib\": _capability_entries(\"contextlib\", _CAPABILITY_RETAIN_SAFE, {name: _CAPABILITY_DENY for name in (\"redirect_stdin\", \"redirect_stdout\", \"redirect_stderr\")}),\n"
    b"    \"signal\": _capability_entries(\"signal\", _CAPABILITY_RETAIN_SAFE, {\"set_wakeup_fd\": _CAPABILITY_DENY, \"SIGBREAK\": _CAPABILITY_RETAIN_SAFE}),\n"
    b"    \"subprocess\": _capability_entries(\"subprocess\", _CAPABILITY_DENY, {name: _CAPABILITY_GUARDED_SAFE for name in (\"PIPE\", \"DEVNULL\", \"STDOUT\", \"TimeoutExpired\", \"CompletedProcess\", \"Popen\", \"run\", \"check_output\")}),\n"
    b"    \"sys\": _capability_entries(\"sys\", _CAPABILITY_DENY, {name: _CAPABILITY_GUARDED_SAFE for name in (\"executable\", \"stdin\", \"stdout\", \"stderr\", \"__stdin__\", \"__stdout__\", \"__stderr__\")}),\n"
    b"}\n"
    b"_CAPABILITY_CLASSIFICATION_REGISTRY = _types.MappingProxyType({\n"
    b"    \"nt\": _types.MappingProxyType(dict(_CAPABILITY_CLASSIFICATION_ROOTS)),\n"
    b"    \"posix\": _types.MappingProxyType(dict(_CAPABILITY_CLASSIFICATION_ROOTS)),\n"
    b"})\n"
    b"def _guard_module_alias(value, root):\n"
    b"    if root == \"sys\":\n"
    b"        return _GUARDED_SYS\n"
    b"    if root == \"subprocess\":\n"
    b"        return _GUARDED_SUBPROCESS\n"
    b"    if root not in _ROOTS:\n"
    b"        raise ImportError(\"RUNNER_IMPORT_FORBIDDEN\")\n"
    b"    return _GuardedModuleProxy(value, root)\n"
    b"\n"
    b"def _verify_module_alias_inventory(modules=None):\n"
    b"    sources = _raw_module_sources(modules)\n"
    b"    observed = _raw_module_alias_inventory(modules)\n"
    b"    for root, name, child_root in observed:\n"
    b"        value = getattr(sources[root], name)\n"
    b"        if child_root not in _ROOTS:\n"
    b"            try:\n"
    b"                _guard_module_alias(value, child_root)\n"
    b"            except ImportError as error:\n"
    b"                if str(error) == \"RUNNER_IMPORT_FORBIDDEN\":\n"
    b"                    continue\n"
    b"                raise\n"
    b"            raise ImportError(\"RUNNER_MODULE_ALIAS_UNGUARDED\")\n"
    b"        guarded = _guard_module_alias(value, child_root)\n"
    b"        expected = (\"_GuardedSysProxy\" if child_root == \"sys\" else \"_GuardedSubprocessProxy\" if child_root == \"subprocess\" else \"_GuardedModuleProxy\")\n"
    b"        if type(guarded).__name__ != expected:\n"
    b"            raise ImportError(\"RUNNER_MODULE_ALIAS_UNGUARDED\")\n"
    b"    return observed\n"
    b"\n"
    b"def _capability_registry(platform=None):\n"
    b"    platform = _os.name if platform is None else platform\n"
    b"    try:\n"
    b"        return _CAPABILITY_CLASSIFICATION_REGISTRY[platform]\n"
    b"    except (KeyError, TypeError):\n"
    b"        raise ImportError(\"RUNNER_CAPABILITY_PLATFORM_UNSUPPORTED:\" + repr(platform))\n"
    b"\n"
    b"def _raw_module_sources(modules=None):\n"
    b"    sources = {root: _builtins.__import__(root) for root in _ROOTS}\n"
    b"    if modules is not None:\n"
    b"        try:\n"
    b"            sources.update(modules)\n"
    b"        except (AttributeError, TypeError, ValueError):\n"
    b"            raise ImportError(\"RUNNER_CAPABILITY_INVENTORY_FAILED:modules\")\n"
    b"    return sources\n"
    b"\n"
    b"def _raw_capability_inventory(platform=None, modules=None):\n"
    b"    platform = _os.name if platform is None else platform\n"
    b"    _capability_registry(platform)\n"
    b"    sources = _raw_module_sources(modules)\n"
    b"    observed = []\n"
    b"    for root in _CAPABILITY_INVENTORY_ROOTS:\n"
    b"        try:\n"
    b"            public_names = tuple(name for name in dir(sources[root]) if isinstance(name, str) and not name.startswith(\"_\"))\n"
    b"        except (AttributeError, KeyError, TypeError):\n"
    b"            raise ImportError(\"RUNNER_CAPABILITY_INVENTORY_FAILED:\" + repr((platform, root)))\n"
    b"        observed.extend((platform, root, name) for name in public_names)\n"
    b"    observed.extend((platform, \"sys\", name) for name in _GuardedSysProxy._NAMES)\n"
    b"    return tuple(sorted(set(observed)))\n"
    b"\n"
    b"def _raw_module_alias_inventory(modules=None):\n"
    b"    sources = _raw_module_sources(modules)\n"
    b"    observed = []\n"
    b"    for root in sorted(_ROOTS):\n"
    b"        module = sources[root]\n"
    b"        for name in dir(module):\n"
    b"            if not isinstance(name, str) or name.startswith(\"_\"):\n"
    b"                continue\n"
    b"            try:\n"
    b"                value = getattr(module, name)\n"
    b"            except AttributeError:\n"
    b"                continue\n"
    b"            if isinstance(value, _types.ModuleType):\n"
    b"                child_name = getattr(value, \"__name__\", \"\")\n"
    b"                child_root = child_name.split(\".\", 1)[0] if isinstance(child_name, str) else \"\"\n"
    b"                observed.append((root, name, child_root))\n"
    b"    return tuple(sorted(set(observed)))\n"
    b"\n"
    b"def _require_capability_classifications(platform=None, modules=None):\n"
    b"    platform = _os.name if platform is None else platform\n"
    b"    registry = _capability_registry(platform)\n"
    b"    observed = _raw_capability_inventory(platform, modules)\n"
    b"    unknown = tuple(\n"
    b"        item for item in observed\n"
    b"        if item[1] not in registry or item[2] not in registry[item[1]]\n"
    b"    )\n"
    b"    if unknown:\n"
    b"        raise ImportError(\"RUNNER_CAPABILITY_UNCLASSIFIED:\" + repr(unknown))\n"
    b"    _verify_module_alias_inventory(modules)\n"
    b"    return registry\n"
    b"\n"
    b"def _capability_classification(root, name):\n"
    b"    if root not in _CAPABILITY_INVENTORY_ROOTS:\n"
    b"        return None\n"
    b"    registry = _require_capability_classifications()\n"
    b"    entries = registry[root]\n"
    b"    return entries[name] if name in entries else None\n"
    b"\n"
    b"_PROCESS_CAPABILITY_POLICY = _types.MappingProxyType({\n"
    b"    \"os\": _CAPABILITY_OS_NAMES,\n"
    b"    \"contextlib\": frozenset({\n"
    b"        \"redirect_stdin\", \"redirect_stdout\", \"redirect_stderr\",\n"
    b"    }),\n"
    b"    \"signal\": frozenset({\"set_wakeup_fd\"}),\n"
    b"})\n"
    b"\n"
    b"class _GuardedModuleProxy:\n"
    b"    __slots__ = (\"_module\", \"_root\")\n"
    b"    def __init__(self, module, root):\n"
    b"        object.__setattr__(self, \"_module\", module)\n"
    b"        object.__setattr__(self, \"_root\", root)\n"
    b"    def __getattribute__(self, name):\n"
    b"        if name == \"__name__\":\n"
    b"            return object.__getattribute__(self, \"_root\")\n"
    b"        if not isinstance(name, str) or name.startswith(\"_\"):\n"
    b"            raise AttributeError(name)\n"
    b"        root = object.__getattribute__(self, \"_root\")\n"
    b"        classification = _capability_classification(root, name)\n"
    b"        if classification == _CAPABILITY_DENY or name in _PROCESS_CAPABILITY_POLICY.get(root, ()):\n"
    b"            raise AttributeError(name)\n"
    b"        module = object.__getattribute__(self, \"_module\")\n"
    b"        value = getattr(module, name)\n"
    b"        if isinstance(value, _types.ModuleType):\n"
    b"            child = getattr(value, \"__name__\", \"\")\n"
    b"            root = child.split(\".\", 1)[0]\n"
    b"            if root == \"sys\":\n"
    b"                return _GUARDED_SYS\n"
    b"            if root == \"subprocess\":\n"
    b"                return _GUARDED_SUBPROCESS\n"
    b"            if root not in _ROOTS:\n"
    b"                raise ImportError(\"RUNNER_IMPORT_FORBIDDEN\")\n"
    b"            return _module_proxy(value, root)\n"
    b"        return value\n"
    b"    def __setattr__(self, _name, _value):\n"
    b"        raise AttributeError(\"sealed module\")\n"
    b"    def __delattr__(self, _name):\n"
    b"        raise AttributeError(\"sealed module\")\n"
    b"    def __dir__(self):\n"
    b"        module = object.__getattribute__(self, \"_module\")\n"
    b"        root = object.__getattribute__(self, \"_root\")\n"
    b"        denied = set(_PROCESS_CAPABILITY_POLICY.get(root, ()))\n"
    b"        if root in _CAPABILITY_INVENTORY_ROOTS:\n"
    b"            entries = _require_capability_classifications()[root]\n"
    b"            denied.update(name for name, value in entries.items() if value == _CAPABILITY_DENY)\n"
    b"        return [name for name in dir(module) if not name.startswith(\"_\") and name not in denied]\n"
    b"    def __repr__(self):\n"
    b"        return \"<GuardedModuleProxy>\"\n"
    b"\n"
    b"_MODULE_PROXIES = {}\n"
    b"def _module_proxy(module, root):\n"
    b"    if root in _CAPABILITY_INVENTORY_ROOTS:\n"
    b"        _require_capability_classifications()\n"
    b"    key = id(module)\n"
    b"    proxy = _MODULE_PROXIES.get(key)\n"
    b"    if proxy is None:\n"
    b"        proxy = _GuardedModuleProxy(module, root)\n"
    b"        _MODULE_PROXIES[key] = proxy\n"
    b"    return proxy\n"
    b"\n"
    b"_SUBPROCESS_OPTION_NAMES = frozenset((\"stdin\", \"stdout\", \"stderr\", \"shell\", \"close_fds\", \"pass_fds\"))\n"
    b"_SUBPROCESS_REQUIRED_OPTIONS = (\"stdin\", \"stdout\", \"stderr\", \"shell\", \"close_fds\", \"pass_fds\")\n"
    b"\n"
    b"def _subprocess_args(positional, options):\n"
    b"    if \"args\" in options:\n"
    b"        if positional:\n"
    b"            _fail(RunnerControlCode.SUBPROCESS_STDIO_REQUIRED)\n"
    b"        args = options.pop(\"args\")\n"
    b"    elif len(positional) == 1:\n"
    b"        args = positional[0]\n"
    b"    else:\n"
    b"        _fail(RunnerControlCode.SUBPROCESS_STDIO_REQUIRED)\n"
    b"    if type(args) not in (list, tuple) or not args or any(type(value) is not str for value in args):\n"
    b"        _fail(RunnerControlCode.SUBPROCESS_STDIO_REQUIRED)\n"
    b"    return args\n"
    b"\n"
    b"class _GuardedSubprocessProxy:\n"
    b"    __slots__ = ()\n"
    b"    _NAMES = (\n"
    b"        \"PIPE\", \"DEVNULL\", \"STDOUT\", \"TimeoutExpired\",\n"
    b"        \"CompletedProcess\", \"Popen\", \"run\", \"check_output\",\n"
    b"    )\n"
    b"    def __getattribute__(self, name):\n"
    b"        if name == \"PIPE\":\n"
    b"            return _subprocess.PIPE\n"
    b"        if name == \"DEVNULL\":\n"
    b"            return _subprocess.DEVNULL\n"
    b"        if name == \"STDOUT\":\n"
    b"            return _subprocess.STDOUT\n"
    b"        if name == \"TimeoutExpired\":\n"
    b"            return _subprocess.TimeoutExpired\n"
    b"        if name == \"CompletedProcess\":\n"
    b"            return _subprocess.CompletedProcess\n"
    b"        if name in (\"Popen\", \"run\", \"check_output\"):\n"
    b"            return object.__getattribute__(self, name)\n"
    b"        raise AttributeError(name)\n"
    b"    def __setattr__(self, _name, _value):\n"
    b"        raise AttributeError(\"sealed subprocess\")\n"
    b"    def __delattr__(self, _name):\n"
    b"        raise AttributeError(\"sealed subprocess\")\n"
    b"    def __dir__(self):\n"
    b"        return list(_GuardedSubprocessProxy._NAMES)\n"
    b"    def __repr__(self):\n"
    b"        return \"<GuardedSubprocessProxy>\"\n"
    b"    def Popen(self, *positional, **options):\n"
    b"        args = _subprocess_args(positional, options)\n"
    b"        _validate_subprocess(args, options)\n"
    b"        return _launch_child(args, options)\n"
    b"    def run(self, *positional, **options):\n"
    b"        args = _subprocess_args(positional, options)\n"
    b"        _validate_subprocess(args, options)\n"
    b"        process = _launch_child(args, options)\n"
    b"        stdout, stderr = process.communicate()\n"
    b"        return _subprocess.CompletedProcess(args, process.returncode, stdout, stderr)\n"
    b"    def check_output(self, *positional, **options):\n"
    b"        args = _subprocess_args(positional, options)\n"
    b"        _validate_subprocess(args, options, True)\n"
    b"        process = _launch_child(args, options)\n"
    b"        stdout, stderr = process.communicate()\n"
    b"        stdout = b\"\" if stdout is None else stdout\n"
    b"        if process.returncode:\n"
    b"            raise _subprocess.CalledProcessError(\n"
    b"                process.returncode, args, output=stdout, stderr=stderr\n"
    b"            )\n"
    b"        return stdout\n"
    b"\n"
    b"def _launch_child(args, options):\n"
    b"    return _subprocess.Popen(\n"
    b"        args,\n"
    b"        stdin=options[\"stdin\"],\n"
    b"        stdout=options[\"stdout\"],\n"
    b"        stderr=options[\"stderr\"],\n"
    b"        shell=options[\"shell\"],\n"
    b"        close_fds=options[\"close_fds\"],\n"
    b"        pass_fds=options[\"pass_fds\"],\n"
    b"    )\n"
    b"\n"
    b"def _validate_subprocess(args, options, check_output=False):\n"
    b"    if any(name not in _SUBPROCESS_OPTION_NAMES for name in options):\n"
    b"        _fail(RunnerControlCode.SUBPROCESS_STDIO_REQUIRED)\n"
    b"    if any(name not in options for name in _SUBPROCESS_REQUIRED_OPTIONS):\n"
    b"        _fail(RunnerControlCode.SUBPROCESS_STDIO_REQUIRED)\n"
    b"    if type(options[\"stdin\"]) is not int or options[\"stdin\"] not in (_subprocess.PIPE, _subprocess.DEVNULL):\n"
    b"        _fail(RunnerControlCode.SUBPROCESS_STDIO_REQUIRED)\n"
    b"    if \"stdout\" in options and (type(options[\"stdout\"]) is not int or options[\"stdout\"] not in (_subprocess.PIPE, _subprocess.DEVNULL)):\n"
    b"        _fail(RunnerControlCode.SUBPROCESS_STDIO_REQUIRED)\n"
    b"    if type(options[\"stderr\"]) is not int or options[\"stderr\"] not in (_subprocess.PIPE, _subprocess.DEVNULL, _subprocess.STDOUT):\n"
    b"        _fail(RunnerControlCode.SUBPROCESS_STDIO_REQUIRED)\n"
    b"    if type(options[\"shell\"]) is not bool or options[\"shell\"] is not False or type(options[\"close_fds\"]) is not bool or options[\"close_fds\"] is not True:\n"
    b"        _fail(RunnerControlCode.SUBPROCESS_STDIO_REQUIRED)\n"
    b"    if type(options[\"pass_fds\"]) is not tuple or options[\"pass_fds\"] != ():\n"
    b"        _fail(RunnerControlCode.SUBPROCESS_STDIO_REQUIRED)\n"
    b"    if check_output and options[\"stdout\"] is not _subprocess.PIPE:\n"
    b"        _fail(RunnerControlCode.SUBPROCESS_STDIO_REQUIRED)\n"
    b"\n"
    b"_GUARDED_SUBPROCESS = _GuardedSubprocessProxy()\n"
    b"_GUARDED_SYS = _GuardedSysProxy(_sys)\n"
    b"\n"
    b"def _guarded_import(name, globals_=None, locals_=None, fromlist=(), level=0):\n"
    b"    if (\n"
    b"        level != 0 or not isinstance(name, str)\n"
    b"        or name.split(\".\", 1)[0] not in _ROOTS\n"
    b"    ):\n"
    b"        raise ImportError(\"RUNNER_IMPORT_FORBIDDEN\")\n"
    b"    root = name.split(\".\", 1)[0]\n"
    b"    if root == \"sys\":\n"
    b"        return _GUARDED_SYS\n"
    b"    if root == \"subprocess\":\n"
    b"        return _GUARDED_SUBPROCESS\n"
    b"    raw = _builtins.__import__(name, globals_, locals_, fromlist, level)\n"
    b"    return _module_proxy(raw, root)\n"
    b"\n"
    b"def _runner_namespace():\n"
    b"    builtins_copy = dict(_builtins.__dict__)\n"
    b"    builtins_copy[\"__import__\"] = _guarded_import\n"
    b"    return {\n"
    b"        \"__name__\": \"__runner_bundle__\",\n"
    b"        \"__builtins__\": builtins_copy,\n"
    b"        \"RunnerAbortCode\": RunnerAbortCode,\n"
    b"        \"RunnerControlCode\": RunnerControlCode,\n"
    b"        \"ResultClassification\": ResultClassification,\n"
    b"    }\n"
    b"\n"
    b"def _validate_run(value):\n"
    b"    if value is None:\n"
    b"        _fail(RunnerControlCode.RUNNER_MISSING)\n"
    b"    if not callable(value):\n"
    b"        _fail(RunnerControlCode.RUNNER_NOT_CALLABLE)\n"
    b"    if _inspect.iscoroutinefunction(value) or _inspect.isasyncgenfunction(value):\n"
    b"        _fail(RunnerControlCode.RUNNER_SIGNATURE_INVALID)\n"
    b"    try:\n"
    b"        signature = _inspect.signature(value)\n"
    b"    except (TypeError, ValueError):\n"
    b"        _fail(RunnerControlCode.RUNNER_SIGNATURE_INVALID)\n"
    b"    parameters = list(signature.parameters.values())\n"
    b"    if (\n"
    b"        len(parameters) != 1\n"
    b"        or parameters[0].kind not in (\n"
    b"            _inspect.Parameter.POSITIONAL_ONLY,\n"
    b"            _inspect.Parameter.POSITIONAL_OR_KEYWORD,\n"
    b"        )\n"
    b"        or parameters[0].default is not _inspect.Parameter.empty\n"
    b"    ):\n"
    b"        _fail(RunnerControlCode.RUNNER_SIGNATURE_INVALID)\n"
    b"\n"
    b"@_ctx.contextmanager\n"
    b"def _isolate(capture):\n"
    b"    old_streams = (\n"
    b"        _sys.stdout, _sys.stderr, _sys.stdin,\n"
    b"        _sys.__stdout__, _sys.__stderr__, _sys.__stdin__,\n"
    b"    )\n"
    b"    saved = []\n"
    b"    readers = []\n"
    b"    captures = [_Capture(4096), _Capture(4096)]\n"
    b"    try:\n"
    b"        saved = [_os.dup(0), _os.dup(1), _os.dup(2)]\n"
    b"        if capture:\n"
    b"            out_read, out_write = _os.pipe()\n"
    b"            err_read, err_write = _os.pipe()\n"
    b"            for fd, target in ((out_read, captures[0]), (err_read, captures[1])):\n"
    b"                thread = _threading.Thread(target=_drain, args=(fd, target), daemon=True)\n"
    b"                thread.start()\n"
    b"                readers.append(thread)\n"
    b"            null = _os.open(_os.devnull, _os.O_RDONLY)\n"
    b"            _os.dup2(null, 0)\n"
    b"            _os.close(null)\n"
    b"            _os.dup2(out_write, 1)\n"
    b"            _os.dup2(err_write, 2)\n"
    b"            _os.close(out_write)\n"
    b"            _os.close(err_write)\n"
    b"        else:\n"
    b"            null = _os.open(_os.devnull, _os.O_RDWR)\n"
    b"            for target in (0, 1, 2):\n"
    b"                _os.dup2(null, target)\n"
    b"            _os.close(null)\n"
    b"        blocked_out = _ForbiddenTextStream(RunnerControlCode.RUNNER_STDOUT_FORBIDDEN)\n"
    b"        blocked_err = _ForbiddenTextStream(RunnerControlCode.RUNNER_STDERR_FORBIDDEN)\n"
    b"        blocked_in = _ForbiddenTextStream(RunnerControlCode.RUNNER_INPUT_FORBIDDEN)\n"
    b"        _sys.stdout = _sys.__stdout__ = blocked_out\n"
    b"        _sys.stderr = _sys.__stderr__ = blocked_err\n"
    b"        _sys.stdin = _sys.__stdin__ = blocked_in\n"
    b"        object.__getattribute__(_GUARDED_SYS, \"_streams\").update({\n"
    b"            \"stdin\": blocked_in, \"stdout\": blocked_out, \"stderr\": blocked_err,\n"
    b"            \"__stdin__\": blocked_in, \"__stdout__\": blocked_out, \"__stderr__\": blocked_err,\n"
    b"        })\n"
    b"        yield\n"
    b"    finally:\n"
    b"        (\n"
    b"            _sys.stdout, _sys.stderr, _sys.stdin,\n"
    b"            _sys.__stdout__, _sys.__stderr__, _sys.__stdin__,\n"
    b"        ) = old_streams\n"
    b"        if saved:\n"
    b"            for target, source in ((0, saved[0]), (1, saved[1]), (2, saved[2])):\n"
    b"                try:\n"
    b"                    _os.dup2(source, target)\n"
    b"                except OSError:\n"
    b"                    pass\n"
    b"            for source in saved:\n"
    b"                try:\n"
    b"                    _os.close(source)\n"
    b"                except OSError:\n"
    b"                    pass\n"
    b"        for thread in readers:\n"
    b"            thread.join(timeout=1.0)\n"
    b"        if capture:\n"
    b"            if captures[0].bytes_seen:\n"
    b"                raise RunnerControlError(RunnerControlCode.RUNNER_STDOUT_FORBIDDEN)\n"
    b"            if captures[1].bytes_seen:\n"
    b"                raise RunnerControlError(RunnerControlCode.RUNNER_STDERR_FORBIDDEN)\n"
    b"\n"
    b"class _Capture:\n"
    b"    def __init__(self, limit):\n"
    b"        self.limit = limit\n"
    b"        self.bytes_seen = 0\n"
    b"    def add(self, payload):\n"
    b"        self.bytes_seen += len(payload)\n"
    b"\n"
    b"def _drain(fd, capture):\n"
    b"    try:\n"
    b"        while True:\n"
    b"            payload = _os.read(fd, 4096)\n"
    b"            if not payload:\n"
    b"                return\n"
    b"            capture.add(payload)\n"
    b"    except OSError:\n"
    b"        return\n"
    b"    finally:\n"
    b"        try:\n"
    b"            _os.close(fd)\n"
    b"        except OSError:\n"
    b"            pass\n"
    b"\n"
    b"class _RemoteChannel:\n"
    b"    def __init__(self, reader, writer, graph, clock=_time.monotonic, randomness=_os.urandom):\n"
    b"        self.reader = reader\n"
    b"        self.writer = writer\n"
    b"        self.graph = graph\n"
    b"        self._clock = clock\n"
    b"        self._randomness = randomness\n"
    b"        self.sequence = 1\n"
    b"        self.bytes_seen = 0\n"
    b"        self._nonces = set()\n"
    b"        self._lock = _threading.Lock()\n"
    b"    def _new_nonce(self):\n"
    b"        try:\n"
    b"            value = _nonce(self._randomness(16), 16)\n"
    b"        except Exception:\n"
    b"            _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"        if value in self._nonces:\n"
    b"            _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"        return value\n"
    b"    def _account(self, frame):\n"
    b"        if frame.frame_nonce in self._nonces or len(self._nonces) >= 16:\n"
    b"            _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"        total = self.bytes_seen + _FRAME_OVERHEAD + len(frame.payload)\n"
    b"        if total > _MAX_SESSION_BYTES:\n"
    b"            _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"        self._nonces.add(frame.frame_nonce)\n"
    b"        self.bytes_seen = total\n"
    b"    def receive(self, key, direction, timeout=None):\n"
    b"        with self._lock:\n"
    b"            header = _read_exact(self.reader, _FRAME.size, timeout, self._clock)\n"
    b"            try:\n"
    b"                length = _FRAME.unpack(header)[-1]\n"
    b"            except _struct.error:\n"
    b"                _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"            if length > _MAX_PAYLOAD:\n"
    b"                _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"            raw = header + _read_exact(\n"
    b"                self.reader, length + _TAG_BYTES, timeout, self._clock\n"
    b"            )\n"
    b"        try:\n"
    b"            frame = _decode_frame(raw, key, direction, self.sequence, self.graph.n_session)\n"
    b"        except RunnerControlError:\n"
    b"            _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"        self._account(frame)\n"
    b"        self.sequence += 1\n"
    b"        return frame\n"
    b"    def send(self, key, direction, message, payload):\n"
    b"        nonce = self._new_nonce()\n"
    b"        frame = _encode_frame(\n"
    b"            key, direction, message, self.sequence, self.graph.n_session, payload, nonce\n"
    b"        )\n"
    b"        if self.bytes_seen + len(frame) > _MAX_SESSION_BYTES or len(self._nonces) >= 16:\n"
    b"            _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"        try:\n"
    b"            self.writer.write(frame)\n"
    b"            self.writer.flush()\n"
    b"        except (BrokenPipeError, OSError, ValueError):\n"
    b"            _fail(RunnerControlCode.PROTOCOL_BROKEN_PIPE)\n"
    b"        self._nonces.add(nonce)\n"
    b"        self.bytes_seen += len(frame)\n"
    b"        self.sequence += 1\n"
    b"\n"
    b"class ProceedGrant:\n"
    b"    __slots__ = ()\n"
    b"    def __new__(cls, *args, **kwargs):\n"
    b"        raise TypeError(\"opaque capability\")\n"
    b"    def __repr__(self):\n"
    b"        return \"<ProceedGrant opaque>\"\n"
    b"    __str__ = __repr__\n"
    b"    def __copy__(self):\n"
    b"        raise TypeError(\"opaque capability\")\n"
    b"    def __deepcopy__(self, _memo):\n"
    b"        raise TypeError(\"opaque capability\")\n"
    b"    def __reduce__(self):\n"
    b"        raise TypeError(\"opaque capability\")\n"
    b"\n"
    b"def _mint_grant():\n"
    b"    return object.__new__(ProceedGrant)\n"
    b"\n"
    b"class RunnerRuntime:\n"
    b"    _INITIAL = \"INITIAL\"\n"
    b"    _RUNNING = \"RUNNING\"\n"
    b"    _WAITING_DECISION = \"WAITING_DECISION\"\n"
    b"    _PROCEED_GRANTED = \"PROCEED_GRANTED\"\n"
    b"    _RESULT_SENT = \"RESULT_SENT\"\n"
    b"    _TERMINAL = \"TERMINAL\"\n"
    b"    def __init__(self, channel, barrier_utc, decision_timeout=5.0):\n"
    b"        self._channel = channel\n"
    b"        self._barrier_utc = _barrier(barrier_utc)\n"
    b"        self._decision_timeout = decision_timeout\n"
    b"        self._state = self._INITIAL\n"
    b"        self._grants = {}\n"
    b"        self._terminal_frame_sent = False\n"
    b"        self._discovery_sent = False\n"
    b"        self._pending_artifact = None\n"
    b"        self._pending_isolation = None\n"
    b"    @property\n"
    b"    def barrier_utc(self):\n"
    b"        return self._barrier_utc\n"
    b"    def _send_abort(self, code):\n"
    b"        if self._terminal_frame_sent:\n"
    b"            return\n"
    b"        self._channel.send(\n"
    b"            self._channel.graph.k_session, _REMOTE_TO_LOCAL, _ABORT,\n"
    b"            _encode_control({\"type\": \"ABORT\", \"version\": 1, \"code\": code.value}),\n"
    b"        )\n"
    b"        self._terminal_frame_sent = True\n"
    b"        self._state = self._TERMINAL\n"
    b"    def discover(self, execution_row_id, artifact_filename, isolation_state, isolation_commitment):\n"
    b"        if self._discovery_sent:\n"
    b"            _fail(RunnerControlCode.DISCOVERY_DUPLICATE)\n"
    b"        if self._state != self._RUNNING:\n"
    b"            _fail(RunnerControlCode.RUNTIME_TERMINAL)\n"
    b"        try:\n"
    b"            row, filename = _discovery_tuple(execution_row_id, artifact_filename)\n"
    b"        except RunnerControlError:\n"
    b"            _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"        if isolation_state != \"PASS\" or not _is_commitment(isolation_commitment):\n"
    b"            _fail(RunnerControlCode.ISOLATION_FAILED)\n"
    b"        artifact = _recovery_commitment(\"artifact-row\", str(row), filename)\n"
    b"        self._channel.send(\n"
    b"            self._channel.graph.k_session, _REMOTE_TO_LOCAL, _DISCOVERY,\n"
    b"            _encode_control({\n"
    b"                \"type\": \"DISCOVERY\", \"version\": 1,\n"
    b"                \"execution_row_id\": row, \"artifact_filename\": filename,\n"
    b"                \"isolation_state\": \"PASS\",\n"
    b"                \"isolation_commitment\": isolation_commitment,\n"
    b"            }),\n"
    b"        )\n"
    b"        self._discovery_sent = True\n"
    b"        self._pending_artifact = artifact\n"
    b"        self._pending_isolation = isolation_commitment\n"
    b"        self._state = self._WAITING_DECISION\n"
    b"        try:\n"
    b"            frame = self._channel.receive(\n"
    b"                self._channel.graph.k_session, _LOCAL_TO_REMOTE, timeout=self._decision_timeout\n"
    b"            )\n"
    b"        except RunnerControlError:\n"
    b"            self._state = self._TERMINAL\n"
    b"            raise\n"
    b"        if frame.message == _ABORT:\n"
    b"            try:\n"
    b"                value = _decode_control(frame.payload, \"ABORT\")\n"
    b"                code = RunnerControlCode(value[\"code\"])\n"
    b"            except (RunnerControlError, TypeError, ValueError):\n"
    b"                self._state = self._TERMINAL\n"
    b"                _fail(RunnerControlCode.PROCEED_INVALID)\n"
    b"            self._terminal_frame_sent = True\n"
    b"            self._state = self._TERMINAL\n"
    b"            raise RunnerControlError(code)\n"
    b"        if frame.message != _PROCEED:\n"
    b"            self._state = self._TERMINAL\n"
    b"            _fail(RunnerControlCode.PROCEED_INVALID)\n"
    b"        try:\n"
    b"            value = _decode_control(frame.payload, \"PROCEED\")\n"
    b"            expected = {\n"
    b"                \"epoch_digest\": _digest_commitment(self._channel.graph.epoch_digest),\n"
    b"                \"authority_digest\": _digest_commitment(self._channel.graph.authority_digest),\n"
    b"                \"runner_digest\": _digest_commitment(self._channel.graph.runner_digest),\n"
    b"                \"bundle_digest\": _digest_commitment(self._channel.graph.bundle_digest),\n"
    b"                \"barrier_utc\": self._barrier_utc,\n"
    b"                \"artifact_commitment\": self._pending_artifact,\n"
    b"                \"isolation_commitment\": self._pending_isolation,\n"
    b"            }\n"
    b"            if any(value[name] != expected_value for name, expected_value in expected.items()):\n"
    b"                _fail(RunnerControlCode.PROCEED_INVALID)\n"
    b"            capability = _proceed_commitment(\n"
    b"                self._channel.graph, value[\"artifact_commitment\"],\n"
    b"                value[\"isolation_commitment\"], value[\"transition_id\"],\n"
    b"                value[\"pre_cas_ledger_digest\"],\n"
    b"                value[\"transition_data_commitment\"],\n"
    b"                value[\"consumed_record_digest\"],\n"
    b"            )\n"
    b"            raw = _b64.urlsafe_b64decode(value[\"grant\"] + \"===\")\n"
    b"            if not _hmac.compare_digest(raw, _grant_token(self._channel.graph, capability)):\n"
    b"                _fail(RunnerControlCode.PROCEED_INVALID)\n"
    b"        except RunnerControlError:\n"
    b"            self._state = self._TERMINAL\n"
    b"            raise\n"
    b"        except (TypeError, ValueError, _bin.Error):\n"
    b"            self._state = self._TERMINAL\n"
    b"            _fail(RunnerControlCode.PROCEED_INVALID)\n"
    b"        grant = _mint_grant()\n"
    b"        self._grants[id(grant)] = (grant, capability)\n"
    b"        self._state = self._PROCEED_GRANTED\n"
    b"        return grant\n"
    b"    def send_result(self, grant, classification, result_commitment):\n"
    b"        if self._state == self._RESULT_SENT:\n"
    b"            _fail(RunnerControlCode.RESULT_DUPLICATE)\n"
    b"        if self._state != self._PROCEED_GRANTED:\n"
    b"            _fail(RunnerControlCode.RESULT_BEFORE_PROCEED)\n"
    b"        record = self._grants.get(id(grant))\n"
    b"        if type(grant) is not ProceedGrant or record is None or record[0] is not grant:\n"
    b"            _fail(RunnerControlCode.PROCEED_INVALID)\n"
    b"        try:\n"
    b"            classification = ResultClassification(classification)\n"
    b"        except (TypeError, ValueError):\n"
    b"            _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"        if not _is_commitment(result_commitment):\n"
    b"            _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"        del self._grants[id(grant)]\n"
    b"        self._channel.send(\n"
    b"            self._channel.graph.k_session, _REMOTE_TO_LOCAL, _RESULT,\n"
    b"            _encode_control({\n"
    b"                \"type\": \"RESULT\", \"version\": 1,\n"
    b"                \"classification\": classification.value,\n"
    b"                \"result_commitment\": result_commitment,\n"
    b"            }),\n"
    b"        )\n"
    b"        self._terminal_frame_sent = True\n"
    b"        self._state = self._RESULT_SENT\n"
    b"    def abort(self, code):\n"
    b"        if not isinstance(code, RunnerAbortCode):\n"
    b"            raise TypeError(\"RunnerRuntime.abort accepts RunnerAbortCode\")\n"
    b"        if self._state == self._TERMINAL or self._terminal_frame_sent:\n"
    b"            _fail(RunnerControlCode.RUNTIME_TERMINAL)\n"
    b"        self._send_abort(RunnerControlCode(code.value))\n"
    b"        raise RunnerControlError(RunnerControlCode(code.value))\n"
    b"\n"
    b"class RemoteLoader:\n"
    b"    def __init__(self, reader, writer, capture_fds=False, clock=_time.monotonic, randomness=_os.urandom):\n"
    b"        self._raw_reader = reader\n"
    b"        self._raw_writer = writer\n"
    b"        self._capture_fds = capture_fds\n"
    b"        self._clock = clock\n"
    b"        self._randomness = randomness\n"
    b"        self._protocol_reader = reader\n"
    b"        self._protocol_writer = writer\n"
    b"        self._owned = []\n"
    b"        try:\n"
    b"            reader_fd = reader.fileno()\n"
    b"            writer_fd = writer.fileno()\n"
    b"            self._protocol_reader = _os.fdopen(_os.dup(reader_fd), \"rb\", buffering=0)\n"
    b"            self._protocol_writer = _os.fdopen(_os.dup(writer_fd), \"wb\", buffering=0)\n"
    b"            self._owned = [self._protocol_reader, self._protocol_writer]\n"
    b"        except (AttributeError, OSError, _io.UnsupportedOperation):\n"
    b"            self._protocol_reader = reader\n"
    b"            self._protocol_writer = writer\n"
    b"        self._terminal_sent = False\n"
    b"    def _send_raw(self, payload):\n"
    b"        try:\n"
    b"            self._protocol_writer.write(payload)\n"
    b"            self._protocol_writer.flush()\n"
    b"        except (BrokenPipeError, OSError, ValueError):\n"
    b"            _fail(RunnerControlCode.PROTOCOL_BROKEN_PIPE)\n"
    b"    def _abort(self, channel, code):\n"
    b"        if self._terminal_sent:\n"
    b"            return\n"
    b"        try:\n"
    b"            channel.send(\n"
    b"                channel.graph.k_session, _REMOTE_TO_LOCAL, _ABORT,\n"
    b"                _encode_control({\"type\": \"ABORT\", \"version\": 1, \"code\": code.value}),\n"
    b"            )\n"
    b"        except RunnerControlError:\n"
    b"            pass\n"
    b"        self._terminal_sent = True\n"
    b"    def run(self):\n"
    b"        channel = None\n"
    b"        runtime = None\n"
    b"        pending = None\n"
    b"        try:\n"
    b"            try:\n"
    b"                n_remote = _nonce(self._randomness(32), 32)\n"
    b"            except Exception:\n"
    b"                return 66\n"
    b"            self._send_raw(_HELLO.pack(_HELLO_MAGIC, 1, 1, 0, n_remote))\n"
    b"            deadline = self._clock() + 30.0\n"
    b"            preamble = _decode_preamble(\n"
    b"                _read_exact(\n"
    b"                    self._protocol_reader, 272, 5.0, self._clock\n"
    b"                )\n"
    b"            )\n"
    b"            if preamble[\"n_remote\"] != n_remote:\n"
    b"                _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"            graph = _Graph(preamble)\n"
    b"            channel = _RemoteChannel(\n"
    b"                self._protocol_reader, self._protocol_writer, graph,\n"
    b"                clock=self._clock, randomness=self._randomness\n"
    b"            )\n"
    b"            boot = channel.receive(\n"
    b"                graph.k_boot, _LOCAL_TO_REMOTE,\n"
    b"                max(0.0, min(deadline, self._clock() + 5.0) - self._clock()),\n"
    b"            )\n"
    b"            if boot.message != _BOOT:\n"
    b"                _fail(RunnerControlCode.PROTOCOL_FAILURE)\n"
    b"            barrier, source = _decode_boot(boot.payload, graph.bundle_digest)\n"
    b"            graph = _Graph(preamble, barrier)\n"
    b"            channel.graph = graph\n"
    b"            runtime = RunnerRuntime(channel, barrier)\n"
    b"            namespace = _runner_namespace()\n"
    b"            try:\n"
    b"                with _isolate(self._capture_fds):\n"
    b"                    exec(\n"
    b"                        compile(\n"
    b"                            source.decode(\"utf-8\", \"strict\"),\n"
    b"                            \"<runner-bundle>\", \"exec\", dont_inherit=True,\n"
    b"                        ),\n"
    b"                        namespace, namespace,\n"
    b"                    )\n"
    b"                    _validate_run(namespace.get(\"run\"))\n"
    b"                    channel.send(\n"
    b"                        graph.k_session, _REMOTE_TO_LOCAL, _READY,\n"
    b"                        _encode_control({\n"
    b"                            \"type\": \"READY\", \"version\": 1,\n"
    b"                            \"barrier_utc\": runtime.barrier_utc,\n"
    b"                        }),\n"
    b"                    )\n"
    b"                    runtime._state = runtime._RUNNING\n"
    b"                    returned = namespace[\"run\"](runtime)\n"
    b"                    if runtime._state == runtime._RESULT_SENT:\n"
    b"                        if returned is not None:\n"
    b"                            _fail(RunnerControlCode.RUNNER_NON_NONE_RETURN)\n"
    b"                    elif runtime._state != runtime._TERMINAL:\n"
    b"                        _fail(\n"
    b"                            RunnerControlCode.RUNNER_NO_RESULT\n"
    b"                            if returned is None else RunnerControlCode.RUNNER_NON_NONE_RETURN\n"
    b"                        )\n"
    b"            except RunnerControlError as error:\n"
    b"                pending = error\n"
    b"            except BaseException:\n"
    b"                pending = RunnerControlError(RunnerControlCode.RUNNER_TOP_LEVEL_EXCEPTION)\n"
    b"            if pending is not None:\n"
    b"                if runtime is not None and not runtime._terminal_frame_sent:\n"
    b"                    self._abort(channel, pending.code)\n"
    b"                return 65\n"
    b"            return 0 if runtime is not None and runtime._state == runtime._RESULT_SENT else 65\n"
    b"        except RunnerControlError as error:\n"
    b"            if runtime is None:\n"
    b"                return 66\n"
    b"            if channel is not None and not self._terminal_sent:\n"
    b"                self._abort(channel, error.code)\n"
    b"            return 65\n"
    b"        except Exception:\n"
    b"            return 66\n"
    b"        finally:\n"
    b"            for stream in self._owned:\n"
    b"                try:\n"
    b"                    stream.close()\n"
    b"                except (OSError, ValueError):\n"
    b"                    pass\n"
    b"\n"
    b"__all__ = (\n"
    b"    \"RunnerAbortCode\", \"RunnerControlCode\", \"ResultClassification\",\n"
    b"    \"RunnerControlError\", \"ProceedGrant\", \"RunnerRuntime\",\n"
    b"    \"_RemoteChannel\", \"RemoteLoader\",\n"
    b")\n"
)
if len(CANONICAL_LOADER_PAYLOAD_BYTES) > MAX_RUNNER_BUNDLE_BYTES:
    raise RuntimeError("canonical loader payload too large")
FIXED_LOADER_MAX_BYTES = 16384
_CANONICAL_REMOTE_NAMESPACE = {
    "__name__": "__canonical_remote_payload__",
    "p": CANONICAL_LOADER_PAYLOAD_BYTES,
}
exec(
    compile(
        CANONICAL_LOADER_PAYLOAD_BYTES,
        "__canonical_remote_payload__",
        "exec",
        dont_inherit=True,
    ),
    _CANONICAL_REMOTE_NAMESPACE,
    _CANONICAL_REMOTE_NAMESPACE,
)
_EXPECTED_REMOTE_EXPORTS = (
    "RunnerAbortCode",
    "RunnerControlCode",
    "ResultClassification",
    "RunnerControlError",
    "ProceedGrant",
    "RunnerRuntime",
    "_RemoteChannel",
    "RemoteLoader",
)
if tuple(_CANONICAL_REMOTE_NAMESPACE.get("__all__", ())) != _EXPECTED_REMOTE_EXPORTS:
    raise RuntimeError("canonical remote export contract mismatch")
if any(name not in _CANONICAL_REMOTE_NAMESPACE for name in _EXPECTED_REMOTE_EXPORTS):
    raise RuntimeError("canonical remote export missing")
_REMOTE_EXPORTS = types.MappingProxyType(
    {name: _CANONICAL_REMOTE_NAMESPACE[name] for name in _EXPECTED_REMOTE_EXPORTS}
)
RunnerAbortCode = _REMOTE_EXPORTS["RunnerAbortCode"]
RunnerControlCode = _REMOTE_EXPORTS["RunnerControlCode"]
ResultClassification = _REMOTE_EXPORTS["ResultClassification"]
RunnerControlError = _REMOTE_EXPORTS["RunnerControlError"]
ProceedGrant = _REMOTE_EXPORTS["ProceedGrant"]
RunnerRuntime = _REMOTE_EXPORTS["RunnerRuntime"]
_RemoteChannel = _REMOTE_EXPORTS["_RemoteChannel"]
RemoteLoader = _REMOTE_EXPORTS["RemoteLoader"]

_FIXED_LOADER_ENCODED = base64.b85encode(
    lzma.compress(
        CANONICAL_LOADER_PAYLOAD_BYTES,
        format=lzma.FORMAT_XZ,
        check=lzma.CHECK_CRC64,
        preset=lzma.PRESET_EXTREME | 9,
    )
).decode("ascii")
FIXED_LOADER_SOURCE = (
    "import base64,lzma,sys\n"
    "p=lzma.decompress(base64.b85decode("
    + repr(_FIXED_LOADER_ENCODED)
    + "),format=lzma.FORMAT_XZ)\n"
    "g={'__name__':'__canonical_remote_payload__','p':p}\n"
    "exec(compile(p,'__canonical_remote_payload__','exec'),g,g)\n"
    "raise SystemExit(g['RemoteLoader'](sys.stdin.buffer,sys.stdout.buffer).run())\n"
)
def build_fixed_loader_source() -> bytes:
    source = FIXED_LOADER_SOURCE.encode("ascii", "strict")
    if len(source) > FIXED_LOADER_MAX_BYTES:
        _raise(ProtocolError, "FRAME_INVALID")
    compile(source.decode("ascii"), "<fixed-loader>", "exec", dont_inherit=True)
    return source


def fixed_loader_commitment() -> str:
    return STORE.bytes_commitment("bridge-loader", CANONICAL_LOADER_PAYLOAD_BYTES)


def build_fixed_loader_command() -> tuple[str, str, str]:
    return ("python3", "-c", FIXED_LOADER_SOURCE)


@dataclass(frozen=True, slots=True, repr=False)
class ProcessTerminalEvidence:
    exit_code: int | None
    natural_exit: bool
    stdout_eof: bool
    stderr_eof: bool
    stdout_trailing_bytes: int
    stderr_bytes: int
    stdout_overflow: bool
    stderr_overflow: bool
    termination_uncertain: bool

    def __repr__(self) -> str:
        return (
            "ProcessTerminalEvidence("
            f"exit_code={self.exit_code!r}, natural_exit={self.natural_exit!r}, "
            f"stdout_eof={self.stdout_eof!r}, stderr_eof={self.stderr_eof!r}, "
            f"stdout_trailing_bytes={self.stdout_trailing_bytes}, "
            f"stderr_bytes={self.stderr_bytes}, "
            f"stdout_overflow={self.stdout_overflow!r}, "
            f"stderr_overflow={self.stderr_overflow!r}, "
            f"termination_uncertain={self.termination_uncertain!r})"
        )


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
    """Windows-safe bounded reader-thread supervision for anonymous pipes."""

    def __init__(
        self,
        process: Any,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_stdout_bytes: int = MAX_SESSION_BYTES,
        max_stderr_bytes: int = MAX_STDERR_CAPTURE_BYTES,
    ):
        self.process = process
        self._clock = clock
        self._max_stdout_bytes = max_stdout_bytes
        self.stdout_queue: queue.Queue[tuple[str, bytes | None]] = queue.Queue(maxsize=64)
        self.stderr_capture = _BoundedCapture(max_stderr_bytes)
        self.stdout_bytes_seen = 0
        self.stdout_overflow = False
        self.stderr_done = threading.Event()
        self.stdout_done = threading.Event()
        self._stdout_buffer = bytearray()
        self._threads: list[threading.Thread] = []
        self._started = False

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        for name, stream, done in (
            ("stdout", self.process.stdout, self.stdout_done),
            ("stderr", self.process.stderr, self.stderr_done),
        ):
            thread = threading.Thread(
                target=self._reader,
                args=(name, stream, done),
                daemon=True,
            )
            thread.start()
            self._threads.append(thread)

    def _reader(self, name: str, stream: Any, done: threading.Event) -> None:
        try:
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    return
                if name == "stderr":
                    self.stderr_capture.add(chunk)
                    continue
                self.stdout_bytes_seen += len(chunk)
                if self.stdout_bytes_seen > self._max_stdout_bytes:
                    self.stdout_overflow = True
                try:
                    self.stdout_queue.put((name, chunk), timeout=0.05)
                except queue.Full:
                    self.stdout_overflow = True
        except (OSError, ValueError):
            return
        finally:
            done.set()

    def read_exact(self, size: int, deadline: float) -> bytes:
        while len(self._stdout_buffer) < size:
            if self.stdout_overflow:
                _raise(BridgeError, "PROCESS_CAPTURE_OVERFLOW")
            remaining = deadline - self._clock()
            if remaining <= 0:
                _raise(BridgeError, "PROCESS_TIMEOUT")
            try:
                _name, chunk = self.stdout_queue.get(timeout=min(remaining, 0.05))
            except queue.Empty:
                if self.stdout_done.is_set():
                    _raise(BridgeError, "PROCESS_EOF")
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
            if self._clock() >= deadline:
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

    def close_stdin(self) -> None:
        stream = getattr(self.process, "stdin", None)
        if stream is None:
            return
        try:
            stream.close()
        except (BrokenPipeError, OSError, ValueError):
            pass

    def _drain_stdout_queue(self) -> int:
        trailing = len(self._stdout_buffer)
        self._stdout_buffer.clear()
        while True:
            try:
                _name, chunk = self.stdout_queue.get_nowait()
            except queue.Empty:
                return trailing
            if chunk:
                trailing += len(chunk)

    def await_natural(self, deadline: float) -> ProcessTerminalEvidence:
        wait_completed = False
        exit_code: int | None = None
        remaining = max(0.0, deadline - self._clock())
        try:
            exit_code = self.process.wait(timeout=remaining)
            wait_completed = True
        except (_subprocess.TimeoutExpired, TimeoutError, OSError, ValueError):
            wait_completed = False
        if exit_code is None:
            try:
                candidate = getattr(self.process, "returncode", None)
                if isinstance(candidate, int):
                    exit_code = candidate
            except Exception:
                pass
        threads_done = True
        for thread in self._threads:
            remaining = max(0.0, deadline - self._clock())
            thread.join(timeout=remaining)
            if thread.is_alive():
                threads_done = False
        trailing = self._drain_stdout_queue()
        termination_uncertain = not wait_completed or not threads_done or exit_code is None
        return ProcessTerminalEvidence(
            exit_code=exit_code,
            natural_exit=wait_completed and not termination_uncertain,
            stdout_eof=self.stdout_done.is_set(),
            stderr_eof=self.stderr_done.is_set(),
            stdout_trailing_bytes=trailing,
            stderr_bytes=self.stderr_capture.data_seen,
            stdout_overflow=self.stdout_overflow,
            stderr_overflow=self.stderr_capture.overflow,
            termination_uncertain=termination_uncertain,
        )

    @staticmethod
    def finality_error(
        evidence: ProcessTerminalEvidence,
        *,
        expected_exit: int = EXIT_SUCCESS,
    ) -> str | None:
        if evidence.stdout_overflow or evidence.stderr_overflow:
            return "PROCESS_CAPTURE_OVERFLOW"
        if evidence.stdout_trailing_bytes:
            return "PROCESS_TRAILING_OUTPUT"
        if not evidence.stdout_eof or not evidence.stderr_eof:
            return "PROCESS_TERMINATION_UNCERTAIN"
        if evidence.termination_uncertain or not evidence.natural_exit:
            return "PROCESS_TERMINATION_UNCERTAIN"
        if evidence.exit_code != expected_exit:
            return "PROCESS_EXIT_NONZERO"
        if evidence.stderr_bytes:
            return "PROCESS_STDERR_FORBIDDEN"
        return None

    def stop(self) -> None:
        try:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=0.5)
                except (_subprocess.TimeoutExpired, OSError, ValueError):
                    self.process.kill()
        except (OSError, ValueError, AttributeError):
            pass
        for stream in (
            getattr(self.process, "stdin", None),
            getattr(self.process, "stdout", None),
            getattr(self.process, "stderr", None),
        ):
            try:
                if stream is not None:
                    stream.close()
            except (OSError, ValueError):
                pass
        for thread in self._threads:
            thread.join(timeout=1.0)


# Final exported order: the operational bridge is the corrected Run-318
# controller, and all public entrypoints follow the final supervisor.
ControllerBridge = _Run318ControllerBridge
_DummyControllerBridge = _Run318DummyControllerBridge


def run_controller_bridge(
    store: Any,
    epoch_ref: str,
    barrier_utc: str,
    runner_bundle: RunnerBundle,
    *,
    launcher: Callable[[], Any],
    clock: Callable[[], float] = time.monotonic,
    randomness: Callable[[int], bytes] = os.urandom,
    counters: BridgeCounters | None = None,
    timeout_seconds: float = WHOLE_SESSION_TIMEOUT_SECONDS,
) -> BridgeResult:
    return ControllerBridge(
        store,
        epoch_ref,
        barrier_utc,
        runner_bundle,
        launcher=launcher,
        clock=clock,
        randomness=randomness,
        counters=counters,
        timeout_seconds=timeout_seconds,
    ).run()


def run_dummy_controller_bridge(
    store: Any,
    epoch_ref: str,
    barrier_utc: str,
    runner_bundle: RunnerBundle,
    *,
    decision: DummyDecision | None = None,
    clock: Callable[[], float] = time.monotonic,
    randomness: Callable[[int], bytes] = os.urandom,
    counters: BridgeCounters | None = None,
    timeout_seconds: float = WHOLE_SESSION_TIMEOUT_SECONDS,
) -> BridgeResult:
    chosen = decision or DummyDecision.allow()
    if not isinstance(chosen, DummyDecision):
        raise TypeError("decision must be DummyDecision")
    return _DummyControllerBridge(
        store,
        epoch_ref,
        barrier_utc,
        runner_bundle,
        decision=chosen,
        clock=clock,
        randomness=randomness,
        counters=counters,
        timeout_seconds=timeout_seconds,
    ).run()


def _dummy_child_main() -> int:
    return _REMOTE_EXPORTS["RemoteLoader"](
        sys.stdin.buffer,
        sys.stdout.buffer,
        capture_fds=True,
    ).run()


def main(argv: Sequence[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    if values == ["--dummy-child"]:
        return _dummy_child_main()
    return EXIT_PROTOCOL_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())
