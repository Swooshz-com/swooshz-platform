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


class RunnerAbortCode(str, Enum):
    """The ten runner-requested pre-DISCOVERY abort reasons."""

    PRESTATE_FAILED = "PRESTATE_FAILED"
    BACKUP_NOT_QUALIFYING = "BACKUP_NOT_QUALIFYING"
    LOCATOR_NOT_FOUND = "LOCATOR_NOT_FOUND"
    LOCATOR_AMBIGUOUS = "LOCATOR_AMBIGUOUS"
    RESOURCE_COLLISION = "RESOURCE_COLLISION"
    RESOURCE_CREATE_FAILED = "RESOURCE_CREATE_FAILED"
    ISOLATION_FAILED = "ISOLATION_FAILED"
    CLEANUP_UNPROVEN = "CLEANUP_UNPROVEN"
    RESTORE_PRECONDITION_FAILED = "RESTORE_PRECONDITION_FAILED"
    RUNNER_ABORTED = "RUNNER_ABORTED"


class RunnerControlCode(str, Enum):
    """Finite public-safe control/error codes."""

    PRESTATE_FAILED = RunnerAbortCode.PRESTATE_FAILED.value
    BACKUP_NOT_QUALIFYING = RunnerAbortCode.BACKUP_NOT_QUALIFYING.value
    LOCATOR_NOT_FOUND = RunnerAbortCode.LOCATOR_NOT_FOUND.value
    LOCATOR_AMBIGUOUS = RunnerAbortCode.LOCATOR_AMBIGUOUS.value
    RESOURCE_COLLISION = RunnerAbortCode.RESOURCE_COLLISION.value
    RESOURCE_CREATE_FAILED = RunnerAbortCode.RESOURCE_CREATE_FAILED.value
    ISOLATION_FAILED = RunnerAbortCode.ISOLATION_FAILED.value
    CLEANUP_UNPROVEN = RunnerAbortCode.CLEANUP_UNPROVEN.value
    RESTORE_PRECONDITION_FAILED = RunnerAbortCode.RESTORE_PRECONDITION_FAILED.value
    RUNNER_ABORTED = RunnerAbortCode.RUNNER_ABORTED.value

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
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"


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

    def close(self) -> None:
        # TextIOBase finalization calls close while the temporary stream is
        # being replaced.  Do not turn that bookkeeping into protocol stderr.
        return None

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
        try:
            snapshot = self.store.load_epoch(self.epoch_ref)
            if snapshot.record["state"] not in getattr(
                STORE,
                "TERMINAL_EPOCH_STATES",
                frozenset(),
            ):
                self.store.abandon(self.epoch_ref)
        except Exception:
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

    def _assert_consumed_reload(
        self,
        *,
        transition_id: str,
        transition_commitment: str,
    ) -> STORE.V2EpochSnapshot:
        try:
            snapshot = self.store.load_epoch(self.epoch_ref)
        except Exception:
            _raise(BridgeError, "POST_CAS_UNCERTAIN")
        if not (
            isinstance(snapshot, STORE.V2EpochSnapshot)
            and snapshot.record["state"] == "ACTIVE"
            and snapshot.record["artifact_binding_state"] == "BOUND"
            and snapshot.artifact_binding.artifact_binding_state == "BOUND"
            and snapshot.ledger["state"] == "CONSUMED"
            and snapshot.ledger["transition_id"] == transition_id
            and snapshot.ledger["transition_target"] == "RESTORE_STARTED"
            and snapshot.ledger["transition_data_commitment"] == transition_commitment
            and snapshot.spool["state"] == "OPEN"
            and snapshot.spool["last_stage"] == "RUNNER_STARTED"
        ):
            _raise(BridgeError, "POST_CAS_UNCERTAIN")
        return snapshot

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
        try:
            self.store.consume_restore(
                self.epoch_ref,
                transition_id,
                expected_digest=pre_cas_ledger_digest,
                data=transition,
            )
        except Exception:
            _raise(BridgeError, "STORE_TRANSITION_FAILED")
        self._post_cas = True
        self._assert_consumed_reload(
            transition_id=transition_id,
            transition_commitment=transition_commitment,
        )
        self._ingest_stage(
            "RESTORE_BEGIN",
            {"ref": transition_id, "commitment": transition_commitment},
        )
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
            if not self._post_cas and self._graph is not None and not self._terminal:
                self._send_abort_once(RunnerControlCode.LOCAL_ABORT)
            self._safe_abandon()
            return self._result(
                "FAILURE",
                error.code,
                post_cas_uncertain=self._post_cas,
            )
        except Exception:
            if not self._post_cas and self._graph is not None and not self._terminal:
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


# Run-318 contract-final definitions

class _RemoteChannel:
    def __init__(
        self,
        reader: BinaryIO,
        writer: BinaryIO,
        graph: BridgeKeyGraph,
        *,
        clock: Callable[[], float] = time.monotonic,
        randomness: Callable[[int], bytes] = os.urandom,
    ):
        self.reader = reader
        self.writer = writer
        self.graph = graph
        self._clock = clock
        self._randomness = randomness
        self.sequence = 1
        self.bytes_seen = 0
        self._frame_nonces: set[bytes] = set()
        self._read_lock = threading.Lock()

    def _new_frame_nonce(self) -> bytes:
        try:
            value = self._randomness(FRAME_NONCE_BYTES)
            _validate_nonce(value, "frame nonce", FRAME_NONCE_BYTES)
        except Exception:
            _raise(RunnerControlError, RunnerControlCode.PROTOCOL_FAILURE)
        if value in self._frame_nonces:
            _raise(RunnerControlError, RunnerControlCode.PROTOCOL_FAILURE)
        return value

    def _account_frame(self, frame: AuthenticatedFrame) -> None:
        if frame.frame_nonce in self._frame_nonces:
            _raise(RunnerControlError, RunnerControlCode.PROTOCOL_FAILURE)
        if len(self._frame_nonces) >= MAX_SESSION_FRAMES:
            _raise(RunnerControlError, RunnerControlCode.PROTOCOL_FAILURE)
        new_total = self.bytes_seen + AUTH_FRAME_OVERHEAD + len(frame.payload)
        if new_total > MAX_SESSION_BYTES:
            _raise(RunnerControlError, RunnerControlCode.PROTOCOL_FAILURE)
        self._frame_nonces.add(frame.frame_nonce)
        self.bytes_seen = new_total

    def _read_chunk_with_timeout(self, size: int, timeout: float | None) -> bytes:
        if timeout is None:
            return self.reader.read(size) or b""
        if timeout <= 0:
            _raise(RunnerControlError, RunnerControlCode.DECISION_TIMEOUT)
        result: queue.Queue[tuple[bytes | None, BaseException | None]] = queue.Queue(maxsize=1)

        def read_once() -> None:
            try:
                result.put((self.reader.read(size) or b"", None))
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
        deadline = None if timeout is None else self._clock() + timeout
        while len(chunks) < size:
            remaining = None if deadline is None else max(0.0, deadline - self._clock())
            chunk = self._read_chunk_with_timeout(size - len(chunks), remaining)
            if not chunk:
                _raise(RunnerControlError, RunnerControlCode.DECISION_EOF)
            chunks.extend(chunk)
        return bytes(chunks)

    def _read_frame(self, key: bytes, direction: int, timeout: float | None = None) -> AuthenticatedFrame:
        with self._read_lock:
            header = self._read_exact(AUTH_FRAME_HEADER_STRUCT.size, timeout=timeout)
            try:
                length = AUTH_FRAME_HEADER_STRUCT.unpack(header)[-1]
            except struct.error:
                _raise(RunnerControlError, RunnerControlCode.PROTOCOL_FAILURE)
            if length > MAX_AUTH_PAYLOAD_BYTES:
                _raise(RunnerControlError, RunnerControlCode.PROTOCOL_FAILURE)
            raw = header + self._read_exact(length + AUTH_FRAME_TAG_SIZE, timeout=timeout)
        try:
            frame = decode_authenticated_frame(
                raw,
                key,
                expected_direction=direction,
                expected_sequence=self.sequence,
                expected_session_nonce=self.graph.n_session,
            )
        except BridgeError:
            _raise(RunnerControlError, RunnerControlCode.PROTOCOL_FAILURE)
        self._account_frame(frame)
        self.sequence += 1
        return frame

    def send(self, key: bytes, direction: int, message: int, payload: bytes) -> None:
        frame_nonce = self._new_frame_nonce()
        frame = encode_authenticated_frame(
            key,
            direction,
            message,
            self.sequence,
            self.graph.n_session,
            payload,
            frame_nonce=frame_nonce,
        )
        if self.bytes_seen + len(frame) > MAX_SESSION_BYTES or len(self._frame_nonces) >= MAX_SESSION_FRAMES:
            _raise(RunnerControlError, RunnerControlCode.PROTOCOL_FAILURE)
        try:
            self.writer.write(frame)
            self.writer.flush()
        except (BrokenPipeError, OSError, ValueError):
            _raise(RunnerControlError, RunnerControlCode.PROTOCOL_BROKEN_PIPE)
        self._frame_nonces.add(frame_nonce)
        self.bytes_seen += len(frame)
        self.sequence += 1

    def receive(self, key: bytes, direction: int, *, timeout: float | None = None) -> AuthenticatedFrame:
        return self._read_frame(key, direction, timeout=timeout)


class RunnerRuntime:
    """The only public capability surface visible to run(runtime)."""

    _INITIAL = "INITIAL"
    _RUNNING = "RUNNING"
    _WAITING_DECISION = "WAITING_DECISION"
    _PROCEED_GRANTED = "PROCEED_GRANTED"
    _RESULT_SENT = "RESULT_SENT"
    _TERMINAL = "TERMINAL"

    def __init__(
        self,
        channel: _RemoteChannel,
        barrier_utc: str,
        *,
        decision_timeout: float = PROCEED_TIMEOUT_SECONDS,
    ):
        self._channel = channel
        self._barrier_utc = _validate_canonical_barrier(barrier_utc)
        self._decision_timeout = decision_timeout
        self._state = self._INITIAL
        self._grant_records: dict[int, tuple[ProceedGrant, str]] = {}
        self._terminal_frame_sent = False
        self._discovery_sent = False
        self._pending_artifact: str | None = None
        self._pending_isolation: str | None = None

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
        self._state = self._TERMINAL

    def discover(
        self,
        execution_row_id: int,
        artifact_filename: str,
        isolation_state: str,
        isolation_commitment: str,
    ) -> ProceedGrant:
        if self._discovery_sent:
            _raise(RunnerControlError, RunnerControlCode.DISCOVERY_DUPLICATE)
        if self._state != self._RUNNING:
            _raise(RunnerControlError, RunnerControlCode.RUNTIME_TERMINAL)
        try:
            execution_row_id, artifact_filename = _validate_discovery_tuple(
                execution_row_id,
                artifact_filename,
            )
        except BridgeError:
            _raise(RunnerControlError, RunnerControlCode.PROTOCOL_FAILURE)
        if isolation_state != "PASS" or not _is_commitment(isolation_commitment):
            _raise(RunnerControlError, RunnerControlCode.ISOLATION_FAILED)
        artifact_commitment = STORE.recovery_commitment(
            "artifact-row",
            str(execution_row_id),
            artifact_filename,
        )
        try:
            self._channel.send(
                self._channel.graph.k_session,
                DIRECTION_REMOTE_TO_LOCAL,
                MESSAGE_DISCOVERY,
                encode_control(
                    {
                        "type": "DISCOVERY",
                        "version": 1,
                        "execution_row_id": execution_row_id,
                        "artifact_filename": artifact_filename,
                        "isolation_state": "PASS",
                        "isolation_commitment": isolation_commitment,
                    }
                ),
            )
        except RunnerControlError:
            self._state = self._TERMINAL
            raise
        self._discovery_sent = True
        self._pending_artifact = artifact_commitment
        self._pending_isolation = isolation_commitment
        self._state = self._WAITING_DECISION
        try:
            frame = self._channel.receive(
                self._channel.graph.k_session,
                DIRECTION_LOCAL_TO_REMOTE,
                timeout=self._decision_timeout,
            )
        except RunnerControlError:
            self._state = self._TERMINAL
            raise
        except (BrokenPipeError, OSError, ValueError):
            self._state = self._TERMINAL
            _raise(RunnerControlError, RunnerControlCode.DECISION_BROKEN_PIPE)
        if frame.message == MESSAGE_ABORT:
            try:
                value = decode_control(frame.payload, "ABORT")
                code = RunnerControlCode(value["code"])
            except (BridgeError, TypeError, ValueError):
                self._state = self._TERMINAL
                _raise(RunnerControlError, RunnerControlCode.PROCEED_INVALID)
            self._terminal_frame_sent = True
            self._state = self._TERMINAL
            raise RunnerControlError(code)
        if frame.message != MESSAGE_PROCEED:
            self._state = self._TERMINAL
            _raise(RunnerControlError, RunnerControlCode.PROCEED_INVALID)
        try:
            value = decode_control(frame.payload, "PROCEED")
            expected = {
                "epoch_digest": _digest_commitment(self._channel.graph.epoch_digest),
                "authority_digest": _digest_commitment(self._channel.graph.authority_digest),
                "runner_digest": _digest_commitment(self._channel.graph.runner_digest),
                "bundle_digest": _digest_commitment(self._channel.graph.bundle_digest),
                "barrier_utc": self._barrier_utc,
                "artifact_commitment": self._pending_artifact,
                "isolation_commitment": self._pending_isolation,
            }
            for name, expected_value in expected.items():
                if value[name] != expected_value:
                    _raise(RunnerControlError, RunnerControlCode.PROCEED_INVALID)
            capability = proceed_commitment(
                self._channel.graph,
                value["artifact_commitment"],
                value["isolation_commitment"],
                value["transition_id"],
                value["pre_cas_ledger_digest"],
                value["transition_data_commitment"],
                value["consumed_record_digest"],
            )
            raw_token = base64.urlsafe_b64decode(value["grant"] + "===")
            if not hmac.compare_digest(raw_token, _grant_token(self._channel.graph, capability)):
                _raise(RunnerControlError, RunnerControlCode.PROCEED_INVALID)
        except RunnerControlError:
            self._state = self._TERMINAL
            raise
        except (BridgeError, TypeError, ValueError, binascii.Error):
            self._state = self._TERMINAL
            _raise(RunnerControlError, RunnerControlCode.PROCEED_INVALID)
        grant = ProceedGrant(ProceedGrant._SEAL)
        self._grant_records[id(grant)] = (grant, capability)
        self._state = self._PROCEED_GRANTED
        return grant

    def send_result(
        self,
        grant: ProceedGrant,
        classification: ResultClassification | str,
        result_commitment: str,
    ) -> None:
        if self._state == self._RESULT_SENT:
            _raise(RunnerControlError, RunnerControlCode.RESULT_DUPLICATE)
        if self._state != self._PROCEED_GRANTED:
            _raise(RunnerControlError, RunnerControlCode.RESULT_BEFORE_PROCEED)
        record = self._grant_records.get(id(grant))
        if type(grant) is not ProceedGrant or record is None or record[0] is not grant:
            _raise(RunnerControlError, RunnerControlCode.PROCEED_INVALID)
        try:
            classification = ResultClassification(classification)
        except (TypeError, ValueError):
            _raise(RunnerControlError, RunnerControlCode.PROTOCOL_FAILURE)
        if not _is_commitment(result_commitment):
            _raise(RunnerControlError, RunnerControlCode.PROTOCOL_FAILURE)
        del self._grant_records[id(grant)]
        try:
            self._channel.send(
                self._channel.graph.k_session,
                DIRECTION_REMOTE_TO_LOCAL,
                MESSAGE_RESULT,
                encode_control(
                    {
                        "type": "RESULT",
                        "version": 1,
                        "classification": classification.value,
                        "result_commitment": result_commitment,
                    }
                ),
            )
        except RunnerControlError:
            self._state = self._TERMINAL
            raise
        self._terminal_frame_sent = True
        self._state = self._RESULT_SENT

    def abort(self, code: RunnerAbortCode) -> None:
        if not isinstance(code, RunnerAbortCode):
            raise TypeError("RunnerRuntime.abort accepts RunnerAbortCode")
        if self._state == self._TERMINAL or self._terminal_frame_sent:
            _raise(RunnerControlError, RunnerControlCode.RUNTIME_TERMINAL)
        control = RunnerControlCode(code.value)
        self._send_abort(control)
        raise RunnerControlError(control)


# Run-318 contract-final definitions continue below.

class RemoteLoader:
    """Fixed loader state machine used by the local-only dummy child."""

    def __init__(
        self,
        reader: BinaryIO,
        writer: BinaryIO,
        *,
        capture_fds: bool = False,
        clock: Callable[[], float] = time.monotonic,
        randomness: Callable[[int], bytes] = os.urandom,
    ):
        self._raw_reader = reader
        self._raw_writer = writer
        self._capture_fds = capture_fds
        self._clock = clock
        self._randomness = randomness
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

    def _read_chunk_with_timeout(self, size: int, timeout: float | None) -> bytes:
        if timeout is None:
            return self._protocol_reader.read(size) or b""
        if timeout <= 0:
            _raise(ProtocolError, "PROCESS_TIMEOUT")
        result: queue.Queue[tuple[bytes | None, BaseException | None]] = queue.Queue(maxsize=1)

        def read_once() -> None:
            try:
                result.put((self._protocol_reader.read(size) or b"", None))
            except BaseException as error:
                result.put((None, error))

        thread = threading.Thread(target=read_once, daemon=True)
        thread.start()
        try:
            chunk, error = result.get(timeout=timeout)
        except queue.Empty:
            _raise(ProtocolError, "PROCESS_TIMEOUT")
        if error is not None:
            raise error
        return chunk or b""

    def _read_exact(self, size: int, deadline: float) -> bytes:
        payload = bytearray()
        while len(payload) < size:
            remaining = deadline - self._clock()
            if remaining <= 0:
                _raise(ProtocolError, "PROCESS_TIMEOUT")
            chunk = self._read_chunk_with_timeout(size - len(payload), remaining)
            if not chunk:
                _raise(ProtocolError, "PROCESS_EOF")
            payload.extend(chunk)
        return bytes(payload)

    def _send_raw(self, payload: bytes) -> None:
        try:
            self._protocol_writer.write(payload)
            self._protocol_writer.flush()
        except (BrokenPipeError, OSError, ValueError):
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
        channel: _RemoteChannel | None = None
        runtime: RunnerRuntime | None = None
        pending_error: RunnerControlError | None = None
        try:
            try:
                n_remote = self._randomness(SESSION_NONCE_BYTES)
                _validate_nonce(n_remote, "n_remote", SESSION_NONCE_BYTES)
            except Exception:
                return EXIT_PROTOCOL_FAILURE
            self._send_raw(encode_hello(n_remote))
            overall_deadline = self._clock() + WHOLE_SESSION_TIMEOUT_SECONDS
            preamble = decode_preamble(
                self._read_exact(
                    PREAMBLE_SIZE,
                    min(overall_deadline, self._clock() + HELLO_TIMEOUT_SECONDS),
                )
            )
            if preamble["n_remote"] != n_remote:
                _raise(ProtocolError, "HELLO_INVALID")
            graph = derive_key_graph_from_preamble(preamble)
            channel = _RemoteChannel(
                self._protocol_reader,
                self._protocol_writer,
                graph,
                clock=self._clock,
                randomness=self._randomness,
            )
            boot = channel.receive(
                graph.k_boot,
                DIRECTION_LOCAL_TO_REMOTE,
                timeout=max(
                    0.0,
                    min(overall_deadline, self._clock() + BOOT_TIMEOUT_SECONDS)
                    - self._clock(),
                ),
            )
            if boot.message != MESSAGE_BOOT:
                _raise(ProtocolError, "FRAME_INVALID")
            barrier = self._extract_barrier(boot.payload)
            source = decode_boot_payload(
                boot.payload,
                expected_barrier=barrier,
                expected_digest=graph.bundle_digest,
            )
            bundle = RunnerBundle(
                source,
                expected_commitment=_digest_commitment(graph.bundle_digest),
            )
            validate_runner_bundle(bundle)
            graph = graph.with_barrier(barrier)
            channel.graph = graph
            runtime = RunnerRuntime(channel, barrier)
            namespace = _runner_namespace()
            try:
                with runner_stdio_isolation(capture_fds=self._capture_fds):
                    try:
                        exec(
                            compile(
                                source.decode("utf-8", "strict"),
                                "<runner-bundle>",
                                "exec",
                                dont_inherit=True,
                            ),
                            namespace,
                            namespace,
                        )
                        if "run" not in namespace:
                            _raise(RunnerControlError, RunnerControlCode.RUNNER_MISSING)
                        _validate_run_callable(namespace["run"])
                        channel.send(
                            graph.k_session,
                            DIRECTION_REMOTE_TO_LOCAL,
                            MESSAGE_READY,
                            encode_control(
                                {
                                    "type": "READY",
                                    "version": 1,
                                    "barrier_utc": runtime.barrier_utc,
                                }
                            ),
                        )
                        runtime._state = runtime._RUNNING
                        returned = namespace["run"](runtime)
                        if runtime._state == runtime._RESULT_SENT:
                            if returned is not None:
                                _raise(
                                    RunnerControlError,
                                    RunnerControlCode.RUNNER_NON_NONE_RETURN,
                                )
                        elif runtime._state != runtime._TERMINAL:
                            _raise(
                                RunnerControlError,
                                RunnerControlCode.RUNNER_NO_RESULT
                                if returned is None
                                else RunnerControlCode.RUNNER_NON_NONE_RETURN,
                            )
                    except RunnerControlError as error:
                        pending_error = error
                    except BaseException:
                        pending_error = RunnerControlError(
                            RunnerControlCode.RUNNER_TOP_LEVEL_EXCEPTION
                        )
            except RunnerControlError as error:
                pending_error = error
            if pending_error is not None:
                if runtime is not None and not runtime._terminal_frame_sent:
                    self._send_abort(channel, pending_error.code)
                return EXIT_RUNNER_ABORT
            return EXIT_SUCCESS if runtime._state == runtime._RESULT_SENT else EXIT_RUNNER_ABORT
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
        if not isinstance(payload, bytes) or len(payload) <= BOOT_BARRIER_BYTES:
            _raise(ProtocolError, "FRAME_INVALID")
        try:
            barrier = payload[:BOOT_BARRIER_BYTES].decode("ascii", "strict")
        except UnicodeDecodeError:
            _raise(ProtocolError, "FRAME_INVALID")
        return _validate_canonical_barrier(barrier)
_CANONICAL_LOADER_COMPRESSED = "T>t=p0RR90|NsC0{{S?bN@uuIJafwOWx8GH_92ly!q_WVJd&ajOcvkVg|WZnDW|>F*7r?_-DsrT$O`2ATKzXl>q_c7<nb}X)M77Sv#Son+VC@&SCBg)>&QJ%cgg$~VZ%ZnYVOjg{+A{NRdJ7pp6rfAD;wxL6UwLu`kaAdaTSnUHyK*D7oAm+&Gz=V+(&3nw_rgj4oG~FNl{PH0n6$~M|OG04XxC37A(T_j8B>7QOh@rUHh)=y~{-ofFB3f;GaR*rkIE#+I#!1f2Gt4F7O0nc4^8AZ}qaOlEx5!J4uiG5)X7SOxGA#+pm2_!L`5azl|26UBj0wULUX*>N)BH=r>2-$bW}I>t<PM6~X{p1^g2h;E$o*bfyOYM%9FyFcT<Cxh3Z*_}9|xNSJwYgq)H_B}Cy+`-7o&G<hyN<V?oqRZZKUa#3o(+oCNAg?+u@>)XIhg(LOGKVQdll|n}F<qhfO^CDo);RB|mEH6m66&Qt8@E$Pf#1zG#@KpHiQ1&aECpBAfF`_JL?FnIW3>H}9Sekevv@G#UW0B&082OD${e!2si=TV1bw0GwoU|$Qo#_**o~Q=oVOrp9ebJBbzPw_T@k-oT@#C$R1;@xthf_e#ou-AF-z4ElwJsdi!*?foA}vjT=ijJyDU2K4tbuPT!6Zo#-PeayCN)Uf2PV|4iBt*38Y0R?QKKn>!mvPh{U}ceP{aOK3zhOpNoeGU@}2b9NSqj!dZXTQZ4`GYX9q4leLbf|HFbSLi#cj8Ra*R!&RAKK!29`6DhG$P)mySvmEsJQq53VvP$@1!fkxQIDPy+@gzJY;$c?>=O)WyDj258mX^!wJkR3HBe<EJ7N1AOXJclD<ZdMBN*pg6_T5(ECR*XgE|A93_O8-S*kxqW)T79-4xI(;2eIA%ADBTjsoc6GdGbkC(@GWsYbhie~5I$xI$I2$F!g}reX{%px<hoelzF}}L>Wue9UW_!SHVA+3njOLu4k@{R185HcCIPi}y*~uGH3H{$A6;ldWh^K5y-^}mpC9u+r%uef{DCF0s~UI-!;|*^rm`+n{kn0c@*|q;ejAoGe#$*L-^OY_C$1Rs2%a_4h9F%@d+Aii?v#5H{k}<Bp;lY#86vREKz(8r2_7fI?l<C}g^^*=Dy3Jn+vR?eq-rCr5D!Dv$ZN$iSLYvaqeki=6{@DC+2XWPUPzGRd{`x)2|vgQy;BDuDt3<=vw?Mj@N6)-vA8)@cm!e=ky4TaF4=|f^3rKv?)T=#EgHIQ$f;ci5ogPxSg+11;V)4%ACY9{Q8@AM`s)5E-7E98NGyzt97f9Jxc&?GZOplz#|{|q!;8WW;5t&p|4|2VTzZ^}{h-d2JVpWe0uri)1(D_{07`(4QPk=-;$#s^!$+6A4aPKE;_%J0!MwLvO+KT+O@%`x3aV5dvmOic$uhj7)p+M#m}F`{7ANb<^iOupt0w<mLKR?0o!F5TO)o^h4m8a$HLk{eA9PF9mju_?H;oiUcX?B1lx|px`mr@B;5-ad(|6dZuHQT-I#`LG>px2u^AtFK`+Md76<F0K#>X)731#vYlPTUHv6BPr5IizoOd?*a;pR$_iYOq^#(m||tfDTLz@jR48Kx-2|B26<#?hD!wv--OL=olQLeo9=`j9!gE+bL1Y3c6K(yY_!gK<X7;)zVMFIC6TN}8Z#%vca=dF@K|E11OUn68D=<a9JDssovH)8aH^pOLnil)pkx!qQ$ovaQeVm>`euDF=N-TrHAkZP8vM0vR_$@<-|F(+pP#j$cZ6W`#r5iJ^{LW~@P{QgVS&s?LKR;Nr<S{8+$5cnNw)g*K$io@k&3i<+(QTGjMpP2FG3AyaKEW;i<d^-QXg-N-S~4yNm%FW~)fenj>1b$cxXiGxzN{GletRS%)39Xz+<C~^4pZ+TWiP6`(nah&?EX4OfZmN`@L9{PW7e-K543ww=%p<^HcL{9e5<l@E6FwKI!uMa`SYx|;FXao{Zm%}j9%p#6R9d<^WWv{#+g*>A;U6uq$*Di;B#kVD1PsQMes?z+4W93IiEMQktu5DFJi$eL@B}NW5?3%Rf(9RA%i0<c(^G7FE;QzGT)7Pr<KoGmusur&SC}c5_3H!x$Ho~at(*LS?YFw>%WU|$+l;jZXHkBnK;7rbCMug+t=BQhA=!V3u&uOy`{;lQHqh&Ip-+nMP)v~@6HBkhbt}yB+2lYy+cwI@bC2@Y%496v>Nv7M3{cwKDIf^=;yl{$fh|SN>fXpgc3V`{V3X9%36?Y3r0qmXuFyPIim$f+1?;Hp$HuWY^?nXUP>w5rLn$84}>C33#n^UY~6=o$4Ih7w{=8)O34!m@I2x5FIu0&JThRl*1&=NIy_xQImSD~qnEK^qI&DIdX#V{%<^f{TdP7m@K@NIwBRd1QsvNhz$>_4=&r<lEHK1HkvI>yH`t6c8WH^}Z2oSk{>qXH@NbrRpPaH%nK-W;ZYM}akJCMQ!TxEPQE@>aM4HU!Nq2raDm*6Ale;l(iYzBKp%#M3+3*70)`l4Y%+a?=EF@E>?prXh`Ky174cuzm~guwn5~DDxZ#a=Z#%tu6VupPhw5^Wo=F*gLJhg6ADuK#<aC#iMIsolKQQG^>QmiE_h|nWV)RRE=QIZ1)AKJx5DDXmy`ALYxm{*O*2`p#tk_H8KSsxZ%=GgPvYn7j@G-6_|-p(!&68T>Jh~yYGQWrbTUUA`<&W0f}cO8RMTDp2p@V7WT5D5>~PU`+wYTb|uOn%Pl0Sx0c~V#CTkvqD^^!-(={-?*!+!GueL(5dUpNVx7Dg#|AspLN6;OAR87ko1CpAnTL|zM+O8}J0#K(z(EMvNlYX)ViwBJTE?+GuuKx~&bk^<`ot)Xf=qK|&#ehBa=K{^rZ2U?&wRxa5@uBx_k_Kn@rmg2+MQ{xQi(Q8l9KWD<DX}tKR`p9aP<7L1`NS0l7}y_dpS7R{Hrl2nM^cg9i$XahNQDmAS6$D1Ewo-&3ke9Fs%=rBjdcRk=$*np=<giW`iD09!YTJ{~U=`NO>yev5jhLlu$vD?M^Ah+Ctcrch0HxDP<F#)lK~9Pt36ftyhmWa=s>H!-xr+`{Nt(fUC0KP*tA%N@6fBq&dE2e}L27@#K^E9jk%JHls5;l<~*jbqFSeSob&$6&xG2oBq=!`q!%-2`ZnO5e8)Un^?+kUE=@m#ihtAyp4$9vYo<MSR(E!*d<Gc^D5(Zw2BD0?=jKEb<qy?U%xbs2D8gIYC3|BZUh*rB#S5yK`j6gH#CDL7t)(wt9M`T>73d|gOZi?ygwN<L^ittIxu!NUf(rRm7?rk;UpDCL4TZS)Sx4RqIW`CFZ}u;`wwiiNA;FD5r4F8f3`N9gMfY^!3%EomKj1Ae<<DSJ~nWxkCOIJCEU9h$_7?5>l^Y(Oh8=2snw*o3nCJ*(^bNE<DiNQ8MY70XDqCQ+7xrOG+^c3TF<`B7_=%+jb1a83T=eO$zv7UVS)yZSBpZ|L<aP_pz$`$Md>}n&Hx^w!F;PoT^^oh%ISNAE;8`!Y@fn$u*J3>DfE~Ph<^`|$h&lnn60x}V)VG0KHmL55S`)mD9y$~>_&ho$R#N4>;In^st&xxlMhVho`Fcjwxd{K`RzDXUpIU06yBRB#Vs8pee<@<ig-<DWaga_m%XjDfjLqDcFEKLB{bmeO{4U`uh@k2IIlpN{g05_mm)+`Pf2Fs9=5bzc^8TfD~{O|+T;%=4X3|9ui$}?`0B?_B(8-`xdYGi=0ry@*$uQ22n?lSAu46ge$@1|y`!wJRSt{r9CT!vqHn!+&br%)L}EKwZlIX3#(_!FSKA5{N1d&!t=Kpv_A-lHl&TH=$VZfhg`Iy$5*X>-A9KQjAm!Hs+q4JyD1?>iqaQ?8K%^M<yX-e+;s%eT!EBd>(5FIr8S9mfRj`(Fq;EURFNe$D8`Ioa$qIt*ZoW^fT$<u;MiCYzXiIJ!DPv1zLk|DVv0sdv(9ba`NvhfF)lOx9w2f~+6^~$Q8ltMXk4)b!kHRo9_zTF3I))e#{D-g)<bFVX*i_eaevba&bNK"
CANONICAL_LOADER_PAYLOAD_BYTES = lzma.decompress(
    base64.b85decode(_CANONICAL_LOADER_COMPRESSED)
)
if len(CANONICAL_LOADER_PAYLOAD_BYTES) > 65536:
    raise RuntimeError("fixed loader payload oversized")
FIXED_LOADER_MAX_BYTES = 4096
_FIXED_LOADER_COMPRESSED = _CANONICAL_LOADER_COMPRESSED
FIXED_LOADER_SOURCE = (
    "import lzma as l,base64 as b\n"
    "p=l.decompress(b.b85decode(" + repr(_FIXED_LOADER_COMPRESSED) + "))\n"
    "if len(p)>65536:raise ValueError(0)\n"
    "exec(compile(p,\"\",\"exec\"),{\"p\":p})\n"
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
    return RemoteLoader(sys.stdin.buffer, sys.stdout.buffer, capture_fds=True).run()


def main(argv: Sequence[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    if values == ["--dummy-child"]:
        return _dummy_child_main()
    return EXIT_PROTOCOL_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())
