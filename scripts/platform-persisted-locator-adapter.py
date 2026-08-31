#!/usr/bin/env python3
"""Offline-safe SPLQ v1 persisted-locator adapter.

The public protocol is deliberately separate from the private PostgreSQL phase.
The only admission path for the private phase is AdmissionState.step(), which
is also exercised directly by the offline contract fixtures.
"""

from __future__ import annotations

import json
import queue
import re
import selectors
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, BinaryIO, Callable


Header = struct.Struct("!4sBBHI")
Magic = b"SPLQ"
Version = 1
REQUEST_SCHEMA_VERSION = 3

CANONICAL_UTC_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
CANONICAL_UTC_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z"
)

REQUEST = 1
STARTED = 2
RESULT = 3
FAILED = 4

REQMAX = 1024
PAYMAX = 4096
QMAX = 4096
OMAX = 4096
EMAX = 4096
CMAX = 8192
NMAX = 2048
EVENT_QUEUE_MAX = 16

PRE_OMAX = 64
PRE_EMAX = 64

R = 5
I = 2
S = 7
MARGIN = 1
PGCONNECT_TIMEOUT = 2
T_HOST = R + 2 * I + S + MARGIN
assert T_HOST == 17

READINESS_COMMAND = b"\\echo SPLQ_PUBLIC_READY_V1\n"
READY_MARKER = b"SPLQ_PUBLIC_READY_V1\n"

WRITER_PENDING = "pending"
WRITER_OK = "ok"
WRITER_SHORT = "short"
WRITER_ERROR = "error"

ADMISSION_WAIT = "WAIT"
ADMISSION_ACCEPT = "ACCEPT"
ADMISSION_FAIL = "FAIL"
ADMISSION_CLOSED = "CLOSED"

ZERO_ROW_MATCH = "ZERO_ROW_MATCH"
MULTIPLE_ROW_MATCH = "MULTIPLE_ROW_MATCH"
PRIVATE_LOCATOR_MISSING = "PRIVATE_LOCATOR_MISSING"
EXACTLY_ONE = "EXACTLY_ONE"

QUERY_NOT_EXECUTED = "QUERY_NOT_EXECUTED"
QUERY_FAILED = "QUERY_FAILED"

PGOPTIONS_VALUE = "-c statement_timeout=7000 -c idle_session_timeout=2000 -c TimeZone=UTC"


SHELL_WRAPPER = r'''set -eu
if [ -z "${POSTGRES_USER:-}" ]; then exit 64; fi
if [ "${POSTGRES_DB:-}" != "coolify" ]; then exit 65; fi
postgres_user=$POSTGRES_USER
unset PGHOST PGHOSTADDR PGPORT PGDATABASE PGUSER PGPASSWORD PGPASSFILE
unset PGSERVICE PGSERVICEFILE PGOPTIONS PGSSLMODE PGSSLNEGOTIATION
unset PGSSLCERT PGSSLKEY PGSSLROOTCERT PGSSLCRL PGSSLCRLDIR
unset PGREQUIRESSL PGTZ PGTARGETSESSIONATTRS PGCHANNELBINDING PGAPPNAME
unset PGGSSENCMODE PGKRBSRVNAME PGREALM PGREQUIREAUTH POSTGRES_DB POSTGRES_USER
export HOME=/nonexistent
export PGPASSFILE=/dev/null
export PGCONNECT_TIMEOUT=2
export PGOPTIONS='-c statement_timeout=7000 -c idle_session_timeout=2000 -c TimeZone=UTC'
exec /usr/local/bin/psql \
  -X \
  -w \
  -n \
  -q \
  -A \
  -t \
  -v ON_ERROR_STOP=1 \
  --host=/var/run/postgresql \
  --port=5432 \
  --username="$postgres_user" \
  --dbname=coolify \
  --pset=pager=off \
  -f -
'''


class AdapterError(Exception):
    """Base class for safe, non-private adapter failures."""


class ProtocolError(AdapterError):
    pass


class QueryConstructionError(AdapterError):
    pass


class SelectorOutputError(AdapterError):
    pass


def _validate_canonical_utc(
    value: Any,
    error_type: type[AdapterError],
    label: str,
) -> str:
    if not isinstance(value, str) or CANONICAL_UTC_PATTERN.fullmatch(value) is None:
        raise error_type(f"{label} is not canonical UTC")
    try:
        parsed = datetime.strptime(value, CANONICAL_UTC_FORMAT)
    except ValueError as error:
        raise error_type(f"{label} is not a real date/time") from error
    canonical = (
        f"{parsed.year:04d}-{parsed.month:02d}-{parsed.day:02d}"
        f"T{parsed.hour:02d}:{parsed.minute:02d}:{parsed.second:02d}"
        f".{parsed.microsecond:06d}Z"
    )
    if canonical != value:
        raise error_type(f"{label} is not canonically serialised")
    return canonical


def validate_barrier_utc(value: Any) -> str:
    return _validate_canonical_utc(value, ProtocolError, "barrier UTC")


def _validate_positive_id(value: Any, error_type: type[AdapterError], label: str) -> int:
    if type(value) is not int or not 0 < value < 9223372036854775808:
        raise error_type(f"{label} is invalid")
    return value


def validate_schedule_id(value: Any) -> int:
    return _validate_positive_id(value, ProtocolError, "schedule id")


def _validate_selector_id(value: Any, label: str) -> int:
    return _validate_positive_id(value, SelectorOutputError, label)


def _validate_filename(value: Any) -> str:
    if not isinstance(value, str):
        raise SelectorOutputError("selector filename is not a string")
    try:
        filename_size = len(value.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise SelectorOutputError("selector filename is not valid UTF-8") from error
    if filename_size == 0:
        raise SelectorOutputError("selector filename is empty")
    if filename_size > NMAX:
        raise SelectorOutputError("selector filename is oversized")
    return value


def _validate_execution_created_at(value: Any) -> str:
    return _validate_canonical_utc(value, SelectorOutputError, "execution timestamp")


def _reject_constant(value: str) -> None:
    raise ProtocolError("non-finite JSON constant")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("duplicate JSON key")
        result[key] = value
    return result


def parse_strict_json(payload: bytes) -> Any:
    if not isinstance(payload, bytes):
        raise ProtocolError("JSON payload must be bytes")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProtocolError("JSON payload is not UTF-8") from error
    if not text or text != text.strip():
        raise ProtocolError("JSON payload has surrounding input")
    decoder = json.JSONDecoder(
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_constant,
    )
    try:
        value, end = decoder.raw_decode(text)
    except (json.JSONDecodeError, ProtocolError) as error:
        raise ProtocolError("invalid JSON payload") from error
    if end != len(text):
        raise ProtocolError("JSON payload has trailing input")
    return value


def parse_request_payload(payload: bytes) -> dict[str, Any]:
    if not isinstance(payload, bytes):
        raise ProtocolError("request payload must be bytes")
    if len(payload) > REQMAX or len(payload) > PAYMAX:
        raise ProtocolError("request payload is oversized")
    value = parse_strict_json(payload)
    if not isinstance(value, dict) or set(value) != {"type", "version", "barrier_utc"}:
        raise ProtocolError("request object shape is invalid")
    if (
        value["type"] != "REQUEST"
        or type(value["version"]) is not int
        or value["version"] != REQUEST_SCHEMA_VERSION
    ):
        raise ProtocolError("request version or type is invalid")
    barrier_utc = validate_barrier_utc(value["barrier_utc"])
    return {"type": "REQUEST", "version": REQUEST_SCHEMA_VERSION, "barrier_utc": barrier_utc}


def decode_request_frame(frame: bytes) -> dict[str, Any]:
    if not isinstance(frame, bytes) or len(frame) < Header.size:
        raise ProtocolError("request frame is incomplete")
    magic, version, message_type, flags, payload_length = Header.unpack(frame[:Header.size])
    if magic != Magic or version != Version or message_type != REQUEST or flags != 0:
        raise ProtocolError("request frame header is invalid")
    if payload_length > REQMAX or payload_length > PAYMAX:
        raise ProtocolError("request frame payload is oversized")
    expected_length = Header.size + payload_length
    if len(frame) != expected_length:
        raise ProtocolError("request frame has trailing or missing input")
    return parse_request_payload(frame[Header.size:])


def _read_some(stream: BinaryIO, length: int) -> bytes:
    read1 = getattr(stream, "read1", None)
    if callable(read1):
        return read1(length)
    return stream.read(length)


def _read_exact(
    stream: BinaryIO,
    length: int,
    deadline: float,
    buffered: bytearray | None = None,
) -> bytes:
    result = bytearray()
    pending = buffered if buffered is not None else bytearray()
    selector = None
    try:
        while len(result) < length:
            if pending:
                take = min(length - len(result), len(pending))
                result.extend(pending[:take])
                del pending[:take]
                continue
            if selector is None:
                selector = selectors.DefaultSelector()
                selector.register(stream, selectors.EVENT_READ)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProtocolError("request read timed out")
            if not selector.select(remaining):
                raise ProtocolError("request read timed out")
            chunk = _read_some(stream, Header.size + REQMAX + 1)
            if not chunk:
                raise ProtocolError("request frame ended early")
            take = min(length - len(result), len(chunk))
            result.extend(chunk[:take])
            pending.extend(chunk[take:])
    except (ValueError, OSError) as error:
        raise ProtocolError("request frame could not be read") from error
    finally:
        if selector is not None:
            selector.close()
    return bytes(result)


def _reject_immediate_trailing_input(stream: BinaryIO) -> None:
    selector = selectors.DefaultSelector()
    try:
        selector.register(stream, selectors.EVENT_READ)
        if not selector.select(0):
            return
        chunk = _read_some(stream, 1)
        if chunk:
            raise ProtocolError("request frame has trailing input")
    except (ValueError, OSError) as error:
        raise ProtocolError("request frame could not be read") from error
    finally:
        selector.close()


def read_request_frame(stream: BinaryIO, timeout: int = R) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    buffered = bytearray()
    header = _read_exact(stream, Header.size, deadline, buffered)
    magic, version, message_type, flags, payload_length = Header.unpack(header)
    if magic != Magic or version != Version or message_type != REQUEST or flags != 0:
        raise ProtocolError("request frame header is invalid")
    if payload_length > REQMAX or payload_length > PAYMAX:
        raise ProtocolError("request frame payload is oversized")
    payload = _read_exact(stream, payload_length, deadline, buffered)
    if buffered:
        raise ProtocolError("request frame has trailing input")
    _reject_immediate_trailing_input(stream)
    return parse_request_payload(payload)


def _json_bytes(value: dict[str, Any], limit: int) -> bytes:
    try:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ProtocolError("public JSON payload is invalid") from error
    if len(encoded) > limit:
        raise ProtocolError("public JSON payload is oversized")
    return encoded


def build_frame(message_type: int, value: dict[str, Any], limit: int = PAYMAX) -> bytes:
    payload = _json_bytes(value, limit)
    return Header.pack(Magic, Version, message_type, 0, len(payload)) + payload


def started_frame() -> bytes:
    return build_frame(STARTED, {"type": "STARTED", "version": Version})


def result_frame(
    classification: str,
    filename: str | None = None,
    schedule_id: int | None = None,
    execution_id: int | None = None,
    execution_created_at: str | None = None,
) -> bytes:
    if classification not in {ZERO_ROW_MATCH, MULTIPLE_ROW_MATCH, PRIVATE_LOCATOR_MISSING, EXACTLY_ONE}:
        raise ProtocolError("invalid result classification")
    value: dict[str, Any] = {"type": "RESULT", "version": Version, "classification": classification}
    private_tuple = (schedule_id, execution_id, execution_created_at, filename)
    if classification != EXACTLY_ONE:
        if any(item is not None for item in private_tuple):
            raise ProtocolError("non-single result cannot include private identity")
        return build_frame(RESULT, value)
    if any(item is None for item in private_tuple):
        raise ProtocolError("exact result needs a complete private tuple")
    try:
        value["schedule_id"] = _validate_positive_id(schedule_id, SelectorOutputError, "schedule id")
        value["execution_id"] = _validate_positive_id(execution_id, SelectorOutputError, "execution id")
        value["execution_created_at"] = _validate_canonical_utc(
            execution_created_at,
            SelectorOutputError,
            "execution timestamp",
        )
        value["filename"] = _validate_filename(filename)
    except SelectorOutputError as error:
        raise ProtocolError("exact result private tuple is invalid") from error
    return build_frame(RESULT, value)


def failed_frame(classification: str) -> bytes:
    if classification not in {QUERY_NOT_EXECUTED, QUERY_FAILED}:
        raise ProtocolError("invalid failure classification")
    return build_frame(FAILED, {"type": "FAILED", "version": Version, "classification": classification})


def write_public_frame(stream: BinaryIO, frame: bytes) -> None:
    written = stream.write(frame)
    if written != len(frame):
        raise ProtocolError("public frame write was short")
    stream.flush()


@dataclass
class AdmissionState:
    """Single-use readiness admission latch used by the production loop."""

    terminal: bool = False
    private_admission_latch: bool = False

    def step(
        self,
        captured_stdout: bytes,
        writer_status: str,
        now: float,
        readiness_deadline: float,
        *,
        stderr_failed: bool = False,
        overflow_failed: bool = False,
        process_failed: bool = False,
        route_failed: bool = False,
    ) -> str:
        if self.terminal:
            return ADMISSION_CLOSED
        if not isinstance(captured_stdout, bytes):
            self.terminal = True
            return ADMISSION_FAIL
        if stderr_failed or overflow_failed or process_failed or route_failed:
            self.terminal = True
            return ADMISSION_FAIL
        if writer_status not in {WRITER_PENDING, WRITER_OK, WRITER_SHORT, WRITER_ERROR}:
            self.terminal = True
            return ADMISSION_FAIL
        if writer_status in {WRITER_SHORT, WRITER_ERROR}:
            self.terminal = True
            return ADMISSION_FAIL
        if captured_stdout == READY_MARKER:
            marker_exact = True
        elif READY_MARKER.startswith(captured_stdout):
            marker_exact = False
        else:
            self.terminal = True
            return ADMISSION_FAIL
        if now >= readiness_deadline:
            self.terminal = True
            return ADMISSION_FAIL
        if not marker_exact or writer_status == WRITER_PENDING:
            return ADMISSION_WAIT
        if self.private_admission_latch or writer_status != WRITER_OK:
            self.terminal = True
            return ADMISSION_FAIL
        self.private_admission_latch = True
        self.terminal = True
        return ADMISSION_ACCEPT


def admission_step(
    state: AdmissionState,
    captured_stdout: bytes,
    writer_status: str,
    now: float,
    readiness_deadline: float,
    **guards: bool,
) -> str:
    return state.step(captured_stdout, writer_status, now, readiness_deadline, **guards)


@dataclass
class BoundedCapture:
    limit: int
    data: bytearray = field(default_factory=bytearray)
    overflow: bool = False

    def append(self, chunk: bytes) -> None:
        if not isinstance(chunk, bytes):
            self.overflow = True
            return
        if len(self.data) + len(chunk) > self.limit:
            self.overflow = True
            remaining = max(0, self.limit - len(self.data))
            self.data.extend(chunk[:remaining])
            return
        self.data.extend(chunk)

    def snapshot(self) -> bytes:
        return bytes(self.data)


@dataclass
class CaptureSet:
    stdout: BoundedCapture = field(default_factory=lambda: BoundedCapture(OMAX))
    stderr: BoundedCapture = field(default_factory=lambda: BoundedCapture(EMAX))
    combined_size: int = 0
    combined_overflow: bool = False

    def append(self, channel: str, chunk: bytes) -> None:
        if channel == "stdout":
            self.stdout.append(chunk)
        elif channel == "stderr":
            self.stderr.append(chunk)
        else:
            raise ValueError("unknown capture channel")
        self.combined_size += len(chunk) if isinstance(chunk, bytes) else 0
        if self.combined_size > CMAX:
            self.combined_overflow = True


def write_once(stream: BinaryIO, payload: bytes) -> str:
    """Perform one full-write/flush attempt and never retry it."""

    try:
        written = stream.write(payload)
        if written != len(payload):
            return WRITER_SHORT
        stream.flush()
        return WRITER_OK
    except Exception:
        return WRITER_ERROR


def extract_after_ready_marker(captured_stdout: bytes) -> bytes:
    if not captured_stdout.startswith(READY_MARKER):
        raise SelectorOutputError("readiness marker is missing")
    return captured_stdout[len(READY_MARKER):]


def build_locator_query(barrier_utc: str) -> str:
    try:
        barrier_utc = validate_barrier_utc(barrier_utc)
    except ProtocolError as error:
        raise QueryConstructionError("locator barrier is invalid") from error
    query = rf"""WITH schedule_candidates AS (
  SELECT s.id
  FROM scheduled_database_backups AS s
  WHERE s.id > 0
    AND s.enabled IS TRUE
    AND s.database_id = 0
    AND s.database_type = 'App\Models\StandalonePostgresql'
    AND s.frequency = '0 18 * * *'
    AND s.save_s3 IS TRUE
    AND s.disable_local_backup IS FALSE
), schedule_cardinality AS (
  SELECT
    CASE WHEN count(*) > 1 THEN 2 ELSE count(*) END AS schedule_count,
    CASE WHEN count(*) = 1 THEN max(id) ELSE NULL END AS schedule_id
  FROM schedule_candidates
), execution_candidates AS (
  SELECT
    e.id AS execution_id,
    to_char(e.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS execution_created_at,
    e.filename
  FROM scheduled_database_backup_executions AS e
  JOIN schedule_candidates AS s
    ON e.scheduled_database_backup_id = s.id
  WHERE e.database_name = 'coolify'
    AND e.status = 'success'
    AND e.created_at > TIMESTAMPTZ '{barrier_utc}'
    AND CASE
          WHEN e.size ~ '^[0-9]+$'
          THEN e.size::numeric = 830082
          ELSE false
        END
    AND e.s3_uploaded IS TRUE
    AND e.filename IS NOT NULL
    AND e.local_storage_deleted IS FALSE
), execution_cardinality AS (
  SELECT
    CASE WHEN count(*) > 1 THEN 2 ELSE count(*) END AS execution_count,
    CASE WHEN count(*) = 1 THEN max(execution_id) ELSE NULL END AS execution_id,
    CASE WHEN count(*) = 1 THEN max(execution_created_at) ELSE NULL END AS execution_created_at,
    CASE WHEN count(*) = 1 THEN max(filename) ELSE NULL END AS filename
  FROM execution_candidates
)
SELECT json_build_object(
  'schedule_count', schedule_count,
  'schedule_id', CASE
                   WHEN schedule_count = 1 AND execution_count = 1 THEN schedule_id
                   ELSE NULL
                 END,
  'execution_count', execution_count,
  'execution_id', CASE
                   WHEN schedule_count = 1 AND execution_count = 1 THEN execution_id
                   ELSE NULL
                 END,
  'execution_created_at', CASE
                            WHEN schedule_count = 1 AND execution_count = 1 THEN execution_created_at
                            ELSE NULL
                          END,
  'filename', CASE
                WHEN schedule_count = 1 AND execution_count = 1 THEN filename
                ELSE NULL
              END
      )::text
FROM schedule_cardinality
CROSS JOIN execution_cardinality;"""
    encoded_length = len(query.encode("utf-8"))
    if encoded_length > QMAX:
        raise QueryConstructionError("locator query is oversized")
    return query


def phase2_payload(query: str) -> bytes:
    try:
        encoded_query = query.encode("utf-8")
    except UnicodeEncodeError as error:
        raise QueryConstructionError("locator query is not UTF-8") from error
    if len(encoded_query) > QMAX:
        raise QueryConstructionError("locator query is oversized")
    return encoded_query + b"\n\\q\n"


@dataclass(frozen=True)
class SelectorDetails:
    classification: str
    filename: str | None
    cause: str
    schedule_id: int | None = None
    execution_id: int | None = None
    execution_created_at: str | None = None


SCHEDULE_ZERO = "SCHEDULE_ZERO"
SCHEDULE_MULTIPLE = "SCHEDULE_MULTIPLE"
EXECUTION_ZERO = "EXECUTION_ZERO"
EXECUTION_MULTIPLE = "EXECUTION_MULTIPLE"


def _selector_cardinality(value: Any, field: str) -> int:
    if type(value) is not int or value not in {0, 1, 2}:
        raise SelectorOutputError(f"selector {field} is invalid")
    return value


def classify_selector_details(value: Any) -> SelectorDetails:
    if not isinstance(value, dict) or set(value) != {
        "schedule_count",
        "schedule_id",
        "execution_count",
        "execution_id",
        "execution_created_at",
        "filename",
    }:
        raise SelectorOutputError("selector output shape is invalid")
    schedule_count = _selector_cardinality(value["schedule_count"], "schedule count")
    execution_count = _selector_cardinality(value["execution_count"], "execution count")
    schedule_id = value["schedule_id"]
    execution_id = value["execution_id"]
    execution_created_at = value["execution_created_at"]
    filename = value["filename"]
    private_tuple = (schedule_id, execution_id, execution_created_at, filename)
    if schedule_count == 0:
        if any(item is not None for item in private_tuple):
            raise SelectorOutputError("non-single selector output has private identity")
        return SelectorDetails(ZERO_ROW_MATCH, None, SCHEDULE_ZERO)
    if schedule_count == 2:
        if any(item is not None for item in private_tuple):
            raise SelectorOutputError("non-single selector output has private identity")
        return SelectorDetails(MULTIPLE_ROW_MATCH, None, SCHEDULE_MULTIPLE)
    if execution_count == 0:
        if any(item is not None for item in private_tuple):
            raise SelectorOutputError("non-single selector output has private identity")
        return SelectorDetails(ZERO_ROW_MATCH, None, EXECUTION_ZERO)
    if execution_count == 2:
        if any(item is not None for item in private_tuple):
            raise SelectorOutputError("non-single selector output has private identity")
        return SelectorDetails(MULTIPLE_ROW_MATCH, None, EXECUTION_MULTIPLE)
    if any(item is None for item in private_tuple) or filename == "":
        for item, label in [
            (schedule_id, "schedule id"),
            (execution_id, "execution id"),
            (execution_created_at, "execution timestamp"),
        ]:
            if item is not None:
                if label in {"schedule id", "execution id"}:
                    _validate_selector_id(item, label)
                else:
                    _validate_execution_created_at(item)
        if filename not in {None, ""}:
            _validate_filename(filename)
        return SelectorDetails(PRIVATE_LOCATOR_MISSING, None, PRIVATE_LOCATOR_MISSING)
    schedule_id = _validate_selector_id(schedule_id, "schedule id")
    execution_id = _validate_selector_id(execution_id, "execution id")
    execution_created_at = _validate_execution_created_at(execution_created_at)
    filename = _validate_filename(filename)
    return SelectorDetails(
        EXACTLY_ONE,
        filename,
        EXACTLY_ONE,
        schedule_id,
        execution_id,
        execution_created_at,
    )


def classify_selector_object(value: Any) -> tuple[str, str | None]:
    details = classify_selector_details(value)
    return details.classification, details.filename


def parse_selector_output(output: bytes) -> SelectorDetails:
    if not isinstance(output, bytes) or len(output) > OMAX or not output.endswith(b"\n"):
        raise SelectorOutputError("selector output framing is invalid")
    try:
        value = parse_strict_json(output[:-1])
    except ProtocolError as error:
        raise SelectorOutputError("selector output JSON is invalid") from error
    return classify_selector_details(value)


def failure_classification(query_started: bool) -> str:
    return QUERY_FAILED if query_started else QUERY_NOT_EXECUTED


@dataclass
class OperationCounts:
    docker_execs: int = 0
    shell_wrappers: int = 0
    psql_sessions: int = 0
    logical_selects: int = 0
    phase1_writes: int = 0
    phase2_writes: int = 0
    retries: int = 0
    fallbacks: int = 0


@dataclass
class OperationSuccess:
    classification: str
    filename: str | None
    counts: OperationCounts
    schedule_id: int | None = None
    execution_id: int | None = None
    execution_created_at: str | None = None


@dataclass
class OperationFailure:
    query_started: bool
    counts: OperationCounts

    @property
    def classification(self) -> str:
        return failure_classification(self.query_started)


def open_docker_process() -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        ["docker", "exec", "-i", "coolify-db", "/bin/sh", "-c", SHELL_WRAPPER],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )


def _reader_worker(channel: str, stream: BinaryIO, events: queue.Queue[tuple[str, Any]]) -> None:
    try:
        while True:
            chunk = stream.read(4096)
            if not chunk:
                events.put((f"{channel}:eof", None))
                return
            events.put((channel, bytes(chunk)))
    except Exception as error:
        events.put((f"{channel}:error", error))


def _writer_worker(kind: str, stream: BinaryIO, payload: bytes, events: queue.Queue[tuple[str, Any]]) -> None:
    events.put((kind, write_once(stream, payload)))


def _cleanup_process(process: Any, stdin: BinaryIO | None) -> None:
    """Close local resources only; this is never database-terminality proof."""

    streams = [stdin, getattr(process, "stdout", None), getattr(process, "stderr", None)]
    seen_streams: set[int] = set()
    for stream in streams:
        if stream is None or id(stream) in seen_streams:
            continue
        seen_streams.add(id(stream))
        try:
            stream.close()
        except Exception:
            pass
    try:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=0.2)
            except Exception:
                process.kill()
                process.wait(timeout=0.2)
    except Exception:
        pass


def _capture_guard_failure(captures: CaptureSet, admitted: bool) -> tuple[bool, bool]:
    if admitted:
        post_failure = captures.stdout.overflow or captures.stderr.overflow or captures.combined_overflow
        return False, post_failure
    pre_failure = (
        len(captures.stdout.data) > PRE_OMAX
        or len(captures.stderr.data) > PRE_EMAX
        or captures.stdout.overflow
        or captures.stderr.overflow
        or captures.combined_overflow
    )
    return bool(captures.stderr.data), pre_failure


def _poll_process(process: Any) -> tuple[Any, bool]:
    try:
        return process.poll(), False
    except Exception:
        return None, True


def _wait_through_database_bound(clock: Callable[[], float], deadline: float, events: queue.Queue[tuple[str, Any]]) -> None:
    """Wait through the PostgreSQL-derived bound without treating client exit as proof."""

    while clock() < deadline:
        try:
            events.get(timeout=min(0.05, max(0.0, deadline - clock())))
        except queue.Empty:
            pass


def execute_operation(
    barrier_utc: str,
    *,
    process_factory: Callable[[], Any] = open_docker_process,
    clock: Callable[[], float] = time.monotonic,
    event_queue_factory: Callable[[], queue.Queue[tuple[str, Any]]] | None = None,
) -> OperationSuccess | OperationFailure:
    counts = OperationCounts()
    try:
        barrier_utc = validate_barrier_utc(barrier_utc)
    except AdapterError:
        return OperationFailure(False, counts)
    t0 = clock()
    readiness_deadline = t0 + R
    process: Any | None = None
    stdin: BinaryIO | None = None
    query_started = False
    try:
        try:
            process = process_factory()
            counts.docker_execs = 1
            counts.shell_wrappers = 1
            counts.psql_sessions = 1
            stdin = process.stdin
            if process.stdout is None or process.stderr is None or stdin is None:
                raise AdapterError("process pipes are unavailable")
        except Exception:
            return OperationFailure(False, counts)

        events = (
            event_queue_factory()
            if event_queue_factory is not None
            else queue.Queue(maxsize=EVENT_QUEUE_MAX)
        )
        threading.Thread(target=_reader_worker, args=("stdout", process.stdout, events), daemon=True).start()
        threading.Thread(target=_reader_worker, args=("stderr", process.stderr, events), daemon=True).start()
        counts.phase1_writes = 1
        threading.Thread(target=_writer_worker, args=("phase1", stdin, READINESS_COMMAND, events), daemon=True).start()

        captures = CaptureSet()
        admission = AdmissionState()
        writer_status = WRITER_PENDING
        pre_stderr_failed = False
        pre_overflow_failed = False
        process_failed = False
        accepted = False
        stdout_eof = False
        stderr_eof = False

        while not accepted:
            now = clock()
            if now >= readiness_deadline:
                decision = admission_step(
                    admission,
                    captures.stdout.snapshot(),
                    writer_status,
                    now,
                    readiness_deadline,
                    stderr_failed=pre_stderr_failed,
                    overflow_failed=pre_overflow_failed,
                    process_failed=process_failed,
                )
                if decision != ADMISSION_ACCEPT:
                    return OperationFailure(False, counts)
            remaining = max(0.0, readiness_deadline - now)
            try:
                event, value = events.get(timeout=min(remaining, 0.05))
            except queue.Empty:
                continue
            if event == "stdout":
                captures.append("stdout", value)
            elif event == "stderr":
                captures.append("stderr", value)
            elif event == "phase1":
                writer_status = value
            elif event == "stdout:eof":
                stdout_eof = True
                process_failed = True
            elif event == "stderr:eof":
                stderr_eof = True
            elif event in {"stdout:error", "stderr:error"}:
                process_failed = True
            try:
                if process.poll() is not None:
                    process_failed = True
            except Exception:
                process_failed = True
            pre_stderr_failed, pre_overflow_failed = _capture_guard_failure(captures, False)
            decision = admission_step(
                admission,
                captures.stdout.snapshot(),
                writer_status,
                clock(),
                readiness_deadline,
                stderr_failed=pre_stderr_failed,
                overflow_failed=pre_overflow_failed,
                process_failed=process_failed,
            )
            if decision == ADMISSION_ACCEPT:
                accepted = True
            elif decision in {ADMISSION_FAIL, ADMISSION_CLOSED}:
                return OperationFailure(False, counts)

        query = build_locator_query(barrier_utc)
        payload = phase2_payload(query)
        query_started = True
        counts.logical_selects = 1
        counts.phase2_writes = 1
        phase2_status = write_once(stdin, payload)
        terminal_deadline = t0 + T_HOST
        post_failure = phase2_status != WRITER_OK
        while clock() < terminal_deadline:
            returncode, poll_failed = _poll_process(process)
            post_failure = post_failure or poll_failed
            if returncode is not None and (type(returncode) is not int or returncode != 0):
                post_failure = True
            if stdout_eof and stderr_eof and type(returncode) is int and returncode == 0 and not post_failure:
                break
            try:
                event, value = events.get(timeout=min(0.05, max(0.0, terminal_deadline - clock())))
            except queue.Empty:
                continue
            if event == "stdout":
                captures.append("stdout", value)
            elif event == "stderr":
                captures.append("stderr", value)
            elif event == "stdout:eof":
                stdout_eof = True
            elif event == "stderr:eof":
                stderr_eof = True
            elif event in {"stdout:error", "stderr:error"}:
                post_failure = True
            if captures.stderr.data or captures.stdout.overflow or captures.stderr.overflow or captures.combined_overflow:
                post_failure = True
            returncode, poll_failed = _poll_process(process)
            post_failure = post_failure or poll_failed
            if returncode is not None and (type(returncode) is not int or returncode != 0):
                post_failure = True
        if clock() >= terminal_deadline:
            post_failure = True
        returncode, poll_failed = _poll_process(process)
        if poll_failed or type(returncode) is not int or returncode != 0:
            post_failure = True
        if post_failure:
            return OperationFailure(query_started, counts)
        remainder = extract_after_ready_marker(captures.stdout.snapshot())
        try:
            details = parse_selector_output(remainder)
        except (AdapterError, OSError, ValueError, TypeError):
            _wait_through_database_bound(clock, terminal_deadline, events)
            return OperationFailure(query_started, counts)
        return OperationSuccess(
            details.classification,
            details.filename,
            counts,
            details.schedule_id,
            details.execution_id,
            details.execution_created_at,
        )
    except (AdapterError, OSError, ValueError, TypeError):
        return OperationFailure(query_started, counts)
    finally:
        if process is not None:
            _cleanup_process(process, stdin)


def handle_protocol(
    input_stream: BinaryIO,
    output_stream: BinaryIO,
    *,
    operation: Callable[[str], OperationSuccess | OperationFailure] = execute_operation,
) -> None:
    """Serve exactly one public request and emit STARTED plus one terminal frame."""

    try:
        request = read_request_frame(input_stream, R)
    except Exception:
        write_public_frame(output_stream, failed_frame(QUERY_NOT_EXECUTED))
        return
    write_public_frame(output_stream, started_frame())
    outcome = operation(request["barrier_utc"])
    if isinstance(outcome, OperationSuccess):
        try:
            terminal_frame = result_frame(
                outcome.classification,
                outcome.filename,
                outcome.schedule_id,
                outcome.execution_id,
                outcome.execution_created_at,
            )
        except (AdapterError, OSError, TypeError, ValueError):
            terminal_frame = failed_frame(QUERY_FAILED)
    else:
        terminal_frame = failed_frame(outcome.classification)
    write_public_frame(output_stream, terminal_frame)


def main() -> None:
    handle_protocol(sys.stdin.buffer, sys.stdout.buffer)


if __name__ == "__main__":
    main()
