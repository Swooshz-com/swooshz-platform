import ast
import base64
import hashlib
import importlib.util
import io
import json
import pathlib
import queue
import socket
import sys
import threading
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE_PATH = ROOT / "scripts" / "platform-persisted-locator-adapter.py"
EXPECTED_ADAPTER_UTF8_BYTES = 35994
EXPECTED_ADAPTER_BASE64URL_LENGTH = 47992
EXPECTED_ADAPTER_SHA256 = "17925f1364565edbb39fa0f776e25d6f0410d8408d9bdce214143edf1d6f34d5"
EXPECTED_ADAPTER_LINES = 1019
SPEC = importlib.util.spec_from_file_location("platform_persisted_locator_adapter", SOURCE_PATH)
ADAPTER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = ADAPTER
SPEC.loader.exec_module(ADAPTER)


BARRIER_UTC = "2026-08-31T00:00:00.000000Z"
SCHEDULE_ID = 17
EXECUTION_ID = 23
EXECUTION_CREATED_AT = "2026-08-31T00:00:01.123456Z"
FILENAME = "backup.tar"
EXACT_SELECTOR_VALUE = {
    "schedule_count": 1,
    "schedule_id": SCHEDULE_ID,
    "execution_count": 1,
    "execution_id": EXECUTION_ID,
    "execution_created_at": EXECUTION_CREATED_AT,
    "filename": FILENAME,
}
EXACT_SELECTOR_OUTPUT = (
    b'{"schedule_count":1,"schedule_id":17,"execution_count":1,'
    b'"execution_id":23,"execution_created_at":"2026-08-31T00:00:01.123456Z",'
    b'"filename":"backup.tar"}\n'
)


class FakeStream:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.writes = []
        self.flushes = 0

    def write(self, payload):
        self.writes.append(payload)
        if self.error is not None:
            raise self.error
        if self.result is None:
            return len(payload)
        return self.result

    def flush(self):
        self.flushes += 1
        if self.error is not None:
            raise self.error


class ReadSignalStream:
    def __init__(self, stream, first_read):
        self.stream = stream
        self.first_read = first_read
        self.read_count = 0

    def fileno(self):
        return self.stream.fileno()

    def read1(self, length):
        chunk = self.stream.read1(length)
        self.read_count += 1
        if self.read_count == 1:
            self.first_read.set()
        return chunk

    def close(self):
        self.stream.close()


class PayloadGateStream:
    def __init__(self, stream, header_read, payload_read, allow_probe):
        self.stream = stream
        self.header_read = header_read
        self.payload_read = payload_read
        self.allow_probe = allow_probe
        self.read_count = 0

    def fileno(self):
        return self.stream.fileno()

    def read1(self, length):
        chunk = self.stream.read1(length)
        self.read_count += 1
        if self.read_count == 1:
            self.header_read.set()
        if self.read_count == 2:
            self.payload_read.set()
            if not self.allow_probe.wait(1):
                raise OSError("trailing-input probe was not released")
        return chunk

    def close(self):
        self.stream.close()


class PrefetchedFrameStream:
    def __init__(self, frame):
        self.frame = frame
        self.read_socket, self.write_socket = socket.socketpair()
        self.write_socket.sendall(b"r")
        self.read_count = 0

    def fileno(self):
        return self.read_socket.fileno()

    def read1(self, _length):
        self.read_count += 1
        if self.read_count != 1:
            raise AssertionError("production reader attempted a descriptor read for buffered payload")
        self.read_socket.recv(1)
        return self.frame

    def close(self):
        self.read_socket.close()
        self.write_socket.close()


class FastClock:
    def __init__(self, step=0.05):
        self.step = step
        self.value = 0.0
        self.calls = 0

    def __call__(self):
        current = self.value
        self.value += self.step
        self.calls += 1
        return current


class ProcessEventQueue:
    def __init__(self, process):
        self.process = process
        self._queue = queue.Queue(maxsize=ADAPTER.EVENT_QUEUE_MAX)

    def put(self, item):
        self.process.put_events.append(item)
        event, value = item
        if event == "stdout" and value == ADAPTER.READY_MARKER:
            self.process.marker_enqueued.set()
        elif event == "phase1":
            self.process.writer_enqueued.set()
        self._queue.put(item)

    def get(self, block=True, timeout=None):
        if not block:
            item = self._queue.get_nowait()
        else:
            wait = 0.001 if timeout is None else min(max(timeout, 0.0), 0.001)
            if wait == 0:
                item = self._queue.get_nowait()
            else:
                item = self._queue.get(timeout=wait)
        self.process.get_events.append(item)
        event, _ = item
        if event == "stderr:eof":
            self.process.stderr_eof_observed.set()
        elif event == "stdout:eof":
            self.process.stdout_eof_observed.set()
        if self.process.stderr_eof_observed.is_set() and self.process.stdout_eof_observed.is_set():
            self.process.both_eof_observed.set()
        return item


class ScriptedInput:
    def __init__(
        self,
        process,
        *,
        phase1_status=ADAPTER.WRITER_OK,
        phase2_status=ADAPTER.WRITER_OK,
        phase1_release=None,
        phase1_flush_error=False,
        phase2_flush_error=False,
    ):
        self.process = process
        self.phase1_status = phase1_status
        self.phase2_status = phase2_status
        self.phase1_release = phase1_release
        self.phase1_flush_error = phase1_flush_error
        self.phase2_flush_error = phase2_flush_error
        self.writes = []
        self.flushes = 0
        self.last_kind = None
        self.closed = False
        self.phase1_started = threading.Event()

    def write(self, payload):
        self.writes.append(payload)
        if payload == ADAPTER.READINESS_COMMAND:
            self.last_kind = "phase1"
            self.phase1_started.set()
            if self.phase1_release is not None:
                self.phase1_release.wait()
            if self.phase1_status == ADAPTER.WRITER_ERROR:
                raise OSError("phase-1 write failure")
            if self.phase1_status == ADAPTER.WRITER_SHORT:
                return 1
            return len(payload)

        self.last_kind = "phase2"
        self.process.phase2_written.set()
        self.process.phase2_precondition = (
            self.process.marker_enqueued.is_set() and self.process.writer_enqueued.is_set()
        )
        self.process.phase2_payloads.append(payload)
        if self.phase2_status == ADAPTER.WRITER_ERROR:
            raise OSError("phase-2 write failure")
        if self.phase2_status == ADAPTER.WRITER_SHORT:
            return 1
        return len(payload)

    def flush(self):
        self.flushes += 1
        if self.last_kind == "phase1" and self.phase1_flush_error:
            raise OSError("phase-1 flush failure")
        if self.last_kind == "phase2" and self.phase2_flush_error:
            raise OSError("phase-2 flush failure")

    def close(self):
        self.closed = True


class ScriptedReadStream:
    def __init__(self, process, channel):
        self.process = process
        self.channel = channel
        self.read_count = 0
        self.closed = False

    def read(self, _length):
        if self.channel == "stderr":
            return b""
        if self.read_count == 0:
            self.read_count += 1
            if self.process.marker_after_writer:
                if not self.process.writer_enqueued.wait(2):
                    raise OSError("writer acknowledgement did not arrive")
            return ADAPTER.READY_MARKER
        if self.read_count == 1:
            self.read_count += 1
            while not self.process.phase2_written.is_set() and not self.process.close_event.is_set():
                self.process.phase2_written.wait(0.01)
            if self.process.close_event.is_set() and not self.process.phase2_written.is_set():
                return b""
            return self.process.selector_output or b""
        if self.process.hold_after_output:
            self.process.close_event.wait()
        return b""

    def close(self):
        self.closed = True
        self.process.close_event.set()


class ScriptedProcess:
    def __init__(
        self,
        *,
        marker_after_writer=False,
        phase1_status=ADAPTER.WRITER_OK,
        phase2_status=ADAPTER.WRITER_OK,
        phase1_release=None,
        phase1_flush_error=False,
        phase2_flush_error=False,
        selector_output=EXACT_SELECTOR_OUTPUT,
        hold_after_output=False,
        post_poll_error=False,
        nonzero_after_eof=False,
    ):
        self.marker_after_writer = marker_after_writer
        self.selector_output = selector_output
        self.hold_after_output = hold_after_output
        self.post_poll_error = post_poll_error
        self.nonzero_after_eof = nonzero_after_eof
        self.marker_enqueued = threading.Event()
        self.writer_enqueued = threading.Event()
        self.phase2_written = threading.Event()
        self.close_event = threading.Event()
        self.stderr_eof_observed = threading.Event()
        self.stdout_eof_observed = threading.Event()
        self.both_eof_observed = threading.Event()
        self.put_events = []
        self.get_events = []
        self.phase2_payloads = []
        self.phase2_precondition = False
        self.poll_count = 0
        self.post_eof_none_returned = False
        self.post_eof_observations = []
        self.factory_calls = 0
        self.terminated = False
        self.killed = False
        self.stdin = ScriptedInput(
            self,
            phase1_status=phase1_status,
            phase2_status=phase2_status,
            phase1_release=phase1_release,
            phase1_flush_error=phase1_flush_error,
            phase2_flush_error=phase2_flush_error,
        )
        self.stdout = ScriptedReadStream(self, "stdout")
        self.stderr = ScriptedReadStream(self, "stderr")

    def event_queue(self):
        return ProcessEventQueue(self)

    def poll(self):
        self.poll_count += 1
        if not self.phase2_written.is_set():
            return None
        if self.post_poll_error:
            raise OSError("poll failure")
        if not self.both_eof_observed.is_set():
            return None
        if self.nonzero_after_eof:
            if not self.post_eof_none_returned:
                self.post_eof_none_returned = True
                self.post_eof_observations.append(None)
                return None
            self.post_eof_observations.append(23)
            return 23
        if self.hold_after_output:
            return None
        return 0

    def terminate(self):
        self.terminated = True
        self.close_event.set()

    def kill(self):
        self.killed = True
        self.close_event.set()

    def wait(self, timeout=None):
        return 0


class AdapterContractTests(unittest.TestCase):
    def _run_execute(self, process, clock=None):
        clock = clock or FastClock()
        result = []
        errors = []

        def process_factory():
            process.factory_calls += 1
            return process

        def target():
            try:
                result.append(
                    ADAPTER.execute_operation(
                        BARRIER_UTC,
                        process_factory=process_factory,
                        clock=clock,
                        event_queue_factory=process.event_queue,
                    )
                )
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        thread.join(3)
        if thread.is_alive():
            process.close_event.set()
            if process.stdin.phase1_release is not None:
                process.stdin.phase1_release.set()
            thread.join(1)
        self.assertFalse(thread.is_alive(), "production operation did not reach a bounded outcome")
        if errors:
            self.fail(f"production operation raised unexpectedly: {errors[0]!r}")
        self.assertEqual(len(result), 1)
        return result[0], clock

    @staticmethod
    def _request_frame(payload=None):
        if payload is None:
            payload = b'{"type":"REQUEST","version":3,"barrier_utc":"2026-08-31T00:00:00.000000Z"}'
        return ADAPTER.Header.pack(ADAPTER.Magic, 1, ADAPTER.REQUEST, 0, len(payload)) + payload

    @staticmethod
    def _decode_public_frames(data):
        frames = []
        offset = 0
        while offset < len(data):
            if len(data) - offset < ADAPTER.Header.size:
                raise AssertionError("public frame header is incomplete")
            magic, version, message_type, flags, payload_length = ADAPTER.Header.unpack(
                data[offset : offset + ADAPTER.Header.size]
            )
            if magic != ADAPTER.Magic or version != ADAPTER.Version or flags != 0:
                raise AssertionError("public frame header is invalid")
            payload_start = offset + ADAPTER.Header.size
            payload_end = payload_start + payload_length
            if payload_end > len(data):
                raise AssertionError("public frame payload is incomplete")
            frames.append((message_type, json.loads(data[payload_start:payload_end])))
            offset = payload_end
        return frames

    def _handle_protocol(self, operation, *, frame=None, suffix=b"", half_close=False):
        client, adapter_socket = socket.socketpair()
        input_stream = None
        output_stream = io.BytesIO()
        thread = None
        try:
            input_stream = adapter_socket.makefile("rb")
            errors = []

            def target():
                try:
                    ADAPTER.handle_protocol(input_stream, output_stream, operation=operation)
                except BaseException as error:
                    errors.append(error)

            thread = threading.Thread(target=target, daemon=True)
            thread.start()
            client.sendall((self._request_frame() if frame is None else frame) + suffix)
            if half_close:
                client.shutdown(socket.SHUT_WR)
            thread.join(1)
            if thread.is_alive():
                try:
                    adapter_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                thread.join(1)
                self.fail("production protocol handler did not complete promptly")
            if errors:
                self.fail(f"production protocol handler raised unexpectedly: {errors[0]!r}")
            raw = output_stream.getvalue()
            return self._decode_public_frames(raw), raw
        finally:
            if input_stream is not None:
                input_stream.close()
            adapter_socket.close()
            client.close()

    def _assert_single_operation_counts(self, process, outcome):
        self.assertIsInstance(outcome, ADAPTER.OperationSuccess)
        counts = outcome.counts
        self.assertEqual(
            (
                counts.docker_execs,
                counts.shell_wrappers,
                counts.psql_sessions,
                counts.logical_selects,
                counts.phase1_writes,
                counts.phase2_writes,
                counts.retries,
                counts.fallbacks,
            ),
            (1, 1, 1, 1, 1, 1, 0, 0),
        )
        self.assertEqual(process.factory_calls, 1)
        self.assertEqual(len(process.stdin.writes), 2)
        self.assertEqual(len(process.phase2_payloads), 1)
        self.assertTrue(process.phase2_precondition)

    def test_python_ast_and_compile_without_main_call(self):
        source = SOURCE_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(SOURCE_PATH))
        compile(tree, str(SOURCE_PATH), "exec")
        top_level_main_calls = [
            node for node in tree.body
            if isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id in {"main", "run"}
        ]
        self.assertEqual(top_level_main_calls, [])

    def test_constants_and_timer_equation(self):
        self.assertEqual(ADAPTER.Version, 1)
        self.assertEqual(ADAPTER.REQUEST_SCHEMA_VERSION, 3)
        self.assertEqual((ADAPTER.R, ADAPTER.I, ADAPTER.S, ADAPTER.MARGIN), (5, 2, 7, 1))
        self.assertEqual(ADAPTER.PGCONNECT_TIMEOUT, 2)
        self.assertEqual(ADAPTER.T_HOST, ADAPTER.R + 2 * ADAPTER.I + ADAPTER.S + ADAPTER.MARGIN)
        self.assertEqual(ADAPTER.T_HOST, 17)
        self.assertEqual(
            ADAPTER.PGOPTIONS_VALUE,
            "-c statement_timeout=7000 -c idle_session_timeout=2000 -c TimeZone=UTC",
        )

    def test_postgres_session_timezone_is_pinned_and_pgtz_is_unset(self):
        expected_options = "-c statement_timeout=7000 -c idle_session_timeout=2000 -c TimeZone=UTC"
        wrapper = ADAPTER.SHELL_WRAPPER
        psql_index = wrapper.index("exec /usr/local/bin/psql")
        pgtz_index = wrapper.index("PGTZ")
        export = f"export PGOPTIONS='{expected_options}'"
        self.assertEqual(ADAPTER.PGOPTIONS_VALUE, expected_options)
        self.assertEqual(wrapper.count(export), 1)
        self.assertLess(wrapper.index(export), psql_index)
        self.assertLess(pgtz_index, psql_index)
        self.assertEqual(wrapper.count("PGTZ"), 1)
        self.assertNotIn("PGTZ=", wrapper)
        self.assertNotIn("export PGTZ", wrapper)

        query = ADAPTER.build_locator_query(BARRIER_UTC)
        self.assertEqual(query.count("e.created_at > TIMESTAMPTZ"), 1)
        self.assertEqual(
            query.count("to_char(e.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')"),
            1,
        )
        self.assertNotIn("SET TIME ZONE", query.upper())
        self.assertNotIn("SET TIMEZONE", query.upper())
        self.assertEqual(query.count("SELECT json_build_object("), 1)

    def test_splq_frame_and_exact_request(self):
        payload = b'{"type":"REQUEST","version":3,"barrier_utc":"2026-08-31T00:00:00.000000Z"}'
        frame = ADAPTER.Header.pack(ADAPTER.Magic, 1, ADAPTER.REQUEST, 0, len(payload)) + payload
        self.assertEqual(
            ADAPTER.decode_request_frame(frame),
            {"type": "REQUEST", "version": 3, "barrier_utc": BARRIER_UTC},
        )
        with self.assertRaises(ADAPTER.ProtocolError):
            ADAPTER.decode_request_frame(frame + b"x")
        with self.assertRaises(ADAPTER.ProtocolError):
            ADAPTER.decode_request_frame(ADAPTER.Header.pack(b"BAD!", 1, 1, 0, len(payload)) + payload)
        with self.assertRaises(ADAPTER.ProtocolError):
            ADAPTER.decode_request_frame(ADAPTER.Header.pack(ADAPTER.Magic, 1, 1, 1, len(payload)) + payload)
        oversized = ADAPTER.Header.pack(ADAPTER.Magic, 1, 1, 0, ADAPTER.REQMAX + 1)
        with self.assertRaises(ADAPTER.ProtocolError):
            ADAPTER.decode_request_frame(oversized + b"x" * (ADAPTER.REQMAX + 1))

    def test_open_duplex_valid_request_runs_operation_once(self):
        operation_calls = []

        def operation(barrier_utc):
            operation_calls.append(barrier_utc)
            return ADAPTER.OperationSuccess(ADAPTER.ZERO_ROW_MATCH, None, ADAPTER.OperationCounts())

        frames, _ = self._handle_protocol(operation)
        self.assertEqual(operation_calls, [BARRIER_UTC])
        self.assertEqual([message_type for message_type, _ in frames], [ADAPTER.STARTED, ADAPTER.RESULT])
        self.assertEqual(sum(message_type in {ADAPTER.RESULT, ADAPTER.FAILED} for message_type, _ in frames), 1)

    def test_open_duplex_trailing_byte_is_rejected_before_operation(self):
        operation_calls = []

        frames, _ = self._handle_protocol(lambda: operation_calls.append(True), suffix=b"x")
        self.assertEqual(operation_calls, [])
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0], (ADAPTER.FAILED, {"type": "FAILED", "version": 1, "classification": ADAPTER.QUERY_NOT_EXECUTED}))

    def test_half_closed_trailing_byte_is_rejected_before_operation(self):
        operation_calls = []

        frames, _ = self._handle_protocol(
            lambda: operation_calls.append(True),
            suffix=b"x",
            half_close=True,
        )
        self.assertEqual(operation_calls, [])
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0], (ADAPTER.FAILED, {"type": "FAILED", "version": 1, "classification": ADAPTER.QUERY_NOT_EXECUTED}))

    def test_immediately_readable_trailing_byte_is_rejected_before_operation(self):
        client, adapter_socket = socket.socketpair()
        input_stream = None
        thread = None
        errors = []
        output_stream = io.BytesIO()
        header_read = threading.Event()
        payload_read = threading.Event()
        allow_probe = threading.Event()
        operation_calls = []
        frame = self._request_frame()
        try:
            input_stream = PayloadGateStream(adapter_socket.makefile("rb"), header_read, payload_read, allow_probe)

            def target():
                try:
                    ADAPTER.handle_protocol(
                        input_stream,
                        output_stream,
                        operation=lambda: operation_calls.append(True),
                    )
                except BaseException as error:
                    errors.append(error)

            thread = threading.Thread(target=target, daemon=True)
            thread.start()
            client.sendall(frame[: ADAPTER.Header.size])
            self.assertTrue(header_read.wait(1), "production reader did not consume the split header")
            client.sendall(frame[ADAPTER.Header.size :])
            self.assertTrue(payload_read.wait(1), "production reader did not finish the payload read")
            client.sendall(b"x")
            allow_probe.set()
            thread.join(1)
            if thread.is_alive():
                self.fail("immediate-trailing production protocol handler did not complete promptly")
            if errors:
                self.fail(f"immediate-trailing production protocol handler raised unexpectedly: {errors[0]!r}")
            self.assertEqual(operation_calls, [])
            frames = self._decode_public_frames(output_stream.getvalue())
            self.assertEqual(
                frames,
                [(ADAPTER.FAILED, {"type": "FAILED", "version": 1, "classification": ADAPTER.QUERY_NOT_EXECUTED})],
            )
        finally:
            allow_probe.set()
            if thread is not None and thread.is_alive():
                try:
                    adapter_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                thread.join(1)
            if input_stream is not None:
                input_stream.close()
            adapter_socket.close()
            client.close()

    def test_malformed_request_is_rejected_before_operation(self):
        payload = b'{"type":"REQUEST","version":2}'
        invalid_frame = ADAPTER.Header.pack(b"BAD!", 1, ADAPTER.REQUEST, 0, len(payload)) + payload
        operation_calls = []

        frames, _ = self._handle_protocol(
            lambda: operation_calls.append(True),
            frame=invalid_frame,
        )
        self.assertEqual(operation_calls, [])
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0], (ADAPTER.FAILED, {"type": "FAILED", "version": 1, "classification": ADAPTER.QUERY_NOT_EXECUTED}))

    def test_split_delivery_accepts_header_and_payload_without_eof(self):
        client, adapter_socket = socket.socketpair()
        input_stream = None
        thread = None
        errors = []
        output_stream = io.BytesIO()
        first_read = threading.Event()
        operation_calls = []
        frame = self._request_frame()
        try:
            input_stream = ReadSignalStream(adapter_socket.makefile("rb"), first_read)

            def target():
                try:
                    ADAPTER.handle_protocol(
                        input_stream,
                        output_stream,
                        operation=lambda barrier_utc: (
                            operation_calls.append(True)
                            or ADAPTER.OperationSuccess(ADAPTER.ZERO_ROW_MATCH, None, ADAPTER.OperationCounts())
                        ),
                    )
                except BaseException as error:
                    errors.append(error)

            thread = threading.Thread(target=target, daemon=True)
            thread.start()
            client.sendall(frame[: ADAPTER.Header.size])
            self.assertTrue(first_read.wait(1), "production reader did not consume the split header")
            client.sendall(frame[ADAPTER.Header.size :])
            thread.join(1)
            if thread.is_alive():
                self.fail("split-delivery production protocol handler did not complete promptly")
            if errors:
                self.fail(f"split-delivery production protocol handler raised unexpectedly: {errors[0]!r}")
            self.assertEqual(operation_calls, [True])
            frames = self._decode_public_frames(output_stream.getvalue())
            self.assertEqual([message_type for message_type, _ in frames], [ADAPTER.STARTED, ADAPTER.RESULT])
        finally:
            if thread is not None and thread.is_alive():
                try:
                    adapter_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                thread.join(1)
            if input_stream is not None:
                input_stream.close()
            adapter_socket.close()
            client.close()

    def test_buffered_prefetch_is_consumed_without_descriptor_readiness_wait(self):
        frame = self._request_frame()
        stream = PrefetchedFrameStream(frame)
        try:
            self.assertEqual(
                ADAPTER.read_request_frame(stream, timeout=1),
                {"type": "REQUEST", "version": 3, "barrier_utc": BARRIER_UTC},
            )
            self.assertEqual(stream.read_count, 1)
        finally:
            stream.close()

    def test_terminal_protocol_frames(self):
        header = ADAPTER.Header.size
        started = ADAPTER.started_frame()
        self.assertEqual(started[:4], ADAPTER.Magic)
        self.assertEqual(json.loads(started[header:]), {"type": "STARTED", "version": 1})
        failed = ADAPTER.failed_frame(ADAPTER.QUERY_NOT_EXECUTED)
        self.assertEqual(json.loads(failed[header:]), {"type": "FAILED", "version": 1, "classification": "QUERY_NOT_EXECUTED"})
        with self.assertRaises(ADAPTER.ProtocolError):
            ADAPTER.failed_frame("PRIVATE_SQL")
        with self.assertRaises(ADAPTER.ProtocolError):
            ADAPTER.result_frame(ADAPTER.ZERO_ROW_MATCH, "must-not-leak")

    def test_request_json_adversaries(self):
        cases = [
            b'{"type":"REQUEST","version":2,"barrier_utc":"2026-08-31T00:00:00.000000Z"}',
            b'{"type":"REQUEST","version":3,"barrier_utc":"2026-08-31T00:00:00Z"}',
            b'{"type":"REQUEST","version":3,"barrier_utc":"2026-08-31T00:00:00.000000+00:00"}',
            b'{"type":"REQUEST","version":3,"barrier_utc":"2026-08-31T00:00:00.000000z"}',
            b'{"type":"REQUEST","version":3,"barrier_utc":" 2026-08-31T00:00:00.000000Z"}',
            b'{"type":"REQUEST","version":3,"barrier_utc":"2026-08-31T00:00:00.000000Z "}',
            b'{"type":"REQUEST","version":3,"barrier_utc":"2026-08-31T00:00:00.00000Z"}',
            b'{"type":"REQUEST","version":3,"barrier_utc":"2026-08-31T00:00:00.0000000Z"}',
            b'{"type":"REQUEST","version":3,"barrier_utc":"2026-02-29T00:00:00.000000Z"}',
            b'{"type":"REQUEST","version":3,"barrier_utc":"2026-13-01T00:00:00.000000Z"}',
            b'{"type":"REQUEST","version":3,"barrier_utc":"2026-08-31T24:00:00.000000Z"}',
            b'{"type":"REQUEST","version":3,"barrier_utc":7}',
            b'{"type":"REQUEST","version":3,"extra":0,"barrier_utc":"2026-08-31T00:00:00.000000Z"}',
            b'{"type":"REQUEST","version":3}',
            b'{"type":"REQUEST","version":3,"barrier_utc":"2026-08-31T00:00:00.000000Z","barrier_utc":"2026-08-31T00:00:01.000000Z"}',
            b'{"type":"REQUEST","type":"REQUEST","version":3,"barrier_utc":"2026-08-31T00:00:00.000000Z"}',
            b'{"type":"REQUEST","version":3,"version":3,"barrier_utc":"2026-08-31T00:00:00.000000Z"}',
            b'{"type":"REQUEST","version":3,"barrier_utc":NaN}',
            b'{"type":"REQUEST","version":3,"barrier_utc":Infinity}',
            b'{"type":"REQUEST","version":3,"barrier_utc":"2026-08-31T00:00:00.000000Z"} trailing',
            b' {"type":"REQUEST","version":3,"barrier_utc":"2026-08-31T00:00:00.000000Z"}',
            b'{"type":"REQUEST","version":3,"barrier_utc":"2026-08-31T00:00:00.000000Z"',
            b'{"type":"REQUEST","version":3,"barrier_utc":"2026-08-31T00:00:00.000000\xff"}',
            b'{"type":1,"version":3,"barrier_utc":"2026-08-31T00:00:00.000000Z"}',
            b'{"type":"REQUEST","version":"3","barrier_utc":"2026-08-31T00:00:00.000000Z"}',
            b'{"type":"REQUEST","version":1,"barrier_utc":"2026-08-31T00:00:00.000000Z"}',
        ]
        for payload in cases:
            with self.subTest(payload=payload), self.assertRaises(ADAPTER.ProtocolError):
                ADAPTER.parse_request_payload(payload)
            operation_calls = []
            frames, _ = self._handle_protocol(
                lambda barrier_utc: operation_calls.append(barrier_utc),
                frame=self._request_frame(payload),
            )
            self.assertEqual(operation_calls, [])
            self.assertEqual(
                frames,
                [
                    (
                        ADAPTER.FAILED,
                        {
                            "type": "FAILED",
                            "version": 1,
                            "classification": ADAPTER.QUERY_NOT_EXECUTED,
                        },
                    )
                ],
            )

    def test_old_selector_request_is_rejected_before_operation(self):
        operation_calls = []
        old_request = b'{"type":"REQUEST","version":2,"schedule_id":7}'
        frames, _ = self._handle_protocol(
            lambda: operation_calls.append(True),
            frame=self._request_frame(old_request),
        )
        self.assertEqual(operation_calls, [])
        self.assertEqual(
            frames,
            [(ADAPTER.FAILED, {"type": "FAILED", "version": 1, "classification": ADAPTER.QUERY_NOT_EXECUTED})],
        )

    def test_readiness_command_and_marker_are_distinct(self):
        self.assertEqual(ADAPTER.READINESS_COMMAND, b"\\echo SPLQ_PUBLIC_READY_V1\n")
        self.assertEqual(ADAPTER.READY_MARKER, b"SPLQ_PUBLIC_READY_V1\n")
        self.assertNotEqual(ADAPTER.READINESS_COMMAND, ADAPTER.READY_MARKER)
        self.assertEqual(ADAPTER.extract_after_ready_marker(ADAPTER.READY_MARKER + b"x"), b"x")
        with self.assertRaises(ADAPTER.SelectorOutputError):
            ADAPTER.extract_after_ready_marker(ADAPTER.READINESS_COMMAND)

    def test_writer_readiness_concurrency_fixtures(self):
        before = 4.0
        deadline = 5.0

        state = ADAPTER.AdmissionState()
        self.assertEqual(state.step(ADAPTER.READY_MARKER, ADAPTER.WRITER_PENDING, before, deadline), ADAPTER.ADMISSION_WAIT)
        self.assertEqual(state.step(ADAPTER.READY_MARKER, ADAPTER.WRITER_OK, before, deadline), ADAPTER.ADMISSION_ACCEPT)
        self.assertEqual(state.step(ADAPTER.READY_MARKER, ADAPTER.WRITER_OK, before, deadline), ADAPTER.ADMISSION_CLOSED)

        state = ADAPTER.AdmissionState()
        self.assertEqual(state.step(ADAPTER.READY_MARKER, ADAPTER.WRITER_SHORT, before, deadline), ADAPTER.ADMISSION_FAIL)
        state = ADAPTER.AdmissionState()
        self.assertEqual(state.step(ADAPTER.READY_MARKER, ADAPTER.WRITER_ERROR, before, deadline), ADAPTER.ADMISSION_FAIL)

        state = ADAPTER.AdmissionState()
        self.assertEqual(state.step(ADAPTER.READY_MARKER, ADAPTER.WRITER_PENDING, deadline, deadline), ADAPTER.ADMISSION_FAIL)
        self.assertEqual(state.step(ADAPTER.READY_MARKER, ADAPTER.WRITER_OK, before, deadline), ADAPTER.ADMISSION_CLOSED)

        state = ADAPTER.AdmissionState()
        self.assertEqual(state.step(b"", ADAPTER.WRITER_OK, before, deadline), ADAPTER.ADMISSION_WAIT)
        self.assertEqual(state.step(ADAPTER.READY_MARKER[:-1], ADAPTER.WRITER_OK, before, deadline), ADAPTER.ADMISSION_WAIT)
        self.assertEqual(state.step(ADAPTER.READY_MARKER, ADAPTER.WRITER_OK, before, deadline), ADAPTER.ADMISSION_ACCEPT)

        state = ADAPTER.AdmissionState()
        self.assertEqual(state.step(ADAPTER.READY_MARKER, ADAPTER.WRITER_OK, before, deadline), ADAPTER.ADMISSION_ACCEPT)

    def test_readiness_negative_fixtures(self):
        bad_stdout = [
            ADAPTER.READINESS_COMMAND,
            ADAPTER.READY_MARKER + ADAPTER.READY_MARKER,
            b"SPLQ_PUBLIC_READY_V1\r\n",
            b"x" + ADAPTER.READY_MARKER,
            ADAPTER.READY_MARKER + b"x",
        ]
        for value in bad_stdout:
            with self.subTest(value=value):
                state = ADAPTER.AdmissionState()
                self.assertEqual(state.step(value, ADAPTER.WRITER_OK, 4.0, 5.0), ADAPTER.ADMISSION_FAIL)
        state = ADAPTER.AdmissionState()
        self.assertEqual(
            state.step(ADAPTER.READY_MARKER, ADAPTER.WRITER_OK, 4.0, 5.0, stderr_failed=True),
            ADAPTER.ADMISSION_FAIL,
        )
        state = ADAPTER.AdmissionState()
        self.assertEqual(
            state.step(ADAPTER.READY_MARKER, ADAPTER.WRITER_OK, 4.0, 5.0, overflow_failed=True),
            ADAPTER.ADMISSION_FAIL,
        )
        state = ADAPTER.AdmissionState()
        self.assertEqual(state.step(ADAPTER.READY_MARKER, ADAPTER.WRITER_OK, 5.0, 5.0), ADAPTER.ADMISSION_FAIL)

    def test_no_private_bytes_before_readiness_conjunction(self):
        sink = FakeStream()
        state = ADAPTER.AdmissionState()
        decision = state.step(ADAPTER.READY_MARKER, ADAPTER.WRITER_PENDING, 4.0, 5.0)
        if decision == ADAPTER.ADMISSION_ACCEPT:
            ADAPTER.write_once(sink, b"private")
        self.assertEqual(sink.writes, [])
        decision = state.step(ADAPTER.READY_MARKER, ADAPTER.WRITER_OK, 4.0, 5.0)
        if decision == ADAPTER.ADMISSION_ACCEPT:
            ADAPTER.write_once(sink, b"private")
        self.assertEqual(sink.writes, [b"private"])

    def test_writer_short_and_error_are_single_attempts(self):
        short = FakeStream(result=1)
        self.assertEqual(ADAPTER.write_once(short, b"abcd"), ADAPTER.WRITER_SHORT)
        self.assertEqual(short.writes, [b"abcd"])
        self.assertEqual(short.flushes, 0)
        error = FakeStream(error=OSError("closed"))
        self.assertEqual(ADAPTER.write_once(error, b"abcd"), ADAPTER.WRITER_ERROR)
        self.assertEqual(error.writes, [b"abcd"])

    def test_private_selector_query_is_exact_and_bounded(self):
        query = ADAPTER.build_locator_query(BARRIER_UTC)
        self.assertLessEqual(len(query.encode("utf-8")), ADAPTER.QMAX)
        self.assertEqual(query.count("SELECT json_build_object("), 1)
        self.assertEqual(query.count("FROM scheduled_database_backups AS s"), 1)
        self.assertEqual(query.count("FROM scheduled_database_backup_executions AS e"), 1)
        self.assertEqual(query.count("JOIN schedule_candidates AS s"), 1)
        for fragment in [
            "s.id > 0",
            "s.enabled IS TRUE",
            "s.database_id = 0",
            "s.database_type = 'App\\Models\\StandalonePostgresql'",
            "s.frequency = '0 18 * * *'",
            "s.save_s3 IS TRUE",
            "s.disable_local_backup IS FALSE",
            "ON e.scheduled_database_backup_id = s.id",
            "e.database_name = 'coolify'",
            "e.status = 'success'",
            "e.created_at > TIMESTAMPTZ '2026-08-31T00:00:00.000000Z'",
            "e.size ~ '^[0-9]+$'",
            "e.size::numeric = 830082",
            "e.s3_uploaded IS TRUE",
            "e.filename IS NOT NULL",
            "e.local_storage_deleted IS FALSE",
            "'schedule_count', schedule_count",
            "'schedule_id', CASE",
            "'execution_count', execution_count",
            "'execution_id', CASE",
            "'execution_created_at', CASE",
            "CASE WHEN count(*) > 1 THEN 2 ELSE count(*) END AS schedule_count",
            "CASE WHEN count(*) > 1 THEN 2 ELSE count(*) END AS execution_count",
            "to_char(e.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS execution_created_at",
        ]:
            self.assertIn(fragment, query)
        self.assertEqual(query.count("e.created_at > TIMESTAMPTZ"), 1)
        self.assertNotIn("2026-08-27T18:00:03Z", query)
        self.assertNotIn("2026-08-27T18:00:04Z", query)
        self.assertNotIn("ORDER BY", query.upper())
        self.assertNotIn("LIMIT", query.upper())
        self.assertEqual(ADAPTER.phase2_payload(query), query.encode() + b"\n\\q\n")

    def test_invalid_barrier_is_rejected_before_query_construction(self):
        for barrier in [
            "2026-08-31T00:00:00Z",
            "2026-08-31T00:00:00.000000+00:00",
            "2026-02-29T00:00:00.000000Z",
            None,
            7,
        ]:
            with self.subTest(barrier=barrier), self.assertRaises(ADAPTER.QueryConstructionError):
                ADAPTER.build_locator_query(barrier)

    def test_selector_cardinality_privacy_and_bounds(self):
        matrix = {
            (0, 0): (ADAPTER.ZERO_ROW_MATCH, ADAPTER.SCHEDULE_ZERO),
            (0, 1): (ADAPTER.ZERO_ROW_MATCH, ADAPTER.SCHEDULE_ZERO),
            (0, 2): (ADAPTER.ZERO_ROW_MATCH, ADAPTER.SCHEDULE_ZERO),
            (1, 0): (ADAPTER.ZERO_ROW_MATCH, ADAPTER.EXECUTION_ZERO),
            (1, 1): (ADAPTER.EXACTLY_ONE, ADAPTER.EXACTLY_ONE),
            (1, 2): (ADAPTER.MULTIPLE_ROW_MATCH, ADAPTER.EXECUTION_MULTIPLE),
            (2, 0): (ADAPTER.MULTIPLE_ROW_MATCH, ADAPTER.SCHEDULE_MULTIPLE),
            (2, 1): (ADAPTER.MULTIPLE_ROW_MATCH, ADAPTER.SCHEDULE_MULTIPLE),
            (2, 2): (ADAPTER.MULTIPLE_ROW_MATCH, ADAPTER.SCHEDULE_MULTIPLE),
        }
        for (schedule_count, execution_count), (classification, cause) in matrix.items():
            with self.subTest(schedule_count=schedule_count, execution_count=execution_count):
                private = EXACT_SELECTOR_VALUE if (schedule_count, execution_count) == (1, 1) else {
                    "schedule_id": None,
                    "execution_id": None,
                    "execution_created_at": None,
                    "filename": None,
                }
                value = {
                    "schedule_count": schedule_count,
                    "schedule_id": private["schedule_id"],
                    "execution_count": execution_count,
                    "execution_id": private["execution_id"],
                    "execution_created_at": private["execution_created_at"],
                    "filename": private["filename"],
                }
                details = ADAPTER.classify_selector_details(value)
                expected_private = private if classification == ADAPTER.EXACTLY_ONE else {
                    "schedule_id": None,
                    "execution_id": None,
                    "execution_created_at": None,
                    "filename": None,
                }
                self.assertEqual(
                    (
                        details.classification,
                        details.filename,
                        details.cause,
                        details.schedule_id,
                        details.execution_id,
                        details.execution_created_at,
                    ),
                    (
                        classification,
                        expected_private["filename"],
                        cause,
                        expected_private["schedule_id"],
                        expected_private["execution_id"],
                        expected_private["execution_created_at"],
                    ),
                )
                self.assertEqual(
                    ADAPTER.classify_selector_object(value),
                    (classification, expected_private["filename"]),
                )

        for missing_field in ["schedule_id", "execution_id", "execution_created_at", "filename"]:
            value = dict(EXACT_SELECTOR_VALUE)
            value[missing_field] = None
            details = ADAPTER.classify_selector_details(value)
            self.assertEqual(details.classification, ADAPTER.PRIVATE_LOCATOR_MISSING)
            self.assertEqual(
                (details.schedule_id, details.execution_id, details.execution_created_at, details.filename),
                (None, None, None, None),
            )
        missing_filename = dict(EXACT_SELECTOR_VALUE)
        missing_filename["filename"] = ""
        self.assertEqual(
            ADAPTER.classify_selector_object(missing_filename),
            (ADAPTER.PRIVATE_LOCATOR_MISSING, None),
        )
        for value in [
            {**EXACT_SELECTOR_VALUE, "schedule_count": 0, "schedule_id": SCHEDULE_ID},
            {**EXACT_SELECTOR_VALUE, "schedule_count": 2, "execution_id": EXECUTION_ID},
            {**EXACT_SELECTOR_VALUE, "execution_count": 0, "filename": FILENAME},
            {**EXACT_SELECTOR_VALUE, "execution_count": 2, "execution_created_at": EXECUTION_CREATED_AT},
            {**EXACT_SELECTOR_VALUE, "schedule_count": True},
            {**EXACT_SELECTOR_VALUE, "execution_count": True},
            {**EXACT_SELECTOR_VALUE, "schedule_count": 3},
            {**EXACT_SELECTOR_VALUE, "execution_count": 3},
            {**EXACT_SELECTOR_VALUE, "schedule_id": 0},
            {**EXACT_SELECTOR_VALUE, "schedule_id": -1},
            {**EXACT_SELECTOR_VALUE, "schedule_id": True},
            {**EXACT_SELECTOR_VALUE, "schedule_id": "17"},
            {**EXACT_SELECTOR_VALUE, "execution_id": 0},
            {**EXACT_SELECTOR_VALUE, "execution_id": True},
            {**EXACT_SELECTOR_VALUE, "execution_id": "23"},
            {**EXACT_SELECTOR_VALUE, "execution_created_at": "2026-08-31T00:00:01Z"},
            {**EXACT_SELECTOR_VALUE, "execution_created_at": "2026-08-31T00:00:01.123456+00:00"},
            {**EXACT_SELECTOR_VALUE, "execution_created_at": "2026-02-29T00:00:01.123456Z"},
            {**EXACT_SELECTOR_VALUE, "filename": 7},
            {**EXACT_SELECTOR_VALUE, "filename": "x" * (ADAPTER.NMAX + 1)},
            {**EXACT_SELECTOR_VALUE, "filename": "\ud800"},
            {**EXACT_SELECTOR_VALUE, "filename": b"bytes"},
            {**EXACT_SELECTOR_VALUE, "extra": 1},
            {key: value for key, value in EXACT_SELECTOR_VALUE.items() if key != "execution_id"},
        ]:
            with self.subTest(value=value), self.assertRaises(ADAPTER.SelectorOutputError):
                ADAPTER.classify_selector_object(value)
        parsed = ADAPTER.parse_selector_output(EXACT_SELECTOR_OUTPUT)
        self.assertEqual(
            (
                parsed.classification,
                parsed.schedule_id,
                parsed.execution_id,
                parsed.execution_created_at,
                parsed.filename,
            ),
            (ADAPTER.EXACTLY_ONE, SCHEDULE_ID, EXECUTION_ID, EXECUTION_CREATED_AT, FILENAME),
        )
        with self.assertRaises(ADAPTER.SelectorOutputError):
            ADAPTER.parse_selector_output(
                b'{"schedule_count":0,"schedule_id":null,"execution_count":0,'
                b'"execution_id":null,"execution_created_at":null,"filename":null}\n\n'
            )
        with self.assertRaises(ADAPTER.SelectorOutputError):
            ADAPTER.parse_selector_output(
                b'{"schedule_count":1,"schedule_id":17,"execution_count":1,"execution_id":23,'
                b'"execution_created_at":"2026-08-31T00:00:01.123456Z",'
                b'"filename":"ok","filename":"dup"}\n'
            )
        with self.assertRaises(ADAPTER.SelectorOutputError):
            ADAPTER.parse_selector_output(
                b'{"schedule_count":NaN,"schedule_id":null,"execution_count":1,'
                b'"execution_id":null,"execution_created_at":null,"filename":null}\n'
            )

    def test_route_and_topology_static_contract(self):
        source = SOURCE_PATH.read_text(encoding="utf-8")
        self.assertEqual(source.count("subprocess.Popen("), 1)
        self.assertEqual(ADAPTER.SHELL_WRAPPER.count("/usr/local/bin/psql"), 1)
        self.assertIn('"docker", "exec", "-i", "coolify-db"', source)
        for flag in [
            "-X", "-w", "-n", "-q", "-A", "-t", "-v ON_ERROR_STOP=1",
            "--host=/var/run/postgresql", "--port=5432", "--dbname=coolify",
            "--pset=pager=off", "-f -",
        ]:
            self.assertIn(flag, ADAPTER.SHELL_WRAPPER)
        self.assertNotIn("docker inspect", source)
        self.assertNotIn("docker ps", source)
        self.assertNotIn("127.0.0.1", ADAPTER.SHELL_WRAPPER)
        self.assertNotIn("--service", ADAPTER.SHELL_WRAPPER)
        self.assertNotIn("--password", ADAPTER.SHELL_WRAPPER)
        self.assertEqual(ADAPTER.OperationCounts().retries, 0)
        self.assertEqual(ADAPTER.OperationCounts().fallbacks, 0)
        self.assertEqual(ADAPTER.SHELL_WRAPPER.count("/bin/sh"), 0)
        self.assertEqual(source.count("coolify-db"), 1)
        self.assertEqual(ADAPTER.SHELL_WRAPPER.count("\\q"), 0)

    def test_capture_limits_and_guard_failures(self):
        captures = ADAPTER.CaptureSet()
        captures.append("stdout", b"x" * (ADAPTER.PRE_OMAX + 1))
        pre_stderr, pre_overflow = ADAPTER._capture_guard_failure(captures, False)
        self.assertFalse(pre_stderr)
        self.assertTrue(pre_overflow)
        captures = ADAPTER.CaptureSet()
        captures.append("stderr", b"x")
        pre_stderr, pre_overflow = ADAPTER._capture_guard_failure(captures, False)
        self.assertTrue(pre_stderr)
        self.assertFalse(pre_overflow)
        captures = ADAPTER.CaptureSet()
        captures.append("stdout", b"x" * (ADAPTER.CMAX + 1))
        _, post_overflow = ADAPTER._capture_guard_failure(captures, True)
        self.assertTrue(post_overflow)
        state = ADAPTER.AdmissionState()
        self.assertEqual(state.step(ADAPTER.READY_MARKER, ADAPTER.WRITER_OK, 4.0, 5.0, route_failed=True), ADAPTER.ADMISSION_FAIL)

    def test_execute_operation_marker_before_writer_ack_is_production_path(self):
        process = ScriptedProcess()
        outcome, _ = self._run_execute(process)
        self._assert_single_operation_counts(process, outcome)
        self.assertEqual(outcome.classification, ADAPTER.EXACTLY_ONE)
        self.assertEqual(
            (
                outcome.schedule_id,
                outcome.execution_id,
                outcome.execution_created_at,
                outcome.filename,
            ),
            (SCHEDULE_ID, EXECUTION_ID, EXECUTION_CREATED_AT, FILENAME),
        )
        marker_index = next(i for i, item in enumerate(process.put_events) if item == ("stdout", ADAPTER.READY_MARKER))
        writer_index = next(i for i, item in enumerate(process.put_events) if item[0] == "phase1")
        self.assertLess(marker_index, writer_index)

    def test_execute_operation_writer_ack_before_marker_is_production_path(self):
        process = ScriptedProcess(marker_after_writer=True)
        outcome, _ = self._run_execute(process)
        self._assert_single_operation_counts(process, outcome)
        writer_index = next(i for i, item in enumerate(process.put_events) if item[0] == "phase1")
        marker_index = next(i for i, item in enumerate(process.put_events) if item == ("stdout", ADAPTER.READY_MARKER))
        self.assertLess(writer_index, marker_index)

    def test_execute_operation_exact_conjunction_has_one_private_phase2_write(self):
        process = ScriptedProcess()
        outcome, _ = self._run_execute(process)
        self._assert_single_operation_counts(process, outcome)
        self.assertEqual(process.stdin.writes[0], ADAPTER.READINESS_COMMAND)
        self.assertEqual(process.stdin.writes[1], process.phase2_payloads[0])
        self.assertIn(
            f"e.created_at > TIMESTAMPTZ '{BARRIER_UTC}'".encode(),
            process.phase2_payloads[0],
        )
        self.assertTrue(process.marker_enqueued.is_set())
        self.assertTrue(process.writer_enqueued.is_set())

    def test_execute_operation_invalid_barrier_fails_before_private_process(self):
        process_factory_calls = []
        outcome = ADAPTER.execute_operation(
            "2026-08-31T00:00:00Z",
            process_factory=lambda: process_factory_calls.append(True),
        )
        self.assertIsInstance(outcome, ADAPTER.OperationFailure)
        self.assertFalse(outcome.query_started)
        self.assertEqual(process_factory_calls, [])

    def test_execute_operation_readiness_deadline_closes_permanently(self):
        release = threading.Event()
        process = ScriptedProcess(phase1_release=release)
        outcome, clock = self._run_execute(process)
        self.assertIsInstance(outcome, ADAPTER.OperationFailure)
        self.assertFalse(outcome.query_started)
        self.assertEqual(process.phase2_payloads, [])
        self.assertGreaterEqual(clock.value, ADAPTER.R)
        release.set()
        self.assertTrue(process.writer_enqueued.wait(1))
        self.assertEqual(process.phase2_payloads, [])

    def test_execute_operation_phase1_short_and_write_flush_errors_fail_closed(self):
        cases = [
            {"phase1_status": ADAPTER.WRITER_SHORT},
            {"phase1_flush_error": True},
            {"phase1_status": ADAPTER.WRITER_ERROR},
        ]
        for options in cases:
            with self.subTest(options=options):
                process = ScriptedProcess(**options)
                outcome, _ = self._run_execute(process)
                self.assertIsInstance(outcome, ADAPTER.OperationFailure)
                self.assertFalse(outcome.query_started)
                self.assertEqual(len(process.phase2_payloads), 0)
                self.assertEqual(process.factory_calls, 1)

    def test_execute_operation_phase2_short_and_flush_errors_wait_to_database_bound(self):
        cases = [
            {"phase2_status": ADAPTER.WRITER_SHORT},
            {"phase2_flush_error": True},
            {"phase2_status": ADAPTER.WRITER_ERROR},
        ]
        for options in cases:
            with self.subTest(options=options):
                process = ScriptedProcess(**options)
                outcome, clock = self._run_execute(process)
                self.assertIsInstance(outcome, ADAPTER.OperationFailure)
                self.assertTrue(outcome.query_started)
                self.assertGreaterEqual(clock.value, ADAPTER.T_HOST)
                self.assertEqual(len(process.phase2_payloads), 1)

    def test_execute_operation_ambiguous_post_admission_state_waits_to_database_bound(self):
        process = ScriptedProcess(hold_after_output=True)
        outcome, clock = self._run_execute(process)
        self.assertIsInstance(outcome, ADAPTER.OperationFailure)
        self.assertTrue(outcome.query_started)
        self.assertGreaterEqual(clock.value, ADAPTER.T_HOST)

    def test_execute_operation_poll_failure_waits_to_database_bound(self):
        process = ScriptedProcess(post_poll_error=True)
        outcome, clock = self._run_execute(process)
        self.assertIsInstance(outcome, ADAPTER.OperationFailure)
        self.assertTrue(outcome.query_started)
        self.assertGreaterEqual(clock.value, ADAPTER.T_HOST)

    def test_execute_operation_f1_eof_none_then_nonzero_race_fails_closed(self):
        process = ScriptedProcess(nonzero_after_eof=True)
        outcome, clock = self._run_execute(process)
        self.assertIsInstance(outcome, ADAPTER.OperationFailure)
        self.assertEqual(outcome.classification, ADAPTER.QUERY_FAILED)
        self.assertTrue(process.both_eof_observed.is_set())
        self.assertEqual(process.post_eof_observations[:2], [None, 23])
        self.assertGreaterEqual(clock.value, ADAPTER.T_HOST)

    def test_execute_operation_clean_zero_return_is_success(self):
        process = ScriptedProcess()
        outcome, _ = self._run_execute(process)
        self._assert_single_operation_counts(process, outcome)
        self.assertEqual(outcome.classification, ADAPTER.EXACTLY_ONE)
        self.assertEqual(outcome.filename, FILENAME)
        self.assertEqual(outcome.schedule_id, SCHEDULE_ID)
        self.assertEqual(outcome.execution_id, EXECUTION_ID)
        self.assertEqual(outcome.execution_created_at, EXECUTION_CREATED_AT)

    def test_execute_operation_selector_parse_failure_after_admission_waits_to_bound(self):
        process = ScriptedProcess(selector_output=b"not-json\n")
        outcome, clock = self._run_execute(process)
        self.assertIsInstance(outcome, ADAPTER.OperationFailure)
        self.assertEqual(outcome.classification, ADAPTER.QUERY_FAILED)
        self.assertTrue(outcome.query_started)
        self.assertGreaterEqual(clock.value, ADAPTER.T_HOST)

    def test_handle_protocol_emits_started_and_one_terminal_frame_for_each_outcome(self):
        outcomes = [
            ADAPTER.OperationSuccess(
                ADAPTER.EXACTLY_ONE,
                FILENAME,
                ADAPTER.OperationCounts(),
                SCHEDULE_ID,
                EXECUTION_ID,
                EXECUTION_CREATED_AT,
            ),
            ADAPTER.OperationFailure(False, ADAPTER.OperationCounts()),
            ADAPTER.OperationFailure(True, ADAPTER.OperationCounts()),
        ]
        for expected in outcomes:
            with self.subTest(expected=expected):
                operation_calls = []

                def operation(barrier_utc, expected=expected):
                    operation_calls.append(True)
                    self.assertEqual(barrier_utc, BARRIER_UTC)
                    return expected

                frames, _ = self._handle_protocol(operation)
                self.assertEqual(operation_calls, [True])
                self.assertEqual(len(frames), 2)
                self.assertEqual(frames[0], (ADAPTER.STARTED, {"type": "STARTED", "version": 1}))
                expected_terminal_type = ADAPTER.RESULT if isinstance(expected, ADAPTER.OperationSuccess) else ADAPTER.FAILED
                self.assertEqual(frames[1][0], expected_terminal_type)
                self.assertEqual(frames[1][1]["classification"], expected.classification)

    def test_handle_protocol_result_serialization_overflow_falls_back_to_bounded_query_failed(self):
        filename = '"' * ADAPTER.NMAX
        self.assertEqual(len(filename.encode("utf-8")), ADAPTER.NMAX)
        with self.assertRaises(ADAPTER.ProtocolError):
            ADAPTER.result_frame(
                ADAPTER.EXACTLY_ONE,
                filename,
                SCHEDULE_ID,
                EXECUTION_ID,
                EXECUTION_CREATED_AT,
            )

        outcome = ADAPTER.OperationSuccess(
            ADAPTER.EXACTLY_ONE,
            filename,
            ADAPTER.OperationCounts(),
            SCHEDULE_ID,
            EXECUTION_ID,
            EXECUTION_CREATED_AT,
        )
        frames, raw = self._handle_protocol(lambda barrier_utc: outcome)
        self.assertEqual([message_type for message_type, _ in frames], [ADAPTER.STARTED, ADAPTER.FAILED])
        self.assertEqual(frames[1][1], {"type": "FAILED", "version": 1, "classification": ADAPTER.QUERY_FAILED})
        _, _, _, _, started_length = ADAPTER.Header.unpack(raw[: ADAPTER.Header.size])
        terminal_header_offset = ADAPTER.Header.size + started_length
        _, _, _, _, terminal_length = ADAPTER.Header.unpack(
            raw[terminal_header_offset : terminal_header_offset + ADAPTER.Header.size]
        )
        terminal_payload_start = terminal_header_offset + ADAPTER.Header.size
        terminal_payload = raw[terminal_payload_start : terminal_payload_start + terminal_length]
        self.assertLessEqual(len(terminal_payload), ADAPTER.PAYMAX)
        self.assertNotIn(b"filename", terminal_payload)
        self.assertNotIn(filename.encode("utf-8"), raw)

    def test_shell_environment_and_passwordless_route(self):
        wrapper = ADAPTER.SHELL_WRAPPER
        self.assertIn('if [ "${POSTGRES_DB:-}" != "coolify" ]', wrapper)
        self.assertIn('if [ -z "${POSTGRES_USER:-}" ]', wrapper)
        self.assertIn("HOME=/nonexistent", wrapper)
        self.assertIn("PGPASSFILE=/dev/null", wrapper)
        self.assertIn("PGCONNECT_TIMEOUT=2", wrapper)
        self.assertIn("PGOPTIONS='-c statement_timeout=7000 -c idle_session_timeout=2000 -c TimeZone=UTC'", wrapper)
        for variable in ["PGHOST", "PGHOSTADDR", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGSERVICE", "PGSERVICEFILE", "PGSSLMODE", "PGSSLKEY", "PGSSLROOTCERT", "PGTZ"]:
            self.assertIn(variable, wrapper)

    def test_public_frames_never_include_private_sql_or_cardinality_fields(self):
        query = ADAPTER.build_locator_query(BARRIER_UTC)
        exact = ADAPTER.result_frame(
            ADAPTER.EXACTLY_ONE,
            "file.tar",
            SCHEDULE_ID,
            EXECUTION_ID,
            EXECUTION_CREATED_AT,
        )
        zero = ADAPTER.result_frame(ADAPTER.ZERO_ROW_MATCH)
        self.assertNotIn(query.encode(), exact)
        self.assertNotIn(query.encode(), zero)
        self.assertIn(b"schedule_id", exact)
        self.assertIn(b"execution_id", exact)
        self.assertIn(b"execution_created_at", exact)
        self.assertIn(b"filename", exact)
        self.assertNotIn(b"schedule_id", zero)
        self.assertNotIn(b"execution_id", zero)
        self.assertNotIn(b"execution_created_at", zero)
        self.assertNotIn(b"filename", zero)
        self.assertEqual(
            json.loads(exact[ADAPTER.Header.size:]),
            {
                "type": "RESULT",
                "version": 1,
                "classification": ADAPTER.EXACTLY_ONE,
                "schedule_id": SCHEDULE_ID,
                "execution_id": EXECUTION_ID,
                "execution_created_at": EXECUTION_CREATED_AT,
                "filename": "file.tar",
            },
        )

    def test_result_frame_rejects_invalid_or_non_single_private_tuple(self):
        with self.assertRaises(ADAPTER.ProtocolError):
            ADAPTER.result_frame(
                ADAPTER.EXACTLY_ONE,
                FILENAME,
                0,
                EXECUTION_ID,
                EXECUTION_CREATED_AT,
            )
        with self.assertRaises(ADAPTER.ProtocolError):
            ADAPTER.result_frame(
                ADAPTER.EXACTLY_ONE,
                FILENAME,
                SCHEDULE_ID,
                EXECUTION_ID,
                "2026-08-31T00:00:01Z",
            )
        with self.assertRaises(ADAPTER.ProtocolError):
            ADAPTER.result_frame(
                ADAPTER.EXACTLY_ONE,
                7,
                SCHEDULE_ID,
                EXECUTION_ID,
                EXECUTION_CREATED_AT,
            )
        with self.assertRaises(ADAPTER.ProtocolError):
            ADAPTER.result_frame(ADAPTER.ZERO_ROW_MATCH, FILENAME)

    def test_disconnect_classification_does_not_claim_database_terminality(self):
        self.assertEqual(ADAPTER.failure_classification(False), ADAPTER.QUERY_NOT_EXECUTED)
        self.assertEqual(ADAPTER.failure_classification(True), ADAPTER.QUERY_FAILED)
        self.assertIn("never database-terminality proof", ADAPTER._cleanup_process.__doc__)

    def test_one_operation_counts_are_explicit(self):
        counts = ADAPTER.OperationCounts(
            docker_execs=1,
            shell_wrappers=1,
            psql_sessions=1,
            logical_selects=1,
            phase1_writes=1,
            phase2_writes=1,
        )
        self.assertEqual(counts.docker_execs, 1)
        self.assertEqual(counts.shell_wrappers, 1)
        self.assertEqual(counts.psql_sessions, 1)
        self.assertEqual(counts.logical_selects, 1)
        self.assertEqual(counts.phase1_writes, 1)
        self.assertEqual(counts.phase2_writes, 1)
        self.assertEqual(counts.retries, 0)
        self.assertEqual(counts.fallbacks, 0)

    def test_source_integrity_metrics_are_reproducible(self):
        contents = SOURCE_PATH.read_bytes()
        digest = hashlib.sha256(contents).hexdigest()
        encoded = base64.urlsafe_b64encode(contents).rstrip(b"=")
        source_text = SOURCE_PATH.read_text(encoding="utf-8")
        self.assertEqual(len(contents), EXPECTED_ADAPTER_UTF8_BYTES)
        self.assertEqual(len(encoded), EXPECTED_ADAPTER_BASE64URL_LENGTH)
        self.assertEqual(digest, EXPECTED_ADAPTER_SHA256)
        self.assertEqual(len(source_text.splitlines()), EXPECTED_ADAPTER_LINES)
        self.assertEqual(len(contents), len(SOURCE_PATH.read_text(encoding="utf-8").encode("utf-8")))


if __name__ == "__main__":
    unittest.main()
