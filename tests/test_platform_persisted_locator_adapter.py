import ast
import base64
import hashlib
import importlib.util
import json
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE_PATH = ROOT / "scripts" / "platform-persisted-locator-adapter.py"
SPEC = importlib.util.spec_from_file_location("platform_persisted_locator_adapter", SOURCE_PATH)
ADAPTER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = ADAPTER
SPEC.loader.exec_module(ADAPTER)


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


class AdapterContractTests(unittest.TestCase):
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
        self.assertEqual((ADAPTER.R, ADAPTER.I, ADAPTER.S, ADAPTER.MARGIN), (5, 2, 7, 1))
        self.assertEqual(ADAPTER.PGCONNECT_TIMEOUT, 2)
        self.assertEqual(ADAPTER.T_HOST, ADAPTER.R + 2 * ADAPTER.I + ADAPTER.S + ADAPTER.MARGIN)
        self.assertEqual(ADAPTER.T_HOST, 17)
        self.assertEqual(ADAPTER.PGOPTIONS_VALUE, "-c statement_timeout=7000 -c idle_session_timeout=2000")

    def test_splq_frame_and_exact_request(self):
        payload = b'{"type":"REQUEST","version":1,"schedule_id":7}'
        frame = ADAPTER.Header.pack(ADAPTER.Magic, 1, ADAPTER.REQUEST, 0, len(payload)) + payload
        self.assertEqual(ADAPTER.decode_request_frame(frame), {"type": "REQUEST", "version": 1, "schedule_id": 7})
        with self.assertRaises(ADAPTER.ProtocolError):
            ADAPTER.decode_request_frame(frame + b"x")
        with self.assertRaises(ADAPTER.ProtocolError):
            ADAPTER.decode_request_frame(ADAPTER.Header.pack(b"BAD!", 1, 1, 0, len(payload)) + payload)
        with self.assertRaises(ADAPTER.ProtocolError):
            ADAPTER.decode_request_frame(ADAPTER.Header.pack(ADAPTER.Magic, 1, 1, 1, len(payload)) + payload)
        oversized = ADAPTER.Header.pack(ADAPTER.Magic, 1, 1, 0, ADAPTER.REQMAX + 1)
        with self.assertRaises(ADAPTER.ProtocolError):
            ADAPTER.decode_request_frame(oversized + b"x" * (ADAPTER.REQMAX + 1))

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
            b'{"type":"REQUEST","version":1,"schedule_id":true}',
            b'{"type":"REQUEST","version":1,"schedule_id":1.0}',
            b'{"type":"REQUEST","version":1,"schedule_id":0}',
            b'{"type":"REQUEST","version":1,"schedule_id":-1}',
            b'{"type":"REQUEST","version":1,"schedule_id":9223372036854775808}',
            b'{"type":"REQUEST","version":1,"schedule_id":1,"extra":0}',
            b'{"type":"REQUEST","version":1,"schedule_id":1,"schedule_id":2}',
            b'{"type":"REQUEST","version":1,"schedule_id":NaN}',
            b'{"type":"REQUEST","version":1,"schedule_id":Infinity}',
            b'{"type":"REQUEST","version":1,"schedule_id":1} trailing',
            b' {"type":"REQUEST","version":1,"schedule_id":1}',
        ]
        for payload in cases:
            with self.subTest(payload=payload), self.assertRaises(ADAPTER.ProtocolError):
                ADAPTER.parse_request_payload(payload)

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
        query = ADAPTER.build_locator_query(8301)
        self.assertLessEqual(len(query.encode("utf-8")), ADAPTER.QMAX)
        self.assertEqual(query.count("SELECT json_build_object("), 1)
        for fragment in [
            "s.id = 8301",
            "s.database_id = 0",
            "s.database_type = 'App\\Models\\StandalonePostgresql'",
            "e.database_name = 'coolify'",
            "e.status = 'success'",
            "e.created_at >= TIMESTAMPTZ '2026-08-27T18:00:03Z'",
            "e.created_at < TIMESTAMPTZ '2026-08-27T18:00:04Z'",
            "e.size ~ '^[0-9]+$'",
            "e.size::numeric = 830082",
            "e.s3_uploaded IS TRUE",
            "e.filename IS NOT NULL",
            "e.local_storage_deleted IS FALSE",
        ]:
            self.assertIn(fragment, query)
        with self.assertRaises(ADAPTER.ProtocolError):
            ADAPTER.build_locator_query(True)
        with self.assertRaises(ADAPTER.ProtocolError):
            ADAPTER.build_locator_query(0)
        self.assertEqual(ADAPTER.phase2_payload(query), query.encode() + b"\n\\q\n")

    def test_selector_cardinality_privacy_and_bounds(self):
        self.assertEqual(ADAPTER.classify_selector_object({"row_count": 0, "filename": None}), (ADAPTER.ZERO_ROW_MATCH, None))
        self.assertEqual(ADAPTER.classify_selector_object({"row_count": 2, "filename": None}), (ADAPTER.MULTIPLE_ROW_MATCH, None))
        self.assertEqual(ADAPTER.classify_selector_object({"row_count": 1, "filename": None}), (ADAPTER.PRIVATE_LOCATOR_MISSING, None))
        self.assertEqual(ADAPTER.classify_selector_object({"row_count": 1, "filename": "backup.tar"}), (ADAPTER.EXACTLY_ONE, "backup.tar"))
        for value in [
            {"row_count": 0, "filename": "leak"},
            {"row_count": 2, "filename": "leak"},
            {"row_count": True, "filename": None},
            {"row_count": 3, "filename": None},
            {"row_count": 1, "filename": 7},
            {"row_count": 1, "filename": "x" * (ADAPTER.NMAX + 1)},
            {"row_count": 1, "filename": "ok", "extra": 1},
        ]:
            with self.subTest(value=value), self.assertRaises(ADAPTER.SelectorOutputError):
                ADAPTER.classify_selector_object(value)
        self.assertEqual(
            ADAPTER.parse_selector_output(b'{"row_count":1,"filename":"backup.tar"}\n'),
            (ADAPTER.EXACTLY_ONE, "backup.tar"),
        )
        with self.assertRaises(ADAPTER.SelectorOutputError):
            ADAPTER.parse_selector_output(b'{"row_count":0,"filename":null}\n\n')

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

    def test_shell_environment_and_passwordless_route(self):
        wrapper = ADAPTER.SHELL_WRAPPER
        self.assertIn('if [ "${POSTGRES_DB:-}" != "coolify" ]', wrapper)
        self.assertIn('if [ -z "${POSTGRES_USER:-}" ]', wrapper)
        self.assertIn("HOME=/nonexistent", wrapper)
        self.assertIn("PGPASSFILE=/dev/null", wrapper)
        self.assertIn("PGCONNECT_TIMEOUT=2", wrapper)
        self.assertIn("PGOPTIONS='-c statement_timeout=7000 -c idle_session_timeout=2000'", wrapper)
        for variable in ["PGHOST", "PGHOSTADDR", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGSERVICE", "PGSERVICEFILE", "PGSSLMODE", "PGSSLKEY", "PGSSLROOTCERT"]:
            self.assertIn(variable, wrapper)

    def test_public_frames_never_include_private_sql_or_row_count(self):
        query = ADAPTER.build_locator_query(1)
        exact = ADAPTER.result_frame(ADAPTER.EXACTLY_ONE, "file.tar")
        zero = ADAPTER.result_frame(ADAPTER.ZERO_ROW_MATCH)
        self.assertNotIn(query.encode(), exact)
        self.assertNotIn(query.encode(), zero)
        self.assertNotIn(b"row_count", exact)
        self.assertNotIn(b"filename", zero)
        self.assertEqual(json.loads(exact[ADAPTER.Header.size:])["filename"], "file.tar")

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
        self.assertEqual(len(contents), len(SOURCE_PATH.read_text(encoding="utf-8").encode("utf-8")))
        self.assertEqual(len(digest), 64)
        self.assertGreater(len(encoded), len(contents))


if __name__ == "__main__":
    unittest.main()
