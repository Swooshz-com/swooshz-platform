import ast
import base64
import copy
import ctypes
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import sys
import tempfile
import threading
import time
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE_PATH = ROOT / "scripts" / "platform-recovery-controller-bridge.py"
SPEC = importlib.util.spec_from_file_location("platform_recovery_controller_bridge", SOURCE_PATH)
BRIDGE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = BRIDGE
SPEC.loader.exec_module(BRIDGE)


BARRIER_UTC = "2026-08-31T00:00:00.000000Z"
EPOCH_REF = "epoch-bridge-synthetic-001"
AUTHORITY_REF = "authority-bridge-synthetic-001"
ARTIFACT_ROW_ID = 23
ARTIFACT_FILENAME = "synthetic-artifact-001"
ISOLATION_COMMITMENT = BRIDGE.bridge_commitment("isolation", "synthetic-pass")
RESULT_COMMITMENT = BRIDGE.bridge_commitment("result", "synthetic-committed")
PRIVATE_V2 = {
    "container_identity": "synthetic-container-001",
    "volume_identity": "synthetic-volume-001",
    "runner_identity": "synthetic-runner-001",
    "salt": "synthetic-salt-only-in-private-fixture",
    "spool_hmac_key": "synthetic-hmac-key-only-in-private-fixture",
}


def harden_windows_test_root(root):
    if os.name != "nt":
        return
    adapter = BRIDGE.STORE.WindowsDurabilityAdapter()
    kernel32, advapi32 = adapter._require_api()
    current, current_buffer = adapter._current_sid()
    system = adapter._well_known_sid("S-1-5-18")
    administrators = adapter._well_known_sid("S-1-5-32-544")
    try:
        advapi32.InitializeAcl.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]
        advapi32.InitializeAcl.restype = ctypes.c_int
        advapi32.AddAccessAllowedAceEx.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ubyte, ctypes.c_ulong, ctypes.c_void_p]
        advapi32.AddAccessAllowedAceEx.restype = ctypes.c_int
        advapi32.SetNamedSecurityInfoW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        advapi32.SetNamedSecurityInfoW.restype = ctypes.c_ulong
        acl = ctypes.create_string_buffer(4096)
        if not advapi32.InitializeAcl(acl, len(acl), 2):
            raise unittest.SkipTest("disposable ACL fixture initialization unavailable")
        inheritance = 0x01 | 0x02
        for sid in (current, system, administrators):
            if not advapi32.AddAccessAllowedAceEx(acl, 2, inheritance, 0x1F01FF, sid):
                raise unittest.SkipTest("disposable ACL fixture construction unavailable")
        result = advapi32.SetNamedSecurityInfoW(str(root), 1, 0x00000004, None, None, ctypes.cast(acl, ctypes.c_void_p), None)
        if result != 0:
            raise unittest.SkipTest("disposable ACL fixture assignment unavailable")
    finally:
        kernel32.LocalFree(system)
        kernel32.LocalFree(administrators)
        _ = current_buffer


def valid_runner_source(
    *,
    row_id=ARTIFACT_ROW_ID,
    filename=ARTIFACT_FILENAME,
    isolation=ISOLATION_COMMITMENT,
    result=RESULT_COMMITMENT,
):
    return (
        "def run(runtime):\n"
        f"    runtime.send_discovery({row_id!r}, {filename!r}, 'PASS', {isolation!r})\n"
        "    grant = runtime.wait_for_decision()\n"
        f"    runtime.send_result(grant, 'COMMITTED', {result!r})\n"
    )


class _FakeChannel:
    def __init__(self, graph, incoming=None):
        self.graph = graph
        self.sequence = 1
        self.sent = []
        self.incoming = list(incoming or [])

    def send(self, key, direction, message, payload):
        self.sent.append((key, direction, message, payload))

    def receive(self, key, direction, *, timeout=None):
        if not self.incoming:
            raise AssertionError("fake channel has no incoming frame")
        return self.incoming.pop(0)


class _BlockingReader:
    def __init__(self):
        self.release = threading.Event()

    def read(self, _size):
        self.release.wait(2.0)
        return b""


class _SyntheticResourceLifecycle:
    """In-memory proof of the pre-CAS target/volume ownership contract."""

    def __init__(self, *, prior_absence=True, owner="run-317-synthetic"):
        self.prior_absence = prior_absence
        self.owner = owner
        self.created = False
        self.events = []

    def create(self):
        if not self.prior_absence or self.created:
            raise RuntimeError("RESOURCE_COLLISION")
        self.created = True
        self.events.extend(("CREATE_VOLUME", "CREATE_TARGET", "ISOLATION_PASS"))

    def isolation_commitment(self):
        if not self.created or self.events[-1] != "ISOLATION_PASS":
            raise RuntimeError("ISOLATION_FAILED")
        return BRIDGE.bridge_commitment("synthetic-isolation", self.owner, "volume", "target")

    def cleanup(self, owner):
        if owner != self.owner:
            raise RuntimeError("CLEANUP_FAILED")
        if self.created:
            self.events.append("CLEANUP")
            self.created = False


class BridgeTestCase(unittest.TestCase):
    def new_store(self, epoch_ref=EPOCH_REF):
        temporary = tempfile.TemporaryDirectory(prefix="run317-controller-bridge-")
        self.addCleanup(temporary.cleanup)
        harden_windows_test_root(pathlib.Path(temporary.name))
        store = BRIDGE.STORE.ControllerStore.for_disposable_test_root(temporary.name)
        store.create_epoch_v2(
            epoch_ref,
            AUTHORITY_REF,
            prebackup_identities=PRIVATE_V2,
        )
        return store

    def run_bundle(self, source, *, decision=None, epoch_ref=EPOCH_REF, timeout_seconds=3.0):
        store = self.new_store(epoch_ref)
        result = BRIDGE.run_controller_bridge(
            store,
            epoch_ref,
            BARRIER_UTC,
            BRIDGE.RunnerBundle(source),
            decision=decision,
            timeout_seconds=timeout_seconds,
        )
        return store, result

    def assert_runner_abort(self, source, code):
        store, result = self.run_bundle(source)
        self.assertEqual(result.error_code, code)
        self.assertEqual(result.counters.public()["ssh_launches"], 0)
        self.assertEqual(result.counters.public()["network_connections"], 0)
        self.assertEqual(result.counters.public()["provider_calls"], 0)
        self.assertEqual(result.counters.public()["backup_calls"], 0)
        self.assertEqual(result.counters.public()["restore_attempts"], 0)
        self.assertEqual(store.load_epoch(EPOCH_REF).record["state"], "ABANDONED")
        return store, result


class ContractTests(BridgeTestCase):
    def test_public_enums_and_import_roots_are_exact(self):
        self.assertEqual(len(BRIDGE.RunnerAbortCode), 10)
        self.assertEqual(
            set(BRIDGE.RunnerControlCode),
            {BRIDGE.RunnerControlCode(value) for value in BRIDGE.RUNNER_CONTROL_VALUES},
        )
        self.assertEqual(
            BRIDGE.RUNNER_IMPORT_ROOTS,
            frozenset(
                {
                    "base64", "binascii", "collections", "contextlib", "dataclasses",
                    "datetime", "hashlib", "hmac", "io", "json", "math", "os",
                    "pathlib", "queue", "re", "selectors", "shlex", "signal", "stat",
                    "struct", "subprocess", "sys", "threading", "time", "typing", "uuid",
                }
            ),
        )
        error = BRIDGE.RunnerControlError(BRIDGE.RunnerAbortCode.QUERY_FAILED)
        self.assertIs(error.code, BRIDGE.RunnerControlCode.QUERY_FAILED)
        self.assertEqual(str(error), "QUERY_FAILED")

    def test_bundle_boundaries_compile_without_execution_and_hide_source(self):
        bundle = BRIDGE.RunnerBundle(valid_runner_source())
        self.assertIs(BRIDGE.validate_runner_bundle(bundle), bundle)
        self.assertNotIn("def run", repr(bundle))
        with self.assertRaisesRegex(BRIDGE.BundleError, "BUNDLE_COMPILE_FAILED"):
            BRIDGE.validate_runner_bundle(BRIDGE.RunnerBundle("def run(:\n"))
        with self.assertRaisesRegex(BRIDGE.BundleError, "BUNDLE_NOT_UTF8"):
            BRIDGE.RunnerBundle(b"\xff")
        with self.assertRaisesRegex(BRIDGE.BundleError, "BUNDLE_OVERSIZED"):
            BRIDGE.RunnerBundle(b"x" * (BRIDGE.MAX_RUNNER_BUNDLE_BYTES + 1))

    def test_barrier_discovery_and_control_validation_is_canonical(self):
        self.assertEqual(BRIDGE.validate_barrier_utc(BARRIER_UTC), BARRIER_UTC)
        for invalid in (
            "2026-08-31T00:00:00Z",
            "2026-08-31T00:00:00.000000+00:00",
            "2026-02-30T00:00:00.000000Z",
            "2026-08-31T00:00:00.000000z",
        ):
            with self.assertRaisesRegex(BRIDGE.ProtocolError, "BARRIER_INVALID"):
                BRIDGE.validate_barrier_utc(invalid)
        for row, filename in ((True, "a"), (0, "a"), (1, "a/b"), (1, ".."), (1, "a\x00b")):
            with self.assertRaisesRegex(BRIDGE.ProtocolError, "DISCOVERY_INVALID"):
                BRIDGE._validate_discovery_tuple(row, filename)
        payload = {
            "type": "DISCOVERY",
            "version": 1,
            "execution_row_id": ARTIFACT_ROW_ID,
            "artifact_filename": ARTIFACT_FILENAME,
            "isolation_state": "PASS",
            "isolation_commitment": ISOLATION_COMMITMENT,
        }
        encoded = BRIDGE.encode_control(payload)
        self.assertEqual(BRIDGE.decode_control(encoded, "DISCOVERY"), payload)
        with self.assertRaisesRegex(BRIDGE.ProtocolError, "FRAME_INVALID"):
            BRIDGE.decode_control(encoded[:-1] + b" ", "DISCOVERY")

    def test_hello_preamble_boot_and_authenticated_frame_limits(self):
        nonce = b"r" * 32
        self.assertEqual(BRIDGE.decode_hello(BRIDGE.encode_hello(nonce)), nonce)
        preamble = BRIDGE.encode_preamble(*(bytes([index]) * 32 for index in range(1, 9)))
        self.assertEqual(len(preamble), 272)
        decoded = BRIDGE.decode_preamble(preamble)
        self.assertEqual(decoded["n_remote"], b"\x01" * 32)
        graph = BRIDGE.derive_key_graph_from_preamble(decoded)
        payload = BRIDGE.encode_control({"type": "READY", "version": 1, "barrier_utc": BARRIER_UTC})
        frame = BRIDGE.encode_authenticated_frame(
            graph.k_session,
            BRIDGE.DIRECTION_REMOTE_TO_LOCAL,
            BRIDGE.MESSAGE_READY,
            1,
            graph.n_session,
            payload,
            frame_nonce=b"f" * 16,
        )
        decoded_frame = BRIDGE.decode_authenticated_frame(
            frame,
            graph.k_session,
            expected_direction=BRIDGE.DIRECTION_REMOTE_TO_LOCAL,
            expected_sequence=1,
            expected_session_nonce=graph.n_session,
        )
        self.assertEqual(decoded_frame.payload, payload)
        with self.assertRaisesRegex(BRIDGE.ProtocolError, "FRAME_INVALID"):
            BRIDGE.decode_authenticated_frame(
                frame[:-1] + bytes([frame[-1] ^ 1]),
                graph.k_session,
                expected_direction=BRIDGE.DIRECTION_REMOTE_TO_LOCAL,
                expected_sequence=1,
                expected_session_nonce=graph.n_session,
            )
        with self.assertRaisesRegex(BRIDGE.ProtocolError, "FRAME_INVALID"):
            BRIDGE.encode_authenticated_frame(
                graph.k_session,
                BRIDGE.DIRECTION_REMOTE_TO_LOCAL,
                BRIDGE.MESSAGE_READY,
                1,
                graph.n_session,
                b"x" * (BRIDGE.MAX_AUTH_PAYLOAD_BYTES + 1),
            )

    def test_sibling_imports_are_explicit_and_fixed_loader_is_public(self):
        self.assertEqual(
            BRIDGE.STORE_IMPORT_SYMBOLS,
            ("ControllerStore", "ControllerStoreError", "V2EpochSnapshot", "recovery_commitment"),
        )
        self.assertEqual(BRIDGE.LOCATOR_IMPORT_SYMBOLS, ("validate_barrier_utc",))
        fixed = BRIDGE.build_fixed_loader_source()
        compile(fixed.decode("ascii"), "<fixed-loader>", "exec", dont_inherit=True)
        command = BRIDGE.build_fixed_loader_command()
        self.assertEqual(command[1], str(SOURCE_PATH))
        self.assertEqual(command[2:], ("--dummy-child",))
        for private_value in PRIVATE_V2.values():
            self.assertNotIn(private_value.encode(), fixed)

    def test_key_graph_has_sibling_domains_and_opaque_grant(self):
        bundle = BRIDGE.RunnerBundle(valid_runner_source())
        graph = BRIDGE.derive_local_key_graph(
            spool_hmac_key=PRIVATE_V2["spool_hmac_key"],
            salt=PRIVATE_V2["salt"],
            epoch_ref=EPOCH_REF,
            authority_ref=AUTHORITY_REF,
            runner_identity=PRIVATE_V2["runner_identity"],
            bundle=bundle,
            n_remote=b"r" * 32,
            n_local=b"l" * 32,
        )
        self.assertNotEqual(graph.k_boot, graph.k_session)
        self.assertNotEqual(graph.k_session, graph.k_proceed)
        self.assertNotIn(PRIVATE_V2["spool_hmac_key"], repr(graph))
        grant = BRIDGE.ProceedGrant(BRIDGE.ProceedGrant._SEAL)
        self.assertEqual(repr(grant), "<ProceedGrant opaque>")
        with self.assertRaises(TypeError):
            copy.copy(grant)
        with self.assertRaises(TypeError):
            BRIDGE.ProceedGrant()

    def test_guarded_import_and_subprocess_require_safe_stdio(self):
        with self.assertRaisesRegex(ImportError, "RUNNER_IMPORT_FORBIDDEN"):
            BRIDGE._guarded_import("socket")
        with self.assertRaisesRegex(ImportError, "RUNNER_IMPORT_FORBIDDEN"):
            BRIDGE._guarded_import("asyncio")
        with self.assertRaisesRegex(BRIDGE.RunnerControlError, "SUBPROCESS_STDIO_REQUIRED"):
            BRIDGE._GUARDED_SUBPROCESS.run(["synthetic"], capture_output=True)
        with self.assertRaisesRegex(BRIDGE.RunnerControlError, "SUBPROCESS_STDIO_REQUIRED"):
            BRIDGE._GUARDED_SUBPROCESS.Popen(["synthetic"], stdin=BRIDGE._subprocess.PIPE, stdout=BRIDGE._subprocess.PIPE, stderr=BRIDGE._subprocess.PIPE, shell=True)

    def test_decision_timeout_is_symbolic_and_does_not_retry(self):
        graph = BRIDGE.derive_local_key_graph(
            spool_hmac_key=PRIVATE_V2["spool_hmac_key"],
            salt=PRIVATE_V2["salt"],
            epoch_ref=EPOCH_REF,
            authority_ref=AUTHORITY_REF,
            runner_identity=PRIVATE_V2["runner_identity"],
            bundle=BRIDGE.RunnerBundle(valid_runner_source()),
            n_remote=b"r" * 32,
            n_local=b"l" * 32,
        )
        reader = _BlockingReader()
        channel = BRIDGE._RemoteChannel(reader, io.BytesIO(), graph)
        with self.assertRaises(BRIDGE.RunnerControlError) as raised:
            channel.receive(graph.k_session, BRIDGE.DIRECTION_LOCAL_TO_REMOTE, timeout=0.01)
        self.assertIs(raised.exception.code, BRIDGE.RunnerControlCode.DECISION_TIMEOUT)
        reader.release.set()

    def test_authenticated_boot_rejects_tamper_before_source_execution(self):
        source = "raise RuntimeError('source-must-not-run')\n"
        bundle = BRIDGE.RunnerBundle(source)
        seed = b"s" * 32
        preamble = BRIDGE.encode_preamble(
            b"r" * 32,
            b"l" * 32,
            b"n" * 32,
            b"e" * 32,
            b"a" * 32,
            b"u" * 32,
            hashlib.sha256(BRIDGE.LP("runner-bundle.v1", bundle.source)).digest(),
            seed,
        )
        graph = BRIDGE.derive_key_graph_from_preamble(BRIDGE.decode_preamble(preamble))
        boot = BRIDGE.encode_authenticated_frame(
            graph.k_boot,
            BRIDGE.DIRECTION_LOCAL_TO_REMOTE,
            BRIDGE.MESSAGE_BOOT,
            1,
            graph.n_session,
            BRIDGE.encode_boot_payload(bundle, BARRIER_UTC),
            frame_nonce=b"b" * 16,
        )
        tampered = boot[:-1] + bytes([boot[-1] ^ 1])
        output = io.BytesIO()
        exit_code = BRIDGE.RemoteLoader(io.BytesIO(preamble + tampered), output).run()
        self.assertEqual(exit_code, BRIDGE.EXIT_RUNNER_ABORT)
        self.assertGreater(len(output.getvalue()), BRIDGE.HELLO_SIZE)

    def test_frame_duplicate_reorder_gap_and_direction_are_rejected(self):
        graph = self.graph_for_contract()
        payload = BRIDGE.encode_control({"type": "READY", "version": 1, "barrier_utc": BARRIER_UTC})

        def frame(sequence, direction=BRIDGE.DIRECTION_REMOTE_TO_LOCAL):
            return BRIDGE.encode_authenticated_frame(
                graph.k_session, direction, BRIDGE.MESSAGE_READY, sequence,
                graph.n_session, payload, frame_nonce=bytes([sequence]) * 16,
            )

        duplicate = BRIDGE._RemoteChannel(io.BytesIO(frame(1) + frame(1)), io.BytesIO(), graph)
        duplicate.receive(graph.k_session, BRIDGE.DIRECTION_REMOTE_TO_LOCAL)
        with self.assertRaises(BRIDGE.RunnerControlError):
            duplicate.receive(graph.k_session, BRIDGE.DIRECTION_REMOTE_TO_LOCAL)
        gap = BRIDGE._RemoteChannel(io.BytesIO(frame(1) + frame(3)), io.BytesIO(), graph)
        gap.receive(graph.k_session, BRIDGE.DIRECTION_REMOTE_TO_LOCAL)
        with self.assertRaises(BRIDGE.RunnerControlError):
            gap.receive(graph.k_session, BRIDGE.DIRECTION_REMOTE_TO_LOCAL)
        reordered = BRIDGE._RemoteChannel(io.BytesIO(frame(2) + frame(1)), io.BytesIO(), graph)
        with self.assertRaises(BRIDGE.RunnerControlError):
            reordered.receive(graph.k_session, BRIDGE.DIRECTION_REMOTE_TO_LOCAL)
        wrong_direction = BRIDGE._RemoteChannel(io.BytesIO(frame(1, BRIDGE.DIRECTION_LOCAL_TO_REMOTE)), io.BytesIO(), graph)
        with self.assertRaises(BRIDGE.RunnerControlError):
            wrong_direction.receive(graph.k_session, BRIDGE.DIRECTION_REMOTE_TO_LOCAL)

    def graph_for_contract(self):
        return BRIDGE.derive_local_key_graph(
            spool_hmac_key=PRIVATE_V2["spool_hmac_key"],
            salt=PRIVATE_V2["salt"],
            epoch_ref=EPOCH_REF,
            authority_ref=AUTHORITY_REF,
            runner_identity=PRIVATE_V2["runner_identity"],
            bundle=BRIDGE.RunnerBundle(valid_runner_source()),
            n_remote=b"r" * 32,
            n_local=b"l" * 32,
        )

    def test_pre_cas_resource_ownership_collision_and_cleanup_simulation(self):
        resources = _SyntheticResourceLifecycle()
        resources.create()
        isolation = resources.isolation_commitment()
        self.assertTrue(isolation.startswith("sha256:v1:"))
        self.assertEqual(resources.events[:3], ["CREATE_VOLUME", "CREATE_TARGET", "ISOLATION_PASS"])
        with self.assertRaisesRegex(RuntimeError, "CLEANUP_FAILED"):
            resources.cleanup("other-run")
        self.assertTrue(resources.created)
        resources.cleanup("run-317-synthetic")
        self.assertFalse(resources.created)
        with self.assertRaisesRegex(RuntimeError, "RESOURCE_COLLISION"):
            _SyntheticResourceLifecycle(prior_absence=False).create()


class RuntimeTests(BridgeTestCase):
    def graph(self):
        return BRIDGE.derive_local_key_graph(
            spool_hmac_key=PRIVATE_V2["spool_hmac_key"],
            salt=PRIVATE_V2["salt"],
            epoch_ref=EPOCH_REF,
            authority_ref=AUTHORITY_REF,
            runner_identity=PRIVATE_V2["runner_identity"],
            bundle=BRIDGE.RunnerBundle(valid_runner_source()),
            n_remote=b"r" * 32,
            n_local=b"l" * 32,
        )

    def proceed_frame(self, graph, artifact=BRIDGE.bridge_commitment("artifact", "synthetic"), isolation=ISOLATION_COMMITMENT):
        capability = BRIDGE.proceed_commitment(graph, artifact, isolation)
        token = BRIDGE._grant_token(graph, capability)
        payload = BRIDGE.encode_control(
            {
                "type": "PROCEED",
                "version": 1,
                "artifact_commitment": artifact,
                "isolation_commitment": isolation,
                "grant": base64.urlsafe_b64encode(token).decode("ascii").rstrip("="),
            }
        )
        return BRIDGE.AuthenticatedFrame(
            BRIDGE.DIRECTION_LOCAL_TO_REMOTE,
            BRIDGE.MESSAGE_PROCEED,
            1,
            graph.n_session,
            b"f" * 16,
            payload,
        )

    def runtime(self, incoming=None):
        graph = self.graph()
        channel = _FakeChannel(graph, incoming)
        runtime = BRIDGE.RunnerRuntime(channel, BARRIER_UTC, decision_timeout=0.01)
        runtime._state = BRIDGE.RunnerRuntime.RUNNING
        return runtime, channel, graph

    def test_runtime_state_guards_and_duplicate_result(self):
        graph = self.graph()
        runtime, channel, _graph = self.runtime([self.proceed_frame(graph)])
        runtime.send_discovery(23, ARTIFACT_FILENAME, "PASS", ISOLATION_COMMITMENT)
        grant = runtime.wait_for_decision()
        self.assertEqual(runtime.state, BRIDGE.RunnerRuntime.PROCEED_GRANTED)
        runtime.send_result(grant, BRIDGE.ResultClassification.COMMITTED, RESULT_COMMITMENT)
        self.assertEqual(runtime.state, BRIDGE.RunnerRuntime.RESULT_SENT)
        with self.assertRaises(BRIDGE.RunnerControlError) as raised:
            runtime.send_result(grant, BRIDGE.ResultClassification.COMMITTED, RESULT_COMMITMENT)
        self.assertIs(raised.exception.code, BRIDGE.RunnerControlCode.RESULT_DUPLICATE)
        with self.assertRaises(TypeError):
            runtime.abort(BRIDGE.RunnerControlCode.LOCAL_ABORT)

    def test_runtime_grant_is_session_bound_one_use_and_unforgeable(self):
        runtime, _channel, graph = self.runtime([self.proceed_frame(self.graph())])
        runtime.send_discovery(23, ARTIFACT_FILENAME, "PASS", ISOLATION_COMMITMENT)
        grant = runtime.wait_for_decision()
        forged = BRIDGE.ProceedGrant(BRIDGE.ProceedGrant._SEAL)
        with self.assertRaises(BRIDGE.RunnerControlError) as raised:
            runtime.send_result(forged, "COMMITTED", RESULT_COMMITMENT)
        self.assertIs(raised.exception.code, BRIDGE.RunnerControlCode.PROCEED_INVALID)
        self.assertNotIn(PRIVATE_V2["spool_hmac_key"], repr(grant))
        self.assertEqual(graph.n_session, runtime._channel.graph.n_session)

    def test_runtime_abort_accepts_only_runner_abort_code(self):
        runtime, _channel, _graph = self.runtime()
        with self.assertRaises(TypeError):
            runtime.abort(BRIDGE.RunnerControlCode.LOCAL_ABORT)
        with self.assertRaises(BRIDGE.RunnerControlError) as raised:
            runtime.abort(BRIDGE.RunnerAbortCode.ARTIFACT_MISSING)
        self.assertIs(raised.exception.code, BRIDGE.RunnerControlCode.ARTIFACT_MISSING)
        self.assertEqual(runtime.state, BRIDGE.RunnerRuntime.TERMINAL)

    def test_runtime_result_before_grant_local_abort_and_proceed_replay(self):
        runtime, _channel, _graph = self.runtime()
        with self.assertRaises(BRIDGE.RunnerControlError) as raised:
            runtime.send_result(None, "COMMITTED", RESULT_COMMITMENT)
        self.assertIs(raised.exception.code, BRIDGE.RunnerControlCode.RESULT_BEFORE_PROCEED)

        graph = self.graph()
        abort_frame = BRIDGE.AuthenticatedFrame(
            BRIDGE.DIRECTION_LOCAL_TO_REMOTE,
            BRIDGE.MESSAGE_ABORT,
            1,
            graph.n_session,
            b"a" * 16,
            BRIDGE.encode_control({"type": "ABORT", "version": 1, "code": "LOCAL_ABORT"}),
        )
        runtime, _channel, _graph = self.runtime([abort_frame])
        runtime.send_discovery(23, ARTIFACT_FILENAME, "PASS", ISOLATION_COMMITMENT)
        with self.assertRaises(BRIDGE.RunnerControlError) as raised:
            runtime.wait_for_decision()
        self.assertIs(raised.exception.code, BRIDGE.RunnerControlCode.LOCAL_ABORT)
        self.assertEqual(runtime.state, BRIDGE.RunnerRuntime.TERMINAL)

        graph = self.graph()
        runtime, _channel, _graph = self.runtime([self.proceed_frame(graph)])
        runtime.send_discovery(23, ARTIFACT_FILENAME, "PASS", ISOLATION_COMMITMENT)
        runtime.wait_for_decision()
        with self.assertRaises(BRIDGE.RunnerControlError) as raised:
            runtime.wait_for_decision()
        self.assertIs(raised.exception.code, BRIDGE.RunnerControlCode.RUNTIME_TERMINAL)

    def test_runtime_rejects_cross_session_grant_and_maps_broken_pipe(self):
        graph_one = self.graph()
        graph_two = BRIDGE.derive_local_key_graph(
            spool_hmac_key=PRIVATE_V2["spool_hmac_key"],
            salt=PRIVATE_V2["salt"],
            epoch_ref=EPOCH_REF,
            authority_ref=AUTHORITY_REF,
            runner_identity=PRIVATE_V2["runner_identity"],
            bundle=BRIDGE.RunnerBundle(valid_runner_source()),
            n_remote=b"q" * 32,
            n_local=b"l" * 32,
        )
        runtime = BRIDGE.RunnerRuntime(
            _FakeChannel(graph_two, [self.proceed_frame(graph_one)]),
            BARRIER_UTC,
            decision_timeout=0.01,
        )
        runtime._state = BRIDGE.RunnerRuntime.RUNNING
        runtime.send_discovery(23, ARTIFACT_FILENAME, "PASS", ISOLATION_COMMITMENT)
        with self.assertRaises(BRIDGE.RunnerControlError) as raised:
            runtime.wait_for_decision()
        self.assertIs(raised.exception.code, BRIDGE.RunnerControlCode.PROCEED_INVALID)

        class BrokenChannel(_FakeChannel):
            def send(self, _key, _direction, _message, _payload):
                raise BrokenPipeError()

        broken = BrokenChannel(self.graph())
        runtime = BRIDGE.RunnerRuntime(broken, BARRIER_UTC)
        runtime._state = BRIDGE.RunnerRuntime.RUNNING
        with self.assertRaises(BRIDGE.RunnerControlError) as raised:
            runtime.send_discovery(23, ARTIFACT_FILENAME, "PASS", ISOLATION_COMMITMENT)
        self.assertIs(raised.exception.code, BRIDGE.RunnerControlCode.PROTOCOL_BROKEN_PIPE)


class DummyChildMatrixTests(BridgeTestCase):
    def frame_stages(self, store, epoch_ref=EPOCH_REF):
        frames_dir = store._frames_path(epoch_ref)
        entries = sorted(
            (entry for entry in store.adapter.list_entries(frames_dir) if entry.name.startswith("frame-")),
            key=lambda entry: entry.name,
        )
        stages = []
        for entry in entries:
            payload = store.adapter.read_authority(entry, max_bytes=BRIDGE.STORE.MAX_FRAME_BYTES)
            stages.append(json.loads(payload.decode("utf-8"))["stage"])
        return stages

    def test_valid_dummy_child_runs_complete_durable_lifecycle(self):
        store, result = self.run_bundle(valid_runner_source())
        self.assertEqual(result.classification, "COMMITTED")
        self.assertEqual(result.error_code, None)
        self.assertFalse(result.post_cas_uncertain)
        self.assertEqual(
            result.counters.public(),
            {
                "ssh_launches": 0,
                "network_connections": 0,
                "provider_calls": 0,
                "backup_calls": 0,
                "restore_attempts": 0,
                "bind_calls": 1,
                "proceed_messages": 1,
                "discovery_messages": 1,
                "result_messages": 1,
            },
        )
        snapshot = store.load_epoch(EPOCH_REF)
        self.assertEqual(snapshot.record["state"], "CONSUMED")
        self.assertEqual(snapshot.record["artifact_binding_state"], "BOUND")
        self.assertEqual(snapshot.ledger["state"], "CONSUMED")
        self.assertEqual(snapshot.spool["last_stage"], "COMMIT")
        self.assertEqual(self.frame_stages(store), ["EPOCH_READY", "RUNNER_STARTED", "RESTORE_BEGIN", "COMMIT"])
        public = store.public_projection(EPOCH_REF)
        self.assertNotIn(PRIVATE_V2["container_identity"], repr(public))
        self.assertNotIn(PRIVATE_V2["volume_identity"], repr(public))
        self.assertNotIn(PRIVATE_V2["runner_identity"], repr(public))
        self.assertNotIn(PRIVATE_V2["salt"], repr(public))
        self.assertNotIn(PRIVATE_V2["spool_hmac_key"], repr(public))

    def test_local_deny_is_one_shot_post_cas_and_never_retries(self):
        store, result = self.run_bundle(
            valid_runner_source(),
            decision=BRIDGE.DummyDecision.deny(BRIDGE.RunnerControlCode.LOCAL_ABORT),
        )
        self.assertEqual(result.classification, "ABANDONED")
        self.assertEqual(result.error_code, "LOCAL_ABORT")
        self.assertTrue(result.post_cas_uncertain)
        self.assertEqual(result.counters.public()["proceed_messages"], 0)
        self.assertEqual(result.counters.public()["discovery_messages"], 1)
        self.assertEqual(result.counters.public()["bind_calls"], 1)
        snapshot = store.load_epoch(EPOCH_REF)
        self.assertEqual(snapshot.ledger["state"], "CONSUMED")
        self.assertEqual(snapshot.spool["last_stage"], "ABANDON")

    def test_runner_abort_before_discovery_is_symbolic_and_direct_pending_abandon(self):
        source = (
            "def run(runtime):\n"
            "    runtime.abort(RunnerAbortCode.ARTIFACT_MISSING)\n"
        )
        store, result = self.assert_runner_abort(source, "ARTIFACT_MISSING")
        snapshot = store.load_epoch(EPOCH_REF)
        self.assertEqual(snapshot.record["artifact_binding_state"], "PENDING")
        self.assertEqual(snapshot.ledger["state"], "UNCONSUMED")
        self.assertEqual(snapshot.spool["last_stage"], "ABANDON")
        self.assertEqual(result.counters.public()["bind_calls"], 0)
        self.assertEqual(result.counters.public()["discovery_messages"], 0)

    def test_loader_callable_and_return_contract_matrix(self):
        cases = (
            ("VALUE = 1\n", "RUNNER_MISSING"),
            ("run = 1\n", "RUNNER_NOT_CALLABLE"),
            ("def run(a, b):\n    return None\n", "RUNNER_SIGNATURE_INVALID"),
            ("async def run(runtime):\n    return None\n", "RUNNER_SIGNATURE_INVALID"),
            ("def run(runtime):\n    return None\n", "RUNNER_NO_RESULT"),
            ("def run(runtime):\n    return 'synthetic'\n", "RUNNER_NON_NONE_RETURN"),
        )
        for index, (source, code) in enumerate(cases):
            with self.subTest(code=code):
                store, result = self.run_bundle(source, epoch_ref=f"epoch-bridge-matrix-{index:02d}")
                self.assertEqual(result.error_code, code)
                self.assertEqual(result.counters.public()["bind_calls"], 0)
                self.assertEqual(store.load_epoch(f"epoch-bridge-matrix-{index:02d}").record["state"], "ABANDONED")

    def test_loader_exception_import_and_stdio_matrix_never_exposes_text(self):
        cases = (
            ("raise RuntimeError('private-sentinel')\n", "RUNNER_TOP_LEVEL_EXCEPTION"),
            ("import socket\n", "RUNNER_TOP_LEVEL_EXCEPTION"),
            (
                "def run(runtime):\n"
                "    print('synthetic stdout')\n",
                "RUNNER_STDOUT_FORBIDDEN",
            ),
            (
                "def run(runtime):\n"
                "    import sys\n"
                "    sys.stderr.write('synthetic stderr')\n",
                "RUNNER_STDERR_FORBIDDEN",
            ),
            (
                "def run(runtime):\n"
                "    import sys\n"
                "    sys.stdin.read()\n",
                "RUNNER_INPUT_FORBIDDEN",
            ),
        )
        for index, (source, code) in enumerate(cases):
            with self.subTest(code=code):
                _store, result = self.run_bundle(source, epoch_ref=f"epoch-bridge-stdio-{index:02d}")
                self.assertEqual(result.error_code, code)
                self.assertNotIn("private-sentinel", repr(result))

    def test_guarded_subprocess_in_dummy_child_cannot_inherit_protocol_stdio(self):
        source = (
            "import subprocess\n"
            "def run(runtime):\n"
            "    subprocess.run(['synthetic-child'], capture_output=True)\n"
        )
        _store, result = self.run_bundle(source)
        self.assertEqual(result.error_code, "SUBPROCESS_STDIO_REQUIRED")
        self.assertEqual(result.counters.public()["bind_calls"], 0)

    def test_guarded_subprocess_rejects_pass_fds_and_shell_variants_in_dummy_child(self):
        cases = (
            "subprocess.run(['synthetic-child'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(1,))\n",
            "subprocess.run(['synthetic-child'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)\n",
        )
        for index, operation in enumerate(cases):
            source = "import subprocess\ndef run(runtime):\n    " + operation
            with self.subTest(index=index):
                _store, result = self.run_bundle(source, epoch_ref=f"epoch-bridge-subprocess-{index:02d}")
                self.assertEqual(result.error_code, "SUBPROCESS_STDIO_REQUIRED")

    def test_raw_fd_capture_overflow_is_symbolic_and_private_safe(self):
        cases = (
            ("1", "RUNNER_STDOUT_FORBIDDEN"),
            ("2", "RUNNER_STDERR_FORBIDDEN"),
        )
        for index, (fd, code) in enumerate(cases):
            source = (
                "import os\n"
                "def run(runtime):\n"
                f"    os.write({fd}, b'x' * 4097)\n"
            )
            with self.subTest(code=code):
                _store, result = self.run_bundle(source, epoch_ref=f"epoch-bridge-overflow-{index:02d}")
                self.assertEqual(result.error_code, code)
                self.assertNotIn("x" * 32, repr(result))

    def test_discovery_and_isolation_qualification_reject_before_bind(self):
        cases = (
            (
                "def run(runtime):\n"
                "    runtime.send_discovery(1, 'bad/name', 'PASS', " + repr(ISOLATION_COMMITMENT) + ")\n",
                "PROTOCOL_FAILURE",
            ),
            (
                "def run(runtime):\n"
                "    runtime.send_discovery(1, 'synthetic-artifact', 'FAIL', " + repr(ISOLATION_COMMITMENT) + ")\n",
                "PROTOCOL_FAILURE",
            ),
            (
                "def run(runtime):\n"
                "    runtime.send_discovery(1, 'synthetic-artifact', 'PASS', 'not-a-commitment')\n",
                "PROTOCOL_FAILURE",
            ),
        )
        for index, (source, code) in enumerate(cases):
            with self.subTest(index=index):
                store, result = self.run_bundle(source, epoch_ref=f"epoch-bridge-discovery-{index:02d}")
                self.assertEqual(result.error_code, code)
                self.assertEqual(result.counters.public()["bind_calls"], 0)
                self.assertEqual(result.counters.public()["discovery_messages"], 0)
                self.assertEqual(store.load_epoch(f"epoch-bridge-discovery-{index:02d}").record["state"], "ABANDONED")

    def test_runtime_duplicate_discovery_is_single_wire_message(self):
        source = (
            "def run(runtime):\n"
            f"    runtime.send_discovery(23, 'synthetic-artifact-001', 'PASS', {ISOLATION_COMMITMENT!r})\n"
            "    runtime.send_discovery(23, 'synthetic-artifact-001', 'PASS', " + repr(ISOLATION_COMMITMENT) + ")\n"
        )
        _store, result = self.run_bundle(source)
        self.assertIn(result.error_code, {"DISCOVERY_DUPLICATE", "PROTOCOL_BROKEN_PIPE"})
        self.assertEqual(result.counters.public()["discovery_messages"], 1)
        self.assertEqual(result.counters.public()["bind_calls"], 1)
        self.assertLessEqual(result.counters.public()["proceed_messages"], 1)
        self.assertTrue(result.post_cas_uncertain)

    def test_remote_crash_after_cas_loses_result_without_retry(self):
        source = (
            "import os\n"
            "def run(runtime):\n"
            f"    runtime.send_discovery(23, 'synthetic-artifact-001', 'PASS', {ISOLATION_COMMITMENT!r})\n"
            "    runtime.wait_for_decision()\n"
            "    os._exit(0)\n"
        )
        store, result = self.run_bundle(source, epoch_ref="epoch-bridge-crash-after-cas")
        self.assertEqual(result.error_code, "PROCESS_EOF")
        self.assertTrue(result.post_cas_uncertain)
        self.assertEqual(result.counters.public()["proceed_messages"], 1)
        self.assertEqual(result.counters.public()["result_messages"], 0)
        snapshot = store.load_epoch("epoch-bridge-crash-after-cas")
        self.assertEqual(snapshot.ledger["state"], "CONSUMED")
        self.assertEqual(snapshot.spool["last_stage"], "ABANDON")

    def test_controller_spawn_crash_abandons_before_cas(self):
        store = self.new_store("epoch-bridge-crash-before-cas")

        def crash_before_spawn():
            raise RuntimeError("synthetic controller crash")

        result = BRIDGE.run_controller_bridge(
            store,
            "epoch-bridge-crash-before-cas",
            BARRIER_UTC,
            BRIDGE.RunnerBundle(valid_runner_source()),
            process_factory=crash_before_spawn,
        )
        self.assertEqual(result.error_code, "PROTOCOL_FAILURE")
        self.assertFalse(result.post_cas_uncertain)
        self.assertEqual(store.load_epoch("epoch-bridge-crash-before-cas").record["state"], "ABANDONED")
        self.assertEqual(result.counters.public()["bind_calls"], 0)

    def test_isolation_commitment_is_bound_into_cas_and_proceed_capability(self):
        source = valid_runner_source()
        store, result = self.run_bundle(source)
        snapshot = store.load_epoch(EPOCH_REF)
        data = {
            "artifact_commitment": snapshot.record["artifact_commitment"],
            "isolation_commitment": ISOLATION_COMMITMENT,
            "runner_bundle_commitment": BRIDGE.RunnerBundle(source).commitment,
        }
        self.assertEqual(
            snapshot.ledger["transition_data_commitment"],
            BRIDGE.STORE._private_data_commitment(data),
        )
        graph = BRIDGE.derive_local_key_graph(
            spool_hmac_key=PRIVATE_V2["spool_hmac_key"],
            salt=PRIVATE_V2["salt"],
            epoch_ref=EPOCH_REF,
            authority_ref=AUTHORITY_REF,
            runner_identity=PRIVATE_V2["runner_identity"],
            bundle=BRIDGE.RunnerBundle(source),
            n_remote=b"r" * 32,
            n_local=b"l" * 32,
        )
        artifact = snapshot.record["artifact_commitment"]
        self.assertNotEqual(
            BRIDGE.proceed_commitment(graph, artifact, ISOLATION_COMMITMENT),
            BRIDGE.proceed_commitment(graph, artifact, BRIDGE.bridge_commitment("isolation", "tampered")),
        )
        self.assertEqual(result.counters.public()["proceed_messages"], 1)

    def test_no_network_or_live_operation_symbols_in_bridge_module(self):
        tree = ast.parse(SOURCE_PATH.read_text(encoding="utf-8"))
        imported_roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".", 1)[0])
        for forbidden in ("socket", "multiprocessing", "http", "urllib", "ftplib", "smtplib", "asyncio", "paramiko", "docker"):
            self.assertNotIn(forbidden, imported_roots)
        source = SOURCE_PATH.read_text(encoding="utf-8").lower()
        self.assertNotIn("paramiko", source)
        self.assertNotIn("known_hosts", source)
        self.assertNotIn("coolify", source)
        self.assertNotIn("requests", source)
