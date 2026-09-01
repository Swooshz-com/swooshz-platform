import ast
import base64
import copy
import ctypes
import importlib.util
import inspect
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
SPEC = importlib.util.spec_from_file_location(
    "platform_recovery_controller_bridge_run318",
    SOURCE_PATH,
)
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
RESULT_COMMITMENT = BRIDGE.bridge_commitment("result", "synthetic-success")
SYNTHETIC_ISOLATION_PROOF = {
    "schema": "bridge-isolation-proof.v1",
    "version": 1,
    "prior_absence": True,
    "volume_id": "run318-volume-001",
    "target_id": "run318-target-001",
    "owner": "run318",
    "effective_isolation": True,
}
SYNTHETIC_ISOLATION_COMMITMENT = BRIDGE.STORE.bytes_commitment(
    "bridge-isolation-proof",
    BRIDGE.STORE.canonical_json_bytes(
        SYNTHETIC_ISOLATION_PROOF,
        max_bytes=BRIDGE.STORE.MAX_RESTORE_LEDGER_BYTES,
    ),
)
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
        advapi32.AddAccessAllowedAceEx.argtypes = [
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.c_ubyte,
            ctypes.c_ulong,
            ctypes.c_void_p,
        ]
        advapi32.AddAccessAllowedAceEx.restype = ctypes.c_int
        advapi32.SetNamedSecurityInfoW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        advapi32.SetNamedSecurityInfoW.restype = ctypes.c_ulong
        acl = ctypes.create_string_buffer(4096)
        if not advapi32.InitializeAcl(acl, len(acl), 2):
            raise unittest.SkipTest("disposable ACL fixture initialization unavailable")
        inheritance = 0x01 | 0x02
        for sid in (current, system, administrators):
            if not advapi32.AddAccessAllowedAceEx(
                acl,
                2,
                inheritance,
                0x1F01FF,
                sid,
            ):
                raise unittest.SkipTest("disposable ACL fixture construction unavailable")
        result = advapi32.SetNamedSecurityInfoW(
            str(root),
            1,
            0x00000004,
            None,
            None,
            ctypes.cast(acl, ctypes.c_void_p),
            None,
        )
        if result != 0:
            raise unittest.SkipTest("disposable ACL fixture assignment unavailable")
    finally:
        kernel32.LocalFree(system)
        kernel32.LocalFree(administrators)
        _ = current_buffer


def bundle(source):
    if isinstance(source, str):
        source = source.encode("utf-8")
    return BRIDGE.RunnerBundle(source, BRIDGE.runner_bundle_commitment(source))


def valid_runner_source(
    *,
    row_id=ARTIFACT_ROW_ID,
    filename=ARTIFACT_FILENAME,
    isolation=ISOLATION_COMMITMENT,
    result=RESULT_COMMITMENT,
    classification="SUCCESS",
):
    return (
        "def run(runtime):\n"
        f"    grant = runtime.discover({row_id!r}, {filename!r}, 'PASS', {isolation!r})\n"
        f"    runtime.send_result(grant, {classification!r}, {result!r})\n"
    )


def frame_stages(store, epoch_ref):
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


class BridgeTestCase(unittest.TestCase):
    def new_store(self, epoch_ref=EPOCH_REF):
        temporary = tempfile.TemporaryDirectory(prefix="run318-controller-bridge-")
        self.addCleanup(temporary.cleanup)
        harden_windows_test_root(pathlib.Path(temporary.name))
        store = BRIDGE.STORE.ControllerStore.for_disposable_test_root(temporary.name)
        store.create_epoch_v2(
            epoch_ref,
            AUTHORITY_REF,
            prebackup_identities=PRIVATE_V2,
        )
        return store

    def run_bundle(self, source, *, decision=None, epoch_ref=EPOCH_REF, timeout_seconds=8.0):
        store = self.new_store(epoch_ref)
        if decision is None:
            result = BRIDGE.run_dummy_controller_bridge(
                store,
                epoch_ref,
                BARRIER_UTC,
                bundle(source),
                timeout_seconds=timeout_seconds,
            )
        else:
            result = BRIDGE.run_dummy_controller_bridge(
                store,
                epoch_ref,
                BARRIER_UTC,
                bundle(source),
                decision=decision,
                timeout_seconds=timeout_seconds,
            )
        return store, result


class ContractTests(BridgeTestCase):
    def test_exact_enums_and_public_runtime_api(self):
        self.assertEqual(
            [item.value for item in BRIDGE.RunnerAbortCode],
            [
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
            ],
        )
        self.assertEqual(
            [item.value for item in BRIDGE.ResultClassification],
            ["SUCCESS", "FAILURE"],
        )
        self.assertEqual(
            [item.value for item in BRIDGE.RunnerControlCode],
            [
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
                "DECISION_EOF",
                "DECISION_TIMEOUT",
                "DECISION_BROKEN_PIPE",
                "PROTOCOL_BROKEN_PIPE",
                "PROCEED_INVALID",
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
            ],
        )
        self.assertEqual(
            BRIDGE.RUNNER_IMPORT_ROOTS,
            frozenset(
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
            ),
        )
        runtime_names = {
            name for name in dir(BRIDGE.RunnerRuntime)
            if not name.startswith("_")
        }
        self.assertEqual(runtime_names, {"barrier_utc", "discover", "abort", "send_result"})
        self.assertNotIn("state", runtime_names)
        self.assertNotIn("send_discovery", runtime_names)
        self.assertNotIn("wait_for_decision", runtime_names)

    def test_bundle_is_exact_bytes_bound_and_source_is_opaque(self):
        source = valid_runner_source().encode()
        commitment = BRIDGE.STORE.bytes_commitment("bridge-runner-bundle", source)
        value = BRIDGE.RunnerBundle(source, commitment)
        hints = __import__("typing").get_type_hints(BRIDGE.RunnerBundle)
        self.assertEqual(
            [(item.name, hints[item.name]) for item in __import__("dataclasses").fields(value)],
            [("source", bytes), ("expected_commitment", str)],
        )
        self.assertNotIn("def run", repr(value))
        self.assertNotIn("def run", str(value))
        self.assertIs(BRIDGE.validate_runner_bundle(value), value)
        with self.assertRaises(BRIDGE.BundleError):
            BRIDGE.RunnerBundle(valid_runner_source(), commitment)
        with self.assertRaises(BRIDGE.BundleError):
            BRIDGE.RunnerBundle(bytearray(source), commitment)
        with self.assertRaises(TypeError):
            BRIDGE.RunnerBundle(source)
        for invalid in (b"\xef\xbb\xbf" + source, b"def run(runtime):\x00\n"):
            with self.assertRaises(BRIDGE.BundleError):
                BRIDGE.RunnerBundle(invalid, BRIDGE.runner_bundle_commitment(invalid))
        with self.assertRaises(BRIDGE.BundleError):
            BRIDGE.RunnerBundle(b"\xff", BRIDGE.runner_bundle_commitment(b"\xff"))

    def test_wire_headers_boot_and_limits_are_exact(self):
        self.assertEqual(BRIDGE.HELLO_STRUCT.format, "!8sBBH32s")
        self.assertEqual(BRIDGE.HELLO_SIZE, 44)
        self.assertEqual(BRIDGE.PREAMBLE_HEADER_STRUCT.format, "!8sBBHHH")
        self.assertEqual(BRIDGE.PREAMBLE_SIZE, 272)
        self.assertEqual(BRIDGE.PREAMBLE_BODY_SIZE, 256)
        self.assertEqual(
            BRIDGE.AUTH_FRAME_HEADER_STRUCT.format,
            "!8sBBBBQ32s16sI",
        )
        self.assertEqual(BRIDGE.MAX_SESSION_FRAMES, 16)
        self.assertEqual(BRIDGE.MAX_SESSION_BYTES, 1048576)
        self.assertEqual(BRIDGE.CONTROL_MAX_BYTES, 4096)
        source = valid_runner_source().encode()
        boot = BRIDGE.encode_boot_payload(bundle(source), BARRIER_UTC)
        self.assertEqual(boot, BARRIER_UTC.encode("ascii") + source)
        self.assertEqual(
            BRIDGE.decode_boot_payload(
                boot,
                expected_barrier=BARRIER_UTC,
                expected_digest=BRIDGE._bundle_digest_bytes(source),
            ),
            source,
        )
        with self.assertRaises(BRIDGE.ProtocolError):
            BRIDGE.decode_boot_payload(
                boot + b"x",
                expected_barrier=BARRIER_UTC,
                expected_digest=BRIDGE._bundle_digest_bytes(source),
            )

    def test_barrier_discovery_and_control_validation(self):
        self.assertEqual(BRIDGE.validate_barrier_utc(BARRIER_UTC), BARRIER_UTC)
        for invalid in (
            "2026-08-31T00:00:00Z",
            "2026-08-31T00:00:00.000000+00:00",
            "2026-02-30T00:00:00.000000Z",
            "2026-08-31T00:00:00.000000z",
        ):
            with self.assertRaises(BRIDGE.ProtocolError):
                BRIDGE.validate_barrier_utc(invalid)
        for row, filename in (
            (True, "a"),
            (0, "a"),
            (-1, "a"),
            (1, "a/b"),
            (1, ".."),
            (1, "a\x00b"),
        ):
            with self.assertRaises(BRIDGE.ProtocolError):
                BRIDGE._validate_discovery_tuple(row, filename)
        discovery = {
            "type": "DISCOVERY",
            "version": 1,
            "execution_row_id": ARTIFACT_ROW_ID,
            "artifact_filename": ARTIFACT_FILENAME,
            "isolation_state": "PASS",
            "isolation_commitment": ISOLATION_COMMITMENT,
        }
        self.assertEqual(BRIDGE.decode_control(BRIDGE.encode_control(discovery)), discovery)
        with self.assertRaises(BRIDGE.ProtocolError):
            BRIDGE.decode_control(BRIDGE.encode_control(discovery)[:-1] + b" ")

    def test_wire_control_schemas_are_exact_and_restore_begin_is_local_only(self):
        graph = self.graph_for_contract()
        controls = [
            {
                "type": "READY",
                "version": 1,
                "barrier_utc": BARRIER_UTC,
            },
            {
                "type": "DISCOVERY",
                "version": 1,
                "execution_row_id": ARTIFACT_ROW_ID,
                "artifact_filename": ARTIFACT_FILENAME,
                "isolation_state": "PASS",
                "isolation_commitment": ISOLATION_COMMITMENT,
            },
            BRIDGE.decode_control(self.proceed_frame(graph).payload),
            {
                "type": "ABORT",
                "version": 1,
                "code": BRIDGE.RunnerControlCode.LOCAL_ABORT.value,
            },
            {
                "type": "RESULT",
                "version": 1,
                "classification": "SUCCESS",
                "result_commitment": RESULT_COMMITMENT,
            },
        ]
        expected_fields = {
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
        }
        for control in controls:
            decoded = BRIDGE.decode_control(BRIDGE.encode_control(control))
            self.assertEqual(tuple(decoded), expected_fields[control["type"]])
            self.assertEqual(decoded, control)
            extra = dict(control)
            extra["extra"] = "candidate-field"
            with self.assertRaises(BRIDGE.ProtocolError):
                BRIDGE.encode_control(extra)
        self.assertFalse(hasattr(BRIDGE, "MESSAGE_RESTORE_BEGIN"))
        with self.assertRaises(BRIDGE.ProtocolError):
            BRIDGE.decode_control(
                b'{"type":"RESTORE_BEGIN","version":1}'
            )

    def graph_for_contract(self, *, barrier=BARRIER_UTC):
        source = valid_runner_source().encode()
        return BRIDGE.derive_local_key_graph(
            spool_hmac_key=PRIVATE_V2["spool_hmac_key"],
            salt=PRIVATE_V2["salt"],
            epoch_ref=EPOCH_REF,
            authority_ref=AUTHORITY_REF,
            runner_identity=PRIVATE_V2["runner_identity"],
            bundle=bundle(source),
            n_remote=b"r" * 32,
            n_local=b"l" * 32,
            barrier_utc=barrier,
        )

    def proceed_frame(self, graph, *, nonce=b"p" * 16):
        artifact = BRIDGE.STORE.recovery_commitment(
            "artifact-row",
            str(ARTIFACT_ROW_ID),
            ARTIFACT_FILENAME,
        )
        isolation = ISOLATION_COMMITMENT
        pre_cas = BRIDGE.bridge_commitment("ledger", "pre")
        transition = BRIDGE.bridge_commitment("transition", "data")
        consumed = BRIDGE.bridge_commitment("record", "consumed")
        transition_id = "bridge-restore-test"
        capability = BRIDGE.proceed_commitment(
            graph,
            artifact,
            isolation,
            transition_id,
            pre_cas,
            transition,
            consumed,
        )
        token = BRIDGE._grant_token(graph, capability)
        payload = BRIDGE.encode_control(
            {
                "type": "PROCEED",
                "version": 1,
                "epoch_digest": BRIDGE._digest_commitment(graph.epoch_digest),
                "authority_digest": BRIDGE._digest_commitment(graph.authority_digest),
                "runner_digest": BRIDGE._digest_commitment(graph.runner_digest),
                "bundle_digest": BRIDGE._digest_commitment(graph.bundle_digest),
                "barrier_utc": BARRIER_UTC,
                "artifact_commitment": artifact,
                "isolation_commitment": isolation,
                "transition_id": transition_id,
                "pre_cas_ledger_digest": pre_cas,
                "transition_data_commitment": transition,
                "consumed_record_digest": consumed,
                "grant": base64.urlsafe_b64encode(token).decode("ascii").rstrip("="),
            }
        )
        return BRIDGE.AuthenticatedFrame(
            BRIDGE.DIRECTION_LOCAL_TO_REMOTE,
            BRIDGE.MESSAGE_PROCEED,
            1,
            graph.n_session,
            nonce,
            payload,
        )

    def test_key_graph_is_sibling_separated_and_binds_barrier(self):
        graph = self.graph_for_contract()
        self.assertTrue(graph.k_bridge_root)
        self.assertNotEqual(graph.k_boot, graph.k_session)
        self.assertNotEqual(graph.k_session, graph.k_proceed)
        self.assertNotEqual(graph.k_boot, graph.k_proceed)
        self.assertEqual(graph.barrier_utc, BARRIER_UTC)
        self.assertEqual(graph.bundle_commitment, BRIDGE.runner_bundle_commitment(valid_runner_source().encode()))
        self.assertNotIn(PRIVATE_V2["spool_hmac_key"], repr(graph))
        graph_without_barrier = BRIDGE.derive_local_key_graph(
            spool_hmac_key=PRIVATE_V2["spool_hmac_key"],
            salt=PRIVATE_V2["salt"],
            epoch_ref=EPOCH_REF,
            authority_ref=AUTHORITY_REF,
            runner_identity=PRIVATE_V2["runner_identity"],
            bundle=bundle(valid_runner_source()),
            n_remote=b"r" * 32,
            n_local=b"l" * 32,
        )
        self.assertNotEqual(graph.k_session, graph_without_barrier.k_session)
        self.assertNotEqual(graph.k_proceed, graph_without_barrier.k_proceed)

    def test_preamble_commitment_bindings_are_consistent_and_required(self):
        graph = self.graph_for_contract()
        preamble = {
            name: getattr(graph, name)
            for name in BRIDGE.PREAMBLE_FIELDS
        }
        for argument, domain in (
            ("record_commitment", "record"),
            ("authority_commitment", "authority"),
            ("runner_commitment", "runner"),
        ):
            with self.assertRaises(BRIDGE.ProtocolError) as raised:
                BRIDGE.derive_key_graph_from_preamble(
                    preamble,
                    barrier_utc=BARRIER_UTC,
                    **{argument: BRIDGE.bridge_commitment("mismatch", domain)},
                )
            self.assertEqual(raised.exception.code, "PREAMBLE_INVALID")
        with self.assertRaises(BRIDGE.ProtocolError) as raised:
            BRIDGE.derive_key_graph_from_preamble(
                preamble,
                barrier_utc=BARRIER_UTC,
                loader_commitment="not-a-commitment",
            )
        self.assertEqual(raised.exception.code, "PREAMBLE_INVALID")

        incomplete = dict(preamble)
        del incomplete["bootstrap_seed"]
        with self.assertRaises(BRIDGE.ProtocolError) as raised:
            BRIDGE.derive_key_graph_from_preamble(incomplete)
        self.assertEqual(raised.exception.code, "PREAMBLE_INVALID")

    def test_transition_is_canonical_and_every_capability_input_changes_it(self):
        graph = self.graph_for_contract()
        values = {
            "epoch_ref": EPOCH_REF,
            "authority_ref": AUTHORITY_REF,
            "runner_commitment": graph.runner_commitment,
            "runner_bundle_commitment": graph.bundle_commitment,
            "barrier_utc": BARRIER_UTC,
            "artifact_commitment": BRIDGE.STORE.recovery_commitment(
                "artifact-row",
                str(ARTIFACT_ROW_ID),
                ARTIFACT_FILENAME,
            ),
            "isolation_commitment": ISOLATION_COMMITMENT,
            "pre_cas_ledger_digest": BRIDGE.bridge_commitment("ledger", "pre"),
        }
        transition, transition_id, transition_commitment = BRIDGE.build_restore_transition(**values)
        self.assertEqual(
            tuple(transition),
            (
                "schema",
                "version",
                "epoch_ref",
                "authority_ref",
                "runner_commitment",
                "runner_bundle_commitment",
                "barrier_utc",
                "artifact_commitment",
                "isolation_commitment",
                "pre_cas_ledger_digest",
                "transition_id",
            ),
        )
        self.assertEqual(transition["transition_id"], transition_id)
        self.assertEqual(
            transition_commitment,
            BRIDGE.STORE.bytes_commitment(
                "restore-ledger-transition",
                BRIDGE.STORE.canonical_json_bytes(
                    transition,
                    max_bytes=BRIDGE.STORE.MAX_RESTORE_LEDGER_BYTES,
                ),
            ),
        )
        base_capability = BRIDGE.proceed_commitment(
            graph,
            values["artifact_commitment"],
            values["isolation_commitment"],
            transition_id,
            values["pre_cas_ledger_digest"],
            transition_commitment,
            BRIDGE.bridge_commitment("record", "consumed"),
        )
        self.assertTrue(base_capability.startswith("sha256:v1:"))
        for field in (
            "artifact_commitment",
            "isolation_commitment",
            "pre_cas_ledger_digest",
        ):
            altered = dict(values)
            altered[field] = BRIDGE.bridge_commitment("changed", field)
            _, altered_id, altered_commitment = BRIDGE.build_restore_transition(**altered)
            altered_capability = BRIDGE.proceed_commitment(
                graph,
                altered["artifact_commitment"],
                altered["isolation_commitment"],
                altered_id,
                altered["pre_cas_ledger_digest"],
                altered_commitment,
                BRIDGE.bridge_commitment("record", "consumed"),
            )
            self.assertNotEqual(altered_id, transition_id)
            self.assertNotEqual(altered_commitment, transition_commitment)
            self.assertNotEqual(altered_capability, base_capability)

    def test_process_finality_requires_all_clean_terminal_evidence(self):
        defaults = {
            "exit_code": BRIDGE.EXIT_SUCCESS,
            "natural_exit": True,
            "stdout_eof": True,
            "stderr_eof": True,
            "stdout_trailing_bytes": 0,
            "stderr_bytes": 0,
            "stdout_overflow": False,
            "stderr_overflow": False,
            "termination_uncertain": False,
        }

        def evidence(**changes):
            value = dict(defaults)
            value.update(changes)
            return BRIDGE.ProcessTerminalEvidence(**value)

        self.assertIsNone(BRIDGE.ProcessSupervisor.finality_error(evidence()))
        for changes, expected in (
            ({"stderr_bytes": 1}, "PROCESS_STDERR_FORBIDDEN"),
            ({"stdout_trailing_bytes": 1}, "PROCESS_TRAILING_OUTPUT"),
            ({"stdout_overflow": True}, "PROCESS_CAPTURE_OVERFLOW"),
            ({"termination_uncertain": True}, "PROCESS_TERMINATION_UNCERTAIN"),
            ({"natural_exit": False}, "PROCESS_TERMINATION_UNCERTAIN"),
            ({"exit_code": BRIDGE.EXIT_PROTOCOL_FAILURE}, "PROCESS_EXIT_NONZERO"),
        ):
            self.assertEqual(
                BRIDGE.ProcessSupervisor.finality_error(evidence(**changes)),
                expected,
            )

    def test_remote_hello_challenge_is_checked_before_boot_or_source(self):
        n_remote = b"x" * BRIDGE.SESSION_NONCE_BYTES
        n_local = b"l" * BRIDGE.SESSION_NONCE_BYTES
        seed = b"s" * BRIDGE.KEY_BYTES
        digests = [bytes([value]) * BRIDGE.KEY_BYTES for value in range(1, 5)]
        n_session = BRIDGE._derive_key(
            seed,
            BRIDGE.K_SESSION_NONCE_DOMAIN,
            n_remote,
            n_local,
            *digests,
        )
        preamble = BRIDGE.encode_preamble(
            n_remote,
            n_local,
            n_session,
            *digests,
            seed,
        )
        output = io.BytesIO()
        loader = BRIDGE.RemoteLoader(
            io.BytesIO(preamble),
            output,
            randomness=lambda size: b"r" * size,
        )
        self.assertEqual(loader.run(), BRIDGE.EXIT_PROTOCOL_FAILURE)
        self.assertEqual(BRIDGE.decode_hello(output.getvalue()), b"r" * 32)

    def test_fixed_loader_is_public_python3_dash_c_without_private_path(self):
        source = BRIDGE.build_fixed_loader_source()
        compile(source.decode("ascii"), "<fixed-loader-test>", "exec", dont_inherit=True)
        command = BRIDGE.build_fixed_loader_command()
        self.assertEqual(len(command), 3)
        self.assertEqual(command[:2], ("python3", "-c"))
        self.assertEqual(command[2], BRIDGE.FIXED_LOADER_SOURCE)
        self.assertNotIn(str(SOURCE_PATH).encode(), source)
        self.assertNotIn(b"--dummy-child", source)
        for private_value in PRIVATE_V2.values():
            self.assertNotIn(private_value.encode(), source)

    def test_operational_entrypoint_requires_caller_launcher_and_local_compile_only(self):
        controller_parameters = inspect.signature(BRIDGE.ControllerBridge).parameters
        run_parameters = inspect.signature(BRIDGE.run_controller_bridge).parameters
        self.assertIs(
            controller_parameters["launcher"].default,
            inspect.Parameter.empty,
        )
        self.assertIs(
            run_parameters["launcher"].default,
            inspect.Parameter.empty,
        )
        self.assertNotIn("decision", run_parameters)
        with self.assertRaises(TypeError):
            BRIDGE.run_controller_bridge(
                None,
                EPOCH_REF,
                BARRIER_UTC,
                bundle(b"pass\n"),
            )

        invalid_source = b"def run(:\n"
        invalid_bundle = BRIDGE.RunnerBundle(
            invalid_source,
            BRIDGE.runner_bundle_commitment(invalid_source),
        )
        with self.assertRaises(BRIDGE.BundleError) as raised:
            BRIDGE.validate_runner_bundle(invalid_bundle)
        self.assertEqual(raised.exception.code, "BUNDLE_COMPILE_FAILED")
        with self.assertRaises(BRIDGE.BundleError):
            BRIDGE.encode_boot_payload(invalid_bundle, BARRIER_UTC)

    def test_frame_nonce_replay_fails_even_with_new_sequence(self):
        graph = self.graph_for_contract()
        payload = BRIDGE.encode_control(
            {"type": "READY", "version": 1, "barrier_utc": BARRIER_UTC}
        )
        nonce = b"n" * 16
        first = BRIDGE.encode_authenticated_frame(
            graph.k_session,
            BRIDGE.DIRECTION_REMOTE_TO_LOCAL,
            BRIDGE.MESSAGE_READY,
            1,
            graph.n_session,
            payload,
            frame_nonce=nonce,
        )
        second = BRIDGE.encode_authenticated_frame(
            graph.k_session,
            BRIDGE.DIRECTION_REMOTE_TO_LOCAL,
            BRIDGE.MESSAGE_READY,
            2,
            graph.n_session,
            payload,
            frame_nonce=nonce,
        )
        channel = BRIDGE._RemoteChannel(io.BytesIO(first + second), io.BytesIO(), graph)
        channel.receive(graph.k_session, BRIDGE.DIRECTION_REMOTE_TO_LOCAL)
        with self.assertRaises(BRIDGE.RunnerControlError) as raised:
            channel.receive(graph.k_session, BRIDGE.DIRECTION_REMOTE_TO_LOCAL)
        self.assertIs(raised.exception.code, BRIDGE.RunnerControlCode.PROTOCOL_FAILURE)


class RuntimeTests(BridgeTestCase):
    class FakeChannel:
        def __init__(self, graph, incoming=None):
            self.graph = graph
            self.sent = []
            self.incoming = list(incoming or [])

        def send(self, key, direction, message, payload):
            self.sent.append((key, direction, message, payload))

        def receive(self, key, direction, *, timeout=None):
            if not self.incoming:
                raise AssertionError("fake channel has no incoming frame")
            return self.incoming.pop(0)

    def graph_for_contract(self):
        source = valid_runner_source().encode()
        return BRIDGE.derive_local_key_graph(
            spool_hmac_key=PRIVATE_V2["spool_hmac_key"],
            salt=PRIVATE_V2["salt"],
            epoch_ref=EPOCH_REF,
            authority_ref=AUTHORITY_REF,
            runner_identity=PRIVATE_V2["runner_identity"],
            bundle=bundle(source),
            n_remote=b"r" * 32,
            n_local=b"l" * 32,
            barrier_utc=BARRIER_UTC,
        )

    def proceed_frame(self, graph, *, nonce=b"p" * 16):
        artifact = BRIDGE.STORE.recovery_commitment(
            "artifact-row",
            str(ARTIFACT_ROW_ID),
            ARTIFACT_FILENAME,
        )
        isolation = ISOLATION_COMMITMENT
        pre_cas = BRIDGE.bridge_commitment("ledger", "pre")
        transition = BRIDGE.bridge_commitment("transition", "data")
        consumed = BRIDGE.bridge_commitment("record", "consumed")
        transition_id = "bridge-restore-test"
        capability = BRIDGE.proceed_commitment(
            graph,
            artifact,
            isolation,
            transition_id,
            pre_cas,
            transition,
            consumed,
        )
        token = BRIDGE._grant_token(graph, capability)
        payload = BRIDGE.encode_control(
            {
                "type": "PROCEED",
                "version": 1,
                "epoch_digest": BRIDGE._digest_commitment(graph.epoch_digest),
                "authority_digest": BRIDGE._digest_commitment(graph.authority_digest),
                "runner_digest": BRIDGE._digest_commitment(graph.runner_digest),
                "bundle_digest": BRIDGE._digest_commitment(graph.bundle_digest),
                "barrier_utc": BARRIER_UTC,
                "artifact_commitment": artifact,
                "isolation_commitment": isolation,
                "transition_id": transition_id,
                "pre_cas_ledger_digest": pre_cas,
                "transition_data_commitment": transition,
                "consumed_record_digest": consumed,
                "grant": base64.urlsafe_b64encode(token).decode("ascii").rstrip("="),
            }
        )
        return BRIDGE.AuthenticatedFrame(
            BRIDGE.DIRECTION_LOCAL_TO_REMOTE,
            BRIDGE.MESSAGE_PROCEED,
            1,
            graph.n_session,
            nonce,
            payload,
        )

    def runtime(self, incoming=None):
        graph = self.graph_for_contract()
        channel = self.FakeChannel(graph, incoming)
        runtime = BRIDGE.RunnerRuntime(channel, BARRIER_UTC, decision_timeout=0.01)
        runtime._state = runtime._RUNNING
        return runtime, channel, graph

    def test_discover_is_one_wire_message_and_result_is_one_use(self):
        graph = self.graph_for_contract()
        runtime, channel, _ = self.runtime([self.proceed_frame(graph)])
        grant = runtime.discover(
            ARTIFACT_ROW_ID,
            ARTIFACT_FILENAME,
            "PASS",
            ISOLATION_COMMITMENT,
        )
        self.assertEqual(len(channel.sent), 1)
        runtime.send_result(grant, "SUCCESS", RESULT_COMMITMENT)
        self.assertEqual(len(channel.sent), 2)
        with self.assertRaises(BRIDGE.RunnerControlError) as raised:
            runtime.send_result(grant, "SUCCESS", RESULT_COMMITMENT)
        self.assertIs(raised.exception.code, BRIDGE.RunnerControlCode.RESULT_DUPLICATE)

    def test_grant_is_opaque_unforgeable_and_abort_is_typed(self):
        graph = self.graph_for_contract()
        runtime, _channel, _ = self.runtime([self.proceed_frame(graph)])
        grant = runtime.discover(
            ARTIFACT_ROW_ID,
            ARTIFACT_FILENAME,
            "PASS",
            ISOLATION_COMMITMENT,
        )
        self.assertEqual(repr(grant), "<ProceedGrant opaque>")
        self.assertNotIn(PRIVATE_V2["spool_hmac_key"], repr(grant))
        with self.assertRaises(TypeError):
            BRIDGE.ProceedGrant()
        forged = BRIDGE.ProceedGrant(BRIDGE.ProceedGrant._SEAL)
        with self.assertRaises(BRIDGE.RunnerControlError) as raised:
            runtime.send_result(forged, "SUCCESS", RESULT_COMMITMENT)
        self.assertIs(raised.exception.code, BRIDGE.RunnerControlCode.PROCEED_INVALID)

        runtime, channel, _ = self.runtime()
        with self.assertRaises(BRIDGE.RunnerControlError) as raised:
            runtime.abort(BRIDGE.RunnerAbortCode.LOCATOR_NOT_FOUND)
        self.assertIs(raised.exception.code, BRIDGE.RunnerControlCode.LOCATOR_NOT_FOUND)
        self.assertEqual(channel.sent[0][2], BRIDGE.MESSAGE_ABORT)
        with self.assertRaises(BRIDGE.RunnerControlError) as raised:
            runtime.abort(BRIDGE.RunnerAbortCode.LOCATOR_NOT_FOUND)
        self.assertIs(raised.exception.code, BRIDGE.RunnerControlCode.RUNTIME_TERMINAL)

    def test_discover_validates_before_emitting_and_result_requires_grant(self):
        runtime, channel, _ = self.runtime()
        with self.assertRaises(BRIDGE.RunnerControlError) as raised:
            runtime.discover(True, ARTIFACT_FILENAME, "PASS", ISOLATION_COMMITMENT)
        self.assertIs(raised.exception.code, BRIDGE.RunnerControlCode.PROTOCOL_FAILURE)
        self.assertEqual(channel.sent, [])
        with self.assertRaises(BRIDGE.RunnerControlError) as raised:
            runtime.send_result(None, "SUCCESS", RESULT_COMMITMENT)
        self.assertIs(raised.exception.code, BRIDGE.RunnerControlCode.RESULT_BEFORE_PROCEED)

    def test_proceed_tamper_and_session_mismatch_fail_closed(self):
        graph = self.graph_for_contract()
        frame = self.proceed_frame(graph)
        decoded = json.loads(frame.payload.decode("utf-8"))
        decoded["isolation_commitment"] = BRIDGE.bridge_commitment("isolation", "tampered")
        bad = BRIDGE.AuthenticatedFrame(
            frame.direction,
            frame.message,
            frame.sequence,
            frame.session_nonce,
            frame.frame_nonce,
            BRIDGE.encode_control(decoded),
        )
        runtime, _channel, _ = self.runtime([bad])
        with self.assertRaises(BRIDGE.RunnerControlError) as raised:
            runtime.discover(
                ARTIFACT_ROW_ID,
                ARTIFACT_FILENAME,
                "PASS",
                ISOLATION_COMMITMENT,
            )
        self.assertIs(raised.exception.code, BRIDGE.RunnerControlCode.PROCEED_INVALID)


class DummyChildMatrixTests(BridgeTestCase):
    def test_success_waits_for_natural_clean_process_finality_before_commit(self):
        store, result = self.run_bundle(valid_runner_source())
        self.assertEqual(result.classification, "SUCCESS")
        self.assertEqual(result.state, "CONSUMED")
        self.assertIsNone(result.error_code)
        self.assertFalse(result.post_cas_uncertain)
        self.assertEqual(
            frame_stages(store, EPOCH_REF),
            ["EPOCH_READY", "RUNNER_STARTED", "RESTORE_BEGIN", "COMMIT"],
        )
        snapshot = store.load_epoch(EPOCH_REF)
        self.assertEqual(snapshot.ledger["state"], "CONSUMED")
        self.assertEqual(snapshot.spool["last_stage"], "COMMIT")
        self.assertEqual(result.counters.public()["bind_calls"], 1)
        self.assertEqual(result.counters.public()["proceed_messages"], 1)
        self.assertEqual(result.counters.public()["discovery_messages"], 1)
        self.assertEqual(result.counters.public()["result_messages"], 1)
        for name in (
            "ssh_launches",
            "network_connections",
            "provider_calls",
            "backup_calls",
            "restore_attempts",
        ):
            self.assertEqual(result.counters.public()[name], 0)

    def test_result_success_followed_by_non_none_return_cannot_commit(self):
        source = valid_runner_source() + "    return 'invalid-after-success'\n"
        store, result = self.run_bundle(
            source,
            epoch_ref="epoch-bridge-non-none-after-success",
        )
        self.assertEqual(result.classification, "FAILURE")
        self.assertEqual(result.error_code, "PROCESS_EXIT_NONZERO")
        self.assertTrue(result.post_cas_uncertain)
        snapshot = store.load_epoch("epoch-bridge-non-none-after-success")
        self.assertEqual(snapshot.ledger["state"], "CONSUMED")
        self.assertEqual(snapshot.spool["last_stage"], "ABANDON")
        self.assertNotIn("COMMIT", frame_stages(store, "epoch-bridge-non-none-after-success"))

    def test_result_failure_is_evidence_and_store_abandons_cleanly(self):
        source = valid_runner_source(classification="FAILURE")
        store, result = self.run_bundle(
            source,
            epoch_ref="epoch-bridge-runner-failure",
        )
        self.assertEqual(result.classification, "FAILURE")
        self.assertIsNone(result.error_code)
        self.assertFalse(result.post_cas_uncertain)
        snapshot = store.load_epoch("epoch-bridge-runner-failure")
        self.assertEqual(snapshot.record["state"], "ABANDONED")
        self.assertEqual(snapshot.ledger["state"], "CONSUMED")
        self.assertEqual(snapshot.spool["last_stage"], "ABANDON")

    def test_result_success_with_unframed_output_cannot_commit(self):
        source = (
            "import os\n"
            + valid_runner_source()
            + "    os.write(1, b'unframed-protocol-output')\n"
            + "    os.write(2, b'unexpected-runner-stderr')\n"
        )
        store, result = self.run_bundle(
            source,
            epoch_ref="epoch-bridge-unframed-output",
        )
        self.assertEqual(result.classification, "FAILURE")
        self.assertEqual(result.error_code, "PROCESS_EXIT_NONZERO")
        self.assertTrue(result.post_cas_uncertain)
        snapshot = store.load_epoch("epoch-bridge-unframed-output")
        self.assertEqual(snapshot.ledger["state"], "CONSUMED")
        self.assertEqual(snapshot.spool["last_stage"], "ABANDON")
        self.assertNotIn("COMMIT", frame_stages(store, "epoch-bridge-unframed-output"))

    def test_capture_overflow_after_result_cannot_commit(self):
        source = (
            "import os\n"
            + valid_runner_source()
            + "    os.write(1, b'x' * 5000)\n"
        )
        store, result = self.run_bundle(
            source,
            epoch_ref="epoch-bridge-capture-overflow",
        )
        self.assertEqual(result.classification, "FAILURE")
        self.assertEqual(result.error_code, "PROCESS_EXIT_NONZERO")
        self.assertTrue(result.post_cas_uncertain)
        snapshot = store.load_epoch("epoch-bridge-capture-overflow")
        self.assertEqual(snapshot.ledger["state"], "CONSUMED")
        self.assertEqual(snapshot.spool["last_stage"], "ABANDON")
        self.assertNotIn("COMMIT", frame_stages(store, "epoch-bridge-capture-overflow"))

    def test_runner_abort_and_invalid_discovery_are_pre_cas_and_single_shot(self):
        source = (
            "def run(runtime):\n"
            "    runtime.abort(RunnerAbortCode.PRESTATE_FAILED)\n"
        )
        store, result = self.run_bundle(
            source,
            epoch_ref="epoch-bridge-runner-abort",
        )
        self.assertEqual(result.error_code, "PRESTATE_FAILED")
        self.assertEqual(result.counters.public()["bind_calls"], 0)
        self.assertEqual(store.load_epoch("epoch-bridge-runner-abort").record["state"], "ABANDONED")

        source = (
            "def run(runtime):\n"
            f"    runtime.discover(True, {ARTIFACT_FILENAME!r}, 'PASS', {ISOLATION_COMMITMENT!r})\n"
        )
        store, result = self.run_bundle(
            source,
            epoch_ref="epoch-bridge-invalid-discovery",
        )
        self.assertEqual(result.error_code, "PROTOCOL_FAILURE")
        self.assertEqual(result.counters.public()["bind_calls"], 0)
        self.assertEqual(
            store.load_epoch("epoch-bridge-invalid-discovery").record["state"],
            "ABANDONED",
        )

    def test_integrated_synthetic_isolation_proof_reaches_discovery(self):
        source = (
            "import hashlib\n"
            "import json\n"
            "resources = {'volume': None, 'target': None, 'owner': None, 'created': 0}\n"
            "def _lp(value):\n"
            "    raw = value.encode('utf-8')\n"
            "    return len(raw).to_bytes(4, 'big') + raw\n"
            "def _bytes_commitment(domain, payload):\n"
            "    framed = _lp('recovery-commitment.v1') + _lp(domain)\n"
            "    framed += len(payload).to_bytes(4, 'big') + payload\n"
            "    return 'sha256:v1:' + hashlib.sha256(framed).hexdigest()\n"
            "def run(runtime):\n"
            "    proof = {\n"
            "        'schema': 'bridge-isolation-proof.v1',\n"
            "        'version': 1,\n"
            "        'prior_absence': True,\n"
            "        'volume_id': 'run318-volume-001',\n"
            "        'target_id': 'run318-target-001',\n"
            "        'owner': 'run318',\n"
            "        'effective_isolation': True,\n"
            "    }\n"
            "    if resources['volume'] is not None or resources['target'] is not None:\n"
            "        runtime.abort(RunnerAbortCode.RESOURCE_COLLISION)\n"
            "    resources['volume'] = proof['volume_id']\n"
            "    resources['target'] = proof['target_id']\n"
            "    resources['owner'] = proof['owner']\n"
            "    resources['created'] += 1\n"
            "    if resources['created'] != 1 or resources['owner'] != proof['owner']:\n"
            "        runtime.abort(RunnerAbortCode.RESOURCE_CREATE_FAILED)\n"
            "    proof_payload = (json.dumps(proof, ensure_ascii=False, separators=(',', ':')) + '\\n').encode('utf-8')\n"
            "    isolation = _bytes_commitment('bridge-isolation-proof', proof_payload)\n"
            "    if isolation != " + repr(SYNTHETIC_ISOLATION_COMMITMENT) + " or not proof['effective_isolation']:\n"
            "        runtime.abort(RunnerAbortCode.ISOLATION_FAILED)\n"
            "    cleanup_proven = False\n"
            "    try:\n"
            f"        grant = runtime.discover({ARTIFACT_ROW_ID!r}, {ARTIFACT_FILENAME!r}, 'PASS', isolation)\n"
            f"        runtime.send_result(grant, 'SUCCESS', {RESULT_COMMITMENT!r})\n"
            "    finally:\n"
            "        if (resources['owner'] == proof['owner']\n"
            "                and resources['target'] == proof['target_id']\n"
            "                and resources['volume'] == proof['volume_id']):\n"
            "            resources['target'] = None\n"
            "            resources['volume'] = None\n"
            "            resources['owner'] = None\n"
            "            cleanup_proven = True\n"
            "    if not cleanup_proven or resources['target'] is not None or resources['volume'] is not None:\n"
            "        raise RuntimeError('cleanup proof failed')\n"
        )
        store, result = self.run_bundle(
            source,
            epoch_ref="epoch-bridge-isolation-integrated",
        )
        self.assertEqual(result.classification, "SUCCESS")
        self.assertEqual(result.counters.public()["discovery_messages"], 1)
        self.assertEqual(
            store.load_epoch("epoch-bridge-isolation-integrated").record["state"],
            "CONSUMED",
        )

    def test_isolation_collision_missing_and_non_pass_block_cas_and_proceed(self):
        cases = (
            (
                "epoch-bridge-isolation-collision",
                "resources = {'volume': 'pre-existing', 'target': None}\n"
                "def run(runtime):\n"
                "    if resources['volume'] is not None:\n"
                "        runtime.abort(RunnerAbortCode.RESOURCE_COLLISION)\n",
                "RESOURCE_COLLISION",
            ),
            (
                "epoch-bridge-isolation-non-pass",
                "def run(runtime):\n"
                f"    runtime.discover({ARTIFACT_ROW_ID!r}, {ARTIFACT_FILENAME!r}, 'FAIL', {ISOLATION_COMMITMENT!r})\n",
                "ISOLATION_FAILED",
            ),
            (
                "epoch-bridge-isolation-missing",
                "def run(runtime):\n"
                f"    runtime.discover({ARTIFACT_ROW_ID!r}, {ARTIFACT_FILENAME!r}, 'PASS', None)\n",
                "ISOLATION_FAILED",
            ),
        )
        for epoch_ref, source, error_code in cases:
            store, result = self.run_bundle(source, epoch_ref=epoch_ref)
            self.assertEqual(result.error_code, error_code)
            self.assertEqual(result.counters.public()["discovery_messages"], 0)
            self.assertEqual(result.counters.public()["bind_calls"], 0)
            self.assertEqual(result.counters.public()["proceed_messages"], 0)
            self.assertEqual(store.load_epoch(epoch_ref).record["state"], "ABANDONED")

    def test_test_only_post_cas_abort_is_not_operational_api(self):
        store, result = self.run_bundle(
            valid_runner_source(),
            decision=BRIDGE.DummyDecision.deny(BRIDGE.RunnerControlCode.LOCAL_ABORT),
            epoch_ref="epoch-bridge-test-only-deny",
        )
        self.assertEqual(result.classification, "FAILURE")
        self.assertEqual(result.error_code, "LOCAL_ABORT")
        self.assertTrue(result.post_cas_uncertain)
        snapshot = store.load_epoch("epoch-bridge-test-only-deny")
        self.assertEqual(snapshot.ledger["state"], "CONSUMED")
        self.assertEqual(snapshot.spool["last_stage"], "ABANDON")
