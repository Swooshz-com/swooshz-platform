import json
import importlib.util
import inspect
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


CONTROLLER = load("swz_test_controller", ROOT / "recovery/managed/controller.py")
QUALIFY = load("swz_test_qualify", ROOT / "recovery/managed/qualify.py")


class ControllerIntegrationTests(unittest.TestCase):
    def context(self):
        return CONTROLLER.make_admitted_context("11" * 32, "22" * 32, "33" * 32)

    def test_store_is_unavailable_before_matching_remote_accept(self):
        controller = CONTROLLER.ManagedController(self.context())
        self.assertIsNone(controller.store)
        with self.assertRaises(CONTROLLER.ControllerError):
            controller._require_accepted()
        with self.assertRaises(CONTROLLER.ControllerError):
            controller.accept()
        self.assertIsNone(controller.store)

    def test_cas_is_real_and_uncertainty_sticks_when_native_provider_is_absent(self):
        with tempfile.TemporaryDirectory(prefix="swz-controller-test-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "qualified-artifact"
            target = root / "restore-target"
            store_root = QUALIFY.make_private_store_root(root)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(store_root.stat().st_mode), 0o700)
            source.write_bytes(b"disposable-qualified-artifact\n")
            controller = CONTROLLER.ManagedController(self.context())
            accepted = CONTROLLER.BACKEND.wire_kat_frames(
                controller.n_local,
                session=bytes.fromhex(controller.context.session_hex),
                connection=bytes.fromhex(controller.context.accepted_connection_hex),
            )[-1]
            controller.accept(accepted)
            with self.assertRaises(CONTROLLER.QualificationProviderHold):
                controller.run(store_root=store_root, artifact_source=source, artifact_target=target, agent_binary=root / "missing-swz-agent")
            self.assertIsNotNone(controller.store)
            self.assertEqual(controller.store.read_restore_ledger("epoch-qualified-001")["state"], "CONSUMED")
            self.assertEqual(controller.store.ledger_safety_classification("epoch-qualified-001"), "CONSUMED")
            self.assertFalse(target.exists())

    def test_qualification_defers_exact_native_boundary_after_durable_store_proof(self):
        class FakeProviderHold(RuntimeError):
            pass

        class FakeFilesystemSafetyError(RuntimeError):
            pass

        class FakeStore:
            def read_restore_ledger(self, epoch_ref):
                self.ledger_epoch_ref = epoch_ref
                return {"state": "CONSUMED"}

            def load_epoch(self, epoch_ref):
                self.loaded_epoch_ref = epoch_ref
                return SimpleNamespace(
                    ledger={"state": "CONSUMED"},
                    record={
                        "state": "ACTIVE",
                        "durability": {
                            "file_flush_verified": True,
                            "readback_verified": True,
                            "atomic_authority_transition": True,
                            "directory_flush_verified": True,
                        },
                    },
                    spool={"state": "OPEN", "last_stage": "RESTORE_BEGIN"},
                )

        context = SimpleNamespace(
            session_hex="99" * 32,
            generation_hex="aa" * 32,
            accepted_connection_hex="bb" * 32,
        )

        class FakeBackend:
            @staticmethod
            def wire_kat_frames(*args, **kwargs):
                return [object()]

        class FakeManagedController:
            def __init__(self, admitted_context):
                self.context = admitted_context
                self.n_local = bytes(32)
                self.store = None

            def accept(self, frame):
                self.accepted_frame = frame

            def run(self, **kwargs):
                self.store = FakeStore()
                raise FakeProviderHold("supervisor-provider-required")

        fake_controller = SimpleNamespace(
            QualificationProviderHold=FakeProviderHold,
            STORE=SimpleNamespace(FilesystemSafetyError=FakeFilesystemSafetyError),
            BACKEND=FakeBackend(),
            make_admitted_context=lambda *args, **kwargs: context,
            ManagedController=FakeManagedController,
        )
        with tempfile.TemporaryDirectory(prefix="swz-qualification-test-") as temporary:
            with mock.patch.object(QUALIFY, "load_module", return_value=fake_controller):
                result = QUALIFY.run_store_cas_locator_integration(pathlib.Path(temporary) / "build")
        self.assertEqual(result["status"], "DEFERRED_TO_GUEST")
        self.assertNotEqual(result["status"], "PASS")
        self.assertEqual(result["reason"], "supervisor-provider-required")
        self.assertEqual(result["ledger_state"], "CONSUMED")
        self.assertEqual(result["record_state"], "ACTIVE")
        self.assertEqual(result["spool_state"], "OPEN")
        self.assertEqual(result["spool_stage"], "RESTORE_BEGIN")
        self.assertTrue(all(result["durability"].values()))

    def test_preflight_deferral_never_synthesizes_security_success(self):
        candidate_sha = "a" * 40
        results = {
            "exact_scope": {"tracked_paths": [], "tracked_count": 41, "path_ceiling": 41, "untracked_output": []},
            "canonical_store_locator_equality": {"files": [], "byte_equal": True},
            "run_result_ownership_static": {"status": "PASS", "PYTHON_FABRICATED_RESULT": "ABSENT"},
            "run_host_boundary_static": {"status": "PASS"},
            "run_deterministic_tests": {"status": "PASS"},
            "run_native_c11_build": {"status": "PASS"},
            "run_native_static_closure": {"status": "PASS"},
            "run_c_native_kat": {"status": "PASS"},
            "run_python_identity_agreement": {"status": "PASS"},
            "run_store_cas_locator_integration": {
                "status": "DEFERRED_TO_GUEST",
                "ledger_state": "CONSUMED",
                "record_state": "ACTIVE",
                "spool_state": "OPEN",
                "spool_stage": "RESTORE_BEGIN",
            },
            "run_application_gates": {"status": "DELEGATED_TO_CI"},
            "run_container_build": {"status": "DELEGATED_TO_CI"},
        }

        def fake_run(command, **kwargs):
            self.assertEqual(command, ["git", "rev-parse", "HEAD"])
            return subprocess.CompletedProcess(command, 0, candidate_sha + "\n", "")

        with tempfile.TemporaryDirectory(prefix="swz-preflight-test-") as temporary:
            output = pathlib.Path(temporary) / "preflight.json"
            build_output = pathlib.Path(temporary) / "build"
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(QUALIFY, "run", side_effect=fake_run))
                stack.enter_context(mock.patch.dict(os.environ, {}, clear=False))
                for name, value in results.items():
                    stack.enter_context(mock.patch.object(QUALIFY, name, return_value=value))
                status = QUALIFY.main([
                    "--phase", "preflight", "--expected-sha", candidate_sha,
                    "--output", str(output), "--build-output", str(build_output),
                ])
            evidence = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(status, 0)
        self.assertEqual(evidence["store_cas_locator"]["status"], "DEFERRED_TO_GUEST")
        self.assertEqual(evidence["mandatory_security_skips"], "NOT_YET_PROVEN")
        self.assertNotIn("guest", evidence)
        self.assertEqual(evidence["guest_deferred"], list(QUALIFY.GUEST_PROOF_CASES))

    def test_guest_phase_rejects_missing_security_proof_after_preflight_deferral(self):
        candidate_sha = "b" * 40
        results = {
            "exact_scope": {"tracked_paths": [], "tracked_count": 41, "path_ceiling": 41, "untracked_output": []},
            "canonical_store_locator_equality": {"files": [], "byte_equal": True},
            "run_result_ownership_static": {"status": "PASS", "PYTHON_FABRICATED_RESULT": "ABSENT"},
            "run_host_boundary_static": {"status": "PASS"},
            "run_deterministic_tests": {"status": "PASS"},
            "run_native_c11_build": {"status": "PASS"},
            "run_native_static_closure": {"status": "PASS"},
            "run_c_native_kat": {"status": "PASS"},
            "run_python_identity_agreement": {"status": "PASS"},
            "run_store_cas_locator_integration": {"status": "DEFERRED_TO_GUEST"},
            "run_build": {"status": "PASS"},
            "run_locator_integration": {"status": "PASS"},
            "run_guest": {"mandatory_security_skips": 1},
        }

        def fake_run(command, **kwargs):
            self.assertEqual(command, ["git", "rev-parse", "HEAD"])
            return subprocess.CompletedProcess(command, 0, candidate_sha + "\n", "")

        with tempfile.TemporaryDirectory(prefix="swz-guest-gate-test-") as temporary:
            output = pathlib.Path(temporary) / "qualification.json"
            resume = pathlib.Path(temporary) / "preflight.json"
            resume.write_text("{}\n", encoding="utf-8")
            build_output = pathlib.Path(temporary) / "build"
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(QUALIFY, "run", side_effect=fake_run))
                stack.enter_context(mock.patch.dict(os.environ, {}, clear=False))
                for name, value in results.items():
                    stack.enter_context(mock.patch.object(QUALIFY, name, return_value=value))
                status = QUALIFY.main([
                    "--phase", "guest", "--expected-sha", candidate_sha,
                    "--output", str(output), "--resume", str(resume),
                    "--build-output", str(build_output),
                ])
            evidence = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(status, 1)
        self.assertEqual(evidence["guest"]["mandatory_security_skips"], 1)
        self.assertEqual(evidence["mandatory_security_skips"], "NOT_YET_PROVEN")
        self.assertIn("mandatory-security-skips", evidence["failures"])

    def test_disposable_inputs_are_explicitly_qualified(self):
        inputs = CONTROLLER.disposable_inputs()
        self.assertEqual(inputs.barrier_utc, "2026-09-07T00:00:00.000000Z")
        self.assertTrue(inputs.bundle_commitment.startswith("sha256:v1:"))
        self.assertEqual(inputs.artifact_stream_commitment, "")

    def test_controller_has_no_result_payload_injection_authority(self):
        source = inspect.getsource(CONTROLLER.ManagedController._run_supervised_agent)
        self.assertNotIn("result_payload", source)
        self.assertNotIn("BACKEND.build_result", inspect.getsource(CONTROLLER.ManagedController.run))
        self.assertIn("agent_exchange(context_record, proceed_frame, source, target)", source)
        with self.assertRaises(CONTROLLER.ControllerError):
            CONTROLLER.NativeAgentExchange(b"caller-supplied-result", b"")

    def test_disposable_locator_preserves_canonical_psql_path(self):
        result = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.object(QUALIFY, "run", return_value=result) as run_mock:
            QUALIFY.ensure_disposable_locator_client_path("coolify-db")
        command = run_mock.call_args.args[0]
        self.assertEqual(command[:5], ["docker", "exec", "--user", "root", "coolify-db"])
        self.assertIn("command -v psql", command[-1])
        self.assertIn("/usr/local/bin/psql", command[-1])


if __name__ == "__main__":
    unittest.main()
