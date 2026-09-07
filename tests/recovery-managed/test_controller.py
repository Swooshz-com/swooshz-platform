import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("swz_test_controller", ROOT / "recovery/managed/controller.py")
CONTROLLER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = CONTROLLER
SPEC.loader.exec_module(CONTROLLER)


class ControllerIntegrationTests(unittest.TestCase):
    def context(self):
        return CONTROLLER.make_admitted_context(
            "11" * 32,
            "22" * 32,
            "33" * 32,
        )

    def test_store_is_unavailable_before_matching_remote_accept(self):
        controller = CONTROLLER.ManagedController(self.context())
        self.assertIsNone(controller.store)
        with self.assertRaises(CONTROLLER.ControllerError):
            controller._require_accepted()
        controller.accept()
        self.assertIsNone(controller.store)

    def test_cas_is_real_and_uncertainty_sticks_when_native_provider_is_absent(self):
        with tempfile.TemporaryDirectory(prefix="swz-controller-test-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "qualified-artifact"
            target = root / "restore-target"
            (root / "store").mkdir()
            source.write_bytes(b"disposable-qualified-artifact\n")
            controller = CONTROLLER.ManagedController(self.context())
            if os.name == "nt":
                with self.assertRaises(CONTROLLER.STORE.FilesystemSafetyError):
                    controller.run(
                        store_root=root / "store",
                        artifact_source=source,
                        artifact_target=target,
                        agent_binary=root / "missing-swz-agent",
                    )
                return
            with self.assertRaises(CONTROLLER.QualificationProviderHold):
                controller.run(
                    store_root=root / "store",
                    artifact_source=source,
                    artifact_target=target,
                    agent_binary=root / "missing-swz-agent",
                )
            self.assertIsNotNone(controller.store)
            self.assertEqual(controller.store.read_restore_ledger("epoch-qualified-001")["state"], "CONSUMED")
            self.assertEqual(controller.store.ledger_safety_classification("epoch-qualified-001"), "CONSUMED")
            self.assertFalse(target.exists())

    def test_disposable_inputs_are_explicitly_qualified(self):
        inputs = CONTROLLER.disposable_inputs()
        self.assertEqual(inputs.barrier_utc, "2026-09-07T00:00:00Z")
        self.assertTrue(inputs.bundle_commitment.startswith("sha256:v1:"))
        self.assertEqual(inputs.artifact_stream_commitment, "")


if __name__ == "__main__":
    unittest.main()
