import importlib.util
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest
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
            with self.assertRaises(CONTROLLER.QualificationProviderHold):
                controller.run(store_root=store_root, artifact_source=source, artifact_target=target, agent_binary=root / "missing-swz-agent")
            self.assertIsNotNone(controller.store)
            self.assertEqual(controller.store.read_restore_ledger("epoch-qualified-001")["state"], "CONSUMED")
            self.assertEqual(controller.store.ledger_safety_classification("epoch-qualified-001"), "CONSUMED")
            self.assertFalse(target.exists())

    def test_disposable_inputs_are_explicitly_qualified(self):
        inputs = CONTROLLER.disposable_inputs()
        self.assertEqual(inputs.barrier_utc, "2026-09-07T00:00:00Z")
        self.assertTrue(inputs.bundle_commitment.startswith("sha256:v1:"))
        self.assertEqual(inputs.artifact_stream_commitment, "")

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

