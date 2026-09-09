import importlib.util
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("swz_generation_backend", ROOT / "recovery/managed/backend.py")
assert SPEC is not None and SPEC.loader is not None
BACKEND = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BACKEND
SPEC.loader.exec_module(BACKEND)


class GenerationTests(unittest.TestCase):
    def test_generation_order_and_no_reactivation(self):
        lifecycle = BACKEND.GenerationLifecycle()
        for state in (BACKEND.GenerationState.QUALIFIED, BACKEND.GenerationState.ACTIVE,
                      BACKEND.GenerationState.DRAINING, BACKEND.GenerationState.RETIRING,
                      BACKEND.GenerationState.OFFLINE):
            lifecycle.advance(state)
        with self.assertRaises(BACKEND.StateTransitionError):
            lifecycle.advance(BACKEND.GenerationState.ACTIVE)

    def test_admission_failure_is_terminal(self):
        lifecycle = BACKEND.AdmissionLifecycle()
        lifecycle.fail("wrong-peer")
        with self.assertRaises(BACKEND.StateTransitionError):
            lifecycle.advance(BACKEND.AdmissionState.SSH_AUTHENTICATED)


if __name__ == "__main__":
    unittest.main()

