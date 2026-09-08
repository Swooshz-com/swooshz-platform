import importlib.util
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("swz_generation_backend", ROOT / "recovery/managed/backend.py")
BACKEND = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = BACKEND
SPEC.loader.exec_module(BACKEND)


class GenerationLifecycleTests(unittest.TestCase):
    def test_generation_can_only_activate_from_qualified(self):
        lifecycle = BACKEND.GenerationLifecycle()
        lifecycle.advance(BACKEND.GenerationState.QUALIFIED)
        lifecycle.advance(BACKEND.GenerationState.ACTIVE)
        lifecycle.advance(BACKEND.GenerationState.DRAINING)
        lifecycle.advance(BACKEND.GenerationState.RETIRING)
        lifecycle.advance(BACKEND.GenerationState.OFFLINE)
        self.assertEqual(lifecycle.state, BACKEND.GenerationState.OFFLINE)

    def test_generation_rejects_skipping_qualification(self):
        lifecycle = BACKEND.GenerationLifecycle()
        with self.assertRaises(BACKEND.StateTransitionError):
            lifecycle.advance(BACKEND.GenerationState.ACTIVE)

    def test_admission_transcript_has_no_store_effect_before_accept(self):
        admission = BACKEND.AdmissionLifecycle()
        self.assertEqual(admission.state, BACKEND.AdmissionState.ACCEPTED_SOCKET)
        admission.advance(BACKEND.AdmissionState.SSH_AUTHENTICATED)
        admission.advance(BACKEND.AdmissionState.BOOTSTRAP)
        admission.advance(BACKEND.AdmissionState.CHALLENGE)
        admission.advance(BACKEND.AdmissionState.EVIDENCE)
        admission.advance(BACKEND.AdmissionState.CONTROLLER_VALIDATED)
        admission.advance(BACKEND.AdmissionState.ACCEPT_SENT)
        admission.advance(BACKEND.AdmissionState.REMOTE_ACCEPTED)
        admission.advance(BACKEND.AdmissionState.OPERATIONAL)
        self.assertEqual(admission.state, BACKEND.AdmissionState.OPERATIONAL)

    def test_admission_failure_is_terminal(self):
        admission = BACKEND.AdmissionLifecycle()
        admission.fail("controller-mismatch")
        self.assertEqual(admission.state, BACKEND.AdmissionState.FAILED)
        with self.assertRaises(BACKEND.StateTransitionError):
            admission.advance(BACKEND.AdmissionState.SSH_AUTHENTICATED)


if __name__ == "__main__":
    unittest.main()
