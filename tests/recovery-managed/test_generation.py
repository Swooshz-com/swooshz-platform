import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "recovery" / "managed"))

import backend  # noqa: E402


class GenerationTests(unittest.TestCase):
    def test_generation_lifecycle_is_linear(self) -> None:
        lifecycle = backend.GenerationLifecycle()
        for state in (
            backend.GenerationState.QUALIFIED,
            backend.GenerationState.ACTIVE,
            backend.GenerationState.DRAINING,
            backend.GenerationState.RETIRING,
            backend.GenerationState.OFFLINE,
        ):
            lifecycle.advance(state)
        self.assertEqual(lifecycle.state, backend.GenerationState.OFFLINE)
        with self.assertRaises(backend.StateTransitionError):
            lifecycle.advance(backend.GenerationState.ACTIVE)

    def test_admission_cannot_skip_controller_validation(self) -> None:
        lifecycle = backend.AdmissionLifecycle()
        with self.assertRaises(backend.StateTransitionError):
            lifecycle.advance(backend.AdmissionState.OPERATIONAL)
        for state in (
            backend.AdmissionState.SSH_AUTHENTICATED,
            backend.AdmissionState.BOOTSTRAP,
            backend.AdmissionState.CHALLENGE,
            backend.AdmissionState.EVIDENCE,
            backend.AdmissionState.CONTROLLER_VALIDATED,
            backend.AdmissionState.ACCEPT_SENT,
            backend.AdmissionState.REMOTE_ACCEPTED,
            backend.AdmissionState.OPERATIONAL,
        ):
            lifecycle.advance(state)
        self.assertEqual(lifecycle.state, backend.AdmissionState.OPERATIONAL)

    def test_failure_is_terminal(self) -> None:
        lifecycle = backend.AdmissionLifecycle()
        lifecycle.fail("invalid-evidence")
        self.assertEqual(lifecycle.state, backend.AdmissionState.FAILED)
        self.assertEqual(lifecycle.failure_code, "invalid-evidence")
        with self.assertRaises(backend.StateTransitionError):
            lifecycle.fail("second-failure")


if __name__ == "__main__":
    unittest.main()
