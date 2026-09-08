import importlib.util
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("swz_broker_backend", ROOT / "recovery/managed/backend.py")
assert SPEC is not None and SPEC.loader is not None
BACKEND = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BACKEND
SPEC.loader.exec_module(BACKEND)


class BrokerLifecycleTests(unittest.TestCase):
    def test_accepted_restore_result_finality(self):
        lifecycle = BACKEND.BrokerLifecycle()
        for state in (BACKEND.BrokerState.ACCEPTED, BACKEND.BrokerState.DISCOVERY, BACKEND.BrokerState.CAS_A,
                      BACKEND.BrokerState.RESTORE_BEGIN, BACKEND.BrokerState.PROCEED, BACKEND.BrokerState.EOF,
                      BACKEND.BrokerState.RESTORED, BACKEND.BrokerState.RESULT, BACKEND.BrokerState.FINAL):
            lifecycle.advance(state)
        self.assertEqual(lifecycle.state, BACKEND.BrokerState.FINAL)

    def test_consumed_uncertainty_is_sticky(self):
        lifecycle = BACKEND.BrokerLifecycle()
        lifecycle.advance(BACKEND.BrokerState.ACCEPTED)
        lifecycle.advance(BACKEND.BrokerState.DISCOVERY)
        lifecycle.advance(BACKEND.BrokerState.CAS_A)
        lifecycle.consumed_uncertainty()
        with self.assertRaises(BACKEND.StateTransitionError):
            lifecycle.advance(BACKEND.BrokerState.RESTORE_BEGIN)


if __name__ == "__main__":
    unittest.main()

