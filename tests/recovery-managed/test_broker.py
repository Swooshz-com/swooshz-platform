import importlib.util
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("swz_broker_backend", ROOT / "recovery/managed/backend.py")
BACKEND = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = BACKEND
SPEC.loader.exec_module(BACKEND)


class BrokerLifecycleTests(unittest.TestCase):
    def test_post_accept_sequence_reaches_final(self):
        broker = BACKEND.BrokerLifecycle()
        for state in (
            BACKEND.BrokerState.ACCEPTED,
            BACKEND.BrokerState.DISCOVERY,
            BACKEND.BrokerState.CAS_A,
            BACKEND.BrokerState.RESTORE_BEGIN,
            BACKEND.BrokerState.PROCEED,
            BACKEND.BrokerState.EOF,
            BACKEND.BrokerState.RESTORED,
            BACKEND.BrokerState.RESULT,
            BACKEND.BrokerState.FINAL,
        ):
            broker.advance(state)
        self.assertEqual(broker.state, BACKEND.BrokerState.FINAL)

    def test_restore_cannot_start_before_cas(self):
        broker = BACKEND.BrokerLifecycle()
        broker.advance(BACKEND.BrokerState.ACCEPTED)
        broker.advance(BACKEND.BrokerState.DISCOVERY)
        with self.assertRaises(BACKEND.StateTransitionError):
            broker.advance(BACKEND.BrokerState.RESTORE_BEGIN)

    def test_consumed_uncertainty_is_sticky(self):
        broker = BACKEND.BrokerLifecycle()
        broker.advance(BACKEND.BrokerState.ACCEPTED)
        broker.advance(BACKEND.BrokerState.DISCOVERY)
        broker.advance(BACKEND.BrokerState.CAS_A)
        broker.consumed_uncertainty()
        self.assertEqual(broker.state, BACKEND.BrokerState.CONSUMED_UNCERTAINTY)
        with self.assertRaises(BACKEND.StateTransitionError):
            broker.advance(BACKEND.BrokerState.RESTORE_BEGIN)


if __name__ == "__main__":
    unittest.main()
