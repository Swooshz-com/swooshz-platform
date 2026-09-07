import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "recovery" / "managed"))

import backend  # noqa: E402


class BrokerTests(unittest.TestCase):
    def test_exact_broker_restore_order(self) -> None:
        broker = backend.BrokerLifecycle()
        expected = [
            backend.BrokerState.DISCOVERY,
            backend.BrokerState.CAS_A,
            backend.BrokerState.RESTORE_BEGIN_DURABLE,
            backend.BrokerState.PROCEED,
            backend.BrokerState.HALF_CLOSED,
            backend.BrokerState.REMOTE_EOF,
            backend.BrokerState.RESTORE_AUTHORIZED,
            backend.BrokerState.RESULT,
            backend.BrokerState.FINAL,
        ]
        for state in expected:
            broker.advance(state)
        self.assertEqual(broker.state, backend.BrokerState.FINAL)
        self.assertEqual(broker.half_close_count, 1)

    def test_out_of_order_and_duplicate_half_close_are_rejected(self) -> None:
        broker = backend.BrokerLifecycle()
        with self.assertRaises(backend.StateTransitionError):
            broker.advance(backend.BrokerState.PROCEED)
        for state in (
            backend.BrokerState.DISCOVERY,
            backend.BrokerState.CAS_A,
            backend.BrokerState.RESTORE_BEGIN_DURABLE,
            backend.BrokerState.PROCEED,
            backend.BrokerState.HALF_CLOSED,
        ):
            broker.advance(state)
        with self.assertRaises(backend.StateTransitionError):
            broker.advance(backend.BrokerState.HALF_CLOSED)
        self.assertEqual(broker.half_close_count, 1)

    def test_trailing_input_sticks_consumed_uncertainty(self) -> None:
        broker = backend.BrokerLifecycle()
        for state in (
            backend.BrokerState.DISCOVERY,
            backend.BrokerState.CAS_A,
            backend.BrokerState.RESTORE_BEGIN_DURABLE,
            backend.BrokerState.PROCEED,
            backend.BrokerState.HALF_CLOSED,
        ):
            broker.advance(state)
        broker.consumed_uncertainty()
        self.assertEqual(broker.state, backend.BrokerState.CONSUMED_UNCERTAINTY)
        with self.assertRaises(backend.StateTransitionError):
            broker.advance(backend.BrokerState.REMOTE_EOF)
        with self.assertRaises(backend.StateTransitionError):
            broker.consumed_uncertainty()


if __name__ == "__main__":
    unittest.main()
