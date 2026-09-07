import json
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "recovery" / "managed"))

import backend  # noqa: E402
from controller import ControllerError, RecoveryController  # noqa: E402


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "wire-kats.json"


def fixture_parts() -> tuple[dict, dict, dict, dict]:
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    transition, evidence, result = fixture["profiles"]
    return fixture, transition, evidence, result


class ControllerTests(unittest.TestCase):
    def _controller(self) -> tuple[RecoveryController, dict, dict, dict, dict]:
        fixture, transition, evidence, result = fixture_parts()
        kat = fixture["transcript"]
        return (
            RecoveryController(
                bytes.fromhex(kat["accepted_session_hex"]),
                bytes.fromhex(kat["discovery_frame_hash_hex"]),
                bindings={"epoch_ref": "epoch-001", "authority_ref": "authority-001"},
            ),
            fixture,
            transition,
            evidence,
            result,
        )

    def test_store_is_unreachable_before_complete_admission(self) -> None:
        controller, fixture, _, _, _ = self._controller()
        with self.assertRaises(ControllerError):
            controller.cas_a(fixture["transcript"]["consumed_record_commitment"])
        self.assertEqual(controller.snapshot().store_mutations, 0)
        self.assertFalse(controller.restore_authorized)
        controller.admit()
        self.assertEqual(controller.snapshot().store_mutations, 0)
        self.assertFalse(controller.restore_authorized)

    def test_full_restore_order_and_exact_transcript(self) -> None:
        controller, fixture, transition, evidence, result = self._controller()
        kat = fixture["transcript"]
        controller.admit()
        controller.cas_a(kat["consumed_record_commitment"])
        restore_begin = controller.restore_begin(
            backend.StoreWire.from_bytes(transition["schema_id"], transition["store_text"].encode()),
            backend.StoreWire.from_bytes(evidence["schema_id"], evidence["store_text"].encode()),
        )
        self.assertEqual(len(restore_begin), kat["restore_begin_payload_bytes"])
        restore_frame = backend.build_frame(1, "RESTORE_BEGIN", 4, b"\x44" * 32, restore_begin)
        proceed, pc = controller.proceed(backend.frame_hash(restore_frame))
        proceed_frame = backend.build_frame(1, "PROCEED", 5, b"\x55" * 32, proceed)
        self.assertEqual(controller.set_proceed_frame_hash(proceed_frame).hex(), kat["proceed_frame_hash_hex"])
        self.assertEqual(controller.controller_half_close(), 1)
        controller.remote_eof(0)
        with self.assertRaises(ControllerError):
            controller.result(backend.StoreWire.from_bytes(result["schema_id"], result["store_text"].encode()))
        controller.authorize_restore()
        called: list[str] = []
        controller.run_authorized_restore(lambda: called.append("restore") or "done")
        result_payload, result_commitment = controller.result(
            backend.StoreWire.from_bytes(result["schema_id"], result["store_text"].encode())
        )
        controller.finalize()
        self.assertEqual(called, ["restore"])
        self.assertEqual(result_commitment.hex(), kat["result_commitment_hex"])
        self.assertEqual(controller.snapshot().broker_state, backend.BrokerState.FINAL)
        self.assertEqual(controller.snapshot().restore_count, 1)
        self.assertEqual(controller.transcript().proceed_commitment, pc)
        self.assertEqual(result_payload, controller.transcript().result_payload)

    def test_post_cas_rejection_is_sticky_consumed_uncertainty(self) -> None:
        controller, fixture, transition, evidence, _ = self._controller()
        controller.admit()
        controller.cas_a(fixture["transcript"]["consumed_record_commitment"])
        wrong_id = transition["transition_id"][:-1] + "0"
        invalid_evidence = evidence["store_text"].replace(transition["transition_id"], wrong_id)
        invalid_wire = backend.StoreWire.from_bytes(evidence["schema_id"], invalid_evidence.encode())
        with self.assertRaises(ControllerError):
            controller.restore_begin(
                backend.StoreWire.from_bytes(transition["schema_id"], transition["store_text"].encode()),
                invalid_wire,
            )
        snapshot = controller.snapshot()
        self.assertTrue(snapshot.consumed_uncertainty)
        self.assertFalse(snapshot.restore_authorized)
        with self.assertRaises(ControllerError):
            controller.authorize_restore()


if __name__ == "__main__":
    unittest.main()
