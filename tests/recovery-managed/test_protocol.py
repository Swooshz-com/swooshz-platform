import importlib.util
import json
import pathlib
import sys
import unittest
from collections import OrderedDict


ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("swz_test_backend", ROOT / "recovery/managed/backend.py")
assert SPEC is not None and SPEC.loader is not None
BACKEND = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BACKEND
SPEC.loader.exec_module(BACKEND)


def commitment(char: str) -> str:
    return "sha256:v1:" + char * 64


def transition_record() -> OrderedDict:
    return OrderedDict((
        ("schema", "restore-ledger-transition-data.v2"), ("version", 2),
        ("epoch_ref", "epoch-qualified-001"), ("authority_ref", "authority-qualified-001"),
        ("barrier_utc", "2026-09-07T00:00:00Z"), ("barrier_commitment", commitment("a")),
        ("runner_commitment", commitment("b")), ("bundle_commitment", commitment("c")),
        ("image_commitment", commitment("d")), ("target_commitment", commitment("e")),
        ("isolation_commitment", commitment("f")), ("artifact_commitment", commitment("1")),
        ("artifact_stream_commitment", commitment("2")), ("pre_cas_ledger_digest", commitment("3")),
    ))


def evidence_record() -> OrderedDict:
    return OrderedDict((
        ("schema", "restore-begin-evidence.v2"), ("epoch_ref", "epoch-qualified-001"),
        ("transition_id", "restore-v2-" + "a" * 48), ("transition_data_commitment", commitment("a")),
        ("artifact_commitment", commitment("1")), ("artifact_stream_commitment", commitment("2")),
        ("ledger_state", "CONSUMED"), ("record_state", "CONSUMED"),
        ("spool_previous_stage", "RUNNER_STARTED"), ("frame_sequence", 3),
        ("previous_frame_hash", commitment("4")), ("frame_hash", commitment("5")),
        ("spool_commitment", commitment("6")), ("ledger_after_digest", commitment("7")),
        ("durability", OrderedDict((field, True) for field in BACKEND.DURABILITY_FIELDS)),
    ))


def result_record() -> OrderedDict:
    fields = OrderedDict((field, commitment("a")) for field in BACKEND.RESULT_FIELDS)
    fields["schema"] = "swz-recovery-result.v2"
    for field in ("classification", "stage", "epoch_ref", "authority_ref", "barrier_utc", "cleanup_state"):
        fields[field] = {"classification": "SUCCESS", "stage": "RESTORE", "epoch_ref": "epoch-qualified-001", "authority_ref": "authority-qualified-001", "barrier_utc": "2026-09-07T00:00:00Z", "cleanup_state": "CLEAN"}[field]
    fields["transition_id"] = "restore-v2-" + "a" * 48
    for field in ("result_code", "restore_count", "exit_status"):
        fields[field] = 0 if field != "restore_count" else 1
    for field in ("stdin_eof", "stdout_eof", "stderr_eof", "trailing_unframed_bytes", "terminal_input_eof", "terminal_input_trailing_bytes"):
        fields[field] = field not in {"trailing_unframed_bytes", "terminal_input_trailing_bytes"}
    return fields


class ProtocolContractTests(unittest.TestCase):
    def test_identity_vector_matches_frozen_kat(self):
        vector = BACKEND.identity_vector()
        self.assertEqual(vector.installation.hex(), "e8a0ef6f2c154a38e9b514b1d1c1692c9ff4128e0e73916003833c2377fd597f")
        self.assertEqual(vector.endpoint_template.hex(), "198d57f1638a38bb74fcb7e6c0800a44263cf2eea4afbf6fa5e2f1ebd921af3a")
        self.assertEqual(vector.endpoint_actual.hex(), "d7b07ef7b4a95aea2f1914496733af29f5073ac6e6d52bcb0c5fd3675d9566fb")

    def test_domains_and_identity_graph_are_closed(self):
        BACKEND.assert_domain_uniqueness()
        BACKEND.reject_self_reference(BACKEND.IDENTITY_GRAPH)
        self.assertEqual(len(BACKEND.MANAGED_DOMAINS), 43)

    def test_store_commitment_is_distinct_from_managed_hash(self):
        payload = b"exact bytes\n"
        self.assertNotEqual(BACKEND.store_commitment("x", payload), BACKEND.managed_hash("x", payload).hex())
        self.assertEqual(BACKEND.store_commitment("x", payload).startswith("sha256:v1:"), True)

    def test_store_wire_preserves_bytes_and_rejects_shape_changes(self):
        transition = transition_record()
        raw = BACKEND.store_bytes(transition)
        wire = BACKEND.store_wire_record("restore-ledger-transition-data.v2", transition)
        encoded = BACKEND.encode_store_wire(wire.schema_id, raw)
        decoded = BACKEND.decode_store_wire(encoded)
        self.assertEqual(decoded.store_bytes, raw)
        with self.assertRaises(BACKEND.StoreWireError):
            BACKEND.decode_store_wire([BACKEND.STORE_MARKER, wire.schema_id, json.loads(raw.decode())])
        altered = raw.replace(b'"version":2,"epoch_ref"', b'"epoch_ref"', 1)
        with self.assertRaises(BACKEND.StoreWireError):
            BACKEND.validate_retained_store_bytes(wire.schema_id, altered)

    def test_exact_frame_header_and_chain(self):
        payload = BACKEND.managed_json(["BOOT", 2, BACKEND.MANAGED_SCHEMA])
        raw = BACKEND.build_frame(BACKEND.DIRECTION_LOCAL_TO_REMOTE, "BOOT", 1, b"n" * 32, payload)
        self.assertEqual(len(raw), BACKEND.FRAME_HEADER_BYTES + len(payload))
        self.assertEqual(raw[:8], b"SWZFRM02")
        decoded = BACKEND.decode_frame(raw)
        self.assertEqual((decoded.direction, decoded.message, decoded.sequence, decoded.payload), (1, "BOOT", 1, payload))
        self.assertEqual(BACKEND.frame_hash(raw), __import__("hashlib").sha256(raw).digest())
        with self.assertRaises(BACKEND.ProtocolError):
            BACKEND.decode_frame(raw + b"x")

    def test_store_profiles_and_restore_messages_use_exact_order(self):
        transition = BACKEND.store_wire_record("restore-ledger-transition-data.v2", transition_record())
        evidence = BACKEND.store_wire_record("restore-begin-evidence.v2", evidence_record())
        begin = BACKEND.build_restore_begin(b"s" * 32, b"d" * 32, transition, evidence, commitment("8"))
        begin_value = BACKEND.parse_managed_json(begin)
        self.assertEqual(begin_value[0:3], ["RESTORE_BEGIN", 2, BACKEND.MANAGED_SCHEMA])
        proceed, pc = BACKEND.build_proceed(b"s" * 32, "restore-v2-" + "a" * 48, commitment("a"), BACKEND.frame_hash(BACKEND.build_frame(2, "RESTORE_BEGIN", 7, b"r" * 32, begin)))
        result, rc = BACKEND.build_result(b"s" * 32, "restore-v2-" + "a" * 48, BACKEND.frame_hash(BACKEND.build_frame(1, "PROCEED", 8, b"p" * 32, proceed)), pc, BACKEND.store_wire_record("swz-recovery-result.v2", result_record()))
        self.assertEqual(len(pc), 32)
        self.assertEqual(len(rc), 32)
        self.assertEqual(BACKEND.parse_managed_json(result)[0], "RESULT")

    def test_filename_uuid_and_limits_fail_closed(self):
        with self.assertRaises(BACKEND.IdentityError):
            BACKEND.canonical_filename_octets("../artifact")
        with self.assertRaises(BACKEND.IdentityError):
            BACKEND.validate_uuid_text("00000000-0000-3000-8000-000000000000")
        with self.assertRaises(BACKEND.ProtocolError):
            BACKEND.build_frame(1, "BOOT", 17, b"n" * 32, b"{}\n")


if __name__ == "__main__":
    unittest.main()

