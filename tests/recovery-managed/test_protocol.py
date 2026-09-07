import hashlib
import json
import sys
import unittest
from collections import OrderedDict
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "recovery" / "managed"))

import backend  # noqa: E402


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "wire-kats.json"


def load_wire_fixture() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


class ProtocolTests(unittest.TestCase):
    def test_managed_json_is_sorted_and_strict(self) -> None:
        payload = backend.managed_json({"a": 1, "b": [True, "ok"]})
        self.assertEqual(payload, b'{"a":1,"b":[true,"ok"]}')
        self.assertEqual(backend.parse_managed_json(payload), {"a": 1, "b": [True, "ok"]})
        for invalid in (
            b'{"b":1,"a":2}',
            b'{"a":1,"a":2}',
            b'{"a":1.0}',
            b'{"a":null}',
            b' {"a":1}',
            b'{"a":1}\n',
            b'{"a":"\\ud800"}',
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(backend.BoundaryError):
                    backend.parse_managed_json(invalid)

    def test_digest_types_never_guess(self) -> None:
        bare = "a" * 64
        tagged = "sha256:v1:" + bare
        self.assertEqual(backend.managed_digest(bare), b"\xaa" * 32)
        self.assertEqual(backend.strict_store_digest(tagged), b"\xaa" * 32)
        for value in (tagged, bare.upper(), "SHA256:V1:" + bare):
            with self.subTest(value=value):
                with self.assertRaises(backend.BoundaryError):
                    backend.managed_digest(value)
        for value in (bare, tagged.upper(), "sha256:v1:" + bare.upper()):
            with self.subTest(value=value):
                with self.assertRaises(backend.BoundaryError):
                    backend.strict_store_digest(value)

    def test_run374_identity_golden_and_domain_closure(self) -> None:
        vector = json.loads(
            (Path(__file__).parent / "fixtures" / "transition-kats.json").read_text(encoding="utf-8")
        )
        actual = backend.test_identity_vector_inputs()
        identity = vector["identity_vector"]
        self.assertEqual(actual["installation"].hex(), identity["installation"])
        self.assertEqual(actual["endpoint_template"].hex(), identity["endpoint_template"])
        self.assertEqual(actual["endpoint_actual"].hex(), identity["endpoint_actual"])
        self.assertEqual(len(backend.MANAGED_DOMAINS), vector["managed_domains"]["count"])
        backend.assert_domain_uniqueness()
        self.assertEqual(
            len({domain for _, domain in backend.MANAGED_DOMAINS}),
            vector["managed_domains"]["count"],
        )
        backend.assert_identity_graph_acyclic()

    def test_raw_identity_negative_cases(self) -> None:
        vector = backend.test_identity_vector_inputs()
        with self.assertRaises(backend.IdentityError):
            backend.literal_endpoint_record("192.0.2.010")
        with self.assertRaises(backend.IdentityError):
            backend.validate_uuid_text("00000000-0000-0000-0000-000000000000")
        with self.assertRaises(backend.IdentityError):
            backend.validate_uuid_text("10213243-5465-4767-98A9-bacbdcedfe0f")
        with self.assertRaises(backend.IdentityError):
            backend.installation_identity(
                vector["boot_uuid"],
                vector["admission_blob"],
                vector["host_blob"],
                vector["controller_blob"],
                vector["endpoint_record"],
                vector["uidgid_map"],
                b"\x11" * 31,
            )
        with self.assertRaises(backend.IdentityError):
            backend.assert_identity_graph_acyclic({"A": ("A",)})

    def test_storewire_profiles_preserve_exact_bytes(self) -> None:
        fixture = load_wire_fixture()
        for profile in fixture["profiles"]:
            with self.subTest(schema_id=profile["schema_id"]):
                raw = profile["store_text"].encode("utf-8")
                wire = backend.StoreWire.from_bytes(profile["schema_id"], raw)
                self.assertEqual(wire.store_bytes, raw)
                self.assertEqual(
                    hashlib.sha256(wire.payload()).hexdigest(),
                    profile["wire_payload_sha256"],
                )
                self.assertEqual(backend.decode_store_wire(wire.payload()).store_bytes, raw)
                self.assertEqual(backend.store_commitment(
                    "restore-ledger-transition" if profile["schema_id"].startswith("restore-ledger")
                    else "restore-begin-evidence" if profile["schema_id"].startswith("restore-begin")
                    else "restore-result",
                    raw,
                )[:10], "sha256:v1:")

    def test_storewire_sorted_order_and_nested_order_reject(self) -> None:
        fixture = load_wire_fixture()
        transition = fixture["profiles"][0]
        parsed = json.loads(transition["store_text"], object_pairs_hook=OrderedDict)
        sorted_record = OrderedDict(sorted(parsed.items()))
        sorted_bytes = (json.dumps(sorted_record, separators=(",", ":")) + "\n").encode("utf-8")
        with self.assertRaises(backend.StoreWireError):
            backend.StoreWire.from_bytes(transition["schema_id"], sorted_bytes)

        evidence = fixture["profiles"][1]
        evidence_record = json.loads(evidence["store_text"], object_pairs_hook=OrderedDict)
        evidence_record["durability"] = OrderedDict(
            reversed(list(evidence_record["durability"].items()))
        )
        mutated = (json.dumps(evidence_record, separators=(",", ":")) + "\n").encode("utf-8")
        with self.assertRaises(backend.StoreWireError):
            backend.StoreWire.from_bytes(evidence["schema_id"], mutated)

    def test_storewire_rejects_alternate_crossings_and_lossy_mutations(self) -> None:
        fixture = load_wire_fixture()
        profile = fixture["profiles"][0]
        raw = profile["store_text"].encode("utf-8")
        alternatives = (
            ["store-json.v1", profile["schema_id"], json.loads(profile["store_text"])],
            ["store-json.v1", profile["schema_id"], raw.hex()],
            ["store-json.v1", profile["schema_id"], "untagged"],
            ["other-marker", profile["schema_id"], profile["store_text"]],
            ["store-json.v1", "unknown.v1", profile["store_text"]],
            ["store-json.v1", profile["schema_id"]],
        )
        for alternative in alternatives:
            with self.subTest(alternative=alternative[:2]):
                with self.assertRaises(backend.StoreWireError):
                    backend.decode_store_wire(alternative)
        for mutated in (raw[:-1], raw + b"\n", raw.replace(b"\n", b"\r\n")):
            with self.subTest(mutated=mutated[-4:]):
                with self.assertRaises(backend.StoreWireError):
                    backend.StoreWire.from_bytes(profile["schema_id"], mutated)

    def test_storewire_payload_and_frame_limits(self) -> None:
        fixture = load_wire_fixture()
        profile = fixture["profiles"][0]
        raw = profile["store_text"].encode("utf-8")
        self.assertLessEqual(len(raw), backend.MAX_CONTROL_PAYLOAD_BYTES)
        oversized = raw[:-1] + (b"x" * (backend.MAX_CONTROL_PAYLOAD_BYTES + 1)) + b"\n"
        with self.assertRaises(backend.StoreWireError):
            backend.StoreWire.from_bytes(profile["schema_id"], oversized)
        with self.assertRaises(backend.ProtocolError):
            backend.build_frame(1, "BOOT", 0, b"\x01" * 32, b"x" * (backend.MAX_CONTROL_PAYLOAD_BYTES + 1))

    def test_transcript_kat_and_result_hash_position(self) -> None:
        fixture = load_wire_fixture()
        transition, evidence, result = fixture["profiles"]
        transition_wire = backend.StoreWire.from_bytes(
            transition["schema_id"], transition["store_text"].encode("utf-8")
        )
        evidence_wire = backend.StoreWire.from_bytes(
            evidence["schema_id"], evidence["store_text"].encode("utf-8")
        )
        result_wire = backend.StoreWire.from_bytes(
            result["schema_id"], result["store_text"].encode("utf-8")
        )
        kat = fixture["transcript"]
        session = bytes.fromhex(kat["accepted_session_hex"])
        discovery_hash = bytes.fromhex(kat["discovery_frame_hash_hex"])
        restore_begin = backend.build_restore_begin(
            discovery_hash,
            session,
            transition_wire,
            evidence_wire,
            kat["consumed_record_commitment"],
        )
        self.assertEqual(len(restore_begin), kat["restore_begin_payload_bytes"])
        self.assertEqual(hashlib.sha256(restore_begin).hexdigest(), kat["restore_begin_payload_sha256"])
        restore_frame = backend.build_frame(1, "RESTORE_BEGIN", 4, b"\x44" * 32, restore_begin)
        self.assertEqual(backend.frame_hash(restore_frame).hex(), kat["restore_begin_frame_hash_hex"])
        proceed, pc = backend.build_proceed(
            session,
            transition["transition_id"],
            transition["store_commitment"],
            backend.frame_hash(restore_frame),
        )
        self.assertEqual(hashlib.sha256(proceed).hexdigest(), kat["proceed_payload_sha256"])
        self.assertEqual(pc.hex(), kat["proceed_commitment_hex"])
        proceed_frame = backend.build_frame(1, "PROCEED", 5, b"\x55" * 32, proceed)
        proceed_hash = backend.frame_hash(proceed_frame)
        self.assertEqual(proceed_hash.hex(), kat["proceed_frame_hash_hex"])
        result_payload, rc = backend.build_result(
            session,
            transition["transition_id"],
            proceed_hash,
            pc,
            result_wire,
        )
        self.assertEqual(len(result_payload), kat["result_payload_bytes"])
        self.assertEqual(hashlib.sha256(result_payload).hexdigest(), kat["result_payload_sha256"])
        self.assertEqual(rc.hex(), kat["result_commitment_hex"])
        self.assertEqual(json.loads(result_payload)[3], kat["proceed_frame_hash_hex"])
        self.assertNotEqual(json.loads(result_payload)[3], pc.hex())


if __name__ == "__main__":
    unittest.main()
