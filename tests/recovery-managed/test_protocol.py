import hashlib
import importlib.util
import json
import pathlib
import sys
import unittest
from collections import OrderedDict


ROOT = pathlib.Path(__file__).resolve().parents[2]
BACKEND_PATH = ROOT / "recovery" / "managed" / "backend.py"
SPEC = importlib.util.spec_from_file_location("swz_test_backend", BACKEND_PATH)
BACKEND = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = BACKEND
SPEC.loader.exec_module(BACKEND)


def load_json(path: pathlib.Path):
    return json.loads(path.read_text(encoding="utf-8"))


class ProtocolAndIdentityTests(unittest.TestCase):
    def test_locked_identity_vector(self):
        vector = load_json(ROOT / "tests/recovery-managed/fixtures/transition-kats.json")["identity_vector"]
        values = BACKEND.identity_vector()
        self.assertEqual(values.installation.hex(), vector["installation"])
        self.assertEqual(values.endpoint_template.hex(), vector["endpoint_template"])
        self.assertEqual(values.endpoint_actual.hex(), vector["endpoint_actual"])
        self.assertEqual(BACKEND.literal_endpoint_record("192.0.2.10").hex(), "01010002c000020a56ce")

    def test_domain_and_graph_closure(self):
        kat = load_json(ROOT / "tests/recovery-managed/fixtures/transition-kats.json")
        self.assertEqual(BACKEND.MANAGED_DOMAINS, tuple(kat["managed_domains"]["names"]))
        BACKEND.assert_domain_uniqueness()
        BACKEND.reject_self_reference(BACKEND.IDENTITY_GRAPH)
        with self.assertRaises(BACKEND.IdentityError):
            BACKEND.reject_self_reference({"identity": ("identity",)})

    def test_managed_digest_and_store_digest_are_distinct(self):
        bare = "a" * 64
        tagged = "sha256:v1:" + bare
        self.assertEqual(BACKEND.managed_digest(bare), b"\xaa" * 32)
        self.assertEqual(BACKEND.strict_store_digest(tagged), b"\xaa" * 32)
        with self.assertRaises(BACKEND.BoundaryError):
            BACKEND.strict_store_digest(bare)
        with self.assertRaises(BACKEND.BoundaryError):
            BACKEND.managed_digest(tagged)

    def test_canonical_json_rejections(self):
        with self.assertRaises(BACKEND.CanonicalJSONError):
            BACKEND.parse_managed_json(b'{"b":1,"a":2}')
        with self.assertRaises(BACKEND.CanonicalJSONError):
            BACKEND.managed_json({"value": None})
        with self.assertRaises(BACKEND.CanonicalJSONError):
            BACKEND.managed_json({"value": 1.0})
        with self.assertRaises(BACKEND.CanonicalJSONError):
            BACKEND.parse_managed_json(b'{"value":1}\n')

    def test_ipv4_uuid_filename_negative_cases(self):
        with self.assertRaises(BACKEND.IdentityError):
            BACKEND.literal_endpoint_record("192.0.2.010")
        with self.assertRaises(BACKEND.IdentityError):
            BACKEND.literal_endpoint_record("example.invalid")
        with self.assertRaises(BACKEND.IdentityError):
            BACKEND.validate_uuid_text("00112233-4455-4677-8899-AABBCCDDEEFF")
        with self.assertRaises(BACKEND.IdentityError):
            BACKEND.validate_uuid_text("00000000-0000-0000-0000-000000000000")
        with self.assertRaises(BACKEND.IdentityError):
            BACKEND.canonical_filename_octets("../artifact")
        with self.assertRaises(BACKEND.IdentityError):
            BACKEND.canonical_filename_octets("artifact\\name")
        with self.assertRaises(BACKEND.IdentityError):
            BACKEND.canonical_filename_octets("artifact-e\u0301")

    def test_store_wire_profiles_preserve_original_bytes(self):
        fixture = load_json(ROOT / "tests/recovery-managed/fixtures/wire-kats.json")
        for profile in fixture["profiles"]:
            raw = profile["store_text"].encode("utf-8")
            wire = BACKEND.StoreWire.from_bytes(profile["schema_id"], raw)
            self.assertEqual(wire.store_bytes, raw)
            self.assertEqual(wire.envelope()[2].encode("utf-8"), raw)
            self.assertEqual(BACKEND.transition_id(raw), profile["transition_id"]) if profile["schema_id"].startswith("restore-ledger") else None
            domain = profile.get("commitment_domain")
            if domain is None:
                domain = "restore-ledger-transition" if profile["schema_id"].startswith("restore-ledger") else "restore-begin-evidence"
            self.assertEqual(BACKEND.store_commitment(domain, raw), profile["store_commitment"])

    def test_store_wire_rejects_lossy_forms(self):
        fixture = load_json(ROOT / "tests/recovery-managed/fixtures/wire-kats.json")
        raw = fixture["profiles"][0]["store_text"].encode("utf-8")
        with self.assertRaises(BACKEND.StoreWireError):
            BACKEND.StoreWire.from_bytes("restore-ledger-transition-data.v2", raw[:-1])
        with self.assertRaises(BACKEND.StoreWireError):
            BACKEND.decode_store_wire(["store-json.v1", "restore-ledger-transition-data.v2", json.loads(raw.decode())])
        with self.assertRaises(BACKEND.StoreWireError):
            BACKEND.decode_store_wire(["wrong-marker", "restore-ledger-transition-data.v2", raw.decode()])
        sorted_text = json.dumps(json.loads(raw.decode()), ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
        with self.assertRaises(BACKEND.StoreWireError):
            BACKEND.StoreWire.from_bytes("restore-ledger-transition-data.v2", sorted_text.encode())
        normalized_variant = raw.replace(b"epoch-001", "epoch-e\u0301".encode("utf-8"))
        with self.assertRaises(BACKEND.StoreWireError):
            BACKEND.StoreWire.from_bytes("restore-ledger-transition-data.v2", normalized_variant)

    def test_exact_wire_arrays_and_frame_hash(self):
        raw = b"\x22" * 32
        tagged = "sha256:v1:" + "a" * 64
        transition = load_json(ROOT / "tests/recovery-managed/fixtures/wire-kats.json")["profiles"][0]["store_text"].encode()
        wire = BACKEND.StoreWire.from_bytes("restore-ledger-transition-data.v2", transition)
        restore_begin = BACKEND.build_restore_begin(raw, b"\x33" * 32, wire, wire, tagged)
        self.assertEqual(BACKEND.parse_managed_json(restore_begin)[0:3], ["RESTORE_BEGIN", 2, BACKEND.MANAGED_SCHEMA])
        frame = BACKEND.build_frame(BACKEND.DIRECTION_LOCAL_TO_REMOTE, "DISCOVERY", 1, b"\x44" * 32, restore_begin)
        self.assertEqual(BACKEND.frame_hash(frame), hashlib.sha256(frame).digest())
        decoded = BACKEND.decode_frame(frame)
        self.assertEqual(decoded.payload, restore_begin)

    def test_payload_and_frame_boundaries(self):
        with self.assertRaises(BACKEND.ProtocolError):
            BACKEND.build_frame(BACKEND.DIRECTION_LOCAL_TO_REMOTE, "DISCOVERY", 0, b"\0" * 32, b"{}")
        with self.assertRaises(BACKEND.ProtocolError):
            BACKEND.build_frame(BACKEND.DIRECTION_LOCAL_TO_REMOTE, "DISCOVERY", 1, b"\0" * 32, b"x" * (BACKEND.MAX_CONTROL_PAYLOAD_BYTES + 1))


if __name__ == "__main__":
    unittest.main()
