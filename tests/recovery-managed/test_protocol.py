import hashlib
import importlib.util
import json
import pathlib
import stat
import struct
import sys
import unittest
from collections import OrderedDict
from dataclasses import replace


ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("swz_test_backend", ROOT / "recovery/managed/backend.py")
assert SPEC is not None and SPEC.loader is not None
BACKEND = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BACKEND
SPEC.loader.exec_module(BACKEND)


N_LOCAL = bytes(range(32))
N_REMOTE = bytes(range(32, 64))
M = "ab" * 32
I = "01" * 32
ET = "02" * 32
EA = "03" * 32
A = "04" * 32
G = "05" * 32
C = "06" * 32
L = "07" * 32
P = "08" * 32
V = "09" * 32
O = "0a" * 32
HK = "0b" * 32
Q = "0c" * 32
SUP = "0d" * 32
CUS = "0e" * 32
DIS = "0f" * 32
BST = "10" * 32
BRK = "11" * 32
AGT = "12" * 32
BQ = "13" * 32
U = "14" * 32
RQ = "15" * 32
ACCEPTED_SESSION = "16" * 32


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


def runtime_record() -> list[object]:
    return [
        "12345678-1234-4234-8234-123456789abc",
        "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14",
        True, True, 0, "0", True, M, "17" * 32, "18" * 32,
    ]


def admission_transcript() -> list[bytes]:
    boot = BACKEND.build_boot("0" * 64, "epoch-qualified-001", "authority-qualified-001",
                              "2026-09-07T00:00:00.000000Z", I, ET, G, L, U, RQ)
    boot_frame = BACKEND.build_frame(1, "BOOT", 0, N_LOCAL, boot)
    challenge_commitment = BACKEND.managed_hash(
        "challenge.v1", BACKEND.frame_hash(boot_frame), bytes.fromhex(C),
        bytes.fromhex(A), N_LOCAL, N_REMOTE).hex()
    challenge = BACKEND.build_challenge(BACKEND.frame_hash(boot_frame), A, C, N_REMOTE,
                                        BACKEND.frame_hash(boot_frame), "123456789")
    challenge_frame = BACKEND.build_frame(2, "CHALLENGE", 1, N_LOCAL, challenge)
    evidence_fields = [I, ET, EA, A, G, L, P, V, O, HK, Q, SUP, BST, CUS, BRK, AGT,
                       BQ, C, M, U, RQ, challenge_commitment, runtime_record(), M]
    evidence_fields[-1] = BACKEND.managed_hash(
        "evidence.v1", N_LOCAL, BACKEND.frame_hash(challenge_frame),
        BACKEND.managed_json(evidence_fields[:-1])).hex()
    evidence = BACKEND.build_evidence(BACKEND.frame_hash(challenge_frame), evidence_fields)
    evidence_frame = BACKEND.build_frame(2, "EVIDENCE", 2, N_LOCAL, evidence)
    accept_without_commitment = [C, G, U, evidence_fields[-1], BACKEND.frame_hash(evidence_frame).hex()]
    accept_commitment = BACKEND.managed_hash(
        "accept.v1", N_LOCAL, BACKEND.managed_json(accept_without_commitment)).hex()
    accept = BACKEND.build_accept(BACKEND.frame_hash(evidence_frame),
                                  [*accept_without_commitment, accept_commitment])
    accept_frame = BACKEND.build_frame(1, "ACCEPT", 3, N_LOCAL, accept)
    accepted = BACKEND.build_accepted(BACKEND.frame_hash(accept_frame),
                                      [C, A, accept_commitment, ACCEPTED_SESSION, M])
    accepted_frame = BACKEND.build_frame(2, "ACCEPTED", 4, N_LOCAL, accepted)
    session = BACKEND.FrameSession(N_LOCAL)
    for raw, direction, name in ((boot_frame, 1, "BOOT"), (challenge_frame, 2, "CHALLENGE"),
                                 (evidence_frame, 2, "EVIDENCE"), (accept_frame, 1, "ACCEPT"),
                                 (accepted_frame, 2, "ACCEPTED")):
        session.accept(raw, direction=direction, message=name)
    return [boot_frame, challenge_frame, evidence_frame, accept_frame, accepted_frame]


class ProtocolContractTests(unittest.TestCase):
    @staticmethod
    def repack(frame: bytes, payload: bytes) -> bytes:
        header = list(BACKEND.FRAME_HEADER.unpack(frame[:BACKEND.FRAME_HEADER_BYTES]))
        header[-1] = len(payload)
        return BACKEND.FRAME_HEADER.pack(*header) + payload

    def assert_frame_rejected(self, frame: bytes) -> None:
        with self.assertRaises(BACKEND.BoundaryError):
            BACKEND.decode_frame(frame)

    @staticmethod
    def result_context_vector() -> tuple[object, object, bytes, bytes]:
        bind = BACKEND.ResultContextBind(
            context_generation=0x0102030405060708,
            generation=b"g" * 32,
            connection=b"c" * 32,
            session=b"s" * 32,
            n_local=N_LOCAL,
            restore_begin_frame_hash=b"r" * 32,
            transition_id="restore-v2-" + "a" * 48,
            epoch_ref="epoch-qualified-001",
            authority_ref="authority-qualified-001",
            barrier_utc="2026-09-07T00:00:00.000000Z",
            commitments=tuple(bytes([index + 1]) * 32 for index in range(17)),
            source=BACKEND.ResultContextSourceDescriptor(
                1, 2, 3, stat.S_IFREG | 0o600, 4, 5, 1, 0,
                b"x" * 32, b"y" * 32,
            ),
            target=BACKEND.ResultContextTargetDescriptor(
                6, 7, stat.S_IFIFO | 0o600, 8, b"z" * 32, b"w" * 32,
            ),
        )
        bind_envelope = BACKEND.encode_result_context_bind(bind)
        final = BACKEND.ResultContextFinal(
            bind_envelope_sha256=hashlib.sha256(bind_envelope).digest(),
            context_generation=bind.context_generation,
            generation=bind.generation,
            connection=bind.connection,
            session=bind.session,
            transition_id=bind.transition_id,
            finality_serial=9,
            source_bytes_read=3,
            sink_bytes_accepted=3,
            source_sha256=b"q" * 32,
            sink_ack_digest=b"p" * 32,
            restore_count=1,
            exit_status=0,
            result_code=0,
            source_eof=True,
            restore_stdin_eof=True,
            worker_stdout_eof=True,
            worker_stderr_eof=True,
            worker_pidfd_exited=True,
            worker_cgroup_empty=True,
            target_readback_verified=True,
            owned_cleanup_complete=True,
            cleanup_state=1,
            stdout=b"",
            stderr=b"",
            cleanup_inventory_digest=b"k" * 32,
        )
        final_envelope = BACKEND.encode_result_context_final(final)
        return bind, final, bind_envelope, bind_envelope + final_envelope

    def test_run400_result_context_exact_vectors_and_rejections(self):
        bind, final, bind_envelope, stream = self.result_context_vector()
        decoded_bind, decoded_final = BACKEND.decode_result_context_stream(stream)
        self.assertEqual(decoded_bind, bind)
        self.assertEqual(decoded_final, final)
        self.assertEqual(stream[:8], BACKEND.RESULT_CONTEXT_BIND_MAGIC)
        self.assertEqual(stream[len(bind_envelope):len(bind_envelope) + 8], BACKEND.RESULT_CONTEXT_FINAL_MAGIC)
        self.assertEqual(len(bind_envelope), 16 + 1048 + 32)
        self.assertEqual(len(stream) - len(bind_envelope), 16 + 344 + 32)
        self.assertLessEqual(len(bind_envelope) - 48, BACKEND.RESULT_CONTEXT_BIND_PAYLOAD_MAX_BYTES)
        self.assertLessEqual(len(stream) - 96, BACKEND.RESULT_CONTEXT_COMBINED_PAYLOAD_MAX_BYTES)

        for malformed in (
                stream[:-1], stream + b"x", b"X" + stream[1:],
                bind_envelope + bind_envelope,
                b"x" * (BACKEND.RESULT_CONTEXT_STREAM_MAX_BYTES + 1),
        ):
            with self.assertRaises(BACKEND.BoundaryError):
                BACKEND.decode_result_context_stream(malformed)

        stale_final = replace(final, transition_id="restore-v2-" + "b" * 48)
        stale_stream = bind_envelope + BACKEND.encode_result_context_final(stale_final)
        with self.assertRaises(BACKEND.BoundaryError):
            BACKEND.decode_result_context_stream(stale_stream)

        for field in ("generation", "connection", "session"):
            mismatched_final = replace(final, **{field: b"n" * 32})
            mismatched_stream = bind_envelope + BACKEND.encode_result_context_final(mismatched_final)
            with self.assertRaises(BACKEND.BoundaryError):
                BACKEND.decode_result_context_stream(mismatched_stream)

        bad_bind_digest = replace(final, bind_envelope_sha256=b"d" * 32)
        bad_digest_stream = bind_envelope + BACKEND.encode_result_context_final(bad_bind_digest)
        with self.assertRaises(BACKEND.BoundaryError):
            BACKEND.decode_result_context_stream(bad_digest_stream)

        with self.assertRaises(BACKEND.BoundaryError):
            BACKEND.encode_result_context_final(replace(final, stdout=b"x" * 4097))
        with self.assertRaises(BACKEND.BoundaryError):
            BACKEND.ResultContextTargetDescriptor(
                6, 7, stat.S_IFREG | 0o600, 8, b"z" * 32, b"w" * 32)
        with self.assertRaises(BACKEND.BoundaryError):
            BACKEND.ResultContextSourceDescriptor(
                1, 2, 3, stat.S_IFIFO | 0o600, 4, 5, 1, 0,
                b"x" * 32, b"y" * 32)

    def test_native_result_validation_reconstructs_rc_and_requires_terminal_eof(self):
        bind, final, _, _ = self.result_context_vector()
        transition_data_commitment = "sha256:v1:" + (bytes([15]) * 32).hex()
        proceed_payload, proceed_commitment = BACKEND.build_proceed(
            bind.session, bind.transition_id, transition_data_commitment,
            bind.restore_begin_frame_hash)
        proceed_frame = BACKEND.build_frame(
            BACKEND.DIRECTION_LOCAL_TO_REMOTE, "PROCEED", 7, bind.n_local,
            proceed_payload)
        expected_record = BACKEND.native_result_record_for_validation(bind, final)
        result_wire = BACKEND.store_wire_record("swz-recovery-result.v2", expected_record)
        result_payload, expected_rc = BACKEND.build_result(
            bind.session, bind.transition_id, BACKEND.frame_hash(proceed_frame),
            proceed_commitment, result_wire)
        result_frame = BACKEND.build_frame(
            BACKEND.DIRECTION_REMOTE_TO_LOCAL, "RESULT", 8, bind.n_local,
            result_payload)
        _, decoded_wire, decoded_record, decoded_rc = BACKEND.validate_native_result_frame(
            result_frame, n_local=bind.n_local, proceed_frame=proceed_frame,
            session=bind.session, transition_id=bind.transition_id,
            proceed_commitment=proceed_commitment, bind=bind, final=final)
        self.assertEqual(decoded_wire, result_wire)
        self.assertEqual(decoded_record, expected_record)
        self.assertEqual(decoded_rc, expected_rc)
        self.assertTrue(result_wire.store_bytes.endswith(b"\n"))
        with self.assertRaises(BACKEND.BoundaryError):
            BACKEND.native_result_record_for_validation(
                bind, final, terminal_input_eof=False)
        forged_record = OrderedDict(expected_record)
        forged_record["terminal_input_eof"] = False
        forged_wire = BACKEND.store_wire_record(
            "swz-recovery-result.v2", forged_record)
        forged_payload, _ = BACKEND.build_result(
            bind.session, bind.transition_id, BACKEND.frame_hash(proceed_frame),
            proceed_commitment, forged_wire)
        forged_frame = BACKEND.build_frame(
            BACKEND.DIRECTION_REMOTE_TO_LOCAL, "RESULT", 8, bind.n_local,
            forged_payload)
        with self.assertRaises(BACKEND.ProtocolError):
            BACKEND.validate_native_result_frame(
                forged_frame, n_local=bind.n_local, proceed_frame=proceed_frame,
                session=bind.session, transition_id=bind.transition_id,
                proceed_commitment=proceed_commitment, bind=bind, final=final)

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
        frames = admission_transcript()
        raw = frames[0]
        self.assertEqual(raw[:8], b"SWZFRM02")
        decoded = BACKEND.decode_frame(raw, expected_n_local=N_LOCAL,
                                       expected_direction=1, expected_message="BOOT",
                                       expected_sequence=0)
        self.assertEqual(len(raw), BACKEND.FRAME_HEADER_BYTES + len(decoded.payload))
        self.assertEqual((decoded.direction, decoded.message, decoded.sequence), (1, "BOOT", 0))
        self.assertEqual(decoded.n_local, N_LOCAL)
        self.assertEqual(BACKEND.frame_hash(raw), __import__("hashlib").sha256(raw).digest())
        with self.assertRaises(BACKEND.ProtocolError):
            BACKEND.decode_frame(raw + b"x")

    def test_store_profiles_and_restore_messages_use_exact_order(self):
        frames = admission_transcript()
        transition = BACKEND.store_wire_record("restore-ledger-transition-data.v2", transition_record())
        evidence = BACKEND.store_wire_record("restore-begin-evidence.v2", evidence_record())
        discovery, _ = BACKEND.build_discovery(bytes.fromhex(ACCEPTED_SESSION), 23,
                                                "qualified-artifact",
                                                commitment("d"), commitment("e"),
                                                commitment("f"), commitment("1"),
                                                commitment("2"),
                                                BACKEND.frame_hash(frames[4]))
        discovery_frame = BACKEND.build_frame(2, "DISCOVERY", 5, N_LOCAL, discovery)
        begin = BACKEND.build_restore_begin(bytes.fromhex(ACCEPTED_SESSION),
                                            BACKEND.frame_hash(discovery_frame),
                                            transition, evidence, commitment("8"))
        begin_frame = BACKEND.build_frame(1, "RESTORE_BEGIN", 6, N_LOCAL, begin)
        begin_value = BACKEND.parse_managed_json(begin)
        self.assertEqual(begin_value[0:3], ["RESTORE_BEGIN", 2, BACKEND.MANAGED_SCHEMA])
        proceed, pc = BACKEND.build_proceed(bytes.fromhex(ACCEPTED_SESSION),
                                            "restore-v2-" + "a" * 48,
                                            commitment("a"),
                                            BACKEND.frame_hash(begin_frame))
        proceed_frame = BACKEND.build_frame(1, "PROCEED", 7, N_LOCAL, proceed)
        result, rc = BACKEND.build_result(bytes.fromhex(ACCEPTED_SESSION),
                                           "restore-v2-" + "a" * 48,
                                           BACKEND.frame_hash(proceed_frame), pc,
                                           BACKEND.store_wire_record("swz-recovery-result.v2", result_record()))
        result_frame = BACKEND.build_frame(2, "RESULT", 8, N_LOCAL, result)
        self.assertEqual(len(pc), 32)
        self.assertEqual(len(rc), 32)
        self.assertEqual(BACKEND.parse_managed_json(result)[0], "RESULT")
        session = BACKEND.FrameSession(N_LOCAL)
        for raw, direction, message in zip(
                frames + [discovery_frame, begin_frame, proceed_frame, result_frame],
                (1, 2, 2, 1, 2, 2, 1, 1, 2),
                ("BOOT", "CHALLENGE", "EVIDENCE", "ACCEPT", "ACCEPTED",
                 "DISCOVERY", "RESTORE_BEGIN", "PROCEED", "RESULT")):
            session.accept(raw, direction=direction, message=message)

    def test_managed_json_is_strict_and_id_two_is_reserved(self):
        with self.assertRaises(BACKEND.CanonicalJSONError):
            BACKEND.parse_managed_json(b'["BOOT",2,"swz-managed.v1",null]')
        with self.assertRaises(BACKEND.CanonicalJSONError):
            BACKEND.parse_managed_json(b'["BOOT",2,"swz-managed.v1",1.0]')
        with self.assertRaises(BACKEND.CanonicalJSONError):
            BACKEND.parse_managed_json(b'{"z":1,"a":2}')
        with self.assertRaises(BACKEND.ProtocolError):
            BACKEND.make_message("READY", "0" * 64, [])

    def test_wire_type_domains_do_not_substitute(self):
        value = bytes(range(32))
        with self.assertRaises(BACKEND.ProtocolError):
            BACKEND.build_challenge("0" * 64, BACKEND.Managed32(value),
                                    BACKEND.Managed32(value), BACKEND.FrameHash32(value),
                                    BACKEND.FrameHash32(value), "1")
        with self.assertRaises(BACKEND.ProtocolError):
            BACKEND.build_challenge("0" * 64, M, C, BACKEND.PlainSHA256(value),
                                    BACKEND.FrameHash32(value), "1")

    def test_complete_python_frame_kat_is_independent_and_chained(self):
        frames = admission_transcript()
        self.assertEqual(len(frames), 5)
        previous = None
        for sequence, raw in enumerate(frames):
            decoded = BACKEND.decode_frame(raw, expected_n_local=N_LOCAL,
                                           previous_frame=previous,
                                           expected_sequence=sequence)
            self.assertEqual(decoded.n_local, N_LOCAL)
            self.assertEqual(decoded.payload[0], ord("["))
            payload = BACKEND.parse_managed_json(decoded.payload)
            self.assertEqual(payload[3], "0" * 64 if sequence == 0 else BACKEND.frame_hash(previous).hex())
            previous = raw

    def test_run395_wire_shape_and_type_rejections(self):
        frames = admission_transcript()
        for sequence, raw in enumerate(frames):
            self.assertEqual(raw[20:52], N_LOCAL)
            self.assertEqual(BACKEND.parse_managed_json(raw[56:])[3],
                             "0" * 64 if sequence == 0 else BACKEND.frame_hash(frames[sequence - 1]).hex())

        uppercase = bytearray(frames[1])
        uppercase[56 + uppercase[56:].find(b"a")] = ord("A")
        self.assert_frame_rejected(bytes(uppercase))

        challenge = BACKEND.parse_managed_json(frames[1][56:])
        short_hex = list(challenge)
        short_hex[6] = short_hex[6][:-1]
        self.assert_frame_rejected(self.repack(frames[1], BACKEND.managed_json(short_hex)))
        long_hex = list(challenge)
        long_hex[6] = long_hex[6] + "0"
        self.assert_frame_rejected(self.repack(frames[1], BACKEND.managed_json(long_hex)))
        numeric_u64 = list(challenge)
        numeric_u64[8] = 123456789
        self.assert_frame_rejected(self.repack(frames[1], BACKEND.managed_json(numeric_u64)))

        evidence = BACKEND.parse_managed_json(frames[2][56:])
        runtime_u32_string = list(evidence)
        runtime_u32_string[26] = list(runtime_u32_string[26])
        runtime_u32_string[26][17] = "0"
        self.assert_frame_rejected(self.repack(frames[2], BACKEND.managed_json(runtime_u32_string)))
        runtime_u64_number = list(evidence)
        runtime_u64_number[26] = list(runtime_u64_number[26])
        runtime_u64_number[26][1] = 1
        self.assert_frame_rejected(self.repack(frames[2], BACKEND.managed_json(runtime_u64_number)))

        missing = list(challenge)
        missing.pop()
        self.assert_frame_rejected(self.repack(frames[1], BACKEND.managed_json(missing)))
        extra = list(challenge)
        extra.append("17" * 32)
        self.assert_frame_rejected(self.repack(frames[1], BACKEND.managed_json(extra)))
        null_value = list(challenge)
        null_value[4] = None
        null_payload = json.dumps(null_value, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        with self.assertRaises(BACKEND.BoundaryError):
            BACKEND.decode_frame(self.repack(frames[1], null_payload))

        with self.assertRaises(BACKEND.ProtocolError):
            BACKEND.build_frame(1, "BOOT", 0, N_LOCAL, b"SWZAPP01")

        reordered = list(evidence)
        reordered[26] = list(reordered[26])
        reordered[26][0], reordered[26][1] = reordered[26][1], reordered[26][0]
        self.assert_frame_rejected(self.repack(frames[2], BACKEND.managed_json(reordered)))

    def test_store_wire_and_numeric_forms_are_not_interchangeable(self):
        self.assertTrue(struct.Struct("!8sBBBBQ32sI").size == BACKEND.FRAME_HEADER_BYTES)
        discovery, _ = BACKEND.build_discovery(bytes.fromhex(ACCEPTED_SESSION), 23,
                                                "qualified-artifact", commitment("d"),
                                                commitment("e"), commitment("f"),
                                                commitment("1"), commitment("2"))
        value = BACKEND.parse_managed_json(discovery)
        value[5] = 23
        with self.assertRaises(BACKEND.ProtocolError):
            BACKEND.build_frame(2, "DISCOVERY", 5, N_LOCAL, BACKEND.managed_json(value))

    def test_filename_uuid_and_limits_fail_closed(self):
        with self.assertRaises(BACKEND.IdentityError):
            BACKEND.canonical_filename_octets("../artifact")
        with self.assertRaises(BACKEND.IdentityError):
            BACKEND.validate_uuid_text("00000000-0000-3000-8000-000000000000")
        with self.assertRaises(BACKEND.ProtocolError):
            BACKEND.build_frame(1, "BOOT", 17, b"n" * 32, b"{}\n")


if __name__ == "__main__":
    unittest.main()
