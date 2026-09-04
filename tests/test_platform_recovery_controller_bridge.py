from __future__ import annotations

import ast
import base64
import copy
import hashlib
import importlib.util
import json
import pathlib
import struct
import sys
import types
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


def _load_module(name: str, path: pathlib.Path) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("module spec unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


BRIDGE = _load_module(
    "platform_recovery_controller_bridge_run343_tests",
    ROOT / "scripts" / "platform-recovery-controller-bridge.py",
)


def _store_lp(*parts: str | bytes) -> bytes:
    result = bytearray()
    for part in parts:
        value = part.encode("utf-8") if isinstance(part, str) else part
        result.extend(struct.pack("!I", len(value)))
        result.extend(value)
    return bytes(result)


def _store_commitment(domain: str, *parts: str | bytes) -> str:
    return "sha256:v1:" + hashlib.sha256(
        _store_lp("recovery-commitment.v1", domain, *parts)
    ).hexdigest()


class MemoryStore:
    """Small deterministic V2 store double; it exposes no external side effects."""

    def __init__(self, *, cas_mode: str = "A") -> None:
        self.cas_mode = cas_mode
        self.bind_calls = 0
        self.consume_calls = 0
        self.abandon_calls = 0
        self.frames: list[dict[str, object]] = []
        private = {
            "container_identity": "container-private",
            "volume_identity": "volume-private",
            "runner_identity": "runner-private",
            "salt": "salt-private",
            "spool_hmac_key": "s" * 32,
        }
        ref = "epoch-run343"
        authority = "authority-run343"
        self.snapshot = types.SimpleNamespace(
            record={
                "epoch_ref": ref,
                "authority_ref": authority,
                "state": "INITIALISED",
                "artifact_binding_state": "PENDING",
                "artifact_commitment": None,
                "runner_commitment": _store_commitment("runner", private["runner_identity"]),
                "manifest_digest": _store_commitment("manifest", b"manifest"),
                "container_commitment": _store_commitment("container-identity", private["container_identity"]),
                "volume_commitment": _store_commitment("volume-identity", private["volume_identity"]),
            },
            manifest={},
            private_identities=private,
            artifact_binding={
                "artifact_binding_state": "PENDING",
                "execution_row_id": None,
                "artifact_filename": None,
                "artifact_commitment": None,
            },
            ledger={
                "state": "UNCONSUMED",
                "transition_id": None,
                "transition_target": None,
                "transition_data_commitment": None,
            },
            spool={
                "state": "OPEN",
                "last_stage": "NONE",
                "next_sequence": 1,
                "last_frame_hash": "sha256:v1:" + ("0" * 64),
                "highest_contiguous_commit": 0,
                "frame_count": 0,
            },
        )

    def load_epoch(self, epoch_ref: str):
        if epoch_ref != self.snapshot.record["epoch_ref"]:
            raise RuntimeError("unknown epoch")
        return copy.deepcopy(self.snapshot)

    def record_digest(self, epoch_ref: str) -> str:
        return _store_commitment(
            "epoch-record",
            BRIDGE._canonical_json(self.snapshot.record, limit=65536),
        )

    def ledger_digest(self, epoch_ref: str) -> str:
        payload = {
            "epoch_ref": epoch_ref,
            "state": self.snapshot.ledger["state"],
            "transition_id": self.snapshot.ledger["transition_id"],
            "transition_target": self.snapshot.ledger["transition_target"],
            "transition_data_commitment": self.snapshot.ledger["transition_data_commitment"],
        }
        return _store_commitment(
            "restore-ledger",
            BRIDGE._canonical_json(payload, limit=8192),
        )

    def bind_artifact_v2(self, epoch_ref: str, execution_row_id: int, artifact_filename: str) -> str:
        self.bind_calls += 1
        commitment = _store_commitment(
            "artifact-row", str(execution_row_id), artifact_filename
        )
        self.snapshot.record["state"] = "INITIALISED"
        self.snapshot.record["artifact_binding_state"] = "BOUND"
        self.snapshot.record["artifact_commitment"] = commitment
        self.snapshot.artifact_binding.update(
            {
                "artifact_binding_state": "BOUND",
                "execution_row_id": str(execution_row_id),
                "artifact_filename": artifact_filename,
                "artifact_commitment": commitment,
            }
        )
        return commitment

    def mark_ready(self, epoch_ref: str):
        self.snapshot.record["state"] = "READY"
        return self.load_epoch(epoch_ref)

    def activate(self, epoch_ref: str):
        self.snapshot.record["state"] = "ACTIVE"
        return self.load_epoch(epoch_ref)

    def consume_restore(self, epoch_ref: str, transition_id: str, *, expected_digest: str, data):
        self.consume_calls += 1
        if self.cas_mode == "B":
            raise BRIDGE.StoreTransitionError("CAS_MISMATCH", safety_state="UNCONSUMED")
        if self.cas_mode == "C":
            self.snapshot.ledger.update(
                {
                    "state": "CONSUMED",
                    "transition_id": transition_id,
                    "transition_target": "RESTORE_STARTED",
                    "transition_data_commitment": _store_commitment("restore-ledger-transition", b"wrong"),
                }
            )
            raise BRIDGE.StoreTransitionError("WRITE_UNCERTAIN", safety_state="CONSUMED")
        if expected_digest != self.ledger_digest(epoch_ref):
            raise BRIDGE.StoreTransitionError("CAS_MISMATCH", safety_state="UNCONSUMED")
        transition_commitment = _store_commitment(
            "restore-ledger-transition",
            BRIDGE._canonical_json(data, limit=8192),
        )
        self.snapshot.ledger.update(
            {
                "state": "CONSUMED",
                "transition_id": transition_id,
                "transition_target": "RESTORE_STARTED",
                "transition_data_commitment": transition_commitment,
            }
        )
        return types.SimpleNamespace(state="CONSUMED", idempotent=False)

    def prepare_runner_frame(self, epoch_ref: str, stage: str, payload):
        return {"stage": stage, "payload": dict(payload)}

    def ingest_frame(self, epoch_ref: str, frame):
        self.frames.append(copy.deepcopy(frame))
        stage = frame["stage"]
        self.snapshot.spool["last_stage"] = stage
        self.snapshot.spool["frame_count"] += 1
        self.snapshot.spool["next_sequence"] += 1
        if stage == "COMMIT":
            self.snapshot.record["state"] = "CONSUMED"
            self.snapshot.spool["state"] = "COMMITTED"
            self.snapshot.spool["highest_contiguous_commit"] = self.snapshot.spool["frame_count"]
        elif stage == "ABANDON":
            self.snapshot.record["state"] = "ABANDONED"
            self.snapshot.spool["state"] = "ABANDONED"
        return types.SimpleNamespace(sequence=self.snapshot.spool["frame_count"])

    def abandon(self, epoch_ref: str):
        self.abandon_calls += 1
        self.snapshot.record["state"] = "ABANDONED"
        self.snapshot.spool["last_stage"] = "ABANDON"
        self.snapshot.spool["state"] = "ABANDONED"
        return self.load_epoch(epoch_ref)


class BridgeContractTests(unittest.TestCase):
    barrier = "2026-09-04T00:00:00.000000Z"

    def test_exact_package_provenance_and_fixed_namespace(self):
        self.assertEqual(len(BRIDGE.CANONICAL_LOCATOR_PACKAGE), 8398)
        self.assertEqual(len(BRIDGE.CANONICAL_LOCATOR_SOURCE), 35994)
        self.assertEqual(len(BRIDGE.CANONICAL_LOCATOR_SOURCE.splitlines()), 1019)
        self.assertEqual(
            hashlib.sha256(BRIDGE.CANONICAL_LOCATOR_SOURCE).hexdigest(),
            "17925f1364565edbb39fa0f776e25d6f0410d8408d9bdce214143edf1d6f34d5",
        )
        self.assertEqual(
            hashlib.sha256(BRIDGE.CANONICAL_LOCATOR_PACKAGE).hexdigest(),
            "5913fd800e89eff823cef6c08753154e5447eb0ff04eca68dac1668999d002ee",
        )
        self.assertEqual(
            hashlib.sha256(BRIDGE.CANONICAL_LOCATOR_PACKAGE_B64.encode()).hexdigest(),
            "44fba3ed738e696e83e72d0a406cb1d8652c21aaa49f583debb4d907fae05321",
        )
        self.assertEqual(
            BRIDGE.CANONICAL_LOCATOR_PACKAGE_COMMITMENT,
            "49ff535562d62c7b06b02638685c8962e24714d873b8c75a2602a05d84ded386",
        )
        self.assertEqual(
            BRIDGE.verify_canonical_locator_package(),
            BRIDGE.CANONICAL_LOCATOR_SOURCE,
        )
        drift = BRIDGE.CANONICAL_LOCATOR_PACKAGE_B64[:-1] + (
            "A" if BRIDGE.CANONICAL_LOCATOR_PACKAGE_B64[-1] != "A" else "B"
        )
        with self.assertRaises(BRIDGE.PackageIntegrityError):
            BRIDGE.verify_canonical_locator_package(drift)

        namespace = BRIDGE.compile_canonical_locator_namespace()
        self.assertNotEqual(namespace["__name__"], "__main__")
        self.assertTrue(callable(namespace["execute_operation"]))
        tree = ast.parse(BRIDGE.CANONICAL_LOCATOR_SOURCE.decode("utf-8"))
        self.assertEqual(
            sum(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "execute_operation"
                for node in ast.walk(tree)),
            1,
        )
        facts = BRIDGE.execute_canonical_locator_once(self.barrier)
        self.assertEqual(facts.classification, "EXACTLY_ONE")
        self.assertEqual(facts.operation_counts["logical_selects"], 1)

    def test_fixed_limits_accept_exact_and_reject_limit_plus_one(self):
        key = b"k" * 32
        nonce = b"n" * 32
        frame_nonce = b"f" * 16
        payload = b"x" * BRIDGE.MAX_AUTH_PAYLOAD_BYTES
        frame = BRIDGE.encode_authenticated_frame(
            key, BRIDGE.DIRECTION_LOCAL_TO_REMOTE, BRIDGE.MESSAGE_BOOT,
            1, nonce, payload, frame_nonce=frame_nonce
        )
        self.assertEqual(len(frame), BRIDGE.MAX_AUTH_FRAME_BYTES)
        with self.assertRaises(BRIDGE.ProtocolError):
            BRIDGE.encode_authenticated_frame(
                key, BRIDGE.DIRECTION_LOCAL_TO_REMOTE, BRIDGE.MESSAGE_BOOT,
                1, nonce, payload + b"x", frame_nonce=b"g" * 16
            )

        session = BRIDGE.SessionBudget()
        for _ in range(BRIDGE.MAX_SESSION_FRAMES):
            session.charge(BRIDGE.MAX_AUTH_FRAME_BYTES)
        self.assertEqual(session.frames, 16)
        self.assertEqual(session.bytes, BRIDGE.MAX_SESSION_BYTES)
        with self.assertRaises(BRIDGE.ProtocolError):
            session.charge(1)

        capture = BRIDGE.BoundedCapture(BRIDGE.MAX_STDOUT_CAPTURE_BYTES)
        capture.append(b"x" * BRIDGE.MAX_STDOUT_CAPTURE_BYTES)
        self.assertFalse(capture.overflow)
        capture.append(b"x")
        self.assertTrue(capture.overflow)

        captures = BRIDGE.CaptureSet()
        captures.append("stdout", b"x" * BRIDGE.MAX_STDOUT_CAPTURE_BYTES)
        captures.append("stderr", b"y" * BRIDGE.MAX_STDERR_CAPTURE_BYTES)
        self.assertFalse(captures.combined_overflow)
        captures.append("stderr", b"z")
        self.assertTrue(captures.stderr.overflow)
        self.assertTrue(captures.combined_overflow)

        exact_control = json.dumps(
            "x" * (BRIDGE.MAX_CONTROL_PAYLOAD_BYTES - 2),
            separators=(",", ":"),
        ).encode()
        self.assertEqual(len(exact_control), BRIDGE.MAX_CONTROL_PAYLOAD_BYTES)
        BRIDGE.validate_control_payload(exact_control)
        with self.assertRaises(BRIDGE.ProtocolError):
            BRIDGE.validate_control_payload(exact_control + b"x")

        exact_loader = b"#" * BRIDGE.MAX_LOADER_SOURCE_BYTES
        BRIDGE.validate_loader_source(exact_loader)
        with self.assertRaises(BRIDGE.PackageIntegrityError):
            BRIDGE.validate_loader_source(exact_loader + b"#")

        exact_public = BRIDGE.encode_public_splq_frame(
            1, b"x" * BRIDGE.MAX_PUBLIC_PAYLOAD_BYTES
        )
        self.assertEqual(len(exact_public), BRIDGE.MAX_PUBLIC_FRAME_BYTES)
        self.assertEqual(
            BRIDGE.decode_public_splq_frame(exact_public)[1],
            b"x" * BRIDGE.MAX_PUBLIC_PAYLOAD_BYTES,
        )
        with self.assertRaises(BRIDGE.ProtocolError):
            BRIDGE.encode_public_splq_frame(1, b"x" * (BRIDGE.MAX_PUBLIC_PAYLOAD_BYTES + 1))

        BRIDGE.validate_reader_chunk(b"x" * BRIDGE.READER_CHUNK_BYTES)
        with self.assertRaises(BRIDGE.BridgeError):
            BRIDGE.validate_reader_chunk(b"x" * (BRIDGE.READER_CHUNK_BYTES + 1))

        events = BRIDGE.EventQueueBudget()
        for index in range(BRIDGE.EVENT_QUEUE_MAX_ENTRIES):
            events.put(index)
        self.assertEqual(events.size, BRIDGE.EVENT_QUEUE_MAX_ENTRIES)
        with self.assertRaises(BRIDGE.BridgeError):
            events.put("limit-plus-one")

        memory = BRIDGE.MemoryBudget()
        memory.reserve(BRIDGE.MAX_MEMORY_BYTES)
        with self.assertRaises(BRIDGE.BridgeError):
            memory.reserve(1)

        BRIDGE._validate_discovery_tuple(1, "a" * BRIDGE.MAX_FILENAME_BYTES)
        with self.assertRaises(BRIDGE.ProtocolError):
            BRIDGE._validate_discovery_tuple(1, "a" * (BRIDGE.MAX_FILENAME_BYTES + 1))

    def test_boot_causality_and_strict_control(self):
        plan = BRIDGE.RecoveryPlanV1(
            "epoch-run343", "authority-run343", self.barrier,
            "container-private", "volume-private", "runner-private", "salt-private"
        )
        boot = BRIDGE.build_boot_payload(plan)
        self.assertNotIn("image_id", boot)
        self.assertNotIn("image_commitment", boot)
        self.assertEqual(boot["image_ref"], "postgres:17-alpine")
        self.assertEqual(BRIDGE.validate_boot_payload(boot), boot)
        with self.assertRaises(BRIDGE.ProtocolError):
            BRIDGE.validate_boot_payload({**boot, "image_id": "sha256:" + "a" * 64})
        ready = {"type": "READY", "version": 1, "barrier_utc": self.barrier}
        self.assertEqual(BRIDGE.decode_control(BRIDGE.encode_control(ready), "READY"), ready)
        with self.assertRaises(BRIDGE.ProtocolError):
            BRIDGE.decode_control(BRIDGE.encode_control(ready) + b" ", "READY")

    def test_authenticated_frame_replay_and_finality(self):
        key = b"k" * 32
        nonce = b"n" * 32
        raw = BRIDGE.encode_authenticated_frame(
            key, BRIDGE.DIRECTION_LOCAL_TO_REMOTE, BRIDGE.MESSAGE_READY,
            1, nonce, b"{}", frame_nonce=b"f" * 16
        )
        decoded = BRIDGE.decode_authenticated_frame(key, raw)
        self.assertEqual(decoded.sequence, 1)
        session = BRIDGE.SessionBudget()
        session.add(decoded)
        with self.assertRaises(BRIDGE.ProtocolError):
            session.add(decoded)
        clean = BRIDGE.ProcessTerminalEvidence(
            0, True, True, True, 0, 0, False, False, False
        )
        self.assertIsNone(BRIDGE.ProcessSupervisor.finality_error(clean))
        for evidence, expected in (
            (copy.copy(clean). __class__(0, True, True, True, 1, 0, False, False, False), "PROCESS_TRAILING_OUTPUT"),
            (copy.copy(clean). __class__(0, True, True, True, 0, 1, False, False, False), "PROCESS_STDERR_FORBIDDEN"),
            (copy.copy(clean). __class__(0, True, False, True, 0, 0, False, False, False), "PROCESS_TERMINATION_UNCERTAIN"),
        ):
            self.assertEqual(BRIDGE.ProcessSupervisor.finality_error(evidence), expected)

    def test_success_has_one_session_and_private_continuity(self):
        store = MemoryStore()
        image = BRIDGE.SyntheticImageSource()
        artifacts = BRIDGE.SyntheticArtifactProvider()
        result = BRIDGE.run_controller_bridge(
            store, "epoch-run343", self.barrier,
            image_source=image, artifact_source=artifacts,
            randomness=lambda n: bytes(range(1, n + 1)),
        )
        self.assertEqual(result.classification, "SUCCESS")
        self.assertEqual(result.error_code, None)
        self.assertEqual(
            result.transcript,
            ("BOOT", "READY", "DISCOVERY", "EPOCH_READY", "RUNNER_STARTED",
             "CAS_A", "RESTORE_BEGIN", "PROCEED", "RESULT", "COMMIT"),
        )
        self.assertEqual(store.bind_calls, 1)
        self.assertEqual(store.consume_calls, 1)
        self.assertEqual(store.abandon_calls, 0)
        counts = result.counters.public()
        self.assertEqual(counts["image_inspections"], 1)
        self.assertEqual(counts["target_creations"], 1)
        self.assertEqual(counts["isolation_readbacks"], 1)
        self.assertEqual(counts["discovery_messages"], 1)
        self.assertEqual(counts["bind_calls"], 1)
        self.assertEqual(counts["cas_attempts"], 1)
        self.assertEqual(counts["cas_a"], 1)
        self.assertEqual(counts["proceed_messages"], 1)
        self.assertEqual(counts["result_messages"], 1)
        self.assertEqual(counts["commits"], 1)
        self.assertEqual(counts["restore_attempts"], 1)
        self.assertEqual(counts["cleanup_calls"], 1)
        self.assertEqual(counts["session_frames"], 5)
        self.assertGreater(counts["session_bytes"], 0)
        self.assertEqual(image.inspect_calls, 1)
        self.assertEqual(image.pull_calls, 0)
        self.assertEqual(image.create_calls, 1)
        self.assertEqual(image.readback_calls, 1)
        self.assertEqual(image.cleanup_calls, 1)
        artifact = artifacts.last_artifact
        self.assertIsNotNone(artifact)
        self.assertEqual(artifact.fstat_calls, 1)
        self.assertEqual(artifact.read_calls, 1)
        self.assertEqual(artifact.restore_calls, 1)
        self.assertEqual(artifact.reopen_attempts, 0)
        self.assertEqual(store.snapshot.record["state"], "CONSUMED")
        self.assertEqual(store.snapshot.ledger["state"], "CONSUMED")
        self.assertEqual(store.snapshot.spool["last_stage"], "COMMIT")
        public = result.public_projection()
        encoded = json.dumps(public, separators=(",", ":")).encode()
        for secret_name in (
            "container-private", "volume-private", "runner-private",
            "s" * 32, "synthetic-backup-001.dump",
        ):
            self.assertNotIn(secret_name.encode(), encoded)

    def test_cas_b_only_abandons_accepted_unconsumed_state(self):
        store = MemoryStore(cas_mode="B")
        result = BRIDGE.run_controller_bridge(store, "epoch-run343", self.barrier)
        self.assertEqual(result.classification, "FAILURE")
        self.assertEqual(result.error_code, "STORE_TRANSITION_FAILED")
        self.assertFalse(result.post_cas_uncertain)
        self.assertEqual(result.counters.public()["cas_b"], 1)
        self.assertEqual(store.abandon_calls, 1)
        self.assertEqual(store.snapshot.record["state"], "ABANDONED")
        self.assertEqual(store.snapshot.ledger["state"], "UNCONSUMED")
        self.assertEqual(result.counters.public()["proceed_messages"], 0)

    def test_cas_c_is_uncertain_and_never_abandoned_or_proceeded(self):
        store = MemoryStore(cas_mode="C")
        result = BRIDGE.run_controller_bridge(store, "epoch-run343", self.barrier)
        self.assertEqual(result.classification, "FAILURE")
        self.assertEqual(result.error_code, "POST_CAS_UNCERTAIN")
        self.assertTrue(result.post_cas_uncertain)
        self.assertEqual(result.counters.public()["cas_c"], 1)
        self.assertEqual(store.abandon_calls, 0)
        self.assertEqual(result.counters.public()["proceed_messages"], 0)
        self.assertEqual(store.snapshot.record["state"], "ACTIVE")
        self.assertEqual(store.snapshot.ledger["state"], "CONSUMED")
        self.assertEqual(store.snapshot.spool["last_stage"], "RUNNER_STARTED")

    def test_unsupported_platform_and_image_failure_fail_closed_with_cleanup(self):
        unsupported = MemoryStore()
        result = BRIDGE.run_controller_bridge(
            unsupported, "epoch-run343", self.barrier,
            recovery_host_platform="windows",
        )
        self.assertEqual(result.error_code, "PLATFORM_UNSUPPORTED")
        self.assertEqual(unsupported.abandon_calls, 1)

        failed_store = MemoryStore()
        image = BRIDGE.SyntheticImageSource(mode="isolation-fail")
        result = BRIDGE.run_controller_bridge(
            failed_store, "epoch-run343", self.barrier, image_source=image
        )
        self.assertEqual(result.classification, "FAILURE")
        self.assertEqual(result.error_code, "ISOLATION_FAILED")
        self.assertEqual(image.inspect_calls, 1)
        self.assertEqual(image.pull_calls, 0)
        self.assertEqual(image.create_calls, 1)
        self.assertEqual(image.cleanup_calls, 1)
        self.assertEqual(failed_store.abandon_calls, 1)


if __name__ == "__main__":
    unittest.main()
