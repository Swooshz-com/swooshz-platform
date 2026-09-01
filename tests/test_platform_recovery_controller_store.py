import base64
import ctypes
import importlib.util
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE_PATH = ROOT / "scripts" / "platform-recovery-controller-store.py"
SPEC = importlib.util.spec_from_file_location("platform_recovery_controller_store", SOURCE_PATH)
STORE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = STORE
SPEC.loader.exec_module(STORE)


PRIVATE = {
    "container_identity": "synthetic-container-001",
    "volume_identity": "synthetic-volume-001",
    "runner_identity": "synthetic-runner-001",
    "artifact_row_id": "synthetic-row-001",
    "artifact_filename": "synthetic-artifact-001",
    "salt": "synthetic-salt-only-in-private-fixture",
    "spool_hmac_key": "synthetic-hmac-key-only-in-private-fixture",
}


def harden_windows_test_root(root):
    if os.name != "nt":
        return
    adapter = STORE.WindowsDurabilityAdapter()
    kernel32, advapi32 = adapter._require_api()
    current, current_buffer = adapter._current_sid()
    system = adapter._well_known_sid("S-1-5-18")
    administrators = adapter._well_known_sid("S-1-5-32-544")
    try:
        advapi32.InitializeAcl.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]
        advapi32.InitializeAcl.restype = ctypes.c_int
        advapi32.AddAccessAllowedAceEx.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ubyte, ctypes.c_ulong, ctypes.c_void_p]
        advapi32.AddAccessAllowedAceEx.restype = ctypes.c_int
        advapi32.SetNamedSecurityInfoW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        advapi32.SetNamedSecurityInfoW.restype = ctypes.c_ulong
        acl = ctypes.create_string_buffer(4096)
        if not advapi32.InitializeAcl(acl, len(acl), 2):
            raise unittest.SkipTest("disposable ACL fixture initialization unavailable")
        inheritance = 0x01 | 0x02
        for sid in (current, system, administrators):
            if not advapi32.AddAccessAllowedAceEx(acl, 2, inheritance, 0x1F01FF, sid):
                raise unittest.SkipTest("disposable ACL fixture construction unavailable")
        result = advapi32.SetNamedSecurityInfoW(str(root), 1, 0x00000004, None, None, ctypes.cast(acl, ctypes.c_void_p), None)
        if result != 0:
            raise unittest.SkipTest("disposable ACL fixture assignment unavailable")
    finally:
        kernel32.LocalFree(system)
        kernel32.LocalFree(administrators)
        _ = current_buffer


class FaultAdapter(STORE.DurabilityAdapter):
    """Strict fault injector around the real current-OS adapter."""

    def __init__(self, delegate):
        super().__init__()
        self.delegate = delegate
        self.platform_name = delegate.platform_name
        self.used_primitives = delegate.used_primitives
        self.fail_before_transition_name = None
        self.fail_after_transition_name = None
        self.fail_after_temp_readback = False
        self.mismatch_readback = False

    def prove_root(self, root, *, test_mode=False):
        return self.delegate.prove_root(root, test_mode=test_mode)

    def validate_component(self, path, *, expect_directory=None):
        return self.delegate.validate_component(path, expect_directory=expect_directory)

    def mkdir_exclusive(self, path):
        return self.delegate.mkdir_exclusive(path)

    def create_transaction_lock(self, path):
        return self.delegate.create_transaction_lock(path)

    @contextmanager
    def epoch_transaction_lock(self, path):
        with self.delegate.epoch_transaction_lock(path):
            yield

    def read_authority(self, path, *, max_bytes):
        return self.delegate.read_authority(path, max_bytes=max_bytes)

    def list_entries(self, directory):
        return self.delegate.list_entries(directory)

    def flush_directory(self, directory):
        return self.delegate.flush_directory(directory)

    def write_authority(self, path, payload, *, replace, max_bytes):
        old_before = self.delegate.before_authority_transition
        old_after = self.delegate.after_temp_readback

        def before(target):
            if self.fail_before_transition_name == target.name:
                raise STORE.DurabilityError("INJECTED_PRE_TRANSITION_FAILURE")

        def after(temp_path, expected, actual):
            if self.fail_after_temp_readback:
                raise STORE.DurabilityError("INJECTED_PARTIAL_TEMP_FAILURE")
            if self.mismatch_readback:
                raise STORE.DurabilityError("INJECTED_READBACK_MISMATCH")

        self.delegate.before_authority_transition = before
        self.delegate.after_temp_readback = after
        try:
            proof = self.delegate.write_authority(path, payload, replace=replace, max_bytes=max_bytes)
            if self.fail_after_transition_name == path.name:
                raise STORE.DurabilityError("INJECTED_POST_TRANSITION_FAILURE")
            return proof
        finally:
            self.delegate.before_authority_transition = old_before
            self.delegate.after_temp_readback = old_after


class ControllerStoreTests(unittest.TestCase):
    def new_store(self, adapter=None):
        temporary = tempfile.TemporaryDirectory(prefix="run291-controller-store-")
        self.addCleanup(temporary.cleanup)
        root = pathlib.Path(temporary.name)
        harden_windows_test_root(root)
        return STORE.ControllerStore.for_disposable_test_root(root, adapter=adapter)

    def create_epoch(self, store, epoch_ref="epoch-synthetic-001", authority_ref="authority-synthetic-001", *, supersedes=None):
        store.create_epoch(
            epoch_ref,
            authority_ref,
            private_identities=PRIVATE,
            supersedes_epoch_ref=supersedes,
        )
        return epoch_ref

    def create_active_epoch(self, store, epoch_ref="epoch-synthetic-001", authority_ref="authority-synthetic-001", *, supersedes=None):
        self.create_epoch(store, epoch_ref, authority_ref, supersedes=supersedes)
        store.bind_artifact_row(epoch_ref, PRIVATE["artifact_row_id"])
        store.bind_artifact(epoch_ref, PRIVATE["artifact_row_id"], PRIVATE["artifact_filename"])
        store.mark_ready(epoch_ref)
        store.activate(epoch_ref)
        return epoch_ref

    def ingest_stage(self, store, epoch_ref, stage, payload=None):
        return store.ingest_frame(
            epoch_ref,
            store.prepare_runner_frame(epoch_ref, stage, payload or {"ref": f"{stage.lower()}-ref"}),
        )

    def prepare_runner_sequence(self, store, epoch_ref):
        self.ingest_stage(store, epoch_ref, "EPOCH_READY", {"ref": "epoch-ready-ref"})
        self.ingest_stage(store, epoch_ref, "RUNNER_STARTED", {"ref": "runner-started-ref"})

    def commit_epoch(self, store, epoch_ref, transition_id="transition-commit-helper"):
        self.prepare_runner_sequence(store, epoch_ref)
        store.consume_restore(epoch_ref, transition_id, expected_digest=store.ledger_digest(epoch_ref), data={"classification": "synthetic"})
        self.ingest_stage(store, epoch_ref, "RESTORE_BEGIN", {"ref": "restore-begin-ref"})
        self.ingest_stage(store, epoch_ref, "COMMIT", {"ref": "commit-ref"})
        return store.load_epoch(epoch_ref)

    def mutate_json_file(self, store, epoch_ref, filename, mutator):
        path = store._file_path(epoch_ref, filename)
        payload = store.adapter.read_authority(path, max_bytes=STORE._document_limit(filename))
        value = json.loads(payload.decode("utf-8"))
        mutated = mutator(value)
        path.write_bytes(STORE.canonical_json_bytes(mutated, max_bytes=STORE._document_limit(filename)))
        return path

    def test_fresh_create_and_readback_pass(self):
        store = self.new_store()
        snapshot = store.create_epoch("epoch-fresh-001", "authority-fresh-001", private_identities=PRIVATE)
        self.assertEqual(snapshot.record["state"], "INITIALISED")
        self.assertEqual(snapshot.ledger["state"], "UNCONSUMED")
        self.assertEqual(snapshot.spool["next_sequence"], 1)
        self.assertEqual(store.load_epoch("epoch-fresh-001"), snapshot)

    def test_duplicate_epoch_collision_is_rejected_without_adoption(self):
        store = self.new_store()
        self.create_epoch(store, "epoch-collision-001")
        with self.assertRaisesRegex(STORE.EpochStateError, "EPOCH_COLLISION"):
            self.create_epoch(store, "epoch-collision-001")

    def test_manifest_bytes_and_digest_are_deterministic(self):
        first = self.new_store()
        first_ref = self.create_epoch(first, "epoch-deterministic-001", "authority-deterministic-001")
        first_bytes = first.read_authoritative_bytes(first_ref, STORE.MANIFEST_FILENAME)
        first_digest = first.load_epoch(first_ref).record["manifest_digest"]
        first_record_digest = first.record_digest(first_ref)

        second = self.new_store()
        second_ref = self.create_epoch(second, "epoch-deterministic-001", "authority-deterministic-001")
        second_bytes = second.read_authoritative_bytes(second_ref, STORE.MANIFEST_FILENAME)
        second_digest = second.load_epoch(second_ref).record["manifest_digest"]
        second_record_digest = second.record_digest(second_ref)
        self.assertEqual(first_bytes, second_bytes)
        self.assertEqual(first_digest, second_digest)
        self.assertEqual(first_record_digest, second_record_digest)
        self.assertTrue(first_bytes.endswith(b"\n"))
        self.assertNotIn(b"\xef\xbb\xbf", first_bytes)

    def test_namespace_layout_is_exact(self):
        store = self.new_store()
        epoch = self.create_epoch(store, "epoch-layout-001")
        spool_meta = store._file_path(epoch, STORE.SPOOL_META_FILENAME)
        self.assertEqual(spool_meta.parent.name, STORE.SPOOL_DIRNAME)
        self.assertTrue(spool_meta.is_file())
        self.assertFalse((store._epoch_path(epoch) / STORE.SPOOL_META_FILENAME).exists())
        self.assertTrue(store._frames_path(epoch).is_dir())
        self.assertTrue(store._transaction_lock_path(epoch).is_file())

    def test_corrupt_json_is_rejected(self):
        store = self.new_store()
        epoch = self.create_epoch(store)
        path = store._file_path(epoch, STORE.MANIFEST_FILENAME)
        path.write_bytes(b"{\"schema\":\"broken\"}\n")
        with self.assertRaises(STORE.IntegrityError):
            store.load_epoch(epoch)

    def test_truncated_json_is_rejected(self):
        store = self.new_store()
        epoch = self.create_epoch(store)
        path = store._file_path(epoch, STORE.MANIFEST_FILENAME)
        original = store.adapter.read_authority(path, max_bytes=STORE.MAX_MANIFEST_BYTES)
        path.write_bytes(original[:-2])
        with self.assertRaises(STORE.IntegrityError):
            store.load_epoch(epoch)

    def test_digest_mismatch_is_rejected(self):
        store = self.new_store()
        epoch = self.create_epoch(store)

        def change_state(value):
            value["state"] = "READY"
            return value

        self.mutate_json_file(store, epoch, STORE.MANIFEST_FILENAME, change_state)
        with self.assertRaisesRegex(STORE.IntegrityError, "MANIFEST_DIGEST_MISMATCH|CROSS_FILE_CONTRADICTION"):
            store.load_epoch(epoch)

    def test_unknown_and_forbidden_public_fields_are_rejected(self):
        store = self.new_store()
        epoch = self.create_epoch(store)
        evidence = store.public_projection(epoch)
        evidence["secret"] = "synthetic-secret"
        with self.assertRaisesRegex(STORE.PublicEvidenceError, "PUBLIC_FIELD_FORBIDDEN"):
            STORE.serialize_public_evidence(evidence)
        nested = store.public_projection(epoch)
        nested["epoch_ref"] = {"salt": "synthetic-secret"}
        with self.assertRaises(STORE.PublicEvidenceError):
            STORE.serialize_public_evidence(nested)

    def test_legal_ledger_consume(self):
        store = self.new_store()
        epoch = self.create_active_epoch(store)
        self.prepare_runner_sequence(store, epoch)
        digest = store.ledger_digest(epoch)
        permit = store.consume_restore(epoch, "transition-synthetic-001", expected_digest=digest, data={"classification": "synthetic"})
        self.assertFalse(permit.idempotent)
        self.assertEqual(permit.state, "CONSUMED")
        self.assertEqual(store.read_restore_ledger(epoch)["state"], "CONSUMED")
        snapshot = store.load_epoch(epoch)
        self.assertEqual(snapshot.record["state"], "ACTIVE")
        self.assertEqual(snapshot.spool["state"], "OPEN")
        self.assertEqual(snapshot.spool["last_stage"], "RUNNER_STARTED")

    def test_exact_duplicate_consume_is_idempotent_only_for_identical_data(self):
        store = self.new_store()
        epoch = self.create_active_epoch(store)
        self.prepare_runner_sequence(store, epoch)
        data = {"classification": "synthetic"}
        store.consume_restore(epoch, "transition-synthetic-002", expected_digest=store.ledger_digest(epoch), data=data)
        duplicate = store.consume_restore(epoch, "transition-synthetic-002", expected_digest=store.ledger_digest(epoch), data=data)
        self.assertTrue(duplicate.idempotent)
        with self.assertRaisesRegex(STORE.LedgerError, "LEDGER_CONTRADICTION"):
            store.consume_restore(epoch, "transition-synthetic-002", expected_digest=store.ledger_digest(epoch), data={"classification": "different"})

    def test_exact_duplicate_consume_is_not_reissued_after_restore_progression_or_reload(self):
        for progressed_stage in ("RESTORE_BEGIN", "COMMIT", "ABANDON"):
            with self.subTest(progressed_stage=progressed_stage):
                store = self.new_store()
                epoch = self.create_active_epoch(store, f"epoch-permit-non-reuse-{progressed_stage.lower()}")
                self.prepare_runner_sequence(store, epoch)
                transition_id = f"transition-permit-non-reuse-{progressed_stage.lower()}"
                data = {"classification": f"permit-non-reuse-{progressed_stage.lower()}"}
                store.consume_restore(
                    epoch,
                    transition_id,
                    expected_digest=store.ledger_digest(epoch),
                    data=data,
                )

                self.ingest_stage(store, epoch, "RESTORE_BEGIN", {"ref": f"restore-begin-{progressed_stage.lower()}"})
                if progressed_stage == "COMMIT":
                    self.ingest_stage(store, epoch, "COMMIT", {"ref": "commit-permit-non-reuse"})
                elif progressed_stage == "ABANDON":
                    store.abandon(epoch)

                snapshot = store.load_epoch(epoch)
                expected_state = {
                    "RESTORE_BEGIN": ("ACTIVE", "OPEN", "RESTORE_BEGIN"),
                    "COMMIT": ("CONSUMED", "COMMITTED", "COMMIT"),
                    "ABANDON": ("ABANDONED", "ABANDONED", "ABANDON"),
                }[progressed_stage]
                self.assertEqual(
                    (snapshot.record["state"], snapshot.spool["state"], snapshot.spool["last_stage"]),
                    expected_state,
                )

                reloaded = STORE.ControllerStore.for_disposable_test_root(store.root)
                for candidate in (store, reloaded):
                    with self.subTest(progressed_stage=progressed_stage, candidate="reloaded" if candidate is reloaded else "original"):
                        expected_error = "EPOCH_TERMINAL" if progressed_stage == "ABANDON" else "RESTORE_PERMIT_NOT_REUSABLE"
                        with self.assertRaisesRegex(STORE.LedgerError, expected_error) as raised:
                            candidate.consume_restore(
                                epoch,
                                transition_id,
                                expected_digest=candidate.ledger_digest(epoch),
                                data=data,
                            )
                        self.assertEqual(raised.exception.safety_state, "CONSUMED")

    def test_ledger_reset_is_rejected(self):
        store = self.new_store()
        epoch = self.create_active_epoch(store)
        self.prepare_runner_sequence(store, epoch)
        store.consume_restore(epoch, "transition-synthetic-003", expected_digest=store.ledger_digest(epoch))
        bad = {
            "schema": STORE.SCHEMA_RESTORE_LEDGER,
            "epoch_ref": epoch,
            "state": "UNCONSUMED",
            "transition_id": None,
            "transition_target": None,
            "transition_data_commitment": None,
        }
        with self.assertRaises(STORE.LedgerError):
            STORE.validate_restore_ledger({**bad, "state": "UNKNOWN_POTENTIALLY_CONSUMED"})
        with self.assertRaises(STORE.LedgerError):
            store.consume_restore(epoch, "transition-synthetic-004", expected_digest=store.ledger_digest(epoch))

    def test_consumed_epoch_cannot_resume(self):
        store = self.new_store()
        epoch = self.create_active_epoch(store)
        self.prepare_runner_sequence(store, epoch)
        store.consume_restore(epoch, "transition-synthetic-005", expected_digest=store.ledger_digest(epoch))
        with self.assertRaisesRegex(STORE.EpochStateError, "EPOCH_TERMINAL"):
            store.resume_epoch(epoch)

    def test_abandoned_epoch_cannot_resume(self):
        store = self.new_store()
        epoch = self.create_active_epoch(store, "epoch-abandoned-001")
        self.ingest_stage(store, epoch, "EPOCH_READY", {"ref": "abandon-ready-ref"})
        store.abandon(epoch)
        with self.assertRaisesRegex(STORE.EpochStateError, "EPOCH_TERMINAL"):
            store.mark_ready(epoch)

    def test_pre_consumption_failure_leaves_ledger_unconsumed(self):
        base = STORE.make_durability_adapter()
        fault = FaultAdapter(base)
        store = self.new_store(fault)
        epoch = self.create_active_epoch(store, "epoch-pre-failure-001")
        self.prepare_runner_sequence(store, epoch)
        fault.fail_before_transition_name = STORE.LEDGER_FILENAME
        with self.assertRaisesRegex(STORE.DurabilityError, "INJECTED_PRE_TRANSITION_FAILURE"):
            store.consume_restore(epoch, "transition-synthetic-006", expected_digest=store.ledger_digest(epoch))
        fault.fail_before_transition_name = None
        self.assertEqual(store.read_restore_ledger(epoch)["state"], "UNCONSUMED")
        self.assertEqual(store.load_epoch(epoch).record["state"], "ACTIVE")

    def test_post_consumption_failure_remains_consumed(self):
        base = STORE.make_durability_adapter()
        fault = FaultAdapter(base)
        store = self.new_store(fault)
        epoch = self.create_active_epoch(store, "epoch-post-failure-001")
        self.prepare_runner_sequence(store, epoch)
        fault.fail_before_transition_name = STORE.RECORD_FILENAME
        with self.assertRaisesRegex(STORE.DurabilityError, "INJECTED_PRE_TRANSITION_FAILURE"):
            store.consume_restore(epoch, "transition-synthetic-007", expected_digest=store.ledger_digest(epoch))
        fault.fail_before_transition_name = None
        self.assertEqual(store.read_restore_ledger(epoch)["state"], "CONSUMED")
        self.assertEqual(store.ledger_safety_classification(epoch), "CONSUMED")

    def test_ledger_transition_failure_before_store_return_is_consumed(self):
        base = STORE.make_durability_adapter()
        fault = FaultAdapter(base)
        store = self.new_store(fault)
        epoch = self.create_active_epoch(store, "epoch-ledger-transition-failure-001")
        self.prepare_runner_sequence(store, epoch)
        fault.fail_after_transition_name = STORE.LEDGER_FILENAME
        with self.assertRaisesRegex(STORE.DurabilityError, "INJECTED_POST_TRANSITION_FAILURE") as raised:
            store.consume_restore(
                epoch,
                "transition-post-authority-001",
                expected_digest=store.ledger_digest(epoch),
            )
        self.assertEqual(raised.exception.safety_state, "CONSUMED")
        fault.fail_after_transition_name = None
        self.assertEqual(store.read_restore_ledger(epoch)["state"], "CONSUMED")
        self.assertEqual(store.ledger_safety_classification(epoch), "CONSUMED")

    def test_consumed_ledger_frame_transition_failures_are_consumed_and_non_retryable(self):
        for stage in ("RESTORE_BEGIN", "COMMIT", "ABANDON"):
            with self.subTest(stage=stage):
                base = STORE.make_durability_adapter()
                fault = FaultAdapter(base)
                store = self.new_store(fault)
                epoch = self.create_active_epoch(store, f"epoch-frame-transition-failure-{stage.lower()}")
                self.prepare_runner_sequence(store, epoch)
                store.consume_restore(
                    epoch,
                    f"transition-frame-failure-{stage.lower()}",
                    expected_digest=store.ledger_digest(epoch),
                )
                if stage in ("COMMIT", "ABANDON"):
                    self.ingest_stage(store, epoch, "RESTORE_BEGIN", {"ref": f"restore-before-{stage.lower()}"})
                frame = store.prepare_runner_frame(epoch, stage, {"ref": f"failure-{stage.lower()}"})
                frame_name = f"frame-{frame['sequence']:012d}.json"
                fault.fail_after_transition_name = frame_name
                with self.assertRaisesRegex(STORE.DurabilityError, "INJECTED_POST_TRANSITION_FAILURE") as raised:
                    store.ingest_frame(epoch, frame)
                self.assertEqual(raised.exception.safety_state, "CONSUMED")
                fault.fail_after_transition_name = None
                self.assertTrue((store._frames_path(epoch) / frame_name).is_file())
                with self.assertRaises(STORE.ControllerStoreError) as retry:
                    store.ingest_frame(epoch, frame)
                self.assertEqual(retry.exception.safety_state, "CONSUMED")
                self.assertEqual(store.ledger_safety_classification(epoch), "CONSUMED")

    def test_ledger_classifier_requires_a_fully_valid_epoch(self):
        store = self.new_store()
        epoch = self.create_active_epoch(store, "epoch-classifier-validity-001")
        self.prepare_runner_sequence(store, epoch)
        self.assertEqual(store.ledger_safety_classification(epoch), "UNCONSUMED")
        store.consume_restore(
            epoch,
            "transition-classifier-validity-001",
            expected_digest=store.ledger_digest(epoch),
        )
        self.assertEqual(store.ledger_safety_classification(epoch), "CONSUMED")

    def test_bounded_non_validatable_authority_is_conservatively_consumed(self):
        malformed_payloads = (
            ("large-integer", ("9" * 5000 + "\n").encode("ascii")),
            ("deep-structure", ("[" * 2000 + "0" + "]" * 2000 + "\n").encode("ascii")),
        )
        for label, payload in malformed_payloads:
            with self.subTest(label=label):
                store = self.new_store()
                epoch = self.create_epoch(store, f"epoch-classifier-malformed-{label}")
                self.assertLessEqual(len(payload), STORE.MAX_MANIFEST_BYTES)
                store._file_path(epoch, STORE.MANIFEST_FILENAME).write_bytes(payload)

                self.assertEqual(store.ledger_safety_classification(epoch), "CONSUMED")
                with self.assertRaisesRegex(STORE.IntegrityError, "AUTHORITATIVE_STATE_INVALID") as raised:
                    store.load_epoch(epoch)
                self.assertEqual(raised.exception.safety_state, "CONSUMED")

    def test_canonical_unconsumed_ledger_with_terminal_history_classifies_consumed(self):
        store = self.new_store()
        epoch = self.create_active_epoch(store, "epoch-classifier-contradiction-001")
        self.commit_epoch(store, epoch, "transition-classifier-contradiction-001")

        def make_unconsumed(value):
            value.update(
                {
                    "state": "UNCONSUMED",
                    "transition_id": None,
                    "transition_target": None,
                    "transition_data_commitment": None,
                }
            )
            return value

        self.mutate_json_file(store, epoch, STORE.LEDGER_FILENAME, make_unconsumed)
        self.assertEqual(store.read_restore_ledger(epoch)["state"], "UNCONSUMED")
        self.assertEqual(store.ledger_safety_classification(epoch), "CONSUMED")

    def test_pre_replace_failure_preserves_prior_authority(self):
        base = STORE.make_durability_adapter()
        fault = FaultAdapter(base)
        store = self.new_store(fault)
        epoch = self.create_epoch(store, "epoch-authority-001")
        store.mark_ready(epoch)
        self.ingest_stage(store, epoch, "EPOCH_READY", {"ref": "authority-ready-ref"})
        before = store.read_authoritative_bytes(epoch, STORE.MANIFEST_FILENAME)
        fault.fail_before_transition_name = STORE.MANIFEST_FILENAME
        with self.assertRaisesRegex(STORE.DurabilityError, "INJECTED_PRE_TRANSITION_FAILURE"):
            store.abandon(epoch)
        fault.fail_before_transition_name = None
        self.assertEqual(store.read_authoritative_bytes(epoch, STORE.MANIFEST_FILENAME), before)

    def test_partial_temp_is_never_authoritative(self):
        base = STORE.make_durability_adapter()
        fault = FaultAdapter(base)
        store = self.new_store(fault)
        epoch = self.create_epoch(store, "epoch-partial-temp-001")
        before = store.read_authoritative_bytes(epoch, STORE.MANIFEST_FILENAME)
        fault.fail_after_temp_readback = True
        with self.assertRaisesRegex(STORE.DurabilityError, "INJECTED_PARTIAL_TEMP_FAILURE"):
            store.mark_ready(epoch)
        fault.fail_after_temp_readback = False
        self.assertEqual(store.read_authoritative_bytes(epoch, STORE.MANIFEST_FILENAME), before)
        self.assertEqual(store.load_epoch(epoch).record["state"], "INITIALISED")

    def test_readback_mismatch_failure_leaves_prior_authority(self):
        base = STORE.make_durability_adapter()
        fault = FaultAdapter(base)
        store = self.new_store(fault)
        epoch = self.create_epoch(store, "epoch-readback-001")
        before = store.read_authoritative_bytes(epoch, STORE.MANIFEST_FILENAME)
        fault.mismatch_readback = True
        with self.assertRaisesRegex(STORE.DurabilityError, "INJECTED_READBACK_MISMATCH"):
            store.mark_ready(epoch)
        fault.mismatch_readback = False
        self.assertEqual(store.read_authoritative_bytes(epoch, STORE.MANIFEST_FILENAME), before)

    def test_persisted_frame_auth_and_hash_are_reverified_on_reload(self):
        store = self.new_store()
        epoch = self.create_active_epoch(store, "epoch-persisted-frame-integrity-001")
        self.ingest_stage(store, epoch, "EPOCH_READY", {"ref": "epoch-ready-persisted-001"})
        frame = store.prepare_runner_frame(epoch, "RUNNER_STARTED", {"ref": "runner-ref-persisted-001"})
        store.ingest_frame(epoch, frame)
        frame_path = store._frames_path(epoch) / "frame-000000000001.json"
        original = store.adapter.read_authority(frame_path, max_bytes=STORE.MAX_FRAME_BYTES)
        tampered = json.loads(original.decode("utf-8"))
        tampered["auth"] = "hmac:v1:" + ("f" * 64)
        frame_path.write_bytes(STORE.canonical_json_bytes(tampered, max_bytes=STORE.MAX_FRAME_BYTES))
        with self.assertRaisesRegex(STORE.IntegrityError, "SPOOL_AUTH_CONTRADICTION"):
            store.load_epoch(epoch)
        frame_path.write_bytes(original)
        tampered = json.loads(original.decode("utf-8"))
        tampered["frame_hash"] = STORE.recovery_commitment("tampered", "persisted-frame")
        frame_path.write_bytes(STORE.canonical_json_bytes(tampered, max_bytes=STORE.MAX_FRAME_BYTES))
        with self.assertRaisesRegex(STORE.IntegrityError, "SPOOL_FRAME_HASH_CONTRADICTION"):
            store.load_epoch(epoch)

    def test_private_identity_commitment_contradiction_fails_closed(self):
        store = self.new_store()
        epoch = self.create_epoch(store, "epoch-private-integrity-001")
        path = store._file_path(epoch, STORE.PRIVATE_IDENTITIES_FILENAME)
        value = json.loads(store.adapter.read_authority(path, max_bytes=STORE.MAX_PRIVATE_IDENTITIES_BYTES).decode("utf-8"))
        value["container_identity"] = "synthetic-container-tampered"
        path.write_bytes(STORE.canonical_json_bytes(value, max_bytes=STORE.MAX_PRIVATE_IDENTITIES_BYTES))
        with self.assertRaisesRegex(STORE.IntegrityError, "PRIVATE_IDENTITIES_DIGEST_MISMATCH|PRIVATE_IDENTITY_COMMITMENT_MISMATCH"):
            store.load_epoch(epoch)

    def test_cross_file_contradiction_fails_closed(self):
        store = self.new_store()
        epoch = self.create_epoch(store, "epoch-contradiction-001")

        def contradict(value):
            value["restore_ledger_state"] = "CONSUMED"
            return value

        self.mutate_json_file(store, epoch, STORE.MANIFEST_FILENAME, contradict)
        with self.assertRaisesRegex(STORE.IntegrityError, "CROSS_FILE_CONTRADICTION|LEDGER_CROSS_FILE_CONTRADICTION"):
            store.load_epoch(epoch)

    def test_symlink_or_reparse_component_is_rejected(self):
        temporary = tempfile.TemporaryDirectory(prefix="run291-reparse-")
        self.addCleanup(temporary.cleanup)
        root = pathlib.Path(temporary.name)
        link = root.parent / (root.name + "-link")
        try:
            link.symlink_to(root, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("current account cannot create a disposable reparse/symlink fixture")
        self.addCleanup(lambda: link.is_symlink() and link.unlink())
        with self.assertRaisesRegex(STORE.ControllerStoreError, "REPARSE|SYMLINK|STORE_ROOT"):
            STORE.ControllerStore.for_disposable_test_root(link)

    def test_special_file_or_non_directory_root_is_rejected(self):
        temporary = tempfile.TemporaryDirectory(prefix="run291-special-")
        self.addCleanup(temporary.cleanup)
        file_path = pathlib.Path(temporary.name) / "not-a-directory"
        file_path.write_text("synthetic", encoding="utf-8")
        with self.assertRaises(STORE.ControllerStoreError):
            STORE.ControllerStore.for_disposable_test_root(file_path)
        if hasattr(os, "mkfifo"):
            fifo = pathlib.Path(temporary.name) / "synthetic-fifo"
            os.mkfifo(fifo)
            with self.assertRaises(STORE.ControllerStoreError):
                STORE.ControllerStore.for_disposable_test_root(fifo)

    def test_size_limits_are_enforced(self):
        with self.assertRaises(STORE.SchemaError):
            STORE.canonical_json_bytes({"x": "x" * STORE.MAX_FRAME_BYTES}, max_bytes=STORE.MAX_FRAME_BYTES)
        valid_commitment = STORE.recovery_commitment("synthetic", "value")
        with self.assertRaises(STORE.SpoolError):
            STORE.validate_spool_meta({
                "schema": STORE.SCHEMA_SPOOL_META,
                "epoch_ref": "epoch-size-001",
                "state": "OPEN",
                "next_sequence": STORE.MAX_FRAMES + 2,
                "last_frame_hash": STORE.ZERO_FRAME_HASH,
                "highest_contiguous_commit": 0,
                "frame_count": STORE.MAX_FRAMES + 1,
                "total_spool_bytes": STORE.MAX_TOTAL_SPOOL_BYTES + 1,
                "last_stage": "NONE",
                "spool_commitment": valid_commitment,
            })

    def test_public_projection_never_contains_private_fixture_values(self):
        store = self.new_store()
        evidence = store.public_projection(self.create_epoch(store, "epoch-privacy-001"))
        serialized = STORE.serialize_public_evidence(evidence)
        for secret in PRIVATE.values():
            self.assertNotIn(secret.encode("utf-8"), serialized)
        self.assertNotIn(b"container_identity", serialized)
        self.assertNotIn(b"spool_hmac_key", serialized)

    def test_windows_native_gate_or_posix_native_gate_is_truthful(self):
        store = self.new_store()
        self.create_epoch(store, "epoch-native-001")
        primitives = set(store.adapter.used_primitives)
        if os.name == "nt":
            self.assertIsInstance(store.adapter, STORE.WindowsDurabilityAdapter)
            self.assertTrue(any("CreateFileW:CREATE_NEW" in value for value in primitives))
            self.assertIn("FlushFileBuffers", primitives)
            self.assertIn("MoveFileExW:WRITE_THROUGH", primitives)
        else:
            self.assertIsInstance(store.adapter, STORE.PosixDurabilityAdapter)
            self.assertIn("os.open:O_NOFOLLOW|O_EXCL", primitives)
            self.assertIn("os.fsync:file", primitives)
            self.assertIn("os.fsync:directory", primitives)

    def test_unproven_platform_durability_fails_closed(self):
        class Unproven(STORE.DurabilityAdapter):
            platform_name = "synthetic-unsupported"

        temporary = tempfile.TemporaryDirectory(prefix="run291-unproven-")
        self.addCleanup(temporary.cleanup)
        with self.assertRaisesRegex(STORE.FilesystemSafetyError, "DURABILITY_UNSUPPORTED"):
            STORE.ControllerStore.for_disposable_test_root(pathlib.Path(temporary.name), adapter=Unproven())

    def test_posix_semantics_are_not_claimed_on_windows(self):
        if os.name != "nt":
            self.skipTest("opposite-platform gate is only exercised on Windows")
        with self.assertRaisesRegex(STORE.FilesystemSafetyError, "DURABILITY_UNSUPPORTED"):
            STORE.PosixDurabilityAdapter().prove_root(pathlib.Path(tempfile.gettempdir()))

    def test_runner_hmac_hash_and_sequence_rules(self):
        store = self.new_store()
        epoch = self.create_active_epoch(store, "epoch-spool-001")
        first = store.prepare_runner_frame(epoch, "EPOCH_READY", {"ref": "epoch-ready-ref-001"})
        receipt = store.ingest_frame(epoch, first)
        self.assertEqual(receipt.sequence, 1)
        with self.assertRaisesRegex(STORE.SpoolError, "FRAME_DUPLICATE"):
            store.ingest_frame(epoch, first)
        gap = dict(first)
        gap["sequence"] = 3
        with self.assertRaisesRegex(STORE.SpoolError, "FRAME_GAP_OR_REORDER"):
            store.ingest_frame(epoch, gap)
        runner_started = store.prepare_runner_frame(epoch, "RUNNER_STARTED", {"ref": "runner-ref-001"})
        bad_auth = dict(runner_started)
        bad_auth["auth"] = "hmac:v1:" + ("f" * 64)
        with self.assertRaisesRegex(STORE.SpoolError, "FRAME_AUTH_INVALID"):
            store.ingest_frame(epoch, bad_auth)
        bad_hash = dict(runner_started)
        bad_hash["frame_hash"] = STORE.recovery_commitment("tampered", "frame")
        with self.assertRaisesRegex(STORE.SpoolError, "FRAME_HASH_INVALID"):
            store.ingest_frame(epoch, bad_hash)

    def test_runner_reorder_and_stage_contradiction_are_rejected(self):
        store = self.new_store()
        epoch = self.create_active_epoch(store, "epoch-stage-001")
        self.ingest_stage(store, epoch, "EPOCH_READY", {"ref": "epoch-ready-stage-002"})
        with self.assertRaisesRegex(STORE.SpoolError, "FRAME_STAGE_CONTRADICTION"):
            store.prepare_runner_frame(epoch, "EPOCH_READY", {"ref": "lower-stage-001"})

    def test_restore_begin_without_consumed_ledger_is_contradictory(self):
        store = self.new_store()
        epoch = self.create_active_epoch(store, "epoch-restore-begin-001")
        self.prepare_runner_sequence(store, epoch)
        with self.assertRaisesRegex(STORE.SpoolError, "RESTORE_BEGIN_BEFORE_LEDGER_CONSUMED"):
            store.prepare_runner_frame(epoch, "RESTORE_BEGIN", {"ref": "restore-ref-001"})

    def test_highest_contiguous_commit_is_persisted(self):
        store = self.new_store()
        epoch = self.create_active_epoch(store, "epoch-commit-001")
        self.prepare_runner_sequence(store, epoch)
        store.consume_restore(epoch, "transition-commit-001", expected_digest=store.ledger_digest(epoch))
        self.ingest_stage(store, epoch, "RESTORE_BEGIN", {"ref": "restore-ref-002"})
        receipt = self.ingest_stage(store, epoch, "COMMIT", {"ref": "commit-ref-002"})
        self.assertEqual(receipt.highest_contiguous_commit, 4)
        reloaded = store.load_epoch(epoch)
        self.assertEqual(reloaded.spool["highest_contiguous_commit"], 4)
        self.assertEqual(reloaded.record["state"], "CONSUMED")
        self.assertEqual(reloaded.ledger["state"], "CONSUMED")
        self.assertEqual(reloaded.spool["state"], "COMMITTED")
        self.assertEqual(store.public_projection(epoch)["highest_contiguous_commit"], 4)

    def test_exact_stage_sequence_and_consume_preconditions(self):
        store = self.new_store()
        epoch = self.create_active_epoch(store, "epoch-exact-stage-001")
        with self.assertRaisesRegex(STORE.SpoolError, "FRAME_STAGE_CONTRADICTION"):
            store.prepare_runner_frame(epoch, "RUNNER_STARTED", {"ref": "runner-before-ready"})
        self.ingest_stage(store, epoch, "EPOCH_READY", {"ref": "epoch-ready-exact-001"})
        with self.assertRaisesRegex(STORE.SpoolError, "FRAME_STAGE_CONTRADICTION"):
            store.prepare_runner_frame(epoch, "EPOCH_READY", {"ref": "duplicate-ready-001"})
        self.ingest_stage(store, epoch, "RUNNER_STARTED", {"ref": "runner-started-exact-001"})
        with self.assertRaisesRegex(STORE.SpoolError, "FRAME_STAGE_CONTRADICTION"):
            store.prepare_runner_frame(epoch, "COMMIT", {"ref": "commit-before-restore-001"})
        precondition_store = self.new_store()
        precondition_epoch = self.create_active_epoch(precondition_store, "epoch-consume-precondition-001")
        with self.assertRaisesRegex(STORE.LedgerError, "RESTORE_PRECONDITION_FAILED"):
            precondition_store.consume_restore(
                precondition_epoch,
                "transition-before-runner-001",
                expected_digest=precondition_store.ledger_digest(precondition_epoch),
            )

    def test_abandon_requires_prior_nonterminal_frame_and_preserves_unconsumed_ledger(self):
        store = self.new_store()
        epoch = self.create_active_epoch(store, "epoch-abandon-contract-001")
        with self.assertRaisesRegex(STORE.SpoolError, "FRAME_STAGE_CONTRADICTION"):
            store.abandon(epoch)
        self.ingest_stage(store, epoch, "EPOCH_READY", {"ref": "epoch-ready-abandon-001"})
        snapshot = store.abandon(epoch)
        self.assertEqual(snapshot.record["state"], "ABANDONED")
        self.assertEqual(snapshot.manifest["state"], "ABANDONED")
        self.assertEqual(snapshot.spool["state"], "ABANDONED")
        self.assertEqual(snapshot.spool["last_stage"], "ABANDON")
        self.assertEqual(snapshot.ledger["state"], "UNCONSUMED")
        self.assertEqual(snapshot.record["restore_ledger_state"], "UNCONSUMED")
        self.assertEqual(snapshot.manifest["restore_ledger_state"], "UNCONSUMED")
        with self.assertRaisesRegex(STORE.EpochStateError, "EPOCH_TERMINAL"):
            store.prepare_runner_frame(epoch, "RUNNER_STARTED", {"ref": "after-abandon-001"})

    def test_post_consumption_abandon_terminalizes_and_preserves_consumed_ledger(self):
        store = self.new_store()
        epoch = self.create_active_epoch(store, "epoch-post-consumption-abandon-001")
        self.prepare_runner_sequence(store, epoch)
        transition_id = "transition-post-abandon-001"
        data = {"classification": "synthetic-post-abandon"}
        store.consume_restore(
            epoch,
            transition_id,
            expected_digest=store.ledger_digest(epoch),
            data=data,
        )
        self.ingest_stage(store, epoch, "RESTORE_BEGIN", {"ref": "restore-begin-post-abandon-001"})

        terminal = store.abandon(epoch)
        self.assertEqual(terminal.record["state"], "ABANDONED")
        self.assertEqual(terminal.manifest["state"], "ABANDONED")
        self.assertEqual(terminal.record["restore_ledger_state"], "CONSUMED")
        self.assertEqual(terminal.manifest["restore_ledger_state"], "CONSUMED")
        self.assertEqual(terminal.ledger["state"], "CONSUMED")
        self.assertEqual(terminal.spool["state"], "ABANDONED")
        self.assertEqual(terminal.spool["last_stage"], "ABANDON")
        self.assertEqual(terminal.spool["highest_contiguous_commit"], 0)
        self.assertEqual(terminal.spool["frame_count"], 4)

        reloaded = store.load_epoch(epoch)
        self.assertEqual(reloaded.record["state"], "ABANDONED")
        self.assertEqual(reloaded.spool["state"], "ABANDONED")
        self.assertEqual(reloaded.spool["last_stage"], "ABANDON")
        self.assertEqual(reloaded.ledger["state"], "CONSUMED")
        self.assertEqual(reloaded.record["restore_ledger_state"], "CONSUMED")
        self.assertEqual(reloaded.manifest["restore_ledger_state"], "CONSUMED")
        projection = store.public_projection(epoch)
        self.assertEqual(projection["state"], "ABANDONED")
        self.assertEqual(projection["restore_ledger_state"], "CONSUMED")

        with self.assertRaisesRegex(STORE.EpochStateError, "EPOCH_TERMINAL"):
            store.prepare_runner_frame(epoch, "RUNNER_STARTED", {"ref": "after-post-abandon-001"})
        with self.assertRaisesRegex(STORE.SpoolError, "EPOCH_TERMINAL"):
            store.ingest_frame(epoch, {})
        for attempted_id, attempted_data in ((transition_id, data), ("transition-post-abandon-002", data)):
            with self.subTest(attempted_id=attempted_id):
                with self.assertRaisesRegex(STORE.LedgerError, "EPOCH_TERMINAL"):
                    store.consume_restore(
                        epoch,
                        attempted_id,
                        expected_digest=store.ledger_digest(epoch),
                        data=attempted_data,
                    )

    def test_consumed_ledger_abandon_before_restore_begin_is_rejected(self):
        store = self.new_store()
        epoch = self.create_active_epoch(store, "epoch-consumed-abandon-before-restore-001")
        self.prepare_runner_sequence(store, epoch)
        store.consume_restore(
            epoch,
            "transition-consumed-abandon-before-restore-001",
            expected_digest=store.ledger_digest(epoch),
        )
        with self.assertRaisesRegex(STORE.SpoolError, "ABANDON_AFTER_LEDGER_CONSUMED"):
            store.prepare_runner_frame(epoch, "ABANDON", {"state": "ABANDONED"})
        with self.assertRaisesRegex(STORE.SpoolError, "ABANDON_AFTER_LEDGER_CONSUMED"):
            store.abandon(epoch)
        snapshot = store.load_epoch(epoch)
        self.assertEqual(snapshot.record["state"], "ACTIVE")
        self.assertEqual(snapshot.spool["last_stage"], "RUNNER_STARTED")
        self.assertEqual(snapshot.ledger["state"], "CONSUMED")

    def test_reload_rejects_consumed_abandon_without_restore_begin(self):
        store = self.new_store()
        epoch = self.create_active_epoch(store, "epoch-tampered-consumed-abandon-001")
        self.ingest_stage(store, epoch, "EPOCH_READY", {"ref": "epoch-ready-tampered-abandon-001"})
        abandoned = store.abandon(epoch)

        ledger = dict(abandoned.ledger)
        ledger.update(
            {
                "state": "CONSUMED",
                "transition_id": "transition-tampered-abandon-001",
                "transition_target": "RESTORE_STARTED",
                "transition_data_commitment": STORE._private_data_commitment({"classification": "tampered"}),
            }
        )
        store._write_document(
            store._file_path(epoch, STORE.LEDGER_FILENAME),
            ledger,
            max_bytes=STORE.MAX_RESTORE_LEDGER_BYTES,
            replace=True,
        )
        manifest = dict(abandoned.manifest)
        manifest["restore_ledger_state"] = "CONSUMED"
        manifest_bytes = store._write_document(
            store._file_path(epoch, STORE.MANIFEST_FILENAME),
            manifest,
            max_bytes=STORE.MAX_MANIFEST_BYTES,
            replace=True,
        )
        record = dict(abandoned.record)
        record["restore_ledger_state"] = "CONSUMED"
        record["manifest_digest"] = STORE.bytes_commitment(STORE.DOMAIN_MANIFEST, manifest_bytes)
        store._write_document(
            store._file_path(epoch, STORE.RECORD_FILENAME),
            record,
            max_bytes=STORE.MAX_EPOCH_RECORD_BYTES,
            replace=True,
        )

        with self.assertRaisesRegex(STORE.IntegrityError, "ABANDON_AFTER_LEDGER_CONSUMED"):
            store.load_epoch(epoch)

    def test_commit_requires_restore_begin_and_terminalizes_record(self):
        store = self.new_store()
        epoch = self.create_active_epoch(store, "epoch-commit-contract-001")
        self.prepare_runner_sequence(store, epoch)
        store.consume_restore(epoch, "transition-contract-001", expected_digest=store.ledger_digest(epoch))
        with self.assertRaisesRegex(STORE.SpoolError, "FRAME_STAGE_CONTRADICTION"):
            store.prepare_runner_frame(epoch, "COMMIT", {"ref": "commit-before-restore-002"})
        self.ingest_stage(store, epoch, "RESTORE_BEGIN", {"ref": "restore-begin-contract-001"})
        snapshot = self.ingest_stage(store, epoch, "COMMIT", {"ref": "commit-contract-001"})
        self.assertEqual(snapshot.sequence, 4)
        reloaded = store.load_epoch(epoch)
        self.assertEqual(reloaded.record["state"], "CONSUMED")
        self.assertEqual(reloaded.ledger["state"], "CONSUMED")
        self.assertEqual(reloaded.spool["state"], "COMMITTED")
        with self.assertRaisesRegex(STORE.EpochStateError, "EPOCH_TERMINAL"):
            store.prepare_runner_frame(epoch, "EPOCH_READY", {"ref": "after-commit-001"})

    def test_spool_metadata_is_derived_and_metadata_only_reopen_fails(self):
        store = self.new_store()
        epoch = self.create_active_epoch(store, "epoch-spool-derived-001")
        self.ingest_stage(store, epoch, "EPOCH_READY", {"ref": "epoch-ready-derived-001"})
        frame_path = store._frames_path(epoch) / "frame-000000000001.json"
        frame_path.unlink()
        with self.assertRaisesRegex(STORE.IntegrityError, "SPOOL_FRAME_COUNT_CONTRADICTION"):
            store.load_epoch(epoch)

    def test_committed_and_abandoned_spool_metadata_tamper_fails_closed(self):
        committed_mutations = (
            ("state", "OPEN"),
            ("last_stage", "EPOCH_READY"),
            ("highest_contiguous_commit", 0),
            ("last_frame_hash", STORE.ZERO_FRAME_HASH),
            ("total_spool_bytes", 1),
        )
        for field, replacement in committed_mutations:
            with self.subTest(state="COMMITTED", field=field):
                store = self.new_store()
                epoch = self.create_active_epoch(store, f"epoch-committed-tamper-{field.lower()}")
                self.commit_epoch(store, epoch)
                self.mutate_json_file(store, epoch, STORE.SPOOL_META_FILENAME, lambda value, field=field, replacement=replacement: {**value, field: replacement})
                with self.assertRaises(STORE.IntegrityError):
                    store.load_epoch(epoch)

        abandoned_mutations = (("state", "OPEN"), ("last_stage", "EPOCH_READY"))
        for field, replacement in abandoned_mutations:
            with self.subTest(state="ABANDONED", field=field):
                store = self.new_store()
                epoch = self.create_active_epoch(store, f"epoch-abandoned-tamper-{field.lower()}")
                self.ingest_stage(store, epoch, "EPOCH_READY", {"ref": "epoch-ready-tamper-001"})
                store.abandon(epoch)
                self.mutate_json_file(store, epoch, STORE.SPOOL_META_FILENAME, lambda value, field=field, replacement=replacement: {**value, field: replacement})
                with self.assertRaises(STORE.IntegrityError):
                    store.load_epoch(epoch)

    def test_terminal_frame_followed_by_frame_is_rejected_on_reload(self):
        for terminal_stage in ("COMMIT", "ABANDON"):
            with self.subTest(terminal_stage=terminal_stage):
                store = self.new_store()
                epoch = self.create_active_epoch(store, f"epoch-terminal-followed-{terminal_stage.lower()}")
                if terminal_stage == "COMMIT":
                    snapshot = self.commit_epoch(store, epoch)
                else:
                    self.ingest_stage(store, epoch, "EPOCH_READY", {"ref": "epoch-ready-terminal-001"})
                    store.abandon(epoch)
                    snapshot = store.load_epoch(epoch)
                sequence = snapshot.spool["next_sequence"]
                payload = {"ref": "after-terminal-frame"}
                stage = "RUNNER_STARTED"
                auth = store._frame_auth(snapshot.private_identities, epoch, sequence, stage, payload, snapshot.spool["last_frame_hash"])
                frame = {
                    "schema": STORE.SCHEMA_RUNNER_FRAME,
                    "epoch_ref": epoch,
                    "sequence": sequence,
                    "stage": stage,
                    "payload": payload,
                    "previous_hash": snapshot.spool["last_frame_hash"],
                    "auth": auth,
                    "frame_hash": store._frame_hash(epoch, sequence, stage, payload, snapshot.spool["last_frame_hash"], auth),
                }
                frame_bytes = STORE.canonical_json_bytes(frame, max_bytes=STORE.MAX_FRAME_BYTES)
                store._write_document(
                    store._frames_path(epoch) / f"frame-{sequence:012d}.json",
                    frame,
                    max_bytes=STORE.MAX_FRAME_BYTES,
                    replace=False,
                )

                def append_frame(value):
                    value["next_sequence"] = sequence + 1
                    value["last_frame_hash"] = frame["frame_hash"]
                    value["frame_count"] = snapshot.spool["frame_count"] + 1
                    value["total_spool_bytes"] = snapshot.spool["total_spool_bytes"] + len(frame_bytes)
                    value["highest_contiguous_commit"] = sequence if terminal_stage == "COMMIT" else 0
                    value["last_stage"] = terminal_stage
                    return value

                self.mutate_json_file(store, epoch, STORE.SPOOL_META_FILENAME, append_frame)
                with self.assertRaisesRegex(STORE.IntegrityError, "SPOOL_STAGE_CONTRADICTION"):
                    store.load_epoch(epoch)

    def test_private_salt_and_hmac_key_digest_is_checked_before_and_after_frames(self):
        for field in ("salt", "spool_hmac_key"):
            with self.subTest(field=field, point="before-frames"):
                store = self.new_store()
                epoch = self.create_epoch(store, f"epoch-private-before-{field}")
                self.mutate_json_file(
                    store,
                    epoch,
                    STORE.PRIVATE_IDENTITIES_FILENAME,
                    lambda value, field=field: {**value, field: value[field] + "-tampered"},
                )
                with self.assertRaisesRegex(STORE.IntegrityError, "PRIVATE_IDENTITIES_DIGEST_MISMATCH"):
                    store.load_epoch(epoch)
            with self.subTest(field=field, point="after-frames"):
                store = self.new_store()
                epoch = self.create_active_epoch(store, f"epoch-private-after-{field}")
                self.ingest_stage(store, epoch, "EPOCH_READY", {"ref": "epoch-ready-private-001"})
                self.mutate_json_file(
                    store,
                    epoch,
                    STORE.PRIVATE_IDENTITIES_FILENAME,
                    lambda value, field=field: {**value, field: value[field] + "-tampered"},
                )
                with self.assertRaisesRegex(STORE.IntegrityError, "PRIVATE_IDENTITIES_DIGEST_MISMATCH"):
                    store.load_epoch(epoch)

    def test_two_independent_store_instances_serialize_same_digest_consume(self):
        temporary = tempfile.TemporaryDirectory(prefix="run293-controller-race-")
        self.addCleanup(temporary.cleanup)
        root = pathlib.Path(temporary.name)
        harden_windows_test_root(root)
        first = STORE.ControllerStore.for_disposable_test_root(root)
        epoch = self.create_active_epoch(first, "epoch-instance-race-001")
        self.prepare_runner_sequence(first, epoch)
        second = STORE.ControllerStore.for_disposable_test_root(root)
        expected_digest = first.ledger_digest(epoch)
        barrier = threading.Barrier(2)
        results = []

        def consume(store):
            barrier.wait()
            try:
                permit = store.consume_restore(
                    epoch,
                    "transition-instance-race-001",
                    expected_digest=expected_digest,
                    data={"classification": "instance-race"},
                )
                results.append(("permit", permit.idempotent))
            except STORE.ControllerStoreError as error:
                results.append(("error", error.code))

        threads = [threading.Thread(target=consume, args=(first,)), threading.Thread(target=consume, args=(second,))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(sorted(results), [("permit", False), ("permit", True)])
        snapshot = first.load_epoch(epoch)
        self.assertEqual(snapshot.record["state"], "ACTIVE")
        self.assertEqual(snapshot.ledger["state"], "CONSUMED")

    def test_competing_processes_serialize_same_digest_consume_on_current_os(self):
        temporary = tempfile.TemporaryDirectory(prefix="run293-controller-process-race-")
        self.addCleanup(temporary.cleanup)
        root = pathlib.Path(temporary.name)
        harden_windows_test_root(root)
        store = STORE.ControllerStore.for_disposable_test_root(root)
        epoch = self.create_active_epoch(store, "epoch-process-race-001")
        self.prepare_runner_sequence(store, epoch)
        expected_digest = store.ledger_digest(epoch)
        coordination = tempfile.TemporaryDirectory(prefix="run293-process-coordination-")
        self.addCleanup(coordination.cleanup)
        coordination_path = pathlib.Path(coordination.name)
        ready_paths = [coordination_path / "ready-1", coordination_path / "ready-2"]
        go_path = coordination_path / "go"
        worker = r"""
import importlib.util
import json
import pathlib
import sys
import time

source_path, root_path, epoch_ref, expected_digest, ready_path, go_path = sys.argv[1:]
spec = importlib.util.spec_from_file_location("run293_store_child", source_path)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = module
spec.loader.exec_module(module)
pathlib.Path(ready_path).write_text("ready", encoding="ascii")
deadline = time.monotonic() + 20
while not pathlib.Path(go_path).exists():
    if time.monotonic() >= deadline:
        raise RuntimeError("coordination-timeout")
    time.sleep(0.01)
try:
    store = module.ControllerStore.for_disposable_test_root(root_path)
    permit = store.consume_restore(
        epoch_ref,
        "transition-process-race-001",
        expected_digest=expected_digest,
        data={"classification": "process-race"},
    )
    print(json.dumps({"ok": True, "idempotent": permit.idempotent}, sort_keys=True), flush=True)
except Exception as error:
    print(json.dumps({"ok": False, "type": type(error).__name__, "code": getattr(error, "code", None)}, sort_keys=True), flush=True)
    raise
"""
        processes = []
        try:
            for index, ready_path in enumerate(ready_paths, start=1):
                processes.append(
                    subprocess.Popen(
                        [
                            sys.executable,
                            "-c",
                            worker,
                            str(SOURCE_PATH),
                            str(root),
                            epoch,
                            expected_digest,
                            str(ready_path),
                            str(go_path),
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                )
            deadline = time.monotonic() + 20
            while not all(path.exists() for path in ready_paths):
                if time.monotonic() >= deadline:
                    self.fail("process race workers did not rendezvous")
                time.sleep(0.01)
            go_path.write_text("go", encoding="ascii")
            outputs = []
            for process in processes:
                stdout, stderr = process.communicate(timeout=30)
                self.assertEqual(process.returncode, 0, stdout + stderr)
                outputs.append(json.loads(stdout.strip().splitlines()[-1]))
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
            for process in processes:
                if process.poll() is None:
                    process.kill()
        self.assertEqual(sorted((result["ok"], result["idempotent"]) for result in outputs), [(True, False), (True, True)])
        self.assertEqual(store.load_epoch(epoch).ledger["state"], "CONSUMED")

    def test_ephemeral_mountinfo_is_rejected_without_positive_test_proof(self):
        root = pathlib.Path(tempfile.gettempdir()) / "run293-synthetic-mounted-root"
        mountinfo = pathlib.Path(tempfile.gettempdir()) / f"run293-mountinfo-{os.getpid()}.txt"
        self.addCleanup(lambda: mountinfo.exists() and mountinfo.unlink())
        for filesystem in ("tmpfs", "ramfs", "overlay", "aufs", "squashfs"):
            mountinfo.write_text(
                f"36 25 0:32 / {root.as_posix()} rw,relatime - {filesystem} {filesystem} rw\n",
                encoding="ascii",
            )
            with self.subTest(filesystem=filesystem):
                with self.assertRaisesRegex(STORE.FilesystemSafetyError, "LOCAL_VOLUME_PROOF_FAILED"):
                    STORE._prove_posix_local_volume(root, mountinfo_path=mountinfo, test_mode=False)
                if filesystem in ("tmpfs", "ramfs", "overlay", "aufs"):
                    STORE._prove_posix_local_volume(root, mountinfo_path=mountinfo, test_mode=True)
                else:
                    with self.assertRaisesRegex(STORE.FilesystemSafetyError, "LOCAL_VOLUME_PROOF_FAILED"):
                        STORE._prove_posix_local_volume(root, mountinfo_path=mountinfo, test_mode=True)

    def test_windows_handle_bound_proof_uses_reparse_safe_identity_acl_and_lock_apis(self):
        if os.name != "nt":
            self.skipTest("current-OS Windows proof is only exercised on Windows")
        store = self.new_store()
        epoch = self.create_epoch(store, "epoch-windows-proof-001")
        store.load_epoch(epoch)
        primitives = set(store.adapter.used_primitives)
        self.assertIsInstance(store.adapter, STORE.WindowsDurabilityAdapter)
        self.assertTrue(any("OPEN_REPARSE_POINT" in value for value in primitives))
        self.assertTrue(any("FileAttributeTagInfo" in value for value in primitives))
        self.assertTrue(any("FileIdInfo" in value for value in primitives))
        self.assertTrue(any("GetSecurityInfo:opened-handle" in value for value in primitives))
        self.assertIn("LockFileEx:LOCKFILE_EXCLUSIVE_LOCK", primitives)
        self.assertIn("UnlockFileEx", primitives)
        source_text = SOURCE_PATH.read_text(encoding="utf-8")
        self.assertNotIn("GetFileAttributesW", source_text)
        self.assertNotIn("GetNamedSecurityInfoW", source_text)

    def test_run276_unknown_state_cannot_import(self):
        unknown = {
            "schema": STORE.SCHEMA_RESTORE_LEDGER,
            "epoch_ref": "epoch-unknown-001",
            "state": "UNKNOWN_POTENTIALLY_CONSUMED",
            "transition_id": None,
            "transition_target": None,
            "transition_data_commitment": None,
        }
        with self.assertRaisesRegex(STORE.LedgerError, "UNKNOWN_LEDGER_STATE"):
            STORE.import_restore_ledger(unknown)

    def test_configuration_rejects_missing_relative_cwd_worktree_tmp_temp_and_network(self):
        with self.assertRaisesRegex(STORE.ConfigurationError, "STORE_ROOT_NOT_CONFIGURED"):
            STORE.ControllerStore.from_environment(environ={})
        with self.assertRaises(STORE.ConfigurationError):
            STORE.ControllerStore.from_environment(environ={"PLATFORM_RECOVERY_STORE_ROOT": "."})
        with self.assertRaises(STORE.ConfigurationError):
            STORE.ControllerStore.from_environment(environ={"PLATFORM_RECOVERY_STORE_ROOT": str(ROOT)})
        with self.assertRaises(STORE.ConfigurationError):
            STORE.ControllerStore.from_environment(environ={"PLATFORM_RECOVERY_STORE_ROOT": str(ROOT / ".tmp" / "synthetic")})
        with self.assertRaises(STORE.ConfigurationError):
            STORE.ControllerStore.from_environment(environ={"PLATFORM_RECOVERY_STORE_ROOT": tempfile.gettempdir()})
        with self.assertRaises(STORE.ConfigurationError):
            STORE.ControllerStore.from_environment(environ={"PLATFORM_RECOVERY_STORE_ROOT": "\\\\synthetic-server\\share"})

    def test_supersession_requires_fresh_barrier_and_terminalizes_old_epoch(self):
        store = self.new_store()
        old = self.create_active_epoch(store, "epoch-old-001", "authority-super-001")
        new = self.create_epoch(store, "epoch-new-001", "authority-super-001", supersedes=old)
        result = store.supersede(old, new)
        self.assertEqual(result.record["state"], "SUPERSEDED")
        with self.assertRaisesRegex(STORE.EpochStateError, "EPOCH_TERMINAL"):
            store.activate(old)

    def test_authoritative_file_modes_are_restrictive_on_posix(self):
        if os.name != "posix":
            self.skipTest("POSIX mode proof is not claimed on Windows")
        store = self.new_store()
        epoch = self.create_epoch(store, "epoch-mode-001")
        for filename in (STORE.RECORD_FILENAME, STORE.MANIFEST_FILENAME, STORE.PRIVATE_IDENTITIES_FILENAME, STORE.LEDGER_FILENAME, STORE.SPOOL_META_FILENAME):
            mode = stat.S_IMODE(os.lstat(store._file_path(epoch, filename)).st_mode)
            self.assertEqual(mode, 0o600)
        for directory in (store.root, store.root / "epochs", store._spool_path(epoch), store._frames_path(epoch)):
            self.assertEqual(stat.S_IMODE(os.lstat(directory).st_mode), 0o700)

    def test_canonical_parser_rejects_noncanonical_whitespace(self):
        with self.assertRaisesRegex(STORE.SchemaError, "JSON_NOT_CANONICAL"):
            STORE.parse_canonical_json(b" {\"synthetic\":true}\n", max_bytes=128)

    def test_canonical_commitment_uses_fixed_length_prefixed_fields(self):
        one = STORE.recovery_commitment("artifact-row", "a", "bc")
        two = STORE.recovery_commitment("artifact-row", "ab", "c")
        self.assertRegex(one, r"^sha256:v1:[0-9a-f]{64}$")
        self.assertNotEqual(one, two)
        with self.assertRaises(STORE.SchemaError):
            STORE.recovery_commitment("artifact-row", 1)


if __name__ == "__main__":
    unittest.main()
