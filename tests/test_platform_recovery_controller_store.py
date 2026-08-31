import base64
import ctypes
import importlib.util
import json
import os
import pathlib
import stat
import sys
import tempfile
import unittest


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
        self.fail_after_temp_readback = False
        self.mismatch_readback = False

    def prove_root(self, root):
        return self.delegate.prove_root(root)

    def validate_component(self, path, *, expect_directory=None):
        return self.delegate.validate_component(path, expect_directory=expect_directory)

    def mkdir_exclusive(self, path):
        return self.delegate.mkdir_exclusive(path)

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
            return self.delegate.write_authority(path, payload, replace=replace, max_bytes=max_bytes)
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
        digest = store.ledger_digest(epoch)
        permit = store.consume_restore(epoch, "transition-synthetic-001", expected_digest=digest, data={"classification": "synthetic"})
        self.assertFalse(permit.idempotent)
        self.assertEqual(permit.state, "CONSUMED")
        self.assertEqual(store.read_restore_ledger(epoch)["state"], "CONSUMED")
        self.assertEqual(store.load_epoch(epoch).record["state"], "CONSUMED")

    def test_exact_duplicate_consume_is_idempotent_only_for_identical_data(self):
        store = self.new_store()
        epoch = self.create_active_epoch(store)
        data = {"classification": "synthetic"}
        store.consume_restore(epoch, "transition-synthetic-002", expected_digest=store.ledger_digest(epoch), data=data)
        duplicate = store.consume_restore(epoch, "transition-synthetic-002", expected_digest=store.ledger_digest(epoch), data=data)
        self.assertTrue(duplicate.idempotent)
        with self.assertRaisesRegex(STORE.LedgerError, "LEDGER_CONTRADICTION"):
            store.consume_restore(epoch, "transition-synthetic-002", expected_digest=store.ledger_digest(epoch), data={"classification": "different"})

    def test_ledger_reset_is_rejected(self):
        store = self.new_store()
        epoch = self.create_active_epoch(store)
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
        store.consume_restore(epoch, "transition-synthetic-005", expected_digest=store.ledger_digest(epoch))
        with self.assertRaisesRegex(STORE.EpochStateError, "EPOCH_TERMINAL"):
            store.resume_epoch(epoch)

    def test_abandoned_epoch_cannot_resume(self):
        store = self.new_store()
        epoch = self.create_epoch(store, "epoch-abandoned-001")
        store.abandon(epoch)
        with self.assertRaisesRegex(STORE.EpochStateError, "EPOCH_TERMINAL"):
            store.mark_ready(epoch)

    def test_pre_consumption_failure_leaves_ledger_unconsumed(self):
        base = STORE.make_durability_adapter()
        fault = FaultAdapter(base)
        store = self.new_store(fault)
        epoch = self.create_active_epoch(store, "epoch-pre-failure-001")
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
        fault.fail_before_transition_name = STORE.RECORD_FILENAME
        with self.assertRaisesRegex(STORE.DurabilityError, "INJECTED_PRE_TRANSITION_FAILURE"):
            store.consume_restore(epoch, "transition-synthetic-007", expected_digest=store.ledger_digest(epoch))
        fault.fail_before_transition_name = None
        self.assertEqual(store.read_restore_ledger(epoch)["state"], "CONSUMED")
        self.assertEqual(store.ledger_safety_classification(epoch), "CONSUMED")

    def test_pre_replace_failure_preserves_prior_authority(self):
        base = STORE.make_durability_adapter()
        fault = FaultAdapter(base)
        store = self.new_store(fault)
        epoch = self.create_active_epoch(store, "epoch-authority-001")
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
        with self.assertRaisesRegex(STORE.IntegrityError, "PRIVATE_IDENTITY_COMMITMENT_MISMATCH"):
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
        first = store.prepare_runner_frame(epoch, "RUNNER_STARTED", {"ref": "runner-ref-001"})
        receipt = store.ingest_frame(epoch, first)
        self.assertEqual(receipt.sequence, 1)
        with self.assertRaisesRegex(STORE.SpoolError, "FRAME_DUPLICATE"):
            store.ingest_frame(epoch, first)
        gap = dict(first)
        gap["sequence"] = 3
        with self.assertRaisesRegex(STORE.SpoolError, "FRAME_GAP_OR_REORDER"):
            store.ingest_frame(epoch, gap)
        bad_auth = store.prepare_runner_frame(epoch, "COMMIT", {"ref": "commit-ref-001"})
        bad_auth["auth"] = "hmac:v1:" + ("f" * 64)
        with self.assertRaisesRegex(STORE.SpoolError, "FRAME_AUTH_INVALID"):
            store.ingest_frame(epoch, bad_auth)
        bad_hash = store.prepare_runner_frame(epoch, "COMMIT", {"ref": "commit-ref-001"})
        bad_hash["frame_hash"] = STORE.recovery_commitment("tampered", "frame")
        with self.assertRaisesRegex(STORE.SpoolError, "FRAME_HASH_INVALID"):
            store.ingest_frame(epoch, bad_hash)

    def test_runner_reorder_and_stage_contradiction_are_rejected(self):
        store = self.new_store()
        epoch = self.create_active_epoch(store, "epoch-stage-001")
        first = store.prepare_runner_frame(epoch, "RUNNER_STARTED", {"ref": "runner-ref-002"})
        store.ingest_frame(epoch, first)
        lower = store.prepare_runner_frame(epoch, "EPOCH_READY", {"ref": "lower-stage-001"})
        with self.assertRaisesRegex(STORE.SpoolError, "FRAME_STAGE_CONTRADICTION"):
            store.ingest_frame(epoch, lower)

    def test_restore_begin_without_consumed_ledger_is_contradictory(self):
        store = self.new_store()
        epoch = self.create_active_epoch(store, "epoch-restore-begin-001")
        frame = store.prepare_runner_frame(epoch, "RESTORE_BEGIN", {"ref": "restore-ref-001"})
        with self.assertRaisesRegex(STORE.SpoolError, "RESTORE_BEGIN_BEFORE_LEDGER_CONSUMED"):
            store.ingest_frame(epoch, frame)

    def test_highest_contiguous_commit_is_persisted(self):
        store = self.new_store()
        epoch = self.create_active_epoch(store, "epoch-commit-001")
        store.ingest_frame(epoch, store.prepare_runner_frame(epoch, "RUNNER_STARTED", {"ref": "runner-ref-003"}))
        receipt = store.ingest_frame(epoch, store.prepare_runner_frame(epoch, "COMMIT", {"ref": "commit-ref-002"}))
        self.assertEqual(receipt.highest_contiguous_commit, 2)
        reloaded = store.load_epoch(epoch)
        self.assertEqual(reloaded.spool["highest_contiguous_commit"], 2)
        self.assertEqual(store.public_projection(epoch)["highest_contiguous_commit"], 2)

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
        for directory in (store.root, store.root / "epochs", store._file_path(epoch, "spool"), store._file_path(epoch, "frame-000000000001.json").parent):
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
