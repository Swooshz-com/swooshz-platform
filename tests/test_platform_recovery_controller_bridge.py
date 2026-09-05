from __future__ import annotations

import copy
import ctypes
import importlib.util
import os
import pathlib
import stat
import sys
import tempfile
import types
import unittest
from collections import deque
from contextlib import contextmanager


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "platform_recovery_controller_bridge_run355_tests",
    ROOT / "scripts" / "platform-recovery-controller-bridge.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("bridge module spec unavailable")
BRIDGE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BRIDGE
SPEC.loader.exec_module(BRIDGE)
REMOTE = BRIDGE.REMOTE
STORE = BRIDGE.STORE

BARRIER_UTC = "2026-09-05T00:00:00.000000Z"
EPOCH_REF = "epoch-fixture"
AUTHORITY_REF = "authority-fixture"
ROW_ID = 23
ARTIFACT_FILENAME = "synthetic-artifact-001"
PRIVATE_V2 = {
    "container_identity": "synthetic-container-001",
    "volume_identity": "synthetic-volume-001",
    "runner_identity": "synthetic-runner-001",
    "salt": "synthetic-salt-only-in-private-fixture",
    "spool_hmac_key": "synthetic-hmac-key-only-in-private-fixture",
}


def c(domain: str, value: bytes = b"fixture") -> str:
    return REMOTE.bytes_commitment(domain, value)


def harden_windows_test_root(root: pathlib.Path) -> None:
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
        advapi32.AddAccessAllowedAceEx.argtypes = [
            ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ubyte,
            ctypes.c_ulong, ctypes.c_void_p,
        ]
        advapi32.AddAccessAllowedAceEx.restype = ctypes.c_int
        advapi32.SetNamedSecurityInfoW.argtypes = [
            ctypes.c_wchar_p, ctypes.c_uint, ctypes.c_uint,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
        ]
        advapi32.SetNamedSecurityInfoW.restype = ctypes.c_ulong
        acl = ctypes.create_string_buffer(4096)
        if not advapi32.InitializeAcl(acl, len(acl), 2):
            raise unittest.SkipTest("disposable ACL initialization unavailable")
        inheritance = 0x01 | 0x02
        for sid in (current, system, administrators):
            if not advapi32.AddAccessAllowedAceEx(acl, 2, inheritance, 0x1F01FF, sid):
                raise unittest.SkipTest("disposable ACL construction unavailable")
        result = advapi32.SetNamedSecurityInfoW(
            str(root), 1, 0x00000004, None, None,
            ctypes.cast(acl, ctypes.c_void_p), None,
        )
        if result != 0:
            raise unittest.SkipTest("disposable ACL assignment unavailable")
    finally:
        kernel32.LocalFree(system)
        kernel32.LocalFree(administrators)
        _ = current_buffer


def endpoint() -> BRIDGE.EndpointConfig:
    source = (ROOT / "scripts" / "platform-recovery-remote-agent.py").read_bytes()
    commitments = REMOTE.compute_production_commitments(source)
    return BRIDGE.EndpointConfig(
        host="recovery.example",
        port=2222,
        ssh_binary=(r"C:\\OpenSSH\\ssh.exe" if os.name == "nt" else "/usr/bin/ssh"),
        identity_path="/etc/swooshz/recovery/id_ed25519",
        known_hosts_path="/etc/swooshz/recovery/known_hosts",
        authorized_keys_path="/etc/ssh/authorized_keys/swooshz-recovery",
        sshd_config_path="/etc/ssh/sshd_config",
        known_hosts_bytes=b"recovery.example ssh-ed25519 AAAA\n",
        authorized_keys_bytes=(
            f'command="{BRIDGE.FORCED_COMMAND}",restrict ssh-ed25519 AAAA\n'
        ).encode("ascii"),
        sshd_config_bytes=(
            f"Match User {BRIDGE.RECOVERY_USER}\n"
            f"    ForceCommand {BRIDGE.FORCED_COMMAND}\n"
        ).encode("ascii"),
        ssh_binary_bytes=b"openssh-fixture",
        client_identity_bytes=b"identity-fixture",
        effective_config=dict(BRIDGE.EXPECTED_EFFECTIVE_SSH),
        loader_commitment=BRIDGE.FIXED_LOADER_COMMITMENT,
        launcher_commitment=commitments["launcher_commitment"],
        agent_commitment=commitments["agent_commitment"],
    )


def result_evidence(proceed: dict[str, object], endpoint_commitment: str) -> dict[str, object]:
    value = {
        "schema": REMOTE.SCHEMA_RESULT,
        "classification": "SUCCESS",
        "stage": "CLEANUP",
        "epoch_ref": proceed["epoch_ref"],
        "authority_ref": proceed["authority_ref"],
        "barrier_utc": proceed["barrier_utc"],
        "ssh_endpoint_commitment": endpoint_commitment,
        "epoch_commitment": proceed["epoch_commitment"],
        "authority_commitment": proceed["authority_commitment"],
        "barrier_commitment": proceed["barrier_commitment"],
        "runner_commitment": proceed["runner_commitment"],
        "bundle_commitment": proceed["bundle_commitment"],
        "launcher_commitment": proceed["launcher_commitment"],
        "agent_commitment": proceed["agent_commitment"],
        "image_commitment": proceed["image_commitment"],
        "target_commitment": proceed["target_commitment"],
        "isolation_commitment": proceed["isolation_commitment"],
        "artifact_commitment": proceed["artifact_commitment"],
        "artifact_stream_commitment": proceed["artifact_stream_commitment"],
        "transition_id": proceed["transition_id"],
        "pre_cas_ledger_digest": proceed["pre_cas_ledger_digest"],
        "transition_data_commitment": proceed["transition_data_commitment"],
        "consumed_record_commitment": proceed["consumed_record_commitment"],
        "restore_begin_commitment": proceed["restore_begin_commitment"],
        "process_commitment": c("process-evidence"),
        "restore_commitment": c("restore-evidence"),
        "cleanup_commitment": c("cleanup-evidence"),
        "stdout_capture_commitment": c("stdout-capture"),
        "stderr_capture_commitment": c("stderr-capture"),
        "result_code": "RESTORE_SUCCEEDED",
        "restore_count": 1,
        "exit_status": 0,
        "stdin_eof": True,
        "stdout_eof": True,
        "stderr_eof": True,
        "trailing_unframed_bytes": 0,
        "cleanup_state": "COMPLETE",
    }
    return REMOTE.validate_result_evidence(value)


class FakeSession:
    def __init__(self, configured_endpoint: BRIDGE.EndpointConfig) -> None:
        self.endpoint = configured_endpoint
        self.n_local: bytes | None = None
        self.incoming: deque[REMOTE.DecodedFrame] = deque()
        self.sent: list[REMOTE.DecodedFrame] = []
        self.closed = False

    def send_frame(self, frame: bytes) -> None:
        decoded = REMOTE.decode_frame(frame)
        self.sent.append(decoded)
        if decoded.message == BRIDGE.MESSAGE_BOOT:
            self.n_local = decoded.n_local
            ready = {field: decoded.payload[field] for field in REMOTE.READY_FIELDS}
            ready["type"] = "READY"
            discovery = {
                "type": "DISCOVERY",
                "version": 2,
                "schema": REMOTE.SCHEMA_WIRE,
                "epoch_ref": decoded.payload["epoch_ref"],
                "authority_ref": decoded.payload["authority_ref"],
                "execution_row_id": ROW_ID,
                "artifact_filename": ARTIFACT_FILENAME,
                "image_commitment": c("image"),
                "target_commitment": c("target"),
                "isolation_commitment": c("isolation"),
            }
            self.incoming.append(
                REMOTE.decode_frame(
                    REMOTE.encode_frame(
                        BRIDGE.DIRECTION_REMOTE_TO_LOCAL,
                        BRIDGE.MESSAGE_READY,
                        1,
                        self.n_local,
                        ready,
                    )
                )
            )
            self.incoming.append(
                REMOTE.decode_frame(
                    REMOTE.encode_frame(
                        BRIDGE.DIRECTION_REMOTE_TO_LOCAL,
                        BRIDGE.MESSAGE_DISCOVERY,
                        2,
                        self.n_local,
                        discovery,
                    )
                )
            )
        elif decoded.message == BRIDGE.MESSAGE_PROCEED:
            evidence = result_evidence(decoded.payload, self.endpoint.endpoint_commitment)
            result = {
                "type": "RESULT",
                "version": 2,
                "schema": REMOTE.SCHEMA_WIRE,
                "classification": evidence["classification"],
                "result_evidence": evidence,
                "result_commitment": REMOTE.bytes_commitment(
                    "result-evidence",
                    REMOTE.canonical_json(evidence, terminal_lf=True),
                ),
            }
            self.incoming.append(
                REMOTE.decode_frame(
                    REMOTE.encode_frame(
                        BRIDGE.DIRECTION_REMOTE_TO_LOCAL,
                        BRIDGE.MESSAGE_RESULT,
                        4,
                        self.n_local,
                        result,
                    )
                )
            )

    def receive_frame(self) -> REMOTE.DecodedFrame | None:
        if not self.incoming:
            return None
        return self.incoming.popleft()

    def close(self) -> None:
        self.closed = True


class CasFaultStore:
    def __init__(self, delegate: object, mode: str) -> None:
        self.delegate = delegate
        self.mode = mode
        self.consume_calls = 0

    def __getattr__(self, name: str) -> object:
        return getattr(self.delegate, name)

    def consume_restore(self, epoch_ref: str, transition_id: str, *, expected_digest: str, data: object = None) -> object:
        self.consume_calls += 1
        if self.mode == "B":
            raise STORE.ControllerStoreError("INJECTED_UNCONSUMED", safety_state="UNCONSUMED")
        permit = self.delegate.consume_restore(
            epoch_ref,
            transition_id,
            expected_digest=expected_digest,
            data=data,
        )
        if self.mode == "C":
            raise STORE.ControllerStoreError("INJECTED_CONSUMED_UNCERTAINTY", safety_state="CONSUMED")
        return permit


class BridgeTestCase(unittest.TestCase):
    def new_store(self) -> tuple[STORE.ControllerStore, tempfile.TemporaryDirectory[str]]:
        temporary = tempfile.TemporaryDirectory(prefix="run355-controller-")
        root = pathlib.Path(temporary.name)
        harden_windows_test_root(root)
        store = STORE.ControllerStore.for_disposable_test_root(root)
        store.create_epoch_v2(
            EPOCH_REF,
            AUTHORITY_REF,
            prebackup_identities=PRIVATE_V2,
        )
        self.addCleanup(temporary.cleanup)
        return store, temporary

    def run_bridge(self, store: object, *, mode: str | None = None) -> tuple[BRIDGE.BridgeResult, FakeSession]:
        configured_endpoint = endpoint()
        session = FakeSession(configured_endpoint)
        if mode is not None:
            store = CasFaultStore(store, mode)
        result = BRIDGE.run_controller_bridge(
            store,
            configured_endpoint,
            EPOCH_REF,
            BARRIER_UTC,
            session_factory=lambda _endpoint: session,
            nonce_factory=lambda size: bytes(range(size)),
            artifact_stream_commitment=c("artifact-stream"),
            test_mode=True,
        )
        return result, session


class EndpointAndProtocolTests(BridgeTestCase):
    def test_endpoint_bootstrap_and_exact_ssh_argv(self) -> None:
        configured = endpoint()
        self.assertEqual(
            BRIDGE.build_ssh_argv(configured),
            (
                configured.ssh_binary, "-F", "none", "-p", "2222",
                "-i", "/etc/swooshz/recovery/id_ed25519",
                "-o", "IdentitiesOnly=yes",
                "-o", "IdentityAgent=none",
                "-o", "CertificateFile=none",
                "-o", "UserKnownHostsFile=/etc/swooshz/recovery/known_hosts",
                "-o", "GlobalKnownHostsFile=none",
                "-o", "StrictHostKeyChecking=yes",
                "-o", "UpdateHostKeys=no",
                "-o", "VerifyHostKeyDNS=no",
                "-o", "CanonicalizeHostname=no",
                "-o", "ProxyCommand=none",
                "-o", "ProxyJump=none",
                "-o", "ClearAllForwardings=yes",
                "-o", "ForwardAgent=no",
                "-o", "ForwardX11=no",
                "-o", "ForwardX11Trusted=no",
                "-o", "RequestTTY=no",
                "-o", "RemoteCommand=none",
                "-o", "PermitLocalCommand=no",
                "-o", "LocalCommand=none",
                "-o", "ControlMaster=no",
                "-o", "ControlPath=none",
                "-o", "ControlPersist=no",
                "-o", "SendEnv=",
                "swooshz-recovery@recovery.example",
            ),
        )
        self.assertNotIn("ssh", BRIDGE.build_ssh_argv(configured)[-1])
        self.assertEqual(configured.bundle_commitment, REMOTE.compute_bundle_commitment(configured.launcher_commitment, configured.agent_commitment))
        self.assertEqual(
            BRIDGE.validate_account_bootstrap({
                "login_shell": "/bin/sh",
                "home": "/var/empty/swooshz-recovery",
                "forced_command": BRIDGE.FORCED_COMMAND,
                "ssh_original_command": "",
                "permit_user_rc": "no",
                "permit_user_environment": "no",
                "accept_env": "",
            })["home"],
            "/var/empty/swooshz-recovery",
        )
        with self.assertRaises(BRIDGE.EndpointAdmissionError):
            BRIDGE.EndpointConfig(
                **{**configured.__dict__, "port": 0}
            )

    def test_barrier_and_transition_domains_are_distinct(self) -> None:
        barrier = BRIDGE.build_barrier_commitment(BARRIER_UTC)
        supersession = STORE.recovery_commitment(
            STORE.DOMAIN_SUPERSESSION_BARRIER, "NONE", EPOCH_REF, AUTHORITY_REF
        )
        self.assertNotEqual(barrier, supersession)
        values = {
            "epoch_ref": EPOCH_REF,
            "authority_ref": AUTHORITY_REF,
            "barrier_utc": BARRIER_UTC,
            "barrier_commitment": barrier,
            "runner_commitment": c("runner"),
            "bundle_commitment": c("bundle"),
            "image_commitment": c("image"),
            "target_commitment": c("target"),
            "isolation_commitment": c("isolation"),
            "artifact_commitment": c("artifact"),
            "artifact_stream_commitment": c("artifact-stream"),
            "pre_cas_ledger_digest": c("ledger"),
        }
        transition = BRIDGE.build_restore_transition(**values)
        self.assertTrue(transition.transition_id.startswith("restore-v2-"))
        self.assertEqual(
            transition.data_commitment,
            STORE.bytes_commitment(
                STORE.DOMAIN_RESTORE_TRANSITION,
                REMOTE.canonical_json(transition.data, terminal_lf=True),
            ),
        )


class StoreSequenceTests(BridgeTestCase):
    def test_cas_a_durable_restore_begin_and_commit(self) -> None:
        store, _ = self.new_store()
        result, session = self.run_bridge(store)
        self.assertEqual(result.classification, "SUCCESS")
        self.assertEqual(result.cas_classification, "A")
        self.assertTrue(result.finality_complete)
        self.assertEqual(
            result.trace,
            ("BOOT", "READY", "DISCOVERY", "PRE_CAS", "CAS_A", "PROCEED", "RESULT", "COMMIT", "FINAL"),
        )
        snapshot = store.load_epoch(EPOCH_REF)
        self.assertEqual(snapshot.record["state"], "CONSUMED")
        self.assertEqual(snapshot.ledger["state"], "CONSUMED")
        self.assertEqual(snapshot.spool["last_stage"], "COMMIT")
        sent_types = [frame.message for frame in session.sent]
        self.assertEqual(sent_types, [BRIDGE.MESSAGE_BOOT, BRIDGE.MESSAGE_PROCEED])
        self.assertTrue(session.closed)
        self.assertEqual(result.result_evidence["cleanup_state"], "COMPLETE")

    def test_cas_b_abandons_and_emits_only_the_legal_abort(self) -> None:
        store, _ = self.new_store()
        result, session = self.run_bridge(store, mode="B")
        self.assertEqual(result.classification, "FAILURE")
        self.assertEqual(result.cas_classification, "B")
        self.assertEqual(result.code, "CAS_REJECTED_UNCONSUMED")
        self.assertEqual(store.load_epoch(EPOCH_REF).record["state"], "ABANDONED")
        self.assertEqual([frame.message for frame in session.sent], [BRIDGE.MESSAGE_BOOT, BRIDGE.MESSAGE_ABORT])
        self.assertEqual(result.trace[-1], "ABORT")

    def test_cas_c_is_sticky_and_does_not_abandon_or_emit_abort(self) -> None:
        store, _ = self.new_store()
        result, session = self.run_bridge(store, mode="C")
        self.assertEqual(result.classification, "FAILURE")
        self.assertEqual(result.cas_classification, "C")
        self.assertEqual(result.code, "CAS_UNCERTAIN")
        snapshot = store.load_epoch(EPOCH_REF)
        self.assertEqual(snapshot.ledger["state"], "CONSUMED")
        self.assertEqual(snapshot.record["state"], "ACTIVE")
        self.assertEqual(snapshot.spool["last_stage"], "RUNNER_STARTED")
        self.assertEqual([frame.message for frame in session.sent], [BRIDGE.MESSAGE_BOOT])
        self.assertFalse(result.finality_complete)


if __name__ == "__main__":
    unittest.main()
