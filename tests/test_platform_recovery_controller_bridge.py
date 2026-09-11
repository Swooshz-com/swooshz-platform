from __future__ import annotations

import ctypes
import importlib.util
import io
import os
import pathlib
import queue
import stat
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "platform_recovery_controller_bridge_run362_tests",
    ROOT / "scripts" / "platform-recovery-controller-bridge.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("controller bridge module spec unavailable")
BRIDGE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BRIDGE
SPEC.loader.exec_module(BRIDGE)
REMOTE = BRIDGE.REMOTE
STORE = BRIDGE.STORE

BARRIER_UTC = "2026-09-06T00:00:00.000000Z"
EPOCH_REF = "epoch-fixture"
AUTHORITY_REF = "authority-fixture"
PRIVATE_V2 = {
    "container_identity": "synthetic-container-001",
    "volume_identity": "synthetic-volume-001",
    "runner_identity": "synthetic-runner-001",
    "salt": "synthetic-salt-only-in-private-fixture",
    "spool_hmac_key": "synthetic-hmac-key-only-in-private-fixture",
}


def commitment(domain: str, value: bytes = b"fixture") -> str:
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
        advapi32.AddAccessAllowedAceEx.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ubyte, ctypes.c_ulong, ctypes.c_void_p]
        advapi32.AddAccessAllowedAceEx.restype = ctypes.c_int
        advapi32.SetNamedSecurityInfoW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        advapi32.SetNamedSecurityInfoW.restype = ctypes.c_ulong
        acl = ctypes.create_string_buffer(4096)
        if not advapi32.InitializeAcl(acl, len(acl), 2):
            raise unittest.SkipTest("disposable ACL initialization unavailable")
        for sid in (current, system, administrators):
            if not advapi32.AddAccessAllowedAceEx(acl, 2, 0x01 | 0x02, 0x1F01FF, sid):
                raise unittest.SkipTest("disposable ACL construction unavailable")
        if advapi32.SetNamedSecurityInfoW(str(root), 1, 0x00000004, None, None, ctypes.cast(acl, ctypes.c_void_p), None) != 0:
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
        ssh_binary=(r"C:\OpenSSH\ssh.exe" if os.name == "nt" else "/usr/bin/ssh"),
        identity_path=(r"C:\Swooshz\recovery\id_ed25519" if os.name == "nt" else "/etc/swooshz/recovery/id_ed25519"),
        known_hosts_path=(r"C:\Swooshz\recovery\known_hosts" if os.name == "nt" else "/etc/swooshz/recovery/known_hosts"),
        authorized_keys_path=(r"C:\Swooshz\ssh\authorized_keys" if os.name == "nt" else "/etc/ssh/authorized_keys/swooshz-recovery"),
        sshd_config_path=(r"C:\Swooshz\ssh\sshd_config" if os.name == "nt" else "/etc/ssh/sshd_config"),
        known_hosts_bytes=b"recovery.example ssh-ed25519 AAAA\n",
        authorized_keys_bytes=(f'command="{BRIDGE.FORCED_COMMAND}",restrict ssh-ed25519 AAAA\n').encode("ascii"),
        sshd_config_bytes=(f"Match User {BRIDGE.RECOVERY_USER}\n    ForceCommand {BRIDGE.FORCED_COMMAND}\n").encode("ascii"),
        ssh_binary_bytes=b"openssh-fixture",
        client_identity_bytes=b"identity-fixture",
        effective_config=dict(BRIDGE.EXPECTED_EFFECTIVE_SSH),
        loader_commitment=BRIDGE.FIXED_LOADER_COMMITMENT,
        launcher_commitment=commitments["launcher_commitment"],
        agent_commitment=commitments["agent_commitment"],
    )


def failure_evidence(proceed: dict[str, object], endpoint_commitment: str) -> dict[str, object]:
    value: dict[str, object] = {}
    for field in REMOTE.RESULT_EVIDENCE_FIELDS:
        if field == "schema":
            value[field] = REMOTE.SCHEMA_RESULT
        elif field in proceed:
            value[field] = proceed[field]
        elif field == "ssh_endpoint_commitment":
            value[field] = endpoint_commitment
        elif field == "classification":
            value[field] = "FAILURE"
        elif field == "stage":
            value[field] = "PROCESS"
        elif field == "result_code":
            value[field] = "RESTORE_PROCESS_FAILED"
        elif field == "restore_count":
            value[field] = 0
        elif field == "exit_status":
            value[field] = 1
        elif field in {"stdin_eof", "stdout_eof", "stderr_eof", "terminal_input_eof"}:
            value[field] = True
        elif field in {"trailing_unframed_bytes", "terminal_input_trailing_bytes"}:
            value[field] = 0
        elif field == "cleanup_state":
            value[field] = "COMPLETE"
        elif field.endswith("_commitment") or field.endswith("_digest"):
            value[field] = commitment(field)
        else:
            value[field] = "fixture"
    return REMOTE.validate_result_evidence(value)


class QueueBytes:
    def __init__(self) -> None:
        self._queue: queue.Queue[bytes | None] = queue.Queue()
        self._buffer = bytearray()
        self._closed = False
        self._close_lock = threading.Lock()

    def write(self, value: bytes) -> int:
        if self._closed:
            raise OSError("stream closed")
        if not isinstance(value, bytes):
            raise TypeError("bytes required")
        self._queue.put(value)
        return len(value)

    def close(self) -> None:
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
            self._queue.put(None)

    def flush(self) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        if size == 0:
            return b""
        while not self._buffer:
            item = self._queue.get(timeout=10.0)
            if item is None:
                return b""
            self._buffer.extend(item)
        if size < 0 or len(self._buffer) <= size:
            result = bytes(self._buffer)
            self._buffer.clear()
            return result
        result = bytes(self._buffer[:size])
        del self._buffer[:size]
        return result


class CoupledRemoteBackend:
    test_only = False
    synthetic_provenance = False

    def __init__(self, events: list[str]) -> None:
        self.events = events
        artifact = STORE.recovery_commitment(STORE.DOMAIN_ARTIFACT_ROW, "23", "artifact-023")
        self.discovery = REMOTE.DockerDiscovery(
            commitment("image-evidence"),
            commitment("target-evidence"),
            commitment("isolation-evidence"),
            23,
            "artifact-023",
            artifact,
            commitment("artifact-stream"),
        )
        self.boot: dict[str, object] | None = None

    def bind_boot(self, boot: dict[str, object]) -> None:
        self.boot = dict(boot)

    def mark_discovery_emitted(self) -> None:
        self.events.append("DISCOVERY_EMITTED")

    def record_proceed_boundary(self) -> None:
        self.events.append("PROCEED_RECEIVED")

    def discover(self, _epoch_ref: str, _barrier_utc: str) -> REMOTE.DockerDiscovery:
        return self.discovery

    def restore(self, proceed: dict[str, object], *, terminal_input_eof: bool, terminal_input_trailing_bytes: int) -> dict[str, object]:
        self.assert_terminal_input = (terminal_input_eof, terminal_input_trailing_bytes)
        self.events.append("RESTORE")
        return failure_evidence(proceed, str(self.boot["ssh_endpoint_commitment"]))


class CoupledSession:
    def __init__(self, backend: CoupledRemoteBackend, *, fail_half_close: bool = False) -> None:
        self.backend = backend
        self.events = backend.events
        self.fail_half_close = fail_half_close
        self.incoming = QueueBytes()
        self.outgoing = QueueBytes()
        self.sent: list[int] = []
        self._half_closed = False
        self._failures: list[BaseException] = []
        self.thread = threading.Thread(target=self._run_remote, daemon=True)
        self.thread.start()

    def _run_remote(self) -> None:
        try:
            REMOTE.run_agent_protocol(self.incoming, self.outgoing, backend=self.backend, environment={"SWZ_RECOVERY_AGENT_FD": "3"}, test_mode=True)
        except BaseException as error:
            self._failures.append(error)
        finally:
            self.outgoing.close()

    def send_frame(self, frame: bytes) -> None:
        decoded = REMOTE.decode_frame(frame)
        self.sent.append(decoded.message)
        if decoded.message == BRIDGE.MESSAGE_PROCEED:
            self.events.append("PROCEED_SENT")
        self.incoming.write(frame)

    def receive_frame(self) -> REMOTE.DecodedFrame | None:
        return REMOTE.read_frame(self.outgoing, eof_ok=True)

    def half_close_input(self) -> None:
        if self._half_closed:
            raise RuntimeError("duplicate half close")
        self._half_closed = True
        self.events.append("HALF_CLOSE")
        if self.fail_half_close:
            raise BRIDGE.TransportError("SSH_STDIN_EOF_UNCERTAIN", safety_state="CONSUMED")
        self.incoming.close()

    def finalize(self) -> BRIDGE.SessionFinality:
        self.thread.join(timeout=2.0)
        if self.thread.is_alive():
            raise RuntimeError("remote did not finish")
        if self._failures:
            raise self._failures[0]
        return BRIDGE.SessionFinality(0, True, True, True, 0, commitment("stdout"), commitment("stderr"))

    def close(self) -> None:
        self.incoming.close()
        self.outgoing.close()
        self.events.append("CLOSE")


class HandshakeSession:
    """Only supplies READY/DISCOVERY; it never manufactures a RESULT."""

    def __init__(self, configured_endpoint: BRIDGE.EndpointConfig) -> None:
        self.endpoint = configured_endpoint
        self.nonce: bytes | None = None
        self.incoming: list[REMOTE.DecodedFrame] = []
        self.sent: list[int] = []
        self.closed = False

    def send_frame(self, frame: bytes) -> None:
        decoded = REMOTE.decode_frame(frame)
        self.sent.append(decoded.message)
        if decoded.message != BRIDGE.MESSAGE_BOOT:
            return
        self.nonce = decoded.n_local
        ready = {key: decoded.payload[key] for key in REMOTE.READY_FIELDS}
        ready["type"] = "READY"
        self.incoming.append(REMOTE.decode_frame(REMOTE.encode_frame(BRIDGE.DIRECTION_REMOTE_TO_LOCAL, BRIDGE.MESSAGE_READY, 1, self.nonce, ready)))
        artifact = STORE.recovery_commitment(STORE.DOMAIN_ARTIFACT_ROW, "23", "artifact-023")
        discovery = REMOTE.build_discovery_payload(
            decoded.payload["epoch_ref"],
            decoded.payload["authority_ref"],
            REMOTE.DockerDiscovery(commitment("image-evidence"), commitment("target-evidence"), commitment("isolation-evidence"), 23, "artifact-023", artifact, commitment("artifact-stream")),
        )
        self.incoming.append(REMOTE.decode_frame(REMOTE.encode_frame(BRIDGE.DIRECTION_REMOTE_TO_LOCAL, BRIDGE.MESSAGE_DISCOVERY, 2, self.nonce, discovery)))

    def receive_frame(self) -> REMOTE.DecodedFrame | None:
        return self.incoming.pop(0) if self.incoming else None

    def half_close_input(self) -> None:
        return None

    def finalize(self) -> BRIDGE.SessionFinality:
        return BRIDGE.SessionFinality(0, True, True, True, 0, commitment("stdout"), commitment("stderr"))

    def close(self) -> None:
        self.closed = True


class CasFaultStore:
    def __init__(self, delegate: object, mode: str) -> None:
        self.delegate = delegate
        self.mode = mode

    def __getattr__(self, name: str) -> object:
        return getattr(self.delegate, name)

    def consume_restore(self, epoch_ref: str, transition_id: str, *, expected_digest: str, data: object = None) -> object:
        if self.mode == "B":
            raise STORE.LedgerError("CAS_MISMATCH", safety_state="UNCONSUMED")
        permit = self.delegate.consume_restore(epoch_ref, transition_id, expected_digest=expected_digest, data=data)
        if self.mode == "C":
            raise STORE.ControllerStoreError("CONSUMED_UNCERTAINTY", safety_state="CONSUMED")
        return permit


class BridgeTests(unittest.TestCase):
    def new_store(self) -> tuple[STORE.ControllerStore, tempfile.TemporaryDirectory[str]]:
        try:
            temporary = tempfile.TemporaryDirectory(prefix="run362-controller-")
        except FileNotFoundError:
            self.skipTest("runner has no writable temporary directory")
            raise AssertionError("unreachable")
        harden_windows_test_root(pathlib.Path(temporary.name))
        store = STORE.ControllerStore.for_disposable_test_root(temporary.name)
        store.create_epoch_v2(EPOCH_REF, AUTHORITY_REF, prebackup_identities=PRIVATE_V2)
        self.addCleanup(temporary.cleanup)
        return store, temporary

    def test_authoritative_transition_kat(self) -> None:
        values = {
            "epoch_ref": "epoch-kat-001",
            "authority_ref": "authority-kat-001",
            "barrier_utc": "2026-09-04T00:00:00.000000Z",
            "barrier_commitment": "sha256:v1:987f4bbd978903b272c8801c486b84e48fe9522e7cb22cfdcf98c60287eebdc9",
            "runner_commitment": "sha256:v1:46d24a269701c36717f27dca4d205e9c525ece5965bdcc15452027f781556cde",
            "bundle_commitment": "sha256:v1:4d60d7ac7d4ac28d3040d5543f8659037d4a1708235042b9d0b847f130b72bb4",
            "image_commitment": "sha256:v1:a14f52080ef31a7a733b9101b9a6d882fef3d4901238edfef6507bcd6da72ec6",
            "target_commitment": "sha256:v1:159c8bdee81330f1588350855fb4fc1a7d3cd5fc8cddf0d6294b0d520ae2e9ec",
            "isolation_commitment": "sha256:v1:c1245bf941fc8e059a2d0104e4b747e7e5042746659b73b47b706906e43220ad",
            "artifact_commitment": "sha256:v1:059cd76ead3ad80a0027789aad1faab689652146c401485f0bc2d40429bae918",
            "artifact_stream_commitment": "sha256:v1:bed2a6629680112a812d796bae566c178617d64f1be6fa844273324f2ee74c21",
            "pre_cas_ledger_digest": "sha256:v1:45b59bb90160abcea595878c62ae740e934ba1c682ce96a28ea00fe96f46e82c",
        }
        transition = BRIDGE.build_restore_transition(**values)
        self.assertEqual(len(REMOTE.canonical_json(transition.data, terminal_lf=True)), 1058)
        self.assertEqual(transition.transition_id, "restore-v2-d36f96eadb647f14a9cc9c81b4ce5e22f1c96f80e618744c")
        self.assertEqual(transition.data_commitment, "sha256:v1:cbb7eb82b39152a585ba3d91b72f8855134e6b9a49463c2f015b2f720f39490a")

    def test_qualification_precedes_ssh_g_and_spawn_and_rejects_substitution(self) -> None:
        configured = endpoint()
        account = {
            "user": BRIDGE.RECOVERY_USER,
            "uid": 1001,
            "gid": 1001,
            "login_shell": BRIDGE.RECOVERY_SHELL,
            "home": BRIDGE.RECOVERY_HOME,
            "home_uid": 0,
            "home_gid": 0,
            "home_mode": 0o755,
            "forced_command": BRIDGE.FORCED_COMMAND,
            "ssh_original_command": "",
            "permit_user_rc": "no",
            "permit_user_environment": "no",
            "accept_env": "",
            "authorized_key_restriction": "restrict",
            "startup_policy": "noninteractive-login-shell",
        }
        record = lambda path, raw, label: {"path": path, "bytes_commitment": commitment(label, raw), "identity": (1, 2, len(raw), stat.S_IFREG | 0o555, 0, 0), "byte_length": len(raw)}
        calls: list[object] = []

        def qualify(path: str, raw: bytes, label: str, **_kwargs: object) -> dict[str, object]:
            calls.append(label)
            return record(path, raw, label)

        with mock.patch.object(BRIDGE, "read_local_account_bootstrap", side_effect=lambda: (calls.append("account") or account)), \
                mock.patch.object(BRIDGE, "_qualify_installation_file", side_effect=qualify), \
                mock.patch.object(BRIDGE, "validate_ssh_effective_readback", side_effect=lambda *_args, **_kwargs: (calls.append("ssh-G") or {"observed": {}})):
            qualified = BRIDGE.qualify_endpoint_installation(configured)
        self.assertEqual(calls[0], "account")
        self.assertGreater(calls.index("ssh-G"), max(index for index, item in enumerate(calls[:6]) if item != "account"))
        self.assertEqual(qualified["account_bootstrap"], account)

        with mock.patch.object(BRIDGE, "read_local_account_bootstrap", return_value=account), \
                mock.patch.object(BRIDGE, "_qualify_installation_file", side_effect=BRIDGE.EndpointAdmissionError("SSH_BINARY_SUBSTITUTED")), \
                mock.patch.object(BRIDGE.subprocess, "run") as run_fn, \
                mock.patch.object(BRIDGE.subprocess, "Popen") as popen_fn:
            with self.assertRaisesRegex(BRIDGE.EndpointAdmissionError, "SSH_BINARY_SUBSTITUTED"):
                BRIDGE.OpenSSHSession(configured)
        run_fn.assert_not_called()
        popen_fn.assert_not_called()

    def test_coupled_remote_waits_for_controller_half_close(self) -> None:
        store, _ = self.new_store()
        events: list[str] = []
        backend = CoupledRemoteBackend(events)
        session = CoupledSession(backend)
        result = BRIDGE.run_controller_bridge(
            store,
            endpoint(),
            EPOCH_REF,
            BARRIER_UTC,
            session_factory=lambda _endpoint: session,
            nonce_factory=lambda size: bytes(range(size)),
            artifact_stream_commitment=commitment("artifact-stream"),
            test_mode=True,
        )
        self.assertEqual(result.classification, "FAILURE")
        self.assertEqual(result.cas_classification, "A")
        self.assertTrue(result.finality_complete)
        self.assertEqual(list(result.trace), ["BOOT", "READY", "DISCOVERY", "PRE_CAS", "CAS_A", "PROCEED", "RESULT"])
        self.assertEqual(session.sent, [BRIDGE.MESSAGE_BOOT, BRIDGE.MESSAGE_PROCEED])
        self.assertLess(events.index("PROCEED_SENT"), events.index("HALF_CLOSE"))
        self.assertLess(events.index("HALF_CLOSE"), events.index("RESTORE"))
        self.assertEqual(events[-1], "CLOSE")
        snapshot = store.load_epoch(EPOCH_REF)
        self.assertEqual(snapshot.ledger["state"], "CONSUMED")
        self.assertEqual(snapshot.spool["last_stage"], "RESTORE_BEGIN")

    def test_half_close_failure_is_sticky_and_sends_no_followup_frame(self) -> None:
        store, _ = self.new_store()
        events: list[str] = []
        backend = CoupledRemoteBackend(events)
        session = CoupledSession(backend, fail_half_close=True)
        result = BRIDGE.run_controller_bridge(
            store,
            endpoint(),
            EPOCH_REF,
            BARRIER_UTC,
            session_factory=lambda _endpoint: session,
            nonce_factory=lambda size: bytes(range(size)),
            artifact_stream_commitment=commitment("artifact-stream"),
            test_mode=True,
        )
        self.assertEqual(result.code, "CAS_UNCERTAIN")
        self.assertEqual(result.cas_classification, "C")
        self.assertEqual(session.sent, [BRIDGE.MESSAGE_BOOT, BRIDGE.MESSAGE_PROCEED])
        self.assertNotIn("RESTORE", events)
        self.assertEqual(store.load_epoch(EPOCH_REF).ledger["state"], "CONSUMED")

    def test_cas_b_and_c_preserve_one_use_store_algebra(self) -> None:
        for mode, expected_code, expected_sent in (("B", "CAS_REJECTED_UNCONSUMED", [BRIDGE.MESSAGE_BOOT, BRIDGE.MESSAGE_ABORT]), ("C", "CAS_UNCERTAIN", [BRIDGE.MESSAGE_BOOT])):
            with self.subTest(mode=mode):
                store, _ = self.new_store()
                session = HandshakeSession(endpoint())
                result = BRIDGE.run_controller_bridge(
                    CasFaultStore(store, mode),
                    endpoint(),
                    EPOCH_REF,
                    BARRIER_UTC,
                    session_factory=lambda _endpoint, value=session: value,
                    nonce_factory=lambda size: bytes(range(size)),
                    artifact_stream_commitment=commitment("artifact-stream"),
                    test_mode=True,
                )
                self.assertEqual(result.code, expected_code)
                self.assertEqual(session.sent, expected_sent)


if __name__ == "__main__":
    unittest.main()
