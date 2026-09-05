from __future__ import annotations

import copy
import ctypes
import hashlib
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
        "terminal_input_eof": True,
        "terminal_input_trailing_bytes": 0,
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
        self.input_finished = False

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
            "artifact_commitment": REMOTE.text_commitment(
                "artifact-row",
                str(ROW_ID),
                ARTIFACT_FILENAME,
            ),
            "artifact_stream_commitment": c("artifact-stream"),
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

    def finish_input(self) -> None:
        self.input_finished = True

    def close(self) -> None:
        self.closed = True

    def finalize(self) -> BRIDGE.SessionFinality:
        return BRIDGE.SessionFinality(
            0,
            True,
            True,
            True,
            0,
            c("stdout-capture"),
            c("stderr-capture"),
        )


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
            raise STORE.LedgerError("CAS_MISMATCH", safety_state="UNCONSUMED")
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
                "-o", "IdentityFile=/etc/swooshz/recovery/id_ed25519",
                "-o", "IdentitiesOnly=yes",
                "-o", "IdentityAgent=none",
                "-o", "CertificateFile=none",
                "-o", "PKCS11Provider=none",
                "-o", "GSSAPIAuthentication=no",
                "-o", "HostbasedAuthentication=no",
                "-o", "KbdInteractiveAuthentication=no",
                "-o", "PasswordAuthentication=no",
                "-o", "PubkeyAuthentication=yes",
                "-o", "PreferredAuthentications=publickey",
                "-o", "BatchMode=yes",
                "-o", "UserKnownHostsFile=/etc/swooshz/recovery/known_hosts",
                "-o", "GlobalKnownHostsFile=none",
                "-o", "KnownHostsCommand=none",
                "-o", "PermitRemoteOpen=none",
                "-o", "StrictHostKeyChecking=yes",
                "-o", "UpdateHostKeys=no",
                "-o", "VerifyHostKeyDNS=no",
                "-o", "CanonicalizeHostname=no",
                "-o", "CanonicalizeFallbackLocal=no",
                "-o", "CheckHostIP=no",
                "-o", "HashKnownHosts=no",
                "-o", "ProxyCommand=none",
                "-o", "ProxyJump=none",
                "-o", "ProxyUseFdpass=no",
                "-o", "ClearAllForwardings=yes",
                "-o", "ForwardAgent=no",
                "-o", "ForwardX11=no",
                "-o", "ForwardX11Trusted=no",
                "-o", "RequestTTY=no",
                "-o", "PermitLocalCommand=no",
                "-o", "ControlMaster=no",
                "-o", "ControlPath=none",
                "-o", "ControlPersist=no",
                "-o", "SessionType=default",
                "-o", "EscapeChar=none",
                "-o", "StdinNull=no",
                "-o", "Compression=no",
                "-o", "TCPKeepAlive=no",
                "-o", "ConnectionAttempts=1",
                "-o", "ConnectTimeout=5",
                "-o", "ServerAliveInterval=1",
                "-o", "ServerAliveCountMax=3",
                "swooshz-recovery@recovery.example",
            ),
        )
        self.assertNotIn("ssh", BRIDGE.build_ssh_argv(configured)[-1])
        self.assertEqual(configured.bundle_commitment, REMOTE.compute_bundle_commitment(configured.launcher_commitment, configured.agent_commitment))
        self.assertEqual(
            BRIDGE.validate_account_bootstrap({
                "user": BRIDGE.RECOVERY_USER,
                "uid": 1001,
                "gid": 1001,
                "login_shell": "/bin/sh",
                "home": "/var/empty/swooshz-recovery",
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
            })["home"],
            "/var/empty/swooshz-recovery",
        )
        with self.assertRaises(BRIDGE.EndpointAdmissionError):
            BRIDGE.EndpointConfig(
                **{**configured.__dict__, "port": 0}
            )
        with self.assertRaises(BRIDGE.EndpointAdmissionError):
            BRIDGE.OpenSSHSession(configured)

        argv = BRIDGE.build_ssh_argv(configured)
        with self.assertRaises(BRIDGE.EndpointAdmissionError):
            BRIDGE.validate_ssh_effective_readback(configured, argv + ("/bin/sh",))
        forbidden = list(argv)
        forbidden[forbidden.index("PermitLocalCommand=no")] = "RemoteCommand=/bin/sh"
        with self.assertRaises(BRIDGE.EndpointAdmissionError):
            BRIDGE.validate_ssh_effective_readback(configured, tuple(forbidden))

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

    def test_authoritative_transition_kat_is_byte_exact(self) -> None:
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
        expected = (
            b'{"schema":"restore-ledger-transition-data.v2","version":2,"epoch_ref":"epoch-kat-001","authority_ref":"authority-kat-001","barrier_utc":"2026-09-04T00:00:00.000000Z","barrier_commitment":"sha256:v1:987f4bbd978903b272c8801c486b84e48fe9522e7cb22cfdcf98c60287eebdc9","runner_commitment":"sha256:v1:46d24a269701c36717f27dca4d205e9c525ece5965bdcc15452027f781556cde","bundle_commitment":"sha256:v1:4d60d7ac7d4ac28d3040d5543f8659037d4a1708235042b9d0b847f130b72bb4","image_commitment":"sha256:v1:a14f52080ef31a7a733b9101b9a6d882fef3d4901238edfef6507bcd6da72ec6","target_commitment":"sha256:v1:159c8bdee81330f1588350855fb4fc1a7d3cd5fc8cddf0d6294b0d520ae2e9ec","isolation_commitment":"sha256:v1:c1245bf941fc8e059a2d0104e4b747e7e5042746659b73b47b706906e43220ad","artifact_commitment":"sha256:v1:059cd76ead3ad80a0027789aad1faab689652146c401485f0bc2d40429bae918","artifact_stream_commitment":"sha256:v1:bed2a6629680112a812d796bae566c178617d64f1be6fa844273324f2ee74c21","pre_cas_ledger_digest":"sha256:v1:45b59bb90160abcea595878c62ae740e934ba1c682ce96a28ea00fe96f46e82c"}\n'
        )
        self.assertEqual(REMOTE.canonical_json(transition.data, terminal_lf=True), expected)
        self.assertEqual(len(expected), 1058)

        def lp(*parts: str) -> bytes:
            return b"".join(
                len(part.encode("utf-8")).to_bytes(4, "big") + part.encode("utf-8")
                for part in parts
            )

        digest = hashlib.sha256(
            lp("restore-transition-id.v2")
            + len(expected).to_bytes(4, "big")
            + expected
        ).hexdigest()
        commitment = "sha256:v1:" + hashlib.sha256(
            lp("recovery-commitment.v1", "restore-ledger-transition")
            + len(expected).to_bytes(4, "big")
            + expected
        ).hexdigest()
        self.assertEqual(digest, "d36f96eadb647f14a9cc9c81b4ce5e22f1c96f80e618744c8d2c97216e0be289")
        self.assertEqual(transition.transition_id, "restore-v2-d36f96eadb647f14a9cc9c81b4ce5e22f1c96f80e618744c")
        self.assertEqual(commitment, "sha256:v1:cbb7eb82b39152a585ba3d91b72f8855134e6b9a49463c2f015b2f720f39490a")
        self.assertEqual(transition.data_commitment, commitment)


    def test_effective_ssh_readback_account_and_path_safety_are_observed(self) -> None:
        configured = endpoint()
        argv = BRIDGE.build_ssh_argv(configured)
        observed = {
            "user": BRIDGE.RECOVERY_USER,
            "hostname": configured.host,
            "port": "2222",
            "identityfile": [configured.identity_path],
            "identitiesonly": "yes",
            "identityagent": "none",
            "certificatefile": "none",
            "pkcs11provider": "none",
            "gssapiauthentication": "no",
            "hostbasedauthentication": "no",
            "kbdinteractiveauthentication": "no",
            "passwordauthentication": "no",
            "pubkeyauthentication": "yes",
            "preferredauthentications": "publickey",
            "batchmode": "yes",
            "userknownhostsfile": configured.known_hosts_path,
            "globalknownhostsfile": "none",
            "knownhostscommand": "none",
            "permitremoteopen": "none",
            "stricthostkeychecking": "yes",
            "updatehostkeys": "no",
            "verifyhostkeydns": "no",
            "canonicalizehostname": "no",
            "canonicalizefallbacklocal": "no",
            "checkhostip": "no",
            "hashknownhosts": "no",
            "proxycommand": "none",
            "proxyjump": "none",
            "proxyusefdpass": "no",
            "clearallforwardings": "yes",
            "forwardagent": "no",
            "forwardx11": "no",
            "forwardx11trusted": "no",
            "requesttty": "no",
            "permitlocalcommand": "no",
            "controlmaster": "no",
            "controlpath": "none",
            "controlpersist": "no",
            "sessiontype": "default",
            "escapechar": "none",
            "stdinnull": "no",
            "compression": "no",
            "tcpkeepalive": "no",
            "connectionattempts": "1",
            "connecttimeout": "5",
            "serveraliveinterval": "1",
            "serveralivecountmax": "3",
        }
        raw = b"".join(
            f"{key} {value}\n".encode("ascii")
            for key, value in observed.items()
            for value in (value if key == "identityfile" else [value])
        )
        calls: list[tuple[list[str], dict[str, object]]] = []

        def run(argv_value: list[str], **kwargs: object) -> types.SimpleNamespace:
            calls.append((argv_value, kwargs))
            return types.SimpleNamespace(returncode=0, stdout=raw, stderr=b"")

        readback = BRIDGE.validate_ssh_effective_readback(configured, argv, run_fn=run)
        self.assertEqual(readback["observed"]["argv"][1], "-G")
        self.assertEqual(calls[0][0], [configured.ssh_binary, "-G", *argv[1:]])
        self.assertEqual(calls[0][1]["timeout"], 5.0)

        account = types.SimpleNamespace(
            pw_name=BRIDGE.RECOVERY_USER,
            pw_uid=1001,
            pw_gid=1001,
            pw_dir=BRIDGE.RECOVERY_HOME,
            pw_shell=BRIDGE.RECOVERY_SHELL,
        )
        directories = {
            "/var", "/var/empty", BRIDGE.RECOVERY_HOME,
            "/usr", "/usr/bin", "/bin",
        }

        def lstat(path: str) -> types.SimpleNamespace:
            if path in directories:
                return types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)
            if path == "/bin/sh":
                return types.SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0, st_gid=0)
            if path == "/usr/bin/dash":
                return types.SimpleNamespace(st_mode=stat.S_IFREG | 0o555, st_uid=0, st_gid=0)
            raise OSError(path)

        actual = BRIDGE.read_local_account_bootstrap(
            getpwnam_fn=lambda _user: account,
            lstat_fn=lstat,
            realpath_fn=lambda _path: "/usr/bin/dash",
        )
        self.assertEqual(actual["uid"], 1001)
        self.assertEqual(actual["login_shell"], "/bin/sh")
        with self.assertRaisesRegex(BRIDGE.EndpointAdmissionError, "TEST_PATH_UNSAFE"):
            BRIDGE._validate_safe_path_components(
                "/unsafe/file",
                "test",
                lstat_fn=lambda _path: types.SimpleNamespace(
                    st_mode=stat.S_IFDIR | 0o777,
                    st_uid=0,
                    st_gid=0,
                ),
            )


class StoreSequenceTests(BridgeTestCase):
    def test_cas_a_durable_restore_begin_and_commit(self) -> None:
        store, _ = self.new_store()
        result, session = self.run_bridge(store)
        self.assertEqual(result.classification, "FAILURE")
        self.assertEqual(result.cas_classification, "C")
        self.assertFalse(result.finality_complete)
        self.assertEqual(
            result.trace,
            ("BOOT", "READY", "DISCOVERY", "PRE_CAS", "CAS_A", "PROCEED", "RESULT", "CAS_C"),
        )
        snapshot = store.load_epoch(EPOCH_REF)
        self.assertEqual(snapshot.record["state"], "ACTIVE")
        self.assertEqual(snapshot.ledger["state"], "CONSUMED")
        self.assertEqual(snapshot.spool["last_stage"], "RESTORE_BEGIN")
        sent_types = [frame.message for frame in session.sent]
        self.assertEqual(sent_types, [BRIDGE.MESSAGE_BOOT, BRIDGE.MESSAGE_PROCEED])
        self.assertTrue(session.closed)
        self.assertIsNone(result.result_evidence)

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
