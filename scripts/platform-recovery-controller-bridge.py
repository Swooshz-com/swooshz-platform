#!/usr/bin/env python3
"""Repository-only local recovery controller bridge.

This module owns the local trust/session boundary and delegates the durable
one-use authority to the canonical ControllerStore V2.  The only remote
transport is one hermetic OpenSSH session carrying SWZFRM02 frames.  No live
operation is selected by imports or by the deterministic test seams.
"""

from __future__ import annotations

import dataclasses
import hashlib
import importlib.util
import os
import pathlib
import re
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any, BinaryIO, Callable, Mapping

from_remote = importlib.util.spec_from_file_location(
    "platform_recovery_remote_agent_bridge",
    pathlib.Path(__file__).with_name("platform-recovery-remote-agent.py"),
)
if from_remote is None or from_remote.loader is None:
    raise RuntimeError("remote agent module unavailable")
REMOTE = importlib.util.module_from_spec(from_remote)
sys.modules[from_remote.name] = REMOTE
from_remote.loader.exec_module(REMOTE)

from_store = importlib.util.spec_from_file_location(
    "platform_recovery_controller_store_bridge",
    pathlib.Path(__file__).with_name("platform-recovery-controller-store.py"),
)
if from_store is None or from_store.loader is None:
    raise RuntimeError("controller store module unavailable")
STORE = importlib.util.module_from_spec(from_store)
sys.modules[from_store.name] = STORE
from_store.loader.exec_module(STORE)


CANONICAL_REVISION = REMOTE.CANONICAL_REVISION
CANONICAL_LOCATOR_SOURCE_COMMITMENT = REMOTE.CANONICAL_LOCATOR_SOURCE_COMMITMENT
CANONICAL_LOCATOR_PACKAGE_COMMITMENT = REMOTE.CANONICAL_LOCATOR_PACKAGE_COMMITMENT
CANONICAL_LOCATOR_PACKAGE_ATTESTATION = REMOTE.LOCATOR_PACKAGE_ATTESTATION
FIXED_LOADER_SOURCE = REMOTE.FIXED_LOADER_SOURCE
FIXED_LOADER_COMMITMENT = REMOTE.FIXED_LOADER_COMMITMENT

SWZFRM02_MAGIC = REMOTE.SWZFRM02_MAGIC
SWZFRM02_VERSION = REMOTE.SWZFRM02_VERSION
SWZFRM02_HEADER = REMOTE.SWZFRM02_HEADER
FRAME_HEADER_BYTES = REMOTE.FRAME_HEADER_BYTES
MAX_FRAME_BYTES = REMOTE.MAX_FRAME_BYTES
MAX_CONTROL_PAYLOAD_BYTES = REMOTE.MAX_CONTROL_PAYLOAD_BYTES
MAX_SESSION_FRAMES = REMOTE.MAX_SESSION_FRAMES
MAX_SESSION_BYTES = REMOTE.MAX_SESSION_BYTES

DIRECTION_LOCAL_TO_REMOTE = REMOTE.DIRECTION_LOCAL_TO_REMOTE
DIRECTION_REMOTE_TO_LOCAL = REMOTE.DIRECTION_REMOTE_TO_LOCAL
MESSAGE_BOOT = REMOTE.MESSAGE_BOOT
MESSAGE_READY = REMOTE.MESSAGE_READY
MESSAGE_DISCOVERY = REMOTE.MESSAGE_DISCOVERY
MESSAGE_PROCEED = REMOTE.MESSAGE_PROCEED
MESSAGE_RESULT = REMOTE.MESSAGE_RESULT
MESSAGE_ABORT = REMOTE.MESSAGE_ABORT

COMMITMENT_RE = re.compile(r"sha256:v1:[0-9a-f]{64}\Z", re.ASCII)
REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z", re.ASCII)
CANONICAL_UTC_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z",
    re.ASCII,
)

ENDPOINT_FIELDS = (
    "schema",
    "host",
    "port",
    "user",
    "ssh_binary",
    "identity_path",
    "known_hosts_path",
    "authorized_keys_path",
    "sshd_config_path",
    "forced_command",
    "sshd_effective_config_commitment",
    "connect_timeout_seconds",
    "server_alive_interval_seconds",
    "server_alive_count_max",
    "session_type",
    "ssh_binary_bytes_commitment",
    "known_hosts_bytes_commitment",
    "authorized_keys_commitment",
    "sshd_config_bytes_commitment",
    "loader_commitment",
    "launcher_commitment",
    "agent_commitment",
)
ENDPOINT_SCHEMA = "swz-recovery-ssh-endpoint.v2"
FORCED_COMMAND = "/opt/swooshz/recovery/recovery-launcher-v1 --protocol-v2"
RECOVERY_USER = "swooshz-recovery"
RECOVERY_SHELL = "/bin/sh"
RECOVERY_HOME = "/var/empty/swooshz-recovery"
CONNECT_TIMEOUT_SECONDS = 5
SERVER_ALIVE_INTERVAL_SECONDS = 1
SERVER_ALIVE_COUNT_MAX = 3
SESSION_TYPE = "single"

EFFECTIVE_SSH_FIELDS = (
    "user",
    "forcecommand",
    "disableforwarding",
    "allowagentforwarding",
    "allowtcpforwarding",
    "allowstreamlocalforwarding",
    "x11forwarding",
    "permittty",
    "permittunnel",
    "gatewayports",
    "permituserenvironment",
    "permitopen",
    "permitlisten",
    "maxsessions",
    "acceptenv",
)
EXPECTED_EFFECTIVE_SSH = {
    "user": RECOVERY_USER,
    "forcecommand": FORCED_COMMAND,
    "disableforwarding": "yes",
    "allowagentforwarding": "no",
    "allowtcpforwarding": "no",
    "allowstreamlocalforwarding": "no",
    "x11forwarding": "no",
    "permittty": "no",
    "permittunnel": "no",
    "gatewayports": "no",
    "permituserenvironment": "no",
    "permitopen": "none",
    "permitlisten": "none",
    "maxsessions": 1,
    "acceptenv": "",
}

TRANSITION_FIELDS = (
    "schema",
    "version",
    "epoch_ref",
    "authority_ref",
    "barrier_utc",
    "barrier_commitment",
    "runner_commitment",
    "bundle_commitment",
    "image_commitment",
    "target_commitment",
    "isolation_commitment",
    "artifact_commitment",
    "artifact_stream_commitment",
    "pre_cas_ledger_digest",
)
TRANSITION_SCHEMA = "restore-ledger-transition-data.v2"
TRANSITION_VERSION = 2

RESTORE_BEGIN_FIELDS = (
    "schema",
    "epoch_ref",
    "transition_id",
    "transition_data_commitment",
    "artifact_commitment",
    "artifact_stream_commitment",
    "ledger_state",
    "record_state",
    "spool_previous_stage",
    "frame_sequence",
    "previous_frame_hash",
    "frame_hash",
    "spool_commitment",
    "ledger_after_digest",
    "durability",
)
RESTORE_BEGIN_SCHEMA = "restore-begin-evidence.v2"

ABORT_CODES = {
    "SSH_SERVER_ADMISSION_FAILED",
    "LAUNCHER_COMMITMENT_MISMATCH",
    "AGENT_COMMITMENT_MISMATCH",
    "PACKAGE_DRIFT",
    "LOADER_REJECTED",
    "BOOT_INVALID",
    "SESSION_BINDING_INVALID",
    "READY_INVALID",
    "READY_MISMATCH",
    "DISCOVERY_INVALID",
    "LOCATOR_NOT_FOUND",
    "LOCATOR_AMBIGUOUS",
    "IMAGE_ADMISSION_FAILED",
    "TARGET_ISOLATION_FAILED",
    "STORE_STATE_INVALID",
    "ARTIFACT_BIND_FAILED",
    "STORE_READBACK_FAILED",
    "CAS_REJECTED_UNCONSUMED",
    "RESTORE_BEGIN_NOT_DURABLE",
    "PROCEED_INVALID",
    "RESTORE_FAILED",
    "CLEANUP_FAILED",
    "PROCESS_FAILED",
}
UNSET_COMMITMENT = REMOTE.bytes_commitment("unset", b"")


class BridgeError(RuntimeError):
    """Public-safe symbolic bridge failure."""

    def __init__(self, code: str, *, safety_state: str | None = None) -> None:
        self.code = code
        self.safety_state = safety_state
        super().__init__(code)


class ProtocolError(BridgeError):
    pass


class EndpointAdmissionError(BridgeError):
    pass


class StoreIntegrationError(BridgeError):
    pass


class TransportError(BridgeError):
    pass


def _strict_ref(value: Any, label: str) -> str:
    if not isinstance(value, str) or REF_RE.fullmatch(value) is None:
        raise EndpointAdmissionError(f"{label.upper()}_INVALID")
    return value


def _strict_absolute_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not (os.path.isabs(value) or value.startswith("/")) or "\x00" in value:
        raise EndpointAdmissionError(f"{label.upper()}_INVALID")
    if value.endswith(("/", "\\")):
        raise EndpointAdmissionError(f"{label.upper()}_INVALID")
    return value


def _strict_bytes(value: Any, label: str, *, minimum: int = 1, maximum: int = 1 << 20) -> bytes:
    if not isinstance(value, bytes) or not minimum <= len(value) <= maximum:
        raise EndpointAdmissionError(f"{label.upper()}_INVALID")
    return value


def _validate_known_hosts(raw: bytes) -> None:
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise EndpointAdmissionError("KNOWN_HOSTS_INVALID") from error
    lines = text.splitlines()
    if len(lines) != 1 or not text.endswith("\n"):
        raise EndpointAdmissionError("KNOWN_HOSTS_INVALID")
    line = lines[0]
    if any(token in line for token in ("*", "?", "!", "|", "@cert-authority", "@revoked", "#")):
        raise EndpointAdmissionError("KNOWN_HOSTS_INVALID")
    parts = line.split()
    if len(parts) != 3 or not parts[0] or not parts[1] or not parts[2]:
        raise EndpointAdmissionError("KNOWN_HOSTS_INVALID")


def _validate_authorized_keys(raw: bytes) -> None:
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise EndpointAdmissionError("AUTHORIZED_KEYS_INVALID") from error
    lines = text.splitlines()
    if len(lines) != 1 or not text.endswith("\n"):
        raise EndpointAdmissionError("AUTHORIZED_KEYS_INVALID")
    line = lines[0]
    prefix = f'command="{FORCED_COMMAND}",restrict '
    if not line.startswith(prefix):
        raise EndpointAdmissionError("AUTHORIZED_KEYS_INVALID")
    key_parts = line[len(prefix):].split()
    if len(key_parts) != 2 or not key_parts[0].startswith("ssh-") or any(char in line for char in ("\r", "\x00")):
        raise EndpointAdmissionError("AUTHORIZED_KEYS_INVALID")


def validate_account_bootstrap(value: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "login_shell": RECOVERY_SHELL,
        "home": RECOVERY_HOME,
        "forced_command": FORCED_COMMAND,
        "ssh_original_command": "",
        "permit_user_rc": "no",
        "permit_user_environment": "no",
        "accept_env": "",
    }
    if not isinstance(value, Mapping) or tuple(value.keys()) != tuple(expected.keys()) or dict(value) != expected:
        raise EndpointAdmissionError("ACCOUNT_BOOTSTRAP_INVALID")
    return dict(value)

def validate_effective_ssh_config(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or tuple(value.keys()) != EFFECTIVE_SSH_FIELDS:
        raise EndpointAdmissionError("SSHD_EFFECTIVE_FIELDS_INVALID")
    result = dict(value)
    if result != EXPECTED_EFFECTIVE_SSH:
        raise EndpointAdmissionError("SSHD_EFFECTIVE_VALUES_INVALID")
    return result


@dataclass(frozen=True)
class EndpointConfig:
    host: str
    port: int
    ssh_binary: str
    identity_path: str
    known_hosts_path: str
    authorized_keys_path: str
    sshd_config_path: str
    known_hosts_bytes: bytes
    authorized_keys_bytes: bytes
    sshd_config_bytes: bytes
    ssh_binary_bytes: bytes
    client_identity_bytes: bytes
    effective_config: Mapping[str, Any]
    loader_commitment: str
    launcher_commitment: str
    agent_commitment: str
    installation_owned: bool = True
    login_shell: str = RECOVERY_SHELL
    home: str = RECOVERY_HOME

    def __post_init__(self) -> None:
        _strict_ref(self.host, "host")
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise EndpointAdmissionError("PORT_INVALID")
        for value, label in (
            (self.ssh_binary, "ssh_binary"),
            (self.identity_path, "identity_path"),
            (self.known_hosts_path, "known_hosts_path"),
            (self.authorized_keys_path, "authorized_keys_path"),
            (self.sshd_config_path, "sshd_config_path"),
        ):
            _strict_absolute_path(value, label)
        if not self.installation_owned:
            raise EndpointAdmissionError("INSTALLATION_OWNERSHIP_REQUIRED")
        if self.login_shell != RECOVERY_SHELL or self.home != RECOVERY_HOME:
            raise EndpointAdmissionError("ACCOUNT_BOOTSTRAP_INVALID")
        _strict_bytes(self.known_hosts_bytes, "known_hosts_bytes", maximum=65536)
        _strict_bytes(self.authorized_keys_bytes, "authorized_keys_bytes", maximum=65536)
        _strict_bytes(self.sshd_config_bytes, "sshd_config_bytes", maximum=1 << 20)
        _strict_bytes(self.ssh_binary_bytes, "ssh_binary_bytes", maximum=16 << 20)
        _strict_bytes(self.client_identity_bytes, "client_identity_bytes", maximum=1 << 20)
        _validate_known_hosts(self.known_hosts_bytes)
        _validate_authorized_keys(self.authorized_keys_bytes)
        validate_effective_ssh_config(self.effective_config)
        for value, label in (
            (self.loader_commitment, "loader_commitment"),
            (self.launcher_commitment, "launcher_commitment"),
            (self.agent_commitment, "agent_commitment"),
        ):
            if not isinstance(value, str) or COMMITMENT_RE.fullmatch(value) is None:
                raise EndpointAdmissionError(f"{label.upper()}_INVALID")

    @property
    def ssh_binary_bytes_commitment(self) -> str:
        return REMOTE.bytes_commitment("ssh-binary-bytes", self.ssh_binary_bytes)

    @property
    def known_hosts_bytes_commitment(self) -> str:
        return REMOTE.bytes_commitment("ssh-known-hosts-bytes", self.known_hosts_bytes)

    @property
    def authorized_keys_commitment(self) -> str:
        return REMOTE.bytes_commitment("ssh-authorized-keys-bytes", self.authorized_keys_bytes)

    @property
    def client_identity_file_commitment(self) -> str:
        return REMOTE.bytes_commitment("ssh-client-identity-bytes", self.client_identity_bytes)

    @property
    def bundle_commitment(self) -> str:
        return REMOTE.compute_bundle_commitment(self.launcher_commitment, self.agent_commitment)
    @property
    def sshd_config_bytes_commitment(self) -> str:
        return REMOTE.bytes_commitment("sshd-config-bytes", self.sshd_config_bytes)

    @property
    def sshd_effective_config_commitment(self) -> str:
        return REMOTE.bytes_commitment(
            "sshd-effective-config",
            REMOTE.canonical_json(dict(self.effective_config), terminal_lf=True),
        )

    @property
    def endpoint_object(self) -> dict[str, Any]:
        value = {
            "schema": ENDPOINT_SCHEMA,
            "host": self.host,
            "port": self.port,
            "user": RECOVERY_USER,
            "ssh_binary": self.ssh_binary,
            "identity_path": self.identity_path,
            "known_hosts_path": self.known_hosts_path,
            "authorized_keys_path": self.authorized_keys_path,
            "sshd_config_path": self.sshd_config_path,
            "forced_command": FORCED_COMMAND,
            "sshd_effective_config_commitment": self.sshd_effective_config_commitment,
            "connect_timeout_seconds": CONNECT_TIMEOUT_SECONDS,
            "server_alive_interval_seconds": SERVER_ALIVE_INTERVAL_SECONDS,
            "server_alive_count_max": SERVER_ALIVE_COUNT_MAX,
            "session_type": SESSION_TYPE,
            "ssh_binary_bytes_commitment": self.ssh_binary_bytes_commitment,
            "known_hosts_bytes_commitment": self.known_hosts_bytes_commitment,
            "authorized_keys_commitment": self.authorized_keys_commitment,
            "sshd_config_bytes_commitment": self.sshd_config_bytes_commitment,
            "loader_commitment": self.loader_commitment,
            "launcher_commitment": self.launcher_commitment,
            "agent_commitment": self.agent_commitment,
        }
        if tuple(value.keys()) != ENDPOINT_FIELDS:
            raise EndpointAdmissionError("ENDPOINT_FIELDS_INVALID")
        return value

    @property
    def endpoint_commitment(self) -> str:
        return REMOTE.bytes_commitment(
            "ssh-endpoint",
            REMOTE.canonical_json(self.endpoint_object, terminal_lf=True),
        )


def build_ssh_argv(endpoint: EndpointConfig) -> tuple[str, ...]:
    if not isinstance(endpoint, EndpointConfig):
        raise EndpointAdmissionError("ENDPOINT_INVALID")
    argv = (
        endpoint.ssh_binary,
        "-F",
        "none",
        "-p",
        str(endpoint.port),
        "-i",
        endpoint.identity_path,
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
        "-o",
        "CertificateFile=none",
        "-o",
        f"UserKnownHostsFile={endpoint.known_hosts_path}",
        "-o",
        "GlobalKnownHostsFile=none",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "UpdateHostKeys=no",
        "-o",
        "VerifyHostKeyDNS=no",
        "-o",
        "CanonicalizeHostname=no",
        "-o",
        "ProxyCommand=none",
        "-o",
        "ProxyJump=none",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ForwardX11=no",
        "-o",
        "ForwardX11Trusted=no",
        "-o",
        "RequestTTY=no",
        "-o",
        "RemoteCommand=none",
        "-o",
        "PermitLocalCommand=no",
        "-o",
        "LocalCommand=none",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPath=none",
        "-o",
        "ControlPersist=no",
        "-o",
        "SendEnv=",
        f"{RECOVERY_USER}@{endpoint.host}",
    )
    if any(not isinstance(item, str) or "\x00" in item for item in argv):
        raise EndpointAdmissionError("SSH_ARGV_INVALID")
    return argv


class OpenSSHSession:
    """One process, one stdin/stdout session, no retry or remote command."""

    def __init__(self, endpoint: EndpointConfig) -> None:
        argv = build_ssh_argv(endpoint)
        try:
            self.process = subprocess.Popen(
                list(argv),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
                env={},
                bufsize=0,
            )
        except (OSError, ValueError) as error:
            raise TransportError("SSH_SESSION_OPEN_FAILED") from error
        if self.process.stdin is None or self.process.stdout is None or self.process.stderr is None:
            raise TransportError("SSH_SESSION_PIPES_UNAVAILABLE")
        self.stdin = self.process.stdin
        self.stdout = self.process.stdout
        self.stderr = self.process.stderr
        self._closed = False

    def send_frame(self, frame: bytes) -> None:
        if self._closed:
            raise TransportError("SSH_SESSION_CLOSED")
        try:
            REMOTE._write_all(self.stdin, frame)
        except Exception as error:
            raise TransportError("SSH_FRAME_WRITE_FAILED") from error

    def receive_frame(self) -> REMOTE.DecodedFrame | None:
        if self._closed:
            raise TransportError("SSH_SESSION_CLOSED")
        try:
            return REMOTE.read_frame(self.stdout, eof_ok=True)
        except Exception as error:
            raise TransportError("SSH_FRAME_READ_FAILED") from error

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for stream in (self.stdin, self.stdout, self.stderr):
            try:
                stream.close()
            except OSError:
                pass
        try:
            self.process.wait(timeout=1.0)
        except Exception:
            try:
                self.process.kill()
            except OSError:
                pass


@dataclass(frozen=True)
class Transition:
    data: dict[str, Any]
    transition_id: str
    data_commitment: str


def build_barrier_commitment(barrier_utc: str) -> str:
    REMOTE.validate_barrier_utc(barrier_utc)
    return REMOTE.bytes_commitment("barrier-utc", barrier_utc.encode("ascii", "strict"))


def _transition_id(data_bytes: bytes) -> str:
    digest = hashlib.sha256(
        REMOTE._length_prefixed(("restore-transition-id.v2", data_bytes))
    ).hexdigest()
    return "restore-v2-" + digest[:48]


def build_restore_transition(
    *,
    epoch_ref: str,
    authority_ref: str,
    barrier_utc: str,
    barrier_commitment: str,
    runner_commitment: str,
    bundle_commitment: str,
    image_commitment: str,
    target_commitment: str,
    isolation_commitment: str,
    artifact_commitment: str,
    artifact_stream_commitment: str,
    pre_cas_ledger_digest: str,
) -> Transition:
    _strict_ref(epoch_ref, "epoch_ref")
    _strict_ref(authority_ref, "authority_ref")
    REMOTE.validate_barrier_utc(barrier_utc)
    values = (
        barrier_commitment,
        runner_commitment,
        bundle_commitment,
        image_commitment,
        target_commitment,
        isolation_commitment,
        artifact_commitment,
        artifact_stream_commitment,
        pre_cas_ledger_digest,
    )
    if any(not isinstance(value, str) or COMMITMENT_RE.fullmatch(value) is None for value in values):
        raise StoreIntegrationError("TRANSITION_COMMITMENT_INVALID")
    data = {
        "schema": TRANSITION_SCHEMA,
        "version": TRANSITION_VERSION,
        "epoch_ref": epoch_ref,
        "authority_ref": authority_ref,
        "barrier_utc": barrier_utc,
        "barrier_commitment": barrier_commitment,
        "runner_commitment": runner_commitment,
        "bundle_commitment": bundle_commitment,
        "image_commitment": image_commitment,
        "target_commitment": target_commitment,
        "isolation_commitment": isolation_commitment,
        "artifact_commitment": artifact_commitment,
        "artifact_stream_commitment": artifact_stream_commitment,
        "pre_cas_ledger_digest": pre_cas_ledger_digest,
    }
    if tuple(data.keys()) != TRANSITION_FIELDS:
        raise StoreIntegrationError("TRANSITION_FIELDS_INVALID")
    data_bytes = REMOTE.canonical_json(data, limit=STORE.MAX_RESTORE_LEDGER_BYTES, terminal_lf=True)
    return Transition(
        data,
        _transition_id(data_bytes),
        STORE.bytes_commitment(STORE.DOMAIN_RESTORE_TRANSITION, data_bytes),
    )


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        converted = dataclasses.asdict(value)
        if isinstance(converted, dict):
            return converted
    raise StoreIntegrationError(f"{label.upper()}_INVALID")


def _snapshot_is_initial(snapshot: Any) -> bool:
    record = _mapping(snapshot.record, "record")
    ledger = _mapping(snapshot.ledger, "ledger")
    spool = _mapping(snapshot.spool, "spool")
    binding = _mapping(snapshot.artifact_binding, "artifact_binding")
    return (
        isinstance(snapshot, STORE.V2EpochSnapshot)
        and record["state"] == "INITIALISED"
        and record["artifact_binding_state"] == "PENDING"
        and binding["artifact_binding_state"] == "PENDING"
        and record["artifact_commitment"] is None
        and ledger["state"] == "UNCONSUMED"
        and spool["state"] == "OPEN"
        and spool["last_stage"] == "NONE"
    )


def _snapshot_matches_cas_a(
    snapshot: Any,
    *,
    epoch_ref: str,
    transition: Transition,
) -> bool:
    return (
        isinstance(snapshot, STORE.V2EpochSnapshot)
        and snapshot.record["epoch_ref"] == epoch_ref
        and snapshot.record["state"] == "ACTIVE"
        and snapshot.ledger["state"] == "CONSUMED"
        and snapshot.ledger["transition_id"] == transition.transition_id
        and snapshot.ledger["transition_target"] == "RESTORE_STARTED"
        and snapshot.ledger["transition_data_commitment"] == transition.data_commitment
        and snapshot.spool["state"] == "OPEN"
        and snapshot.spool["last_stage"] == "RUNNER_STARTED"
    )


def _snapshot_matches_pre_cas(snapshot: Any, *, expected: Any) -> bool:
    if not isinstance(snapshot, STORE.V2EpochSnapshot):
        return False
    return (
        snapshot.record == expected.record
        and snapshot.ledger == expected.ledger
        and snapshot.spool == expected.spool
        and snapshot.artifact_binding == expected.artifact_binding
    )


def _store_frame(store: Any, epoch_ref: str, stage: str, payload: Mapping[str, Any]) -> Any:
    try:
        frame = store.prepare_runner_frame(epoch_ref, stage, payload)
        return store.ingest_frame(epoch_ref, frame)
    except Exception as error:
        raise StoreIntegrationError(f"STORE_{stage}_FAILED", safety_state=getattr(error, "safety_state", None)) from error


def _commitment(value: Any) -> str:
    if not isinstance(value, str) or COMMITMENT_RE.fullmatch(value) is None:
        raise ProtocolError("COMMITMENT_INVALID")
    return value


def _validate_ready(boot: Mapping[str, Any], ready: Mapping[str, Any], n_local: bytes) -> None:
    if tuple(ready.keys()) != REMOTE.READY_FIELDS:
        raise ProtocolError("READY_FIELDS_INVALID")
    if ready["type"] != "READY" or ready["schema"] != REMOTE.SCHEMA_WIRE:
        raise ProtocolError("READY_INVALID")
    for field in ("epoch_ref", "authority_ref", "barrier_utc", "epoch_commitment", "authority_commitment", "barrier_commitment", "runner_commitment", "bundle_commitment", "launcher_commitment", "agent_commitment"):
        if ready[field] != boot[field]:
            raise ProtocolError("READY_MISMATCH")
    if ready["version"] != REMOTE.SWZFRM02_VERSION or ready["n_local"] != n_local.hex():
        raise ProtocolError("READY_MISMATCH")


def _validate_discovery(payload: Mapping[str, Any], *, epoch_ref: str, authority_ref: str) -> dict[str, Any]:
    value = REMOTE.validate_wire_payload(payload, "DISCOVERY")
    if value["epoch_ref"] != epoch_ref or value["authority_ref"] != authority_ref:
        raise ProtocolError("DISCOVERY_MISMATCH")
    if value["execution_row_id"] <= 0:
        raise ProtocolError("DISCOVERY_INVALID")
    for field in ("image_commitment", "target_commitment", "isolation_commitment"):
        _commitment(value[field])
    return value


def _build_boot(
    *,
    n_local: bytes,
    epoch_ref: str,
    authority_ref: str,
    barrier_utc: str,
    epoch_commitment: str,
    runner_commitment: str,
    bundle_commitment: str,
    endpoint_commitment: str,
    launcher_commitment: str,
    agent_commitment: str,
) -> dict[str, Any]:
    authority_commitment = REMOTE.text_commitment("authority", authority_ref)
    value = {
        "type": "BOOT",
        "version": REMOTE.SWZFRM02_VERSION,
        "schema": REMOTE.SCHEMA_WIRE,
        "n_local": n_local.hex(),
        "epoch_ref": epoch_ref,
        "authority_ref": authority_ref,
        "barrier_utc": barrier_utc,
        "epoch_commitment": epoch_commitment,
        "authority_commitment": authority_commitment,
        "barrier_commitment": build_barrier_commitment(barrier_utc),
        "runner_commitment": runner_commitment,
        "bundle_commitment": bundle_commitment,
        "launcher_commitment": launcher_commitment,
        "agent_commitment": agent_commitment,
        "ssh_endpoint_commitment": endpoint_commitment,
    }
    return REMOTE.validate_wire_payload(value, "BOOT")


def _build_proceed(
    *,
    epoch_ref: str,
    authority_ref: str,
    barrier_utc: str,
    epoch_commitment: str,
    runner_commitment: str,
    bundle_commitment: str,
    launcher_commitment: str,
    agent_commitment: str,
    image_commitment: str,
    target_commitment: str,
    isolation_commitment: str,
    artifact_commitment: str,
    artifact_stream_commitment: str,
    transition: Transition,
    consumed_record_commitment: str,
    restore_begin_commitment: str,
) -> dict[str, Any]:
    value = {
        "type": "PROCEED",
        "version": REMOTE.SWZFRM02_VERSION,
        "schema": REMOTE.SCHEMA_WIRE,
        "epoch_ref": epoch_ref,
        "authority_ref": authority_ref,
        "barrier_utc": barrier_utc,
        "epoch_commitment": epoch_commitment,
        "authority_commitment": REMOTE.text_commitment("authority", authority_ref),
        "barrier_commitment": build_barrier_commitment(barrier_utc),
        "runner_commitment": runner_commitment,
        "bundle_commitment": bundle_commitment,
        "launcher_commitment": launcher_commitment,
        "agent_commitment": agent_commitment,
        "image_commitment": image_commitment,
        "target_commitment": target_commitment,
        "isolation_commitment": isolation_commitment,
        "artifact_commitment": artifact_commitment,
        "artifact_stream_commitment": artifact_stream_commitment,
        "transition_id": transition.transition_id,
        "pre_cas_ledger_digest": transition.data["pre_cas_ledger_digest"],
        "transition_data_commitment": transition.data_commitment,
        "consumed_record_commitment": consumed_record_commitment,
        "restore_begin_commitment": restore_begin_commitment,
    }
    return REMOTE.validate_wire_payload(value, "PROCEED")


def _build_restore_begin_evidence(
    *,
    previous_snapshot: Any,
    snapshot: Any,
    transition: Transition,
    artifact_commitment: str,
    artifact_stream_commitment: str,
    ledger_after_digest: str,
) -> dict[str, Any]:
    previous_spool = _mapping(previous_snapshot.spool, "previous_spool")
    spool = _mapping(snapshot.spool, "spool")
    value = {
        "schema": RESTORE_BEGIN_SCHEMA,
        "epoch_ref": snapshot.record["epoch_ref"],
        "transition_id": transition.transition_id,
        "transition_data_commitment": transition.data_commitment,
        "artifact_commitment": artifact_commitment,
        "artifact_stream_commitment": artifact_stream_commitment,
        "ledger_state": snapshot.ledger["state"],
        "record_state": snapshot.record["state"],
        "spool_previous_stage": previous_spool["last_stage"],
        "frame_sequence": spool["next_sequence"] - 1,
        "previous_frame_hash": previous_spool["last_frame_hash"],
        "frame_hash": spool["last_frame_hash"],
        "spool_commitment": spool["spool_commitment"],
        "ledger_after_digest": ledger_after_digest,
        "durability": dict(snapshot.record["durability"]),
    }
    if tuple(value.keys()) != RESTORE_BEGIN_FIELDS:
        raise StoreIntegrationError("RESTORE_BEGIN_FIELDS_INVALID")
    if value["spool_previous_stage"] != "RUNNER_STARTED" or type(value["frame_sequence"]) is not int or value["frame_sequence"] <= 0:
        raise StoreIntegrationError("RESTORE_BEGIN_EVIDENCE_INVALID")
    if value["previous_frame_hash"] == value["frame_hash"]:
        raise StoreIntegrationError("RESTORE_BEGIN_FRAME_HASH_INVALID")
    for field in ("transition_data_commitment", "artifact_commitment", "artifact_stream_commitment", "spool_commitment", "ledger_after_digest"):
        _commitment(value[field])
    if not isinstance(value["durability"], Mapping):
        raise StoreIntegrationError("RESTORE_BEGIN_DURABILITY_INVALID")
    return value

def _safe_evidence(
    *,
    snapshot: Any,
    endpoint_commitment: str,
    stage: str,
    code: str,
    transition: Transition | None = None,
    barrier_commitment: str | None = None,
    process_finality: str = "NOT_OBSERVED",
    transport_finality: str = "NOT_OBSERVED",
    cleanup_state: str = "NOT_STARTED",
    abandon_allowed: bool = False,
) -> dict[str, Any]:
    if code not in ABORT_CODES:
        raise ProtocolError("ABORT_CODE_INVALID")
    record = _mapping(snapshot.record, "record")
    ledger = _mapping(snapshot.ledger, "ledger")
    spool = _mapping(snapshot.spool, "spool")
    data = {
        "schema": REMOTE.SCHEMA_ABORT,
        "epoch_ref": record["epoch_ref"],
        "authority_ref": record["authority_ref"],
        "ssh_endpoint_commitment": endpoint_commitment,
        "stage": stage,
        "direction": "LOCAL_TO_REMOTE",
        "code": code,
        "classification": "FAILURE",
        "epoch_commitment": STORE.bytes_commitment(STORE.DOMAIN_EPOCH_RECORD, REMOTE.canonical_json(record, terminal_lf=True)),
        "authority_commitment": REMOTE.text_commitment("authority", record["authority_ref"]),
        "barrier_commitment": barrier_commitment or UNSET_COMMITMENT,
        "transition_id": transition.transition_id if transition else "unset-transition",
        "transition_data_commitment": transition.data_commitment if transition else UNSET_COMMITMENT,
        "restore_begin_commitment": UNSET_COMMITMENT,
        "consumed_state": ledger["state"],
        "record_state": record["state"],
        "ledger_state": ledger["state"],
        "spool_last_stage": spool["last_stage"],
        "store_readback_commitment": STORE.bytes_commitment(STORE.DOMAIN_RESTORE_LEDGER, REMOTE.canonical_json(dict(ledger), terminal_lf=True)),
        "process_finality": process_finality,
        "transport_finality": transport_finality,
        "cleanup_state": cleanup_state,
        "retry_allowed": False,
        "reconnect_allowed": False,
        "proceed_allowed": False,
        "restore_allowed": False,
        "commit_allowed": False,
        "abandon_allowed": abandon_allowed,
    }
    REMOTE.validate_abort_evidence(data)
    return data


@dataclass(frozen=True)
class BridgeResult:
    classification: str
    code: str
    stage: str
    cas_classification: str | None
    result_evidence: Mapping[str, Any] | None
    abort_evidence: Mapping[str, Any] | None
    trace: tuple[str, ...]
    finality_complete: bool


def _is_success_result(evidence: Mapping[str, Any]) -> bool:
    return (
        evidence["classification"] == "SUCCESS"
        and evidence["result_code"] == "RESTORE_SUCCEEDED"
        and evidence["restore_count"] == 1
        and evidence["exit_status"] == 0
        and evidence["stdin_eof"] is True
        and evidence["stdout_eof"] is True
        and evidence["stderr_eof"] is True
        and evidence["trailing_unframed_bytes"] == 0
        and evidence["cleanup_state"] == "COMPLETE"
    )


def _validate_result_contract(evidence: Mapping[str, Any], proceed: Mapping[str, Any], endpoint_commitment: str) -> None:
    for field in (
        "epoch_ref", "authority_ref", "barrier_utc", "epoch_commitment",
        "runner_commitment", "bundle_commitment", "launcher_commitment",
        "agent_commitment", "image_commitment", "target_commitment",
        "isolation_commitment", "artifact_commitment",
        "artifact_stream_commitment", "transition_id",
        "pre_cas_ledger_digest", "transition_data_commitment",
        "consumed_record_commitment", "restore_begin_commitment",
    ):
        if evidence[field] != proceed[field]:
            raise ProtocolError("RESULT_MISMATCH")
    if evidence["ssh_endpoint_commitment"] != endpoint_commitment:
        raise ProtocolError("RESULT_MISMATCH")
    if evidence["barrier_commitment"] != proceed["barrier_commitment"]:
        raise ProtocolError("RESULT_MISMATCH")
    if evidence["stage"] not in {"RESTORE", "CLEANUP", "PROCESS"}:
        raise ProtocolError("RESULT_STAGE_INVALID")

class ControllerBridge:
    def __init__(
        self,
        store: Any,
        endpoint: EndpointConfig,
        epoch_ref: str,
        barrier_utc: str,
        *,
        session_factory: Callable[[EndpointConfig], Any] | None = None,
        nonce_factory: Callable[[int], bytes] | None = None,
        clock: Callable[[], float] = time.monotonic,
        artifact_stream_commitment: str | None = None,
        test_mode: bool = False,
    ) -> None:
        if not isinstance(endpoint, EndpointConfig):
            raise EndpointAdmissionError("ENDPOINT_INVALID")
        REMOTE.validate_barrier_utc(barrier_utc)
        _strict_ref(epoch_ref, "epoch_ref")
        if not callable(clock):
            raise TypeError("clock")
        if artifact_stream_commitment is not None:
            _commitment(artifact_stream_commitment)
        if not test_mode and nonce_factory is not None:
            raise BridgeError("TEST_SEAM_NOT_PRODUCTION")
        if not test_mode and session_factory is not None and not callable(session_factory):
            raise BridgeError("SESSION_FACTORY_INVALID")
        self.store = store
        self.endpoint = endpoint
        self.epoch_ref = epoch_ref
        self.barrier_utc = barrier_utc
        self.session_factory = session_factory or OpenSSHSession
        self.nonce_factory = nonce_factory or secrets.token_bytes
        self.clock = clock
        self.artifact_stream_commitment = artifact_stream_commitment
        self.test_mode = test_mode
        self.trace: list[str] = []
        self._sequence = 0
        self._n_local: bytes | None = None
        self._session: Any | None = None
        self._cas_classification: str | None = None
        self._transition: Transition | None = None
        self._restore_begin_commitment: str | None = None
        self._terminal = False
        self._epoch_commitment: str | None = None

    def _new_nonce(self) -> bytes:
        if self._n_local is not None:
            raise ProtocolError("N_LOCAL_REGENERATED")
        value = self.nonce_factory(32)
        if not isinstance(value, bytes) or len(value) != 32:
            raise ProtocolError("N_LOCAL_INVALID")
        self._n_local = value
        return value

    def _send(self, message: int, payload: Mapping[str, Any]) -> None:
        if self._session is None or self._n_local is None:
            raise TransportError("SESSION_NOT_OPEN")
        frame = REMOTE.encode_frame(
            DIRECTION_LOCAL_TO_REMOTE,
            message,
            self._sequence,
            self._n_local,
            payload,
        )
        self._session.send_frame(frame)
        self._sequence += 1

    def _receive(self, expected: tuple[int, ...]) -> REMOTE.DecodedFrame:
        if self._session is None or self._n_local is None:
            raise TransportError("SESSION_NOT_OPEN")
        frame = self._session.receive_frame()
        if frame is None:
            raise TransportError("SESSION_EOF")
        if frame.sequence != self._sequence or frame.n_local != self._n_local:
            raise ProtocolError("SESSION_BINDING_INVALID")
        if frame.direction != DIRECTION_REMOTE_TO_LOCAL or frame.message not in expected:
            raise ProtocolError("SESSION_STATE_INVALID")
        REMOTE.validate_wire_payload(
            frame.payload,
            REMOTE.MESSAGE_NAMES[frame.message],
            n_local=self._n_local if frame.message == MESSAGE_READY else None,
        )
        self._sequence += 1
        if self._sequence > MAX_SESSION_FRAMES:
            raise ProtocolError("SESSION_LIMIT_EXCEEDED")
        return frame

    def _send_abort(self, snapshot: Any, stage: str, code: str, *, abandon_allowed: bool) -> BridgeResult:
        evidence = _safe_evidence(
            snapshot=snapshot,
            endpoint_commitment=self.endpoint.endpoint_commitment,
            stage=stage,
            code=code,
            transition=self._transition,
            abandon_allowed=abandon_allowed,
            barrier_commitment=build_barrier_commitment(self.barrier_utc),
        )
        self.trace.append("ABORT")
        if self._cas_classification != "C":
            try:
                self._send(
                    MESSAGE_ABORT,
                    {
                        "type": "ABORT",
                        "version": REMOTE.SWZFRM02_VERSION,
                        "schema": REMOTE.SCHEMA_WIRE,
                        "code": code,
                        "stage": stage,
                        "direction": "LOCAL_TO_REMOTE",
                        "evidence": evidence,
                        "evidence_commitment": REMOTE.bytes_commitment(
                            "abort-evidence",
                            REMOTE.canonical_json(evidence, terminal_lf=True),
                        ),
                    },
                )
            except (BridgeError, OSError, ValueError, TypeError):
                self.trace.append("ABORT_WRITE_FAILED")
        self._terminal = True
        return BridgeResult("FAILURE", code, stage, self._cas_classification, None, evidence, tuple(self.trace), False)

    def _try_abandon(self, *, required: bool) -> bool:
        try:
            self.store.abandon(self.epoch_ref)
            self.trace.append("ABANDON")
            return True
        except Exception:
            if required:
                raise
            return False

    def _store_pre_cas(self, snapshot: Any, discovery: Mapping[str, Any]) -> tuple[Any, str, str, Transition]:
        try:
            artifact_commitment = self.store.bind_artifact_v2(
                self.epoch_ref,
                discovery["execution_row_id"],
                discovery["artifact_filename"],
            )
            bound = self.store.load_epoch(self.epoch_ref)
            if (
                not isinstance(bound, STORE.V2EpochSnapshot)
                or bound.record["artifact_commitment"] != artifact_commitment
                or bound.artifact_binding.artifact_commitment != artifact_commitment
            ):
                raise StoreIntegrationError("STORE_READBACK_FAILED")
            self.store.mark_ready(self.epoch_ref)
            _store_frame(self.store, self.epoch_ref, "EPOCH_READY", {"state": "READY"})
            self.store.activate(self.epoch_ref)
            runner_commitment = bound.record["runner_commitment"]
            _store_frame(
                self.store,
                self.epoch_ref,
                "RUNNER_STARTED",
                {"commitment": discovery["image_commitment"], "state": "RUNNER_STARTED"},
            )
            active = self.store.load_epoch(self.epoch_ref)
            if not isinstance(active, STORE.V2EpochSnapshot) or active.record["state"] != "ACTIVE" or active.spool["last_stage"] != "RUNNER_STARTED":
                raise StoreIntegrationError("STORE_READBACK_FAILED")
            artifact_stream_commitment = self.artifact_stream_commitment
            if artifact_stream_commitment is None:
                raise StoreIntegrationError("ARTIFACT_STREAM_BIND_REQUIRED")
            pre_digest = self.store.ledger_digest(self.epoch_ref)
            transition = build_restore_transition(
                epoch_ref=self.epoch_ref,
                authority_ref=active.record["authority_ref"],
                barrier_utc=self.barrier_utc,
                barrier_commitment=build_barrier_commitment(self.barrier_utc),
                runner_commitment=runner_commitment,
                bundle_commitment=self.endpoint.bundle_commitment,
                image_commitment=discovery["image_commitment"],
                target_commitment=discovery["target_commitment"],
                isolation_commitment=discovery["isolation_commitment"],
                artifact_commitment=artifact_commitment,
                artifact_stream_commitment=artifact_stream_commitment,
                pre_cas_ledger_digest=pre_digest,
            )
            return active, artifact_commitment, artifact_stream_commitment, transition
        except StoreIntegrationError:
            raise
        except Exception as error:
            raise StoreIntegrationError("STORE_PRE_CAS_FAILED") from error

    def _classify_cas(self, pre_cas: Any, transition: Transition) -> tuple[str, Any | None, str | None]:
        try:
            permit = self.store.consume_restore(
                self.epoch_ref,
                transition.transition_id,
                expected_digest=transition.data["pre_cas_ledger_digest"],
                data=transition.data,
            )
        except Exception as error:
            safety = getattr(error, "safety_state", None)
            try:
                current = self.store.load_epoch(self.epoch_ref)
            except Exception:
                self._cas_classification = "C"
                return "C", None, getattr(error, "code", "CAS_UNCERTAIN")
            if safety == "UNCONSUMED" and _snapshot_matches_pre_cas(current, expected=pre_cas):
                self._cas_classification = "B"
                return "B", current, getattr(error, "code", "CAS_REJECTED_UNCONSUMED")
            self._cas_classification = "C"
            return "C", current, getattr(error, "code", "CAS_UNCERTAIN")
        if getattr(permit, "idempotent", True) is not False or getattr(permit, "state", None) != "CONSUMED":
            self._cas_classification = "C"
            return "C", None, "CAS_RETURN_INVALID"
        try:
            current = self.store.load_epoch(self.epoch_ref)
        except Exception:
            self._cas_classification = "C"
            return "C", None, "CAS_READBACK_FAILED"
        if not _snapshot_matches_cas_a(current, epoch_ref=self.epoch_ref, transition=transition):
            self._cas_classification = "C"
            return "C", current, "CAS_READBACK_CONTRADICTION"
        self._cas_classification = "A"
        consumed = self.store.record_digest(self.epoch_ref)
        return "A", current, consumed

    def run(self) -> BridgeResult:
        snapshot: Any | None = None
        try:
            snapshot = self.store.load_epoch(self.epoch_ref)
            if not _snapshot_is_initial(snapshot):
                raise StoreIntegrationError("STORE_STATE_INVALID")
            self._new_nonce()
            self.trace.append("BOOT")
            self._session = self.session_factory(self.endpoint)
            if self._session is None:
                raise TransportError("SSH_SESSION_OPEN_FAILED")
            epoch_commitment = self.store.record_digest(self.epoch_ref)
            runner_commitment = snapshot.record["runner_commitment"]
            self._epoch_commitment = epoch_commitment
            boot = _build_boot(
                n_local=self._n_local,
                epoch_ref=self.epoch_ref,
                authority_ref=snapshot.record["authority_ref"],
                barrier_utc=self.barrier_utc,
                epoch_commitment=epoch_commitment,
                runner_commitment=runner_commitment,
                bundle_commitment=self.endpoint.bundle_commitment,
                endpoint_commitment=self.endpoint.endpoint_commitment,
                launcher_commitment=self.endpoint.launcher_commitment,
                agent_commitment=self.endpoint.agent_commitment,
            )
            self._send(MESSAGE_BOOT, boot)
            ready_frame = self._receive((MESSAGE_READY, MESSAGE_ABORT))
            if ready_frame.message == MESSAGE_ABORT:
                raise ProtocolError("REMOTE_ABORT")
            _validate_ready(boot, ready_frame.payload, self._n_local)
            self.trace.append("READY")
            discovery_frame = self._receive((MESSAGE_DISCOVERY, MESSAGE_ABORT))
            if discovery_frame.message == MESSAGE_ABORT:
                raise ProtocolError("REMOTE_ABORT")
            discovery = _validate_discovery(
                discovery_frame.payload,
                epoch_ref=self.epoch_ref,
                authority_ref=snapshot.record["authority_ref"],
            )
            self.trace.append("DISCOVERY")
            active, artifact_commitment, artifact_stream_commitment, transition = self._store_pre_cas(snapshot, discovery)
            self._transition = transition
            self.trace.append("PRE_CAS")
            classification, current, consumed_record_commitment = self._classify_cas(active, transition)
            if classification == "B":
                self._try_abandon(required=True)
                return self._send_abort(current, "CAS_B", "CAS_REJECTED_UNCONSUMED", abandon_allowed=True)
            if classification == "C":
                return BridgeResult("FAILURE", "CAS_UNCERTAIN", "PRE_CAS", "C", None, None, tuple(self.trace), False)
            self.trace.append("CAS_A")
            ledger_after_digest = self.store.ledger_digest(self.epoch_ref)
            before_restore_begin = self.store.load_epoch(self.epoch_ref)
            _store_frame(
                self.store,
                self.epoch_ref,
                "RESTORE_BEGIN",
                {"ref": transition.transition_id, "commitment": transition.data_commitment},
            )
            durable_snapshot = self.store.load_epoch(self.epoch_ref)
            if durable_snapshot.spool["last_stage"] != "RESTORE_BEGIN" or durable_snapshot.ledger["state"] != "CONSUMED":
                return BridgeResult("FAILURE", "RESTORE_BEGIN_NOT_DURABLE", "RESTORE_BEGIN", "A", None, None, tuple(self.trace), False)
            restore_begin = _build_restore_begin_evidence(
                previous_snapshot=before_restore_begin,
                snapshot=durable_snapshot,
                transition=transition,
                artifact_commitment=artifact_commitment,
                artifact_stream_commitment=artifact_stream_commitment,
                ledger_after_digest=ledger_after_digest,
            )
            self._restore_begin_commitment = REMOTE.bytes_commitment(
                "restore-begin-evidence",
                REMOTE.canonical_json(restore_begin, terminal_lf=True),
            )
            proceed = _build_proceed(
                epoch_ref=self.epoch_ref,
                authority_ref=active.record["authority_ref"],
                barrier_utc=self.barrier_utc,
                epoch_commitment=self._epoch_commitment,
                runner_commitment=active.record["runner_commitment"],
                bundle_commitment=self.endpoint.bundle_commitment,
                launcher_commitment=self.endpoint.launcher_commitment,
                agent_commitment=self.endpoint.agent_commitment,
                image_commitment=discovery["image_commitment"],
                target_commitment=discovery["target_commitment"],
                isolation_commitment=discovery["isolation_commitment"],
                artifact_commitment=artifact_commitment,
                artifact_stream_commitment=artifact_stream_commitment,
                transition=transition,
                consumed_record_commitment=consumed_record_commitment,
                restore_begin_commitment=self._restore_begin_commitment,
            )
            self.trace.append("PROCEED")
            self._send(MESSAGE_PROCEED, proceed)
            result_frame = self._receive((MESSAGE_RESULT, MESSAGE_ABORT))
            if result_frame.message == MESSAGE_ABORT:
                raise ProtocolError("REMOTE_ABORT")
            evidence = REMOTE.validate_result_evidence(result_frame.payload["result_evidence"])
            if result_frame.payload["classification"] != evidence["classification"]:
                raise ProtocolError("RESULT_MISMATCH")
            _validate_result_contract(evidence, proceed, self.endpoint.endpoint_commitment)
            expected_result_commitment = REMOTE.bytes_commitment(
                "result-evidence",
                REMOTE.canonical_json(evidence, terminal_lf=True),
            )
            if result_frame.payload["result_commitment"] != expected_result_commitment:
                raise ProtocolError("RESULT_COMMITMENT_INVALID")
            if not _is_success_result(evidence):
                self._try_abandon(required=True)
                self._terminal = True
                return BridgeResult("FAILURE", evidence["result_code"], "RESULT", "A", evidence, None, tuple(self.trace), True)
            _store_frame(
                self.store,
                self.epoch_ref,
                "COMMIT",
                {"classification": "SUCCESS", "commitment": expected_result_commitment},
            )
            self.trace.extend(("RESULT", "COMMIT", "FINAL"))
            self._terminal = True
            return BridgeResult("SUCCESS", "RESTORE_SUCCEEDED", "COMMIT", "A", evidence, None, tuple(self.trace), True)
        except (BridgeError, StoreIntegrationError, OSError, ValueError, TypeError) as error:
            code = getattr(error, "code", "PROTOCOL_FAILURE")
            if code == "REMOTE_ABORT":
                code = "RESTORE_FAILED"
            if self._cas_classification == "C":
                self._terminal = True
                return BridgeResult("FAILURE", "CAS_UNCERTAIN", "POST_CAS", "C", None, None, tuple(self.trace), False)
            if snapshot is None:
                snapshot = dataclasses.make_dataclass("Snapshot", [])()
                snapshot.record = {"epoch_ref": self.epoch_ref, "authority_ref": "unknown", "state": "INITIALISED"}
                snapshot.ledger = {"state": "UNCONSUMED"}
                snapshot.spool = {"last_stage": "NONE"}
            if code not in ABORT_CODES:
                code = "PROTOCOL_FAILURE"
            stage = self.trace[-1] if self.trace else "BOOT"
            if stage == "CAS_A":
                stage = "RESTORE_BEGIN"
            try:
                self._try_abandon(required=False)
            except Exception:
                pass
            if code in ABORT_CODES and stage in REMOTE.LOCAL_ABORT_STAGES:
                return self._send_abort(snapshot, stage, code, abandon_allowed=True)
            self._terminal = True
            return BridgeResult("FAILURE", code, stage, self._cas_classification, None, None, tuple(self.trace), False)
        finally:
            if self._session is not None:
                try:
                    self._session.close()
                except Exception:
                    pass


def run_controller_bridge(
    store: Any,
    endpoint: EndpointConfig,
    epoch_ref: str,
    barrier_utc: str,
    *,
    session_factory: Callable[[EndpointConfig], Any] | None = None,
    nonce_factory: Callable[[int], bytes] | None = None,
    artifact_stream_commitment: str | None = None,
    test_mode: bool = False,
) -> BridgeResult:
    return ControllerBridge(
        store,
        endpoint,
        epoch_ref,
        barrier_utc,
        session_factory=session_factory,
        nonce_factory=nonce_factory,
        artifact_stream_commitment=artifact_stream_commitment,
        test_mode=test_mode,
    ).run()


__all__ = [
    "ABORT_CODES",
    "CANONICAL_LOCATOR_PACKAGE_ATTESTATION",
    "CANONICAL_LOCATOR_PACKAGE_COMMITMENT",
    "CANONICAL_LOCATOR_SOURCE_COMMITMENT",
    "ControllerBridge",
    "BridgeError",
    "BridgeResult",
    "EndpointAdmissionError",
    "EndpointConfig",
    "FIXED_LOADER_COMMITMENT",
    "FIXED_LOADER_SOURCE",
    "OpenSSHSession",
    "REMOTE",
    "STORE",
    "SWZFRM02_HEADER",
    "build_barrier_commitment",
    "build_restore_transition",
    "build_ssh_argv",
    "run_controller_bridge",
]
