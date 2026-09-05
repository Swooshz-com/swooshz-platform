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
import io
import os
import pathlib
import re
import secrets
import stat
import subprocess
import sys
import threading
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
    expected_keys = (
        "user",
        "uid",
        "gid",
        "login_shell",
        "home",
        "home_uid",
        "home_gid",
        "home_mode",
        "forced_command",
        "ssh_original_command",
        "permit_user_rc",
        "permit_user_environment",
        "accept_env",
        "authorized_key_restriction",
        "startup_policy",
    )
    if not isinstance(value, Mapping) or tuple(value.keys()) != expected_keys:
        raise EndpointAdmissionError("ACCOUNT_BOOTSTRAP_INVALID")
    result = dict(value)
    if (
        result["user"] != RECOVERY_USER
        or type(result["uid"]) is not int
        or result["uid"] < 0
        or type(result["gid"]) is not int
        or result["gid"] < 0
        or result["login_shell"] != RECOVERY_SHELL
        or result["home"] != RECOVERY_HOME
        or result["home_uid"] != 0
        or result["home_gid"] != 0
        or result["home_mode"] != 0o755
        or result["forced_command"] != FORCED_COMMAND
        or result["ssh_original_command"] != ""
        or result["permit_user_rc"] != "no"
        or result["permit_user_environment"] != "no"
        or result["accept_env"] != ""
        or result["authorized_key_restriction"] != "restrict"
        or result["startup_policy"] != "noninteractive-login-shell"
    ):
        raise EndpointAdmissionError("ACCOUNT_BOOTSTRAP_INVALID")
    return result

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
    installation_qualification: Mapping[str, Any] | None = None
    account_bootstrap: Mapping[str, Any] | None = None

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
        if self.account_bootstrap is not None:
            validate_account_bootstrap(self.account_bootstrap)
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


INSTALLATION_QUALIFICATION_FIELDS = ("schema", "files", "account_bootstrap", "effective_config")
INSTALLATION_QUALIFICATION_SCHEMA = "swz-recovery-installation-qualification.v2"


def _file_identity(value: Any) -> tuple[int, int, int, int, int, int]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_size),
        int(value.st_mode),
        int(value.st_uid),
        int(value.st_gid),
    )


def _read_exact_descriptor(
    fd: int,
    *,
    read_fn: Callable[[int, int], bytes] = os.read,
    limit: int = 16 * 1024 * 1024,
) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = read_fn(fd, REMOTE.READ_CHUNK_BYTES)
        if not isinstance(chunk, bytes) or len(chunk) > REMOTE.READ_CHUNK_BYTES:
            raise EndpointAdmissionError("INSTALLATION_FILE_READ_INVALID")
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > limit:
            raise EndpointAdmissionError("INSTALLATION_FILE_OVERSIZE")
        chunks.append(chunk)


def _qualify_installation_file(
    path: str,
    expected: bytes,
    label: str,
    *,
    open_fn: Callable[..., int] = os.open,
    fstat_fn: Callable[[int], Any] = os.fstat,
    read_fn: Callable[[int, int], bytes] = os.read,
    lseek_fn: Callable[[int, int, int], int] = os.lseek,
    close_fn: Callable[[int], Any] = os.close,
) -> dict[str, Any]:
    if sys.platform != "linux":
        raise EndpointAdmissionError("INSTALLATION_NO_FOLLOW_UNAVAILABLE")
    flags = getattr(os, "O_RDONLY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    if not getattr(os, "O_NOFOLLOW", 0):
        raise EndpointAdmissionError("INSTALLATION_NO_FOLLOW_UNAVAILABLE")
    try:
        fd = open_fn(path, flags)
    except (OSError, ValueError) as error:
        raise EndpointAdmissionError(f"{label.upper()}_OPEN_FAILED") from error
    try:
        before_stat = fstat_fn(fd)
        before = _file_identity(before_stat)
        if (
            not stat.S_ISREG(before_stat.st_mode)
            or before_stat.st_uid != 0
            or before_stat.st_gid != 0
            or before_stat.st_mode & (stat.S_ISUID | stat.S_ISGID)
        ):
            raise EndpointAdmissionError(f"{label.upper()}_ADMISSION_FAILED")
        lseek_fn(fd, 0, os.SEEK_SET)
        actual = _read_exact_descriptor(fd, read_fn=read_fn)
        after = _file_identity(fstat_fn(fd))
        if before != after or actual != expected:
            raise EndpointAdmissionError(f"{label.upper()}_SUBSTITUTED")
        return {
            "path": path,
            "bytes_commitment": REMOTE.bytes_commitment(label + "-bytes", actual),
            "identity": before,
            "byte_length": len(actual),
        }
    finally:
        try:
            close_fn(fd)
        except OSError:
            pass


def qualify_endpoint_installation(endpoint: EndpointConfig) -> Mapping[str, Any]:
    if not isinstance(endpoint, EndpointConfig) or not endpoint.installation_owned:
        raise EndpointAdmissionError("INSTALLATION_OWNERSHIP_REQUIRED")
    validate_ssh_effective_readback(endpoint, build_ssh_argv(endpoint))
    account = endpoint.account_bootstrap
    qualification = endpoint.installation_qualification
    if account is None or qualification is None:
        raise EndpointAdmissionError("INSTALLATION_QUALIFICATION_REQUIRED")
    checked_account = validate_account_bootstrap(account)
    if not isinstance(qualification, Mapping) or tuple(qualification.keys()) != INSTALLATION_QUALIFICATION_FIELDS:
        raise EndpointAdmissionError("INSTALLATION_QUALIFICATION_INVALID")
    if qualification["schema"] != INSTALLATION_QUALIFICATION_SCHEMA:
        raise EndpointAdmissionError("INSTALLATION_QUALIFICATION_INVALID")
    effective = validate_effective_ssh_config(qualification["effective_config"])
    if effective != dict(endpoint.effective_config):
        raise EndpointAdmissionError("SSHD_EFFECTIVE_READBACK_MISMATCH")
    files = qualification["files"]
    if not isinstance(files, Mapping):
        raise EndpointAdmissionError("INSTALLATION_FILES_INVALID")
    expected_files = (
        ("ssh_binary", endpoint.ssh_binary, endpoint.ssh_binary_bytes),
        ("identity", endpoint.identity_path, endpoint.client_identity_bytes),
        ("known_hosts", endpoint.known_hosts_path, endpoint.known_hosts_bytes),
        ("authorized_keys", endpoint.authorized_keys_path, endpoint.authorized_keys_bytes),
        ("sshd_config", endpoint.sshd_config_path, endpoint.sshd_config_bytes),
    )
    if tuple(files.keys()) != tuple(item[0] for item in expected_files):
        raise EndpointAdmissionError("INSTALLATION_FILES_INVALID")
    qualified: dict[str, Any] = {}
    for label, path, raw in expected_files:
        declared = files.get(label)
        if not isinstance(declared, Mapping) or tuple(declared.keys()) != ("path", "bytes_commitment", "identity", "byte_length"):
            raise EndpointAdmissionError("INSTALLATION_FILES_INVALID")
        evidence = _qualify_installation_file(path, raw, label)
        declared_identity = declared.get("identity")
        try:
            declared_identity = tuple(int(item) for item in declared_identity)
        except (TypeError, ValueError):
            declared_identity = None
        if (
            declared.get("path") != path
            or
            declared.get("bytes_commitment") != evidence["bytes_commitment"]
            or declared_identity != evidence["identity"]
            or declared.get("byte_length") != len(raw)
        ):
            raise EndpointAdmissionError("INSTALLATION_READBACK_MISMATCH")
        qualified[label] = evidence
    return {
        "schema": INSTALLATION_QUALIFICATION_SCHEMA,
        "files": qualified,
        "account_bootstrap": checked_account,
        "effective_config": effective,
    }


def build_ssh_argv(endpoint: EndpointConfig) -> tuple[str, ...]:
    if not isinstance(endpoint, EndpointConfig):
        raise EndpointAdmissionError("ENDPOINT_INVALID")
    argv = (
        endpoint.ssh_binary,
        "-F",
        "none",
        "-p",
        str(endpoint.port),
        "-o",
        f"IdentityFile={endpoint.identity_path}",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
        "-o",
        "CertificateFile=none",
        "-o",
        "PKCS11Provider=none",
        "-o",
        "GSSAPIAuthentication=no",
        "-o",
        "HostbasedAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "PubkeyAuthentication=yes",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "BatchMode=yes",
        "-o",
        f"UserKnownHostsFile={endpoint.known_hosts_path}",
        "-o",
        "GlobalKnownHostsFile=none",
        "-o",
        "KnownHostsCommand=none",
        "-o",
        "PermitRemoteOpen=none",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "UpdateHostKeys=no",
        "-o",
        "VerifyHostKeyDNS=no",
        "-o",
        "CanonicalizeHostname=no",
        "-o",
        "CanonicalizeFallbackLocal=no",
        "-o",
        "CheckHostIP=no",
        "-o",
        "HashKnownHosts=no",
        "-o",
        "ProxyCommand=none",
        "-o",
        "ProxyJump=none",
        "-o",
        "ProxyUseFdpass=no",
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
        "PermitLocalCommand=no",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPath=none",
        "-o",
        "ControlPersist=no",
        "-o",
        "SessionType=default",
        "-o",
        "EscapeChar=none",
        "-o",
        "StdinNull=no",
        "-o",
        "Compression=no",
        "-o",
        "TCPKeepAlive=no",
        "-o",
        "ConnectionAttempts=1",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "ServerAliveInterval=1",
        "-o",
        "ServerAliveCountMax=3",
        f"{RECOVERY_USER}@{endpoint.host}",
    )
    if any(not isinstance(item, str) or "\x00" in item for item in argv):
        raise EndpointAdmissionError("SSH_ARGV_INVALID")
    return argv


def validate_ssh_effective_readback(endpoint: EndpointConfig, argv: tuple[str, ...]) -> Mapping[str, Any]:
    if not isinstance(endpoint, EndpointConfig) or not isinstance(argv, tuple):
        raise EndpointAdmissionError("SSH_EFFECTIVE_READBACK_INVALID")
    if argv != build_ssh_argv(endpoint):
        raise EndpointAdmissionError("SSH_EFFECTIVE_READBACK_INVALID")
    options: dict[str, str] = {}
    destination: str | None = None
    index = 0
    while index < len(argv):
        item = argv[index]
        if item == endpoint.ssh_binary:
            index += 1
            continue
        if item == "-F" and index + 1 < len(argv):
            if argv[index + 1] != "none":
                raise EndpointAdmissionError("SSH_EFFECTIVE_READBACK_INVALID")
            index += 2
            continue
        if item == "-p" and index + 1 < len(argv):
            if argv[index + 1] != str(endpoint.port):
                raise EndpointAdmissionError("SSH_EFFECTIVE_READBACK_INVALID")
            index += 2
            continue
        if item == "-o" and index + 1 < len(argv):
            option = argv[index + 1]
            if "=" not in option:
                raise EndpointAdmissionError("SSH_EFFECTIVE_READBACK_INVALID")
            name, value = option.split("=", 1)
            if name in options:
                raise EndpointAdmissionError("SSH_EFFECTIVE_READBACK_INVALID")
            options[name] = value
            index += 2
            continue
        if destination is not None or index != len(argv) - 1:
            raise EndpointAdmissionError("SSH_EFFECTIVE_READBACK_INVALID")
        destination = item
        index += 1
    expected_options = {
        "IdentityFile": endpoint.identity_path,
        "IdentitiesOnly": "yes",
        "IdentityAgent": "none",
        "CertificateFile": "none",
        "PKCS11Provider": "none",
        "GSSAPIAuthentication": "no",
        "HostbasedAuthentication": "no",
        "KbdInteractiveAuthentication": "no",
        "PasswordAuthentication": "no",
        "PubkeyAuthentication": "yes",
        "PreferredAuthentications": "publickey",
        "BatchMode": "yes",
        "UserKnownHostsFile": endpoint.known_hosts_path,
        "GlobalKnownHostsFile": "none",
        "KnownHostsCommand": "none",
        "PermitRemoteOpen": "none",
        "StrictHostKeyChecking": "yes",
        "UpdateHostKeys": "no",
        "VerifyHostKeyDNS": "no",
        "CanonicalizeHostname": "no",
        "CanonicalizeFallbackLocal": "no",
        "CheckHostIP": "no",
        "HashKnownHosts": "no",
        "ProxyCommand": "none",
        "ProxyJump": "none",
        "ProxyUseFdpass": "no",
        "ClearAllForwardings": "yes",
        "ForwardAgent": "no",
        "ForwardX11": "no",
        "ForwardX11Trusted": "no",
        "RequestTTY": "no",
        "PermitLocalCommand": "no",
        "ControlMaster": "no",
        "ControlPath": "none",
        "ControlPersist": "no",
        "SessionType": "default",
        "EscapeChar": "none",
        "StdinNull": "no",
        "Compression": "no",
        "TCPKeepAlive": "no",
        "ConnectionAttempts": "1",
        "ConnectTimeout": "5",
        "ServerAliveInterval": "1",
        "ServerAliveCountMax": "3",
    }
    if options != expected_options or destination != f"{RECOVERY_USER}@{endpoint.host}":
        raise EndpointAdmissionError("SSH_EFFECTIVE_READBACK_INVALID")
    if any(name in options for name in ("SendEnv", "SetEnv", "RemoteCommand", "LocalCommand")):
        raise EndpointAdmissionError("SSH_EFFECTIVE_READBACK_INVALID")
    return {"destination": destination, "options": dict(options)}


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


@dataclass(frozen=True)
class SessionFinality:
    process_exit_status: int | None
    stdin_eof: bool
    stdout_eof: bool
    stderr_eof: bool
    trailing_unframed_bytes: int
    stdout_capture_commitment: str
    stderr_capture_commitment: str

    @property
    def observed(self) -> bool:
        return (
            type(self.process_exit_status) is int
            and self.stdin_eof is True
            and self.stdout_eof is True
            and self.stderr_eof is True
            and type(self.trailing_unframed_bytes) is int
            and self.trailing_unframed_bytes >= 0
            and isinstance(self.stdout_capture_commitment, str)
            and REMOTE.COMMITMENT_RE.fullmatch(self.stdout_capture_commitment) is not None
            and isinstance(self.stderr_capture_commitment, str)
            and REMOTE.COMMITMENT_RE.fullmatch(self.stderr_capture_commitment) is not None
        )

    @property
    def success(self) -> bool:
        return self.observed and self.process_exit_status == 0 and self.trailing_unframed_bytes == 0


class OpenSSHSession:
    """One hermetic OpenSSH process with explicit stream and exit finality."""

    def __init__(self, endpoint: EndpointConfig) -> None:
        self.endpoint = endpoint
        self.installation = qualify_endpoint_installation(endpoint)
        argv = build_ssh_argv(endpoint)
        validate_ssh_effective_readback(endpoint, argv)
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
        self._stderr_capture = REMOTE.BoundedCapture(REMOTE.MAX_CAPTURE_BYTES)
        self._stderr_error: Exception | None = None
        self._stderr_eof = False
        self._closed = False
        self._finality: SessionFinality | None = None
        self._stderr_thread = threading.Thread(target=self._drain_stderr, daemon=True)
        self._stderr_thread.start()

    def _drain_stderr(self) -> None:
        try:
            while True:
                chunk = self.stderr.read(REMOTE.READ_CHUNK_BYTES)
                if not chunk:
                    self._stderr_eof = True
                    return
                try:
                    self._stderr_capture.append(bytes(chunk))
                except Exception as error:
                    self._stderr_error = error
        except Exception as error:
            self._stderr_error = error

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

    def finalize(self) -> SessionFinality:
        if self._finality is not None:
            return self._finality
        stdin_eof = False
        try:
            self.stdin.close()
            stdin_eof = True
        except OSError:
            pass
        stdout_capture = REMOTE.BoundedCapture(REMOTE.MAX_CAPTURE_BYTES)
        stdout_error: Exception | None = None
        stdout_eof = False
        trailing = 0

        def drain_stdout() -> None:
            nonlocal stdout_error, stdout_eof, trailing
            try:
                while True:
                    chunk = self.stdout.read(REMOTE.READ_CHUNK_BYTES)
                    if not chunk:
                        stdout_eof = True
                        return
                    trailing += len(chunk)
                    try:
                        stdout_capture.append(bytes(chunk))
                    except Exception as error:
                        if stdout_error is None:
                            stdout_error = error

            except Exception as error:
                stdout_error = error

        stdout_thread = threading.Thread(target=drain_stdout, daemon=True)
        stdout_thread.start()
        wait_error: Exception | None = None
        exit_status: Any = None
        try:
            exit_status = self.process.wait(timeout=17.0)
        except Exception as error:
            wait_error = error
        stdout_thread.join(timeout=2.0)
        self._stderr_thread.join(timeout=2.0)
        if wait_error is not None:
            raise TransportError("SSH_PROCESS_FINALITY_FAILED") from wait_error
        if stdout_thread.is_alive() or not stdout_eof:
            raise TransportError("SSH_STDOUT_FINALITY_FAILED")
        if stdout_error is not None:
            raise TransportError("SSH_STDOUT_CAPTURE_FAILED") from stdout_error
        if self._stderr_thread.is_alive():
            raise TransportError("SSH_STDERR_FINALITY_FAILED")
        if self._stderr_error is not None or not self._stderr_eof:
            raise TransportError("SSH_STDERR_CAPTURE_FAILED")
        stdout_commitment = REMOTE.bytes_commitment(
            "stdout-capture",
            stdout_capture.snapshot(),
        )
        finality = SessionFinality(
            exit_status if type(exit_status) is int else None,
            stdin_eof,
            True,
            self._stderr_eof,
            trailing,
            stdout_commitment,
            REMOTE.bytes_commitment("stderr-capture", self._stderr_capture.snapshot()),
        )
        self._finality = finality
        return finality

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        errors: list[Exception] = []
        if self._finality is None:
            for stream in (self.stdin, self.stdout, self.stderr):
                try:
                    stream.close()
                except OSError as error:
                    errors.append(error)
            try:
                self.process.wait(timeout=1.0)
            except Exception:
                try:
                    self.process.kill()
                except OSError as error:
                    errors.append(error)
                try:
                    self.process.wait(timeout=1.0)
                except Exception as error:
                    errors.append(error)
        else:
            for stream in (self.stdin, self.stdout, self.stderr):
                try:
                    stream.close()
                except OSError as error:
                    errors.append(error)
        if errors:
            raise TransportError("SSH_SESSION_CLOSE_FAILED") from errors[0]


def _validate_discovery(payload: Mapping[str, Any], *, epoch_ref: str, authority_ref: str) -> dict[str, Any]:
    value = REMOTE.validate_wire_payload(payload, "DISCOVERY")
    if value["epoch_ref"] != epoch_ref or value["authority_ref"] != authority_ref:
        raise ProtocolError("DISCOVERY_MISMATCH")
    for field in (
        "image_commitment", "target_commitment", "isolation_commitment",
        "artifact_commitment", "artifact_stream_commitment",
    ):
        _commitment(value[field])
    expected_artifact = STORE.recovery_commitment(
        STORE.DOMAIN_ARTIFACT_ROW,
        str(value["execution_row_id"]),
        value["artifact_filename"],
    )
    if value["artifact_commitment"] != expected_artifact:
        raise ProtocolError("ARTIFACT_BINDING_MISMATCH")
    return value


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
        if not isinstance(epoch_ref, str) or REF_RE.fullmatch(epoch_ref) is None:
            raise StoreIntegrationError("EPOCH_REF_INVALID")
        REMOTE.validate_barrier_utc(barrier_utc)
        if not test_mode and (session_factory is not None or nonce_factory is not None or artifact_stream_commitment is not None):
            raise EndpointAdmissionError("PRODUCTION_TEST_SEAM_FORBIDDEN")
        self.store = store
        self.endpoint = endpoint
        self.epoch_ref = epoch_ref
        self.barrier_utc = barrier_utc
        self.session_factory = session_factory or OpenSSHSession
        self.nonce_factory = nonce_factory or secrets.token_bytes
        self.clock = clock
        self.test_mode = test_mode
        self._session: Any | None = None
        self._n_local: bytes | None = None
        self._sequence = 0
        self._epoch_commitment: str | None = None
        self._cas_classification: str | None = None
        self._cas_consumed = False
        self._restore_begin_durable = False
        self._transition: Transition | None = None
        self._session_finality: SessionFinality | None = None
        self._session_close_checked = False
        self.trace: list[str] = []

    def _new_nonce(self) -> bytes:
        value = self.nonce_factory(32)
        if not isinstance(value, bytes) or len(value) != 32:
            raise TransportError("N_LOCAL_INVALID")
        self._n_local = value
        return value

    def _send(self, message: int, payload: Mapping[str, Any]) -> None:
        if self._session is None or self._n_local is None:
            raise TransportError("SESSION_NOT_OPEN")
        frame = REMOTE.encode_frame(DIRECTION_LOCAL_TO_REMOTE, message, self._sequence, self._n_local, payload)
        self._session.send_frame(frame)
        self._sequence += 1

    def _receive(self, expected: tuple[int, ...]) -> REMOTE.DecodedFrame:
        if self._session is None or self._n_local is None:
            raise TransportError("SESSION_NOT_OPEN")
        frame = self._session.receive_frame()
        if frame is None:
            raise TransportError("SESSION_EOF")
        if frame.sequence != self._sequence or frame.n_local != self._n_local or frame.direction != DIRECTION_REMOTE_TO_LOCAL or frame.message not in expected:
            raise ProtocolError("SESSION_BINDING_INVALID")
        REMOTE.validate_wire_payload(frame.payload, REMOTE.MESSAGE_NAMES[frame.message], n_local=self._n_local if frame.message == MESSAGE_READY else None)
        self._sequence += 1
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
        payload = {
            "type": "ABORT",
            "version": REMOTE.SWZFRM02_VERSION,
            "schema": REMOTE.SCHEMA_WIRE,
            "code": code,
            "stage": stage,
            "direction": "LOCAL_TO_REMOTE",
            "evidence": evidence,
            "evidence_commitment": REMOTE.abort_commitment(evidence),
        }
        try:
            self._send(MESSAGE_ABORT, payload)
            self.trace.append("ABORT")
        except Exception:
            self.trace.append("ABORT_WRITE_FAILED")
        return BridgeResult("FAILURE", code, stage, self._cas_classification, None, evidence, tuple(self.trace), False)

    def _store_pre_cas(self, snapshot: Any, discovery: Mapping[str, Any]) -> tuple[Any, str, str, Transition]:
        try:
            artifact_commitment = self.store.bind_artifact_v2(
                self.epoch_ref,
                discovery["execution_row_id"],
                discovery["artifact_filename"],
            )
            bound = self.store.load_epoch(self.epoch_ref)
            if not isinstance(bound, STORE.V2EpochSnapshot) or bound.record["artifact_commitment"] != artifact_commitment or bound.artifact_binding.artifact_commitment != artifact_commitment:
                raise StoreIntegrationError("STORE_READBACK_FAILED")
            if discovery["artifact_commitment"] != artifact_commitment:
                raise StoreIntegrationError("ARTIFACT_BINDING_MISMATCH")
            self.store.mark_ready(self.epoch_ref)
            _store_frame(self.store, self.epoch_ref, "EPOCH_READY", {"state": "READY"})
            self.store.activate(self.epoch_ref)
            _store_frame(self.store, self.epoch_ref, "RUNNER_STARTED", {"commitment": discovery["image_commitment"], "state": "RUNNER_STARTED"})
            active = self.store.load_epoch(self.epoch_ref)
            if not isinstance(active, STORE.V2EpochSnapshot) or active.record["state"] != "ACTIVE" or active.spool["last_stage"] != "RUNNER_STARTED":
                raise StoreIntegrationError("STORE_READBACK_FAILED")
            transition = build_restore_transition(
                epoch_ref=self.epoch_ref,
                authority_ref=active.record["authority_ref"],
                barrier_utc=self.barrier_utc,
                barrier_commitment=build_barrier_commitment(self.barrier_utc),
                runner_commitment=active.record["runner_commitment"],
                bundle_commitment=self.endpoint.bundle_commitment,
                image_commitment=discovery["image_commitment"],
                target_commitment=discovery["target_commitment"],
                isolation_commitment=discovery["isolation_commitment"],
                artifact_commitment=artifact_commitment,
                artifact_stream_commitment=discovery["artifact_stream_commitment"],
                pre_cas_ledger_digest=self.store.ledger_digest(self.epoch_ref),
            )
            return active, artifact_commitment, discovery["artifact_stream_commitment"], transition
        except StoreIntegrationError:
            raise
        except Exception as error:
            raise StoreIntegrationError("STORE_PRE_CAS_FAILED", safety_state=getattr(error, "safety_state", None)) from error

    def _classify_cas(self, pre_cas: Any, transition: Transition) -> tuple[str, Any | None, str | None]:
        try:
            permit = self.store.consume_restore(
                self.epoch_ref,
                transition.transition_id,
                expected_digest=transition.data["pre_cas_ledger_digest"],
                data=transition.data,
            )
        except Exception as error:
            current = None
            try:
                current = self.store.load_epoch(self.epoch_ref)
            except Exception:
                self._cas_classification = "C"
                return "C", None, "CAS_UNCERTAIN"
            exact_b = (
                isinstance(error, STORE.LedgerError)
                and getattr(error, "code", None) in {"CAS_MISMATCH", "EPOCH_NOT_ACTIVE", "RESTORE_PRECONDITION_FAILED"}
                and getattr(error, "safety_state", None) == "UNCONSUMED"
                and _snapshot_matches_pre_cas(current, expected=pre_cas)
            )
            self._cas_classification = "B" if exact_b else "C"
            return ("B", current, "CAS_REJECTED_UNCONSUMED") if exact_b else ("C", current, "CAS_UNCERTAIN")
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
        self._cas_consumed = True
        return "A", current, self.store.record_digest(self.epoch_ref)

    def _finalize_session(self) -> SessionFinality:
        if self._session_finality is not None:
            return self._session_finality
        if self._session is None or not callable(getattr(self._session, "finalize", None)):
            raise TransportError("SESSION_FINALITY_UNAVAILABLE")
        value = self._session.finalize()
        if not isinstance(value, SessionFinality):
            raise TransportError("SESSION_FINALITY_INVALID")
        self._session_finality = value
        return value

    def _close_session_after_finality(self) -> None:
        if self._session is None or self._session_close_checked:
            return
        try:
            self._session.close()
        except Exception as error:
            raise TransportError("SSH_SESSION_CLOSE_FAILED") from error
        self._session_close_checked = True

    def _abandon_and_verify(self, expected_ledger_state: str) -> Any:
        try:
            self.store.abandon(self.epoch_ref)
            current = self.store.load_epoch(self.epoch_ref)
        except Exception as error:
            raise StoreIntegrationError("ABANDON_FINALITY_UNCERTAIN", safety_state="CONSUMED") from error
        if not isinstance(current, STORE.V2EpochSnapshot):
            raise StoreIntegrationError("ABANDON_FINALITY_UNCERTAIN", safety_state="CONSUMED")
        if (
            current.record["state"] != "ABANDONED"
            or current.record["restore_ledger_state"] != expected_ledger_state
            or current.manifest["state"] != "ABANDONED"
            or current.manifest["restore_ledger_state"] != expected_ledger_state
            or current.ledger["state"] != expected_ledger_state
            or current.spool["state"] != "ABANDONED"
            or current.spool["last_stage"] != "ABANDON"
        ):
            raise StoreIntegrationError("ABANDON_FINALITY_UNCERTAIN", safety_state="CONSUMED")
        return current

    def run(self) -> BridgeResult:
        snapshot: Any | None = None
        try:
            snapshot = self.store.load_epoch(self.epoch_ref)
            if not _snapshot_is_initial(snapshot):
                raise StoreIntegrationError("STORE_STATE_INVALID")
            if not self.test_mode:
                qualify_endpoint_installation(self.endpoint)
            self._new_nonce()
            self.trace.append("BOOT")
            self._session = self.session_factory(self.endpoint)
            if self._session is None:
                raise TransportError("SSH_SESSION_OPEN_FAILED")
            self._epoch_commitment = self.store.record_digest(self.epoch_ref)
            boot = _build_boot(
                n_local=self._n_local,
                epoch_ref=self.epoch_ref,
                authority_ref=snapshot.record["authority_ref"],
                barrier_utc=self.barrier_utc,
                epoch_commitment=self._epoch_commitment,
                runner_commitment=snapshot.record["runner_commitment"],
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
                try:
                    current = self._abandon_and_verify("UNCONSUMED")
                except Exception:
                    self._cas_classification = "C"
                    self.trace.append("CAS_C")
                    self._terminal = True
                    return BridgeResult("FAILURE", "CAS_UNCERTAIN", "POST_CAS", "C", None, None, tuple(self.trace), False)
                self.trace.append("ABANDON")
                return self._send_abort(current, "CAS_B", "CAS_REJECTED_UNCONSUMED", abandon_allowed=True)
            if classification == "C":
                self.trace.append("CAS_C")
                self._terminal = True
                return BridgeResult("FAILURE", "CAS_UNCERTAIN", "PRE_CAS", "C", None, None, tuple(self.trace), False)
            self.trace.append("CAS_A")
            before_restore_begin = self.store.load_epoch(self.epoch_ref)
            ledger_after_digest = self.store.ledger_digest(self.epoch_ref)
            _store_frame(self.store, self.epoch_ref, "RESTORE_BEGIN", {"ref": transition.transition_id, "commitment": transition.data_commitment})
            durable_snapshot = self.store.load_epoch(self.epoch_ref)
            if durable_snapshot.spool["last_stage"] != "RESTORE_BEGIN" or durable_snapshot.ledger["state"] != "CONSUMED":
                raise StoreIntegrationError("RESTORE_BEGIN_NOT_DURABLE", safety_state="CONSUMED")
            self._restore_begin_durable = True
            restore_begin = _build_restore_begin_evidence(
                previous_snapshot=before_restore_begin,
                snapshot=durable_snapshot,
                transition=transition,
                artifact_commitment=artifact_commitment,
                artifact_stream_commitment=artifact_stream_commitment,
                ledger_after_digest=ledger_after_digest,
            )
            restore_begin_commitment = REMOTE.bytes_commitment("restore-begin-evidence", REMOTE.canonical_json(restore_begin, terminal_lf=True))
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
                restore_begin_commitment=restore_begin_commitment,
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
            expected_result_commitment = REMOTE.result_commitment(evidence)
            if result_frame.payload["result_commitment"] != expected_result_commitment:
                raise ProtocolError("RESULT_COMMITMENT_INVALID")
            self.trace.append("RESULT")
            local_finality = self._finalize_session()
            if not local_finality.observed:
                raise TransportError("SESSION_FINALITY_INCOMPLETE")
            remote_deterministic = (
                evidence["stdin_eof"] is True
                and evidence["stdout_eof"] is True
                and evidence["stderr_eof"] is True
                and evidence["trailing_unframed_bytes"] == 0
                and evidence["cleanup_state"] == "COMPLETE"
            )
            if not remote_deterministic or (evidence["classification"] == "SUCCESS" and not local_finality.success):
                raise TransportError("POST_CAS_FINALITY_UNCERTAIN")
            self._close_session_after_finality()
            if evidence["classification"] == "FAILURE":
                if self.test_mode:
                    return BridgeResult("FAILURE", evidence["result_code"], "RESULT", "A", evidence, None, tuple(self.trace), True)
                self._abandon_and_verify("CONSUMED")
                self.trace.append("ABANDON")
                return BridgeResult("FAILURE", evidence["result_code"], "RESULT", "A", evidence, None, tuple(self.trace), True)
            if self.test_mode:
                raise TransportError("TEST_SUCCESS_NOT_OPERATIONAL")
            _store_frame(self.store, self.epoch_ref, "COMMIT", {"classification": "SUCCESS", "commitment": expected_result_commitment})
            self.trace.extend(("COMMIT", "FINAL"))
            return BridgeResult("SUCCESS", "RESTORE_SUCCEEDED", "COMMIT", "A", evidence, None, tuple(self.trace), True)
        except Exception as error:
            code = getattr(error, "code", "PROTOCOL_FAILURE")
            if self._cas_classification == "C" or self._cas_consumed or self._restore_begin_durable:
                self._cas_classification = "C"
                self.trace.append("CAS_C") if not self.trace or self.trace[-1] != "CAS_C" else None
                return BridgeResult("FAILURE", "CAS_UNCERTAIN", "POST_CAS", "C", None, None, tuple(self.trace), False)
            if code == "REMOTE_ABORT":
                code = "RESTORE_FAILED"
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
                snapshot = self._abandon_and_verify("UNCONSUMED")
                self.trace.append("ABANDON")
                abandoned = True
            except Exception:
                self._cas_classification = "C"
                self.trace.append("CAS_C")
                self._terminal = True
                return BridgeResult("FAILURE", "CAS_UNCERTAIN", "POST_CAS", "C", None, None, tuple(self.trace), False)
            if code in ABORT_CODES and stage in REMOTE.LOCAL_ABORT_STAGES:
                return self._send_abort(snapshot, stage, code, abandon_allowed=abandoned)
            return BridgeResult("FAILURE", code, stage, self._cas_classification, None, None, tuple(self.trace), False)
        finally:
            if self._session is not None and not self._session_close_checked:
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
