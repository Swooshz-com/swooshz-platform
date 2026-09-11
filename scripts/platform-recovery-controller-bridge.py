#!/usr/bin/env python3
"""Local controller for the single-active SWZFRM02 recovery session.

The controller binds a fresh nonce and the durable Store V2 transition before
it can issue PROCEED.  PROCEED is a one-shot consumed boundary: the only
legal next local action is one successful SSH stdin half-close, after which
the controller observes RESULT or ABORT.  A failed or ambiguous boundary is
sticky consumed uncertainty.
"""

from __future__ import annotations

import dataclasses
import hashlib
import importlib.util
import os
import pathlib
import re
import secrets
import stat
import subprocess
import sys
import threading
import time
import types
from dataclasses import dataclass
from typing import Any, Callable, Mapping

try:
    import pwd
except ImportError:  # pragma: no cover
    pwd = None


def _load_module(name: str, path: pathlib.Path) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"{name} unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


REMOTE = _load_module("platform_recovery_remote_agent_bridge_v2", pathlib.Path(__file__).with_name("platform-recovery-remote-agent.py"))
STORE = _load_module("platform_recovery_controller_store_bridge_v2", pathlib.Path(__file__).with_name("platform-recovery-controller-store.py"))

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
MAX_EFFECTIVE_CONFIG_BYTES = 65536

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

ENDPOINT_FIELDS = (
    "schema", "host", "port", "user", "ssh_binary", "identity_path",
    "known_hosts_path", "authorized_keys_path", "sshd_config_path",
    "forced_command", "sshd_effective_config_commitment",
    "connect_timeout_seconds", "server_alive_interval_seconds",
    "server_alive_count_max", "session_type", "ssh_binary_bytes_commitment",
    "known_hosts_bytes_commitment", "authorized_keys_commitment",
    "sshd_config_bytes_commitment", "loader_commitment", "launcher_commitment",
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
    "user", "forcecommand", "disableforwarding", "allowagentforwarding",
    "allowtcpforwarding", "allowstreamlocalforwarding", "x11forwarding",
    "permittty", "permittunnel", "gatewayports", "permituserenvironment",
    "permitopen", "permitlisten", "maxsessions", "acceptenv",
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
    "schema", "version", "epoch_ref", "authority_ref", "barrier_utc",
    "barrier_commitment", "runner_commitment", "bundle_commitment",
    "image_commitment", "target_commitment", "isolation_commitment",
    "artifact_commitment", "artifact_stream_commitment", "pre_cas_ledger_digest",
)
TRANSITION_SCHEMA = "restore-ledger-transition-data.v2"
TRANSITION_VERSION = 2
RESTORE_BEGIN_FIELDS = (
    "schema", "epoch_ref", "transition_id", "transition_data_commitment",
    "artifact_commitment", "artifact_stream_commitment", "ledger_state",
    "record_state", "spool_previous_stage", "frame_sequence", "previous_frame_hash",
    "frame_hash", "spool_commitment", "ledger_after_digest", "durability",
)
RESTORE_BEGIN_SCHEMA = "restore-begin-evidence.v2"
INSTALLATION_QUALIFICATION_FIELDS = ("schema", "files", "account_bootstrap", "effective_config")
INSTALLATION_QUALIFICATION_SCHEMA = "swz-recovery-installation-qualification.v2"

ABORT_CODES = {
    "SSH_SERVER_ADMISSION_FAILED", "LAUNCHER_COMMITMENT_MISMATCH", "AGENT_COMMITMENT_MISMATCH", "PACKAGE_DRIFT", "LOADER_REJECTED", "BOOT_INVALID", "SESSION_BINDING_INVALID", "READY_INVALID", "READY_MISMATCH", "DISCOVERY_INVALID", "LOCATOR_NOT_FOUND", "LOCATOR_AMBIGUOUS", "IMAGE_ADMISSION_FAILED", "TARGET_ISOLATION_FAILED", "STORE_STATE_INVALID", "ARTIFACT_BIND_FAILED", "STORE_READBACK_FAILED", "CAS_REJECTED_UNCONSUMED", "RESTORE_BEGIN_NOT_DURABLE", "PROCEED_INVALID", "RESTORE_FAILED", "CLEANUP_FAILED", "PROCESS_FAILED",
}
UNSET_COMMITMENT = REMOTE.bytes_commitment("unset", b"")


class BridgeError(RuntimeError):
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
    is_windows_absolute = isinstance(value, str) and len(value) >= 3 and value[1] == ":" and value[2] in {"/", "\\"}
    if not isinstance(value, str) or (not value.startswith("/") and not is_windows_absolute) or "\x00" in value or value.endswith(("/", "\\")):
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
    if any(token in lines[0] for token in ("*", "?", "!", "|", "@cert-authority", "@revoked", "#")):
        raise EndpointAdmissionError("KNOWN_HOSTS_INVALID")
    if len(lines[0].split()) != 3:
        raise EndpointAdmissionError("KNOWN_HOSTS_INVALID")


def _validate_authorized_keys(raw: bytes) -> None:
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise EndpointAdmissionError("AUTHORIZED_KEYS_INVALID") from error
    lines = text.splitlines()
    prefix = f'command="{FORCED_COMMAND}",restrict '
    if len(lines) != 1 or not text.endswith("\n") or not lines[0].startswith(prefix):
        raise EndpointAdmissionError("AUTHORIZED_KEYS_INVALID")
    parts = lines[0][len(prefix):].split()
    if len(parts) != 2 or not parts[0].startswith("ssh-") or any(ch in lines[0] for ch in ("\r", "\x00")):
        raise EndpointAdmissionError("AUTHORIZED_KEYS_INVALID")


def validate_account_bootstrap(value: Mapping[str, Any]) -> dict[str, Any]:
    fields = ("user", "uid", "gid", "login_shell", "home", "home_uid", "home_gid", "home_mode", "forced_command", "ssh_original_command", "permit_user_rc", "permit_user_environment", "accept_env", "authorized_key_restriction", "startup_policy")
    if not isinstance(value, Mapping) or tuple(value.keys()) != fields:
        raise EndpointAdmissionError("ACCOUNT_BOOTSTRAP_INVALID")
    expected = {"user": RECOVERY_USER, "login_shell": RECOVERY_SHELL, "home": RECOVERY_HOME, "home_uid": 0, "home_gid": 0, "home_mode": 0o755, "forced_command": FORCED_COMMAND, "ssh_original_command": "", "permit_user_rc": "no", "permit_user_environment": "no", "accept_env": "", "authorized_key_restriction": "restrict", "startup_policy": "noninteractive-login-shell"}
    if any(value.get(key) != expected_value for key, expected_value in expected.items()) or type(value["uid"]) is not int or value["uid"] < 0 or type(value["gid"]) is not int or value["gid"] < 0:
        raise EndpointAdmissionError("ACCOUNT_BOOTSTRAP_INVALID")
    return dict(value)


def read_local_account_bootstrap(*, getpwnam_fn: Callable[[str], Any] | None = None, lstat_fn: Callable[[str], Any] = os.lstat, realpath_fn: Callable[[str], str] = os.path.realpath) -> dict[str, Any]:
    selected = getpwnam_fn
    if selected is None:
        if pwd is None:
            raise EndpointAdmissionError("ACCOUNT_BOOTSTRAP_READBACK_UNAVAILABLE")
        selected = pwd.getpwnam
    try:
        account = selected(RECOVERY_USER)
        home = lstat_fn(RECOVERY_HOME)
        shell_entry = lstat_fn(RECOVERY_SHELL)
        interpreter_path = realpath_fn(RECOVERY_SHELL)
        _validate_safe_path_components(RECOVERY_HOME, "account_home", lstat_fn=lstat_fn)
        _validate_safe_path_components(interpreter_path, "interpreter", lstat_fn=lstat_fn)
        interpreter = lstat_fn(interpreter_path)
    except (KeyError, OSError, ValueError, TypeError) as error:
        raise EndpointAdmissionError("ACCOUNT_BOOTSTRAP_READBACK_FAILED") from error
    mode = int(shell_entry.st_mode)
    if account.pw_name != RECOVERY_USER or account.pw_dir != RECOVERY_HOME or account.pw_shell != RECOVERY_SHELL:
        raise EndpointAdmissionError("ACCOUNT_BOOTSTRAP_READBACK_MISMATCH")
    if not stat.S_ISDIR(home.st_mode) or int(home.st_uid) != 0 or int(home.st_gid) != 0 or stat.S_IMODE(home.st_mode) != 0o755 or int(shell_entry.st_uid) != 0 or int(shell_entry.st_gid) != 0 or (not stat.S_ISLNK(mode) and (mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID))) or (not stat.S_ISLNK(mode) and not stat.S_ISREG(mode)) or not stat.S_ISREG(interpreter.st_mode) or int(interpreter.st_uid) != 0 or int(interpreter.st_gid) != 0 or int(interpreter.st_mode) & (stat.S_IWGRP | stat.S_IWOTH) or not int(interpreter.st_mode) & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        raise EndpointAdmissionError("ACCOUNT_BOOTSTRAP_UNSAFE")
    return validate_account_bootstrap({"user": RECOVERY_USER, "uid": int(account.pw_uid), "gid": int(account.pw_gid), "login_shell": RECOVERY_SHELL, "home": RECOVERY_HOME, "home_uid": int(home.st_uid), "home_gid": int(home.st_gid), "home_mode": stat.S_IMODE(home.st_mode), "forced_command": FORCED_COMMAND, "ssh_original_command": "", "permit_user_rc": "no", "permit_user_environment": "no", "accept_env": "", "authorized_key_restriction": "restrict", "startup_policy": "noninteractive-login-shell"})


def validate_effective_ssh_config(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or tuple(value.keys()) != EFFECTIVE_SSH_FIELDS or dict(value) != EXPECTED_EFFECTIVE_SSH:
        raise EndpointAdmissionError("SSHD_EFFECTIVE_VALUES_INVALID")
    return dict(value)


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
        for value, label in ((self.ssh_binary, "ssh_binary"), (self.identity_path, "identity_path"), (self.known_hosts_path, "known_hosts_path"), (self.authorized_keys_path, "authorized_keys_path"), (self.sshd_config_path, "sshd_config_path")):
            _strict_absolute_path(value, label)
        if self.installation_owned is not True or self.login_shell != RECOVERY_SHELL or self.home != RECOVERY_HOME:
            raise EndpointAdmissionError("INSTALLATION_OWNERSHIP_REQUIRED")
        if self.account_bootstrap is not None:
            validate_account_bootstrap(self.account_bootstrap)
        _strict_bytes(self.known_hosts_bytes, "known_hosts_bytes", maximum=65536)
        _strict_bytes(self.authorized_keys_bytes, "authorized_keys_bytes", maximum=65536)
        _strict_bytes(self.sshd_config_bytes, "sshd_config_bytes")
        _strict_bytes(self.ssh_binary_bytes, "ssh_binary_bytes", maximum=16 << 20)
        _strict_bytes(self.client_identity_bytes, "client_identity_bytes")
        _validate_known_hosts(self.known_hosts_bytes)
        _validate_authorized_keys(self.authorized_keys_bytes)
        validate_effective_ssh_config(self.effective_config)
        for value, label in ((self.loader_commitment, "loader_commitment"), (self.launcher_commitment, "launcher_commitment"), (self.agent_commitment, "agent_commitment")):
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
        return REMOTE.bytes_commitment("sshd-effective-config", REMOTE.canonical_json(dict(self.effective_config), terminal_lf=True))

    @property
    def endpoint_object(self) -> dict[str, Any]:
        value = {"schema": ENDPOINT_SCHEMA, "host": self.host, "port": self.port, "user": RECOVERY_USER, "ssh_binary": self.ssh_binary, "identity_path": self.identity_path, "known_hosts_path": self.known_hosts_path, "authorized_keys_path": self.authorized_keys_path, "sshd_config_path": self.sshd_config_path, "forced_command": FORCED_COMMAND, "sshd_effective_config_commitment": self.sshd_effective_config_commitment, "connect_timeout_seconds": CONNECT_TIMEOUT_SECONDS, "server_alive_interval_seconds": SERVER_ALIVE_INTERVAL_SECONDS, "server_alive_count_max": SERVER_ALIVE_COUNT_MAX, "session_type": SESSION_TYPE, "ssh_binary_bytes_commitment": self.ssh_binary_bytes_commitment, "known_hosts_bytes_commitment": self.known_hosts_bytes_commitment, "authorized_keys_commitment": self.authorized_keys_commitment, "sshd_config_bytes_commitment": self.sshd_config_bytes_commitment, "loader_commitment": self.loader_commitment, "launcher_commitment": self.launcher_commitment, "agent_commitment": self.agent_commitment}
        if tuple(value.keys()) != ENDPOINT_FIELDS:
            raise EndpointAdmissionError("ENDPOINT_FIELDS_INVALID")
        return value

    @property
    def endpoint_commitment(self) -> str:
        return REMOTE.bytes_commitment("ssh-endpoint", REMOTE.canonical_json(self.endpoint_object, terminal_lf=True))


def _file_identity(value: Any) -> tuple[int, int, int, int, int, int]:
    return (int(value.st_dev), int(value.st_ino), int(value.st_size), int(value.st_mode), int(value.st_uid), int(value.st_gid))


def _validate_safe_path_components(path: str, label: str, *, lstat_fn: Callable[[str], Any] = os.lstat) -> None:
    if not isinstance(path, str) or not path.startswith("/") or "\x00" in path:
        raise EndpointAdmissionError(f"{label.upper()}_PATH_INVALID")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts[1:]):
        raise EndpointAdmissionError(f"{label.upper()}_PATH_INVALID")
    current = ""
    for index, part in enumerate(parts[1:], start=1):
        current += "/" + part
        try:
            metadata = lstat_fn(current)
        except (OSError, ValueError) as error:
            raise EndpointAdmissionError(f"{label.upper()}_PATH_READBACK_FAILED") from error
        mode = int(metadata.st_mode)
        if stat.S_ISLNK(mode) or int(metadata.st_uid) != 0 or int(metadata.st_gid) != 0 or mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID):
            raise EndpointAdmissionError(f"{label.upper()}_PATH_UNSAFE")
        if index < len(parts) - 1 and not stat.S_ISDIR(mode):
            raise EndpointAdmissionError(f"{label.upper()}_PATH_UNSAFE")


def _read_exact_descriptor(fd: int, *, read_fn: Callable[[int, int], bytes] = os.read, limit: int = 16 * 1024 * 1024) -> bytes:
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


def _qualify_installation_file(path: str, expected: bytes, label: str, *, open_fn: Callable[..., int] = os.open, fstat_fn: Callable[[int], Any] = os.fstat, read_fn: Callable[[int, int], bytes] = os.read, lseek_fn: Callable[[int, int, int], int] = os.lseek, close_fn: Callable[[int], Any] = os.close, lstat_fn: Callable[[str], Any] = os.lstat) -> dict[str, Any]:
    if sys.platform != "linux" or not getattr(os, "O_NOFOLLOW", 0):
        raise EndpointAdmissionError("INSTALLATION_NO_FOLLOW_UNAVAILABLE")
    _validate_safe_path_components(path, label, lstat_fn=lstat_fn)
    try:
        fd = open_fn(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW)
    except (OSError, ValueError) as error:
        raise EndpointAdmissionError(f"{label.upper()}_OPEN_FAILED") from error
    try:
        before_stat = fstat_fn(fd)
        before = _file_identity(before_stat)
        mode = int(before_stat.st_mode)
        if not stat.S_ISREG(mode) or int(before_stat.st_uid) != 0 or int(before_stat.st_gid) != 0 or mode & (stat.S_ISUID | stat.S_ISGID | stat.S_IWGRP | stat.S_IWOTH) or (label == "ssh_binary" and not mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)) or (label == "identity" and stat.S_IMODE(mode) & 0o077):
            raise EndpointAdmissionError(f"{label.upper()}_ADMISSION_FAILED")
        lseek_fn(fd, 0, os.SEEK_SET)
        actual = _read_exact_descriptor(fd, read_fn=read_fn)
        after = _file_identity(fstat_fn(fd))
        if before != after or actual != expected:
            raise EndpointAdmissionError(f"{label.upper()}_SUBSTITUTED")
        return {"path": path, "bytes_commitment": REMOTE.bytes_commitment(label + "-bytes", actual), "identity": before, "byte_length": len(actual)}
    finally:
        try:
            close_fn(fd)
        except OSError:
            pass


def _verify_bound_installation_files(endpoint: EndpointConfig, admitted: Mapping[str, Any]) -> None:
    files = admitted.get("files") if isinstance(admitted, Mapping) else None
    if not isinstance(files, Mapping):
        raise EndpointAdmissionError("INSTALLATION_FILES_INVALID")
    expected = (("ssh_binary", endpoint.ssh_binary, endpoint.ssh_binary_bytes), ("identity", endpoint.identity_path, endpoint.client_identity_bytes), ("known_hosts", endpoint.known_hosts_path, endpoint.known_hosts_bytes), ("authorized_keys", endpoint.authorized_keys_path, endpoint.authorized_keys_bytes), ("sshd_config", endpoint.sshd_config_path, endpoint.sshd_config_bytes))
    for label, path, raw in expected:
        current = _qualify_installation_file(path, raw, label)
        declared = files.get(label)
        if not isinstance(declared, Mapping) or declared.get("path") != current["path"] or declared.get("bytes_commitment") != current["bytes_commitment"] or tuple(declared.get("identity", ())) != current["identity"] or declared.get("byte_length") != current["byte_length"]:
            raise EndpointAdmissionError("INSTALLATION_READBACK_MISMATCH")


def qualify_endpoint_installation(endpoint: EndpointConfig) -> Mapping[str, Any]:
    """Admit account, paths and all bytes before the first ``ssh -G``."""
    if not isinstance(endpoint, EndpointConfig) or endpoint.installation_owned is not True:
        raise EndpointAdmissionError("INSTALLATION_OWNERSHIP_REQUIRED")

    # This ordering is intentional and regression-tested.  None of these
    # operations starts an SSH process or invokes an SSH executable.
    observed_account = read_local_account_bootstrap()
    if endpoint.account_bootstrap is not None and validate_account_bootstrap(endpoint.account_bootstrap) != observed_account:
        raise EndpointAdmissionError("ACCOUNT_BOOTSTRAP_READBACK_MISMATCH")
    expected = (("ssh_binary", endpoint.ssh_binary, endpoint.ssh_binary_bytes), ("identity", endpoint.identity_path, endpoint.client_identity_bytes), ("known_hosts", endpoint.known_hosts_path, endpoint.known_hosts_bytes), ("authorized_keys", endpoint.authorized_keys_path, endpoint.authorized_keys_bytes), ("sshd_config", endpoint.sshd_config_path, endpoint.sshd_config_bytes))
    qualified_files = {label: _qualify_installation_file(path, raw, label) for label, path, raw in expected}
    qualification = endpoint.installation_qualification
    if qualification is not None:
        if tuple(qualification.keys()) != INSTALLATION_QUALIFICATION_FIELDS or qualification.get("schema") != INSTALLATION_QUALIFICATION_SCHEMA:
            raise EndpointAdmissionError("INSTALLATION_QUALIFICATION_INVALID")
        if validate_account_bootstrap(qualification["account_bootstrap"]) != observed_account or validate_effective_ssh_config(qualification["effective_config"]) != dict(endpoint.effective_config):
            raise EndpointAdmissionError("INSTALLATION_READBACK_MISMATCH")
        declared = qualification["files"]
        if not isinstance(declared, Mapping) or tuple(declared.keys()) != tuple(item[0] for item in expected):
            raise EndpointAdmissionError("INSTALLATION_FILES_INVALID")
        for label in qualified_files:
            item = declared[label]
            if not isinstance(item, Mapping) or item.get("path") != qualified_files[label]["path"] or item.get("bytes_commitment") != qualified_files[label]["bytes_commitment"] or tuple(item.get("identity", ())) != qualified_files[label]["identity"] or item.get("byte_length") != qualified_files[label]["byte_length"]:
                raise EndpointAdmissionError("INSTALLATION_READBACK_MISMATCH")
    argv = build_ssh_argv(endpoint)
    effective = validate_ssh_effective_readback(endpoint, argv)
    # The effective readback is itself guarded by a fresh identity check.
    _verify_bound_installation_files(endpoint, {"files": qualified_files})
    after_account = read_local_account_bootstrap()
    if after_account != observed_account:
        raise EndpointAdmissionError("ACCOUNT_BOOTSTRAP_DRIFT")
    return {"schema": INSTALLATION_QUALIFICATION_SCHEMA, "files": qualified_files, "account_bootstrap": observed_account, "effective_config": dict(endpoint.effective_config), "effective_readback": effective}


def build_ssh_argv(endpoint: EndpointConfig) -> tuple[str, ...]:
    if not isinstance(endpoint, EndpointConfig):
        raise EndpointAdmissionError("ENDPOINT_INVALID")
    options = ("IdentitiesOnly=yes", "IdentityAgent=none", "CertificateFile=none", "PKCS11Provider=none", "GSSAPIAuthentication=no", "HostbasedAuthentication=no", "KbdInteractiveAuthentication=no", "PasswordAuthentication=no", "PubkeyAuthentication=yes", "PreferredAuthentications=publickey", "BatchMode=yes", f"UserKnownHostsFile={endpoint.known_hosts_path}", "GlobalKnownHostsFile=none", "KnownHostsCommand=none", "PermitRemoteOpen=none", "StrictHostKeyChecking=yes", "UpdateHostKeys=no", "VerifyHostKeyDNS=no", "CanonicalizeHostname=no", "CanonicalizeFallbackLocal=no", "CheckHostIP=no", "HashKnownHosts=no", "ProxyCommand=none", "ProxyJump=none", "ProxyUseFdpass=no", "ClearAllForwardings=yes", "ForwardAgent=no", "ForwardX11=no", "ForwardX11Trusted=no", "RequestTTY=no", "PermitLocalCommand=no", "ControlMaster=no", "ControlPath=none", "ControlPersist=no", "SessionType=default", "EscapeChar=none", "StdinNull=no", "Compression=no", "TCPKeepAlive=no", "ConnectionAttempts=1", "ConnectTimeout=5", "ServerAliveInterval=1", "ServerAliveCountMax=3")
    argv: tuple[str, ...] = (endpoint.ssh_binary, "-F", "none", "-p", str(endpoint.port), "-o", f"IdentityFile={endpoint.identity_path}") + tuple(item for option in options for item in ("-o", option)) + (f"{RECOVERY_USER}@{endpoint.host}",)
    if any(not isinstance(item, str) or "\x00" in item for item in argv):
        raise EndpointAdmissionError("SSH_ARGV_INVALID")
    return argv


def _parse_ssh_effective_output(raw: bytes) -> Mapping[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_EFFECTIVE_CONFIG_BYTES:
        raise EndpointAdmissionError("SSH_EFFECTIVE_OUTPUT_INVALID")
    try:
        text = raw.decode("ascii", "strict")
    except UnicodeDecodeError as error:
        raise EndpointAdmissionError("SSH_EFFECTIVE_OUTPUT_INVALID") from error
    observed: dict[str, Any] = {}
    for line in text.splitlines():
        if not line or " " not in line:
            continue
        name, value = line.split(None, 1)
        name = name.lower()
        if name == "identityfile":
            observed.setdefault(name, []).append(value)
        elif name in observed:
            raise EndpointAdmissionError("SSH_EFFECTIVE_OUTPUT_DUPLICATE")
        else:
            observed[name] = value
    if not observed:
        raise EndpointAdmissionError("SSH_EFFECTIVE_OUTPUT_INVALID")
    return observed


def _ssh_readback_environment() -> dict[str, str]:
    # The readback environment is explicit and does not inherit auth or proxy
    # material.  PATH is retained only to let the admitted executable resolve
    # its own helper libraries on a local test host.
    value = {"LANG": "C", "LC_ALL": "C"}
    if os.name != "nt" and os.environ.get("PATH") is not None:
        value["PATH"] = os.environ["PATH"]
    return value


def read_ssh_effective_config(endpoint: EndpointConfig, argv: tuple[str, ...], *, run_fn: Callable[..., Any] = subprocess.run) -> Mapping[str, Any]:
    if not isinstance(endpoint, EndpointConfig) or not isinstance(argv, tuple):
        raise EndpointAdmissionError("SSH_EFFECTIVE_READBACK_INVALID")
    readback_argv = (argv[0], "-G", *argv[1:])
    try:
        completed = run_fn(list(readback_argv), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=5.0, env=_ssh_readback_environment())
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise EndpointAdmissionError("SSH_EFFECTIVE_READBACK_FAILED") from error
    if getattr(completed, "returncode", None) != 0:
        raise EndpointAdmissionError("SSH_EFFECTIVE_READBACK_FAILED")
    observed = _parse_ssh_effective_output(getattr(completed, "stdout", b""))
    expected: dict[str, Any] = {"user": RECOVERY_USER, "hostname": endpoint.host, "port": str(endpoint.port), "identityfile": [endpoint.identity_path], "identitiesonly": "yes", "identityagent": "none", "certificatefile": "none", "pkcs11provider": "none", "gssapiauthentication": "no", "hostbasedauthentication": "no", "kbdinteractiveauthentication": "no", "passwordauthentication": "no", "pubkeyauthentication": {"yes", "true"}, "preferredauthentications": "publickey", "batchmode": "yes", "userknownhostsfile": endpoint.known_hosts_path, "globalknownhostsfile": "none", "knownhostscommand": "none", "permitremoteopen": "none", "stricthostkeychecking": {"yes", "true"}, "updatehostkeys": {"no", "false"}, "verifyhostkeydns": {"no", "false"}, "canonicalizehostname": {"no", "false"}, "canonicalizefallbacklocal": "no", "checkhostip": "no", "hashknownhosts": "no", "proxycommand": "none", "proxyjump": "none", "proxyusefdpass": "no", "clearallforwardings": "yes", "forwardagent": "no", "forwardx11": "no", "forwardx11trusted": "no", "requesttty": {"no", "false"}, "permitlocalcommand": "no", "controlmaster": {"no", "false"}, "controlpath": "none", "controlpersist": "no", "sessiontype": "default", "escapechar": "none", "stdinnull": {"no", "false"}, "compression": "no", "tcpkeepalive": "no", "connectionattempts": "1", "connecttimeout": "5", "serveraliveinterval": "1", "serveralivecountmax": "3"}
    optional = {"pkcs11provider", "knownhostscommand", "proxycommand", "proxyjump", "controlpath"}
    for name, expected_value in expected.items():
        actual = observed.get(name)
        if actual is None and name in optional:
            continue
        if isinstance(expected_value, set):
            matches = actual in expected_value
        else:
            matches = actual == expected_value
        if not matches:
            raise EndpointAdmissionError("SSH_EFFECTIVE_READBACK_MISMATCH")
    return {"argv": readback_argv, "values": dict(observed)}


def validate_ssh_effective_readback(endpoint: EndpointConfig, argv: tuple[str, ...], *, observed_output: bytes | None = None, run_fn: Callable[..., Any] = subprocess.run) -> Mapping[str, Any]:
    if not isinstance(endpoint, EndpointConfig) or not isinstance(argv, tuple) or argv != build_ssh_argv(endpoint):
        raise EndpointAdmissionError("SSH_EFFECTIVE_READBACK_INVALID")
    options: dict[str, str] = {}
    destination: str | None = None
    index = 1
    while index < len(argv):
        item = argv[index]
        if item == "-F" and index + 1 < len(argv):
            if argv[index + 1] != "none":
                raise EndpointAdmissionError("SSH_EFFECTIVE_READBACK_INVALID")
            index += 2
        elif item == "-p" and index + 1 < len(argv):
            if argv[index + 1] != str(endpoint.port):
                raise EndpointAdmissionError("SSH_EFFECTIVE_READBACK_INVALID")
            index += 2
        elif item == "-o" and index + 1 < len(argv):
            option = argv[index + 1]
            if "=" not in option:
                raise EndpointAdmissionError("SSH_EFFECTIVE_READBACK_INVALID")
            name, value = option.split("=", 1)
            if name in options:
                raise EndpointAdmissionError("SSH_EFFECTIVE_READBACK_INVALID")
            options[name] = value
            index += 2
        else:
            if destination is not None or index != len(argv) - 1:
                raise EndpointAdmissionError("SSH_EFFECTIVE_READBACK_INVALID")
            destination = item
            index += 1
    expected_options = {"IdentityFile": endpoint.identity_path, "IdentitiesOnly": "yes", "IdentityAgent": "none", "CertificateFile": "none", "PKCS11Provider": "none", "GSSAPIAuthentication": "no", "HostbasedAuthentication": "no", "KbdInteractiveAuthentication": "no", "PasswordAuthentication": "no", "PubkeyAuthentication": "yes", "PreferredAuthentications": "publickey", "BatchMode": "yes", "UserKnownHostsFile": endpoint.known_hosts_path, "GlobalKnownHostsFile": "none", "KnownHostsCommand": "none", "PermitRemoteOpen": "none", "StrictHostKeyChecking": "yes", "UpdateHostKeys": "no", "VerifyHostKeyDNS": "no", "CanonicalizeHostname": "no", "CanonicalizeFallbackLocal": "no", "CheckHostIP": "no", "HashKnownHosts": "no", "ProxyCommand": "none", "ProxyJump": "none", "ProxyUseFdpass": "no", "ClearAllForwardings": "yes", "ForwardAgent": "no", "ForwardX11": "no", "ForwardX11Trusted": "no", "RequestTTY": "no", "PermitLocalCommand": "no", "ControlMaster": "no", "ControlPath": "none", "ControlPersist": "no", "SessionType": "default", "EscapeChar": "none", "StdinNull": "no", "Compression": "no", "TCPKeepAlive": "no", "ConnectionAttempts": "1", "ConnectTimeout": "5", "ServerAliveInterval": "1", "ServerAliveCountMax": "3"}
    if options != expected_options or destination != f"{RECOVERY_USER}@{endpoint.host}" or any(name in options for name in ("SendEnv", "SetEnv", "RemoteCommand", "LocalCommand")):
        raise EndpointAdmissionError("SSH_EFFECTIVE_READBACK_INVALID")
    if observed_output is None:
        effective = read_ssh_effective_config(endpoint, argv, run_fn=run_fn)
    else:
        effective = read_ssh_effective_config(endpoint, argv, run_fn=lambda *_args, **_kwargs: types.SimpleNamespace(returncode=0, stdout=observed_output, stderr=b""))
    return {"destination": destination, "options": dict(options), "observed": effective}


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
        return type(self.process_exit_status) is int and self.stdin_eof is True and self.stdout_eof is True and self.stderr_eof is True and type(self.trailing_unframed_bytes) is int and self.trailing_unframed_bytes >= 0 and COMMITMENT_RE.fullmatch(self.stdout_capture_commitment or "") is not None and COMMITMENT_RE.fullmatch(self.stderr_capture_commitment or "") is not None

    @property
    def deterministic(self) -> bool:
        return self.observed and self.trailing_unframed_bytes == 0

    @property
    def success(self) -> bool:
        return self.deterministic and self.process_exit_status == 0


def _bounded_process_stop(process: Any, *, deadline: float) -> None:
    killed = False
    while True:
        poll = getattr(process, "poll", None)
        if callable(poll):
            try:
                if poll() is not None:
                    return
            except Exception:
                pass
        if not killed:
            try:
                process.kill()
            except Exception:
                pass
            killed = True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TransportError("SSH_PROCESS_FINALITY_FAILED", safety_state="UNCONSUMED")
        wait = getattr(process, "wait", None)
        if not callable(wait):
            raise TransportError("SSH_PROCESS_REAP_UNAVAILABLE", safety_state="UNCONSUMED")
        try:
            wait(timeout=min(0.25, remaining))
            return
        except (TimeoutError, subprocess.TimeoutExpired):
            continue


class OpenSSHSession:
    """One admitted OpenSSH process; half-close is a one-shot operation."""

    def __init__(self, endpoint: EndpointConfig) -> None:
        self.endpoint = endpoint
        # Qualification is the first executable boundary.  In particular,
        # ssh -G is inside qualify_endpoint_installation and follows every
        # account/path/file admission check.
        self.installation = qualify_endpoint_installation(endpoint)
        argv = build_ssh_argv(endpoint)
        _verify_bound_installation_files(endpoint, self.installation)
        try:
            self.process = subprocess.Popen(list(argv), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, close_fds=True, env={}, bufsize=0)
        except (OSError, ValueError) as error:
            raise TransportError("SSH_SESSION_OPEN_FAILED") from error
        if self.process.stdin is None or self.process.stdout is None or self.process.stderr is None:
            raise TransportError("SSH_SESSION_PIPES_UNAVAILABLE")
        try:
            _verify_bound_installation_files(endpoint, self.installation)
            if read_local_account_bootstrap() != self.installation["account_bootstrap"]:
                raise EndpointAdmissionError("ACCOUNT_BOOTSTRAP_DRIFT")
        except EndpointAdmissionError as error:
            try:
                _bounded_process_stop(self.process, deadline=time.monotonic() + 1.0)
            except Exception:
                pass
            raise TransportError("SSH_INSTALLATION_DRIFT") from error
        self.stdin = self.process.stdin
        self.stdout = self.process.stdout
        self.stderr = self.process.stderr
        self._closed = False
        self._half_close_attempted = False
        self._input_closed = False
        self._finality: SessionFinality | None = None
        self._stderr_capture = REMOTE.BoundedCapture(REMOTE.MAX_CAPTURE_BYTES)
        self._stderr_error: Exception | None = None
        self._stderr_eof = False
        self._stderr_thread = threading.Thread(target=self._drain_stderr, daemon=True)
        self._stderr_thread.start()

    def _drain_stderr(self) -> None:
        try:
            while True:
                chunk = self.stderr.read(REMOTE.READ_CHUNK_BYTES)
                if not chunk:
                    self._stderr_eof = True
                    return
                self._stderr_capture.append(bytes(chunk))
        except Exception as error:
            self._stderr_error = error

    def send_frame(self, frame: bytes) -> None:
        if self._closed or self._input_closed:
            raise TransportError("SSH_SESSION_CLOSED")
        try:
            REMOTE._write_all(self.stdin, frame)
        except Exception as error:
            raise TransportError("SSH_FRAME_WRITE_FAILED", safety_state="CONSUMED" if self._half_close_attempted else None) from error

    def receive_frame(self) -> REMOTE.DecodedFrame | None:
        if self._closed:
            raise TransportError("SSH_SESSION_CLOSED")
        try:
            return REMOTE.read_frame(self.stdout, eof_ok=True)
        except Exception as error:
            raise TransportError("SSH_FRAME_READ_FAILED", safety_state="CONSUMED" if self._half_close_attempted else None) from error

    def half_close_input(self) -> None:
        if self._closed:
            raise TransportError("SSH_SESSION_CLOSED", safety_state="CONSUMED")
        if self._half_close_attempted:
            raise TransportError("SSH_STDIN_EOF_DUPLICATE", safety_state="CONSUMED")
        self._half_close_attempted = True
        try:
            self.stdin.close()
        except OSError as error:
            # The PROCEED bytes have already been consumed by the remote
            # process; do not attempt a compensating frame or retry.
            raise TransportError("SSH_STDIN_EOF_UNCERTAIN", safety_state="CONSUMED") from error
        self._input_closed = True

    def finish_input(self) -> None:
        self.half_close_input()

    def finalize(self) -> SessionFinality:
        if self._finality is not None:
            return self._finality
        if not self._input_closed:
            raise TransportError("SSH_STDIN_EOF_REQUIRED", safety_state="CONSUMED")
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
                    stdout_capture.append(bytes(chunk))
            except Exception as error:
                stdout_error = error

        reader = threading.Thread(target=drain_stdout, daemon=True)
        reader.start()
        wait_error: Exception | None = None
        status: Any = None
        try:
            status = self.process.wait(timeout=REMOTE.ENGINE_IO_DEADLINE_SECONDS)
        except Exception as error:
            wait_error = error
        reader.join(timeout=2.0)
        self._stderr_thread.join(timeout=2.0)
        if wait_error is not None or reader.is_alive() or not stdout_eof or stdout_error is not None or self._stderr_thread.is_alive() or self._stderr_error is not None or not self._stderr_eof:
            raise TransportError("SSH_PROCESS_FINALITY_FAILED", safety_state="CONSUMED") from wait_error
        self._finality = SessionFinality(status if type(status) is int else None, True, stdout_eof, self._stderr_eof, trailing, REMOTE.bytes_commitment("stdout-capture", stdout_capture.snapshot()), REMOTE.bytes_commitment("stderr-capture", self._stderr_capture.snapshot()))
        return self._finality

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        streams = (self.stdout, self.stderr) if self._half_close_attempted else (self.stdin, self.stdout, self.stderr)
        if self._finality is None:
            for stream in streams:
                try:
                    stream.close()
                except OSError:
                    pass
            try:
                _bounded_process_stop(self.process, deadline=time.monotonic() + 1.0)
            except Exception:
                pass
        else:
            for stream in streams:
                try:
                    stream.close()
                except OSError:
                    pass


@dataclass(frozen=True)
class Transition:
    data: dict[str, Any]
    transition_id: str
    data_commitment: str


def build_barrier_commitment(barrier_utc: str) -> str:
    REMOTE.validate_barrier_utc(barrier_utc)
    return REMOTE.bytes_commitment("barrier-utc", barrier_utc.encode("ascii"))


def _transition_id(data_bytes: bytes) -> str:
    return "restore-v2-" + hashlib.sha256(REMOTE._length_prefixed(("restore-transition-id.v2", data_bytes))).hexdigest()[:48]


def build_restore_transition(*, epoch_ref: str, authority_ref: str, barrier_utc: str, barrier_commitment: str, runner_commitment: str, bundle_commitment: str, image_commitment: str, target_commitment: str, isolation_commitment: str, artifact_commitment: str, artifact_stream_commitment: str, pre_cas_ledger_digest: str) -> Transition:
    _strict_ref(epoch_ref, "epoch_ref")
    _strict_ref(authority_ref, "authority_ref")
    REMOTE.validate_barrier_utc(barrier_utc)
    values = (barrier_commitment, runner_commitment, bundle_commitment, image_commitment, target_commitment, isolation_commitment, artifact_commitment, artifact_stream_commitment, pre_cas_ledger_digest)
    if any(not isinstance(value, str) or COMMITMENT_RE.fullmatch(value) is None for value in values):
        raise StoreIntegrationError("TRANSITION_COMMITMENT_INVALID")
    data = {"schema": TRANSITION_SCHEMA, "version": TRANSITION_VERSION, "epoch_ref": epoch_ref, "authority_ref": authority_ref, "barrier_utc": barrier_utc, "barrier_commitment": barrier_commitment, "runner_commitment": runner_commitment, "bundle_commitment": bundle_commitment, "image_commitment": image_commitment, "target_commitment": target_commitment, "isolation_commitment": isolation_commitment, "artifact_commitment": artifact_commitment, "artifact_stream_commitment": artifact_stream_commitment, "pre_cas_ledger_digest": pre_cas_ledger_digest}
    if tuple(data.keys()) != TRANSITION_FIELDS:
        raise StoreIntegrationError("TRANSITION_FIELDS_INVALID")
    data_bytes = REMOTE.canonical_json(data, limit=STORE.MAX_RESTORE_LEDGER_BYTES, terminal_lf=True)
    return Transition(data, _transition_id(data_bytes), STORE.bytes_commitment(STORE.DOMAIN_RESTORE_TRANSITION, data_bytes))


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        converted = dataclasses.asdict(value)
        if isinstance(converted, dict):
            return converted
    raise StoreIntegrationError(f"{label.upper()}_INVALID")


def _snapshot_is_initial(snapshot: Any) -> bool:
    if not isinstance(snapshot, STORE.V2EpochSnapshot):
        return False
    return snapshot.record["state"] == "INITIALISED" and snapshot.record["artifact_binding_state"] == "PENDING" and snapshot.artifact_binding.artifact_binding_state == "PENDING" and snapshot.record["artifact_commitment"] is None and snapshot.ledger["state"] == "UNCONSUMED" and snapshot.spool["state"] == "OPEN" and snapshot.spool["last_stage"] == "NONE"


def _snapshot_matches_cas_a(snapshot: Any, *, epoch_ref: str, transition: Transition) -> bool:
    return isinstance(snapshot, STORE.V2EpochSnapshot) and snapshot.record["epoch_ref"] == epoch_ref and snapshot.record["state"] == "ACTIVE" and snapshot.ledger["state"] == "CONSUMED" and snapshot.ledger["transition_id"] == transition.transition_id and snapshot.ledger["transition_target"] == "RESTORE_STARTED" and snapshot.ledger["transition_data_commitment"] == transition.data_commitment and snapshot.spool["state"] == "OPEN" and snapshot.spool["last_stage"] == "RUNNER_STARTED"


def _snapshot_matches_pre_cas(snapshot: Any, *, expected: Any) -> bool:
    return isinstance(snapshot, STORE.V2EpochSnapshot) and snapshot.record == expected.record and snapshot.ledger == expected.ledger and snapshot.spool == expected.spool and snapshot.artifact_binding == expected.artifact_binding


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
    value = REMOTE.validate_wire_payload(ready, "READY", n_local=n_local)
    for field in ("epoch_ref", "authority_ref", "barrier_utc", "epoch_commitment", "authority_commitment", "barrier_commitment", "runner_commitment", "bundle_commitment", "launcher_commitment", "agent_commitment"):
        if value[field] != boot[field]:
            raise ProtocolError("READY_MISMATCH")


def _validate_discovery(payload: Mapping[str, Any], *, epoch_ref: str, authority_ref: str) -> dict[str, Any]:
    value = REMOTE.validate_wire_payload(payload, "DISCOVERY")
    if value["epoch_ref"] != epoch_ref or value["authority_ref"] != authority_ref:
        raise ProtocolError("DISCOVERY_MISMATCH")
    expected_artifact = STORE.recovery_commitment(STORE.DOMAIN_ARTIFACT_ROW, str(value["execution_row_id"]), value["artifact_filename"])
    if value["artifact_commitment"] != expected_artifact:
        raise ProtocolError("ARTIFACT_BINDING_MISMATCH")
    return value


def _build_boot(*, n_local: bytes, epoch_ref: str, authority_ref: str, barrier_utc: str, epoch_commitment: str, runner_commitment: str, bundle_commitment: str, endpoint_commitment: str, launcher_commitment: str, agent_commitment: str) -> dict[str, Any]:
    value = {"type": "BOOT", "version": REMOTE.SWZFRM02_VERSION, "schema": REMOTE.SCHEMA_WIRE, "n_local": n_local.hex(), "epoch_ref": epoch_ref, "authority_ref": authority_ref, "barrier_utc": barrier_utc, "epoch_commitment": epoch_commitment, "authority_commitment": REMOTE.text_commitment("authority", authority_ref), "barrier_commitment": build_barrier_commitment(barrier_utc), "runner_commitment": runner_commitment, "bundle_commitment": bundle_commitment, "launcher_commitment": launcher_commitment, "agent_commitment": agent_commitment, "ssh_endpoint_commitment": endpoint_commitment}
    return REMOTE.validate_wire_payload(value, "BOOT")


def _build_proceed(*, epoch_ref: str, authority_ref: str, barrier_utc: str, epoch_commitment: str, runner_commitment: str, bundle_commitment: str, launcher_commitment: str, agent_commitment: str, image_commitment: str, target_commitment: str, isolation_commitment: str, artifact_commitment: str, artifact_stream_commitment: str, transition: Transition, consumed_record_commitment: str, restore_begin_commitment: str) -> dict[str, Any]:
    value = {"type": "PROCEED", "version": REMOTE.SWZFRM02_VERSION, "schema": REMOTE.SCHEMA_WIRE, "epoch_ref": epoch_ref, "authority_ref": authority_ref, "barrier_utc": barrier_utc, "epoch_commitment": epoch_commitment, "authority_commitment": REMOTE.text_commitment("authority", authority_ref), "barrier_commitment": build_barrier_commitment(barrier_utc), "runner_commitment": runner_commitment, "bundle_commitment": bundle_commitment, "launcher_commitment": launcher_commitment, "agent_commitment": agent_commitment, "image_commitment": image_commitment, "target_commitment": target_commitment, "isolation_commitment": isolation_commitment, "artifact_commitment": artifact_commitment, "artifact_stream_commitment": artifact_stream_commitment, "transition_id": transition.transition_id, "pre_cas_ledger_digest": transition.data["pre_cas_ledger_digest"], "transition_data_commitment": transition.data_commitment, "consumed_record_commitment": consumed_record_commitment, "restore_begin_commitment": restore_begin_commitment}
    return REMOTE.validate_wire_payload(value, "PROCEED")


def _build_restore_begin_evidence(*, previous_snapshot: Any, snapshot: Any, transition: Transition, artifact_commitment: str, artifact_stream_commitment: str, ledger_after_digest: str) -> dict[str, Any]:
    previous_spool = _mapping(previous_snapshot.spool, "previous_spool")
    spool = _mapping(snapshot.spool, "spool")
    value = {"schema": RESTORE_BEGIN_SCHEMA, "epoch_ref": snapshot.record["epoch_ref"], "transition_id": transition.transition_id, "transition_data_commitment": transition.data_commitment, "artifact_commitment": artifact_commitment, "artifact_stream_commitment": artifact_stream_commitment, "ledger_state": snapshot.ledger["state"], "record_state": snapshot.record["state"], "spool_previous_stage": previous_spool["last_stage"], "frame_sequence": spool["next_sequence"] - 1, "previous_frame_hash": previous_spool["last_frame_hash"], "frame_hash": spool["last_frame_hash"], "spool_commitment": spool["spool_commitment"], "ledger_after_digest": ledger_after_digest, "durability": dict(snapshot.record["durability"])}
    if tuple(value.keys()) != RESTORE_BEGIN_FIELDS or value["spool_previous_stage"] != "RUNNER_STARTED" or type(value["frame_sequence"]) is not int or value["frame_sequence"] <= 0 or value["previous_frame_hash"] == value["frame_hash"]:
        raise StoreIntegrationError("RESTORE_BEGIN_EVIDENCE_INVALID", safety_state="CONSUMED")
    for field in ("transition_data_commitment", "artifact_commitment", "artifact_stream_commitment", "spool_commitment", "ledger_after_digest"):
        _commitment(value[field])
    return value


def _safe_evidence(*, snapshot: Any, endpoint_commitment: str, stage: str, code: str, transition: Transition | None = None, barrier_commitment: str | None = None, process_finality: str = "NOT_OBSERVED", transport_finality: str = "NOT_OBSERVED", cleanup_state: str = "NOT_STARTED", abandon_allowed: bool = False) -> dict[str, Any]:
    if code not in ABORT_CODES:
        raise ProtocolError("ABORT_CODE_INVALID")
    record = _mapping(snapshot.record, "record")
    ledger = _mapping(snapshot.ledger, "ledger")
    spool = _mapping(snapshot.spool, "spool")
    value = {"schema": REMOTE.SCHEMA_ABORT, "epoch_ref": record["epoch_ref"], "authority_ref": record["authority_ref"], "ssh_endpoint_commitment": endpoint_commitment, "stage": stage, "direction": "LOCAL_TO_REMOTE", "code": code, "classification": "FAILURE", "epoch_commitment": STORE.bytes_commitment(STORE.DOMAIN_EPOCH_RECORD, REMOTE.canonical_json(record, terminal_lf=True)), "authority_commitment": REMOTE.text_commitment("authority", record["authority_ref"]), "barrier_commitment": barrier_commitment or UNSET_COMMITMENT, "transition_id": transition.transition_id if transition else "unset-transition", "transition_data_commitment": transition.data_commitment if transition else UNSET_COMMITMENT, "restore_begin_commitment": UNSET_COMMITMENT, "consumed_state": ledger["state"], "record_state": record["state"], "ledger_state": ledger["state"], "spool_last_stage": spool["last_stage"], "store_readback_commitment": STORE.bytes_commitment(STORE.DOMAIN_RESTORE_LEDGER, REMOTE.canonical_json(dict(ledger), terminal_lf=True)), "process_finality": process_finality, "transport_finality": transport_finality, "cleanup_state": cleanup_state, "retry_allowed": False, "reconnect_allowed": False, "proceed_allowed": False, "restore_allowed": False, "commit_allowed": False, "abandon_allowed": abandon_allowed}
    REMOTE.validate_abort_evidence(value)
    return value


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
    return evidence["classification"] == "SUCCESS" and evidence["result_code"] == "RESTORE_SUCCEEDED" and evidence["restore_count"] == 1 and evidence["exit_status"] == 0 and evidence["stdin_eof"] is True and evidence["stdout_eof"] is True and evidence["stderr_eof"] is True and evidence["trailing_unframed_bytes"] == 0 and evidence["terminal_input_eof"] is True and evidence["terminal_input_trailing_bytes"] == 0 and evidence["cleanup_state"] == "COMPLETE"


def _validate_result_contract(evidence: Mapping[str, Any], proceed: Mapping[str, Any], endpoint_commitment: str) -> None:
    for field in ("epoch_ref", "authority_ref", "barrier_utc", "epoch_commitment", "runner_commitment", "bundle_commitment", "launcher_commitment", "agent_commitment", "image_commitment", "target_commitment", "isolation_commitment", "artifact_commitment", "artifact_stream_commitment", "transition_id", "pre_cas_ledger_digest", "transition_data_commitment", "consumed_record_commitment", "restore_begin_commitment"):
        if evidence[field] != proceed[field]:
            raise ProtocolError("RESULT_MISMATCH")
    if evidence["ssh_endpoint_commitment"] != endpoint_commitment or evidence["barrier_commitment"] != proceed["barrier_commitment"] or evidence["stage"] not in {"RESTORE", "CLEANUP", "PROCESS"}:
        raise ProtocolError("RESULT_MISMATCH")


class ControllerBridge:
    def __init__(self, store: Any, endpoint: EndpointConfig, epoch_ref: str, barrier_utc: str, *, session_factory: Callable[[EndpointConfig], Any] | None = None, nonce_factory: Callable[[int], bytes] | None = None, clock: Callable[[], float] = time.monotonic, artifact_stream_commitment: str | None = None, test_mode: bool = False) -> None:
        if not isinstance(endpoint, EndpointConfig):
            raise EndpointAdmissionError("ENDPOINT_INVALID")
        _strict_ref(epoch_ref, "epoch_ref")
        REMOTE.validate_barrier_utc(barrier_utc)
        if not test_mode and any(value is not None for value in (session_factory, nonce_factory, artifact_stream_commitment)):
            raise EndpointAdmissionError("PRODUCTION_TEST_SEAM_FORBIDDEN")
        self.store = store
        self.endpoint = endpoint
        self.epoch_ref = epoch_ref
        self.barrier_utc = barrier_utc
        self.session_factory = session_factory or OpenSSHSession
        self.nonce_factory = nonce_factory or secrets.token_bytes
        self.clock = clock
        self.artifact_stream_commitment_override = artifact_stream_commitment
        self.test_mode = test_mode
        self._session: Any | None = None
        self._n_local: bytes | None = None
        self._sequence = 0
        self._epoch_commitment: str | None = None
        self._cas_classification: str | None = None
        self._cas_consumed = False
        self._restore_begin_durable = False
        self._proceed_sent = False
        self._half_close_attempted = False
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

    def _half_close_input(self) -> None:
        if self._half_close_attempted:
            raise TransportError("SSH_STDIN_EOF_DUPLICATE", safety_state="CONSUMED")
        self._half_close_attempted = True
        if self._session is None:
            raise TransportError("SESSION_NOT_OPEN", safety_state="CONSUMED")
        half_close = getattr(self._session, "half_close_input", None)
        if callable(half_close):
            half_close()
            return
        # Legacy test doubles are accepted only in test mode.  Production
        # sessions must expose the explicit half-close boundary.
        if self.test_mode and callable(getattr(self._session, "finish_input", None)):
            self._session.finish_input()
            return
        raise TransportError("SSH_STDIN_EOF_UNAVAILABLE", safety_state="CONSUMED")

    def _send_abort(self, snapshot: Any, stage: str, code: str, *, abandon_allowed: bool) -> BridgeResult:
        evidence = _safe_evidence(snapshot=snapshot, endpoint_commitment=self.endpoint.endpoint_commitment, stage=stage, code=code, transition=getattr(self, "_transition", None), barrier_commitment=build_barrier_commitment(self.barrier_utc), abandon_allowed=abandon_allowed)
        payload = {"type": "ABORT", "version": REMOTE.SWZFRM02_VERSION, "schema": REMOTE.SCHEMA_WIRE, "code": code, "stage": stage, "direction": "LOCAL_TO_REMOTE", "evidence": evidence, "evidence_commitment": REMOTE.abort_commitment(evidence)}
        try:
            self._send(MESSAGE_ABORT, payload)
            self.trace.append("ABORT")
        except Exception:
            self.trace.append("ABORT_WRITE_FAILED")
        return BridgeResult("FAILURE", code, stage, self._cas_classification, None, evidence, tuple(self.trace), False)

    def _store_pre_cas(self, snapshot: Any, discovery: Mapping[str, Any]) -> tuple[Any, str, str, Transition]:
        try:
            artifact_commitment = self.store.bind_artifact_v2(self.epoch_ref, discovery["execution_row_id"], discovery["artifact_filename"])
            bound = self.store.load_epoch(self.epoch_ref)
            if not isinstance(bound, STORE.V2EpochSnapshot) or bound.record["artifact_commitment"] != artifact_commitment or bound.artifact_binding.artifact_commitment != artifact_commitment or discovery["artifact_commitment"] != artifact_commitment:
                raise StoreIntegrationError("STORE_READBACK_FAILED")
            self.store.mark_ready(self.epoch_ref)
            _store_frame(self.store, self.epoch_ref, "EPOCH_READY", {"state": "READY"})
            self.store.activate(self.epoch_ref)
            _store_frame(self.store, self.epoch_ref, "RUNNER_STARTED", {"commitment": discovery["image_commitment"], "state": "RUNNER_STARTED"})
            active = self.store.load_epoch(self.epoch_ref)
            if not isinstance(active, STORE.V2EpochSnapshot) or active.record["state"] != "ACTIVE" or active.spool["last_stage"] != "RUNNER_STARTED":
                raise StoreIntegrationError("STORE_READBACK_FAILED")
            stream_commitment = self.artifact_stream_commitment_override or discovery["artifact_stream_commitment"]
            transition = build_restore_transition(epoch_ref=self.epoch_ref, authority_ref=active.record["authority_ref"], barrier_utc=self.barrier_utc, barrier_commitment=build_barrier_commitment(self.barrier_utc), runner_commitment=active.record["runner_commitment"], bundle_commitment=self.endpoint.bundle_commitment, image_commitment=discovery["image_commitment"], target_commitment=discovery["target_commitment"], isolation_commitment=discovery["isolation_commitment"], artifact_commitment=artifact_commitment, artifact_stream_commitment=stream_commitment, pre_cas_ledger_digest=self.store.ledger_digest(self.epoch_ref))
            return active, artifact_commitment, stream_commitment, transition
        except StoreIntegrationError:
            raise
        except Exception as error:
            raise StoreIntegrationError("STORE_PRE_CAS_FAILED", safety_state=getattr(error, "safety_state", None)) from error

    def _classify_cas(self, pre_cas: Any, transition: Transition) -> tuple[str, Any | None, str | None]:
        try:
            permit = self.store.consume_restore(self.epoch_ref, transition.transition_id, expected_digest=transition.data["pre_cas_ledger_digest"], data=transition.data)
        except Exception as error:
            try:
                current = self.store.load_epoch(self.epoch_ref)
            except Exception:
                self._cas_classification = "C"
                return "C", None, "CAS_UNCERTAIN"
            exact_b = isinstance(error, STORE.LedgerError) and getattr(error, "code", None) in {"CAS_MISMATCH", "EPOCH_NOT_ACTIVE", "RESTORE_PRECONDITION_FAILED"} and getattr(error, "safety_state", None) == "UNCONSUMED" and _snapshot_matches_pre_cas(current, expected=pre_cas)
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
            raise TransportError("SESSION_FINALITY_UNAVAILABLE", safety_state="CONSUMED")
        value = self._session.finalize()
        if not isinstance(value, SessionFinality):
            raise TransportError("SESSION_FINALITY_INVALID", safety_state="CONSUMED")
        self._session_finality = value
        return value

    def _close_session_after_finality(self) -> None:
        if self._session is None or self._session_close_checked:
            return
        try:
            self._session.close()
        except Exception as error:
            raise TransportError("SSH_SESSION_CLOSE_FAILED", safety_state="CONSUMED") from error
        self._session_close_checked = True

    def _abandon_and_verify(self, expected_ledger_state: str) -> Any:
        try:
            self.store.abandon(self.epoch_ref)
            current = self.store.load_epoch(self.epoch_ref)
        except Exception as error:
            raise StoreIntegrationError("ABANDON_FINALITY_UNCERTAIN", safety_state="CONSUMED") from error
        if not isinstance(current, STORE.V2EpochSnapshot) or current.record["state"] != "ABANDONED" or current.record["restore_ledger_state"] != expected_ledger_state or current.manifest["state"] != "ABANDONED" or current.manifest["restore_ledger_state"] != expected_ledger_state or current.ledger["state"] != expected_ledger_state or current.spool["state"] != "ABANDONED" or current.spool["last_stage"] != "ABANDON":
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
            boot = _build_boot(n_local=self._n_local, epoch_ref=self.epoch_ref, authority_ref=snapshot.record["authority_ref"], barrier_utc=self.barrier_utc, epoch_commitment=self._epoch_commitment, runner_commitment=snapshot.record["runner_commitment"], bundle_commitment=self.endpoint.bundle_commitment, endpoint_commitment=self.endpoint.endpoint_commitment, launcher_commitment=self.endpoint.launcher_commitment, agent_commitment=self.endpoint.agent_commitment)
            self._send(MESSAGE_BOOT, boot)
            ready_frame = self._receive((MESSAGE_READY, MESSAGE_ABORT))
            if ready_frame.message == MESSAGE_ABORT:
                raise ProtocolError("REMOTE_ABORT")
            _validate_ready(boot, ready_frame.payload, self._n_local)
            self.trace.append("READY")
            discovery_frame = self._receive((MESSAGE_DISCOVERY, MESSAGE_ABORT))
            if discovery_frame.message == MESSAGE_ABORT:
                raise ProtocolError("REMOTE_ABORT")
            discovery = _validate_discovery(discovery_frame.payload, epoch_ref=self.epoch_ref, authority_ref=snapshot.record["authority_ref"])
            self.trace.append("DISCOVERY")
            active, artifact_commitment, stream_commitment, transition = self._store_pre_cas(snapshot, discovery)
            self._transition = transition
            self.trace.append("PRE_CAS")
            classification, current, consumed_record_commitment = self._classify_cas(active, transition)
            if classification == "B":
                try:
                    current = self._abandon_and_verify("UNCONSUMED")
                except Exception:
                    self._cas_classification = "C"
                    self.trace.append("CAS_C")
                    return BridgeResult("FAILURE", "CAS_UNCERTAIN", "POST_CAS", "C", None, None, tuple(self.trace), False)
                self.trace.append("ABANDON")
                return self._send_abort(current, "CAS_B", "CAS_REJECTED_UNCONSUMED", abandon_allowed=True)
            if classification == "C":
                self.trace.append("CAS_C")
                return BridgeResult("FAILURE", "CAS_UNCERTAIN", "PRE_CAS", "C", None, None, tuple(self.trace), False)
            self.trace.append("CAS_A")
            before_restore_begin = self.store.load_epoch(self.epoch_ref)
            ledger_after_digest = self.store.ledger_digest(self.epoch_ref)
            _store_frame(self.store, self.epoch_ref, "RESTORE_BEGIN", {"ref": transition.transition_id, "commitment": transition.data_commitment})
            durable_snapshot = self.store.load_epoch(self.epoch_ref)
            if durable_snapshot.spool["last_stage"] != "RESTORE_BEGIN" or durable_snapshot.ledger["state"] != "CONSUMED":
                raise StoreIntegrationError("RESTORE_BEGIN_NOT_DURABLE", safety_state="CONSUMED")
            self._restore_begin_durable = True
            restore_begin = _build_restore_begin_evidence(previous_snapshot=before_restore_begin, snapshot=durable_snapshot, transition=transition, artifact_commitment=artifact_commitment, artifact_stream_commitment=stream_commitment, ledger_after_digest=ledger_after_digest)
            restore_begin_commitment = REMOTE.bytes_commitment("restore-begin-evidence", REMOTE.canonical_json(restore_begin, terminal_lf=True))
            proceed = _build_proceed(epoch_ref=self.epoch_ref, authority_ref=active.record["authority_ref"], barrier_utc=self.barrier_utc, epoch_commitment=self._epoch_commitment, runner_commitment=active.record["runner_commitment"], bundle_commitment=self.endpoint.bundle_commitment, launcher_commitment=self.endpoint.launcher_commitment, agent_commitment=self.endpoint.agent_commitment, image_commitment=discovery["image_commitment"], target_commitment=discovery["target_commitment"], isolation_commitment=discovery["isolation_commitment"], artifact_commitment=artifact_commitment, artifact_stream_commitment=stream_commitment, transition=transition, consumed_record_commitment=consumed_record_commitment, restore_begin_commitment=restore_begin_commitment)
            # From this line onward the Store authority is consumed.  There is
            # exactly one PROCEED and no local frame after it.
            self.trace.append("PROCEED")
            self._proceed_sent = True
            self._send(MESSAGE_PROCEED, proceed)
            # The half-close is immediate and precedes the first RESULT/ABORT
            # read.  Any ambiguity is sticky CAS-C; no frame is attempted.
            self._half_close_input()
            result_frame = self._receive((MESSAGE_RESULT, MESSAGE_ABORT))
            if result_frame.message == MESSAGE_ABORT:
                raise ProtocolError("REMOTE_ABORT")
            evidence = REMOTE.validate_result_evidence(result_frame.payload["result_evidence"])
            if result_frame.payload["classification"] != evidence["classification"]:
                raise ProtocolError("RESULT_MISMATCH")
            _validate_result_contract(evidence, proceed, self.endpoint.endpoint_commitment)
            if result_frame.payload["result_commitment"] != REMOTE.result_commitment(evidence):
                raise ProtocolError("RESULT_COMMITMENT_INVALID")
            self.trace.append("RESULT")
            local_finality = self._finalize_session()
            if not local_finality.observed:
                raise TransportError("SESSION_FINALITY_INCOMPLETE", safety_state="CONSUMED")
            remote_deterministic = evidence["stdin_eof"] is True and evidence["stdout_eof"] is True and evidence["stderr_eof"] is True and evidence["trailing_unframed_bytes"] == 0 and evidence["terminal_input_eof"] is True and evidence["terminal_input_trailing_bytes"] == 0 and evidence["cleanup_state"] == "COMPLETE"
            if not remote_deterministic or not local_finality.deterministic:
                raise TransportError("POST_CAS_FINALITY_UNCERTAIN", safety_state="CONSUMED")
            self._close_session_after_finality()
            if evidence["classification"] == "FAILURE":
                if self.test_mode:
                    return BridgeResult("FAILURE", evidence["result_code"], "RESULT", "A", evidence, None, tuple(self.trace), True)
                self._abandon_and_verify("CONSUMED")
                self.trace.append("ABANDON")
                return BridgeResult("FAILURE", evidence["result_code"], "RESULT", "A", evidence, None, tuple(self.trace), True)
            if self.test_mode:
                raise TransportError("TEST_SUCCESS_NOT_OPERATIONAL", safety_state="CONSUMED")
            _store_frame(self.store, self.epoch_ref, "COMMIT", {"classification": "SUCCESS", "commitment": REMOTE.result_commitment(evidence)})
            self.trace.extend(("COMMIT", "FINAL"))
            return BridgeResult("SUCCESS", "RESTORE_SUCCEEDED", "COMMIT", "A", evidence, None, tuple(self.trace), True)
        except Exception as error:
            code = getattr(error, "code", "PROTOCOL_FAILURE")
            if code == "REMOTE_ABORT":
                code = "RESTORE_FAILED"
            # After CAS-A, RESTORE_BEGIN, PROCEED, or half-close there is no
            # safe local compensation.  This includes an ambiguous write or
            # half-close and intentionally leaves the Store sticky.
            if self._cas_classification == "C" or self._cas_consumed or self._restore_begin_durable or self._proceed_sent:
                self._cas_classification = "C"
                if not self.trace or self.trace[-1] != "CAS_C":
                    self.trace.append("CAS_C")
                return BridgeResult("FAILURE", "CAS_UNCERTAIN", "POST_CAS", "C", None, None, tuple(self.trace), False)
            if snapshot is None:
                snapshot = types.SimpleNamespace(record={"epoch_ref": self.epoch_ref, "authority_ref": "unknown", "state": "INITIALISED"}, ledger={"state": "UNCONSUMED"}, spool={"last_stage": "NONE"})
            if code not in ABORT_CODES:
                code = "PROTOCOL_FAILURE"
            stage = self.trace[-1] if self.trace else "BOOT"
            if stage == "CAS_A":
                stage = "RESTORE_BEGIN"
            try:
                snapshot = self._abandon_and_verify("UNCONSUMED")
                self.trace.append("ABANDON")
            except Exception:
                self._cas_classification = "C"
                self.trace.append("CAS_C")
                return BridgeResult("FAILURE", "CAS_UNCERTAIN", "POST_CAS", "C", None, None, tuple(self.trace), False)
            if code in ABORT_CODES and stage in REMOTE.LOCAL_ABORT_STAGES:
                return self._send_abort(snapshot, stage, code, abandon_allowed=True)
            return BridgeResult("FAILURE", code, stage, self._cas_classification, None, None, tuple(self.trace), False)
        finally:
            if self._session is not None and not self._session_close_checked:
                try:
                    self._session.close()
                except Exception:
                    pass


def run_controller_bridge(store: Any, endpoint: EndpointConfig, epoch_ref: str, barrier_utc: str, *, session_factory: Callable[[EndpointConfig], Any] | None = None, nonce_factory: Callable[[int], bytes] | None = None, artifact_stream_commitment: str | None = None, test_mode: bool = False) -> BridgeResult:
    return ControllerBridge(store, endpoint, epoch_ref, barrier_utc, session_factory=session_factory, nonce_factory=nonce_factory, artifact_stream_commitment=artifact_stream_commitment, test_mode=test_mode).run()


__all__ = ["ABORT_CODES", "CANONICAL_LOCATOR_PACKAGE_ATTESTATION", "CANONICAL_LOCATOR_PACKAGE_COMMITMENT", "CANONICAL_LOCATOR_SOURCE_COMMITMENT", "ControllerBridge", "BridgeError", "BridgeResult", "EndpointAdmissionError", "EndpointConfig", "FIXED_LOADER_COMMITMENT", "FIXED_LOADER_SOURCE", "OpenSSHSession", "REMOTE", "STORE", "SWZFRM02_HEADER", "build_barrier_commitment", "build_restore_transition", "build_ssh_argv", "qualify_endpoint_installation", "run_controller_bridge", "SessionFinality"]
