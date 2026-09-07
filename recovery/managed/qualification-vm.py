"""Boot a disposable software-virtualised guest for the mandatory proof.

The command is deliberately fail-closed. It does not inspect host getenforce
output, use qemu -machine none, treat a QEMU PID as guest evidence, or emit a
synthetic pass when a guest primitive is absent.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import platform
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


class GuestError(RuntimeError):
    pass


class ProviderHold(GuestError):
    pass


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MAX_DIAGNOSTIC_CHARS = 4096


def _bounded(value: object) -> str:
    if isinstance(value, bytes):
        text = value.decode("utf-8", "replace")
    else:
        text = "" if value is None else str(value)
    if len(text) <= MAX_DIAGNOSTIC_CHARS:
        return text
    half = MAX_DIAGNOSTIC_CHARS // 2
    return text[:half] + "\n...[truncated]...\n" + text[-half:]


def _safe_command(command: list[str]) -> str:
    safe: list[str] = []
    for value in command:
        text = str(value)
        if "=" in text:
            key, _, _ = text.partition("=")
            if any(marker in key.upper() for marker in ("PASSWORD", "TOKEN", "SECRET", "PRIVATE_KEY")):
                text = key + "=<redacted>"
        safe.append(text)
    return shlex.join(safe)


def _process_failure(stage: str, command: list[str], result: object) -> str:
    return (
        f"stage={stage}; command={_safe_command(command)}; returncode={getattr(result, 'returncode', 'unknown')}; "
        f"stdout={_bounded(getattr(result, 'stdout', None))}; stderr={_bounded(getattr(result, 'stderr', None))}"
    )


def tool(name: str) -> str:
    value = shutil.which(name)
    if value is None:
        raise ProviderHold(f"guest-tool-unavailable:{name}")
    return value


def choose_kernel(explicit: Path | None) -> Path:
    if explicit is not None:
        if not explicit.is_file():
            raise ProviderHold("guest-kernel-missing")
        return explicit
    candidates = sorted(Path("/boot").glob("vmlinuz-*"))
    if not candidates:
        raise ProviderHold("guest-kernel-not-installed")
    return candidates[-1]


def copy_tree(source: Path, destination: Path) -> None:
    if not source.is_dir():
        raise ProviderHold("guest-root-missing")
    for path in source.rglob("*"):
        relative = path.relative_to(source)
        target = destination / relative
        if path.is_symlink():
            link_text = path.readlink()
            source_root = source.resolve()
            link_target = source / str(link_text).lstrip("/") if link_text.is_absolute() else path.parent / link_text
            resolved = link_target.resolve()
            if source_root not in resolved.parents and resolved != source_root:
                raise GuestError(f"guest-root-link-outside:{relative}")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(link_text, target_is_directory=path.is_dir())
            continue
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif path.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
        else:
            raise GuestError(f"guest-root-special-file:{relative}")


def stage_file(source: Path, destination: Path, *, executable: bool | None = None) -> None:
    if not source.is_file() or source.is_symlink():
        raise ProviderHold(f"candidate-file-missing:{source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    if executable is True:
        destination.chmod(destination.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def stage_runtime_dependencies(binary: Path, root: Path) -> None:
    ldd = shutil.which("ldd")
    if ldd is None:
        raise ProviderHold("guest-runtime-ldd-unavailable")
    command = [ldd, str(binary)]
    try:
        result = subprocess.run(command, check=False, text=True, capture_output=True)
    except OSError as error:
        raise ProviderHold(
            f"stage=guest-runtime-dependencies; command={_safe_command(command)}; "
            f"process-unavailable={type(error).__name__}"
        ) from error
    if result.returncode != 0:
        raise GuestError(_process_failure("guest-runtime-dependencies", command, result))
    paths: set[Path] = set()
    for line in (result.stdout or "").splitlines():
        match = re.search(r"=>\s+(/[^\s]+)", line)
        if match is None:
            match = re.match(r"\s*(/[^\s]+)", line)
        if match is None:
            continue
        dependency = Path(match.group(1))
        if not any(dependency == prefix or prefix in dependency.parents for prefix in (Path("/lib"), Path("/lib64"), Path("/usr/lib"), Path("/usr/lib64"))):
            raise GuestError(f"guest-runtime-dependency-outside-system:{dependency}")
        paths.add(dependency)
    if not paths:
        raise GuestError(f"guest-runtime-dependencies-empty:{binary.name}")
    for dependency in sorted(paths):
        if not dependency.is_file():
            raise GuestError(f"guest-runtime-dependency-missing:{dependency}")
        destination = root / dependency.relative_to("/")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(dependency, destination)


def stage_candidate(build_output: Path, root: Path) -> None:
    if not build_output.is_dir():
        raise ProviderHold("candidate-build-output-missing")
    manifest = build_output / "build-manifest.json"
    if not manifest.is_file():
        raise ProviderHold("candidate-build-manifest-missing")
    try:
        value = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GuestError("candidate-build-manifest-invalid") from error
    if value.get("schema") != "swz-managed-build-manifest.v1":
        raise GuestError("candidate-build-manifest-schema-invalid")
    native = value.get("native")
    if not isinstance(native, dict):
        raise GuestError("candidate-build-native-manifest-invalid")
    for name in (
        "swz-supervisor", "swz-custodian", "swz-dispatcher",
        "swz-bootstrap", "swz-broker", "swz-agent", "swz-launch-base",
    ):
        source = build_output / "native" / name
        try:
            actual = hashlib.sha256(source.read_bytes()).hexdigest()
        except OSError as error:
            raise ProviderHold(f"candidate-native-file-unavailable:{name}") from error
        if actual != native.get(name):
            raise GuestError(f"candidate-native-digest-mismatch:{name}")
        stage_runtime_dependencies(source, root)
        stage_file(source, root / "usr/local/libexec" / name, executable=True)
    openssh = value.get("openssh")
    if not isinstance(openssh, dict):
        raise GuestError("candidate-openssh-manifest-invalid")
    for name, digest_key, destination in (
        ("sshd", "binary_sha256", "sbin/sshd"),
        ("ssh", "ssh_sha256", "bin/ssh"),
        ("ssh-keygen", "ssh_keygen_sha256", "bin/ssh-keygen"),
        ("ssh-agent", "ssh_agent_sha256", "bin/ssh-agent"),
        ("ssh-add", "ssh_add_sha256", "bin/ssh-add"),
    ):
        source = build_output / "openssh" / ("sbin" if name == "sshd" else "bin") / name
        try:
            actual = hashlib.sha256(source.read_bytes()).hexdigest()
        except OSError as error:
            raise ProviderHold(f"candidate-openssh-file-unavailable:{name}") from error
        if actual != openssh.get(digest_key):
            raise GuestError(f"candidate-openssh-digest-mismatch:{name}")
        stage_runtime_dependencies(source, root)
        stage_file(source, root / "opt/swz/openssh" / destination, executable=True)
    for source_name, destination in (
        ("sshd_config", "etc/ssh/recovery_sshd_config"),
        ("accounts.json", "etc/swz/accounts.json"),
        ("selinux.cil", "etc/selinux/swz/swz-managed.cil"),
        ("file_contexts", "etc/selinux/swz/file_contexts"),
        ("kernel.config", "etc/swz/kernel.config"),
    ):
        expected = value.get("source_files", {}).get(source_name)
        source = HERE / source_name
        try:
            actual = hashlib.sha256(source.read_bytes()).hexdigest()
        except OSError as error:
            raise ProviderHold(f"candidate-source-file-unavailable:{source_name}") from error
        if not isinstance(expected, str) or actual != expected:
            raise GuestError(f"candidate-source-digest-mismatch:{source_name}")
        stage_file(source, root / destination)


def prepare_writable_runtime_dirs(root: Path) -> None:
    for relative in ("root/.ssh", "var/lib/swz", "var/empty", "tmp", "run"):
        (root / relative).mkdir(parents=True, exist_ok=True)
    passwd = root / "etc/passwd"
    group = root / "etc/group"
    for path, record in (
        (passwd, "sshd:x:74:74:sshd:/var/empty:/bin/false\n"),
        (group, "sshd:x:74:\n"),
    ):
        if not path.is_file():
            raise ProviderHold(f"guest-account-file-missing:{path.name}")
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise GuestError(f"guest-account-file-unreadable:{path.name}") from error
        if not any(line.startswith(record.split(":", 1)[0] + ":") for line in content.splitlines()):
            try:
                path.write_text(content + ("" if content.endswith("\n") else "\n") + record, encoding="utf-8")
            except OSError as error:
                raise GuestError(f"guest-account-file-update-failed:{path.name}") from error


def set_image_contexts(image: Path) -> None:
    debugfs = tool("debugfs")
    labels = (
        ("etc/swz", "system_u:object_r:etc_t:s0"),
        ("etc/swz/qualification", "system_u:object_r:etc_t:s0"),
        ("etc/swz/qualification/run", "system_u:object_r:etc_t:s0"),
        ("etc/swz/qualification/run/agent-proceed.bin", "system_u:object_r:etc_t:s0"),
        ("etc/swz/qualification/run/agent-result-payload.bin", "system_u:object_r:etc_t:s0"),
        ("etc/swz/qualification/run/agent-result-payload.hex", "system_u:object_r:etc_t:s0"),
        ("etc/swz/qualification/run/accepted.bin", "system_u:object_r:etc_t:s0"),
        ("etc/swz/qualification/run/challenge-payload.bin", "system_u:object_r:etc_t:s0"),
        ("etc/swz/qualification/run/broker-input.bin", "system_u:object_r:etc_t:s0"),
        ("etc/swz/qualification/store", "system_u:object_r:etc_t:s0"),
        ("etc/swz/qualification/store/guest-source-artifact", "system_u:object_r:etc_t:s0"),
        ("usr/local/libexec/swz-supervisor", "system_u:object_r:swz_managed.swz_supervisor_exec_t:s0"),
        ("usr/local/libexec/swz-custodian", "system_u:object_r:swz_managed.swz_custodian_exec_t:s0"),
        ("usr/local/libexec/swz-dispatcher", "system_u:object_r:swz_managed.swz_dispatcher_exec_t:s0"),
        ("usr/local/libexec/swz-bootstrap", "system_u:object_r:swz_managed.swz_bootstrap_exec_t:s0"),
        ("usr/local/libexec/swz-broker", "system_u:object_r:swz_managed.swz_broker_exec_t:s0"),
        ("usr/local/libexec/swz-agent", "system_u:object_r:swz_managed.swz_agent_exec_t:s0"),
        ("usr/local/libexec/swz-launch-base", "system_u:object_r:swz_managed.swz_supervisor_exec_t:s0"),
        ("opt/swz/openssh/sbin/sshd", "system_u:object_r:swz_managed.swz_sshd_exec_t:s0"),
        ("opt/swz/openssh/bin", "system_u:object_r:bin_t:s0"),
        ("opt/swz/openssh/bin/ssh", "system_u:object_r:bin_t:s0"),
        ("opt/swz/openssh/bin/ssh-keygen", "system_u:object_r:bin_t:s0"),
        ("opt/swz/openssh/bin/ssh-agent", "system_u:object_r:bin_t:s0"),
        ("opt/swz/openssh/bin/ssh-add", "system_u:object_r:bin_t:s0"),
        ("etc/ssh/recovery_guest_config", "system_u:object_r:etc_t:s0"),
    )
    for relative, label in labels:
        for command, failure in (
            (f"ea_set /{relative} security.selinux {label}", "guest-image-context-update-failed"),
            (f"set_inode_field /{relative} uid 0", "guest-image-owner-update-failed"),
            (f"set_inode_field /{relative} gid 0", "guest-image-owner-update-failed"),
        ):
            try:
                command_args = [debugfs, "-w", "-R", command, str(image)]
                result = subprocess.run(
                    command_args,
                    check=False,
                    text=True,
                    capture_output=True,
                )
            except OSError as error:
                raise ProviderHold(
                    f"stage=guest-image-context; command={_safe_command(command_args)}; "
                    f"process-unavailable={type(error).__name__}"
                ) from error
            output = ((result.stdout or "") + (result.stderr or "")).lower()
            if result.returncode != 0 or any(marker in output for marker in ("error", "failed", "not found", "no such")):
                raise GuestError(_process_failure(f"guest-image-context:{relative}", command_args, result))


def build_rootfs(data_path: Path, root: Path) -> None:
    mkfs = tool("mkfs.ext4")
    used = 0
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            try:
                used += path.stat().st_size
            except OSError as error:
                raise GuestError(f"guest-root-size-unavailable:{path}") from error
    size = max(512 * 1024 * 1024, used + 256 * 1024 * 1024)
    size = ((size + 4095) // 4096) * 4096
    try:
        with data_path.open("wb") as stream:
            stream.truncate(size)
    except OSError as error:
        raise ProviderHold("guest-verity-data-unavailable") from error
    try:
        command = [mkfs, "-q", "-F", "-O", "ext_attr", "-d", str(root), str(data_path)]
        result = subprocess.run(
            command,
            check=False,
            text=True,
            capture_output=True,
        )
    except OSError as error:
        raise ProviderHold(
            f"stage=guest-rootfs-format; command={_safe_command(command)}; "
            f"process-unavailable={type(error).__name__}"
        ) from error
    if result.returncode != 0:
        raise GuestError(_process_failure("guest-rootfs-format", command, result))
    set_image_contexts(data_path)


def stage_boot_tool(guest_root: Path, boot_root: Path, name: str, destination: str) -> None:
    host_path = Path(tool(name)).resolve()
    try:
        relative = host_path.relative_to(Path("/"))
    except ValueError as error:
        raise GuestError(f"guest-boot-tool-path-invalid:{name}") from error
    source = (guest_root / relative).resolve()
    stage_runtime_dependencies(host_path, boot_root)
    stage_file(source, boot_root / destination, executable=True)


def write_boot_init(root: Path, root_hash: str) -> None:
    init = root / "init"
    init.parent.mkdir(parents=True, exist_ok=True)
    init.write_text(
        f"""#!/bin/sh
set -eu
fail() {{
  echo "SWZ_GUEST_CANDIDATE=FAIL:$1"
  exit "$1"
}}
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
mkdir -p /dev /proc /sys /mnt /dev/mapper
mount -t devtmpfs devtmpfs /dev || fail 10
mount -t proc proc /proc || fail 11
mount -t sysfs sysfs /sys || fail 12
/sbin/veritysetup open --readonly /dev/vda /dev/vdb swz-verity {root_hash} || fail 13
/bin/dd if=/dev/mapper/swz-verity of=/dev/null bs=4096 count=1 || fail 14
mount -t ext4 -o ro /dev/mapper/swz-verity /mnt || fail 15
echo SWZ_GUEST_DM_VERITY=PASS
test -x /mnt/init || fail 17
exec /sbin/switch_root /mnt /init
""",
        encoding="ascii",
    )
    init.chmod(0o755)


def load_backend() -> object:
    spec = importlib.util.spec_from_file_location("swz_guest_backend", HERE / "backend.py")
    if spec is None or spec.loader is None:
        raise GuestError("guest-backend-unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def build_guest_fixtures(root: Path) -> dict[str, str]:
    backend = load_backend()
    session = bytes.fromhex("11" * 32)
    generation = bytes.fromhex("22" * 32)
    cookie = bytes.fromhex("33" * 32)
    artifact = b"guest-native-restore\n"
    artifact_stream = backend.store_commitment("artifact-stream", artifact)
    tagged = backend.store_commitment("guest-field", b"guest-field")
    transition_record = {
        "schema": "restore-ledger-transition-data.v2",
        "version": 2,
        "epoch_ref": "guest-epoch-001",
        "authority_ref": "guest-authority-001",
        "barrier_utc": "2026-09-07T00:00:00Z",
        "barrier_commitment": tagged,
        "runner_commitment": tagged,
        "bundle_commitment": tagged,
        "image_commitment": tagged,
        "target_commitment": tagged,
        "isolation_commitment": tagged,
        "artifact_commitment": tagged,
        "artifact_stream_commitment": artifact_stream,
        "pre_cas_ledger_digest": tagged,
    }
    transition_bytes = backend.store_bytes(transition_record)
    transition_wire = backend.StoreWire.from_bytes("restore-ledger-transition-data.v2", transition_bytes)
    transition_data = backend.store_commitment("restore-ledger-transition", transition_bytes)
    transition = backend.transition_id(transition_bytes)
    discovery_payload, discovery_hash = backend.build_discovery(
        session, 23, "guest-source-artifact", tagged, tagged, tagged, tagged, artifact_stream,
    )
    evidence_record = {
        "schema": "restore-begin-evidence.v2",
        "epoch_ref": "guest-epoch-001",
        "transition_id": transition,
        "transition_data_commitment": transition_data,
        "artifact_commitment": tagged,
        "artifact_stream_commitment": artifact_stream,
        "ledger_state": "CONSUMED",
        "record_state": "ACTIVE",
        "spool_previous_stage": "RUNNER_STARTED",
        "frame_sequence": 3,
        "previous_frame_hash": tagged,
        "frame_hash": tagged,
        "spool_commitment": tagged,
        "ledger_after_digest": tagged,
        "durability": {
            "file_flush_verified": True,
            "readback_verified": True,
            "atomic_authority_transition": True,
            "directory_flush_verified": True,
        },
    }
    evidence_bytes = backend.store_bytes(evidence_record)
    evidence_wire = backend.StoreWire.from_bytes("restore-begin-evidence.v2", evidence_bytes)
    consumed_record_commitment = tagged
    restore_begin_payload = backend.build_restore_begin(
        session, discovery_hash, transition_wire, evidence_wire, consumed_record_commitment,
    )
    restore_begin_frame = backend.build_frame(
        backend.DIRECTION_REMOTE_TO_LOCAL, "RESTORE_BEGIN", 7, bytes.fromhex("66" * 32), restore_begin_payload,
    )
    restore_begin_hash = backend.frame_hash(restore_begin_frame)
    proceed_payload, proceed_commitment = backend.build_proceed(session, transition, transition_data, restore_begin_hash)
    proceed_frame = backend.build_frame(
        backend.DIRECTION_LOCAL_TO_REMOTE, "PROCEED", 8, bytes.fromhex("77" * 32), proceed_payload,
    )
    seed = root / "etc/swz/qualification"
    source = seed / "store/guest-source-artifact"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(artifact)
    seed_run = seed / "run"
    seed_run.mkdir(parents=True, exist_ok=True)
    (seed_run / "agent-proceed.bin").write_bytes(proceed_frame)

    result_record = {
        "schema": "swz-recovery-result.v2",
        "classification": "SUCCESS",
        "stage": "RESTORE",
        "epoch_ref": "guest-epoch-001",
        "authority_ref": "guest-authority-001",
        "barrier_utc": "2026-09-07T00:00:00Z",
        "ssh_endpoint_commitment": tagged,
        "epoch_commitment": tagged,
        "authority_commitment": tagged,
        "barrier_commitment": tagged,
        "runner_commitment": tagged,
        "bundle_commitment": tagged,
        "launcher_commitment": tagged,
        "agent_commitment": tagged,
        "image_commitment": tagged,
        "target_commitment": tagged,
        "isolation_commitment": tagged,
        "artifact_commitment": tagged,
        "artifact_stream_commitment": artifact_stream,
        "transition_id": transition,
        "pre_cas_ledger_digest": tagged,
        "transition_data_commitment": transition_data,
        "consumed_record_commitment": consumed_record_commitment,
        "restore_begin_commitment": backend.store_commitment("restore-begin-evidence", evidence_bytes),
        "process_commitment": tagged,
        "restore_commitment": backend.store_commitment("restore", artifact),
        "cleanup_commitment": tagged,
        "stdout_capture_commitment": tagged,
        "stderr_capture_commitment": tagged,
        "result_code": 0,
        "restore_count": 1,
        "exit_status": 0,
        "stdin_eof": True,
        "stdout_eof": True,
        "stderr_eof": True,
        "trailing_unframed_bytes": False,
        "terminal_input_eof": True,
        "terminal_input_trailing_bytes": False,
        "cleanup_state": "CLEAN",
    }
    result_wire = backend.StoreWire.from_bytes("swz-recovery-result.v2", backend.store_bytes(result_record))
    result_payload, _ = backend.build_result(
        session, transition, backend.frame_hash(proceed_frame), proceed_commitment, result_wire,
    )
    (seed_run / "agent-result-payload.bin").write_bytes(result_payload)
    (seed_run / "agent-result-payload.hex").write_text(result_payload.hex() + "\n", encoding="ascii")

    accepted_payload = backend.managed_json(["ACCEPTED", 2, backend.MANAGED_SCHEMA, session.hex()])
    accepted_frame = backend.build_frame(
        backend.DIRECTION_LOCAL_TO_REMOTE, "ACCEPTED", 5, bytes.fromhex("55" * 32), accepted_payload,
    )
    (seed_run / "accepted.bin").write_bytes(accepted_frame)
    (seed_run / "challenge-payload.bin").write_bytes(
        backend.managed_json(["CHALLENGE", 2, backend.MANAGED_SCHEMA, session.hex()])
    )
    simple_payloads = (
        accepted_payload,
        discovery_payload,
        restore_begin_payload,
        proceed_payload,
        result_payload,
    )
    directions = (
        backend.DIRECTION_REMOTE_TO_LOCAL,
        backend.DIRECTION_LOCAL_TO_REMOTE,
        backend.DIRECTION_REMOTE_TO_LOCAL,
        backend.DIRECTION_LOCAL_TO_REMOTE,
        backend.DIRECTION_REMOTE_TO_LOCAL,
    )
    frames = b"".join(
        backend.build_frame(direction, message, sequence, bytes([sequence]) * 32, payload)
        for sequence, (direction, message, payload) in enumerate(
            zip(directions, ("ACCEPTED", "DISCOVERY", "RESTORE_BEGIN", "PROCEED", "RESULT"), simple_payloads),
            start=5,
        )
    )
    (seed_run / "broker-input.bin").write_bytes(frames)
    return {
        "session": session.hex(),
        "generation": generation.hex(),
        "cookie": cookie.hex(),
        "transition": transition,
        "transition_data": transition_data,
        "artifact_stream": artifact_stream,
        "restore_begin_hash": restore_begin_hash.hex(),
    }


def build_verity(data_path: Path, hash_path: Path) -> str:
    if not data_path.is_file() or data_path.stat().st_size == 0:
        raise GuestError("dm-verity-data-missing")
    command = [
        tool("veritysetup"), "format", str(data_path), str(hash_path),
        "--data-block-size=4096", "--hash-block-size=4096",
    ]
    result = subprocess.run(
        command,
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        raise ProviderHold(_process_failure("dm-verity-format", command, result))
    match = re.search(r"Root hash:\s*([0-9a-f]{64})", (result.stdout or "") + (result.stderr or ""))
    if match is None:
        raise GuestError(_process_failure("dm-verity-format", command, result))
    return match.group(1)


def write_init(root: Path, fixture: dict[str, str]) -> None:
    guest_config = root / "etc/ssh/recovery_guest_config"
    guest_config.parent.mkdir(parents=True, exist_ok=True)
    guest_config.write_text(
        f"""AddressFamily inet
HostKey /run/swz/recovery_host_ed25519.pub
HostKeyAgent /run/swz/custody.sock
AuthorizedKeysFile /root/.ssh/authorized_keys
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
UsePAM no
PermitRootLogin prohibit-password
StrictModes no
PermitTTY no
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
PidFile none
LogLevel QUIET
ForceCommand /usr/local/libexec/swz-dispatcher --bootstrap /usr/local/libexec/swz-bootstrap --session {fixture["session"]} --generation {fixture["generation"]} --cookie {fixture["cookie"]} --owner-pid 1
SetEnv SWZ_ACCEPTED=1 SWZ_SESSION={fixture["session"]} SWZ_GENERATION={fixture["generation"]} SWZ_CONNECTION_COOKIE={fixture["cookie"]} SWZ_LIFECYCLE=ACTIVE
""",
        encoding="ascii",
    )
    guest_config.chmod(0o644)
    init = root / "init"
    init.write_text(
        f"""#!/bin/sh
set -eu
fail() {{
  code="$1"
  echo "SWZ_GUEST_CANDIDATE=FAIL:$code"
  poweroff -f 2>/dev/null || true
  exit "$code"
}}
provider() {{
  detail="$1"
  echo "SWZ_GUEST_PROVIDER=$detail"
  poweroff -f 2>/dev/null || true
  exit 75
}}
mkdir -p /run /mnt
[ -r /proc/mounts ] || fail 40
mkdir -p /sys/fs/selinux
if [ ! -e /sys/fs/selinux/load ]; then
  mount -t selinuxfs selinuxfs /sys/fs/selinux || fail 40
fi
grep -F '/dev/mapper/swz-verity / ext4 ro' /proc/mounts >/dev/null || fail 46
echo SWZ_GUEST_DM_VERITY=PASS
mount -t tmpfs -o mode=0755 tmpfs /run || fail 47
mkdir -p /run/swz/selinux-store
cp -a /var/lib/selinux/. /run/swz/selinux-store/ || fail 48
mount -t tmpfs -o mode=0755 tmpfs /var/lib/selinux || fail 49
cp -a /run/swz/selinux-store/. /var/lib/selinux/ || fail 50
mount -t tmpfs -o mode=1777 tmpfs /tmp || fail 51
mount -t tmpfs -o mode=0755 tmpfs /var/lib/swz || fail 52
mount -t tmpfs -o mode=0700 tmpfs /root/.ssh || fail 53
mkdir -p /run/swz /run/sshd /mnt/verity /dev/mapper /var/lib/swz/store /var/empty
cp -R /etc/swz/qualification/run/. /run/swz/ || fail 54
cp -R /etc/swz/qualification/store/. /var/lib/swz/store/ || fail 54
if [ ! -r /etc/selinux/swz/swz-managed.cil ]; then
  fail 41
fi
LOAD_POLICY=""
for candidate in /sbin/load_policy /usr/sbin/load_policy; do
  if [ -x "$candidate" ]; then LOAD_POLICY="$candidate"; break; fi
done
[ -n "$LOAD_POLICY" ] || provider load_policy
"$LOAD_POLICY" -i || fail 42
SEMODULE=""
for candidate in /usr/bin/semodule /usr/sbin/semodule /bin/semodule /sbin/semodule; do
  if [ -x "$candidate" ]; then SEMODULE="$candidate"; break; fi
done
[ -n "$SEMODULE" ] || provider semodule
"$SEMODULE" -i /etc/selinux/swz/swz-managed.cil || fail 43
SETFILES=""
for candidate in /sbin/setfiles /usr/sbin/setfiles /bin/setfiles /usr/bin/setfiles; do
  if [ -x "$candidate" ]; then SETFILES="$candidate"; break; fi
done
[ -n "$SETFILES" ] || provider setfiles
"$SETFILES" -F /etc/selinux/swz/file_contexts /run/swz /run/sshd /var/lib/swz /usr/local/libexec /opt/swz || fail 44
LS=""
for candidate in /bin/ls /usr/bin/ls; do
  if [ -x "$candidate" ]; then LS="$candidate"; break; fi
done
[ -n "$LS" ] || provider ls
"$LS" -Zd /run/swz /var/lib/swz/store /usr/local/libexec/swz-agent /opt/swz/openssh/sbin/sshd \
  | grep -E 'swz_managed\\.(swz_private_t|swz_store_t|swz_agent_exec_t|swz_sshd_exec_t)' >/dev/null || fail 44
echo SWZ_GUEST_POLICY=PASS
if [ ! -r /sys/fs/selinux/enforce ] || [ "$(cat /sys/fs/selinux/enforce)" != "1" ]; then
  echo SWZ_GUEST_SELINUX=not-enforcing
  fail 45
fi
echo SWZ_GUEST_SELINUX=Enforcing
for component in \
  /usr/local/libexec/swz-supervisor \
  /usr/local/libexec/swz-custodian \
  /usr/local/libexec/swz-dispatcher \
  /usr/local/libexec/swz-bootstrap \
  /usr/local/libexec/swz-broker \
  /usr/local/libexec/swz-agent \
  /usr/local/libexec/swz-launch-base \
  /opt/swz/openssh/sbin/sshd \
  /opt/swz/openssh/bin/ssh-agent \
  /opt/swz/openssh/bin/ssh-add
do
  test -x "$component" || fail 49
done
echo SWZ_GUEST_COMPONENT_CLOSURE=PASS
/opt/swz/openssh/sbin/sshd -V 2>&1 | grep -F 'OpenSSH_10.5p1' >/dev/null || fail 50
echo SWZ_GUEST_OPENSSH=PASS
IP=""
for candidate in /sbin/ip /usr/sbin/ip /bin/ip /usr/bin/ip; do
  if [ -x "$candidate" ]; then IP="$candidate"; break; fi
done
[ -n "$IP" ] || provider ip
if ! "$IP" link show eth0 >/dev/null 2>&1; then
  MODPROBE=""
  for candidate in /sbin/modprobe /usr/sbin/modprobe /bin/modprobe /usr/bin/modprobe; do
    if [ -x "$candidate" ]; then MODPROBE="$candidate"; break; fi
  done
  [ -n "$MODPROBE" ] || provider modprobe
  "$MODPROBE" e1000 || provider network-driver
fi
"$IP" link set lo up || fail 67
"$IP" link set eth0 up || fail 67
"$IP" addr add 10.0.2.15/24 dev eth0 || fail 67

unset SWZ_ACCEPTED SWZ_LAUNCH_AUTHORIZED SWZ_PROCEED_AUTHORIZED SWZ_SESSION \
  SWZ_GENERATION SWZ_CONNECTION_COOKIE SWZ_LIFECYCLE SWZ_BOOTSTRAP
if /opt/swz/openssh/sbin/sshd -i -e -f /etc/ssh/recovery_guest_config \
  </dev/null > /run/swz/sshd-prebarrier-result 2>&1
then
  fail 54
fi
if /usr/local/libexec/swz-agent \
  --source /var/lib/swz/store/guest-source-artifact \
  --target /var/lib/swz/store/prebarrier-restored-artifact \
  --session {fixture["session"]} --generation {fixture["generation"]} \
  --cookie {fixture["cookie"]} --owner-pid 1 \
  --transition {fixture["transition"]} \
  --transition-data {fixture["transition_data"]} \
  --artifact-stream {fixture["artifact_stream"]} \
  --restore-begin-frame {fixture["restore_begin_hash"]} \
  --result-payload "$(cat /run/swz/agent-result-payload.hex)" \
  < /run/swz/agent-proceed.bin > /run/swz/agent-prebarrier-result.bin
then
  fail 54
fi
if /usr/local/libexec/swz-broker < /run/swz/broker-input.bin > /run/swz/broker-prebarrier-result; then
  fail 54
fi
if /usr/local/libexec/swz-dispatcher \
  --bootstrap /usr/local/libexec/swz-bootstrap \
  --session {fixture["session"]} --generation {fixture["generation"]} \
  --cookie {fixture["cookie"]} --owner-pid 1 \
  < /run/swz/accepted.bin > /run/swz/dispatcher-prebarrier-result
then
  fail 54
fi
if /usr/local/libexec/swz-bootstrap \
  --session {fixture["session"]} --generation {fixture["generation"]} \
  --cookie {fixture["cookie"]} --owner-pid 1 \
  < /run/swz/accepted.bin > /run/swz/bootstrap-prebarrier-result
then
  fail 54
fi
if /usr/local/libexec/swz-supervisor --socket /run/swz/prebarrier.sock \
  --generation {fixture["generation"]} --once > /run/swz/prebarrier-supervisor.log 2>&1
then
  fail 54
fi
[ ! -e /run/swz/prebarrier.sock ] || fail 54

/opt/swz/openssh/bin/ssh-keygen -q -t ed25519 -N '' -f /run/swz/recovery_host_ed25519 || fail 54
chmod 600 /run/swz/recovery_host_ed25519
chmod 644 /run/swz/recovery_host_ed25519.pub
if /usr/local/libexec/swz-custodian \
  --socket /run/swz/prebarrier-custody.sock \
  --agent /opt/swz/openssh/bin/ssh-agent \
  --add /opt/swz/openssh/bin/ssh-add \
  --private-key /run/swz/recovery_host_ed25519 \
  --public-key /run/swz/recovery_host_ed25519.pub \
  --owner-pid 1 --cookie {fixture["cookie"]} \
  --session {fixture["session"]} --generation {fixture["generation"]}
then
  fail 54
fi
[ ! -e /run/swz/prebarrier-custody.sock ] || fail 54

export SWZ_ACCEPTED=1
export SWZ_LAUNCH_AUTHORIZED=1
export SWZ_PROCEED_AUTHORIZED=1
export SWZ_SESSION={fixture["session"]}
export SWZ_GENERATION={fixture["generation"]}
export SWZ_CONNECTION_COOKIE={fixture["cookie"]}
export SWZ_LIFECYCLE=ACTIVE

  if /usr/local/libexec/swz-agent \
  --source /var/lib/swz/store/guest-source-artifact \
  --target /var/lib/swz/store/guest-restored-artifact \
  --session {fixture["session"]} --generation {fixture["generation"]} \
  --cookie {fixture["cookie"]} --owner-pid 1 \
  --transition {fixture["transition"]} \
  --transition-data {fixture["transition_data"]} \
  --artifact-stream {fixture["artifact_stream"]} \
  --restore-begin-frame {fixture["restore_begin_hash"]} \
  --result-payload "$(cat /run/swz/agent-result-payload.hex)" \
  < /run/swz/agent-proceed.bin > /run/swz/agent-result.bin
then
  cmp /var/lib/swz/store/guest-source-artifact /var/lib/swz/store/guest-restored-artifact || fail 51
  test -s /run/swz/agent-result.bin || fail 52
  tail -c +57 /run/swz/agent-result.bin > /run/swz/agent-result-payload.out || fail 52
  cmp /run/swz/agent-result-payload.bin /run/swz/agent-result-payload.out || fail 52
else
  fail 53
fi
echo SWZ_GUEST_AGENT=PASS

if /usr/local/libexec/swz-broker < /run/swz/broker-input.bin > /run/swz/broker-result; then
  grep -F 'BROKER_FINAL' /run/swz/broker-result >/dev/null || fail 54
else
  fail 55
fi
echo SWZ_GUEST_BROKER=PASS

SUPERVISOR_SOCKET=/run/swz/listener.sock
/usr/local/libexec/swz-supervisor --socket "$SUPERVISOR_SOCKET" --generation {fixture["generation"]} --once > /run/swz/supervisor.log 2>&1 &
SUPERVISOR_PID=$!
attempt=0
while [ "$attempt" -lt 100 ]; do
  [ -e "$SUPERVISOR_SOCKET" ] && break
  sleep 0.01
  attempt=$((attempt + 1))
done
[ -e "$SUPERVISOR_SOCKET" ] || fail 56
NC=""
for candidate in /usr/bin/nc /bin/nc /usr/bin/netcat /bin/netcat; do
  if [ -x "$candidate" ]; then NC="$candidate"; break; fi
done
[ -n "$NC" ] || provider unix-client
printf 'SWZ-CONNECTION-V1 {fixture["generation"]}\\n' | "$NC" -U "$SUPERVISOR_SOCKET" > /run/swz/supervisor-response || fail 57
grep -F 'SWZ-CONNECTION-ACCEPTED' /run/swz/supervisor-response >/dev/null || fail 58
if wait "$SUPERVISOR_PID"; then :; else fail 59; fi
[ ! -e "$SUPERVISOR_SOCKET" ] || fail 60
echo SWZ_GUEST_SUPERVISOR=PASS

"$SETFILES" -F /etc/selinux/swz/file_contexts /run/swz || fail 61
/usr/local/libexec/swz-custodian \
  --socket /run/swz/custody.sock \
  --agent /opt/swz/openssh/bin/ssh-agent \
  --add /opt/swz/openssh/bin/ssh-add \
  --private-key /run/swz/recovery_host_ed25519 \
  --public-key /run/swz/recovery_host_ed25519.pub \
  --owner-pid 1 --cookie {fixture["cookie"]} \
  --session {fixture["session"]} --generation {fixture["generation"]} &
CUSTODIAN_PID=$!
attempt=0
while [ "$attempt" -lt 100 ]; do
  [ -e /run/swz/custody.sock ] && break
  sleep 0.01
  attempt=$((attempt + 1))
done
[ -e /run/swz/custody.sock ] || fail 62
if SSH_AUTH_SOCK=/run/swz/custody.sock /opt/swz/openssh/bin/ssh-add -T /run/swz/recovery_host_ed25519.pub > /run/swz/sign-result 2>&1; then :; else fail 63; fi
if wait "$CUSTODIAN_PID"; then :; else fail 64; fi
[ ! -e /run/swz/custody.sock ] || fail 65
echo SWZ_GUEST_CUSTODY=PASS

grep -q '^sshd:' /etc/passwd 2>/dev/null || fail 68
grep -q '^sshd:' /etc/group 2>/dev/null || fail 68
/opt/swz/openssh/bin/ssh-keygen -q -t ed25519 -N '' -f /run/swz/client_ed25519 || fail 68
mkdir -p /root/.ssh || fail 68
cat /run/swz/client_ed25519.pub > /root/.ssh/authorized_keys || fail 68
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys
"$SETFILES" -F /etc/selinux/swz/file_contexts /root/.ssh || fail 68
/usr/local/libexec/swz-custodian \
  --socket /run/swz/custody.sock \
  --agent /opt/swz/openssh/bin/ssh-agent \
  --add /opt/swz/openssh/bin/ssh-add \
  --private-key /run/swz/recovery_host_ed25519 \
  --public-key /run/swz/recovery_host_ed25519.pub \
  --owner-pid 1 --cookie {fixture["cookie"]} \
  --session {fixture["session"]} --generation {fixture["generation"]} &
SSH_CUSTODIAN_PID=$!
attempt=0
while [ "$attempt" -lt 100 ]; do
  [ -e /run/swz/custody.sock ] && break
  sleep 0.01
  attempt=$((attempt + 1))
done
[ -e /run/swz/custody.sock ] || fail 69
/usr/local/libexec/swz-supervisor --inetd --address 10.0.2.15 --port 22222 \
  --sshd /opt/swz/openssh/sbin/sshd --config /etc/ssh/recovery_guest_config \
  --generation {fixture["generation"]} > /run/swz/inetd-supervisor.log 2>&1 &
INETD_SUPERVISOR_PID=$!
attempt=0
while [ "$attempt" -lt 100 ]; do
  if grep -F 'SUPERVISOR_INETD_ACTIVE' /run/swz/inetd-supervisor.log >/dev/null 2>&1; then break; fi
  kill -0 "$INETD_SUPERVISOR_PID" 2>/dev/null || fail 69
  sleep 0.01
  attempt=$((attempt + 1))
done
grep -F 'SUPERVISOR_INETD_ACTIVE' /run/swz/inetd-supervisor.log >/dev/null || fail 69
if /opt/swz/openssh/bin/ssh -q -i /run/swz/client_ed25519 -p 22222 \
  -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o PasswordAuthentication=no -o PubkeyAuthentication=yes \
  root@10.0.2.15 ignored-command < /run/swz/accepted.bin > /run/swz/ssh-response
then
  :
else
  kill -TERM "$INETD_SUPERVISOR_PID" 2>/dev/null || true
  wait "$INETD_SUPERVISOR_PID" 2>/dev/null || true
  fail 70
fi
if wait "$INETD_SUPERVISOR_PID"; then :; else fail 70; fi
grep -F 'SUPERVISOR_INETD_RETIRED' /run/swz/inetd-supervisor.log >/dev/null || fail 70
printf 'SWZFRM02' > /run/swz/ssh-header-magic
dd if=/run/swz/ssh-response of=/run/swz/ssh-magic bs=1 count=8 2>/dev/null || fail 71
cmp /run/swz/ssh-header-magic /run/swz/ssh-magic || fail 71
printf '\\002\\002\\002\\000' > /run/swz/ssh-header-route
dd if=/run/swz/ssh-response of=/run/swz/ssh-route bs=1 skip=8 count=4 2>/dev/null || fail 71
cmp /run/swz/ssh-header-route /run/swz/ssh-route || fail 71
printf '\\000\\000\\000\\000\\000\\000\\000\\002' > /run/swz/ssh-sequence
dd if=/run/swz/ssh-response of=/run/swz/ssh-sequence-out bs=1 skip=12 count=8 2>/dev/null || fail 71
cmp /run/swz/ssh-sequence /run/swz/ssh-sequence-out || fail 71
tail -c +57 /run/swz/ssh-response > /run/swz/ssh-payload || fail 71
cmp /run/swz/challenge-payload.bin /run/swz/ssh-payload || fail 71
if wait "$SSH_CUSTODIAN_PID"; then :; else fail 72; fi
[ ! -e /run/swz/custody.sock ] || fail 73
echo SWZ_GUEST_OPENSSH_SESSION=PASS

RUNCON=""
for candidate in /usr/bin/runcon /bin/runcon; do
  if [ -x "$candidate" ]; then RUNCON="$candidate"; break; fi
done
[ -n "$RUNCON" ] || provider runcon
if "$RUNCON" -t swz_managed.swz_dispatcher_t -- /bin/touch /var/lib/swz/store/denied-by-selinux; then
  fail 66
fi
DMESG=""
for candidate in /bin/dmesg /usr/bin/dmesg; do
  if [ -x "$candidate" ]; then DMESG="$candidate"; break; fi
done
[ -n "$DMESG" ] || provider dmesg
"$DMESG" 2>/dev/null | grep -F 'avc:  denied' >/dev/null || provider selinux-denial-audit
echo SWZ_GUEST_SELINUX_DENIAL=PASS
echo SWZ_GUEST_RUNTIME=PASS
poweroff -f
""",
        encoding="ascii",
    )
    init.chmod(0o755)


def make_initramfs(root: Path, output: Path) -> None:
    cpio = tool("cpio")
    gzip = tool("gzip")
    names = "\n".join(str(path.relative_to(root)) for path in sorted(root.rglob("*"))) + "\n"
    try:
        command = [cpio, "-o", "-H", "newc", "--owner=0:0"]
        result = subprocess.run(
            command,
            cwd=root,
            input=names.encode("utf-8"),
            capture_output=True,
            check=False,
        )
    except OSError as error:
        raise ProviderHold(
            f"stage=initramfs-cpio; command={_safe_command(command)}; "
            f"process-unavailable={type(error).__name__}"
        ) from error
    if result.returncode != 0:
        raise ProviderHold(_process_failure("initramfs-cpio", command, result))
    gzip_command = [gzip, "-n"]
    compressed = subprocess.run(gzip_command, input=result.stdout, capture_output=True, check=False)
    if compressed.returncode != 0:
        raise ProviderHold(_process_failure("initramfs-gzip", gzip_command, compressed))
    output.write_bytes(compressed.stdout)


def run_guest(kernel: Path, initramfs: Path, data: Path, hash_tree: Path, root_hash: str, timeout: int) -> str:
    qemu = tool("qemu-system-x86_64")
    command = [
        qemu,
        "-machine", "q35",
        "-accel", "tcg,thread=single",
        "-m", "512M",
        "-smp", "1",
        "-nographic",
        "-no-reboot",
        "-monitor", "none",
        "-serial", "stdio",
        "-kernel", str(kernel),
        "-initrd", str(initramfs),
        "-append", "console=ttyS0 selinux=1 enforcing=1 panic=1 net.ifnames=0",
        "-netdev", "user,id=net0,net=10.0.2.0/24,dhcpstart=10.0.2.15",
        "-device", "e1000,netdev=net0",
        "-drive", f"file={data},if=virtio,format=raw,readonly=on",
        "-drive", f"file={hash_tree},if=virtio,format=raw,readonly=on",
    ]
    try:
        result = subprocess.run(command, check=False, text=True, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        raise GuestError(f"stage=guest-qemu; command={_safe_command(command)}; timeout={timeout}s") from error
    except OSError as error:
        raise ProviderHold(
            f"stage=guest-qemu; command={_safe_command(command)}; process-unavailable={type(error).__name__}"
        ) from error
    output = (result.stdout or "") + (result.stderr or "")
    provider_markers = [line for line in output.splitlines() if line.startswith("SWZ_GUEST_PROVIDER=")]
    if provider_markers:
        raise ProviderHold(_process_failure("guest-qemu", command, result) + f"; marker={provider_markers[-1]}")
    required = (
        "SWZ_GUEST_SELINUX=Enforcing",
        "SWZ_GUEST_POLICY=PASS",
        "SWZ_GUEST_DM_VERITY=PASS",
        "SWZ_GUEST_COMPONENT_CLOSURE=PASS",
        "SWZ_GUEST_OPENSSH=PASS",
        "SWZ_GUEST_OPENSSH_SESSION=PASS",
        "SWZ_GUEST_AGENT=PASS",
        "SWZ_GUEST_BROKER=PASS",
        "SWZ_GUEST_SUPERVISOR=PASS",
        "SWZ_GUEST_CUSTODY=PASS",
        "SWZ_GUEST_SELINUX_DENIAL=PASS",
        "SWZ_GUEST_RUNTIME=PASS",
    )
    if result.returncode != 0 or any(marker not in output for marker in required):
        raise GuestError(_process_failure("guest-qemu", command, result))
    return output


def qualify(args: argparse.Namespace) -> dict[str, str]:
    if platform.system() != "Linux":
        raise ProviderHold("guest-linux-required")
    kernel = choose_kernel(args.kernel)
    for name in ("qemu-system-x86_64", "veritysetup", "cpio", "gzip", "mkfs.ext4", "debugfs", "mount", "switch_root", "sh", "dd"):
        tool(name)
    if args.guest_root is None:
        raise ProviderHold("qualified-guest-root-required")
    if args.build_output is None or args.policy is None or args.file_contexts is None or not args.policy.is_file() or not args.file_contexts.is_file():
        raise ProviderHold("candidate-policy-and-contexts-required")
    try:
        manifest = json.loads((args.build_output / "build-manifest.json").read_text(encoding="utf-8"))
        source_files = manifest["source_files"]
        policy_digest = hashlib.sha256(args.policy.read_bytes()).hexdigest()
        contexts_digest = hashlib.sha256(args.file_contexts.read_bytes()).hexdigest()
    except (KeyError, OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GuestError("candidate-policy-provenance-unavailable") from error
    if policy_digest != source_files.get("selinux.cil") or contexts_digest != source_files.get("file_contexts"):
        raise GuestError("candidate-policy-provenance-mismatch")
    with tempfile.TemporaryDirectory(prefix="swz-guest-") as temporary:
        work = Path(temporary)
        initrd_root = work / "root"
        initrd_root.mkdir()
        copy_tree(args.guest_root, initrd_root)
        stage_candidate(args.build_output, initrd_root)
        prepare_writable_runtime_dirs(initrd_root)
        destination_policy = initrd_root / "etc/selinux/swz/swz-managed.cil"
        destination_policy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(args.policy, destination_policy)
        destination_contexts = initrd_root / "etc/selinux/swz/file_contexts"
        destination_contexts.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(args.file_contexts, destination_contexts)
        data = work / "verity-data.img"
        hash_tree = work / "verity-hash.img"
        fixture = build_guest_fixtures(initrd_root)
        write_init(initrd_root, fixture)
        build_rootfs(data, initrd_root)
        root_hash = build_verity(data, hash_tree)
        boot_root = work / "boot-root"
        boot_root.mkdir()
        for name, destination in (
            ("sh", "bin/sh"),
            ("mount", "bin/mount"),
            ("switch_root", "sbin/switch_root"),
            ("veritysetup", "sbin/veritysetup"),
            ("dd", "bin/dd"),
        ):
            stage_boot_tool(args.guest_root, boot_root, name, destination)
        write_boot_init(boot_root, root_hash)
        initramfs = work / "swz-managed.cpio.gz"
        make_initramfs(boot_root, initramfs)
        transcript = run_guest(kernel, initramfs, data, hash_tree, root_hash, args.timeout)
        transcript_digest = hashlib.sha256(transcript.encode("utf-8")).hexdigest()
    return {
        "status": "PASS",
        "guest": "qemu-system-x86_64",
        "kernel": str(kernel),
        "kernel_sha256": hashlib.sha256(kernel.read_bytes()).hexdigest(),
        "verity_root_hash": root_hash,
        "guest_transcript_sha256": transcript_digest,
        "selinux": "Enforcing",
        "dm_verity": "PASS",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-output", type=Path, required=True)
    parser.add_argument("--guest-root", type=Path)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--file-contexts", type=Path)
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = qualify(args)
    except ProviderHold as error:
        print(f"QUALIFICATION_PROVIDER_HOLD={error}", file=sys.stderr)
        return 75
    except (GuestError, OSError, subprocess.SubprocessError) as error:
        print(f"CANDIDATE_DEFECT={error}", file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    print("DISPOSABLE_GUEST=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
