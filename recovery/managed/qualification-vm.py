"""Boot the disposable enforcing guest used by the mandatory G3 proof.

The guest is assembled in a temporary directory and is never an installation
or an enrollment path.  The only key material created here is an ephemeral
qualification seed.  The host-key seed is opened by the guest supervisor and
passed to the direct custodian as an inherited descriptor; the OpenSSH
process receives no private host-key material.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import platform
import re
import shlex
import shutil
import stat
import struct
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
    text = value.decode("utf-8", "replace") if isinstance(value, bytes) else ("" if value is None else str(value))
    if len(text) <= MAX_DIAGNOSTIC_CHARS:
        return text
    half = MAX_DIAGNOSTIC_CHARS // 2
    return text[:half] + "\n...[truncated]...\n" + text[-half:]


def _safe_command(command: list[str]) -> str:
    return shlex.join(str(value) for value in command)


def _process_failure(stage: str, command: list[str], result: object) -> str:
    return (
        f"stage={stage}; command={_safe_command(command)}; "
        f"returncode={getattr(result, 'returncode', 'unknown')}; "
        f"stdout={_bounded(getattr(result, 'stdout', None))}; "
        f"stderr={_bounded(getattr(result, 'stderr', None))}"
    )


def tool(name: str) -> str:
    value = shutil.which(name)
    if value is None:
        raise ProviderHold(f"guest-tool-unavailable:{name}")
    return value


def run(command: list[str], *, cwd: Path | None = None, input_bytes: bytes | None = None, timeout: int = 120) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            input=input_bytes,
            check=False,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise GuestError(f"stage={command[0]}; timeout={timeout}s") from error
    except OSError as error:
        raise ProviderHold(f"stage={command[0]}; process-unavailable={type(error).__name__}") from error


def choose_kernel(explicit: Path | None) -> Path:
    if explicit is not None:
        if not explicit.is_file() or explicit.is_symlink():
            raise ProviderHold("guest-kernel-missing")
        return explicit
    candidates = sorted(Path("/boot").glob("vmlinuz-*"))
    if not candidates:
        raise ProviderHold("guest-kernel-not-installed")
    return candidates[-1]


def copy_tree(source: Path, destination: Path) -> None:
    if not source.is_dir():
        raise ProviderHold("guest-root-missing")
    source_root = source.resolve()
    for path in source.rglob("*"):
        relative = path.relative_to(source)
        target = destination / relative
        if path.is_symlink():
            link_text = path.readlink()
            link_target = source / str(link_text).lstrip("/") if link_text.is_absolute() else path.parent / link_text
            resolved = link_target.resolve()
            if source_root not in resolved.parents and resolved != source_root:
                raise GuestError(f"guest-root-link-outside:{relative}")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(link_text, target_is_directory=path.is_dir())
        elif path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif path.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
        else:
            raise GuestError(f"guest-root-special-file:{relative}")


def stage_file(source: Path, destination: Path, *, executable: bool = False) -> None:
    if not source.is_file() or source.is_symlink():
        raise ProviderHold(f"candidate-file-missing:{source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    if executable:
        destination.chmod(destination.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def stage_runtime_dependencies(binary: Path, root: Path) -> None:
    ldd = tool("ldd")
    command = [ldd, str(binary)]
    result = run(command, timeout=60)
    if result.returncode != 0:
        raise GuestError(_process_failure("guest-runtime-dependencies", command, result))
    dependencies: set[Path] = set()
    text = (result.stdout or b"").decode("utf-8", "replace")
    for line in text.splitlines():
        match = re.search(r"=>\s+(/[\w./+-]+)", line) or re.match(r"\s*(/[\w./+-]+)", line)
        if match is None:
            continue
        dependency = Path(match.group(1))
        allowed = (Path("/lib"), Path("/lib64"), Path("/usr/lib"), Path("/usr/lib64"))
        if not any(dependency == prefix or prefix in dependency.parents for prefix in allowed):
            raise GuestError(f"guest-runtime-dependency-outside-system:{dependency}")
        dependencies.add(dependency)
    if not dependencies:
        raise GuestError(f"guest-runtime-dependencies-empty:{binary.name}")
    for dependency in sorted(dependencies):
        if not dependency.is_file():
            raise GuestError(f"guest-runtime-dependency-missing:{dependency}")
        destination = root / dependency.relative_to("/")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(dependency, destination)


def stage_candidate(build_output: Path, root: Path) -> None:
    manifest_path = build_output / "build-manifest.json"
    if not manifest_path.is_file():
        raise ProviderHold("candidate-build-manifest-missing")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GuestError("candidate-build-manifest-invalid") from error
    if not isinstance(manifest, dict) or manifest.get("schema") != "swz-managed-build-manifest.v1":
        raise GuestError("candidate-build-manifest-schema-invalid")
    native = manifest.get("native")
    if not isinstance(native, dict):
        raise GuestError("candidate-build-native-manifest-invalid")
    for name in (
        "swz-supervisor", "swz-custodian", "swz-dispatcher", "swz-bootstrap",
        "swz-broker", "swz-agent", "swz-launch-base",
    ):
        source = build_output / "native" / name
        if hashlib.sha256(source.read_bytes()).hexdigest() != native.get(name):
            raise GuestError(f"candidate-native-digest-mismatch:{name}")
        stage_runtime_dependencies(source, root)
        stage_file(source, root / "usr/local/libexec" / name, executable=True)
    openssh = manifest.get("openssh")
    if not isinstance(openssh, dict) or openssh.get("version") != "OpenSSH_10.5p1":
        raise GuestError("candidate-openssh-manifest-invalid")
    for name, digest_key, destination in (
        ("sshd", "binary_sha256", "sbin/sshd"),
        ("ssh", "ssh_sha256", "bin/ssh"),
        ("ssh-keygen", "ssh_keygen_sha256", "bin/ssh-keygen"),
    ):
        source = build_output / "openssh" / ("sbin" if name == "sshd" else "bin") / name
        if hashlib.sha256(source.read_bytes()).hexdigest() != openssh.get(digest_key):
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
        expected = manifest.get("source_files", {}).get(source_name)
        source = HERE / source_name
        if not isinstance(expected, str) or hashlib.sha256(source.read_bytes()).hexdigest() != expected:
            raise GuestError(f"candidate-source-digest-mismatch:{source_name}")
        stage_file(source, root / destination)


def _ed25519_public(seed: bytes) -> bytes:
    """Derive the RFC 8032 public point for the disposable test seed."""

    if len(seed) != 32:
        raise GuestError("qualification-seed-length")
    prime = 2**255 - 19
    d = (-121665 * pow(121666, prime - 2, prime)) % prime
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    base_x = 15112221349535400772501151409588531511454012693041857206046113283949847762202
    base_y = 46316835694926478169428394003475163141307993866256225615783033603165251855960

    def add(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
        x1, y1 = left
        x2, y2 = right
        product = d * x1 * x2 * y1 * y2
        return (
            ((x1 * y2 + y1 * x2) * pow(1 + product, prime - 2, prime)) % prime,
            ((y1 * y2 + x1 * x2) * pow(1 - product, prime - 2, prime)) % prime,
        )

    point = (0, 1)
    addend = (base_x, base_y)
    for bit in range(255):
        if (scalar >> bit) & 1:
            point = add(point, addend)
        addend = add(addend, addend)
    x, y = point
    encoded = bytearray(y.to_bytes(32, "little"))
    encoded[31] |= (x & 1) << 7
    return bytes(encoded)


def _host_public_line(seed: bytes) -> bytes:
    public = _ed25519_public(seed)
    blob = struct.pack("!I", 11) + b"ssh-ed25519" + struct.pack("!I", 32) + public
    return b"ssh-ed25519 " + base64.b64encode(blob) + b" swz-g3-ephemeral\n"


def prepare_test_material(root: Path) -> None:
    seed = hashlib.sha256(os.urandom(64)).digest()
    seed_path = root / "var/lib/swooshz-recovery/host-key/ed25519.seed"
    seed_path.parent.mkdir(parents=True, exist_ok=True)
    seed_path.write_bytes(seed)
    seed_path.chmod(0o400)
    public_path = root / "etc/ssh/recovery_host_ed25519_key.pub"
    public_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.write_bytes(_host_public_line(seed))
    public_path.chmod(0o644)
    keygen = root / "opt/swz/openssh/bin/ssh-keygen"
    client_path = root / "etc/swz/qualification/client_ed25519"
    client_path.parent.mkdir(parents=True, exist_ok=True)
    if not keygen.is_file():
        raise GuestError("qualification-client-keygen-missing")
    keygen_command = [str(keygen), "-q", "-t", "ed25519", "-N", "", "-f", str(client_path)]
    result = run(keygen_command, timeout=60)
    if result.returncode != 0:
        raise GuestError(_process_failure("qualification-client-keygen", keygen_command, result))
    client_public = client_path.with_name(client_path.name + ".pub")
    authorized = root / "etc/ssh/recovery_authorized_keys"
    if not client_public.is_file():
        raise GuestError("qualification-client-public-key-missing")
    authorized.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(client_public, authorized)
    client_path.chmod(0o400)
    client_public.chmod(0o444)
    authorized.chmod(0o644)


def prepare_writable_runtime_dirs(root: Path) -> None:
    for relative in ("root/.ssh", "var/lib/swz", "var/empty", "tmp", "run", "run/sshd"):
        (root / relative).mkdir(parents=True, exist_ok=True)
    # OpenSSH invokes the fixed ForceCommand through the account shell.  The
    # disposable proof image therefore uses /bin/sh for this test account;
    # the production accounts contract remains non-interactive/nologin and
    # the fixed dispatcher still rejects every non-protocol command.
    for path, record in (
        (root / "etc/passwd", "sshd:x:74:74:sshd:/var/empty:/bin/false\n"),
        (root / "etc/group", "sshd:x:74:\n"),
        (root / "etc/passwd", "swz-recovery:x:2001:2001:swz-recovery:/var/empty:/bin/sh\n"),
        (root / "etc/group", "swz-recovery:x:2001:\n"),
    ):
        if not path.is_file():
            raise ProviderHold(f"guest-account-file-missing:{path.name}")
        content = path.read_text(encoding="utf-8")
        name = record.split(":", 1)[0]
        if not any(line.startswith(name + ":") for line in content.splitlines()):
            path.write_text(content + ("" if content.endswith("\n") else "\n") + record, encoding="utf-8")
    # The base image may contain unrelated distribution helpers.  The
    # disposable runtime closure intentionally does not expose them.
    for relative in ("usr/bin/ssh-agent", "usr/bin/ssh-add", "bin/ssh-agent", "bin/ssh-add"):
        candidate = root / relative
        if candidate.is_symlink() or candidate.is_file():
            candidate.unlink()


def build_guest_fixtures(root: Path) -> dict[str, str]:
    backend = _load_backend()
    session = bytes.fromhex("11" * 32)
    generation = bytes.fromhex("22" * 32)
    connection = bytes.fromhex("33" * 32)
    cookie = bytes.fromhex("44" * 32)
    nonce = lambda value: bytes([value]) * 32
    artifact = b"guest-native-restore\n"
    tagged = backend.store_commitment("guest-field", b"guest-field")
    artifact_stream = backend.store_commitment("artifact-stream", artifact)
    transition_record = {
        "schema": "restore-ledger-transition-data.v2", "version": 2,
        "epoch_ref": "guest-epoch-001", "authority_ref": "guest-authority-001",
        "barrier_utc": "2026-09-07T00:00:00Z", "barrier_commitment": tagged,
        "runner_commitment": tagged, "bundle_commitment": tagged,
        "image_commitment": tagged, "target_commitment": tagged,
        "isolation_commitment": tagged, "artifact_commitment": tagged,
        "artifact_stream_commitment": artifact_stream, "pre_cas_ledger_digest": tagged,
    }
    transition_bytes = backend.store_bytes(transition_record)
    transition_wire = backend.StoreWire.from_bytes("restore-ledger-transition-data.v2", transition_bytes)
    transition_data = backend.store_commitment("restore-ledger-transition", transition_bytes)
    transition_id = backend.transition_id(transition_bytes)
    discovery_payload, discovery_hash = backend.build_discovery(
        session, 23, "guest-source-artifact", tagged, tagged, tagged, tagged, artifact_stream,
    )
    evidence_record = {
        "schema": "restore-begin-evidence.v2", "epoch_ref": "guest-epoch-001",
        "transition_id": transition_id, "transition_data_commitment": transition_data,
        "artifact_commitment": tagged, "artifact_stream_commitment": artifact_stream,
        "ledger_state": "CONSUMED", "record_state": "ACTIVE",
        "spool_previous_stage": "RUNNER_STARTED", "frame_sequence": 3,
        "previous_frame_hash": tagged, "frame_hash": tagged,
        "spool_commitment": tagged, "ledger_after_digest": tagged,
        "durability": {
            "file_flush_verified": True, "readback_verified": True,
            "atomic_authority_transition": True, "directory_flush_verified": True,
        },
    }
    evidence_bytes = backend.store_bytes(evidence_record)
    evidence_wire = backend.StoreWire.from_bytes("restore-begin-evidence.v2", evidence_bytes)
    restore_begin_payload = backend.build_restore_begin(
        session, discovery_hash, transition_wire, evidence_wire, tagged,
    )
    restore_begin_frame = backend.build_frame(
        backend.DIRECTION_REMOTE_TO_LOCAL, "RESTORE_BEGIN", 7, nonce(0x66), restore_begin_payload,
    )
    restore_begin_hash = backend.frame_hash(restore_begin_frame)
    proceed_payload, proceed_commitment = backend.build_proceed(
        session, transition_id, transition_data, restore_begin_hash,
    )
    proceed_frame = backend.build_frame(
        backend.DIRECTION_LOCAL_TO_REMOTE, "PROCEED", 8, nonce(0x77), proceed_payload,
    )
    result_record = {
        "schema": "swz-recovery-result.v2", "classification": "SUCCESS", "stage": "RESTORE",
        "epoch_ref": "guest-epoch-001", "authority_ref": "guest-authority-001",
        "barrier_utc": "2026-09-07T00:00:00Z", "ssh_endpoint_commitment": tagged,
        "epoch_commitment": tagged, "authority_commitment": tagged,
        "barrier_commitment": tagged, "runner_commitment": tagged,
        "bundle_commitment": tagged, "launcher_commitment": tagged,
        "agent_commitment": tagged, "image_commitment": tagged,
        "target_commitment": tagged, "isolation_commitment": tagged,
        "artifact_commitment": tagged, "artifact_stream_commitment": artifact_stream,
        "transition_id": transition_id, "pre_cas_ledger_digest": tagged,
        "transition_data_commitment": transition_data, "consumed_record_commitment": tagged,
        "restore_begin_commitment": backend.store_commitment("restore-begin-evidence", evidence_bytes),
        "process_commitment": tagged, "restore_commitment": backend.store_commitment("restore", artifact),
        "cleanup_commitment": tagged, "stdout_capture_commitment": tagged,
        "stderr_capture_commitment": tagged, "result_code": 0, "restore_count": 1,
        "exit_status": 0, "stdin_eof": True, "stdout_eof": True, "stderr_eof": True,
        "trailing_unframed_bytes": False, "terminal_input_eof": True,
        "terminal_input_trailing_bytes": False, "cleanup_state": "CLEAN",
    }
    result_wire = backend.StoreWire.from_bytes(
        "swz-recovery-result.v2", backend.store_bytes(result_record),
    )
    result_payload, _ = backend.build_result(
        session, transition_id, backend.frame_hash(proceed_frame), proceed_commitment, result_wire,
    )
    boot_payload = backend.managed_json(["BOOT", 2, backend.MANAGED_SCHEMA, session.hex()])
    evidence_payload = backend.managed_json(["EVIDENCE", 2, backend.MANAGED_SCHEMA, session.hex(), "guest-evidence"])
    accept_payload = backend.managed_json(["ACCEPT", 2, backend.MANAGED_SCHEMA, session.hex(), "guest-accept"])
    accepted_payload = backend.managed_json(["ACCEPTED", 2, backend.MANAGED_SCHEMA, session.hex()])
    input_frames = [
        backend.build_frame(backend.DIRECTION_LOCAL_TO_REMOTE, "BOOT", 1, nonce(0x11), boot_payload),
        backend.build_frame(backend.DIRECTION_LOCAL_TO_REMOTE, "EVIDENCE", 3, nonce(0x22), evidence_payload),
        backend.build_frame(backend.DIRECTION_REMOTE_TO_LOCAL, "ACCEPT", 4, nonce(0x33), accept_payload),
    ]
    broker_frames = [
        (backend.DIRECTION_REMOTE_TO_LOCAL, "ACCEPTED", 5, accepted_payload),
        (backend.DIRECTION_LOCAL_TO_REMOTE, "DISCOVERY", 6, discovery_payload),
        (backend.DIRECTION_REMOTE_TO_LOCAL, "RESTORE_BEGIN", 7, restore_begin_payload),
        (backend.DIRECTION_LOCAL_TO_REMOTE, "PROCEED", 8, proceed_payload),
        (backend.DIRECTION_REMOTE_TO_LOCAL, "RESULT", 9, result_payload),
    ]
    input_frames.extend(
        backend.build_frame(direction, message, sequence, nonce(sequence), payload)
        for direction, message, sequence, payload in broker_frames
    )
    seed = root / "etc/swz/qualification"
    source = seed / "store/guest-source-artifact"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(artifact)
    run_root = seed / "run"
    run_root.mkdir(parents=True, exist_ok=True)
    (run_root / "client-input.bin").write_bytes(b"".join(input_frames))
    (run_root / "agent-proceed.bin").write_bytes(proceed_frame)
    (run_root / "agent-result-payload.bin").write_bytes(result_payload)
    (run_root / "agent-result-payload.hex").write_text(result_payload.hex() + "\n", encoding="ascii")
    (run_root / "broker-input.bin").write_bytes(b"".join(
        backend.build_frame(direction, message, sequence, nonce(sequence), payload)
        for direction, message, sequence, payload in broker_frames
    ))
    (run_root / "challenge-payload.bin").write_bytes(
        backend.managed_json(["CHALLENGE", 2, backend.MANAGED_SCHEMA, session.hex()])
    )
    return {
        "session": session.hex(), "generation": generation.hex(),
        "connection": connection.hex(), "cookie": cookie.hex(),
        "transition": transition_id, "transition_data": transition_data,
        "artifact_stream": artifact_stream, "restore_begin_hash": restore_begin_hash.hex(),
    }


def set_image_contexts(image: Path) -> None:
    debugfs = tool("debugfs")
    labels = (
        ("etc/swz", "system_u:object_r:etc_t:s0"),
        ("etc/swz/qualification", "system_u:object_r:etc_t:s0"),
        ("etc/swz/qualification/run", "system_u:object_r:etc_t:s0"),
        ("etc/swz/qualification/run/client-input.bin", "system_u:object_r:etc_t:s0"),
        ("etc/swz/qualification/run/agent-proceed.bin", "system_u:object_r:etc_t:s0"),
        ("etc/swz/qualification/run/agent-result-payload.bin", "system_u:object_r:etc_t:s0"),
        ("etc/swz/qualification/run/agent-result-payload.hex", "system_u:object_r:etc_t:s0"),
        ("etc/swz/qualification/run/broker-input.bin", "system_u:object_r:etc_t:s0"),
        ("etc/swz/qualification/run/challenge-payload.bin", "system_u:object_r:etc_t:s0"),
        ("etc/swz/qualification/store", "system_u:object_r:etc_t:s0"),
        ("etc/swz/qualification/store/guest-source-artifact", "system_u:object_r:etc_t:s0"),
        ("etc/swz/qualification/client_ed25519", "system_u:object_r:etc_t:s0"),
        ("etc/swz/qualification/client_ed25519.pub", "system_u:object_r:etc_t:s0"),
        ("etc/ssh/recovery_authorized_keys", "system_u:object_r:swz_managed.swz_authorized_key_t:s0"),
        ("var/lib/swooshz-recovery/host-key/ed25519.seed", "system_u:object_r:swz_managed.swz_custody_key_t:s0"),
        ("etc/ssh/recovery_host_ed25519_key.pub", "system_u:object_r:swz_managed.swz_host_public_key_t:s0"),
        ("etc/ssh/recovery_guest_config", "system_u:object_r:etc_t:s0"),
        ("etc/ssh/recovery_sshd_config", "system_u:object_r:etc_t:s0"),
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
    )
    for relative, label in labels:
        if not image.exists():
            raise GuestError("guest-image-missing")
        for command_text in (
            f"ea_set /{relative} security.selinux {label}",
            f"set_inode_field /{relative} uid 0",
            f"set_inode_field /{relative} gid 0",
        ):
            command = [debugfs, "-w", "-R", command_text, str(image)]
            result = run(command, timeout=60)
            output = ((result.stdout or b"") + (result.stderr or b"")).lower()
            if result.returncode != 0 or any(marker in output for marker in (b"error", b"failed", b"not found", b"no such")):
                raise GuestError(_process_failure(f"guest-image-context:{relative}", command, result))


def build_rootfs(data_path: Path, root: Path) -> None:
    mkfs = tool("mkfs.ext4")
    used = sum(path.stat().st_size for path in root.rglob("*") if path.is_file() and not path.is_symlink())
    size = max(512 * 1024 * 1024, used + 256 * 1024 * 1024)
    size = ((size + 4095) // 4096) * 4096
    with data_path.open("wb") as stream:
        stream.truncate(size)
    command = [mkfs, "-q", "-F", "-O", "ext_attr", "-d", str(root), str(data_path)]
    result = run(command, timeout=300)
    if result.returncode != 0:
        raise GuestError(_process_failure("guest-rootfs-format", command, result))
    set_image_contexts(data_path)


def stage_boot_tool(guest_root: Path, boot_root: Path, name: str, destination: str) -> None:
    host_path = Path(tool(name)).resolve()
    try:
        relative = host_path.relative_to(Path("/"))
    except ValueError as error:
        raise GuestError(f"guest-boot-tool-path-invalid:{name}") from error
    source = guest_root / relative
    stage_runtime_dependencies(host_path, boot_root)
    stage_file(source, boot_root / destination, executable=True)


def write_boot_init(root: Path, root_hash: str) -> None:
    init = root / "init"
    init.write_text(
        f"""#!/bin/sh
set -eu
fail() {{ echo "SWZ_GUEST_CANDIDATE=FAIL:$1"; exit "$1"; }}
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


def _load_backend() -> object:
    spec = importlib.util.spec_from_file_location("swz_guest_backend", HERE / "backend.py")
    if spec is None or spec.loader is None:
        raise GuestError("guest-backend-unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def build_verity(data_path: Path, hash_path: Path) -> str:
    if not data_path.is_file() or data_path.stat().st_size == 0:
        raise GuestError("dm-verity-data-missing")
    command = [tool("veritysetup"), "format", str(data_path), str(hash_path), "--data-block-size=4096", "--hash-block-size=4096"]
    result = run(command, timeout=300)
    if result.returncode != 0:
        raise ProviderHold(_process_failure("dm-verity-format", command, result))
    output = ((result.stdout or b"") + (result.stderr or b"")).decode("utf-8", "replace")
    match = re.search(r"Root hash:\s*([0-9a-f]{64})", output)
    if match is None:
        raise GuestError(_process_failure("dm-verity-format", command, result))
    return match.group(1)


def write_guest_config(root: Path) -> None:
    config = root / "etc/ssh/recovery_guest_config"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(
        """AddressFamily inet
Port 22222
ListenAddress 10.0.2.15
HostKey /etc/ssh/recovery_host_ed25519_key.pub
HostKeyAgent /run/swz/recovery-hostkey-agent.sock
AuthorizedKeysFile /run/swz/authorized_keys
PubkeyAuthentication yes
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
PermitRootLogin prohibit-password
StrictModes yes
PermitTTY no
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
PidFile none
LogLevel QUIET
ForceCommand /usr/local/libexec/swz-dispatcher
""",
        encoding="ascii",
    )
    config.chmod(0o644)


def write_init(root: Path, fixture: dict[str, str]) -> None:
    init = root / "init"
    init.write_text(
        f"""#!/bin/sh
set -eu
fail() {{ echo "SWZ_GUEST_CANDIDATE=FAIL:$1"; poweroff -f 2>/dev/null || true; exit "$1"; }}
provider() {{ echo "SWZ_GUEST_PROVIDER=$1"; poweroff -f 2>/dev/null || true; exit 75; }}
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
mkdir -p /sys/fs/selinux /run /mnt /dev/mapper
grep -F '/dev/mapper/swz-verity / ext4 ro' /proc/mounts >/dev/null || fail 40
echo SWZ_GUEST_DM_VERITY=PASS
mount -t selinuxfs selinuxfs /sys/fs/selinux 2>/dev/null || true
mount -t tmpfs -o mode=0755 tmpfs /run || fail 41
mount -t tmpfs -o mode=1777 tmpfs /tmp || fail 42
mount -t tmpfs -o mode=0755 tmpfs /var/lib/swz || fail 43
mount -t tmpfs -o mode=0700 tmpfs /root/.ssh || fail 44
mkdir -p /run/swz /run/sshd /var/lib/swz/store /var/empty
mkdir -p /run/swz/selinux-store
cp -a /var/lib/selinux/. /run/swz/selinux-store/ || fail 45
mount -t tmpfs -o mode=0755 tmpfs /var/lib/selinux || fail 46
cp -a /run/swz/selinux-store/. /var/lib/selinux/ || fail 47
cp -R /etc/swz/qualification/run/. /run/swz/ || fail 48
cp -R /etc/swz/qualification/store/. /var/lib/swz/store/ || fail 49
LOAD_POLICY=""
for candidate in /sbin/load_policy /usr/sbin/load_policy; do [ -x "$candidate" ] && LOAD_POLICY="$candidate" && break; done
[ -n "$LOAD_POLICY" ] || provider load-policy
"$LOAD_POLICY" -i || fail 50
SEMODULE=""
for candidate in /usr/bin/semodule /usr/sbin/semodule /bin/semodule /sbin/semodule; do [ -x "$candidate" ] && SEMODULE="$candidate" && break; done
[ -n "$SEMODULE" ] || provider semodule
"$SEMODULE" -i /etc/selinux/swz/swz-managed.cil || fail 51
SETFILES=""
for candidate in /sbin/setfiles /usr/sbin/setfiles /bin/setfiles /usr/bin/setfiles; do [ -x "$candidate" ] && SETFILES="$candidate" && break; done
[ -n "$SETFILES" ] || provider setfiles
"$SETFILES" -F /etc/selinux/swz/file_contexts /run/swz /run/sshd /var/lib/swz /usr/local/libexec /opt/swz || fail 52
test "$(cat /sys/fs/selinux/enforce 2>/dev/null || echo 0)" = 1 || fail 53
echo SWZ_GUEST_SELINUX=Enforcing
"$SETFILES" -F /etc/selinux/swz/file_contexts /etc/ssh/recovery_authorized_keys /etc/ssh/recovery_host_ed25519_key.pub /var/lib/swooshz-recovery/host-key/ed25519.seed || fail 54
if SSH_ORIGINAL_COMMAND=forbidden-command /usr/local/libexec/swz-dispatcher </dev/null >/run/swz/dispatcher-negative 2>&1; then fail 55; fi
echo SWZ_GUEST_DISPATCHER_NEGATIVE=PASS
IP=""
for candidate in /sbin/ip /usr/sbin/ip /bin/ip /usr/bin/ip; do [ -x "$candidate" ] && IP="$candidate" && break; done
[ -n "$IP" ] || provider ip
"$IP" link set lo up || fail 56
"$IP" link set eth0 up || fail 57
"$IP" addr add 10.0.2.15/24 dev eth0 || fail 58
mkdir -p /run/swz
cp /etc/swz/qualification/client_ed25519 /run/swz/client_ed25519 || fail 59
chmod 700 /run/swz /run/sshd
chmod 400 /run/swz/client_ed25519
exec 9</var/lib/swooshz-recovery/host-key/ed25519.seed
/usr/local/libexec/swz-supervisor --inetd --generation-raw32 {fixture["generation"]} --session-raw32 {fixture["session"]} --seed-fd 9 >/run/swz/supervisor.log 2>&1 &
SUPERVISOR_PID=$!
sleep 1
kill -0 "$SUPERVISOR_PID" 2>/dev/null || fail 61
/opt/swz/openssh/bin/ssh -q -i /run/swz/client_ed25519 -p 22222 \\
  -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \\
  -o PasswordAuthentication=no -o PubkeyAuthentication=yes -o IdentitiesOnly=yes -o IdentityAgent=none \\
  swz-recovery@10.0.2.15 swz-recovery-v1 < /run/swz/client-input.bin > /run/swz/ssh-response 2>/run/swz/ssh-client.log || fail 62
wait "$SUPERVISOR_PID" || fail 63
grep -aF 'BROKER_FINAL' /run/swz/ssh-response >/dev/null || fail 64
echo SWZ_GUEST_SUPERVISOR_REGISTRATION=PASS
echo SWZ_GUEST_CUSTODY=PASS
echo SWZ_GUEST_OPENSSH_SESSION=PASS
RUNCON=""
for candidate in /usr/bin/runcon /bin/runcon; do [ -x "$candidate" ] && RUNCON="$candidate" && break; done
[ -n "$RUNCON" ] || provider runcon
if "$RUNCON" -t swz_managed.swz_dispatcher_t -- /bin/touch /var/lib/swz/store/denied-by-selinux; then fail 65; fi
DMESG=""
for candidate in /bin/dmesg /usr/bin/dmesg; do [ -x "$candidate" ] && DMESG="$candidate" && break; done
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
    names = "\n".join(str(path.relative_to(root)) for path in sorted(root.rglob("*"))) + "\n"
    command = [tool("cpio"), "-o", "-H", "newc", "--owner=0:0"]
    result = run(command, cwd=root, input_bytes=names.encode("utf-8"), timeout=300)
    if result.returncode != 0:
        raise ProviderHold(_process_failure("initramfs-cpio", command, result))
    compressed_command = [tool("gzip"), "-n"]
    compressed = run(compressed_command, input_bytes=result.stdout, timeout=300)
    if compressed.returncode != 0:
        raise ProviderHold(_process_failure("initramfs-gzip", compressed_command, compressed))
    output.write_bytes(compressed.stdout)


def run_guest(kernel: Path, initramfs: Path, data: Path, hash_tree: Path, timeout: int) -> str:
    command = [
        tool("qemu-system-x86_64"), "-machine", "q35", "-accel", "tcg,thread=single",
        "-m", "512M", "-smp", "1", "-nographic", "-no-reboot", "-monitor", "none",
        "-serial", "stdio", "-kernel", str(kernel), "-initrd", str(initramfs),
        "-append", "console=ttyS0 selinux=1 enforcing=1 panic=1 net.ifnames=0",
        "-netdev", "user,id=net0,net=10.0.2.0/24,dhcpstart=10.0.2.15",
        "-device", "e1000,netdev=net0",
        "-drive", f"file={data},if=virtio,format=raw,readonly=on",
        "-drive", f"file={hash_tree},if=virtio,format=raw,readonly=on",
    ]
    result = run(command, timeout=timeout)
    output = ((result.stdout or b"") + (result.stderr or b"")).decode("utf-8", "replace")
    provider_markers = [line for line in output.splitlines() if line.startswith("SWZ_GUEST_PROVIDER=")]
    if provider_markers:
        raise ProviderHold(_process_failure("guest-qemu", command, result) + f"; marker={provider_markers[-1]}")
    required = (
        "SWZ_GUEST_SELINUX=Enforcing", "SWZ_GUEST_DM_VERITY=PASS",
        "SWZ_GUEST_DISPATCHER_NEGATIVE=PASS", "SWZ_GUEST_SUPERVISOR_REGISTRATION=PASS",
        "SWZ_GUEST_CUSTODY=PASS", "SWZ_GUEST_OPENSSH_SESSION=PASS",
        "SWZ_GUEST_SELINUX_DENIAL=PASS", "SWZ_GUEST_RUNTIME=PASS",
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
    if args.build_output is None or args.policy is None or args.file_contexts is None:
        raise ProviderHold("candidate-policy-and-contexts-required")
    if not args.policy.is_file() or not args.file_contexts.is_file():
        raise ProviderHold("candidate-policy-and-contexts-required")
    try:
        manifest = json.loads((args.build_output / "build-manifest.json").read_text(encoding="utf-8"))
        source_files = manifest["source_files"]
        if hashlib.sha256(args.policy.read_bytes()).hexdigest() != source_files.get("selinux.cil") or hashlib.sha256(args.file_contexts.read_bytes()).hexdigest() != source_files.get("file_contexts"):
            raise GuestError("candidate-policy-provenance-mismatch")
    except (KeyError, OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GuestError("candidate-policy-provenance-unavailable") from error
    with tempfile.TemporaryDirectory(prefix="swz-guest-") as temporary:
        work = Path(temporary)
        initrd_root = work / "root"
        initrd_root.mkdir()
        copy_tree(args.guest_root, initrd_root)
        stage_candidate(args.build_output, initrd_root)
        prepare_writable_runtime_dirs(initrd_root)
        prepare_test_material(initrd_root)
        write_guest_config(initrd_root)
        policy_destination = initrd_root / "etc/selinux/swz/swz-managed.cil"
        context_destination = initrd_root / "etc/selinux/swz/file_contexts"
        shutil.copy2(args.policy, policy_destination)
        shutil.copy2(args.file_contexts, context_destination)
        fixture = build_guest_fixtures(initrd_root)
        write_init(initrd_root, fixture)
        data = work / "verity-data.img"
        hash_tree = work / "verity-hash.img"
        build_rootfs(data, initrd_root)
        root_hash = build_verity(data, hash_tree)
        boot_root = work / "boot-root"
        boot_root.mkdir()
        for name, destination in (
            ("sh", "bin/sh"), ("mount", "bin/mount"),
            ("switch_root", "sbin/switch_root"), ("veritysetup", "sbin/veritysetup"),
            ("dd", "bin/dd"),
        ):
            stage_boot_tool(args.guest_root, boot_root, name, destination)
        write_boot_init(boot_root, root_hash)
        initramfs = work / "swz-managed.cpio.gz"
        make_initramfs(boot_root, initramfs)
        transcript = run_guest(kernel, initramfs, data, hash_tree, args.timeout)
        transcript_digest = hashlib.sha256(transcript.encode("utf-8")).hexdigest()
    return {
        "status": "PASS", "guest": "qemu-system-x86_64", "kernel": str(kernel),
        "kernel_sha256": hashlib.sha256(kernel.read_bytes()).hexdigest(),
        "verity_root_hash": root_hash, "guest_transcript_sha256": transcript_digest,
        "selinux": "Enforcing", "dm_verity": "PASS", "host_key": "ephemeral-test-seed-only",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-output", type=Path, required=True)
    parser.add_argument("--guest-root", type=Path)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--file-contexts", type=Path)
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--timeout", type=int, default=120)
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
