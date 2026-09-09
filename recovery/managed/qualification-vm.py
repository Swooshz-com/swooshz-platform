"""Disposable dm-verity/SELinux guest qualification harness.

The harness never treats a missing kernel primitive or a missing enforcement
tool as a pass. It builds the guest image in a runner-owned temporary root,
boots it with QEMU, and accepts evidence only from the guest serial stream.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import secrets
import shlex
import shutil
import struct
import subprocess
import tempfile
import textwrap
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MAX_DIAGNOSTIC_CHARS = 4096


class GuestError(RuntimeError):
    pass


class ProviderHold(GuestError):
    pass


def _bounded(value: object) -> str:
    text = value.decode("utf-8", "replace") if isinstance(value, bytes) else ("" if value is None else str(value))
    return text if len(text) <= MAX_DIAGNOSTIC_CHARS else text[:MAX_DIAGNOSTIC_CHARS] + "...[truncated]"


def _safe_command(command: list[str]) -> str:
    return shlex.join(str(value) for value in command)


def _process_failure(stage: str, command: list[str], result: object) -> str:
    return f"stage={stage}; command={_safe_command(command)}; returncode={getattr(result, 'returncode', 'unknown')}; stdout={_bounded(getattr(result, 'stdout', ''))}; stderr={_bounded(getattr(result, 'stderr', ''))}"


def tool(name: str) -> str:
    value = shutil.which(name)
    if value is None:
        raise ProviderHold(f"tool-unavailable:{name}")
    return value


def run(command: list[str], *, cwd: Path | None = None, input_bytes: bytes | None = None, timeout: int = 120) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(command, cwd=cwd, input=input_bytes, capture_output=True, check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ProviderHold(f"guest-command-unavailable:{command[0]}") from error


def choose_kernel(explicit: Path | None) -> Path:
    if explicit is not None:
        if not explicit.is_file() or explicit.is_symlink():
            raise ProviderHold("guest-kernel-invalid")
        return explicit
    candidates = sorted(Path("/boot").glob("vmlinuz-*"))
    if not candidates:
        raise ProviderHold("guest-kernel-unavailable")
    return candidates[-1]


def copy_tree(source: Path, destination: Path) -> None:
    if not source.is_dir() or source.is_symlink():
        raise ProviderHold("guest-root-missing")
    destination.mkdir(parents=True, exist_ok=True)
    for item in source.iterdir():
        target = destination / item.name
        if item.is_symlink():
            link = os.readlink(item)
            if os.path.isabs(link) or ".." not in Path(link).parts:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to(link, target_is_directory=item.is_dir())
            continue
        if item.is_dir():
            shutil.copytree(item, target, dirs_exist_ok=True, symlinks=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target, follow_symlinks=False)


def stage_file(source: Path, destination: Path, *, executable: bool = False) -> None:
    if not source.is_file() or source.is_symlink():
        raise ProviderHold(f"candidate-file-missing:{source.name}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    if executable:
        destination.chmod(0o755)


def stage_candidate(build_output: Path, root: Path) -> None:
    native = build_output / "native"
    for name in ("supervisor", "custodian", "dispatcher", "bootstrap", "broker", "agent", "launch-base"):
        stage_file(native / f"swz-{name}", root / "usr/local/libexec" / f"swz-{name}", executable=True)
    stage_file(build_output / "openssh" / "sbin" / "sshd", root / "opt/swz/openssh/sbin/sshd", executable=True)
    stage_file(build_output / "openssh" / "bin" / "ssh", root / "opt/swz/openssh/bin/ssh", executable=True)
    stage_file(build_output / "openssh" / "bin" / "ssh-keygen", root / "opt/swz/openssh/bin/ssh-keygen", executable=True)
    for name in ("sshd-session", "sshd-auth"):
        stage_file(build_output / "openssh" / "libexec" / name,
                   root / "opt/swz/openssh/libexec" / name, executable=True)
    stage_file(HERE / "sshd_config", root / "etc/ssh/recovery_sshd_config")
    stage_file(HERE / "selinux.cil", root / "etc/selinux/swz/swz-managed.cil")
    stage_file(HERE / "file_contexts", root / "etc/selinux/swz/file_contexts")


def prepare_writable_runtime_dirs(root: Path) -> None:
    for relative in ("root/.ssh", "var/lib/swooshz-recovery/host-key", "var/empty", "tmp", "run/swz", "run/sshd"):
        path = root / relative
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o700 if relative.endswith("host-key") else 0o755)


def _ssh_string(data: bytes, offset: int) -> tuple[bytes, int]:
    if offset < 0 or offset + 4 > len(data):
        raise ProviderHold("qualification-key-format")
    length = struct.unpack("!I", data[offset:offset + 4])[0]
    start = offset + 4
    end = start + length
    if end > len(data):
        raise ProviderHold("qualification-key-format")
    return data[start:end], end


def _extract_unencrypted_ed25519_seed(path: Path) -> bytes:
    try:
        encoded = b"".join(line.strip() for line in path.read_bytes().splitlines()
                             if not line.startswith(b"-----"))
        data = base64.b64decode(encoded, validate=True)
    except (OSError, ValueError) as error:
        raise ProviderHold("qualification-key-read") from error
    if not data.startswith(b"openssh-key-v1\0"):
        raise ProviderHold("qualification-key-format")
    offset = len(b"openssh-key-v1\0")
    cipher, offset = _ssh_string(data, offset)
    kdf, offset = _ssh_string(data, offset)
    _, offset = _ssh_string(data, offset)
    if cipher != b"none" or kdf != b"none" or offset + 4 > len(data):
        raise ProviderHold("qualification-key-encryption")
    key_count = struct.unpack("!I", data[offset:offset + 4])[0]
    offset += 4
    if key_count != 1:
        raise ProviderHold("qualification-key-count")
    public_blob, offset = _ssh_string(data, offset)
    private_blob, offset = _ssh_string(data, offset)
    if offset > len(data) or len(private_blob) < 4 + 11 + 4 + 32 + 4 + 64:
        raise ProviderHold("qualification-key-private-format")
    public_type, public_offset = _ssh_string(public_blob, 0)
    public_key, public_offset = _ssh_string(public_blob, public_offset)
    if public_type != b"ssh-ed25519" or len(public_key) != 32:
        raise ProviderHold("qualification-key-public-format")
    if len(private_blob) < 8:
        raise ProviderHold("qualification-key-private-format")
    check_a, check_b = struct.unpack("!II", private_blob[:8])
    if check_a != check_b:
        raise ProviderHold("qualification-key-checkints")
    private_offset = 8
    private_type, private_offset = _ssh_string(private_blob, private_offset)
    private_public, private_offset = _ssh_string(private_blob, private_offset)
    private_key, _ = _ssh_string(private_blob, private_offset)
    if private_type != b"ssh-ed25519" or private_public != public_key or len(private_key) != 64:
        raise ProviderHold("qualification-key-private-format")
    return private_key[:32]


def _append_line(path: Path, line: str) -> None:
    try:
        current = path.read_text(encoding="utf-8") if path.is_file() else ""
        if line not in current.splitlines():
            path.write_text(current + ("" if not current or current.endswith("\n") else "\n") + line + "\n", encoding="utf-8", newline="")
    except OSError as error:
        raise ProviderHold("qualification-account-material") from error


def prepare_test_material(root: Path) -> None:
    qualified_artifact = root / "var/lib/swooshz-recovery/qualified-artifact"
    qualified_artifact.parent.mkdir(parents=True, exist_ok=True)
    qualified_artifact.write_bytes(b"real disposable Store/CAS locator integration\n")
    qualified_artifact.chmod(0o444)

    seed_path = root / "var/lib/swooshz-recovery/host-key/ed25519.seed"
    keygen = tool("ssh-keygen")
    host_key = root / "tmp/swz-qualification-host"
    host_result = run([keygen, "-t", "ed25519", "-N", "", "-f", str(host_key)], timeout=30)
    if host_result.returncode != 0 or not Path(str(host_key) + ".pub").is_file():
        raise ProviderHold(_process_failure("ephemeral-host-key", [keygen], host_result))
    seed = bytearray(_extract_unencrypted_ed25519_seed(host_key))
    seed_path.write_bytes(seed)
    for index in range(len(seed)):
        seed[index] = 0
    seed_path.chmod(0o400)
    public = root / "etc/ssh/recovery_host_ed25519_key.pub"
    public.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(host_key) + ".pub", public)
    public.chmod(0o444)
    host_key.unlink(missing_ok=True)
    Path(str(host_key) + ".pub").unlink(missing_ok=True)

    client_key = root / "tmp/swz-qualification-client"
    client_result = run([keygen, "-t", "ed25519", "-N", "", "-f", str(client_key)], timeout=30)
    if client_result.returncode != 0 or not Path(str(client_key) + ".pub").is_file():
        raise ProviderHold(_process_failure("ephemeral-client-key", [keygen], client_result))
    client_private = root / "root/.ssh/id_ed25519"
    client_private.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(client_key, client_private)
    client_private.chmod(0o600)
    authorized = root / "etc/ssh/recovery_authorized_keys"
    authorized.parent.mkdir(parents=True, exist_ok=True)
    authorized.write_bytes(Path(str(client_key) + ".pub").read_bytes())
    authorized.chmod(0o444)
    client_key.unlink(missing_ok=True)
    Path(str(client_key) + ".pub").unlink(missing_ok=True)
    _append_line(root / "etc/passwd", "swz-recovery:x:2001:2001::/var/empty:/usr/sbin/nologin")
    _append_line(root / "etc/group", "swz-recovery:x:2001:")


def build_rootfs(data_path: Path, root: Path) -> None:
    mkfs = tool("mkfs.ext4")
    used = sum(path.stat().st_size for path in root.rglob("*") if path.is_file() and not path.is_symlink())
    size = max(256 * 1024 * 1024, used * 3 + 16 * 1024 * 1024)
    with data_path.open("wb") as stream:
        stream.truncate(size)
    result = run([mkfs, "-F", "-q", str(data_path)], timeout=120)
    if result.returncode != 0:
        raise ProviderHold(_process_failure("guest-ext4", [mkfs, "-F", str(data_path)], result))
    mountpoint = data_path.parent / "rootfs-mount"
    mountpoint.mkdir()
    mounted = False
    try:
        mount = run(["sudo", "mount", "-o", "loop", str(data_path), str(mountpoint)], timeout=60)
        if mount.returncode != 0:
            raise ProviderHold(_process_failure("guest-rootfs-mount", ["sudo", "mount"], mount))
        mounted = True
        copy_tree(root, mountpoint)
        owner = run(["sudo", "chown", "-R", "0:0", str(mountpoint)], timeout=120)
        if owner.returncode != 0:
            raise ProviderHold(_process_failure("guest-rootfs-owner", ["sudo", "chown"], owner))
    finally:
        if mounted:
            result = run(["sudo", "umount", str(mountpoint)], timeout=60)
            if result.returncode != 0:
                raise GuestError(_process_failure("guest-rootfs-unmount", ["sudo", "umount"], result))


def label_guest_tree(root: Path) -> None:
    setfiles = tool("setfiles")
    contexts = HERE / "file_contexts"
    policy_candidates = sorted((root / "etc/selinux/targeted/policy").glob("policy.*"))
    if not policy_candidates:
        raise ProviderHold("guest-compiled-policy-missing")
    result = run(["sudo", setfiles, "-F", "-c", str(policy_candidates[-1]), "-r", str(root), str(contexts), str(root)], timeout=120)
    if result.returncode != 0:
        raise ProviderHold(_process_failure("guest-file-labels", ["sudo", setfiles], result))


def install_guest_policy(root: Path) -> None:
    semodule = tool("semodule")
    policy = HERE / "selinux.cil"
    install = run(["sudo", semodule, "-p", str(root), "-i", str(policy)], timeout=120)
    if install.returncode != 0:
        raise ProviderHold(_process_failure("guest-selinux-policy-install", ["sudo", semodule], install))
    rebuild = run(["sudo", semodule, "-p", str(root), "-B"], timeout=120)
    if rebuild.returncode != 0:
        raise ProviderHold(_process_failure("guest-selinux-policy-compile", ["sudo", semodule], rebuild))
    listing = run(["sudo", semodule, "-p", str(root), "-l"], timeout=30)
    if listing.returncode != 0 or "swz-managed" not in listing.stdout:
        raise ProviderHold(_process_failure("guest-selinux-policy-list", ["sudo", semodule], listing))


def build_verity(data_path: Path, hash_path: Path) -> str:
    if not data_path.is_file() or data_path.stat().st_size == 0:
        raise GuestError("dm-verity-data-missing")
    result = run([tool("veritysetup"), "format", str(data_path), str(hash_path)], timeout=120)
    if result.returncode != 0:
        raise ProviderHold(_process_failure("dm-verity-format", ["veritysetup", "format"], result))
    text = (result.stdout + result.stderr).decode("utf-8", "replace")
    root_hash = next((line.split(":", 1)[1].strip() for line in text.splitlines() if line.lower().startswith("root hash:")), "")
    if len(root_hash) != 64 or any(char not in "0123456789abcdef" for char in root_hash.lower()):
        raise GuestError("dm-verity-root-hash-missing")
    return root_hash.lower()


def write_guest_controller(root: Path) -> None:
    controller = root / "usr/local/libexec/swz-qualification-client"
    script = textwrap.dedent(r'''\
        #!/usr/bin/python3
        import base64
        import hashlib
        import json
        import os
        import socket
        import stat
        import struct
        import subprocess
        import sys
        import time

        HEADER = struct.Struct("!8sBBBBQ32sI")
        N_LOCAL = bytes(range(32))
        ZERO = bytes(32)
        MAGIC = b"SWZFRM02"

        def lp(value):
            return struct.pack("!I", len(value)) + value

        def managed_hash(domain, *parts):
            value = lp(b"swz-managed.v1") + lp(domain.encode("ascii"))
            value += b"".join(lp(part) for part in parts)
            return hashlib.sha256(value).digest()

        def store_commitment(domain, value):
            value = lp(b"recovery-commitment.v1") + lp(domain.encode("ascii")) + lp(value)
            return "sha256:v1:" + hashlib.sha256(value).hexdigest()

        def store_document(value):
            return (json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=False) + "\n").encode("ascii")

        def frame_payload(message, previous, fields):
            value = [message, 2, "swz-managed.v1", previous.hex(), *fields]
            return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=False).encode("ascii")

        def frame(direction, message_id, sequence, previous, fields):
            payload = frame_payload(message_id[0], previous, fields)
            return HEADER.pack(MAGIC, 2, direction, message_id[1], 0, sequence, N_LOCAL, len(payload)) + payload

        def read_exact(stream, length):
            value = bytearray()
            while len(value) < length:
                part = stream.read(length - len(value))
                if not part:
                    raise RuntimeError("guest-controller-eof")
                value.extend(part)
            return bytes(value)

        def read_frame(stream, expected, direction, sequence, previous):
            header = read_exact(stream, HEADER.size)
            magic, version, actual_direction, message_id, flags, actual_sequence, n_local, length = HEADER.unpack(header)
            if (magic, version, actual_direction, message_id, flags, actual_sequence, n_local) != (MAGIC, 2, direction, expected[1], 0, sequence, N_LOCAL):
                raise RuntimeError("guest-controller-header")
            if length == 0 or length > 4096:
                raise RuntimeError("guest-controller-payload-length")
            payload = read_exact(stream, length)
            value = json.loads(payload.decode("ascii"))
            if not isinstance(value, list) or value[0:4] != [expected[0], 2, "swz-managed.v1", previous.hex()]:
                raise RuntimeError("guest-controller-payload")
            if json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=False).encode("ascii") != payload:
                raise RuntimeError("guest-controller-noncanonical")
            raw = header + payload
            return value, raw, hashlib.sha256(raw).digest()

        def managed32(value):
            return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)

        def store_tag(value):
            return isinstance(value, str) and len(value) == 74 and value.startswith("sha256:v1:") and managed32(value[10:])

        def u64_text(value):
            return isinstance(value, str) and value.isdigit() and (value == "0" or not value.startswith("0")) and int(value) <= 0xffffffffffffffff

        def uuid_v4(value):
            return isinstance(value, str) and len(value) == 36 and value[8] == "-" and value[13] == "-" and value[18] == "-" and value[23] == "-" and value[14] == "4" and value[19] in "89ab" and all(char in "0123456789abcdef-" for char in value)

        def validate_runtime(record):
            if not isinstance(record, list) or len(record) != 23 or not uuid_v4(record[0]):
                raise RuntimeError("guest-controller-runtime-shape")
            if any(not u64_text(value) for value in record[1:15]):
                raise RuntimeError("guest-controller-runtime-u64")
            if record[15:17] != [True, True] or record[17] != 0 or record[18] != "0" or record[19] is not True:
                raise RuntimeError("guest-controller-runtime-enforcement")
            if any(not managed32(value) for value in record[20:23]):
                raise RuntimeError("guest-controller-runtime-commitments")

        def validate_challenge(boot_hash, challenge):
            if len(challenge) != 9 or not managed32(challenge[4]) or not managed32(challenge[5]) or not managed32(challenge[6]) or challenge[7] != boot_hash.hex() or not u64_text(challenge[8]):
                raise RuntimeError("guest-controller-challenge-fields")
            return bytes.fromhex(challenge[4]), bytes.fromhex(challenge[5]), bytes.fromhex(challenge[6]), boot_hash

        def validate_evidence(boot_fields, challenge_fields, challenge_hash, evidence):
            if len(evidence) != 28:
                raise RuntimeError("guest-controller-evidence-arity")
            fields = evidence[4:]
            if any(not managed32(value) for index, value in enumerate(fields) if index != 22):
                raise RuntimeError("guest-controller-evidence-types")
            validate_runtime(fields[22])
            if fields[0] != boot_fields[3] or fields[1] != boot_fields[4] or fields[3] != challenge_fields[0].hex() or fields[4] != boot_fields[5] or fields[5] != boot_fields[6] or fields[17] != challenge_fields[1].hex() or fields[19] != boot_fields[7] or fields[20] != boot_fields[8]:
                raise RuntimeError("guest-controller-evidence-bindings")
            expected_challenge = managed_hash("challenge.v1", challenge_fields[3], challenge_fields[1], challenge_fields[0], N_LOCAL, challenge_fields[2]).hex()
            if fields[21] != expected_challenge:
                raise RuntimeError("guest-controller-challenge-commitment")
            expected_evidence = managed_hash("evidence.v1", N_LOCAL, challenge_hash, json.dumps(fields[:-1], ensure_ascii=True, separators=(",", ":"), sort_keys=False).encode("ascii")).hex()
            if fields[23] != expected_evidence:
                raise RuntimeError("guest-controller-evidence-commitment")
            return fields

        def validate_accepted(boot_fields, challenge_fields, evidence_fields, accept_hash, accept_commitment, accepted):
            if len(accepted) != 9 or not managed32(accepted[4]) or not managed32(accepted[5]) or not managed32(accepted[6]) or not managed32(accepted[7]) or not managed32(accepted[8]):
                raise RuntimeError("guest-controller-accepted-fields")
            expected_session = managed_hash("accepted-session.v1", bytes.fromhex(evidence_fields[0]), bytes.fromhex(evidence_fields[2]), challenge_fields[0], bytes.fromhex(evidence_fields[4]), challenge_fields[1], N_LOCAL, bytes.fromhex(evidence_fields[19]), bytes.fromhex(evidence_fields[23]), accept_commitment)
            expected_receipt = managed_hash("accepted-receipt.v1", expected_session, accept_hash, challenge_fields[1], challenge_fields[0]).hex()
            if accepted[4] != challenge_fields[1].hex() or accepted[5] != challenge_fields[0].hex() or accepted[6] != accept_commitment.hex() or accepted[7] != expected_session.hex() or accepted[8] != expected_receipt:
                raise RuntimeError("guest-controller-accepted-binding")
            return expected_session

        def validate_store_wire(value, schema):
            if not isinstance(value, list) or len(value) != 3 or value[0] != "store-json.v1" or value[1] != schema or not isinstance(value[2], str) or not value[2].endswith("\n"):
                raise RuntimeError("guest-controller-store-wire")
            raw = value[2].encode("ascii")
            try:
                document = json.loads(value[2])
            except Exception as error:
                raise RuntimeError("guest-controller-store-json") from error
            if json.dumps(document, ensure_ascii=True, separators=(",", ":"), sort_keys=False).encode("ascii") + b"\n" != raw:
                raise RuntimeError("guest-controller-store-canonical")
            return raw, document

        def validate_restore_begin(restore, discovery_hash, session):
            if len(restore) != 9 or restore[4] != discovery_hash.hex() or restore[5] != session.hex() or not store_tag(restore[8]):
                raise RuntimeError("guest-controller-restore-bindings")
            transition_raw, transition = validate_store_wire(restore[6], "restore-ledger-transition-data.v2")
            evidence_raw, evidence = validate_store_wire(restore[7], "restore-begin-evidence.v2")
            transition_id = "restore-v2-" + hashlib.sha256(lp(b"restore-transition-id.v2") + lp(transition_raw)).hexdigest()[:48]
            if list(transition) != ["schema", "version", "epoch_ref", "authority_ref", "barrier_utc", "barrier_commitment", "runner_commitment", "bundle_commitment", "image_commitment", "target_commitment", "isolation_commitment", "artifact_commitment", "artifact_stream_commitment", "pre_cas_ledger_digest"] or transition["schema"] != "restore-ledger-transition-data.v2" or transition["version"] != 2 or transition["epoch_ref"] != "epoch-qualified-001" or transition["authority_ref"] != "authority-qualified-001" or any(not store_tag(transition[field]) for field in ("barrier_commitment", "runner_commitment", "bundle_commitment", "image_commitment", "target_commitment", "isolation_commitment", "artifact_commitment", "artifact_stream_commitment", "pre_cas_ledger_digest")):
                raise RuntimeError("guest-controller-transition-schema")
            if list(evidence) != ["schema", "epoch_ref", "transition_id", "transition_data_commitment", "artifact_commitment", "artifact_stream_commitment", "ledger_state", "record_state", "spool_previous_stage", "frame_sequence", "previous_frame_hash", "frame_hash", "spool_commitment", "ledger_after_digest", "durability"] or evidence["schema"] != "restore-begin-evidence.v2" or evidence["epoch_ref"] != "epoch-qualified-001" or evidence["transition_id"] != transition_id or evidence["transition_data_commitment"] != store_commitment("restore-ledger-transition", transition_raw) or not all(store_tag(evidence[field]) for field in ("transition_data_commitment", "artifact_commitment", "artifact_stream_commitment", "previous_frame_hash", "frame_hash", "spool_commitment", "ledger_after_digest")) or evidence["ledger_state"] != "CONSUMED" or evidence["record_state"] != "CONSUMED" or evidence["spool_previous_stage"] != "RESTORE_BEGIN" or evidence["frame_sequence"] != 1 or not isinstance(evidence["durability"], dict) or list(evidence["durability"]) != ["file_flush_verified", "readback_verified", "atomic_authority_transition", "directory_flush_verified"] or not all(evidence["durability"].values()):
                raise RuntimeError("guest-controller-evidence-schema")
            return transition_id, transition_raw, evidence_raw

        def validate_proceed(proceed, session, transition_id, transition_commitment, restore_hash):
            if len(proceed) != 9 or proceed[4] != session.hex() or proceed[5] != transition_id or not store_tag(proceed[6]) or proceed[7] != restore_hash.hex() or not managed32(proceed[8]):
                raise RuntimeError("guest-controller-proceed-fields")
            if proceed[6] != transition_commitment or proceed[8] != managed_hash("proceed.v1", session, transition_id.encode("ascii"), bytes.fromhex(transition_commitment[10:]), restore_hash).hex():
                raise RuntimeError("guest-controller-proceed-commitment")

        def validate_result(result, session, transition_id, proceed_commitment, proceed_hash):
            if len(result) != 9 or result[4] != session.hex() or result[5] != transition_id or result[6] != proceed_commitment.hex() or not managed32(result[8]) or result[3] != proceed_hash.hex():
                raise RuntimeError("guest-controller-result-bindings")
            result_raw, document = validate_store_wire(result[7], "swz-recovery-result.v2")
            expected_keys = ["schema", "classification", "stage", "epoch_ref", "authority_ref", "barrier_utc", "ssh_endpoint_commitment", "epoch_commitment", "authority_commitment", "barrier_commitment", "runner_commitment", "bundle_commitment", "launcher_commitment", "agent_commitment", "image_commitment", "target_commitment", "isolation_commitment", "artifact_commitment", "artifact_stream_commitment", "transition_id", "pre_cas_ledger_digest", "transition_data_commitment", "consumed_record_commitment", "restore_begin_commitment", "process_commitment", "restore_commitment", "cleanup_commitment", "stdout_capture_commitment", "stderr_capture_commitment", "result_code", "restore_count", "exit_status", "stdin_eof", "stdout_eof", "stderr_eof", "trailing_unframed_bytes", "terminal_input_eof", "terminal_input_trailing_bytes", "cleanup_state"]
            if list(document) != expected_keys or document["schema"] != "swz-recovery-result.v2" or document["classification"] != "SUCCESS" or document["stage"] != "RESTORE" or document["epoch_ref"] != "epoch-qualified-001" or document["authority_ref"] != "authority-qualified-001" or document["transition_id"] != transition_id or document["result_code"] != 0 or document["restore_count"] != 1 or document["exit_status"] != 0 or document["stdin_eof"] is not True or document["stdout_eof"] is not True or document["stderr_eof"] is not True or document["trailing_unframed_bytes"] is not False or document["terminal_input_eof"] is not True or document["terminal_input_trailing_bytes"] is not False or document["cleanup_state"] != "CLEAN" or any(not store_tag(document[field]) for field in expected_keys[6:19] + expected_keys[20:29]):
                raise RuntimeError("guest-controller-result-schema")
            if result[8] != managed_hash("result.v1", session, transition_id.encode("ascii"), proceed_commitment, result_raw).hex():
                raise RuntimeError("guest-controller-result-commitment")

        def send_frame(stream, direction, message_id, sequence, previous, fields):
            raw = frame(direction, message_id, sequence, previous, fields)
            stream.write(raw)
            stream.flush()
            return raw, hashlib.sha256(raw).digest()

        def wait_for_socket(path):
            for _ in range(120):
                try:
                    info = os.stat(path)
                    if stat.S_ISSOCK(info.st_mode):
                        return
                except FileNotFoundError:
                    pass
                time.sleep(0.25)
            raise RuntimeError("guest-controller-listeners")

        def custody_negative():
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.settimeout(5)
            try:
                client.connect("/run/swz/recovery-hostkey-agent.sock")
                client.sendall(struct.pack("!I", 1) + bytes([11]))
                if client.recv(1) != b"":
                    raise RuntimeError("guest-controller-negative-accepted")
            except OSError:
                pass
            finally:
                client.close()

        def main():
            for path in ("/run/swz/recovery-network.sock", "/run/swz/recovery-hostkey-agent.sock", "/run/swz/recovery-session-control.sock"):
                wait_for_socket(path)
            network = os.stat("/run/swz/recovery-network.sock")
            agent = os.stat("/run/swz/recovery-hostkey-agent.sock")
            session_control = os.stat("/run/swz/recovery-session-control.sock")
            if len({network.st_ino, agent.st_ino, session_control.st_ino}) != 3:
                raise RuntimeError("guest-controller-listener-alias")
            if stat.S_IMODE(session_control.st_mode) != 0o660:
                raise RuntimeError("guest-controller-session-mode")
            custody_negative()
            ssh = [
                "/opt/swz/openssh/bin/ssh", "-q", "-p", "22222", "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                "-o", "IdentitiesOnly=yes", "-o", "IdentityFile=/root/.ssh/id_ed25519",
                "-o", "HostKeyAlgorithms=ssh-ed25519",
                "-o", "ProxyCommand=/bin/nc -U /run/swz/recovery-network.sock",
                "swz-recovery@swz-managed",
            ]
            process = subprocess.Popen(ssh, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                zero_hex = "0" * 64
                boot_fields = [
                    "epoch-qualified-001", "authority-qualified-001", "2026-09-07T00:00:00.000000Z",
                    "01" * 32, "02" * 32, "03" * 32, "04" * 32, "05" * 32, "06" * 32,
                ]
                boot_raw, boot_hash = send_frame(process.stdin, 1, ("BOOT", 1), 0, ZERO, boot_fields)
                challenge, challenge_raw, challenge_hash = read_frame(process.stdout, ("CHALLENGE", 3), 2, 1, boot_hash)
                challenge_fields = validate_challenge(boot_hash, challenge)
                evidence, evidence_raw, evidence_hash = read_frame(process.stdout, ("EVIDENCE", 4), 2, 2, challenge_hash)
                evidence_fields = validate_evidence(boot_fields, challenge_fields, challenge_hash, evidence)
                connection = challenge_fields[1].hex()
                generation = boot_fields[5]
                authority_context = boot_fields[7]
                accept_without = [connection, generation, authority_context, evidence_fields[23], evidence_hash.hex()]
                accept_commitment = managed_hash("accept.v1", N_LOCAL, json.dumps(accept_without, separators=(",", ":"), ensure_ascii=True).encode("ascii"))
                accept_commitment_hex = accept_commitment.hex()
                accept_raw, accept_hash = send_frame(process.stdin, 1, ("ACCEPT", 5), 3, evidence_hash, [*accept_without, accept_commitment_hex])
                accepted, accepted_raw, accepted_hash = read_frame(process.stdout, ("ACCEPTED", 6), 2, 4, accept_hash)
                session = validate_accepted(boot_fields, challenge_fields, evidence_fields,
                                            accept_hash, accept_commitment, accepted)
                discovery, discovery_raw, discovery_hash = read_frame(process.stdout, ("DISCOVERY", 7), 2, 5, accepted_hash)
                if len(discovery) != 13 or discovery[4] != session.hex() or not u64_text(discovery[5]):
                    raise RuntimeError("guest-controller-discovery")
                try:
                    filename = base64.urlsafe_b64decode(discovery[6] + "===")
                except Exception as error:
                    raise RuntimeError("guest-controller-discovery-filename") from error
                if filename != b"qualified-artifact" or not all(store_tag(value) for value in discovery[7:12]):
                    raise RuntimeError("guest-controller-discovery-fields")
                expected_discovery = managed_hash("discovery.v1", session, struct.pack("!Q", int(discovery[5])), filename, *(bytes.fromhex(value[10:]) for value in discovery[7:12])).hex()
                if discovery[12] != expected_discovery:
                    raise RuntimeError("guest-controller-discovery-commitment")

                image = store_commitment("qualified-image", b"swz-managed-qualified-image-v1")
                target = store_commitment("qualified-target", b"swz-managed-qualified-target-v1")
                isolation = store_commitment("qualified-isolation", b"swz-managed-qualified-isolation-v1")
                artifact = store_commitment("qualified-artifact", b"swz-managed-qualified-artifact-v1")
                artifact_stream = store_commitment("qualified-artifact-stream", b"swz-managed-qualified-artifact-stream-v1")
                transition = {
                    "schema": "restore-ledger-transition-data.v2", "version": 2,
                    "epoch_ref": "epoch-qualified-001", "authority_ref": "authority-qualified-001",
                    "barrier_utc": "2026-09-07T00:00:00.000000Z",
                    "barrier_commitment": store_commitment("barrier", b"qualified-barrier"),
                    "runner_commitment": store_commitment("runner", b"qualified-runner"),
                    "bundle_commitment": store_commitment("bundle", b"qualified-bundle"),
                    "image_commitment": image, "target_commitment": target, "isolation_commitment": isolation,
                    "artifact_commitment": artifact, "artifact_stream_commitment": artifact_stream,
                    "pre_cas_ledger_digest": store_commitment("pre-cas-ledger", b"qualified-pre-cas-ledger"),
                }
                transition_bytes = store_document(transition)
                transition_wire = ["store-json.v1", "restore-ledger-transition-data.v2", transition_bytes.decode("ascii")]
                transition_id = "restore-v2-" + hashlib.sha256(lp(b"restore-transition-id.v2") + lp(transition_bytes)).hexdigest()[:48]
                evidence_record = {
                    "schema": "restore-begin-evidence.v2", "epoch_ref": "epoch-qualified-001",
                    "transition_id": transition_id,
                    "transition_data_commitment": store_commitment("restore-ledger-transition", transition_bytes),
                    "artifact_commitment": artifact, "artifact_stream_commitment": artifact_stream,
                    "ledger_state": "CONSUMED", "record_state": "CONSUMED", "spool_previous_stage": "RESTORE_BEGIN",
                    "frame_sequence": 1, "previous_frame_hash": store_commitment("previous-frame", discovery_raw),
                    "frame_hash": store_commitment("restore-begin-frame", b"qualified-restore-begin-frame"),
                    "spool_commitment": store_commitment("spool", b"qualified-spool"),
                    "ledger_after_digest": store_commitment("ledger-after", b"qualified-ledger-after"),
                    "durability": {"file_flush_verified": True, "readback_verified": True, "atomic_authority_transition": True, "directory_flush_verified": True},
                }
                evidence_bytes = store_document(evidence_record)
                evidence_wire = ["store-json.v1", "restore-begin-evidence.v2", evidence_bytes.decode("ascii")]
                consumed = store_commitment("restore-ledger-record", b"qualified-consumed-record")
                restore_fields = [discovery_hash.hex(), session.hex(), transition_wire, evidence_wire, consumed]
                restore_raw, restore_hash = send_frame(process.stdin, 1, ("RESTORE_BEGIN", 8), 6, discovery_hash, restore_fields)
                validated_transition_id, _, _ = validate_restore_begin(json.loads(frame_payload("RESTORE_BEGIN", discovery_hash, restore_fields)), discovery_hash, session)
                if validated_transition_id != transition_id:
                    raise RuntimeError("guest-controller-transition-id")
                transition_commitment = store_commitment("restore-ledger-transition", transition_bytes)
                proceed_commitment = managed_hash("proceed.v1", session, transition_id.encode("ascii"), bytes.fromhex(transition_commitment[10:]), restore_hash).hex()
                proceed_raw, proceed_hash = send_frame(process.stdin, 1, ("PROCEED", 9), 7, restore_hash,
                                                        [session.hex(), transition_id, transition_commitment, restore_hash.hex(), proceed_commitment])
                validate_proceed(json.loads(frame_payload("PROCEED", restore_hash, [session.hex(), transition_id, transition_commitment, restore_hash.hex(), proceed_commitment])), session, transition_id, transition_commitment, restore_hash)
                process.stdin.close()
                result, result_raw, result_hash = read_frame(process.stdout, ("RESULT", 10), 2, 8, proceed_hash)
                validate_result(result, session, transition_id, bytes.fromhex(proceed_commitment), proceed_hash)
                if process.stdout.read() != b"":
                    raise RuntimeError("guest-controller-output-trailing-bytes")
                if process.wait(timeout=60) != 0:
                    raise RuntimeError("guest-controller-ssh-status")
                print("SWZ_GUEST_OPENSSH=PASS")
                print("SWZ_GUEST_CUSTODY=PASS")
                print("SWZ_GUEST_CUSTODY_NEGATIVE=PASS")
                print("SWZ_GUEST_SESSION_CONTROL=PASS")
                print("SWZ_GUEST_PROTOCOL=PASS")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
            return 0

        if __name__ == "__main__":
            raise SystemExit(main())
    ''')
    controller.parent.mkdir(parents=True, exist_ok=True)
    controller.write_text(script, encoding="ascii", newline="")
    controller.chmod(0o755)


def write_guest_runtime_init(root: Path) -> None:
    init = root / "sbin/swz-guest-init"
    init.parent.mkdir(parents=True, exist_ok=True)
    init.write_text("""#!/bin/sh
set -u
manager_status=0
/usr/local/libexec/swz-launch-base &
manager=$!
client_status=0
/usr/local/libexec/swz-qualification-client || client_status=$?
if [ "$client_status" -ne 0 ]; then
  kill "$manager" 2>/dev/null || true
fi
wait "$manager" || manager_status=$?
if [ "$client_status" -ne 0 ]; then
  exit "$client_status"
fi
if [ "$manager_status" -ne 0 ]; then
  exit "$manager_status"
fi
for path in /run/swz/recovery-network.sock /run/swz/recovery-hostkey-agent.sock /run/swz/recovery-session-control.sock; do
  if [ -e "$path" ]; then
    echo SWZ_GUEST_FINALITY=FAIL
    exit 75
  fi
done
echo SWZ_GUEST_FINALITY=PASS
/sbin/poweroff -f
exit 0
""", encoding="ascii", newline="")
    init.chmod(0o755)


def write_init(root: Path, root_hash: str) -> None:
    init = root / "init"
    init.write_text(f"""#!/bin/sh
set -eu
mount -t devtmpfs devtmpfs /dev
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mkdir -p /sys/fs/selinux /newroot
mount -t selinuxfs selinuxfs /sys/fs/selinux
veritysetup open /dev/vda swzroot {root_hash} --hash-device=/dev/vdb
mount -o ro /dev/mapper/swzroot /newroot
mount -t tmpfs -o mode=0755 swz-run /newroot/run
mkdir -p /newroot/run/swz /newroot/run/sshd
mkdir -p /newroot/dev /newroot/proc /newroot/sys /newroot/sys/fs/selinux
mount --bind /dev /newroot/dev
mount --bind /proc /newroot/proc
mount --bind /sys /newroot/sys
mount --bind /sys/fs/selinux /newroot/sys/fs/selinux
if [ ! -x /newroot/usr/sbin/load_policy ] || ! chroot /newroot /usr/sbin/load_policy -i; then
  echo SWZ_GUEST_SELINUX=POLICY_LOAD_FAILED
  exit 74
fi
setfiles=/newroot/usr/sbin/setfiles
if [ ! -x "$setfiles" ]; then
  setfiles=/newroot/sbin/setfiles
fi
policy=$(ls /newroot/etc/selinux/targeted/policy/policy.* 2>/dev/null | tail -n 1)
if [ ! -x "$setfiles" ] || [ -z "$policy" ] || ! chroot /newroot "${{setfiles#/newroot}}" -F -c "${{policy#/newroot}}" /etc/selinux/swz/file_contexts /run; then
  echo SWZ_GUEST_SELINUX=RUNTIME_LABEL_FAILED
  exit 77
fi
if ! setenforce 1 || [ "$(getenforce)" != Enforcing ]; then
  echo SWZ_GUEST_SELINUX=NOT_ENFORCING
  exit 73
fi
if chroot /newroot /usr/bin/runcon -t swz_sshd_t -- /bin/cat /var/lib/swooshz-recovery/host-key/ed25519.seed >/dev/null 2>&1; then
  echo SWZ_GUEST_SELINUX_DENIAL=FAIL
  exit 76
fi
echo SWZ_GUEST_DM_VERITY=OPEN
echo SWZ_GUEST_SELINUX=Enforcing
echo SWZ_GUEST_SELINUX_DENIAL=PASS
exec switch_root /newroot /sbin/swz-guest-init
""", encoding="ascii", newline="")
    init.chmod(0o755)


def make_initramfs(root: Path, output: Path) -> None:
    entries = "\n".join(str(path.relative_to(root)) for path in sorted(root.rglob("*"))) + "\n"
    result = run([tool("cpio"), "-o", "-H", "newc", "--owner=0:0"], cwd=root, input_bytes=entries.encode("utf-8"), timeout=120)
    if result.returncode != 0:
        raise ProviderHold(_process_failure("guest-initramfs", ["cpio", "-o", "-H", "newc"], result))
    output.write_bytes(result.stdout)


def run_guest(kernel: Path, initramfs: Path, data: Path, hash_tree: Path, timeout: int) -> str:
    command = [tool("qemu-system-x86_64"), "-machine", "q35", "-accel", "tcg,thread=single", "-nographic", "-no-reboot", "-serial", "stdio", "-kernel", str(kernel), "-initrd", str(initramfs), "-append", "console=ttyS0 panic=-1 selinux=1 security=selinux", "-drive", f"file={data},if=virtio,format=raw,readonly=on", "-drive", f"file={hash_tree},if=virtio,format=raw,readonly=on"]
    result = run(command, timeout=timeout)
    text = (result.stdout + result.stderr).decode("utf-8", "replace")
    required_markers = (
        "SWZ_GUEST_DM_VERITY=OPEN", "SWZ_GUEST_SELINUX=Enforcing",
        "SWZ_GUEST_SELINUX_DENIAL=PASS", "SWZ_GUEST_OPENSSH=PASS",
        "SWZ_GUEST_CUSTODY=PASS", "SWZ_GUEST_CUSTODY_NEGATIVE=PASS",
        "SWZ_GUEST_SESSION_CONTROL=PASS", "SWZ_GUEST_PROTOCOL=PASS",
        "SWZ_GUEST_FINALITY=PASS",
    )
    if result.returncode != 0 or any(marker not in text for marker in required_markers):
        raise GuestError(_process_failure("guest-qemu", command, result))
    return text


def qualify(args: argparse.Namespace) -> dict[str, Any]:
    if platform.system() != "Linux":
        raise ProviderHold("guest-linux-required")
    guest_root = Path(args.guest_root).resolve()
    build_output = Path(args.build_output).resolve()
    output = Path(args.output).resolve()
    if not guest_root.is_dir() or not build_output.is_dir():
        raise ProviderHold("guest-input-root-missing")
    kernel = choose_kernel(Path(args.kernel).resolve() if args.kernel else None)
    with tempfile.TemporaryDirectory(prefix="swz-guest-", dir=os.environ.get("RUNNER_TEMP")) as temporary:
        work = Path(temporary)
        root = work / "root"
        copy_tree(guest_root, root)
        prepare_writable_runtime_dirs(root)
        stage_candidate(build_output, root)
        prepare_test_material(root)
        write_guest_controller(root)
        write_guest_runtime_init(root)
        install_guest_policy(root)
        label_guest_tree(root)
        data = work / "rootfs.ext4"
        hash_tree = work / "rootfs.verity"
        build_rootfs(data, root)
        root_hash = build_verity(data, hash_tree)
        write_init(root, root_hash)
        initramfs = work / "swz-managed.cpio"
        make_initramfs(root, initramfs)
        serial = run_guest(kernel, initramfs, data, hash_tree, args.timeout)
        evidence = {"schema": "swz-managed-guest-evidence.v1", "dm_verity": "PASS", "selinux": "Enforcing", "serial_sha256": hashlib.sha256(serial.encode()).hexdigest(), "mandatory_security_skips": 0, "qemu_machine": "q35", "root_hash_sha256": hashlib.sha256(root_hash.encode()).hexdigest()}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8", newline="")
    return evidence


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--guest-root", required=True, type=Path)
    parser.add_argument("--build-output", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args(argv)
    try:
        qualify(args)
    except ProviderHold as error:
        print(f"QUALIFICATION_PROVIDER_HOLD={error}", file=os.sys.stderr)
        return 2
    except GuestError as error:
        print(str(error), file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
