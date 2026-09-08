"""Disposable dm-verity/SELinux guest qualification harness.

The harness never treats a missing kernel primitive or a missing enforcement
tool as a pass. It builds the guest image in a runner-owned temporary root,
boots it with QEMU, and accepts evidence only from the guest serial stream.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import secrets
import shlex
import shutil
import subprocess
import tempfile
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
            continue
        if item.is_dir():
            shutil.copytree(item, target, dirs_exist_ok=True, symlinks=False)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target)


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
    stage_file(HERE / "sshd_config", root / "etc/ssh/recovery_sshd_config")
    stage_file(HERE / "selinux.cil", root / "etc/selinux/swz/swz-managed.cil")
    stage_file(HERE / "file_contexts", root / "etc/selinux/swz/file_contexts")


def prepare_writable_runtime_dirs(root: Path) -> None:
    for relative in ("root/.ssh", "var/lib/swooshz-recovery/host-key", "var/empty", "tmp", "run/swz", "run/sshd"):
        path = root / relative
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o700 if relative.endswith("host-key") else 0o755)


def prepare_test_material(root: Path) -> None:
    seed = secrets.token_bytes(32)
    seed_path = root / "var/lib/swooshz-recovery/host-key/ed25519.seed"
    seed_path.write_bytes(seed)
    seed_path.chmod(0o400)
    # The public-key line is derived by the pinned OpenSSH key utility; the
    # raw seed itself never leaves the disposable guest root.
    key_path = root / "tmp/swz-qualification-host"
    result = run([tool("ssh-keygen"), "-t", "ed25519", "-N", "", "-f", str(key_path)], timeout=30)
    if result.returncode != 0 or not Path(str(key_path) + ".pub").is_file():
        raise ProviderHold(_process_failure("ephemeral-host-key", ["ssh-keygen"], result))
    public = root / "etc/ssh/recovery_host_ed25519_key.pub"
    public.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(key_path) + ".pub", public)
    public.chmod(0o444)


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
    finally:
        if mounted:
            result = run(["sudo", "umount", str(mountpoint)], timeout=60)
            if result.returncode != 0:
                raise GuestError(_process_failure("guest-rootfs-unmount", ["sudo", "umount"], result))


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


def write_init(root: Path, root_hash: str) -> None:
    init = root / "init"
    init.write_text(f"""#!/bin/sh
set -eu
mount -t devtmpfs devtmpfs /dev
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mkdir -p /run /newroot
veritysetup open /dev/vda swzroot {root_hash} --hash-device=/dev/vdb
mount -o ro /dev/mapper/swzroot /newroot
if command -v setenforce >/dev/null 2>&1; then setenforce 1; fi
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" = Enforcing ]; then
  echo SWZ_GUEST_SELINUX=Enforcing
else
  echo SWZ_GUEST_SELINUX=NOT_ENFORCING
  exit 73
fi
echo SWZ_GUEST_DM_VERITY=OPEN
exec switch_root /newroot /usr/local/libexec/swz-launch-base
""", encoding="ascii", newline="")
    init.chmod(0o755)


def make_initramfs(root: Path, output: Path) -> None:
    entries = "\n".join(str(path.relative_to(root)) for path in sorted(root.rglob("*"))) + "\n"
    result = run([tool("cpio"), "-o", "-H", "newc", "--owner=0:0"], cwd=root, input_bytes=entries.encode("utf-8"), timeout=120)
    if result.returncode != 0:
        raise ProviderHold(_process_failure("guest-initramfs", ["cpio", "-o", "-H", "newc"], result))
    output.write_bytes(result.stdout)


def run_guest(kernel: Path, initramfs: Path, data: Path, hash_tree: Path, timeout: int) -> str:
    command = [tool("qemu-system-x86_64"), "-machine", "q35", "-accel", "tcg,thread=single", "-nographic", "-no-reboot", "-serial", "stdio", "-kernel", str(kernel), "-initrd", str(initramfs), "-append", "console=ttyS0 panic=-1", "-drive", f"file={data},if=virtio,format=raw,readonly=on", "-drive", f"file={hash_tree},if=virtio,format=raw,readonly=on"]
    result = run(command, timeout=timeout)
    text = (result.stdout + result.stderr).decode("utf-8", "replace")
    if result.returncode != 0 or "SWZ_GUEST_DM_VERITY=OPEN" not in text or "SWZ_GUEST_SELINUX=Enforcing" not in text:
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
    except GuestError as error:
        print(str(error), file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

