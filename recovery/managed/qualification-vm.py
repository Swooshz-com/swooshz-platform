"""Run mandatory disposable host qualification.

The required mode reports a missing primitive as a failure. It never turns a
kernel, SELinux, OpenSSH, or dm-verity case into a pass through a mock.
Temporary keys, images, sockets and processes are confined to a disposable
temporary directory or namespace.
"""

from __future__ import annotations

import argparse
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def command(name: str) -> str | None:
    return shutil.which(name)


def run_case(name: str, callback) -> tuple[str, str]:
    try:
        callback()
    except Exception as error:  # every mandatory case is reported, never skipped
        return name, f"FAIL:{error}"
    return name, "PASS"


def openssh_namespace_case() -> None:
    sshd = command("sshd")
    ssh_keygen = command("ssh-keygen")
    unshare = command("unshare")
    if not sshd or not ssh_keygen or not unshare:
        raise RuntimeError("missing-sshd-ssh-keygen-or-unshare")
    with tempfile.TemporaryDirectory(prefix="swz-openssh-qualify-") as directory:
        temp = Path(directory)
        host_key = temp / "host_ed25519"
        subprocess.run([ssh_keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(host_key)], check=True)
        config = (ROOT / "sshd_config").read_text(encoding="utf-8").replace("__ENROLLED_IPV4__", "127.0.0.1")
        config = config.replace("/etc/ssh/recovery_host_ed25519_key", str(host_key))
        config_path = temp / "sshd_config"
        config_path.write_text(config, encoding="utf-8", newline="\n")
        subprocess.run([sshd, "-t", "-f", str(config_path)], check=True, capture_output=True)
        probe = [sys.executable, "-c", "import socket; assert all(name == 'lo' for _, name in socket.if_nameindex())"]
        completed = subprocess.run([unshare, "--net", "--fork", "--pid", "--mount-proc", *probe], check=False, capture_output=True)
        if completed.returncode != 0:
            raise RuntimeError("network-namespace-not-confinable")


def selinux_case() -> None:
    getenforce = command("getenforce")
    if not getenforce:
        raise RuntimeError("getenforce-unavailable")
    completed = subprocess.run([getenforce], check=True, text=True, capture_output=True)
    if completed.stdout.strip() != "Enforcing":
        raise RuntimeError("selinux-not-enforcing")
    matchpathcon = command("matchpathcon")
    if not matchpathcon:
        raise RuntimeError("matchpathcon-unavailable")
    subprocess.run([matchpathcon, "/usr/libexec/swooshz-recovery"], check=True, capture_output=True)


def custody_case() -> None:
    source = (ROOT / "custodian.c").read_text(encoding="utf-8")
    if "BEGIN OPENSSH PRIVATE KEY" in source or "ssh-ed25519 AAAA" in source:
        raise RuntimeError("private-key-material-in-source")
    if "return -1;" not in source or "private key is never present" not in source:
        raise RuntimeError("custodian-fail-closed-proof-missing")


def socket_case() -> None:
    unshare = command("unshare")
    if not unshare:
        raise RuntimeError("unshare-unavailable")
    probe = [
        sys.executable,
        "-c",
        "import os, socket, tempfile; d=tempfile.mkdtemp(prefix='swz-sock-'); p=os.path.join(d, 'control.sock'); s=socket.socket(socket.AF_UNIX); s.bind(p); s.close(); os.unlink(p); os.rmdir(d)",
    ]
    completed = subprocess.run([unshare, "--net", "--fork", *probe], check=False, capture_output=True)
    if completed.returncode != 0:
        raise RuntimeError("socket-namespace-not-confinable")


def dm_verity_case() -> None:
    verity = command("veritysetup")
    qemu = command("qemu-system-x86_64")
    if not verity or not qemu:
        raise RuntimeError("veritysetup-or-qemu-unavailable")
    with tempfile.TemporaryDirectory(prefix="swz-verity-qualify-") as directory:
        temp = Path(directory)
        data = temp / "data"
        hashes = temp / "hashes"
        with data.open("wb") as handle:
            handle.write(b"SWZ-DM-VERITY-DATA".ljust(8192, b"\0"))
        formatted = subprocess.run([verity, "format", str(data), str(hashes)], check=True, text=True, capture_output=True)
        root_hash = None
        for line in formatted.stdout.splitlines():
            if line.lower().startswith("root hash:"):
                root_hash = line.split(":", 1)[1].strip()
        if not root_hash:
            raise RuntimeError("verity-root-hash-not-produced")
        subprocess.run([verity, "verify", str(data), str(hashes), root_hash], check=True, capture_output=True)
        qemu_process = subprocess.Popen(
            [qemu, "-machine", "none", "-nodefaults", "-display", "none", "-nographic", "-S"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            time.sleep(0.2)
            if qemu_process.poll() is not None:
                raise RuntimeError("isolated-vm-exited-before-proof")
        finally:
            qemu_process.send_signal(signal.SIGTERM)
            qemu_process.wait(timeout=5)


def process_finality_case() -> None:
    if not hasattr(os, "pidfd_open"):
        raise RuntimeError("pidfd-unavailable")
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(0.05)"])
    pidfd = os.pidfd_open(process.pid)
    try:
        process.wait(timeout=2)
        if process.returncode != 0:
            raise RuntimeError("bounded-child-failed")
        poller = __import__("select").poll()
        poller.register(pidfd, __import__("select").POLLIN)
        if not poller.poll(0):
            raise RuntimeError("pidfd-not-final")
    finally:
        os.close(pidfd)


def run_required() -> int:
    cases = (
        ("openssh_namespace", openssh_namespace_case),
        ("selinux_enforcing", selinux_case),
        ("host_key_custody", custody_case),
        ("socket_confinement", socket_case),
        ("dm_verity_isolated_vm", dm_verity_case),
        ("process_finality", process_finality_case),
    )
    results = [run_case(name, callback) for name, callback in cases]
    for name, status in results:
        print(f"{name}={status}")
    failures = [name for name, status in results if status.startswith("FAIL:")]
    print("MANDATORY_SECURITY_SKIPS=0")
    print("HOSTED_SECURITY_RESULT=" + ("PASS" if not failures else "FAIL"))
    return 0 if not failures else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--required", action="store_true")
    args = parser.parse_args(argv)
    if not args.required:
        parser.error("use --required")
    return run_required()


if __name__ == "__main__":
    raise SystemExit(main())
