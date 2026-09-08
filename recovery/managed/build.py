"""Reproducible Linux build helpers for the managed recovery boundary."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
LOCK_PATH = HERE / "build.lock.json"
SCHEMA_PATH = HERE / "manifest.schema.json"
NATIVE_FLAGS = "-std=c11 -O2 -Wall -Wextra -Werror -Wpedantic"
MAX_DIAGNOSTIC_CHARS = 4096


class BuildError(RuntimeError):
    pass


class ProviderHold(BuildError):
    pass


def _bounded(value: str | None) -> str:
    text = value or ""
    return text if len(text) <= MAX_DIAGNOSTIC_CHARS else text[:MAX_DIAGNOSTIC_CHARS] + "...[truncated]"


def _safe_command(command: list[str]) -> str:
    return " ".join(value.replace("\n", " ")[:256] for value in command)


def _process_failure(stage: str, command: list[str], result: subprocess.CompletedProcess[str]) -> str:
    return f"stage={stage}; command={_safe_command(command)}; returncode={result.returncode}; stdout={_bounded(result.stdout)}; stderr={_bounded(result.stderr)}"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise ProviderHold(f"tool-unavailable:{name}")
    return path


def run(command: list[str], *, cwd: Path | None = None, stage: str | None = None, timeout: int = 1800) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BuildError(f"stage={stage or command[0]}; command={_safe_command(command)}; execution-failed") from error
    if result.returncode != 0:
        raise BuildError(_process_failure(stage or command[0], command, result))
    return result


def download_verified(url: str, expected: str, cache_path: Path) -> Path:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    if cache_path.is_file() and sha256_file(cache_path) == expected:
        return cache_path
    if cache_path.exists():
        cache_path.unlink()
    request = Request(url, headers={"User-Agent": "swooshz-managed-qualification/1"})
    try:
        with urlopen(request, timeout=60) as response, cache_path.open("xb") as destination:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                destination.write(chunk)
    except (OSError, ValueError) as error:
        raise ProviderHold("pinned-download-failed") from error
    if sha256_file(cache_path) != expected:
        cache_path.unlink(missing_ok=True)
        raise BuildError("pinned-download-hash-mismatch")
    return cache_path


def safe_extract(archive: Path, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        if not members or any(member.name.startswith("/") or ".." in Path(member.name).parts for member in members):
            raise BuildError("archive-path-invalid")
        if any(member.issym() or member.islnk() or not (member.isfile() or member.isdir()) for member in members):
            raise BuildError("archive-member-invalid")
        tar.extractall(destination)
    roots = {member.name.split("/", 1)[0] for member in members}
    if len(roots) != 1:
        raise BuildError("archive-root-invalid")
    extracted = destination / next(iter(roots))
    if not extracted.is_dir():
        raise BuildError("archive-root-missing")
    return extracted


def apply_exact_patch(source_root: Path, patch_path: Path) -> None:
    patch_tool = require_tool("patch")
    command = [patch_tool, "--posix", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(patch_path.resolve())]
    run(command, cwd=source_root, stage="apply-managed-patch", timeout=120)


def capture_version(sshd: Path) -> str:
    result = subprocess.run([str(sshd), "-V"], check=False, text=True, capture_output=True)
    version = (result.stderr or result.stdout).strip()
    if result.returncode not in (0, 1) or "OpenSSH_10.5p1" not in version or "swz-baseline=openssh-10.5p1" not in version:
        raise BuildError("openssh-version-proof-failed")
    return version


def build_openssh(lock: dict[str, Any], output: Path, cache: Path) -> dict[str, str]:
    if platform.system() != "Linux":
        raise ProviderHold("openssh-posix-build-required")
    entry = lock["openssh"]
    archive = download_verified(entry["url"], entry["sha256"], cache / "openssh-10.5p1.tar.gz")
    source = safe_extract(archive, output / "sources")
    apply_exact_patch(source, HERE / entry["patch"])
    prefix = (output / "openssh-prefix").resolve()
    prefix.mkdir(parents=True, exist_ok=True)
    configure = ["./configure", f"--prefix={prefix}", *entry["configure"]]
    run(configure, cwd=source, stage="openssh-configure", timeout=300)
    run(["make", "-j2"], cwd=source, stage="openssh-build", timeout=1200)
    run(["make", "install-nokeys"], cwd=source, stage="openssh-install", timeout=600)
    binary = source / "sshd"
    if not binary.is_file():
        raise BuildError("openssh-binary-missing")
    installed = output / "openssh" / "sbin" / "sshd"
    installed.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(binary, installed)
    version = capture_version(installed)
    return {"version": version, "archive_sha256": entry["sha256"], "patch_sha256": sha256_file(HERE / entry["patch"]), "binary_sha256": sha256_file(installed), "prefix": str(prefix), "prefix_absolute": str(prefix.is_absolute())}


def build_musl(lock: dict[str, Any], output: Path, cache: Path) -> dict[str, str]:
    if platform.system() != "Linux":
        raise ProviderHold("musl-posix-build-required")
    entry = lock["musl"]
    archive = download_verified(entry["url"], entry["sha256"], cache / "musl-1.2.5.tar.gz")
    source = safe_extract(archive, output / "sources")
    apply_exact_patch(source, HERE / entry["patch"])
    prefix = (output / "musl-prefix").resolve()
    prefix.mkdir(parents=True, exist_ok=True)
    run(["./configure", f"--prefix={prefix}"], cwd=source, stage="musl-configure", timeout=300)
    run(["make", "-j2"], cwd=source, stage="musl-build", timeout=1200)
    run(["make", "install"], cwd=source, stage="musl-install", timeout=600)
    libc = prefix / "lib" / "libc.so"
    if not libc.is_file():
        raise BuildError("musl-libc-missing")
    return {"version": "1.2.5", "archive_sha256": entry["sha256"], "patch_sha256": sha256_file(HERE / entry["patch"]), "libc_sha256": sha256_file(libc), "prefix": str(prefix), "prefix_absolute": str(prefix.is_absolute())}


def build_native(output: Path) -> dict[str, str]:
    if platform.system() != "Linux":
        raise ProviderHold("native-posix-build-required")
    require_tool("cc")
    require_tool("make")
    native = output / "native"
    native.mkdir(parents=True, exist_ok=True)
    run(["make", "-C", str(HERE), "all", f"BUILD={native}", f"CFLAGS={NATIVE_FLAGS}"], stage="native-c11-build", timeout=600)
    run(["make", "-C", str(HERE), "static-closure", f"BUILD={native}", f"CFLAGS={NATIVE_FLAGS}"], stage="native-static-closure", timeout=300)
    kat = native / "native-unit"
    run([require_tool("cc"), *NATIVE_FLAGS.split(), "-I", str(HERE), str(ROOT / "tests/recovery-managed/native_unit.c"), str(HERE / "platform.c"), str(HERE / "protocol.c"), "-lcrypto", "-o", str(kat)], stage="native-kat-build", timeout=300)
    result = subprocess.run([str(kat)], text=True, capture_output=True, check=False, timeout=30)
    if result.returncode != 0:
        raise BuildError(_process_failure("native-kat-run", [str(kat)], result))
    binaries = {path.name: sha256_file(path) for path in sorted(native.glob("*") ) if path.is_file() and path.name != "native-unit"}
    return binaries


def write_manifest(output: Path, lock: dict[str, Any], openssh: dict[str, str], musl: dict[str, str], native: dict[str, str]) -> Path:
    candidate = os.environ.get("SWZ_CANDIDATE_SHA")
    if candidate is None or len(candidate) != 40 or any(char not in "0123456789abcdef" for char in candidate):
        raise BuildError("candidate-sha-required")
    source_files = {path.name: sha256_file(path) for path in sorted(HERE.iterdir()) if path.is_file() and path.suffix in {".c", ".h", ".json", ".patch", ""}}
    manifest = {
        "schema": "swz-managed-build-manifest.v1", "candidate_sha": candidate,
        "openssh": {"version": "OpenSSH_10.5p1", "archive_sha256": openssh.get("archive_sha256", ""), "patch_sha256": openssh.get("patch_sha256", ""), "binary_sha256": openssh.get("binary_sha256", ""), "ssh_sha256": "", "ssh_keygen_sha256": "", "ssh_agent_sha256": "", "ssh_add_sha256": "", "sshd_version": openssh.get("version", ""), "host_key": "/etc/ssh/recovery_host_ed25519_key.pub", "host_key_agent": "/run/swz/recovery-hostkey-agent.sock", "session_control": "/run/swz/recovery-session-control.sock"},
        "musl": {"version": "1.2.5", "archive_sha256": musl.get("archive_sha256", ""), "patch_sha256": musl.get("patch_sha256", ""), "libc_sha256": musl.get("libc_sha256", "")},
        "native": native, "source_files": source_files,
    }
    path = output / "build-manifest.json"
    path.write_text(json.dumps(manifest, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8", newline="")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=HERE / "build-output")
    parser.add_argument("--native-only", action="store_true")
    args = parser.parse_args(argv)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    native = build_native(output)
    if args.native_only:
        write_manifest(output, lock, {}, {}, native)
        return 0
    cache = (output.parent / "recovery-managed-cache").resolve()
    openssh = build_openssh(lock, output, cache)
    musl = build_musl(lock, output, cache)
    write_manifest(output, lock, openssh, musl, native)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProviderHold as error:
        print(f"QUALIFICATION_PROVIDER_HOLD={error}", file=sys.stderr)
        raise SystemExit(2)
    except BuildError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
