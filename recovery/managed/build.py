"""Reproducible disposable build for the managed recovery boundary."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
LOCK_PATH = HERE / "build.lock.json"
SCHEMA_PATH = HERE / "manifest.schema.json"


class BuildError(RuntimeError):
    pass


class ProviderHold(BuildError):
    pass


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


def run(command: list[str], *, cwd: Path | None = None) -> None:
    try:
        result = subprocess.run(command, cwd=cwd, check=False, text=True, capture_output=True)
    except OSError as error:
        raise ProviderHold(f"process-unavailable:{command[0]}") from error
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        raise BuildError(f"command-failed:{command[0]}:{detail[-1] if detail else result.returncode}")


def download_verified(url: str, expected: str, cache_path: Path) -> Path:
    if cache_path.is_file():
        actual = sha256_file(cache_path)
        if actual != expected:
            raise BuildError(f"cached-source-digest-mismatch:{cache_path.name}")
        return cache_path
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = cache_path.with_suffix(cache_path.suffix + ".partial")
    try:
        with urllib.request.urlopen(url, timeout=30) as response, temporary.open("wb") as output:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                output.write(chunk)
        if sha256_file(temporary) != expected:
            raise BuildError(f"download-digest-mismatch:{cache_path.name}")
        temporary.replace(cache_path)
    except (OSError, TimeoutError, urllib.error.URLError) as error:
        raise ProviderHold(f"source-download-unavailable:{cache_path.name}") from error
    return cache_path


def safe_extract(archive: Path, destination: Path) -> Path:
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        for member in members:
            target = (destination / member.name).resolve()
            if destination.resolve() not in target.parents and target != destination.resolve():
                raise BuildError("archive-path-traversal")
            if member.issym() or member.islnk():
                raise BuildError("archive-link-entry")
        tar.extractall(destination, filter="data")
    roots = {member.name.split("/", 1)[0] for member in members if member.name}
    if len(roots) != 1:
        raise BuildError("archive-root-ambiguous")
    root = destination / next(iter(roots))
    if not root.is_dir():
        raise BuildError("archive-root-missing")
    return root


def apply_exact_patch(source_root: Path, patch_path: Path) -> None:
    patch_tool = require_tool("patch")
    base = [patch_tool, "--posix", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(patch_path)]
    for command in ([patch_tool, "--dry-run", *base[1:]], base):
        try:
            result = subprocess.run(command, cwd=source_root, check=False, text=True, capture_output=True)
        except OSError as error:
            raise ProviderHold(f"process-unavailable:{command[0]}") from error
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip().splitlines()
            raise BuildError(f"command-failed:{command[0]}:{detail[-1] if detail else result.returncode}")
        output = ((result.stdout or "") + (result.stderr or "")).lower()
        if "offset" in output or "fuzz" in output:
            raise BuildError("patch-application-not-exact")


def capture_version(sshd: Path) -> str:
    try:
        result = subprocess.run([str(sshd), "-V"], check=False, text=True, capture_output=True)
    except OSError as error:
        raise BuildError("openssh-version-execution-failed") from error
    output = (result.stdout or "") + (result.stderr or "")
    if "OpenSSH_10.5p1" not in output or "swz-baseline=openssh-10.5p1" not in output:
        raise BuildError("openssh-provenance-not-runtime-derived")
    return "OpenSSH_10.5p1"


def build_openssh(lock: dict[str, Any], output: Path, cache: Path) -> dict[str, str]:
    if platform.system() != "Linux":
        raise ProviderHold("openssh-posix-build-required")
    require_tool("make")
    require_tool("patch")
    require_tool("cc")
    if base64.b64encode(bytes.fromhex(lock["sha256"])).decode("ascii") != lock["release_sha256_base64"]:
        raise BuildError("openssh-release-digest-record-mismatch")
    archive = download_verified(lock["url"], lock["sha256"], cache / "openssh-10.5p1.tar.gz")
    with tempfile.TemporaryDirectory(prefix="swz-openssh-") as temporary:
        source = safe_extract(archive, Path(temporary))
        apply_exact_patch(source, HERE / lock["patch"])
        if "SWZ_MANAGED_OPENSSH_BASELINE" not in (source / "version.h").read_text(encoding="ascii") or \
                "swz-baseline=%s" not in (source / "sshd.c").read_text(encoding="ascii"):
            raise BuildError("openssh-patch-marker-missing")
        configure = [
            "./configure",
            *lock["configure"],
        ]
        run(configure, cwd=source)
        run(["make", "-j2"], cwd=source)
        sshd = source / "sshd"
        ssh = source / "ssh"
        keygen = source / "ssh-keygen"
        agent = source / "ssh-agent"
        add = source / "ssh-add"
        if not all(path.is_file() for path in (sshd, ssh, keygen, agent, add)):
            raise BuildError("openssh-binary-missing")
        version = capture_version(sshd)
        destination = output / "openssh"
        (destination / "sbin").mkdir(parents=True, exist_ok=True)
        (destination / "bin").mkdir(parents=True, exist_ok=True)
        shutil.copy2(sshd, destination / "sbin" / "sshd")
        shutil.copy2(ssh, destination / "bin" / "ssh")
        shutil.copy2(keygen, destination / "bin" / "ssh-keygen")
        shutil.copy2(agent, destination / "bin" / "ssh-agent")
        shutil.copy2(add, destination / "bin" / "ssh-add")
    return {
        "version": version,
        "archive_sha256": sha256_file(archive),
        "patch_sha256": sha256_file(HERE / lock["patch"]),
        "binary_sha256": sha256_file(output / "openssh" / "sbin" / "sshd"),
        "ssh_sha256": sha256_file(output / "openssh" / "bin" / "ssh"),
        "ssh_keygen_sha256": sha256_file(output / "openssh" / "bin" / "ssh-keygen"),
        "ssh_agent_sha256": sha256_file(output / "openssh" / "bin" / "ssh-agent"),
        "ssh_add_sha256": sha256_file(output / "openssh" / "bin" / "ssh-add"),
        "sshd_version": version,
    }


def build_musl(lock: dict[str, Any], output: Path, cache: Path) -> dict[str, str]:
    if platform.system() != "Linux":
        raise ProviderHold("musl-posix-build-required")
    require_tool("make")
    require_tool("patch")
    archive = download_verified(lock["url"], lock["sha256"], cache / "musl-1.2.5.tar.gz")
    with tempfile.TemporaryDirectory(prefix="swz-musl-") as temporary:
        source = safe_extract(archive, Path(temporary))
        apply_exact_patch(source, HERE / lock["patch"])
        if "aux[AT_RANDOM] == 0" not in (source / "src/env/__libc_start_main.c").read_text(encoding="ascii"):
            raise BuildError("musl-patch-marker-missing")
        prefix = output / "musl"
        run(["./configure", f"--prefix={prefix}"], cwd=source)
        run(["make", "-j2"], cwd=source)
        run(["make", "install"], cwd=source)
        libc = prefix / "lib" / "libc.so"
        if not libc.is_file():
            raise BuildError("musl-libc-missing")
    return {
        "version": lock["version"],
        "archive_sha256": sha256_file(archive),
        "patch_sha256": sha256_file(HERE / lock["patch"]),
        "libc_sha256": sha256_file(libc),
    }


def build_native(output: Path) -> dict[str, str]:
    if platform.system() != "Linux":
        raise ProviderHold("native-posix-build-required")
    make = require_tool("make")
    require_tool("cc")
    native_output = output / "native"
    run([make, "-C", str(HERE), f"BUILD={native_output}", "all"])
    binaries = sorted(native_output.glob("swz-*"))
    if len(binaries) != 7 or any(not path.is_file() for path in binaries):
        raise BuildError("native-component-set-incomplete")
    return {path.name: sha256_file(path) for path in binaries}


def write_manifest(output: Path, lock: dict[str, Any], openssh: dict[str, str], musl: dict[str, str], native: dict[str, str]) -> Path:
    candidate = os.environ.get("SWZ_CANDIDATE_SHA")
    if candidate is None:
        try:
            candidate = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        except (OSError, subprocess.CalledProcessError) as error:
            raise BuildError("candidate-sha-unavailable") from error
    if len(candidate) != 40 or any(char not in "0123456789abcdef" for char in candidate):
        raise BuildError("candidate-sha-invalid")
    source_files = {
        "build.lock.json": sha256_file(LOCK_PATH),
        "manifest.schema.json": sha256_file(SCHEMA_PATH),
        "openssh-managed.patch": sha256_file(HERE / lock["openssh"]["patch"]),
        "musl-security.patch": sha256_file(HERE / lock["musl"]["patch"]),
        "sshd_config": sha256_file(HERE / "sshd_config"),
        "selinux.cil": sha256_file(HERE / "selinux.cil"),
        "accounts.json": sha256_file(HERE / "accounts.json"),
        "file_contexts": sha256_file(HERE / "file_contexts"),
        "kernel.config": sha256_file(HERE / "kernel.config"),
    }
    manifest = {
        "schema": "swz-managed-build-manifest.v1",
        "candidate_sha": candidate,
        "openssh": openssh,
        "musl": musl,
        "native": native,
        "source_files": source_files,
    }
    path = output / "build-manifest.json"
    path.write_text(json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=HERE / "build-output")
    parser.add_argument("--cache", type=Path, default=Path(".swz-source-cache"))
    parser.add_argument("--check-source", action="store_true")
    args = parser.parse_args(argv)
    try:
        lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
        args.output.mkdir(parents=True, exist_ok=True)
        args.cache.mkdir(parents=True, exist_ok=True)
        if args.check_source:
            for key, name in (("openssh", "openssh-10.5p1.tar.gz"), ("musl", "musl-1.2.5.tar.gz")):
                download_verified(lock[key]["url"], lock[key]["sha256"], args.cache / name)
            print("SOURCE_PROVENANCE=PASS")
            return 0
        openssh = build_openssh(lock["openssh"], args.output, args.cache)
        musl = build_musl(lock["musl"], args.output, args.cache)
        native = build_native(args.output)
        manifest = write_manifest(args.output, lock, openssh, musl, native)
        print(json.dumps({"status": "PASS", "manifest": str(manifest)}, sort_keys=True))
        return 0
    except ProviderHold as error:
        print(f"QUALIFICATION_PROVIDER_HOLD={error}", file=sys.stderr)
        return 75
    except (BuildError, OSError, json.JSONDecodeError) as error:
        print(f"CANDIDATE_DEFECT={error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
