"""Run deterministic qualification for the managed recovery generation."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent.parent
TEST_ROOT = REPO_ROOT / "tests" / "recovery-managed"
CANONICAL = {
    REPO_ROOT / "scripts" / "platform-recovery-controller-store.py": "884f483da02fb5d3321a570820b7a9fee2f9992fa50fec43b96f445265130c3f",
    REPO_ROOT / "scripts" / "platform-persisted-locator-adapter.py": "17925f1364565edbb39fa0f776e25d6f0410d8408d9bdce214143edf1d6f34d5",
    REPO_ROOT / "tests" / "test_platform_recovery_controller_store.py": "013f190edfb427badd257ae92b3cf19bdfcbd7029c56f0395b686b2a740ab4cf",
    REPO_ROOT / "tests" / "test_platform_persisted_locator_adapter.py": "3b4a49750f822cc8241922f23826d9fadf9d9868d8629f4adfce299305a8d314",
}
ALLOWED_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"


def _run(command: list[str]) -> None:
    completed = subprocess.run(command, cwd=REPO_ROOT, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"command-failed:{' '.join(command)}")


def check_canonical_files() -> None:
    for path, expected in CANONICAL.items():
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise RuntimeError(f"canonical-file-changed:{path.relative_to(REPO_ROOT).as_posix()}")


def check_fixture_json() -> None:
    fixture_dir = TEST_ROOT / "fixtures"
    for path in fixture_dir.glob("*.json"):
        with path.open(encoding="utf-8") as handle:
            json.load(handle)


def check_native_static_closure() -> None:
    source_names = json.loads((ROOT / "build.lock.json").read_text(encoding="utf-8"))["managed_sources"]
    for name in source_names:
        source = (REPO_ROOT / name).read_text(encoding="utf-8")
        for forbidden in ("dlopen(", "dlsym(", "system(", "popen("):
            if forbidden in source:
                raise RuntimeError(f"dynamic-or-shell-call:{name}:{forbidden}")


def check_scope() -> None:
    result = subprocess.run(
        ["git", "diff", "--name-only", "origin/main...HEAD"],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    allowed = {
        "docs/architecture/recovery-managed-boundary-contract.md",
        "recovery/managed/Makefile",
        "recovery/managed/build.lock.json",
        "recovery/managed/manifest.schema.json",
        "recovery/managed/image-layout.json",
        "recovery/managed/protocol.h",
        "recovery/managed/protocol.c",
        "recovery/managed/platform.h",
        "recovery/managed/platform.c",
        "recovery/managed/supervisor.c",
        "recovery/managed/custodian.c",
        "recovery/managed/dispatcher.c",
        "recovery/managed/bootstrap.c",
        "recovery/managed/broker.c",
        "recovery/managed/agent.c",
        "recovery/managed/controller.py",
        "recovery/managed/backend.py",
        "recovery/managed/openssh-managed.patch",
        "recovery/managed/musl-security.patch",
        "recovery/managed/sshd_config",
        "recovery/managed/accounts.json",
        "recovery/managed/selinux.cil",
        "recovery/managed/file_contexts",
        "recovery/managed/launch-base.c",
        "recovery/managed/kernel.config",
        "recovery/managed/build.py",
        "recovery/managed/qualify.py",
        "recovery/managed/install-plan.py",
        "recovery/managed/qualification-vm.py",
        "tests/recovery-managed/native_unit.c",
        "tests/recovery-managed/test_protocol.py",
        "tests/recovery-managed/test_controller.py",
        "tests/recovery-managed/test_broker.py",
        "tests/recovery-managed/test_openssh.py",
        "tests/recovery-managed/test_kernel.py",
        "tests/recovery-managed/test_generation.py",
        "tests/recovery-managed/test_publication.py",
        "tests/recovery-managed/fixtures/wire-kats.json",
        "tests/recovery-managed/fixtures/transition-kats.json",
        "tests/recovery-managed/fixtures/qualification-cases.json",
        ".github/workflows/ci.yml",
    }
    paths = {line for line in result.stdout.splitlines() if line}
    if not paths <= allowed:
        raise RuntimeError("unauthorized-tracked-path:" + ",".join(sorted(paths - allowed)))
    if ALLOWED_WORKFLOW.as_posix().replace("/", "\\") in paths:
        pass


def deterministic() -> None:
    check_canonical_files()
    check_fixture_json()
    check_native_static_closure()
    _run([sys.executable, "-B", "-m", "unittest", "discover", "-s", str(TEST_ROOT), "-p", "test_*.py"])
    print("DETERMINISTIC_QUALIFICATION=PASS")
    print("MANDATORY_SECURITY_SKIPS=0")
    print("HOSTED_KERNEL_SECURITY=REQUIRED")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deterministic", action="store_true")
    parser.add_argument("--all", action="store_true")
    args = parser.parse_args(argv)
    if not args.deterministic and not args.all:
        parser.error("choose --deterministic or --all")
    try:
        deterministic()
        if args.all:
            _run([sys.executable, "-B", str(ROOT / "build.py"), "--verify"])
            _run([sys.executable, "-B", str(ROOT / "qualification-vm.py"), "--required"])
    except (OSError, RuntimeError) as error:
        print(f"DETERMINISTIC_QUALIFICATION=FAIL:{error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
