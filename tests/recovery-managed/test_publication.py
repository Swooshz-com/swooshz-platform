import hashlib
import os
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]

ALLOWED = {
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

CANONICAL = {
    "scripts/platform-recovery-controller-store.py": "884f483da02fb5d3321a570820b7a9fee2f9992fa50fec43b96f445265130c3f",
    "scripts/platform-persisted-locator-adapter.py": "17925f1364565edbb39fa0f776e25d6f0410d8408d9bdce214143edf1d6f34d5",
    "tests/test_platform_recovery_controller_store.py": "013f190edfb427badd257ae92b3cf19bdfcbd7029c56f0395b686b2a740ab4cf",
    "tests/test_platform_persisted_locator_adapter.py": "3b4a49750f822cc8241922f23826d9fadf9d9868d8629f4adfce299305a8d314",
}


class PublicationScopeTests(unittest.TestCase):
    def test_canonical_store_and_locator_files_are_unchanged(self) -> None:
        for relative, expected in CANONICAL.items():
            digest = hashlib.sha256((REPO_ROOT / relative).read_bytes()).hexdigest()
            self.assertEqual(digest, expected, relative)

    def test_tracked_diff_is_within_run377_ceiling(self) -> None:
        result = subprocess.run(
            ["git", "diff", "--name-only", "origin/main...HEAD"],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=True,
        )
        paths = {line for line in result.stdout.splitlines() if line}
        self.assertTrue(paths <= ALLOWED, sorted(paths - ALLOWED))
        self.assertLessEqual(len(paths), 41)
        self.assertFalse({".env", "credentials.json", "id_rsa"} & paths)

    def test_branch_name_is_fresh_run377_name(self) -> None:
        branch = subprocess.check_output(
            ["git", "branch", "--show-current"], cwd=REPO_ROOT, text=True
        ).strip()
        expected = "codex/platform-recovery-managed-boundary-store-wire-closed-g3-20260907-377"
        if branch:
            self.assertEqual(branch, expected)
        else:
            self.assertEqual(os.environ.get("GITHUB_HEAD_REF"), expected)


if __name__ == "__main__":
    unittest.main()
