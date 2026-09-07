import importlib.util
import pathlib
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
BASE = "3bff98ac5ef10c1675d4691f516952ac937915d3"
ALLOWED = {
    ".github/workflows/ci.yml",
    "docs/architecture/recovery-managed-boundary-contract.md",
    "recovery/managed/Makefile",
    "recovery/managed/accounts.json",
    "recovery/managed/agent.c",
    "recovery/managed/backend.py",
    "recovery/managed/bootstrap.c",
    "recovery/managed/broker.c",
    "recovery/managed/build.lock.json",
    "recovery/managed/build.py",
    "recovery/managed/controller.py",
    "recovery/managed/custodian.c",
    "recovery/managed/dispatcher.c",
    "recovery/managed/file_contexts",
    "recovery/managed/image-layout.json",
    "recovery/managed/install-plan.py",
    "recovery/managed/kernel.config",
    "recovery/managed/launch-base.c",
    "recovery/managed/manifest.schema.json",
    "recovery/managed/musl-security.patch",
    "recovery/managed/openssh-managed.patch",
    "recovery/managed/platform.c",
    "recovery/managed/platform.h",
    "recovery/managed/protocol.c",
    "recovery/managed/protocol.h",
    "recovery/managed/qualification-vm.py",
    "recovery/managed/qualify.py",
    "recovery/managed/selinux.cil",
    "recovery/managed/sshd_config",
    "recovery/managed/supervisor.c",
    "tests/recovery-managed/fixtures/qualification-cases.json",
    "tests/recovery-managed/fixtures/transition-kats.json",
    "tests/recovery-managed/fixtures/wire-kats.json",
    "tests/recovery-managed/native_unit.c",
    "tests/recovery-managed/test_broker.py",
    "tests/recovery-managed/test_controller.py",
    "tests/recovery-managed/test_generation.py",
    "tests/recovery-managed/test_kernel.py",
    "tests/recovery-managed/test_openssh.py",
    "tests/recovery-managed/test_protocol.py",
    "tests/recovery-managed/test_publication.py",
}


class PublicationScopeTests(unittest.TestCase):
    def test_changed_paths_are_within_run_ceiling(self):
        result = subprocess.run(
            ["git", "diff", "--name-only", BASE, "--"],
            cwd=ROOT,
            check=True,
            text=True,
            capture_output=True,
        )
        changed = {line for line in result.stdout.splitlines() if line}
        self.assertTrue(changed <= ALLOWED, sorted(changed - ALLOWED))
        self.assertLessEqual(len(changed), 41)

    def test_canonical_files_are_byte_identical_to_admitted_main(self):
        for relative in (
            "scripts/platform-recovery-controller-store.py",
            "scripts/platform-persisted-locator-adapter.py",
            "tests/test_platform_recovery_controller_store.py",
            "tests/test_platform_persisted_locator_adapter.py",
        ):
            expected = subprocess.check_output(["git", "show", f"{BASE}:{relative}"], cwd=ROOT)
            self.assertEqual((ROOT / relative).read_bytes(), expected, relative)

    def test_required_sources_do_not_contain_acceptance_placeholders(self):
        paths = [
            ROOT / "recovery/managed/agent.c",
            ROOT / "recovery/managed/bootstrap.c",
            ROOT / "recovery/managed/broker.c",
            ROOT / "recovery/managed/controller.py",
            ROOT / "recovery/managed/custodian.c",
            ROOT / "recovery/managed/dispatcher.c",
            ROOT / "recovery/managed/supervisor.c",
        ]
        for path in paths:
            content = path.read_text(encoding="utf-8")
            self.assertNotIn("TODO", content, str(path))
            self.assertNotIn("FIXME", content, str(path))
            self.assertNotIn("restore_hook", content, str(path))
            self.assertNotIn("_store_mutations", content, str(path))


if __name__ == "__main__":
    unittest.main()
