import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MANAGED = REPO_ROOT / "recovery" / "managed"


class KernelPolicyTests(unittest.TestCase):
    def test_required_kernel_controls_are_explicit(self) -> None:
        config = (MANAGED / "kernel.config").read_text(encoding="utf-8")
        required = {
            "CONFIG_MODULES": "n",
            "CONFIG_SECCOMP": "y",
            "CONFIG_SECCOMP_FILTER": "y",
            "CONFIG_DM_VERITY": "y",
            "CONFIG_SECURITY_SELINUX": "y",
            "CONFIG_DEFAULT_SECURITY_SELINUX": "y",
            "CONFIG_USER_NS": "n",
            "CONFIG_OVERLAY_FS": "n",
            "CONFIG_KEXEC": "n",
            "CONFIG_KEXEC_FILE": "n",
        }
        entries = dict(re.findall(r"^(CONFIG_[A-Z0-9_]+)=(.*)$", config, re.MULTILINE))
        self.assertEqual(entries, dict(entries))
        for name, value in required.items():
            self.assertEqual(entries.get(name), value)

    def test_no_duplicate_kernel_assignments_or_writable_root(self) -> None:
        lines = [line for line in (MANAGED / "kernel.config").read_text(encoding="utf-8").splitlines() if line]
        names = [line.split("=", 1)[0] for line in lines if line.startswith("CONFIG_")]
        self.assertEqual(len(names), len(set(names)))
        layout = (MANAGED / "image-layout.json").read_text(encoding="utf-8")
        self.assertIn('"rootfs_read_only": true', layout)
        self.assertIn('"writable_paths": []', layout)
        self.assertIn('"forbidden_overlays"', layout)

    def test_selinux_policy_and_contexts_are_scoped(self) -> None:
        cil = (MANAGED / "selinux.cil").read_text(encoding="utf-8")
        contexts = (MANAGED / "file_contexts").read_text(encoding="utf-8")
        self.assertIn("swz_recovery_t", cil)
        self.assertIn("swz_recovery_exec_t", cil)
        self.assertIn("/usr/libexec/swooshz-recovery", contexts)
        self.assertIn("/run/swooshz-recovery", contexts)
        self.assertNotIn("allow unlabeled_t", cil)


if __name__ == "__main__":
    unittest.main()
