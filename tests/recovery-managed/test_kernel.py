import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
MANAGED = ROOT / "recovery/managed"


class GuestSecurityContractTests(unittest.TestCase):
    def test_kernel_enables_boundary_primitives(self):
        config = (MANAGED / "kernel.config").read_text(encoding="ascii")
        for setting in ("CONFIG_NAMESPACES=y", "CONFIG_PID_NS=y", "CONFIG_NET_NS=y", "CONFIG_SECCOMP=y", "CONFIG_DM_VERITY=y", "CONFIG_SECURITY_SELINUX=y", "CONFIG_SECURITY_SELINUX_DEVELOP=n"):
            self.assertIn(setting, config)

    def test_image_layout_forbids_host_mounts_and_overlay(self):
        layout = json.loads((MANAGED / "image-layout.json").read_text(encoding="utf-8"))
        self.assertTrue(layout["boot"]["root_hash_required"])
        self.assertFalse(layout["rootfs_overlay"])
        self.assertFalse(layout["bind_mounts"])
        self.assertIn("/var/run/docker.sock", layout["forbidden_mounts"])
        self.assertIn("/artifact-host", layout["forbidden_mounts"])

    def test_selinux_policy_has_enforcing_boundary_and_denials(self):
        policy = (MANAGED / "selinux.cil").read_text(encoding="ascii")
        contexts = (MANAGED / "file_contexts").read_text(encoding="ascii")
        self.assertIn("swz_sshd_t", policy)
        self.assertIn("neverallow swz_sshd_t swz_recovery_seed_t", policy)
        self.assertIn("swz-supervisor", contexts)
        self.assertIn("swz-agent", contexts)


if __name__ == "__main__":
    unittest.main()

