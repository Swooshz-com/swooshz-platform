import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class KernelQualificationContractTests(unittest.TestCase):
    def test_kernel_configuration_requires_guest_security_primitives(self):
        config = (ROOT / "recovery/managed/kernel.config").read_text(encoding="ascii").splitlines()
        self.assertIn("CONFIG_SECURITY_SELINUX=y", config)
        self.assertIn("CONFIG_DM_VERITY=y", config)
        self.assertIn("CONFIG_SECCOMP_FILTER=y", config)
        self.assertIn("CONFIG_NET_NS=y", config)

    def test_image_layout_forbids_host_and_docker_mounts(self):
        layout = json.loads((ROOT / "recovery/managed/image-layout.json").read_text(encoding="utf-8"))
        self.assertFalse(layout["bind_mounts"])
        self.assertFalse(layout["rootfs_overlay"])
        self.assertIn("/var/run/docker.sock", layout["forbidden_mounts"])
        self.assertTrue(layout["boot"]["root_hash_required"])

    def test_guest_harness_requires_real_guest_markers(self):
        source = (ROOT / "recovery/managed/qualification-vm.py").read_text(encoding="utf-8")
        self.assertIn("SWZ_GUEST_SELINUX=Enforcing", source)
        self.assertIn("SWZ_GUEST_DM_VERITY=PASS", source)
        self.assertIn('"-machine", "q35"', source)
        self.assertNotIn('"-machine", "none"', source)
        self.assertIn("mkfs.ext4", source)
        self.assertIn("switch_root", source)
        self.assertIn("veritysetup open", source)

    def test_guest_fixtures_survive_runtime_overlays(self):
        source = (ROOT / "recovery/managed/qualification-vm.py").read_text(encoding="utf-8")
        self.assertIn('seed = root / "etc/swz/qualification"', source)
        self.assertIn("cp -R /etc/swz/qualification/run/. /run/swz/", source)
        self.assertIn("cp -R /etc/swz/qualification/store/. /var/lib/swz/store/", source)


if __name__ == "__main__":
    unittest.main()
