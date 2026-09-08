import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
MANAGED = ROOT / "recovery/managed"


class OpenSSHBoundaryTests(unittest.TestCase):
    def test_pinned_sources_and_exact_runtime_paths(self):
        lock = json.loads((MANAGED / "build.lock.json").read_text(encoding="utf-8"))
        self.assertEqual(lock["openssh"]["version"], "10.5p1")
        self.assertEqual(lock["openssh"]["patch"], "openssh-managed.patch")
        self.assertEqual(lock["musl"]["version"], "1.2.5")
        self.assertEqual(lock["musl"]["patch"], "musl-security.patch")
        config = (MANAGED / "sshd_config").read_text(encoding="ascii")
        self.assertIn("HostKey /etc/ssh/recovery_host_ed25519_key.pub", config)
        self.assertIn("HostKeyAgent /run/swz/recovery-hostkey-agent.sock", config)
        self.assertIn("ForceCommand /usr/local/libexec/swz-dispatcher", config)
        self.assertNotIn("SSH_AUTH_SOCK", config)

    def test_patch_and_process_order_are_contractual(self):
        patch = (MANAGED / "openssh-managed.patch").read_text(encoding="utf-8")
        supervisor = (MANAGED / "supervisor.c").read_text(encoding="utf-8")
        custodian = (MANAGED / "custodian.c").read_text(encoding="utf-8")
        dispatcher = (MANAGED / "dispatcher.c").read_text(encoding="utf-8")
        bootstrap = (MANAGED / "bootstrap.c").read_text(encoding="utf-8")
        self.assertIn("SWZ_MANAGED_OPENSSH_BASELINE", patch)
        self.assertIn("ssh_get_authentication_socket_path", patch)
        self.assertIn("SWZREG01", custodian)
        self.assertIn("SWZRGOK1", custodian)
        self.assertIn("SWZDIS01", custodian)
        self.assertIn("SWZRET01", custodian)
        self.assertLess(supervisor.index("send_registration("), supervisor.index("SWZ_EXEC_GATE_BYTE"))
        self.assertLess(supervisor.index("SWZ_EXEC_GATE_BYTE"), supervisor.index("execl(SWZ_SSHD_PATH"))
        self.assertIn("SWZ_SESSION_CONTROL_SOCKET_PATH", bootstrap)
        self.assertIn("SOCK_SEQPACKET", bootstrap)
        self.assertIn("recvmsg(", bootstrap)
        self.assertIn("SWZ_CONTEXT_MAGIC", bootstrap)
        self.assertNotIn("SWZ_CONTEXT_FD", bootstrap)
        self.assertNotIn("getenv(", bootstrap)
        self.assertNotIn("getopt(", bootstrap)
        self.assertIn("SSH_ORIGINAL_COMMAND", dispatcher)

    def test_openssh_install_is_unprivileged_destdir_staged(self):
        lock = json.loads((MANAGED / "build.lock.json").read_text(encoding="utf-8"))
        build = (MANAGED / "build.py").read_text(encoding="utf-8")
        self.assertIn("--with-privsep-path=/run/sshd", lock["openssh"]["configure"])
        self.assertIn('install_root = (output / "openssh-install-root").resolve()', build)
        self.assertIn('run(["make", "install-nokeys", f"DESTDIR={install_root}"],', build)
        self.assertIn('staged_privsep = install_root / "run" / "sshd"', build)
        self.assertIn('staged_prefix = install_root / prefix.relative_to(prefix.anchor)', build)
        self.assertIn('staged_binary = staged_prefix / "sbin" / "sshd"', build)
        self.assertIn('staged_session = staged_libexec / "sshd-session"', build)
        self.assertIn('staged_auth = staged_libexec / "sshd-auth"', build)
        self.assertIn("version = capture_version(staged_binary)", build)
        self.assertIn("shutil.copy2(staged_binary, installed)", build)
        self.assertNotIn("sudo", build)
        self.assertNotIn("mkdir -p -m 0755 /run/sshd", build)


if __name__ == "__main__":
    unittest.main()
