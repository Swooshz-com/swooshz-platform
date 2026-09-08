import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
MANAGED = ROOT / "recovery" / "managed"


class OpenSSHContractTests(unittest.TestCase):
    def test_pinned_runtime_paths_and_direct_agent_socket(self):
        config = (MANAGED / "sshd_config").read_text(encoding="ascii")
        self.assertIn("HostKey /etc/ssh/recovery_host_ed25519_key.pub", config)
        self.assertIn("HostKeyAgent /run/swz/recovery-hostkey-agent.sock", config)
        self.assertNotIn("HostKeyAgent SSH_AUTH_SOCK", config)
        self.assertNotIn("Subsystem", config)
        self.assertIn("ForceCommand /usr/local/libexec/swz-dispatcher", config)

    def test_openssh_patch_removes_environment_bridge(self):
        patch = (MANAGED / "openssh-managed.patch").read_text(encoding="ascii")
        self.assertIn("SWZ_MANAGED_OPENSSH_BASELINE", patch)
        self.assertIn("ssh_get_authentication_socket_path(options.host_key_agent", patch)
        self.assertNotIn("swz_managed_runtime_authorized", patch)
        added_lines = "\n".join(
            line[1:] for line in patch.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        )
        self.assertNotIn("setenv(SSH_AUTHSOCKET_ENV_NAME", added_lines)

    def test_runtime_does_not_stage_stock_agent_binaries(self):
        build = (MANAGED / "build.py").read_text(encoding="utf-8")
        install = (MANAGED / "install-plan.py").read_text(encoding="utf-8")
        guest = (MANAGED / "qualification-vm.py").read_text(encoding="utf-8")
        self.assertNotIn("copy2(agent", build)
        self.assertNotIn("copy2(add", build)
        self.assertNotIn("openssh/bin/ssh-agent", install)
        self.assertNotIn("openssh/bin/ssh-add", install)
        self.assertNotIn("/opt/swz/openssh/bin/ssh-agent", guest)
        self.assertNotIn("/opt/swz/openssh/bin/ssh-add", guest)

    def test_registration_precedes_gate_and_exec(self):
        source = (MANAGED / "supervisor.c").read_text(encoding="utf-8")
        registration = source.index("send_registration(")
        gate = source.index("SWZ_EXEC_GATE_BYTE", registration)
        execute = source.index('execl(SWZ_SSHD_PATH', gate)
        self.assertLess(registration, gate)
        self.assertLess(gate, execute)
        self.assertIn("swz_pidfd_open", source)
        self.assertIn("swz_send_fd", source)
        self.assertIn("SWZRGOK1", source)
        self.assertIn("disable_signing", source)

    def test_registration_payload_and_custodian_ack_are_exact(self):
        supervisor = (MANAGED / "supervisor.c").read_text(encoding="utf-8")
        custodian = (MANAGED / "custodian.c").read_text(encoding="utf-8")
        self.assertIn("SWZ_REGISTRATION_BYTES", supervisor)
        self.assertIn("swz_send_fd(control_fd, sshd_pidfd", supervisor)
        self.assertIn("SWZRGOK1", custodian)
        self.assertIn("swz_receive_fd(state->control_fd", custodian)
        self.assertIn("state->registration_expected", custodian)
        self.assertIn('"SWZDIS01"', supervisor)
        self.assertIn('"SWZRET01"', supervisor)

    def test_bootstrap_and_dispatcher_keep_kernel_bound_context_boundary(self):
        bootstrap = (MANAGED / "bootstrap.c").read_text(encoding="utf-8")
        dispatcher = (MANAGED / "dispatcher.c").read_text(encoding="utf-8")
        supervisor = (MANAGED / "supervisor.c").read_text(encoding="utf-8")
        self.assertIn("swz_process_domain_matches(SWZ_EXPECTED_BOOTSTRAP_DOMAIN)", bootstrap)
        self.assertIn("swz_peer_domain_matches(control, SWZ_EXPECTED_BOOTSTRAP_DOMAIN)", supervisor)
        self.assertIn("static const char bootstrap[] = SWZ_BOOTSTRAP_PATH", dispatcher)
        self.assertIn("swz_read_context_record", bootstrap)

    def test_bootstrap_context_is_not_cli_or_environment_authority(self):
        bootstrap = (MANAGED / "bootstrap.c").read_text(encoding="utf-8")
        self.assertIn("SWZ_SESSION_CONTROL_SOCKET_PATH", bootstrap)
        self.assertIn("swz_read_context_record", bootstrap)
        self.assertIn("SWZ_CONTEXT_FD", bootstrap)
        self.assertNotIn("getenv(", bootstrap)
        self.assertNotIn("getopt", bootstrap)


def run_live_inetd_session(build_output: pathlib.Path) -> dict[str, str]:
    raise RuntimeError("real-pinned-openssh-handshake-isolated-guest-required")


if __name__ == "__main__":
    unittest.main()
