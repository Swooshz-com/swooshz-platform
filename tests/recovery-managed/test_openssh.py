import json
import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MANAGED = REPO_ROOT / "recovery" / "managed"


class OpenSSHPolicyTests(unittest.TestCase):
    def test_sshd_policy_is_noninteractive_and_forwarding_closed(self) -> None:
        config = (MANAGED / "sshd_config").read_text(encoding="utf-8")
        for directive in (
            "UsePAM no",
            "PasswordAuthentication no",
            "KbdInteractiveAuthentication no",
            "AuthenticationMethods publickey",
            "PermitRootLogin no",
            "PermitTTY no",
            "AllowAgentForwarding no",
            "AllowTcpForwarding no",
            "GatewayPorts no",
            "PermitTunnel no",
            "X11Forwarding no",
            "DisableForwarding yes",
            "StrictModes yes",
        ):
            self.assertIn(directive, config)
        self.assertIn("ListenAddress __ENROLLED_IPV4__", config)
        self.assertNotIn("PasswordAuthentication yes", config)
        self.assertNotIn("PermitRootLogin yes", config)

    def test_config_has_no_ambient_command_or_key_fallback(self) -> None:
        config = (MANAGED / "sshd_config").read_text(encoding="utf-8")
        self.assertNotRegex(config, re.compile(r"^\s*(AuthorizedKeysCommand|Match exec)\b", re.MULTILINE))
        self.assertNotIn("/root/.ssh", config)
        accounts = json.loads((MANAGED / "accounts.json").read_text(encoding="utf-8"))
        self.assertFalse(accounts["root_login"])
        self.assertFalse(accounts["accounts"][0]["password_login"])
        self.assertEqual(accounts["private_key_process"], "external-custodian")

    def test_patch_inputs_are_pinned_to_named_sources(self) -> None:
        openssh_patch = (MANAGED / "openssh-managed.patch").read_text(encoding="utf-8")
        musl_patch = (MANAGED / "musl-security.patch").read_text(encoding="utf-8")
        self.assertIn("openssh-10.5p1", openssh_patch)
        self.assertIn("musl-1.2.5", musl_patch)
        self.assertNotIn("ssh-rsa", openssh_patch + musl_patch)


if __name__ == "__main__":
    unittest.main()
