import importlib.util
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
MANAGED = ROOT / "recovery" / "managed"


def load_qualify():
    spec = importlib.util.spec_from_file_location("swz_publication_qualify", MANAGED / "qualify.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


QUALIFY = load_qualify()


class PublicationContractTests(unittest.TestCase):
    def test_scope_is_admitted_and_canonical_files_are_unchanged(self):
        scope = QUALIFY.exact_scope()
        self.assertLessEqual(scope["path_count"], 41)
        self.assertEqual(scope["canonical_files"], "byte-identical")
        self.assertTrue(set(scope["changed_paths"]) <= QUALIFY.ALLOWED_PATHS)

    def test_manifest_and_runtime_paths_are_exact(self):
        schema = json.loads((MANAGED / "manifest.schema.json").read_text(encoding="utf-8"))
        required = schema["properties"]["openssh"]["required"]
        self.assertIn("host_key", required)
        self.assertIn("host_key_agent", required)
        self.assertIn("session_control", required)
        self.assertEqual(
            schema["properties"]["openssh"]["properties"]["host_key"]["const"],
            "/etc/ssh/recovery_host_ed25519_key.pub",
        )
        self.assertEqual(
            schema["properties"]["openssh"]["properties"]["host_key_agent"]["const"],
            "/run/swz/recovery-hostkey-agent.sock",
        )
        self.assertEqual(
            schema["properties"]["openssh"]["properties"]["session_control"]["const"],
            "/run/swz/recovery-session-control.sock",
        )

    def test_boundary_sources_have_no_superseded_runtime_authority(self):
        for name in ("supervisor.c", "custodian.c", "bootstrap.c", "broker.c", "launch-base.c"):
            source = (MANAGED / name).read_text(encoding="utf-8")
            self.assertNotIn("SSH_AUTH_SOCK", source)
            self.assertNotIn("SWZ_LAUNCH_AUTHORIZED", source)
            self.assertNotIn("SWZ_PROCEED_AUTHORIZED", source)
            self.assertNotIn("owner-pid", source)
        self.assertNotIn("SSH_AUTH_SOCK", (MANAGED / "sshd_config").read_text(encoding="ascii"))
        self.assertNotIn("HostKeyAgent SSH_AUTH_SOCK", (MANAGED / "sshd_config").read_text(encoding="ascii"))

    def test_qualification_registry_has_no_security_skips(self):
        fixture = json.loads(
            (ROOT / "tests/recovery-managed/fixtures/qualification-cases.json").read_text(encoding="utf-8")
        )
        self.assertEqual(fixture["mandatory_security_skips"], 0)
        self.assertTrue(all(item["mandatory"] is True for item in fixture["cases"]))


if __name__ == "__main__":
    unittest.main()
