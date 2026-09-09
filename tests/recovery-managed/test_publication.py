import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("swz_publication_qualify", ROOT / "recovery/managed/qualify.py")
assert SPEC is not None and SPEC.loader is not None
QUALIFY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = QUALIFY
SPEC.loader.exec_module(QUALIFY)


class PublicationScopeTests(unittest.TestCase):
    def test_allowed_scope_has_exact_41_paths_and_no_canonical_sources(self):
        self.assertEqual(len(QUALIFY.ALLOWED_PATHS), 41)
        canonical = {
            "scripts/platform-recovery-controller-store.py", "scripts/platform-persisted-locator-adapter.py",
            "tests/test_platform_recovery_controller_store.py", "tests/test_platform_persisted_locator_adapter.py",
        }
        self.assertTrue(canonical.isdisjoint(QUALIFY.ALLOWED_PATHS))

    def test_qualification_fixture_has_no_mandatory_skips(self):
        cases = QUALIFY.load_cases(ROOT / "tests/recovery-managed/fixtures/qualification-cases.json")
        self.assertEqual(len(cases), 20)
        self.assertEqual(sum(1 for case in cases if case.get("skip")), 0)
        self.assertTrue(all(case["mandatory"] for case in cases))

    def test_canonical_store_and_locator_files_match_main(self):
        result = QUALIFY.canonical_store_locator_equality()
        self.assertTrue(result["byte_equal"])

    def test_schema_and_lock_are_parseable(self):
        json.loads((ROOT / "recovery/managed/manifest.schema.json").read_text(encoding="utf-8"))
        lock = json.loads((ROOT / "recovery/managed/build.lock.json").read_text(encoding="utf-8"))
        self.assertEqual(lock["openssh"]["version"], "10.5p1")
        self.assertEqual(lock["musl"]["version"], "1.2.5")


if __name__ == "__main__":
    unittest.main()

