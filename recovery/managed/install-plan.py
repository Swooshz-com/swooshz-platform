"""Turn a qualified build manifest into a bounded immutable install plan."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent


class InstallPlanError(RuntimeError):
    pass


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise InstallPlanError("manifest-read") from error
    if not isinstance(value, dict) or value.get("schema") != "swz-managed-build-manifest.v1":
        raise InstallPlanError("manifest-schema")
    return value


def checked_source(root: Path, relative: str, expected: str) -> str:
    source = (root / relative).resolve()
    if root.resolve() not in source.parents or not source.is_file() or digest(source) != expected:
        raise InstallPlanError(f"source-integrity:{relative}")
    return str(source)


def build_plan(manifest_path: Path) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    root = manifest_path.parent.resolve()
    source_files = manifest.get("source_files")
    native = manifest.get("native")
    openssh = manifest.get("openssh")
    if not isinstance(source_files, dict) or not isinstance(native, dict) or not isinstance(openssh, dict):
        raise InstallPlanError("manifest-components")
    checked = {name: checked_source(root, name, value) for name, value in source_files.items() if isinstance(name, str) and isinstance(value, str)}
    if len(checked) != len(source_files) or any(not isinstance(value, str) or len(value) != 64 for value in source_files.values()):
        raise InstallPlanError("manifest-source-entry")
    entries = []
    for name, value in native.items():
        if not isinstance(name, str) or not name.startswith("swz-") or not isinstance(value, str) or len(value) != 64:
            raise InstallPlanError("manifest-native-entry")
        entries.append({"source": f"native/{name[4:]}", "target": f"/usr/local/libexec/{name}", "sha256": value})
    entries.append({"source": "openssh/sbin/sshd", "target": "/opt/swz/openssh/sbin/sshd", "sha256": openssh.get("binary_sha256")})
    return {
        "schema": "swz-managed-install-plan.v1",
        "candidate_sha": manifest["candidate_sha"],
        "source_root": str(root),
        "immutable": True,
        "entries": entries,
        "seed_path": "/var/lib/swooshz-recovery/host-key/ed25519.seed",
        "public_key_path": "/etc/ssh/recovery_host_ed25519_key.pub",
        "host_key_agent": "/run/swz/recovery-hostkey-agent.sock",
        "session_control": "/run/swz/recovery-session-control.sock",
        "checked_sources": checked,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    plan = build_plan(args.manifest.resolve())
    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output.resolve().write_text(json.dumps(plan, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8", newline="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

