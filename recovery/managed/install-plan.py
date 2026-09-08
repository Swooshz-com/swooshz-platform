"""Validate a disposable managed-generation install plan without installing it.

Only the pinned sshd, ssh client, and ssh-keygen are staged. Stock agent
binaries are deliberately absent from the immutable runtime closure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent


class InstallPlanError(RuntimeError):
    pass


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InstallPlanError("manifest-read-failed") from error
    if not isinstance(value, dict) or value.get("schema") != "swz-managed-build-manifest.v1":
        raise InstallPlanError("manifest-schema-invalid")
    if set(value) != {"schema", "candidate_sha", "openssh", "musl", "native", "source_files"}:
        raise InstallPlanError("manifest-fields-invalid")
    if not isinstance(value["native"], dict) or set(value["native"]) != {
        "swz-agent", "swz-bootstrap", "swz-broker", "swz-custodian", "swz-dispatcher", "swz-launch-base", "swz-supervisor",
    }:
        raise InstallPlanError("native-set-invalid")
    return value


def checked_source(root: Path, relative: str, expected: str) -> str:
    source = (root / relative).resolve()
    if root.resolve() not in source.parents or not source.is_file():
        raise InstallPlanError(f"source-missing:{relative}")
    actual = digest(source)
    if actual != expected:
        raise InstallPlanError(f"source-digest-mismatch:{relative}")
    return str(source)


def build_plan(manifest_path: Path) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    root = manifest_path.parent.resolve()
    entries: list[dict[str, str]] = []
    for name in sorted(manifest["native"]):
        entries.append(
            {
                "source": checked_source(root, f"native/{name}", manifest["native"][name]),
                "destination": f"/usr/local/libexec/{name}",
            }
        )
    openssh = manifest["openssh"]
    entries.extend(
        [
            {
                "source": checked_source(root, "openssh/sbin/sshd", openssh["binary_sha256"]),
                "destination": "/opt/swz/openssh/sbin/sshd",
            },
            {
                "source": checked_source(root, "openssh/bin/ssh", openssh["ssh_sha256"]),
                "destination": "/opt/swz/openssh/bin/ssh",
            },
            {
                "source": checked_source(root, "openssh/bin/ssh-keygen", openssh["ssh_keygen_sha256"]),
                "destination": "/opt/swz/openssh/bin/ssh-keygen",
            },
        ]
    )
    for source, destination in (
        ("sshd_config", "/etc/ssh/recovery_sshd_config"),
        ("accounts.json", "/etc/swz/accounts.json"),
        ("selinux.cil", "/etc/selinux/swz/swz-managed.cil"),
        ("file_contexts", "/etc/selinux/swz/file_contexts"),
        ("kernel.config", "/etc/swz/kernel.config"),
    ):
        expected = manifest["source_files"].get(source)
        if not isinstance(expected, str):
            raise InstallPlanError(f"manifest-source-entry-missing:{source}")
        entries.append({"source": checked_source(root, source, expected), "destination": destination})
    destinations = [entry["destination"] for entry in entries]
    if len(destinations) != len(set(destinations)):
        raise InstallPlanError("install-destination-collision")
    return {
        "schema": "swz-managed-install-plan.v1",
        "candidate_sha": manifest["candidate_sha"],
        "immutable": True,
        "activation": "controller-only",
        "entries": entries,
        "forbidden": ["production", "private-host", "docker-socket", "credentials", "real-backup"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        plan = build_plan(args.manifest)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(plan, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    except (InstallPlanError, OSError, UnicodeError) as error:
        print(f"CANDIDATE_DEFECT={error}", file=sys.stderr)
        return 1
    print(f"INSTALL_PLAN=PASS:{args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
