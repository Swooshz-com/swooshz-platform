"""Validate and print an offline immutable-image installation plan.

This command never installs, activates or publishes anything. It only checks
that a caller supplied all qualified inputs and emits a plan for an offline
image builder.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
HEX64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
UUID4 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z", re.ASCII)
IPV4 = re.compile(r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}\Z", re.ASCII)
ROLES = ("supervisor", "custodian", "dispatcher", "bootstrap", "broker", "agent")


class InstallPlanError(ValueError):
    pass


def _keys(value: Any, expected: set[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        raise InstallPlanError(f"{label}-keys")


def _hex(value: Any, label: str) -> None:
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        raise InstallPlanError(f"{label}-hex")


def validate_manifest(manifest: Any) -> dict[str, Any]:
    required = {"schema", "generation_id", "installation_id", "image", "components", "policy", "qualified_inputs"}
    _keys(manifest, required, "manifest")
    if manifest["schema"] != "swz-recovery-generation-manifest.v1":
        raise InstallPlanError("manifest-schema")
    if not isinstance(manifest["generation_id"], str) or not manifest["generation_id"].startswith("sha256:") or HEX64.fullmatch(manifest["generation_id"][7:]) is None:
        raise InstallPlanError("generation-id")
    _hex(manifest["installation_id"], "installation-id")

    image = manifest["image"]
    _keys(image, {"root_digest", "image_digest", "block_size", "hash_block_size", "data_blocks", "hash_offset_bytes", "salt"}, "image")
    for field in ("root_digest", "image_digest", "salt"):
        _hex(image[field], "image-" + field)
    if image["block_size"] != 4096 or image["hash_block_size"] != 4096:
        raise InstallPlanError("image-block-size")
    for field in ("data_blocks", "hash_offset_bytes"):
        if not isinstance(image[field], str) or re.fullmatch(r"[0-9]+", image[field], re.ASCII) is None:
            raise InstallPlanError("image-" + field)
    if image["data_blocks"] == "0":
        raise InstallPlanError("image-data-blocks")

    components = manifest["components"]
    if not isinstance(components, list) or len(components) != len(ROLES):
        raise InstallPlanError("component-count")
    seen_roles: set[str] = set()
    for component in components:
        _keys(component, {"role", "path", "digest", "identity"}, "component")
        if component["role"] not in ROLES or component["role"] in seen_roles:
            raise InstallPlanError("component-role")
        seen_roles.add(component["role"])
        if not isinstance(component["path"], str) or not re.fullmatch(r"/usr/libexec/swooshz-recovery/[a-z0-9-]+", component["path"], re.ASCII):
            raise InstallPlanError("component-path")
        _hex(component["digest"], "component-digest")
        _hex(component["identity"], "component-identity")
    if set(seen_roles) != set(ROLES):
        raise InstallPlanError("component-role-set")

    policy = manifest["policy"]
    _keys(policy, {"source_digest", "compiled_digest", "selinux_digest", "kernel_config_digest"}, "policy")
    for field, value in policy.items():
        _hex(value, "policy-" + field)

    inputs = manifest["qualified_inputs"]
    required_inputs = {
        "installation_uuid",
        "enrolled_ipv4",
        "admission_root_public_key",
        "recovery_host_public_key",
        "controller_public_key",
        "signed_boot_image_digest",
        "dm_verity_root_digest",
        "selinux_policy_digest",
    }
    _keys(inputs, required_inputs, "qualified-inputs")
    if UUID4.fullmatch(inputs["installation_uuid"]) is None:
        raise InstallPlanError("installation-uuid")
    if IPV4.fullmatch(inputs["enrolled_ipv4"]) is None:
        raise InstallPlanError("enrolled-ipv4")
    for field in required_inputs - {"installation_uuid", "enrolled_ipv4"}:
        _hex(inputs[field], "qualified-" + field)
    return manifest


def build_install_plan(manifest: dict[str, Any]) -> dict[str, Any]:
    validate_manifest(manifest)
    components = [component["path"] for component in manifest["components"]]
    return {
        "schema": "swz-recovery-offline-install-plan.v1",
        "generation_id": manifest["generation_id"],
        "installation_id": manifest["installation_id"],
        "immutable_rootfs": True,
        "dm_verity_required": True,
        "selinux_enforcing_required": True,
        "pam_absent": True,
        "component_paths": components,
        "config_substitution": ["__ENROLLED_IPV4__"],
        "host_key_custody": "external-custodian",
        "activation": "controller-authorized-only",
        "runtime_mutations": [],
        "network_publish": False,
        "restore": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        plan = build_install_plan(manifest)
    except (OSError, json.JSONDecodeError, InstallPlanError) as error:
        print(f"INSTALL_PLAN=FAIL:{error}", file=sys.stderr)
        return 1
    print(json.dumps(plan, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
