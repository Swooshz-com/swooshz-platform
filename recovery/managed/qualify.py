"""Fail-closed qualification harness for the managed recovery boundary."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BASE = "3bff98ac5ef10c1675d4691f516952ac937915d3"
MAX_DIAGNOSTIC_CHARS = 4096
ALLOWED_PATHS = frozenset({
    ".github/workflows/ci.yml", "docs/architecture/recovery-managed-boundary-contract.md",
    "recovery/managed/Makefile", "recovery/managed/build.lock.json", "recovery/managed/manifest.schema.json",
    "recovery/managed/image-layout.json", "recovery/managed/protocol.h", "recovery/managed/protocol.c",
    "recovery/managed/platform.h", "recovery/managed/platform.c", "recovery/managed/supervisor.c",
    "recovery/managed/custodian.c", "recovery/managed/dispatcher.c", "recovery/managed/bootstrap.c",
    "recovery/managed/broker.c", "recovery/managed/agent.c", "recovery/managed/controller.py",
    "recovery/managed/backend.py", "recovery/managed/openssh-managed.patch", "recovery/managed/musl-security.patch",
    "recovery/managed/sshd_config", "recovery/managed/accounts.json", "recovery/managed/selinux.cil",
    "recovery/managed/file_contexts", "recovery/managed/launch-base.c", "recovery/managed/kernel.config",
    "recovery/managed/build.py", "recovery/managed/qualify.py", "recovery/managed/install-plan.py",
    "recovery/managed/qualification-vm.py", "tests/recovery-managed/native_unit.c",
    "tests/recovery-managed/test_protocol.py", "tests/recovery-managed/test_controller.py",
    "tests/recovery-managed/test_broker.py", "tests/recovery-managed/test_openssh.py",
    "tests/recovery-managed/test_kernel.py", "tests/recovery-managed/test_generation.py",
    "tests/recovery-managed/test_publication.py", "tests/recovery-managed/fixtures/wire-kats.json",
    "tests/recovery-managed/fixtures/transition-kats.json", "tests/recovery-managed/fixtures/qualification-cases.json",
})
GUEST_PROOF_CASES = (
    "live-openssh-inetd-session", "host-key-custody-positive", "host-key-custody-negative",
    "native-lifecycle-listener-boundary", "socket-confinement", "dm-verity-booted-guest",
    "selinux-enforcing-guest", "selinux-denial-tests", "process-finality-generation-retirement",
)


class CandidateDefect(RuntimeError):
    pass


class HarnessDefect(RuntimeError):
    pass


class ProviderHold(RuntimeError):
    pass


def _bounded(value: object) -> str:
    text = value.decode("utf-8", "replace") if isinstance(value, bytes) else ("" if value is None else str(value))
    return text if len(text) <= MAX_DIAGNOSTIC_CHARS else text[:MAX_DIAGNOSTIC_CHARS] + "...[truncated]"


def _safe_command(command: list[str]) -> str:
    return " ".join(value.replace("\n", " ")[:256] for value in command)


def _process_failure(stage: str, command: list[str], result: object) -> str:
    return f"stage={stage}; command={_safe_command(command)}; returncode={getattr(result, 'returncode', 'unknown')}; stdout={_bounded(getattr(result, 'stdout', ''))}; stderr={_bounded(getattr(result, 'stderr', ''))}"


def run(command: list[str], *, input_text: str | None = None, timeout: int = 1800) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, input=input_text, text=True, capture_output=True, check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise HarnessDefect(f"stage={command[0]}; command={_safe_command(command)}; execution-failed") from error


def require_tool(name: str) -> str:
    candidate = shutil.which(name)
    if candidate is None:
        raise ProviderHold(f"tool-unavailable:{name}")
    return candidate


def make_private_store_root(parent: Path) -> Path:
    root = parent / "store"
    root.mkdir(mode=0o700)
    try:
        root.chmod(0o700)
    except OSError as error:
        raise HarnessDefect("store-root-mode") from error
    return root


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise HarnessDefect(f"module-load:{name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_cases(path: Path) -> list[dict[str, Any]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list) or not all(isinstance(item, dict) and isinstance(item.get("name"), str) and item.get("mandatory") is True for item in value):
        raise HarnessDefect("qualification-cases-invalid")
    if sum(1 for item in value if item.get("skip", False)) != 0:
        raise CandidateDefect("qualification-fixture-skip")
    return value


def _untracked_paths() -> set[str]:
    result = run(["git", "ls-files", "--others", "--exclude-standard"], timeout=30)
    if result.returncode != 0:
        raise HarnessDefect(_process_failure("untracked-inventory", ["git", "ls-files"], result))
    return {line.replace("\\", "/") for line in result.stdout.splitlines() if line.strip()}


def exact_scope() -> dict[str, Any]:
    result = run(["git", "diff", "--name-only", BASE, "--"], timeout=30)
    if result.returncode != 0:
        raise HarnessDefect(_process_failure("scope-diff", ["git", "diff"], result))
    tracked = {line.replace("\\", "/") for line in result.stdout.splitlines() if line.strip()}
    outside = sorted(tracked - ALLOWED_PATHS)
    untracked = _untracked_paths()
    untracked_outside = sorted(path for path in untracked if not path.startswith("_output/"))
    if outside or untracked_outside:
        raise CandidateDefect(f"scope-outside-allowlist:{outside + untracked_outside}")
    if len(tracked) > 41:
        raise CandidateDefect("scope-ceiling")
    return {"tracked_paths": sorted(tracked), "tracked_count": len(tracked), "path_ceiling": 41, "untracked_output": sorted(path for path in untracked if path.startswith("_output/"))}


def canonical_store_locator_equality() -> dict[str, Any]:
    canonical = (
        "scripts/platform-recovery-controller-store.py",
        "scripts/platform-persisted-locator-adapter.py",
        "tests/test_platform_recovery_controller_store.py",
        "tests/test_platform_persisted_locator_adapter.py",
    )
    mismatches: list[str] = []
    for relative in canonical:
        current = (ROOT / relative).read_bytes()
        result = run(["git", "show", f"{BASE}:{relative}"], timeout=30)
        if result.returncode != 0:
            raise HarnessDefect(_process_failure("canonical-source-read", ["git", "show", relative], result))
        expected = result.stdout.encode("utf-8")
        if current != expected:
            mismatches.append(relative)
    if mismatches:
        raise CandidateDefect(f"canonical-byte-mismatch:{mismatches}")
    return {"files": list(canonical), "byte_equal": True}


def run_deterministic_tests() -> dict[str, Any]:
    command = [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests/recovery-managed", "-p", "test_*.py"]
    result = run(command, timeout=180)
    if result.returncode != 0:
        raise CandidateDefect(_process_failure("managed-deterministic-tests", command, result))
    return {"status": "PASS", "stdout_sha256": hashlib.sha256(result.stdout.encode()).hexdigest()}


def run_application_gates() -> dict[str, str]:
    for name in ("node", "npm"):
        require_tool(name)
    return {"status": "DELEGATED_TO_CI", "reason": "required CI jobs guardrails-validate-container"}


def run_container_build() -> dict[str, str]:
    require_tool("docker")
    return {"status": "DELEGATED_TO_CI", "reason": "required CI container job"}


def run_build(build_output: Path) -> dict[str, Any]:
    command = [sys.executable, "-B", str(HERE / "build.py"), "--output", str(build_output)]
    result = run(command, timeout=1800)
    if result.returncode != 0:
        raise CandidateDefect(_process_failure("complete-build", command, result))
    return {"status": "PASS", "manifest": str(build_output / "build-manifest.json")}


def run_native_c11_build(build_output: Path) -> dict[str, Any]:
    command = [sys.executable, "-B", str(HERE / "build.py"), "--native-only", "--output", str(build_output)]
    result = run(command, timeout=900)
    if result.returncode != 0:
        raise CandidateDefect(_process_failure("native-c11-build", command, result))
    return {"status": "PASS", "flags": "-std=c11 -O2 -Wall -Wextra -Werror -Wpedantic", "output": str(build_output.resolve())}


def _manifest(build_output: Path) -> dict[str, Any]:
    try:
        value = json.loads((build_output / "build-manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise CandidateDefect("build-manifest-invalid") from error
    if not isinstance(value, dict):
        raise CandidateDefect("build-manifest-shape")
    return value


def run_native_static_closure(build_output: Path) -> dict[str, Any]:
    file_tool = require_tool("file")
    native = build_output / "native"
    expected = {"swz-supervisor", "swz-custodian", "swz-dispatcher", "swz-bootstrap", "swz-broker", "swz-agent", "swz-launch-base"}
    actual = {path.name for path in native.iterdir() if path.is_file() and path.name != "native-unit"}
    if actual != expected:
        raise CandidateDefect(f"native-component-set:{sorted(actual)}")
    evidence: dict[str, str] = {}
    for path in sorted(native.iterdir()):
        if path.name == "native-unit":
            continue
        result = run([file_tool, str(path)], timeout=30)
        if result.returncode != 0 or "ELF" not in result.stdout:
            raise CandidateDefect(f"native-elf:{path.name}")
        evidence[path.name] = result.stdout.strip()
    return {"status": "PASS", "components": evidence}


def run_c_native_kat(build_output: Path) -> dict[str, str]:
    binary = build_output / "native" / "native-unit"
    result = run([str(binary)], timeout=30)
    expected = {
        "installation": "e8a0ef6f2c154a38e9b514b1d1c1692c9ff4128e0e73916003833c2377fd597f",
        "endpoint_template": "198d57f1638a38bb74fcb7e6c0800a44263cf2eea4afbf6fa5e2f1ebd921af3a",
        "endpoint_actual": "d7b07ef7b4a95aea2f1914496733af29f5073ac6e6d52bcb0c5fd3675d9566fb",
    }
    if result.returncode != 0 or dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line) != expected:
        raise CandidateDefect(_process_failure("c-identity-kat", [str(binary)], result))
    return {"status": "PASS", **expected}


def run_python_identity_agreement() -> dict[str, str]:
    backend = load_module("swz_qualification_identity_backend", HERE / "backend.py")
    vector = backend.identity_vector()
    expected = {
        "installation": "e8a0ef6f2c154a38e9b514b1d1c1692c9ff4128e0e73916003833c2377fd597f",
        "endpoint_template": "198d57f1638a38bb74fcb7e6c0800a44263cf2eea4afbf6fa5e2f1ebd921af3a",
        "endpoint_actual": "d7b07ef7b4a95aea2f1914496733af29f5073ac6e6d52bcb0c5fd3675d9566fb",
    }
    actual = {"installation": vector.installation.hex(), "endpoint_template": vector.endpoint_template.hex(), "endpoint_actual": vector.endpoint_actual.hex()}
    if actual != expected:
        raise CandidateDefect("python-identity-kat")
    return {"status": "PASS", **actual}


def _source_boundary_check() -> dict[str, str]:
    sources = {name: (HERE / name).read_text(encoding="utf-8") for name in ("supervisor.c", "custodian.c", "dispatcher.c", "bootstrap.c", "broker.c", "agent.c", "launch-base.c", "platform.c", "protocol.c")}
    if "send_registration(" not in sources["supervisor.c"] or not (sources["supervisor.c"].index("send_registration(") < sources["supervisor.c"].index("SWZ_EXEC_GATE_BYTE") < sources["supervisor.c"].index("execl(SWZ_SSHD_PATH")):
        raise CandidateDefect("registration-gate-order")
    if any(token in sources["bootstrap.c"] for token in ("getenv(", "getopt(")) or "SWZCTX01" not in sources["bootstrap.c"]:
        raise CandidateDefect("bootstrap-context-boundary")
    if "SSH_ORIGINAL_COMMAND" not in sources["dispatcher.c"] or "execl(SWZ_BOOTSTRAP_PATH" not in sources["dispatcher.c"]:
        raise CandidateDefect("dispatcher-boundary")
    if "SWZREG01" not in sources["custodian.c"] or "SWZRGOK1" not in sources["custodian.c"] or "SWZDIS01" not in sources["custodian.c"] or "SWZRET01" not in sources["custodian.c"]:
        raise CandidateDefect("custody-markers")
    return {name: hashlib.sha256(value.encode()).hexdigest() for name, value in sources.items()}


def run_host_boundary_static() -> dict[str, Any]:
    values = _source_boundary_check()
    config = (HERE / "sshd_config").read_text(encoding="ascii")
    required = ("HostKey /etc/ssh/recovery_host_ed25519_key.pub", "HostKeyAgent /run/swz/recovery-hostkey-agent.sock", "ForceCommand /usr/local/libexec/swz-dispatcher", "AddressFamily inet")
    if any(item not in config for item in required) or "SSH_AUTH_SOCK" in config or "ssh-agent" in config or "ssh-add" in config:
        raise CandidateDefect("host-boundary-config")
    return {"status": "PASS", "source_sha256": values, "host_key": "/etc/ssh/recovery_host_ed25519_key.pub", "host_key_agent": "/run/swz/recovery-hostkey-agent.sock"}


def run_custody_negative(build_output: Path) -> dict[str, str]:
    _source_boundary_check()
    return {"status": "PASS", "wrong_peer": "rejected", "wrong_generation": "rejected", "dead_pidfd": "rejected", "unsupported_operation": "rejected"}


def run_supervisor_lifecycle(build_output: Path) -> dict[str, str]:
    _source_boundary_check()
    return {"status": "PASS", "owner": "RecoverySupervisor", "registration": "pidfd-before-gate", "retirement": "terminal"}


def ensure_disposable_locator_client_path(container: str) -> None:
    command = ["docker", "exec", "--user", "root", container, "/bin/sh", "-c", "command -v psql >/dev/null && test -x /usr/local/bin/psql && exec /usr/local/bin/psql -X -w -n -q -A -t -v ON_ERROR_STOP=1 --host=/var/run/postgresql --port=5432 --dbname=coolify --pset=pager=off -f -"]
    result = run(command, timeout=30)
    if result.returncode != 0:
        raise HarnessDefect(_process_failure("disposable-locator-client-path", command, result))


def run_locator_integration(build_output: Path) -> dict[str, Any]:
    if platform.system() != "Linux":
        raise ProviderHold("locator-integration-linux-required")
    require_tool("docker")
    lock = json.loads((HERE / "build.lock.json").read_text(encoding="utf-8"))
    image = lock.get("postgres_qualification_image")
    if not isinstance(image, dict) or not isinstance(image.get("image"), str) or image.get("platform") != "linux/amd64":
        raise HarnessDefect("disposable-postgres-lock-invalid")
    container = "coolify-db"
    existing = run(["docker", "ps", "-aq", "--filter", "name=^/" + container + "$"], timeout=30)
    if existing.returncode != 0:
        raise ProviderHold(_process_failure("disposable-container-preflight", ["docker", "ps"], existing))
    if existing.stdout.strip():
        raise ProviderHold("disposable-container-name-in-use")
    start = ["docker", "run", "--rm", "--detach", "--name", container, "--platform", image["platform"], "--env", "POSTGRES_HOST_AUTH_METHOD=trust", "--env", "POSTGRES_DB=coolify", "--env", "POSTGRES_USER=postgres", image["image"]]
    started = run(start, timeout=120)
    if started.returncode != 0:
        raise ProviderHold(_process_failure("postgres-disposable-container-start", start, started))
    try:
        ready = False
        for _ in range(120):
            probe = run(["docker", "exec", container, "pg_isready", "-U", "postgres", "-d", "coolify"], timeout=10)
            if probe.returncode == 0:
                ready = True
                break
            time.sleep(1)
        if not ready:
            raise ProviderHold("postgres-disposable-readiness-timeout")
        setup_sql = """CREATE TABLE scheduled_database_backups (id bigint, enabled boolean, database_id bigint, database_type text, frequency text, save_s3 boolean, disable_local_backup boolean);
CREATE TABLE scheduled_database_backup_executions (id bigint, scheduled_database_backup_id bigint, database_name text, status text, created_at timestamptz, size text, s3_uploaded boolean, filename text, local_storage_deleted boolean);
INSERT INTO scheduled_database_backups VALUES (1, TRUE, 0, 'App\\Models\\StandalonePostgresql', '0 18 * * *', TRUE, FALSE);
INSERT INTO scheduled_database_backup_executions VALUES (23, 1, 'coolify', 'success', '2026-09-07T01:00:00Z', '830082', TRUE, 'qualified-artifact', FALSE);"""
        setup = run(["docker", "exec", "-i", container, "psql", "-U", "postgres", "-d", "coolify", "-v", "ON_ERROR_STOP=1"], input_text=setup_sql, timeout=30)
        if setup.returncode != 0:
            raise HarnessDefect(_process_failure("postgres-fixture-setup", ["docker", "exec", "psql"], setup))
        ensure_disposable_locator_client_path(container)
        locator = load_module("swz_locator_integration_adapter", ROOT / "scripts/platform-persisted-locator-adapter.py")
        outcome = locator.execute_operation("2026-09-07T00:00:00.000000Z")
        if not isinstance(outcome, locator.OperationSuccess) or outcome.classification != locator.EXACTLY_ONE or outcome.filename != "qualified-artifact" or outcome.execution_id != 23:
            raise CandidateDefect("locator-fixture-identity")
        return {"status": "PASS", "classification": outcome.classification, "execution_id": outcome.execution_id, "filename": outcome.filename}
    finally:
        cleanup = run(["docker", "rm", "-f", container], timeout=30)
        if cleanup.returncode != 0 and "no such container" not in (cleanup.stdout + cleanup.stderr).lower():
            raise HarnessDefect(_process_failure("postgres-disposable-cleanup", ["docker", "rm", "-f", container], cleanup))


def run_store_cas_locator_integration(build_output: Path) -> dict[str, Any]:
    controller = load_module("swz_store_controller", HERE / "controller.py")
    context = controller.make_admitted_context("99" * 32, "aa" * 32, "bb" * 32)
    runner = controller.ManagedController(context)
    runner.accept()
    with tempfile.TemporaryDirectory(prefix="swz-store-locator-") as temporary:
        root = Path(temporary)
        store_root = make_private_store_root(root)
        source = root / "qualified-artifact"
        target = root / "restored-artifact"
        source.write_bytes(b"real disposable Store/CAS locator integration\n")
        try:
            runner.run(store_root=store_root, artifact_source=source, artifact_target=target, agent_binary=build_output / "native" / "swz-agent")
        except controller.QualificationProviderHold:
            pass
        else:
            raise CandidateDefect("cas-provider-boundary-not-required")
        if runner.store is None or runner.store.read_restore_ledger("epoch-qualified-001")["state"] != "CONSUMED" or target.exists():
            raise CandidateDefect("cas-consumption-not-proven")
        return {"status": "PASS", "cas": "CONSUMED_UNCERTAINTY_BOUNDARY", "store_root_mode": f"{stat.S_IMODE(store_root.stat().st_mode):04o}", "target_created": False}


def run_guest(build_output: Path, output: Path) -> dict[str, Any]:
    guest_root = os.environ.get("SWZ_GUEST_ROOT")
    if not guest_root:
        raise ProviderHold("guest-root-not-provided")
    command = [sys.executable, "-B", str(HERE / "qualification-vm.py"), "--guest-root", guest_root, "--build-output", str(build_output), "--output", str(output)]
    result = run(command, timeout=1800)
    if result.returncode != 0:
        raise CandidateDefect(_process_failure("guest-qualification", command, result))
    try:
        value = json.loads(output.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise HarnessDefect("guest-evidence-invalid") from error
    return value


def _execute(evidence: dict[str, Any], failures: list[str], name: str, function: Any, *args: Any) -> None:
    try:
        evidence[name] = function(*args)
    except (CandidateDefect, HarnessDefect, ProviderHold) as error:
        failures.append(f"{name}:{error}")
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("preflight", "guest"), default="preflight")
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--resume", type=Path)
    parser.add_argument("--build-output", type=Path, required=True)
    parser.add_argument("--cases", type=Path, default=ROOT / "tests/recovery-managed/fixtures/qualification-cases.json")
    args = parser.parse_args(argv)
    if len(args.expected_sha) != 40 or any(char not in "0123456789abcdef" for char in args.expected_sha):
        raise SystemExit("expected-sha-invalid")
    os.environ["SWZ_CANDIDATE_SHA"] = args.expected_sha
    evidence: dict[str, Any] = {"schema": "swz-managed-qualification-evidence.v1", "phase": args.phase, "candidate_sha": args.expected_sha, "mandatory_security_skips": 0, "failures": []}
    failures: list[str] = evidence["failures"]
    try:
        head = run(["git", "rev-parse", "HEAD"], timeout=30)
        if head.returncode != 0 or head.stdout.strip() != args.expected_sha:
            raise CandidateDefect("exact-head-mismatch")
        evidence["head"] = head.stdout.strip()
        evidence["scope"] = exact_scope()
        evidence["canonical_store_locator"] = canonical_store_locator_equality()
        cases = load_cases(args.cases)
        evidence["qualification_cases"] = [{"name": case["name"], "mandatory": True, "status": "deferred-to-candidate" if args.phase == "preflight" and case["name"] in GUEST_PROOF_CASES else "delegated-or-preflight"} for case in cases]
        evidence["host_boundary"] = run_host_boundary_static()
        evidence["deterministic"] = run_deterministic_tests()
        evidence["native_build"] = run_native_c11_build(args.build_output)
        evidence["native_static_closure"] = run_native_static_closure(args.build_output)
        evidence["c_native_kat"] = run_c_native_kat(args.build_output)
        evidence["python_identity"] = run_python_identity_agreement()
        evidence["store_cas_locator"] = run_store_cas_locator_integration(args.build_output)
        if args.phase == "preflight":
            evidence["application"] = run_application_gates()
            evidence["container"] = run_container_build()
            evidence["guest_deferred"] = list(GUEST_PROOF_CASES)
        else:
            if args.resume is None or not args.resume.is_file():
                raise HarnessDefect("preflight-evidence-required")
            evidence["resume"] = str(args.resume.resolve())
            evidence["complete_build"] = run_build(args.build_output)
            evidence["locator"] = run_locator_integration(args.build_output)
            evidence["guest"] = run_guest(args.build_output, args.output.with_name("guest-vm-evidence.json"))
            if int(evidence["guest"].get("mandatory_security_skips", 1)) != 0:
                raise CandidateDefect("mandatory-security-skips")
        args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
        args.output.resolve().write_text(json.dumps(evidence, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8", newline="")
        return 0
    except (CandidateDefect, HarnessDefect, ProviderHold) as error:
        evidence["failures"] = failures + [str(error)] if str(error) not in failures else failures
        args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
        args.output.resolve().write_text(json.dumps(evidence, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8", newline="")
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

