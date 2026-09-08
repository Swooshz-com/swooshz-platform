"""Fail-closed G3 qualification runner for the managed recovery boundary."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BASE = "3bff98ac5ef10c1675d4691f516952ac937915d3"
MAX_DIAGNOSTIC_CHARS = 4096

ALLOWED_PATHS = frozenset({
    ".github/workflows/ci.yml",
    "docs/architecture/recovery-managed-boundary-contract.md",
    "recovery/managed/Makefile",
    "recovery/managed/accounts.json",
    "recovery/managed/agent.c",
    "recovery/managed/backend.py",
    "recovery/managed/bootstrap.c",
    "recovery/managed/broker.c",
    "recovery/managed/build.lock.json",
    "recovery/managed/build.py",
    "recovery/managed/controller.py",
    "recovery/managed/custodian.c",
    "recovery/managed/dispatcher.c",
    "recovery/managed/file_contexts",
    "recovery/managed/image-layout.json",
    "recovery/managed/install-plan.py",
    "recovery/managed/kernel.config",
    "recovery/managed/launch-base.c",
    "recovery/managed/manifest.schema.json",
    "recovery/managed/musl-security.patch",
    "recovery/managed/openssh-managed.patch",
    "recovery/managed/platform.c",
    "recovery/managed/platform.h",
    "recovery/managed/protocol.c",
    "recovery/managed/protocol.h",
    "recovery/managed/qualification-vm.py",
    "recovery/managed/qualify.py",
    "recovery/managed/selinux.cil",
    "recovery/managed/sshd_config",
    "recovery/managed/supervisor.c",
    "tests/recovery-managed/fixtures/qualification-cases.json",
    "tests/recovery-managed/fixtures/transition-kats.json",
    "tests/recovery-managed/fixtures/wire-kats.json",
    "tests/recovery-managed/native_unit.c",
    "tests/recovery-managed/test_broker.py",
    "tests/recovery-managed/test_controller.py",
    "tests/recovery-managed/test_generation.py",
    "tests/recovery-managed/test_kernel.py",
    "tests/recovery-managed/test_openssh.py",
    "tests/recovery-managed/test_protocol.py",
    "tests/recovery-managed/test_publication.py",
})


class CandidateDefect(RuntimeError):
    pass


class HarnessDefect(RuntimeError):
    pass


class ProviderHold(RuntimeError):
    pass


GUEST_PROOF_CASES = (
    "live-openssh-inetd-session",
    "host-key-custody-positive",
    "host-key-custody-negative",
    "native-lifecycle-listener-boundary",
    "socket-confinement",
    "process-finality-generation-retirement",
)


def _bounded(value: object) -> str:
    text = value.decode("utf-8", "replace") if isinstance(value, bytes) else ("" if value is None else str(value))
    if len(text) <= MAX_DIAGNOSTIC_CHARS:
        return text
    half = MAX_DIAGNOSTIC_CHARS // 2
    return text[:half] + "\n...[truncated]...\n" + text[-half:]


def _safe_command(command: list[str]) -> str:
    safe: list[str] = []
    for value in command:
        text = str(value)
        if "=" in text:
            key, _, _ = text.partition("=")
            if any(marker in key.upper() for marker in ("PASSWORD", "TOKEN", "SECRET", "PRIVATE_KEY")):
                text = key + "=<redacted>"
        safe.append(text)
    return shlex.join(safe)


def _process_failure(stage: str, command: list[str], result: object) -> str:
    return (
        f"stage={stage}; command={_safe_command(command)}; "
        f"returncode={getattr(result, 'returncode', 'unknown')}; "
        f"stdout={_bounded(getattr(result, 'stdout', None))}; "
        f"stderr={_bounded(getattr(result, 'stderr', None))}"
    )


def run(
    command: list[str],
    *,
    cwd: Path = ROOT,
    input_text: str | None = None,
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    effective = list(command)
    if os.name == "nt" and effective and effective[0] == "npm":
        effective[0] = shutil.which("npm.cmd") or effective[0]
    try:
        return subprocess.run(
            effective,
            cwd=cwd,
            input=input_text,
            check=False,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except FileNotFoundError as error:
        raise ProviderHold(f"stage={effective[0]}; tool-unavailable={effective[0]}") from error
    except subprocess.TimeoutExpired as error:
        raise HarnessDefect(f"stage={effective[0]}; timeout={timeout}s") from error
    except OSError as error:
        raise HarnessDefect(f"stage={effective[0]}; process-unavailable={type(error).__name__}") from error


def require_tool(name: str) -> str:
    candidate = shutil.which(name)
    if candidate is None:
        raise ProviderHold(f"tool-unavailable:{name}")
    return candidate


def make_private_store_root(parent: Path) -> Path:
    root = parent / "store"
    root.mkdir(mode=0o700)
    if os.name != "nt":
        root.chmod(0o700)
        if stat.S_IMODE(root.stat().st_mode) != 0o700:
            raise HarnessDefect("disposable-store-root-mode")
    return root


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise HarnessDefect(f"module-unavailable:{name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_cases(path: Path) -> list[dict[str, Any]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise HarnessDefect("qualification-case-fixture-invalid") from error
    if (
        not isinstance(value, dict)
        or value.get("schema") != "swz-managed-qualification-cases.v1"
        or value.get("mandatory_security_skips") != 0
    ):
        raise CandidateDefect("qualification-case-registry-invalid")
    cases = value.get("cases")
    if (
        not isinstance(cases, list)
        or not cases
        or any(not isinstance(item, dict) for item in cases)
        or len({item.get("id") for item in cases}) != len(cases)
        or any(item.get("mandatory") is not True for item in cases)
    ):
        raise CandidateDefect("mandatory-case-registry-invalid")
    return cases


def _untracked_paths() -> set[str]:
    result = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard"],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    )
    ignored_prefixes = (".swz-source-cache/", "_agent-toolkit-backups/", "_output/", "scripts/__pycache__/", "recovery/managed/__pycache__/", "tests/recovery-managed/__pycache__/")
    return {
        line.replace("\\", "/")
        for line in result.stdout.splitlines()
        if line and not line.replace("\\", "/").startswith(ignored_prefixes)
    }


def exact_scope() -> dict[str, Any]:
    result = run(["git", "diff", "--name-only", BASE, "--"], timeout=30)
    if result.returncode != 0:
        raise HarnessDefect(_process_failure("scope-diff", ["git", "diff", "--name-only", BASE, "--"], result))
    changed = {line.replace("\\", "/") for line in result.stdout.splitlines() if line}
    changed.update(_untracked_paths())
    unexpected = sorted(changed - ALLOWED_PATHS)
    if unexpected:
        raise CandidateDefect("UNAUTHORISED_PATHS:" + ",".join(unexpected))
    if len(changed) > 41:
        raise CandidateDefect("PATH_CEILING_EXCEEDED")
    for relative in (
        "scripts/platform-recovery-controller-store.py",
        "scripts/platform-persisted-locator-adapter.py",
        "tests/test_platform_recovery_controller_store.py",
        "tests/test_platform_persisted_locator_adapter.py",
    ):
        try:
            expected = subprocess.check_output(["git", "show", f"{BASE}:{relative}"], cwd=ROOT)
        except (OSError, subprocess.CalledProcessError) as error:
            raise HarnessDefect(f"canonical-source-unavailable:{relative}") from error
        if (ROOT / relative).read_bytes() != expected:
            raise CandidateDefect(f"CANONICAL_FILE_CHANGED:{relative}")
    return {"changed_paths": sorted(changed), "path_count": len(changed), "canonical_files": "byte-identical"}


def run_deterministic_tests() -> None:
    command = [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests/recovery-managed", "-p", "test_*.py"]
    result = run(command, timeout=180)
    if result.returncode != 0:
        raise CandidateDefect(_process_failure("managed-deterministic-tests", command, result))


def run_application_gates() -> None:
    require_tool("node")
    require_tool("npm")
    for command in (["npm", "run", "typecheck"], ["npm", "run", "build"], ["npm", "test"]):
        result = run(command, timeout=300)
        if result.returncode != 0:
            raise CandidateDefect(_process_failure("application-" + command[-1], command, result))


def run_container_build() -> None:
    require_tool("docker")
    command = ["docker", "build", "--pull=false", "-t", "swz-managed-platform-g3-ci", "."]
    result = run(command, timeout=600)
    if result.returncode != 0:
        raise ProviderHold(_process_failure("container-build", command, result))


def run_build(build_output: Path) -> None:
    command = [sys.executable, "-B", str(HERE / "build.py"), "--output", str(build_output)]
    result = run(command, timeout=1800)
    if result.returncode == 75:
        raise ProviderHold(_process_failure("managed-build", command, result))
    if result.returncode != 0:
        raise CandidateDefect(_process_failure("managed-build", command, result))
    manifest = build_output / "build-manifest.json"
    if not manifest.is_file():
        raise CandidateDefect("managed-build-manifest-missing")
    install_plan = build_output / "install-plan.json"
    plan_command = [
        sys.executable, "-B", str(HERE / "install-plan.py"),
        "--manifest", str(manifest), "--output", str(install_plan),
    ]
    plan_result = run(plan_command, timeout=120)
    if plan_result.returncode != 0:
        raise CandidateDefect(_process_failure("install-plan-validation", plan_command, plan_result))


def run_native_c11_build(build_output: Path) -> None:
    command = [
        sys.executable, "-B", str(HERE / "build.py"),
        "--native-only", "--output", str(build_output),
    ]
    result = run(command, timeout=300)
    if result.returncode == 75:
        raise ProviderHold(_process_failure("native-c11-build", command, result))
    if result.returncode != 0:
        raise CandidateDefect(_process_failure("native-c11-build", command, result))


def _manifest(build_output: Path) -> dict[str, Any]:
    try:
        value = json.loads((build_output / "build-manifest.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise HarnessDefect("build-manifest-invalid") from error
    if not isinstance(value, dict) or value.get("schema") != "swz-managed-build-manifest.v1":
        raise CandidateDefect("build-manifest-schema-invalid")
    return value


def _load_lock() -> dict[str, Any]:
    try:
        value = json.loads((HERE / "build.lock.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise HarnessDefect("build-lock-invalid") from error
    if not isinstance(value, dict):
        raise HarnessDefect("build-lock-invalid")
    return value


def run_pinned_openssh_build(build_output: Path) -> dict[str, str]:
    value = _manifest(build_output)
    openssh = value.get("openssh")
    lock = _load_lock()
    locked = lock.get("openssh") if isinstance(lock, dict) else None
    musl = value.get("musl")
    if (
        not isinstance(openssh, dict)
        or not isinstance(locked, dict)
        or not isinstance(musl, dict)
        or value.get("candidate_sha") != subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        or openssh.get("version") != "OpenSSH_10.5p1"
        or openssh.get("sshd_version") != "OpenSSH_10.5p1"
        or locked.get("version") != "10.5p1"
        or openssh.get("archive_sha256") != locked.get("sha256")
        or musl.get("version") != "1.2.5"
    ):
        raise CandidateDefect("pinned-openssh-version-invalid")
    if (
        openssh.get("host_key") != "/etc/ssh/recovery_host_ed25519_key.pub"
        or openssh.get("host_key_agent") != "/run/swz/recovery-hostkey-agent.sock"
        or openssh.get("session_control") != "/run/swz/recovery-session-control.sock"
    ):
        raise CandidateDefect("managed-runtime-paths-invalid")
    if (build_output / "openssh" / "bin").joinpath("ssh-agent").exists() or (build_output / "openssh" / "bin").joinpath("ssh-add").exists():
        raise CandidateDefect("stock-agent-staged")
    return {"version": "OpenSSH_10.5p1", "runtime_host_key_agent": "direct-custodian"}


def run_native_static_closure(build_output: Path) -> None:
    file_tool = require_tool("file")
    binaries = sorted((build_output / "native").glob("swz-*"))
    if len(binaries) != 7 or any(not item.is_file() for item in binaries):
        raise CandidateDefect("native-component-set-incomplete")
    for binary in binaries:
        result = run([file_tool, str(binary)], timeout=30)
        if result.returncode != 0 or "executable" not in result.stdout.lower():
            raise CandidateDefect(_process_failure("native-static-closure", [file_tool, str(binary)], result))


def run_c_native_kat(output: Path) -> None:
    if platform.system() != "Linux":
        raise ProviderHold("native-kat-linux-required")
    cc = require_tool("cc")
    with tempfile.TemporaryDirectory(prefix="swz-native-kat-") as temporary:
        executable = Path(temporary) / "native-unit"
        command = [
            cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-Wpedantic", "-D_GNU_SOURCE",
            "-I", str(HERE), str(ROOT / "tests/recovery-managed/native_unit.c"),
            str(HERE / "platform.c"), str(HERE / "protocol.c"), "-lcrypto", "-o", str(executable),
        ]
        result = run(command, timeout=180)
        if result.returncode != 0:
            raise CandidateDefect(_process_failure("native-unit-build", command, result))
        result = run([str(executable)], timeout=30)
        if (
            result.returncode != 0
            or "NATIVE_IDENTITY_KAT=PASS" not in result.stdout
            or "NATIVE_PROTOCOL_KAT=PASS" not in result.stdout
            or "NATIVE_REGISTRATION_KAT=PASS" not in result.stdout
        ):
            raise CandidateDefect(_process_failure("native-unit-run", [str(executable)], result))


def run_python_identity_agreement() -> dict[str, Any]:
    backend = load_module("swz_qualification_identity_backend", HERE / "backend.py")
    fixture_path = ROOT / "tests/recovery-managed/fixtures/transition-kats.json"
    try:
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise HarnessDefect("identity-kat-fixture-invalid") from error
    vector = fixture.get("identity_vector") if isinstance(fixture, dict) else None
    values = backend.identity_vector()
    if (
        not isinstance(vector, dict)
        or values.installation.hex() != vector.get("installation")
        or values.endpoint_template.hex() != vector.get("endpoint_template")
        or values.endpoint_actual.hex() != vector.get("endpoint_actual")
    ):
        raise CandidateDefect("python-identity-vector-mismatch")
    backend.assert_domain_uniqueness()
    backend.reject_self_reference(backend.IDENTITY_GRAPH)
    return {"identity_vector": "PASS", "managed_domains": len(backend.MANAGED_DOMAINS)}


def _source_boundary_check() -> dict[str, str]:
    sources = {
        "custodian": (HERE / "custodian.c").read_text(encoding="utf-8"),
        "supervisor": (HERE / "supervisor.c").read_text(encoding="utf-8"),
        "bootstrap": (HERE / "bootstrap.c").read_text(encoding="utf-8"),
        "dispatcher": (HERE / "dispatcher.c").read_text(encoding="utf-8"),
    }
    required = {
        "custodian": ("SWZ_REGISTRATION_BYTES", "swz_receive_fd", "swz_pidfd_process_in_tree", "SWZRGOK1", "state->armed = 0"),
        "supervisor": ("swz_pidfd_open", "swz_send_fd", "SWZRGOK1", "SWZ_EXEC_GATE_BYTE", "disable_signing", "SWZ_SESSION_CONTROL_SOCKET_PATH"),
        "bootstrap": ("SWZ_CONTEXT_MAGIC", "SWZ_SESSION_CONTROL_SOCKET_PATH", "SWZ_EXPECTED_BOOTSTRAP_DOMAIN", "SWZ_ACCEPTED"),
        "dispatcher": ("SSH_ORIGINAL_COMMAND", "SWZ_BOOTSTRAP_PATH", "clearenv", "swz_confine_process"),
    }
    for name, markers in required.items():
        if any(marker not in sources[name] for marker in markers):
            raise CandidateDefect(f"boundary-marker-missing:{name}")
    for name in ("custodian", "supervisor", "bootstrap", "dispatcher"):
        if "SSH_AUTH_SOCK" in sources[name]:
            raise CandidateDefect(f"environment-authority-present:{name}")
    return {name: "PASS" for name in sources}


def run_host_boundary_static() -> dict[str, Any]:
    source = _source_boundary_check()
    config = (HERE / "sshd_config").read_text(encoding="ascii")
    exact_config = (
        "HostKey /etc/ssh/recovery_host_ed25519_key.pub" in config
        and "HostKeyAgent /run/swz/recovery-hostkey-agent.sock" in config
        and "ForceCommand /usr/local/libexec/swz-dispatcher" in config
        and "HostKeyAgent SSH_AUTH_SOCK" not in config
    )
    if not exact_config:
        raise CandidateDefect("host-boundary-runtime-paths-invalid")
    return {"sources": source, "runtime_paths": "PASS", "kernel_proof": "guest-required"}


def mark_guest_pending(
    evidence: dict[str, Any],
    failures: list[str],
    case_id: str,
    requires: tuple[str, ...],
    detail: str = "isolated-guest-proof-required",
) -> None:
    blocked = [
        dependency for dependency in requires
        if evidence["statuses"].get(dependency, {}).get("status") != "PASS"
    ]
    if blocked:
        evidence["statuses"][case_id] = {
            "status": "QUALIFICATION_DEPENDENCY_FAILURE",
            "blocked_by": blocked,
            "detail": "prerequisite-not-pass",
        }
        failures.append(case_id)
        return
    evidence["statuses"][case_id] = {
        "status": "QUALIFICATION_PENDING_GUEST",
        "detail": detail,
    }


def run_supervisor_lifecycle(build_output: Path) -> dict[str, str]:
    _source_boundary_check()
    if platform.system() != "Linux":
        raise ProviderHold("supervisor-kernel-proof-linux-required")
    if not (build_output / "native" / "swz-supervisor").is_file():
        raise ProviderHold("supervisor-binary-unavailable")
    if os.geteuid() != 0:
        raise ProviderHold("supervisor-fixed-runtime-root-required")
    raise ProviderHold("supervisor-positive-negative-proof-isolated-guest-required")


def run_custody_negative(build_output: Path) -> dict[str, str]:
    _source_boundary_check()
    if platform.system() != "Linux":
        raise ProviderHold("custody-kernel-proof-linux-required")
    if not (build_output / "native" / "swz-custodian").is_file():
        raise ProviderHold("custodian-binary-unavailable")
    raise ProviderHold("custody-positive-negative-proof-isolated-guest-required")


def ensure_disposable_locator_client_path(container: str) -> None:
    command = [
        "docker", "exec", "--user", "root", container, "/bin/sh", "-c",
        "set -eu; "
        "if [ -x /usr/local/bin/psql ]; then exit 0; fi; "
        "if [ -e /usr/local/bin/psql ]; then exit 66; fi; "
        "psql_path=\"$(command -v psql || true)\"; "
        "[ -n \"$psql_path\" ]; "
        "ln -s \"$psql_path\" /usr/local/bin/psql",
    ]
    result = run(command, timeout=30)
    if result.returncode != 0:
        raise HarnessDefect(_process_failure("disposable-locator-client-path", command, result))


def run_locator_integration(build_output: Path) -> dict[str, Any]:
    if platform.system() != "Linux":
        raise ProviderHold("locator-integration-linux-required")
    require_tool("docker")
    lock = _load_lock()
    image = lock.get("postgres_qualification_image") if isinstance(lock, dict) else None
    if not isinstance(image, dict) or not isinstance(image.get("image"), str) or image.get("platform") != "linux/amd64":
        raise HarnessDefect("disposable-postgres-lock-invalid")
    container = "coolify-db"
    existing_command = ["docker", "ps", "-aq", "--filter", "name=^/" + container + "$"]
    existing = run(existing_command, timeout=30)
    if existing.returncode != 0:
        raise ProviderHold(_process_failure("disposable-container-preflight", existing_command, existing))
    if existing.stdout.strip():
        raise ProviderHold("disposable-container-name-in-use")
    start_command = [
        "docker", "run", "--rm", "--detach", "--name", container,
        "--platform", image["platform"],
        "--env", "POSTGRES_PASSWORD=swz-disposable-password",
        "--env", "POSTGRES_DB=coolify", "--env", "POSTGRES_USER=postgres",
        image["image"],
    ]
    started = run(start_command, timeout=120)
    if started.returncode != 0:
        raise ProviderHold(_process_failure("postgres-disposable-container-start", start_command, started))
    try:
        ready = False
        for _ in range(120):
            probe_command = ["docker", "exec", container, "pg_isready", "-U", "postgres", "-d", "coolify"]
            probe = run(probe_command, timeout=10)
            if probe.returncode == 0:
                ready = True
                break
            time.sleep(1)
        if not ready:
            raise ProviderHold("postgres-disposable-readiness-timeout")
        setup_sql = """
CREATE TABLE scheduled_database_backups (
  id bigint, enabled boolean, database_id bigint, database_type text,
  frequency text, save_s3 boolean, disable_local_backup boolean
);
CREATE TABLE scheduled_database_backup_executions (
  id bigint, scheduled_database_backup_id bigint, database_name text,
  status text, created_at timestamptz, size text, s3_uploaded boolean,
  filename text, local_storage_deleted boolean
);
INSERT INTO scheduled_database_backups VALUES
  (1, TRUE, 0, 'App\\Models\\StandalonePostgresql', '0 18 * * *', TRUE, FALSE);
INSERT INTO scheduled_database_backup_executions VALUES
  (23, 1, 'coolify', 'success', '2026-09-07T01:00:00Z', '830082', TRUE,
   'qualified-artifact', FALSE);
"""
        setup_command = [
            "docker", "exec", "-i", container, "psql", "-U", "postgres",
            "-d", "coolify", "-v", "ON_ERROR_STOP=1",
        ]
        setup = run(setup_command, input_text=setup_sql, timeout=30)
        if setup.returncode != 0:
            raise HarnessDefect(_process_failure("postgres-fixture-setup", setup_command, setup))
        ensure_disposable_locator_client_path(container)
        locator = load_module(
            "swz_locator_integration_adapter",
            ROOT / "scripts" / "platform-persisted-locator-adapter.py",
        )
        outcome = locator.execute_operation("2026-09-07T00:00:00.000000Z")
        if not isinstance(outcome, locator.OperationSuccess) or outcome.classification != locator.EXACTLY_ONE:
            raise CandidateDefect(f"locator-not-exactly-one:{getattr(outcome, 'classification', 'unknown')}")
        if outcome.filename != "qualified-artifact" or outcome.execution_id != 23:
            raise CandidateDefect("locator-fixture-identity-mismatch")

        controller = load_module("swz_locator_controller", HERE / "controller.py")
        context = controller.make_admitted_context("99" * 32, "aa" * 32, "bb" * 32)
        runner = controller.ManagedController(context)
        runner.accept()
        with tempfile.TemporaryDirectory(prefix="swz-store-locator-") as temporary:
            root = Path(temporary)
            store_root = make_private_store_root(root)
            source = root / outcome.filename
            target = root / "restored-artifact"
            source.write_bytes(b"real disposable Store/CAS locator integration\n")
            try:
                runner.run(
                    store_root=store_root,
                    artifact_source=source,
                    artifact_target=target,
                    agent_binary=build_output / "native" / "swz-agent",
                    locator_outcome=outcome,
                )
            except controller.QualificationProviderHold:
                pass
            else:
                raise CandidateDefect("locator-cas-provider-boundary-not-required")
            if stat.S_IMODE(store_root.stat().st_mode) != 0o700:
                raise CandidateDefect("store-root-not-private")
            if runner.store is None or runner.store.read_restore_ledger("epoch-qualified-001")["state"] != "CONSUMED":
                raise CandidateDefect("cas-consumption-not-proven")
            return {
                "locator": outcome.classification,
                "execution_id": outcome.execution_id,
                "cas": "CONSUMED_UNCERTAINTY_BOUNDARY",
                "store_root_mode": f"{stat.S_IMODE(store_root.stat().st_mode):04o}",
                "target_created": target.exists(),
            }
    finally:
        cleanup_command = ["docker", "rm", "-f", container]
        cleanup = run(cleanup_command, timeout=30)
        if cleanup.returncode != 0 and "no such container" not in (cleanup.stdout + cleanup.stderr).lower():
            raise HarnessDefect(_process_failure("postgres-disposable-cleanup", cleanup_command, cleanup))


def run_guest(build_output: Path, output: Path) -> dict[str, Any]:
    guest_root = os.environ.get("SWZ_GUEST_ROOT")
    if not guest_root:
        raise ProviderHold("SWZ_GUEST_ROOT-not-provided")
    command = [
        sys.executable, "-B", str(HERE / "qualification-vm.py"),
        "--build-output", str(build_output),
        "--guest-root", guest_root,
        "--policy", str(HERE / "selinux.cil"),
        "--file-contexts", str(HERE / "file_contexts"),
        "--output", str(output),
    ]
    result = run(command, timeout=600)
    if result.returncode == 75:
        raise ProviderHold(_process_failure("disposable-guest-qualification", command, result))
    if result.returncode != 0:
        raise CandidateDefect(_process_failure("disposable-guest-qualification", command, result))
    try:
        evidence = json.loads(output.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise HarnessDefect("guest-evidence-invalid") from error
    if not isinstance(evidence, dict) or evidence.get("status") != "PASS":
        raise CandidateDefect("guest-evidence-not-pass")
    return evidence


def _execute(
    evidence: dict[str, Any],
    failures: list[str],
    holds: list[str],
    case_id: str,
    function: Callable[[], Any],
    requires: tuple[str, ...] = (),
) -> None:
    blocked = [item for item in requires if evidence["statuses"].get(item, {}).get("status") != "PASS"]
    if blocked:
        evidence["statuses"][case_id] = {"status": "QUALIFICATION_DEPENDENCY_FAILURE", "blocked_by": blocked, "detail": "prerequisite-not-pass"}
        return
    try:
        value = function()
    except ProviderHold as error:
        evidence["statuses"][case_id] = {"status": "QUALIFICATION_PROVIDER_HOLD", "detail": str(error)}
        holds.append(case_id)
    except (CandidateDefect, HarnessDefect) as error:
        evidence["statuses"][case_id] = {"status": type(error).__name__.upper(), "detail": str(error)}
        failures.append(case_id)
    except Exception as error:
        evidence["statuses"][case_id] = {"status": "QUALIFICATION_HARNESS_DEFECT", "detail": f"{type(error).__name__}:{_bounded(error)}"}
        failures.append(case_id)
    else:
        evidence["statuses"][case_id] = {"status": "PASS", "evidence": value if isinstance(value, (dict, list, str, int, bool)) else "PASS"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=Path, default=ROOT / "tests/recovery-managed/fixtures/qualification-cases.json")
    parser.add_argument("--output", type=Path, default=HERE / "qualification-evidence.json")
    parser.add_argument("--build-output", type=Path, default=HERE / "build-output")
    parser.add_argument("--expected-sha")
    parser.add_argument("--phase", choices=("all", "preflight", "guest"), default="all")
    parser.add_argument("--resume", type=Path)
    args = parser.parse_args(argv)
    cases = load_cases(args.cases)
    try:
        candidate_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"QUALIFICATION_HARNESS_DEFECT=exact-head-unavailable:{error}", file=sys.stderr)
        return 1
    if args.expected_sha and candidate_sha != args.expected_sha:
        print("CANDIDATE_DEFECT=exact-head-mismatch", file=sys.stderr)
        return 1
    if args.phase == "guest":
        if args.resume is None:
            print("CANDIDATE_DEFECT=guest-phase-preflight-evidence-required", file=sys.stderr)
            return 1
        try:
            evidence = json.loads(args.resume.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            print("CANDIDATE_DEFECT=preflight-evidence-invalid", file=sys.stderr)
            return 1
        if (
            not isinstance(evidence, dict)
            or evidence.get("schema") != "swz-managed-qualification-evidence.v1"
            or evidence.get("gate") != "G3"
            or evidence.get("phase") != "preflight"
            or evidence.get("candidate_sha") != candidate_sha
            or evidence.get("mandatory_security_skips") != 0
            or not isinstance(evidence.get("statuses"), dict)
        ):
            print("CANDIDATE_DEFECT=preflight-evidence-mismatch", file=sys.stderr)
            return 1
        if evidence.get("failures") or evidence.get("provider_holds"):
            print("CANDIDATE_DEFECT=preflight-evidence-not-clear", file=sys.stderr)
            return 1
        evidence["phase"] = "guest"
        failures = list(evidence.get("failures", []))
        holds = list(evidence.get("provider_holds", []))
    else:
        evidence = {
            "schema": "swz-managed-qualification-evidence.v1",
            "gate": "G3",
            "candidate_sha": candidate_sha,
            "phase": args.phase,
            "statuses": {},
            "mandatory_security_skips": 0,
        }
        failures = []
        holds = []

    guest_state: dict[str, Any] = {"value": None}

    def ensure_guest() -> dict[str, Any]:
        if guest_state["value"] is None:
            guest_state["value"] = run_guest(
                args.build_output, args.output.with_name("guest-evidence.json"),
            )
        return guest_state["value"]

    if args.phase in ("all", "preflight"):
        # Keep this order explicit: deterministic and identity checks first,
        # then native warnings-as-errors/static closure, then the pinned
        # OpenSSH/musl build, Store/CAS/locator, and finally the host boundary.
        _execute(evidence, failures, holds, "repository-guardrails", exact_scope)
        _execute(
            evidence, failures, holds, "managed-boundary-deterministic-tests",
            run_deterministic_tests, ("repository-guardrails",),
        )
        _execute(
            evidence, failures, holds, "storewire-identity-kats",
            lambda: run_c_native_kat(args.output.parent),
            ("managed-boundary-deterministic-tests",),
        )
        _execute(
            evidence, failures, holds, "c-python-identity-agreement",
            run_python_identity_agreement, ("storewire-identity-kats",),
        )
        _execute(
            evidence, failures, holds, "container-build", run_container_build,
            ("managed-boundary-deterministic-tests",),
        )
        _execute(
            evidence, failures, holds, "native-c11-build",
            lambda: run_native_c11_build(args.build_output),
            ("c-python-identity-agreement",),
        )
        _execute(
            evidence, failures, holds, "native-static-closure",
            lambda: run_native_static_closure(args.build_output),
            ("native-c11-build",),
        )
        _execute(
            evidence, failures, holds, "pinned-openssh-build",
            lambda: (run_build(args.build_output), run_pinned_openssh_build(args.build_output))[1],
            ("native-static-closure",),
        )
        _execute(
            evidence, failures, holds, "canonical-store-locator-byte-equality",
            exact_scope, ("pinned-openssh-build",),
        )
        _execute(
            evidence, failures, holds, "disposable-store-cas-locator-integration",
            lambda: run_locator_integration(args.build_output),
            ("canonical-store-locator-byte-equality",),
        )
        host_requirements = (
            "native-c11-build", "native-static-closure", "pinned-openssh-build",
            "canonical-store-locator-byte-equality",
            "disposable-store-cas-locator-integration",
        )
        _execute(
            evidence, failures, holds, "socket-confinement",
            run_host_boundary_static, host_requirements,
        )
        if evidence["statuses"].get("socket-confinement", {}).get("status") == "PASS":
            static_evidence = evidence["statuses"]["socket-confinement"].get("evidence")
            evidence["statuses"]["socket-confinement"] = {
                "status": "QUALIFICATION_PENDING_GUEST",
                "detail": "isolated-guest-kernel-proof-required",
                "preflight": static_evidence,
            }
        for case_id in (
            "live-openssh-inetd-session", "host-key-custody-positive",
            "host-key-custody-negative", "native-lifecycle-listener-boundary",
            "process-finality-generation-retirement",
        ):
            mark_guest_pending(evidence, failures, case_id, host_requirements)
        _execute(
            evidence, failures, holds, "publication-scope-provenance", exact_scope,
            ("repository-guardrails",),
        )

    guest_requirements = (
        "repository-guardrails", "managed-boundary-deterministic-tests",
        "storewire-identity-kats", "c-python-identity-agreement", "container-build",
        "native-c11-build", "native-static-closure", "pinned-openssh-build",
        "canonical-store-locator-byte-equality",
        "disposable-store-cas-locator-integration",
    )
    if args.phase in ("all", "guest"):
        _execute(
            evidence, failures, holds, "dm-verity-booted-guest", ensure_guest,
            guest_requirements,
        )
        _execute(
            evidence, failures, holds, "selinux-enforcing-guest", ensure_guest,
            ("dm-verity-booted-guest",),
        )
        _execute(
            evidence, failures, holds, "selinux-denial-tests", ensure_guest,
            ("dm-verity-booted-guest",),
        )
        if evidence["statuses"].get("dm-verity-booted-guest", {}).get("status") == "PASS":
            guest_evidence = evidence["statuses"]["dm-verity-booted-guest"].get("evidence")
            for case_id in GUEST_PROOF_CASES:
                if evidence["statuses"].get(case_id, {}).get("status") == "QUALIFICATION_PENDING_GUEST":
                    evidence["statuses"][case_id] = {
                        "status": "PASS",
                        "evidence": {"guest": guest_evidence, "proof": "kernel-backed-guest-transcript"},
                    }
        _execute(
            evidence, failures, holds, "publication-scope-provenance", exact_scope,
            ("repository-guardrails",),
        )

    expected = {item["id"] for item in cases}
    actual = set(evidence["statuses"])
    missing = set() if args.phase == "preflight" else expected - actual
    for case_id in sorted(missing):
        evidence["statuses"][case_id] = {
            "status": "QUALIFICATION_HARNESS_DEFECT",
            "detail": "case-not-executed",
        }
        failures.append(case_id)
    unexpected = set(evidence["statuses"]) - expected
    for case_id in sorted(unexpected):
        evidence["statuses"][case_id] = {
            "status": "QUALIFICATION_HARNESS_DEFECT",
            "detail": "unregistered-case",
        }
        failures.append(case_id)
    evidence["provider_holds"] = holds
    evidence["failures"] = failures
    evidence["mandatory_security_skips"] = 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    print("MANDATORY_SECURITY_SKIPS=0")
    print(json.dumps(evidence, sort_keys=True))
    if failures:
        return 1
    if holds:
        return 75
    print("QUALIFICATION=" + ("PRE-GUEST-PASS" if args.phase == "preflight" else "PASS"))
    return 0


def run_openssh_live(build_output: Path) -> dict[str, str]:
    raise ProviderHold("real-pinned-openssh-handshake-isolated-guest-required")


if __name__ == "__main__":
    raise SystemExit(main())
