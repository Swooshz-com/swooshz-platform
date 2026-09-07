"""Run the complete disposable G3 qualification matrix.

The runner records every mandatory case. A missing hosted primitive is a
provider hold, a broken test setup is a harness defect, and a failed
candidate assertion is a candidate defect. None of these states is converted
to PASS or to a skipped mandatory case.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BASE = "3bff98ac5ef10c1675d4691f516952ac937915d3"


class CandidateDefect(RuntimeError):
    pass


class HarnessDefect(RuntimeError):
    pass


class ProviderHold(RuntimeError):
    pass


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise HarnessDefect(f"module-unavailable:{name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def run(command: list[str], *, cwd: Path = ROOT, input_text: str | None = None, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    effective_command = list(command)
    if os.name == "nt" and effective_command and effective_command[0] == "npm":
        effective_command[0] = shutil.which("npm.cmd") or effective_command[0]
    try:
        result = subprocess.run(
            effective_command,
            cwd=cwd,
            input=input_text,
            check=False,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except FileNotFoundError as error:
        raise ProviderHold(f"tool-unavailable:{effective_command[0]}") from error
    except subprocess.TimeoutExpired as error:
        raise HarnessDefect(f"command-timeout:{command[0]}") from error
    return result


def require_tool(name: str) -> str:
    names = (name, name + ".cmd") if os.name == "nt" and name in {"npm", "npx"} else (name,)
    for candidate in names:
        path = shutil.which(candidate)
        if path is not None:
            return path
    raise ProviderHold(f"tool-unavailable:{name}")


def load_cases(path: Path) -> list[dict[str, Any]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise HarnessDefect("qualification-case-fixture-invalid") from error
    if value.get("schema") != "swz-managed-qualification-cases.v1" or value.get("mandatory_security_skips") != 0:
        raise CandidateDefect("qualification-case-registry-invalid")
    cases = value.get("cases")
    if not isinstance(cases, list) or not cases or any(not isinstance(item, dict) for item in cases):
        raise HarnessDefect("qualification-case-list-invalid")
    ids = [item.get("id") for item in cases]
    if len(ids) != len(set(ids)) or any(not item.get("mandatory") for item in cases):
        raise CandidateDefect("mandatory-case-registry-invalid")
    return cases


def git_text(*args: str) -> str:
    result = run(["git", *args], timeout=30)
    if result.returncode != 0:
        raise HarnessDefect(f"git-command-failed:{args[0]}")
    return result.stdout


def exact_scope() -> dict[str, Any]:
    allowed = {
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
    }
    names = {line for line in git_text("diff", "--name-only", BASE, "--").splitlines() if line}
    if not names <= allowed:
        raise CandidateDefect("UNAUTHORISED_PATHS:" + ",".join(sorted(names - allowed)))
    if len(names) > 41:
        raise CandidateDefect("PATH_CEILING_EXCEEDED")
    canonical = (
        "scripts/platform-recovery-controller-store.py",
        "scripts/platform-persisted-locator-adapter.py",
        "tests/test_platform_recovery_controller_store.py",
        "tests/test_platform_persisted_locator_adapter.py",
    )
    for relative in canonical:
        expected = subprocess.check_output(["git", "show", f"{BASE}:{relative}"], cwd=ROOT)
        if (ROOT / relative).read_bytes() != expected:
            raise CandidateDefect(f"CANONICAL_FILE_CHANGED:{relative}")
    return {"changed_paths": sorted(names), "path_count": len(names), "canonical_files": "byte-identical"}


def run_deterministic_tests() -> None:
    try:
        with tempfile.TemporaryDirectory(prefix="swz-qualification-preflight-") as temporary:
            probe = Path(temporary) / "write-probe"
            probe.write_bytes(b"qualification-workspace")
            if probe.read_bytes() != b"qualification-workspace":
                raise OSError("qualification-workspace-readback")
    except OSError as error:
        raise ProviderHold("qualification-workspace-unavailable") from error
    if platform.system() != "Linux":
        raise ProviderHold("managed-deterministic-linux-required")
    result = run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests/recovery-managed", "-p", "test_*.py"], timeout=180)
    if result.returncode != 0:
        raise CandidateDefect("deterministic-tests-failed")


def run_application_gates() -> None:
    require_tool("node")
    require_tool("npm")
    for command in (["npm", "run", "typecheck"], ["npm", "run", "build"], ["npm", "test"]):
        result = run(command, timeout=240)
        if result.returncode != 0:
            raise CandidateDefect("application-gate-failed:" + command[-1])


def run_container_build() -> None:
    require_tool("docker")
    result = run(["docker", "build", "--pull=false", "-t", "swz-managed-platform-g3-ci", "."], timeout=600)
    if result.returncode != 0:
        output = (result.stdout or "") + (result.stderr or "")
        provider_signals = (
            "Cannot connect to the Docker daemon",
            "docker_engine",
            "Is the docker daemon running",
            "error during connect",
            "pull access denied",
            "failed to resolve source metadata",
            "network is unreachable",
            "tls handshake timeout",
            "i/o timeout",
            "unable to evaluate symlinks in context path",
        )
        if any(signal in output for signal in provider_signals):
            raise ProviderHold("disposable-container-provider-unavailable")
        raise CandidateDefect("container-build-failed")


def run_build(build_output: Path) -> None:
    result = run(
        [sys.executable, "-B", str(HERE / "build.py"), "--output", str(build_output)],
        timeout=1800,
    )
    if result.returncode == 75:
        raise ProviderHold("managed-build-provider-hold")
    if result.returncode != 0:
        raise CandidateDefect("managed-build-failed")
    manifest = build_output / "build-manifest.json"
    if not manifest.is_file():
        raise CandidateDefect("managed-build-manifest-missing")
    try:
        manifest_value = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CandidateDefect("managed-build-manifest-invalid") from error
    if manifest_value.get("candidate_sha") != git_text("rev-parse", "HEAD").strip():
        raise CandidateDefect("managed-build-manifest-head-mismatch")
    install_plan = build_output / "install-plan.json"
    result = run(
        [
            sys.executable, "-B", str(HERE / "install-plan.py"),
            "--manifest", str(manifest), "--output", str(install_plan),
        ],
        timeout=120,
    )
    if result.returncode != 0:
        raise CandidateDefect("install-plan-validation-failed")


def run_pinned_openssh_build(build_output: Path) -> dict[str, str]:
    ensure_manifest = build_output / "build-manifest.json"
    try:
        manifest = json.loads(ensure_manifest.read_text(encoding="utf-8"))
        lock = json.loads((HERE / "build.lock.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CandidateDefect("openssh-provenance-manifest-invalid") from error
    openssh = manifest.get("openssh")
    locked = lock.get("openssh")
    if not isinstance(openssh, dict) or not isinstance(locked, dict):
        raise CandidateDefect("openssh-provenance-fields-invalid")
    if (
        manifest.get("candidate_sha") != git_text("rev-parse", "HEAD").strip()
        or openssh.get("version") != "OpenSSH_10.5p1"
        or openssh.get("sshd_version") != "OpenSSH_10.5p1"
        or locked.get("version") != "10.5p1"
        or openssh.get("archive_sha256") != locked.get("sha256")
    ):
        raise CandidateDefect("openssh-pinned-provenance-mismatch")
    for relative, key in (
        ("openssh/sbin/sshd", "binary_sha256"),
        ("openssh/bin/ssh", "ssh_sha256"),
        ("openssh/bin/ssh-keygen", "ssh_keygen_sha256"),
        ("openssh/bin/ssh-agent", "ssh_agent_sha256"),
        ("openssh/bin/ssh-add", "ssh_add_sha256"),
    ):
        path = build_output / relative
        try:
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as error:
            raise CandidateDefect("openssh-runtime-file-missing") from error
        if actual != openssh.get(key):
            raise CandidateDefect("openssh-runtime-digest-mismatch")
    result = run([str(build_output / "openssh/sbin/sshd"), "-V"], timeout=30)
    output = (result.stdout or "") + (result.stderr or "")
    if "OpenSSH_10.5p1" not in output or "swz-baseline=openssh-10.5p1" not in output:
        raise CandidateDefect("openssh-runtime-baseline-mismatch")
    return {
        "version": openssh["version"],
        "archive_sha256": openssh["archive_sha256"],
        "binary_sha256": openssh["binary_sha256"],
    }


def run_native_static_closure(build_output: Path) -> None:
    result = run(
        ["make", "-C", str(HERE), f"BUILD={build_output / 'native'}", "static-closure"],
        timeout=180,
    )
    if result.returncode != 0:
        raise CandidateDefect("native-static-closure-failed")


def run_c_native_kat(output: Path) -> None:
    cc = require_tool("cc")
    try:
        output.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise ProviderHold("native-kat-output-unavailable") from error
    executable = output / "native-unit"
    result = run(
        [
            cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
            "-I", str(HERE), str(ROOT / "tests/recovery-managed/native_unit.c"),
            str(HERE / "platform.c"), str(HERE / "protocol.c"), "-lcrypto",
            "-o", str(executable),
        ],
        timeout=120,
    )
    if result.returncode != 0:
        raise CandidateDefect("native-unit-build-failed")
    result = run([str(executable)], timeout=30)
    if result.returncode != 0 or "NATIVE_IDENTITY_KAT=PASS" not in result.stdout:
        raise CandidateDefect("c-python-kat-failed")


def run_openssh_live(build_output: Path) -> dict[str, str]:
    module = load_module("swz_qualification_openssh", ROOT / "tests/recovery-managed/test_openssh.py")
    try:
        return module.run_live_inetd_session(build_output)
    except module.OpenSSHProviderHold as error:
        raise ProviderHold(str(error)) from error
    except module.OpenSSHQualificationError as error:
        raise CandidateDefect(str(error)) from error


def run_supervisor_lifecycle(build_output: Path) -> None:
    if platform.system() != "Linux":
        raise ProviderHold("native-lifecycle-linux-required")
    binary = build_output / "native/swz-supervisor"
    if not binary.is_file():
        raise ProviderHold("supervisor-binary-unavailable")
    with tempfile.TemporaryDirectory(prefix="swz-supervisor-test-") as temporary:
        root = Path(temporary)
        socket_path = root / "listener.sock"
        generation = "44" * 32
        prebarrier_env = os.environ.copy()
        for name in ("SWZ_ACCEPTED", "SWZ_LAUNCH_AUTHORIZED", "SWZ_PROCEED_AUTHORIZED", "SWZ_GENERATION", "SWZ_LIFECYCLE"):
            prebarrier_env.pop(name, None)
        prebarrier = subprocess.run(
            [str(binary), "--socket", str(root / "prebarrier.sock"), "--generation", generation, "--once"],
            env=prebarrier_env,
            check=False,
            capture_output=True,
            timeout=5,
        )
        if prebarrier.returncode == 0 or (root / "prebarrier.sock").exists():
            raise CandidateDefect("supervisor-prebarrier-capability-exposed")
        env = os.environ.copy()
        env.update(
            {
                "SWZ_ACCEPTED": "1",
                "SWZ_LAUNCH_AUTHORIZED": "1",
                "SWZ_PROCEED_AUTHORIZED": "1",
                "SWZ_GENERATION": generation,
                "SWZ_LIFECYCLE": "ACTIVE",
            }
        )
        process = subprocess.Popen(
            [str(binary), "--socket", str(socket_path), "--generation", generation, "--once"],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(200):
            if socket_path.exists():
                break
            if process.poll() is not None:
                break
            time.sleep(0.01)
        if not socket_path.exists():
            stdout, stderr = process.communicate(timeout=3)
            raise CandidateDefect(f"supervisor-listener-missing:{stdout}:{stderr}")
        mode = socket_path.stat().st_mode & 0o777
        if mode != 0o600:
            process.terminate()
            process.wait(timeout=3)
            raise CandidateDefect("supervisor-socket-permissions")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(str(socket_path))
            client.sendall(f"SWZ-CONNECTION-V1 {generation}\n".encode("ascii"))
            if client.recv(64) != b"SWZ-CONNECTION-ACCEPTED\n":
                raise CandidateDefect("supervisor-handshake-invalid")
        if process.wait(timeout=5) != 0 or socket_path.exists():
            raise CandidateDefect("supervisor-retirement-invalid")


def run_custody_negative(build_output: Path) -> None:
    if platform.system() != "Linux":
        raise ProviderHold("custody-linux-required")
    required = [build_output / "native/swz-custodian", build_output / "openssh/bin/ssh-agent", build_output / "openssh/bin/ssh-add", build_output / "openssh/bin/ssh-keygen"]
    if any(not path.is_file() for path in required):
        raise ProviderHold("custody-build-closure-unavailable")
    with tempfile.TemporaryDirectory(prefix="swz-custody-negative-") as temporary:
        root = Path(temporary)
        key = root / "host_ed25519"
        keygen = required[-1]
        result = run([str(keygen), "-q", "-t", "ed25519", "-N", "", "-f", str(key)], timeout=30)
        if result.returncode != 0:
            raise CandidateDefect("custody-test-key-generation-failed")
        public = key.with_name(key.name + ".pub")
        public.chmod(0o644)
        expected = {"SWZ_ACCEPTED": "1", "SWZ_SESSION": "55" * 32, "SWZ_GENERATION": "66" * 32, "SWZ_CONNECTION_COOKIE": "77" * 32, "SWZ_LIFECYCLE": "ACTIVE"}
        env = os.environ.copy()
        env.update(expected)
        def launch(socket_path: Path, owner_pid: str, launch_env: dict[str, str] | None = None) -> subprocess.Popen[str]:
            return subprocess.Popen(
                [
                    str(required[0]), "--socket", str(socket_path), "--agent", str(required[1]),
                    "--add", str(required[2]), "--private-key", str(key), "--public-key", str(public),
                    "--owner-pid", owner_pid, "--cookie", expected["SWZ_CONNECTION_COOKIE"],
                    "--session", expected["SWZ_SESSION"], "--generation", expected["SWZ_GENERATION"],
                ],
                env=env if launch_env is None else launch_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

        def connect(socket_path: Path, peer_env: dict[str, str]) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [
                    sys.executable, "-c",
                    "import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.close()",
                    str(socket_path),
                ],
                env=peer_env,
                check=False,
                capture_output=True,
                timeout=10,
            )

        def require_rejection(label: str, mismatch: tuple[str, str] | None = None, owner_pid: str | None = None) -> Path:
            socket_path = root / f"{label}.sock"
            process = launch(socket_path, owner_pid or str(os.getpid()))
            try:
                if owner_pid is not None:
                    if process.wait(timeout=10) == 0 or socket_path.exists():
                        raise CandidateDefect(f"custody-{label}-accepted")
                    return socket_path
                for _ in range(200):
                    if socket_path.exists() or process.poll() is not None:
                        break
                    time.sleep(0.01)
                if not socket_path.exists():
                    stdout, stderr = process.communicate(timeout=3)
                    raise CandidateDefect(f"custody-listener-missing:{label}:{stdout}:{stderr}")
                if socket_path.stat().st_mode & 0o777 != 0o600:
                    raise CandidateDefect(f"custody-socket-permissions:{label}")
                peer_env = env.copy()
                assert mismatch is not None
                peer_env[mismatch[0]] = mismatch[1]
                probe = connect(socket_path, peer_env)
                if probe.returncode != 0:
                    raise HarnessDefect(f"custody-negative-probe-connect-failed:{label}")
                if process.wait(timeout=10) == 0:
                    raise CandidateDefect(f"custody-{label}-accepted")
                return socket_path
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=3)

        prebarrier_env = env.copy()
        for variable in ("SWZ_ACCEPTED", "SWZ_SESSION", "SWZ_GENERATION", "SWZ_CONNECTION_COOKIE", "SWZ_LIFECYCLE"):
            prebarrier_env.pop(variable, None)
        prebarrier_socket = root / "prebarrier.sock"
        prebarrier = launch(prebarrier_socket, str(os.getpid()), prebarrier_env)
        if prebarrier.wait(timeout=10) == 0 or prebarrier_socket.exists():
            raise CandidateDefect("custody-prebarrier-capability-exposed")
        require_rejection("wrong-owner", owner_pid=str(os.getpid() + 1000000))
        for label, variable, value in (
            ("wrong-cookie", "SWZ_CONNECTION_COOKIE", "88" * 32),
            ("wrong-session", "SWZ_SESSION", "88" * 32),
            ("wrong-generation", "SWZ_GENERATION", "88" * 32),
            ("wrong-lifecycle", "SWZ_LIFECYCLE", "DRAINING"),
        ):
            socket_path = require_rejection(label, (variable, value))
            if socket_path.exists():
                raise CandidateDefect(f"custody-{label}-socket-retained")
            reuse = connect(socket_path, env)
            if reuse.returncode == 0:
                raise CandidateDefect("custody-post-retirement-reuse-accepted")


def run_locator_integration(build_output: Path) -> dict[str, Any]:
    if platform.system() != "Linux":
        raise ProviderHold("locator-integration-linux-required")
    controller = load_module("swz_qualification_controller", HERE / "controller.py")
    context = controller.make_admitted_context("99" * 32, "aa" * 32, "bb" * 32)
    runner = controller.ManagedController(context)
    runner.accept()
    require_tool("docker")
    lock = json.loads((HERE / "build.lock.json").read_text(encoding="utf-8"))
    image = lock["postgres_qualification_image"]["image"]
    container = "coolify-db"
    existing = run(["docker", "ps", "-aq", "--filter", "name=^/" + container + "$"], timeout=30)
    if existing.returncode == 0 and existing.stdout.strip():
        raise ProviderHold("disposable-container-name-in-use")
    started = run(
        [
            "docker", "run", "--rm", "--detach", "--name", container,
            "--platform", lock["postgres_qualification_image"]["platform"],
            "--env", "POSTGRES_PASSWORD=swz-disposable-password",
            "--env", "POSTGRES_DB=coolify", "--env", "POSTGRES_USER=postgres", image,
        ],
        timeout=120,
    )
    if started.returncode != 0:
        raise ProviderHold("postgres-disposable-container-unavailable")
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
        sql = """
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
        setup = run(["docker", "exec", "-i", container, "psql", "-U", "postgres", "-d", "coolify", "-v", "ON_ERROR_STOP=1"], input_text=sql, timeout=30)
        if setup.returncode != 0:
            raise HarnessDefect("postgres-fixture-setup-failed")
        outcome = runner.execute_locator("2026-09-07T00:00:00.000000Z")
        with tempfile.TemporaryDirectory(prefix="swz-store-locator-") as temporary:
            root = Path(temporary)
            store_root = root / "store"
            store_root.mkdir()
            source = root / "qualified-artifact"
            target = root / "restored-artifact"
            source.write_bytes(b"real disposable Store/CAS locator integration\n")
            result = runner.run(
                store_root=store_root, artifact_source=source, artifact_target=target,
                agent_binary=build_output / "native/swz-agent", locator_outcome=outcome,
                inputs=controller.disposable_inputs("2026-09-07T00:00:00Z"),
            )
            return {
                "classification": outcome.classification,
                "execution_id": outcome.execution_id,
                "final_state": result.final_state,
                "half_closes": result.stdin_half_closes,
                "remote_eof": result.remote_eof,
            }
    finally:
        run(["docker", "rm", "-f", container], timeout=30)


def run_guest(build_output: Path, output: Path) -> dict[str, Any]:
    guest_root_text = os.environ.get("SWZ_GUEST_ROOT")
    if not guest_root_text:
        raise HarnessDefect("SWZ_GUEST_ROOT-not-provided")
    root = Path(guest_root_text)
    result = run(
        [
            sys.executable, "-B", str(HERE / "qualification-vm.py"),
            "--build-output", str(build_output),
            "--guest-root", str(root), "--policy", str(HERE / "selinux.cil"),
            "--file-contexts", str(HERE / "file_contexts"), "--output", str(output),
        ],
        timeout=180,
    )
    if result.returncode == 75:
        raise ProviderHold("disposable-guest-provider-hold")
    if result.returncode != 0:
        raise CandidateDefect("disposable-guest-proof-failed")
    try:
        value = json.loads(output.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise HarnessDefect("disposable-guest-evidence-invalid") from error
    if value.get("status") != "PASS":
        raise CandidateDefect("disposable-guest-evidence-not-pass")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=Path, default=HERE.parent.parent / "tests/recovery-managed/fixtures/qualification-cases.json")
    parser.add_argument("--output", type=Path, default=HERE / "qualification-evidence.json")
    parser.add_argument("--build-output", type=Path, default=HERE / "build-output")
    parser.add_argument("--expected-sha")
    args = parser.parse_args(argv)
    cases = load_cases(args.cases)
    evidence: dict[str, Any] = {
        "schema": "swz-managed-qualification-evidence.v1",
        "gate": "G3",
        "candidate_sha": git_text("rev-parse", "HEAD").strip(),
        "statuses": {},
        "mandatory_security_skips": 0,
    }
    if args.expected_sha and evidence["candidate_sha"] != args.expected_sha:
        print("CANDIDATE_DEFECT=exact-head-mismatch", file=sys.stderr)
        return 1
    failures: list[str] = []
    holds: list[str] = []
    build_state = {"built": False}
    guest_state: dict[str, Any] = {"value": None}

    def ensure_build() -> None:
        if not build_state["built"]:
            run_build(args.build_output)
            build_state["built"] = True

    def ensure_static_closure() -> None:
        ensure_build()
        run_native_static_closure(args.build_output)

    def ensure_openssh_live() -> dict[str, str]:
        ensure_build()
        return run_openssh_live(args.build_output)

    def ensure_guest() -> dict[str, Any]:
        if guest_state["value"] is None:
            guest_state["value"] = run_guest(args.build_output, args.output.with_name("guest-evidence.json"))
        return guest_state["value"]

    def execute(case_id: str, function: Callable[[], Any]) -> None:
        try:
            value = function()
        except ProviderHold as error:
            evidence["statuses"][case_id] = {"status": "QUALIFICATION_PROVIDER_HOLD", "detail": str(error)}
            holds.append(case_id)
        except HarnessDefect as error:
            evidence["statuses"][case_id] = {"status": "QUALIFICATION_HARNESS_DEFECT", "detail": str(error)}
            failures.append(case_id)
        except CandidateDefect as error:
            evidence["statuses"][case_id] = {"status": "CANDIDATE_DEFECT", "detail": str(error)}
            failures.append(case_id)
        except Exception as error:
            evidence["statuses"][case_id] = {"status": "QUALIFICATION_HARNESS_DEFECT", "detail": type(error).__name__}
            failures.append(case_id)
        else:
            evidence["statuses"][case_id] = {"status": "PASS", "evidence": value if isinstance(value, (dict, list, str, int, bool)) else "PASS"}

    execute("repository-guardrails", exact_scope)
    execute("application-typecheck-build-tests", run_application_gates)
    execute("managed-boundary-deterministic-tests", run_deterministic_tests)
    execute("storewire-identity-kats", run_deterministic_tests)
    execute("canonical-store-locator-byte-equality", exact_scope)
    execute("container-build", run_container_build)
    execute("native-c11-build", ensure_build)
    execute("native-static-closure", ensure_static_closure)
    execute("c-python-identity-agreement", lambda: run_c_native_kat(args.build_output))
    execute("native-lifecycle-listener-boundary", lambda: run_supervisor_lifecycle(args.build_output))
    execute("socket-confinement", lambda: run_supervisor_lifecycle(args.build_output))
    execute("host-key-custody-negative", lambda: run_custody_negative(args.build_output))
    execute("host-key-custody-positive", ensure_openssh_live)
    execute("pinned-openssh-build", lambda: (ensure_build(), run_pinned_openssh_build(args.build_output))[1])
    execute("live-openssh-inetd-session", ensure_openssh_live)
    execute("disposable-store-cas-locator-integration", lambda: run_locator_integration(args.build_output))
    execute("dm-verity-booted-guest", ensure_guest)
    execute("selinux-enforcing-guest", ensure_guest)
    execute("selinux-denial-tests", ensure_guest)
    execute("process-finality-generation-retirement", lambda: run_supervisor_lifecycle(args.build_output))
    execute("publication-scope-provenance", exact_scope)
    expected_ids = {case["id"] for case in cases}
    actual_ids = set(evidence["statuses"])
    missing = expected_ids - actual_ids
    if missing:
        for case_id in sorted(missing):
            evidence["statuses"][case_id] = {"status": "QUALIFICATION_HARNESS_DEFECT", "detail": "case-not-executed"}
        failures.extend(sorted(missing))
    unexpected = actual_ids - expected_ids
    if unexpected:
        failures.extend(sorted(unexpected))
        for case_id in sorted(unexpected):
            evidence["statuses"][case_id] = {"status": "QUALIFICATION_HARNESS_DEFECT", "detail": "unregistered-case"}
    evidence["provider_holds"] = holds
    evidence["failures"] = failures
    evidence["mandatory_security_skips"] = 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    print("MANDATORY_SECURITY_SKIPS=0")
    if failures:
        print("QUALIFICATION_HARNESS_OR_CANDIDATE_FAILURE=" + ",".join(sorted(set(failures))), file=sys.stderr)
        return 1
    if holds:
        print("QUALIFICATION_PROVIDER_HOLD=" + ",".join(sorted(set(holds))), file=sys.stderr)
        return 75
    print("QUALIFICATION=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
