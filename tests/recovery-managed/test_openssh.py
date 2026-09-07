import hashlib
import importlib.util
import json
import os
import pathlib
import platform
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
MANAGED = ROOT / "recovery/managed"
BACKEND_SPEC = importlib.util.spec_from_file_location("swz_openssh_backend", MANAGED / "backend.py")
assert BACKEND_SPEC is not None and BACKEND_SPEC.loader is not None
BACKEND = importlib.util.module_from_spec(BACKEND_SPEC)
sys.modules[BACKEND_SPEC.name] = BACKEND
BACKEND_SPEC.loader.exec_module(BACKEND)


class OpenSSHQualificationError(RuntimeError):
    pass


class OpenSSHProviderHold(OpenSSHQualificationError):
    pass


def _run(command, *, cwd=None, env=None, timeout=30):
    try:
        result = subprocess.run(command, cwd=cwd, env=env, check=False, text=True, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise OpenSSHProviderHold("openssh-process-unavailable") from error
    if result.returncode != 0:
        raise OpenSSHQualificationError(f"openssh-command-failed:{command[0]}")
    return result


def run_live_inetd_session(build_output: pathlib.Path) -> dict[str, str]:
    if platform.system() != "Linux":
        raise OpenSSHProviderHold("openssh-live-test-linux-required")
    openssh = build_output / "openssh"
    sshd = openssh / "sbin/sshd"
    ssh = openssh / "bin/ssh"
    keygen = openssh / "bin/ssh-keygen"
    custodian = build_output / "native/swz-custodian"
    dispatcher = build_output / "native/swz-dispatcher"
    bootstrap = build_output / "native/swz-bootstrap"
    agent = openssh / "bin/ssh-agent"
    add = openssh / "bin/ssh-add"
    required = (sshd, ssh, keygen, custodian, dispatcher, bootstrap, agent, add)
    if any(not path.is_file() for path in required):
        raise OpenSSHProviderHold("openssh-build-closure-missing")
    import socket
    import threading
    with tempfile.TemporaryDirectory(prefix="swz-openssh-live-") as temporary:
        work = pathlib.Path(temporary)
        host_key = work / "host_ed25519"
        client_key = work / "client_ed25519"
        _run([str(keygen), "-q", "-t", "ed25519", "-N", "", "-f", str(host_key)])
        _run([str(keygen), "-q", "-t", "ed25519", "-N", "", "-f", str(client_key)])
        public_key = (client_key.with_name(client_key.name + ".pub")).read_text(encoding="ascii").strip() + "\n"
        (work / "authorized_keys").write_text(public_key, encoding="ascii")
        host_pub = host_key.with_name(host_key.name + ".pub")
        host_pub.chmod(0o644)
        cookie = "aa" * 32
        session = "bb" * 32
        generation = "cc" * 32
        accepted_payload = BACKEND.managed_json(["ACCEPTED", 2, BACKEND.MANAGED_SCHEMA, session])
        accepted_frame = BACKEND.build_frame(
            BACKEND.DIRECTION_LOCAL_TO_REMOTE,
            "ACCEPTED",
            5,
            bytes.fromhex("dd" * 32),
            accepted_payload,
        )
        env = os.environ.copy()
        env.update(
            {
                "SWZ_SESSION": session,
                "SWZ_GENERATION": generation,
                "SWZ_CONNECTION_COOKIE": cookie,
                "SWZ_LIFECYCLE": "ACTIVE",
                "SWZ_ACCEPTED": "1",
                "SWZ_LAUNCH_AUTHORIZED": "1",
            }
        )
        custody_socket = work / "custodian.sock"
        custodian_process = subprocess.Popen(
            [
                str(custodian), "--socket", str(custody_socket), "--agent", str(agent),
                "--add", str(add), "--private-key", str(host_key), "--public-key", str(host_pub),
                "--owner-pid", str(os.getpid()), "--cookie", cookie, "--session", session,
                "--generation", generation,
            ],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(200):
            if custody_socket.exists():
                break
            if custodian_process.poll() is not None:
                break
            import time
            time.sleep(0.01)
        if not custody_socket.exists():
            stdout, stderr = custodian_process.communicate(timeout=3)
            raise OpenSSHQualificationError(f"custodian-did-not-listen:{stdout}:{stderr}")
        config = work / "sshd_config"
        config.write_text(
            "\n".join(
                [
                    "AddressFamily inet",
                    "HostKey " + str(host_pub),
                    "HostKeyAgent " + str(custody_socket),
                    "AuthorizedKeysFile " + str(work / "authorized_keys"),
                    "PasswordAuthentication no",
                    "KbdInteractiveAuthentication no",
                    "ChallengeResponseAuthentication no",
                    "UsePAM no",
                    "PermitRootLogin prohibit-password",
                    "StrictModes no",
                    "PermitTTY no",
                    "X11Forwarding no",
                    "AllowTcpForwarding no",
                    "AllowAgentForwarding no",
                    "PermitTunnel no",
                    "PidFile none",
                    "LogLevel QUIET",
                    "ForceCommand " + " ".join(
                        shlex.quote(value)
                        for value in (
                            str(dispatcher), "--bootstrap", str(bootstrap), "--session", session,
                            "--generation", generation, "--cookie", cookie,
                            "--owner-pid", str(os.getpid()),
                        )
                    ),
                    "SetEnv SWZ_ACCEPTED=1 SWZ_SESSION=" + session + " SWZ_GENERATION=" + generation +
                    " SWZ_CONNECTION_COOKIE=" + cookie + " SWZ_LIFECYCLE=ACTIVE",
                ]
            )
            + "\n",
            encoding="ascii",
        )
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        server_state = {}

        def serve() -> None:
            try:
                connection, _ = listener.accept()
                with connection:
                    server = subprocess.Popen(
                        [str(sshd), "-i", "-e", "-f", str(config)],
                        stdin=connection,
                        stdout=connection,
                        stderr=subprocess.PIPE,
                        env=env,
                    )
                    server_state["process"] = server
                    server_state["returncode"] = server.wait(timeout=20)
                    server_state["stderr"] = server.stderr.read() if server.stderr is not None else b""
            except Exception as error:
                server_state["error"] = error

        server_thread = threading.Thread(target=serve, daemon=True)
        server_thread.start()
        user = os.environ.get("USER") or os.environ.get("USERNAME")
        if not user:
            raise OpenSSHProviderHold("login-user-unavailable")
        client = subprocess.run(
            [
                str(ssh), "-i", str(client_key), "-p", str(port), "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                f"{user}@127.0.0.1", "ignored-command",
            ],
            env=env,
            check=False,
            input=accepted_frame,
            text=False,
            capture_output=True,
            timeout=30,
        )
        server_thread.join(timeout=30)
        listener.close()
        if server_thread.is_alive():
            raise OpenSSHQualificationError("openssh-server-thread-timeout")
        if "error" in server_state:
            raise OpenSSHQualificationError("openssh-server-thread-failed") from server_state["error"]
        if client.returncode != 0:
            raise OpenSSHQualificationError("openssh-live-session-failed")
        try:
            challenge = BACKEND.decode_frame(client.stdout)
            challenge_payload = BACKEND.parse_managed_json(challenge.payload)
        except BACKEND.BoundaryError as error:
            raise OpenSSHQualificationError("openssh-dispatcher-frame-invalid") from error
        if (
            challenge.direction != BACKEND.DIRECTION_REMOTE_TO_LOCAL
            or challenge.message != "CHALLENGE"
            or challenge_payload != ["CHALLENGE", 2, BACKEND.MANAGED_SCHEMA, session]
        ):
            raise OpenSSHQualificationError("openssh-dispatcher-challenge-invalid")
        if custodian_process.wait(timeout=10) != 0:
            raise OpenSSHQualificationError("custodian-finality-failed")
        if custody_socket.exists():
            raise OpenSSHQualificationError("custody-socket-retained")
        return {
            "status": "PASS",
            "sshd": "OpenSSH_10.5p1",
            "host_key_agent": "functional",
            "inetd_session": "PASS",
            "custodian": "final",
        }


class OpenSSHContractTests(unittest.TestCase):
    def test_source_lock_and_real_patch(self):
        lock = json.loads((MANAGED / "build.lock.json").read_text(encoding="utf-8"))
        self.assertEqual(lock["openssh"]["version"], "10.5p1")
        self.assertEqual(lock["openssh"]["sha256"], "d44d28a839ea9daf969cc69150fde59910b2b39361dad81a3bd6cbd19218db11")
        patch = (MANAGED / "openssh-managed.patch").read_text(encoding="ascii")
        self.assertIn("diff --git a/sshd.c b/sshd.c", patch)
        self.assertIn("swz-baseline=%s", patch)
        self.assertIn("SWZ_MANAGED_OPENSSH_BASELINE", patch)
        self.assertIn("swz_managed_runtime_authorized", patch)

    def test_configuration_requires_agent_and_forbids_subsystems(self):
        config = (MANAGED / "sshd_config").read_text(encoding="ascii")
        self.assertIn("HostKeyAgent SSH_AUTH_SOCK", config)
        self.assertNotIn("Subsystem", config)
        self.assertIn("ForceCommand /usr/local/libexec/swz-dispatcher", config)

    def test_no_distro_sshd_is_selected(self):
        sources = (MANAGED / "build.py").read_text(encoding="utf-8")
        self.assertIn("build_openssh", sources)
        self.assertIn("capture_version", sources)
        self.assertNotIn("shutil.which(\"sshd\")", sources)

    def test_guest_path_uses_native_fresh_inetd_supervisor(self):
        guest = (MANAGED / "qualification-vm.py").read_text(encoding="utf-8")
        supervisor = (MANAGED / "supervisor.c").read_text(encoding="utf-8")
        self.assertIn("--inetd", guest)
        self.assertIn('execl(sshd_path, sshd_path, "-i"', supervisor)


if __name__ == "__main__":
    unittest.main()
