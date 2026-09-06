from __future__ import annotations

import hashlib
import importlib.util
import io
import pathlib
import stat
import sys
import tempfile
import threading
import types
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "platform_recovery_remote_agent_run362_tests",
    ROOT / "scripts" / "platform-recovery-remote-agent.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("remote agent module spec unavailable")
AGENT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AGENT
SPEC.loader.exec_module(AGENT)


def commitment(domain: str, value: bytes = b"fixture") -> str:
    return AGENT.bytes_commitment(domain, value)


def fake_stat(mode: int = 0o555, *, size: int = 4, uid: int = 0, gid: int = 0) -> types.SimpleNamespace:
    return types.SimpleNamespace(
        st_dev=1,
        st_ino=2,
        st_size=size,
        st_mode=stat.S_IFREG | mode,
        st_uid=uid,
        st_gid=gid,
    )


class RemoteAgentContractTests(unittest.TestCase):
    def test_fixed_loader_package_and_bundle_kats(self) -> None:
        compressed, source = AGENT._load_fixed_locator_artifacts()
        self.assertEqual(len(AGENT.CANONICAL_LOCATOR_PACKAGE_B64), AGENT.CANONICAL_LOCATOR_ENCODED_BYTES)
        self.assertEqual(len(compressed), AGENT.CANONICAL_LOCATOR_COMPRESSED_BYTES)
        self.assertEqual(len(source), AGENT.CANONICAL_LOCATOR_SOURCE_BYTES)
        self.assertEqual(hashlib.sha256(compressed).hexdigest(), AGENT.CANONICAL_LOCATOR_COMPRESSED_SHA256)
        self.assertEqual(hashlib.sha256(AGENT.CANONICAL_LOCATOR_PACKAGE_B64.encode("ascii")).hexdigest(), AGENT.CANONICAL_LOCATOR_ENCODED_SHA256)
        self.assertEqual(AGENT.build_fixed_loader_source(), AGENT.FIXED_LOADER_SOURCE)
        self.assertEqual(AGENT.FIXED_LOADER_COMMITMENT, "sha256:v1:1cf141c063a4343ee4e2015e4561415ab1c1e3d645286d76593b0ba01b2e1990")
        self.assertEqual(hashlib.sha256(AGENT.BUNDLE_KAT_BYTES).hexdigest(), AGENT.BUNDLE_KAT_RAW_SHA256)
        self.assertEqual(AGENT.compute_bundle_commitment(AGENT.BUNDLE_KAT_LAUNCHER_COMMITMENT, AGENT.BUNDLE_KAT_AGENT_COMMITMENT), AGENT.BUNDLE_KAT_COMMITMENT)
        module = AGENT.compile_restricted_locator()
        self.assertEqual(module.__name__, "__canonical_locator_payload__")
        self.assertTrue(AGENT._canonical_locator_shell_wrapper().endswith("\n"))

    def test_swzfrm02_canonical_json_and_session_bounds(self) -> None:
        nonce = bytes(range(32))
        payload = {
            "type": "BOOT",
            "version": 2,
            "schema": AGENT.SCHEMA_WIRE,
            "n_local": nonce.hex(),
            "epoch_ref": "epoch-fixture",
            "authority_ref": "authority-fixture",
            "barrier_utc": "2026-09-06T00:00:00.000000Z",
            "epoch_commitment": commitment("epoch"),
            "authority_commitment": commitment("authority"),
            "barrier_commitment": commitment("barrier"),
            "runner_commitment": commitment("runner"),
            "bundle_commitment": commitment("bundle"),
            "launcher_commitment": commitment("launcher"),
            "agent_commitment": commitment("agent"),
            "ssh_endpoint_commitment": commitment("endpoint"),
        }
        frame = AGENT.encode_frame(AGENT.DIRECTION_LOCAL_TO_REMOTE, AGENT.MESSAGE_BOOT, 0, nonce, payload)
        decoded = AGENT.decode_frame(frame)
        self.assertEqual(decoded.payload, payload)
        with self.assertRaises(AGENT.ProtocolError):
            AGENT.parse_wire_json(b'{"a":1,"a":2}')
        with self.assertRaises(AGENT.ProtocolError):
            AGENT.parse_wire_json(b'{"a":1.0}')
        with self.assertRaises(AGENT.ProtocolError):
            AGENT.parse_wire_json(b'{"a":1} trailing')
        machine = AGENT.SessionMachine(local_role=True, n_local=nonce)
        machine.accept(decoded)
        with self.assertRaises(AGENT.ProtocolError):
            machine.accept(decoded)

    def test_descriptor_attestation_and_execveat_are_bound(self) -> None:
        stats = [fake_stat(size=4), fake_stat(size=4)]
        reads = iter((b"abcd", b""))
        attested = AGENT.attest_agent_descriptor(
            7,
            fstat_fn=lambda _fd: stats.pop(0),
            read_fn=lambda _fd, _size: next(reads),
            lseek_fn=lambda *_args: 0,
        )
        self.assertEqual(attested.bytes, b"abcd")
        self.assertEqual(attested.commitment, commitment("recovery-agent-bytes", b"abcd"))
        with self.assertRaises(AGENT.DescriptorAdmissionError):
            AGENT.attest_agent_descriptor(
                7,
                fstat_fn=lambda _fd: fake_stat(mode=0o755),
                read_fn=lambda *_args: b"",
                lseek_fn=lambda *_args: 0,
            )
        self.assertEqual(AGENT.build_execveat_plan(), (3, "", ("/dev/fd/3", "--agent-v1", "--protocol-v2"), {"SWZ_RECOVERY_AGENT_FD": "3"}, 0x1000))
        with self.assertRaises(AGENT.DescriptorAdmissionError):
            AGENT.execveat(3, "", ("/dev/fd/3", "--agent-v1", "--protocol-v2"), {"SWZ_RECOVERY_AGENT_FD": "substituted"}, 0x1000)

    def test_substituted_agent_is_rejected_before_fork_or_exec(self) -> None:
        if sys.platform != "linux":
            self.skipTest("descriptor launch is Linux-only")
        stats = iter((fake_stat(size=4), fake_stat(size=5)))
        reads = iter((b"abcd", b""))
        calls: list[str] = []

        def fork() -> int:
            calls.append("fork")
            raise AssertionError("fork reached before descriptor qualification")

        with self.assertRaisesRegex(AGENT.DescriptorAdmissionError, "AGENT_SUBSTITUTED"):
            AGENT.spawn_descriptor_agent(
                expected_agent_commitment=commitment("recovery-agent-bytes", b"abcd"),
                open_directory_fn=lambda: (10, None),
                open_agent_fn=lambda _directory_fd: (calls.append("open-agent") or 7),
                fstat_fn=lambda _fd: next(stats),
                read_fn=lambda _fd, _size: next(reads),
                lseek_fn=lambda *_args: 0,
                fork_fn=fork,
            )
        self.assertEqual(calls, ["open-agent"])

    def test_artifact_uses_the_same_qualified_descriptor(self) -> None:
        try:
            temporary = tempfile.TemporaryDirectory(prefix="run362-artifact-")
        except FileNotFoundError:
            self.skipTest("runner has no writable temporary directory")
            return
        with temporary as directory:
            path = pathlib.Path(directory) / "artifact"
            path.write_bytes(b"artifact-bytes")
            fd = path.open("rb")
            try:
                admitted_stat = fake_stat(mode=0o444, size=len(b"artifact-bytes"))
                qualified = AGENT.qualify_artifact_descriptor(fd.fileno(), no_follow_verified=True, fstat_fn=lambda _fd: admitted_stat)
                sink = io.BytesIO()
                self.assertEqual(AGENT.stream_qualified_artifact(qualified, sink, fstat_fn=lambda _fd: admitted_stat), len(b"artifact-bytes"))
                self.assertEqual(sink.getvalue(), b"artifact-bytes")
                evidence = AGENT.build_artifact_stream_evidence(qualified, commitment("artifact"))
                self.assertEqual(AGENT.validate_artifact_stream_evidence(evidence), evidence)
                drift = types.SimpleNamespace(**fake_stat(size=99).__dict__)
                with self.assertRaises(AGENT.DescriptorAdmissionError):
                    AGENT.stream_qualified_artifact(qualified, io.BytesIO(), fstat_fn=lambda _fd: drift)
            finally:
                fd.close()

    def test_test_only_backend_cannot_make_operational_success(self) -> None:
        discovery = AGENT.DockerDiscovery(commitment("image"), commitment("target"), commitment("isolation"), 23, "artifact-023")
        backend = AGENT.TestOnlyDockerBackend(discovery=discovery)
        with self.assertRaises(AGENT.DockerAdmissionError):
            backend.operation("2026-09-06T00:00:00.000000Z")
        with self.assertRaises(AGENT.DockerAdmissionError):
            backend.restore({}, terminal_input_eof=True, terminal_input_trailing_bytes=0)

    def test_process_finality_reaps_only_after_pidfd_and_kills_once(self) -> None:
        identity = (1, 2, 4, stat.S_IFREG | 0o555, 0, 0)
        agent = AGENT.AttestedAgent(7, b"abcd", identity, identity, commitment("recovery-agent-bytes", b"abcd"))
        plan = AGENT.build_launch_plan(10, agent, error_read_fd=11, error_write_fd=12, pid=42, pidfd=13)

        class Poller:
            def __init__(self, batches: list[list[tuple[int, int]]]) -> None:
                self.batches = iter(batches)

            def register(self, _fd: int, _mask: int) -> None:
                return None

            def poll(self, _timeout: int) -> list[tuple[int, int]]:
                return next(self.batches)

        order: list[str] = []
        closed: list[int] = []
        result = AGENT.supervise_descriptor_agent(
            plan,
            poll_factory=lambda: Poller([[(11, 1)], [(13, 1)]]),
            read_fn=lambda _fd, _size: (order.append("error-read") or b""),
            waitpid_fn=lambda pid, options: (order.append(f"waitpid:{pid}:{options}") or (42, 0)),
            close_fn=lambda fd: closed.append(fd),
            clock_fn=lambda: 0.0,
        )
        self.assertTrue(result.success)
        self.assertEqual(order, ["error-read", "waitpid:42:0"])
        self.assertEqual(closed, [11, 13])

        kill_calls: list[tuple[int, int]] = []
        waits: list[tuple[int, int]] = []
        clock_values = iter((0.0, 2.0))
        with self.assertRaisesRegex(AGENT.FinalityError, "AGENT_SUPERVISION_TIMEOUT"):
            AGENT.supervise_descriptor_agent(
                plan,
                timeout=1.0,
                poll_factory=lambda: Poller([[]]),
                waitpid_fn=lambda pid, options: (waits.append((pid, options)) or (42, 0)),
                close_fn=lambda _fd: None,
                clock_fn=lambda: next(clock_values),
                kill_fn=lambda pid, signal_number: kill_calls.append((pid, signal_number)),
            )
        self.assertEqual(kill_calls, [(42, getattr(AGENT.signal, "SIGKILL", 9))])
        self.assertEqual(waits, [])

    def test_waitpid_exception_is_not_retried(self) -> None:
        identity = (1, 2, 4, stat.S_IFREG | 0o555, 0, 0)
        plan = AGENT.build_launch_plan(10, AGENT.AttestedAgent(7, b"abcd", identity, identity, commitment("agent", b"abcd")), error_read_fd=11, error_write_fd=12, pid=42, pidfd=13)

        class Poller:
            def register(self, _fd: int, _mask: int) -> None:
                return None

            def poll(self, _timeout: int) -> list[tuple[int, int]]:
                return [(13, 1)]

        calls: list[tuple[int, int]] = []
        kill_calls: list[tuple[int, int]] = []
        with self.assertRaisesRegex(AGENT.FinalityError, "waitpid failure"):
            def waitpid(pid: int, options: int) -> tuple[int, int]:
                calls.append((pid, options))
                raise AGENT.FinalityError("waitpid failure", safety_state="UNCONSUMED")
            AGENT.supervise_descriptor_agent(plan, poll_factory=Poller, waitpid_fn=waitpid, close_fn=lambda _fd: None, clock_fn=lambda: 0.0, kill_fn=lambda pid, signal_number: kill_calls.append((pid, signal_number)))
        self.assertEqual(calls, [(42, 0)])
        self.assertEqual(kill_calls, [])


if __name__ == "__main__":
    unittest.main()
