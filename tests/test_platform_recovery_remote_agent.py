from __future__ import annotations

import dataclasses
import hashlib
import importlib.util
import io
import os
import pathlib
import queue
import socket
import stat
import struct
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_module(name: str, path: pathlib.Path) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("module spec unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


AGENT = load_module(
    "platform_recovery_remote_agent_run355_tests",
    ROOT / "scripts" / "platform-recovery-remote-agent.py",
)


def commitment(domain: str, value: bytes = b"fixture") -> str:
    return AGENT.bytes_commitment(domain, value)


def wire_commitment_fields() -> dict[str, str]:
    return {
        "epoch_commitment": commitment("epoch"),
        "authority_commitment": commitment("authority"),
        "barrier_commitment": commitment("barrier"),
        "runner_commitment": commitment("runner"),
        "bundle_commitment": commitment("bundle"),
        "launcher_commitment": commitment("launcher"),
        "agent_commitment": commitment("agent"),
    }


def boot_payload(n_local: bytes) -> dict[str, object]:
    return {
        "type": "BOOT",
        "version": 2,
        "schema": AGENT.SCHEMA_WIRE,
        "n_local": n_local.hex(),
        "epoch_ref": "epoch-fixture",
        "authority_ref": "authority-fixture",
        "barrier_utc": "2026-09-05T00:00:00.000000Z",
        **wire_commitment_fields(),
        "ssh_endpoint_commitment": commitment("ssh-endpoint"),
    }


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
    def test_provenance_loader_and_production_source_commitments(self) -> None:
        source = (ROOT / "scripts" / "platform-recovery-remote-agent.py").read_bytes()
        self.assertEqual(len(AGENT.CANONICAL_LOCATOR_SOURCE), 35994)
        self.assertEqual(hashlib.sha256(AGENT.CANONICAL_LOCATOR_SOURCE).hexdigest(), "17925f1364565edbb39fa0f776e25d6f0410d8408d9bdce214143edf1d6f34d5")
        self.assertEqual(len(AGENT.CANONICAL_LOCATOR_PACKAGE), 8398)
        self.assertEqual(hashlib.sha256(AGENT.CANONICAL_LOCATOR_PACKAGE).hexdigest(), "5913fd800e89eff823cef6c08753154e5447eb0ff04eca68dac1668999d002ee")
        self.assertEqual(len(AGENT.CANONICAL_LOCATOR_PACKAGE_B64), 11198)
        self.assertEqual(hashlib.sha256(AGENT.CANONICAL_LOCATOR_PACKAGE_B64.encode("ascii")).hexdigest(), "44fba3ed738e696e83e72d0a406cb1d8652c21aaa49f583debb4d907fae05321")
        self.assertEqual(len(AGENT._LOADER_TEMPLATE), 2637)
        self.assertEqual(hashlib.sha256(AGENT._LOADER_TEMPLATE).hexdigest(), "d98352210d982c28a9f1e8ba66d33b610d1e8ea531f8a4abb770173db095ee1e")
        self.assertEqual(len(AGENT.FIXED_LOADER_SOURCE), 13832)
        self.assertEqual(hashlib.sha256(AGENT.FIXED_LOADER_SOURCE).hexdigest(), "8a51925e559907cefde4a0944893a9886d4178a8e244a0b916e73708b9783915")
        self.assertEqual(AGENT.FIXED_LOADER_COMMITMENT, "sha256:v1:1cf141c063a4343ee4e2015e4561415ab1c1e3d645286d76593b0ba01b2e1990")
        commitments = AGENT.compute_production_commitments(source)
        self.assertEqual(commitments["launcher_commitment"], AGENT.bytes_commitment("recovery-launcher-bytes", source))
        self.assertEqual(commitments["agent_commitment"], AGENT.bytes_commitment("recovery-agent-bytes", source))
        self.assertEqual(AGENT.BUNDLE_KAT_BYTES, b"RUN352-BUNDLE-KAT\n")
        self.assertEqual(AGENT.BUNDLE_KAT_RAW_SHA256, hashlib.sha256(AGENT.BUNDLE_KAT_BYTES).hexdigest())
        self.assertEqual(AGENT.compute_bundle_commitment(AGENT.BUNDLE_KAT_LAUNCHER_COMMITMENT, AGENT.BUNDLE_KAT_AGENT_COMMITMENT), AGENT.BUNDLE_KAT_COMMITMENT)
        self.assertEqual(len(commitments["bundle_commitment"]), len("sha256:v1:" + "0" * 64))

    def test_restricted_locator_namespace_and_import_allowlist(self) -> None:
        module = AGENT.compile_restricted_locator()
        self.assertEqual(module.__name__, "__canonical_locator_payload__")
        self.assertEqual(module.__file__, AGENT.CANONICAL_LOCATOR_PATH)
        self.assertIsNone(module.__package__)
        self.assertTrue(callable(module.execute_operation))
        builtins_map = module.__dict__["__builtins__"]
        self.assertEqual(len(builtins_map), 28)
        for denied in ("open", "eval", "exec", "compile", "input", "globals", "locals", "vars", "dir"):
            self.assertNotIn(denied, builtins_map)
        with self.assertRaises(ImportError):
            module.__builtins__["__import__"]("os", {}, {}, (), 0)
        with self.assertRaises(ImportError):
            module.__builtins__["__import__"]("typing", {}, {}, ("Any", "BinaryIO", "Nope"), 0)

    def test_fixed_loader_marker_and_single_package_call_shape(self) -> None:
        self.assertEqual(AGENT.FIXED_LOADER_SOURCE.count(b"@P@"), 0)
        self.assertEqual(AGENT._LOADER_TEMPLATE.count(b"@P@"), 1)
        source = (ROOT / "scripts" / "platform-recovery-remote-agent.py").read_text(encoding="utf-8")
        self.assertEqual(source.count("module.execute_operation("), 1)
        self.assertNotRegex(source.lower(), r"(auth[_-]?frame|kdf|transcript|grant[_-]?mac|k_bridge_root|n_session)")
        with self.assertRaises(AGENT.LoaderIntegrityError):
            AGENT.invoke_canonical_locator_once(
                "2026-09-05T00:00:00.000000Z",
                process_factory=lambda: None,
            )

    def test_swzfrm02_vector_bounds_and_short_write(self) -> None:
        n_local = bytes(range(32))
        payload = boot_payload(n_local)
        frame = AGENT.encode_frame(
            AGENT.DIRECTION_LOCAL_TO_REMOTE,
            AGENT.MESSAGE_BOOT,
            0,
            n_local,
            payload,
        )
        self.assertEqual(len(frame[:56]), 56)
        decoded = AGENT.decode_frame(frame)
        self.assertEqual(decoded.n_local, n_local)
        self.assertEqual(decoded.payload, payload)
        self.assertEqual(AGENT.SWZFRM02_HEADER.size, 56)
        for bad in (
            frame[:1],
            b"NOPE" + frame[4:],
            frame[:-1],
            frame + b"x",
        ):
            with self.assertRaises(AGENT.ProtocolError):
                AGENT.decode_frame(bad)
        class ShortWriter:
            def __init__(self) -> None:
                self.data = bytearray()
            def write(self, value: bytes) -> int:
                self.data.extend(value[:2])
                return min(2, len(value))
            def flush(self) -> None:
                return None
        writer = ShortWriter()
        AGENT.write_frame(writer, frame)
        self.assertEqual(bytes(writer.data), frame)
        class ZeroWriter:
            def write(self, _value: bytes) -> int:
                return 0
            def flush(self) -> None:
                return None
        with self.assertRaises(AGENT.ProtocolError):
            AGENT.write_frame(ZeroWriter(), frame)

    def test_canonical_json_rejects_noncanonical_duplicate_float_and_trailing(self) -> None:
        with self.assertRaises(AGENT.ProtocolError):
            AGENT.parse_wire_json(b'{"a":1,"a":2}')
        with self.assertRaises(AGENT.ProtocolError):
            AGENT.parse_wire_json(b'{"a":1.0}')
        with self.assertRaises(AGENT.ProtocolError):
            AGENT.parse_wire_json(b' {"a":1}')
        canonical = AGENT.canonical_json({"a": 1})
        self.assertEqual(canonical, b'{"a":1}')
        self.assertEqual(AGENT.parse_wire_json(canonical), {"a": 1})

    def test_session_direction_sequence_terminal_and_limits(self) -> None:
        n_local = bytes(range(32))
        boot = AGENT.decode_frame(AGENT.encode_frame(1, 1, 0, n_local, boot_payload(n_local)))
        session = AGENT.SessionMachine(local_role=False, n_local=n_local)
        session.accept(boot)
        self.assertEqual(session.state, "BOOT")
        with self.assertRaises(AGENT.ProtocolError):
            session.accept(boot)
        wrong = dataclasses.replace(boot, sequence=1)
        with self.assertRaises(AGENT.ProtocolError):
            AGENT.SessionMachine(local_role=False, n_local=n_local).accept(wrong)
        session.mark_terminal()
        with self.assertRaises(AGENT.ProtocolError):
            session.accept(boot)

    def test_runtime_dispatch_and_exact_descriptor_agent_contract(self) -> None:
        flags = types.SimpleNamespace(isolated=1, ignore_environment=1, no_user_site=1, safe_path=True)
        AGENT.assert_isolated_runtime(flags)
        with self.assertRaises(AGENT.RecoveryError):
            AGENT.assert_isolated_runtime(types.SimpleNamespace(isolated=0, ignore_environment=1, no_user_site=1, safe_path=True))
        self.assertEqual(
            AGENT.classify_dispatch(["/opt/x", "--protocol-v2"], {"SSH_ORIGINAL_COMMAND": ""}, fd3_present=False),
            "supervisor",
        )
        self.assertEqual(
            AGENT.validate_agent_entry(
                ["/dev/fd/3", "--agent-v1", "--protocol-v2"],
                {"SSH_ORIGINAL_COMMAND": "", "SWZ_RECOVERY_AGENT_FD": "3"},
            ).mode,
            "agent",
        )
        for argv, env, fd3 in (
            (["/opt/x", "--protocol-v2", "extra"], {"SSH_ORIGINAL_COMMAND": ""}, False),
            (["/opt/x", "--protocol-v2"], {"SSH_ORIGINAL_COMMAND": "id"}, False),
            (["/dev/fd/3", "--agent-v1", "--protocol-v2"], {"SWZ_RECOVERY_AGENT_FD": "3"}, False),
        ):
            with self.assertRaises(AGENT.DescriptorAdmissionError):
                AGENT.classify_dispatch(argv, env, fd3_present=fd3)
        plan = AGENT.build_execveat_plan()
        self.assertEqual(plan, (3, "", ("/dev/fd/3", "--agent-v1", "--protocol-v2"), {"SWZ_RECOVERY_AGENT_FD": "3"}, 0x1000))

    def test_openat2_root_anchor_and_agent_same_descriptor_attestation(self) -> None:
        calls: list[tuple[object, ...]] = []
        def open_root(path: str, flags: int) -> int:
            calls.append((path, flags))
            return 90
        def openat2_fn(fd: int, path: str, flags: int, resolve: int) -> int:
            calls.append((fd, path, flags, resolve))
            return 91
        metadata = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)
        opened, _ = AGENT.open_recovery_directory(
            open_root_fn=open_root,
            openat2_fn=openat2_fn,
            fstat_fn=lambda fd: metadata,
            close_fn=lambda _fd: None,
        )
        self.assertEqual(opened, 91)
        self.assertEqual(calls[0][0], "/")
        self.assertEqual(calls[1][1], "opt/swooshz/recovery")
        self.assertEqual(calls[1][3], AGENT.RECOVERY_RESOLVE_FLAGS)
        stats = [fake_stat(size=4), fake_stat(size=4)]
        reads = iter([b"abcd", b""])
        attested = AGENT.attest_agent_descriptor(
            7,
            fstat_fn=lambda _fd: stats.pop(0),
            read_fn=lambda _fd, _size: next(reads),
            lseek_fn=lambda *_args: 0,
        )
        self.assertEqual(attested.bytes, b"abcd")
        self.assertEqual(attested.commitment, commitment("recovery-agent-bytes", b"abcd"))
        stats = [fake_stat(size=4), fake_stat(size=5)]
        reads = iter([b"abcd", b""])
        with self.assertRaises(AGENT.DescriptorAdmissionError):
            AGENT.attest_agent_descriptor(7, fstat_fn=lambda _fd: stats.pop(0), read_fn=lambda *_args: next(reads), lseek_fn=lambda *_args: 0)
        with self.assertRaises(AGENT.DescriptorAdmissionError):
            AGENT.attest_agent_descriptor(7, fstat_fn=lambda _fd: fake_stat(mode=0o755), read_fn=lambda *_args: b"", lseek_fn=lambda *_args: 0)

    def test_fd_normalisation_exec_error_and_pidfd_ownership_shape(self) -> None:
        operations: list[tuple[object, ...]] = []
        AGENT.normalize_child_fds(
            7,
            8,
            dup2_fn=lambda *args, **kwargs: operations.append(("dup2", args, kwargs)),
            set_inheritable_fn=lambda *args: operations.append(("inherit", args)),
            close_fn=lambda fd: operations.append(("close", fd)),
        )
        self.assertIn(("dup2", (7, 3), {"inheritable": True}), operations)
        self.assertIn(("dup2", (8, 4), {"inheritable": False}), operations)
        self.assertIn(("inherit", (3, True)), operations)
        self.assertIn(("inherit", (4, False)), operations)
        writes: list[bytes] = []
        def write_fn(_fd: int, payload: bytes) -> int:
            writes.append(payload)
            return len(payload)
        AGENT.write_exec_error(4, 126, write_fn=write_fn)
        self.assertEqual(b"".join(writes), b"\x00\x00\x00~")
        self.assertEqual(AGENT.build_launch_plan(10, AGENT.AttestedAgent(7, b"x", (1, 2, 1, 0, 0, 0), (1, 2, 1, 0, 0, 0), commitment("recovery-agent-bytes", b"x")), error_read_fd=11, error_write_fd=12).execveat_argv, ("/dev/fd/3", "--agent-v1", "--protocol-v2"))

    def test_capture_finality_artifact_continuity_and_no_fake_backend_success(self) -> None:
        capture = AGENT.BoundedCapture(4)
        capture.append(b"abcd")
        with self.assertRaises(AGENT.FinalityError):
            capture.append(b"x")
        finality = AGENT.ProcessFinality(
            None, True, 0, True, True, True, 0, commitment("stdout"), commitment("stderr")
        )
        self.assertTrue(AGENT.validate_process_finality(finality).success)
        with tempfile.TemporaryDirectory(prefix="run355-artifact-") as temp:
            path = pathlib.Path(temp) / "artifact"
            path.write_bytes(b"artifact-bytes")
            fd = os.open(path, os.O_RDONLY)
            try:
                unqualified = AGENT.qualify_artifact_descriptor(fd)
                with self.assertRaises(AGENT.DescriptorAdmissionError):
                    AGENT.stream_qualified_artifact(unqualified, io.BytesIO())
                qualified = AGENT.qualify_artifact_descriptor(fd, no_follow_verified=True)
                self.assertEqual(qualified.reopen_count, 0)
                self.assertTrue(qualified.stdin_same_descriptor)
                output = io.BytesIO()
                self.assertEqual(AGENT.stream_qualified_artifact(qualified, output), len(b"artifact-bytes"))
                self.assertEqual(output.getvalue(), b"artifact-bytes")
                evidence = AGENT.build_artifact_stream_evidence(qualified, commitment("artifact"))
                self.assertEqual(AGENT.validate_artifact_stream_evidence(evidence), evidence)
                self.assertTrue(AGENT.artifact_stream_evidence_commitment(evidence).startswith("sha256:v1:"))
            finally:
                os.close(fd)
        fixture = AGENT.DockerDiscovery(commitment("image"), commitment("target"), commitment("isolation"), 1, "backup.tar")
        with self.assertRaises(AGENT.DockerAdmissionError):
            AGENT.TestOnlyDockerBackend(discovery=fixture).operation("2026-09-05T00:00:00.000000Z")


    def test_typed_installed_metadata_readers_and_provenance_are_fail_closed(self) -> None:
        image_id = "sha256:" + ("d" * 64)
        with mock.patch.object(AGENT, "_read_admitted_image_id", return_value=image_id):
            config = AGENT.DockerInstallationConfig.from_installed("epoch-fixture")
        self.assertEqual(config.image_id, image_id)
        with mock.patch.object(AGENT, "_read_admitted_line", return_value=commitment("image")):
            with self.assertRaisesRegex(AGENT.DescriptorAdmissionError, "DOCKER_IMAGE_ID_FORMAT_INVALID"):
                AGENT._read_admitted_image_id("fixture")
        with mock.patch.object(AGENT, "_read_admitted_line", return_value=image_id):
            with self.assertRaisesRegex(AGENT.DescriptorAdmissionError, "AGENT_COMMITMENT_FORMAT_INVALID"):
                AGENT._read_admitted_recovery_commitment("fixture", label="agent_commitment")
        config = AGENT.DockerInstallationConfig(
            "/var/run/docker.sock", "postgres:17-alpine", image_id,
            "run-fixture", "volume-fixture", "target-fixture",
        )
        with self.assertRaisesRegex(AGENT.DockerAdmissionError, "DOCKER_PROVENANCE_INVALID"):
            AGENT.ProductionDockerBackend(config, client=object(), provenance="operational")

    def test_engine_short_reads_and_bounded_backpressure(self) -> None:
        events: queue.Queue[bytes | None] = queue.Queue(maxsize=1)
        events.put(b"short")
        output = AGENT._EngineOutput(events)
        self.assertEqual(output.read(4096), b"short")
        finished: queue.Queue[bytes | None] = queue.Queue(maxsize=1)
        done = threading.Event()
        done.set()
        self.assertEqual(AGENT._EngineOutput(finished, done_event=done).read(4096), b"")
        full: queue.Queue[bytes | None] = queue.Queue(maxsize=1)
        full.put(b"occupied")
        with mock.patch.object(AGENT, "ENGINE_QUEUE_TIMEOUT_SECONDS", 0.001), \
                mock.patch.object(AGENT, "ENGINE_IO_DEADLINE_SECONDS", 0.002):
            with self.assertRaisesRegex(AGENT.DockerAdmissionError, "DOCKER_STREAM_BACKPRESSURE"):
                AGENT._put_engine_event(full, b"blocked")

    def test_restore_supervision_kills_and_reaps_once_on_finality_failure(self) -> None:
        image_id = "sha256:" + ("e" * 64)
        config = AGENT.DockerInstallationConfig(
            "/var/run/docker.sock", "postgres:17-alpine", image_id,
            "run-fixture", "volume-fixture", "target-fixture",
        )
        backend = AGENT.ProductionDockerBackend(config, client=object())

        class StuckProcess:
            def __init__(self) -> None:
                self.stdin = io.BytesIO()
                self.stdout = io.BytesIO()
                self.stderr = io.BytesIO()
                self._reader_error = None
                self._stream_eof = True
                self._reader_done = threading.Event()
                self._reader_done.set()
                self.wait_calls = 0
                self.kill_calls = 0

            def wait(self, timeout: float | None = None) -> int:
                self.wait_calls += 1
                if self.wait_calls == 1:
                    raise TimeoutError("fixture timeout")
                return 0

            def kill(self) -> None:
                self.kill_calls += 1

        process = StuckProcess()
        with mock.patch.object(AGENT, "ENGINE_IO_DEADLINE_SECONDS", 0.02):
            with self.assertRaisesRegex(AGENT.FinalityError, "DOCKER_PROCESS_FINALITY_FAILED"):
                backend._supervise_restore_process(process)
        self.assertEqual(process.kill_calls, 1)
        self.assertEqual(process.wait_calls, 2)

    def test_ambiguous_locator_preserves_sticky_cleanup_boundary(self) -> None:
        image_id = "sha256:" + ("f" * 64)
        config = AGENT.DockerInstallationConfig(
            "/var/run/docker.sock", "postgres:17-alpine", image_id,
            "run-fixture", "volume-fixture", "target-fixture",
        )
        backend = AGENT.ProductionDockerBackend(config, client=object())
        backend._admit_metadata_source = mock.Mock(return_value={
            "source_id": "metadata-source-fixture",
            "source_name": "coolify-db",
            "readback_count": 1,
        })
        backend.inspect_image = mock.Mock(return_value={"schema": AGENT.SCHEMA_IMAGE_EVIDENCE})
        backend.create_isolated_target = mock.Mock(return_value=({"target": True}, {"isolation": True}))
        backend.cleanup = mock.Mock()
        with mock.patch.object(
            AGENT,
            "invoke_canonical_locator_once",
            return_value=types.SimpleNamespace(classification="AMBIGUOUS", query_started=True),
        ):
            with self.assertRaisesRegex(AGENT.DockerAdmissionError, "LOCATOR_FINALITY_UNCERTAIN"):
                backend.discover("run-fixture", "2026-09-05T00:00:00.000000Z")
        backend.cleanup.assert_not_called()

    def test_terminal_input_and_failure_finality_require_observed_eof(self) -> None:
        self.assertEqual(AGENT.observe_terminal_input(io.BytesIO(b""), timeout=0.1), (True, 0))
        self.assertEqual(AGENT.observe_terminal_input(io.BytesIO(b"trailing"), timeout=0.1), (True, 8))
        value: dict[str, object] = {}
        for field in AGENT.RESULT_EVIDENCE_FIELDS:
            if field == "schema":
                value[field] = AGENT.SCHEMA_RESULT
            elif field == "classification":
                value[field] = "FAILURE"
            elif field == "stage":
                value[field] = "PROCESS"
            elif field == "result_code":
                value[field] = "RESTORE_PROCESS_FAILED"
            elif field == "restore_count":
                value[field] = 0
            elif field == "exit_status":
                value[field] = 1
            elif field in {"stdin_eof", "stdout_eof", "stderr_eof", "terminal_input_eof"}:
                value[field] = True
            elif field in {"trailing_unframed_bytes", "terminal_input_trailing_bytes"}:
                value[field] = 0
            elif field == "cleanup_state":
                value[field] = "COMPLETE"
            elif field.endswith("_commitment") or field.endswith("_digest"):
                value[field] = commitment(field)
            else:
                value[field] = "fixture"
        self.assertEqual(AGENT.validate_result_evidence(value)["classification"], "FAILURE")
        incomplete = dict(value)
        incomplete["stdout_eof"] = False
        with self.assertRaisesRegex(AGENT.ProtocolError, "RESULT_EVIDENCE_INVALID"):
            AGENT.validate_result_evidence(incomplete)
        incomplete = dict(value)
        incomplete["terminal_input_trailing_bytes"] = 1
        with self.assertRaisesRegex(AGENT.ProtocolError, "RESULT_EVIDENCE_INVALID"):
            AGENT.validate_result_evidence(incomplete)



    def test_docker_socket_only_image_target_isolation_and_no_fake_success(self) -> None:
        image_id = "sha256:" + ("a" * 64)
        class FakeClient:
            def __init__(self) -> None:
                self.calls: list[tuple[str, str, object]] = []
            def request(self, method: str, path: str, body: object = None) -> tuple[int, dict[str, object]]:
                self.calls.append((method, path, body))
                if method == "GET" and path.startswith("/images/"):
                    return 200, {"Id": image_id, "Os": "linux", "Architecture": "amd64"}
                if method == "GET" and path == "/volumes/swooshz-recovery-volume-volume-fixture":
                    if any(call[0] == "POST" and call[1] == "/volumes/create" for call in self.calls):
                        return 200, {"Name": "swooshz-recovery-volume-volume-fixture", "Labels": {"com.swooshz.recovery.run": "run-fixture"}}
                    return 404, {}
                if method == "GET" and path == "/containers/swooshz-recovery-target-target-fixture/json":
                    return 404, {}
                if method == "GET" and path == "/containers/container-fixture/json":
                    return 200, {
                        "Id": "container-fixture",
                        "Name": "/swooshz-recovery-target-target-fixture",
                        "State": {"Running": True},
                        "Config": {
                            "Image": image_id,
                            "Env": ["POSTGRES_DB=coolify"],
                            "Labels": {"com.swooshz.recovery.run": "run-fixture"},
                        },
                        "HostConfig": {
                            "NetworkMode": "none",
                            "Privileged": False,
                            "ReadonlyRootfs": True,
                            "CapDrop": ["ALL"],
                            "CapAdd": [],
                            "PublishAllPorts": False,
                            "PortBindings": {},
                            "ExtraHosts": [],
                            "SecurityOpt": [],
                            "Binds": ["swooshz-recovery-volume-volume-fixture:/var/lib/postgresql/data:rw"],
                        },
                        "Mounts": [{
                            "Destination": "/var/lib/postgresql/data",
                            "RW": True,
                            "Name": "swooshz-recovery-volume-volume-fixture",
                            "Type": "volume",
                        }],
                        "NetworkSettings": {"Networks": {}},
                    }
                if path == "/volumes/create":
                    return 201, {"Name": "swooshz-recovery-volume-volume-fixture"}
                if path.startswith("/containers/create"):
                    return 201, {"Id": "container-fixture"}
                if path == "/containers/container-fixture/start":
                    return 204, {}
                raise AssertionError((method, path))
        client = FakeClient()
        config = AGENT.DockerInstallationConfig(
            "/var/run/docker.sock",
            "postgres:17-alpine",
            image_id,
            "run-fixture",
            "volume-fixture",
            "target-fixture",
        )
        backend = AGENT.ProductionDockerBackend(config, client=client)
        backend._metadata_source = {
            "source_id": "metadata-source-fixture",
            "source_name": "coolify-db",
            "readback_count": 1,
        }
        image = backend.inspect_image()
        target, isolation = backend.create_isolated_target(image)
        self.assertEqual(image["inspect_count"], 1)
        self.assertEqual(image["pull_count"], 0)
        self.assertEqual(image["tag_resolution_count"], 0)
        self.assertTrue(target["run_owned"])
        self.assertFalse(target["preexisting_target"])
        self.assertFalse(target["preexisting_volume"])
        self.assertEqual(isolation["network_mode"], "none")
        self.assertTrue(isolation["rootfs_read_only"])
        self.assertEqual(isolation["cap_drop"], ["ALL"])
        self.assertEqual(backend.pull_count, 0)
        self.assertEqual(backend.tag_resolution_count, 0)
        self.assertIn(("POST", "/containers/container-fixture/start", None), client.calls)
        with self.assertRaises(AGENT.DockerAdmissionError):
            backend.open_locator_process()
        with self.assertRaises(AGENT.DockerAdmissionError):
            AGENT.TestOnlyDockerBackend(
                discovery=AGENT.DockerDiscovery(
                    commitment("image"), commitment("target"), commitment("isolation"), 1, "backup.tar"
                )
            ).operation("2026-09-05T00:00:00.000000Z")

    def test_production_locator_binding_is_fail_closed_and_protocol_has_no_application_mac(self) -> None:
        with self.assertRaises(AGENT.DockerAdmissionError):
            AGENT.fixed_process_factory()
        source = (ROOT / "scripts" / "platform-recovery-remote-agent.py").read_text(encoding="utf-8")
        self.assertNotRegex(source.lower(), r"(auth[_-]?frame|kdf|transcript|grant[_-]?mac|k_bridge_root|k_boot|k_session|k_proceed|n_session)")
        self.assertEqual(source.count("module.execute_operation("), 1)
        self.assertIn('ctypes.c_int(0x1000)', source)
        self.assertIn('("/dev/fd/3", "--agent-v1", "--protocol-v2")', source)

    def test_engine_multiplexing_requires_clean_eof_and_zero_reserved_stream_bytes(self) -> None:
        class Client:
            def request(self, method: str, path: str, body: object = None) -> tuple[int, dict[str, object]]:
                self.last = (method, path, body)
                return 200, {"Running": False, "ExitCode": 0}

        def frame(stream_id: int, payload: bytes) -> bytes:
            return bytes((stream_id, 0, 0, 0)) + struct.pack(">I", len(payload)) + payload

        left, right = socket.socketpair()
        try:
            right.sendall(frame(1, b"out") + frame(2, b"err"))
            right.shutdown(socket.SHUT_WR)
            process = AGENT._DockerEngineProcess(Client(), "exec-fixture", left)
            process.stdin.close()
            self.assertEqual(process.wait(timeout=1.0), 0)
            self.assertEqual(process.stdout.read(), b"out")
            self.assertEqual(process.stderr.read(), b"err")
            self.assertTrue(process._stream_eof)
            self.assertIsNone(process._reader_error)
            process.close()
        finally:
            right.close()

        for malformed in (
            bytes((1, 1, 0, 0)) + struct.pack(">I", 0),
            bytes((3, 0, 0, 0)) + struct.pack(">I", 0),
            b"\x01\x00",
        ):
            malformed_left, malformed_right = socket.socketpair()
            try:
                malformed_right.sendall(malformed)
                malformed_right.shutdown(socket.SHUT_WR)
                process = AGENT._DockerEngineProcess(Client(), "exec-fixture", malformed_left)
                self.assertTrue(process._reader_done.wait(timeout=1.0))
                self.assertIsNotNone(process._reader_error)
                self.assertIn(
                    getattr(process._reader_error, "code", ""),
                    {"DOCKER_STREAM_HEADER_INVALID", "DOCKER_STREAM_ID_INVALID", "DOCKER_STREAM_TRUNCATED"},
                )
                process.close()
            finally:
                malformed_right.close()

    def test_descriptor_supervision_requires_pidfd_and_exact_exec_pipe_eof(self) -> None:
        identity = (1, 2, 1, 0, 0, 0)
        agent = AGENT.AttestedAgent(7, b"x", identity, identity, commitment("recovery-agent-bytes", b"x"))
        plan = AGENT.build_launch_plan(10, agent, error_read_fd=11, error_write_fd=12, pid=42, pidfd=13)

        class Poller:
            def __init__(self, batches: list[list[tuple[int, int]]]) -> None:
                self.batches = iter(batches)
                self.registered: list[tuple[int, int]] = []
            def register(self, fd: int, event: int) -> None:
                self.registered.append((fd, event))
            def poll(self, _timeout: int) -> list[tuple[int, int]]:
                return next(self.batches)

        closed: list[int] = []
        success = AGENT.supervise_descriptor_agent(
            plan,
            poll_factory=lambda: Poller([[(11, 1), (13, 1)]]),
            read_fn=lambda _fd, _size: b"",
            waitpid_fn=lambda _pid, _options: (42, 0),
            close_fn=lambda fd: closed.append(fd),
            clock_fn=lambda: 0.0,
        )
        self.assertTrue(success.success)
        self.assertTrue(success.pidfd_observed)
        self.assertEqual(closed, [11, 13])

        error_bytes = iter((b"\x00\x00\x00~", b""))
        failure = AGENT.supervise_descriptor_agent(
            plan,
            poll_factory=lambda: Poller([[(11, 1)], [(11, 1)], [(13, 1)]]),
            read_fn=lambda _fd, _size: next(error_bytes),
            waitpid_fn=lambda _pid, _options: (42, 0),
            close_fn=lambda _fd: None,
            clock_fn=lambda: 0.0,
        )
        self.assertFalse(failure.success)
        self.assertEqual(failure.exec_error, 126)

        with self.assertRaisesRegex(AGENT.FinalityError, "EXEC_ERROR_PIPE_INVALID"):
            AGENT.supervise_descriptor_agent(
                plan,
                poll_factory=lambda: Poller([[(11, 1)]]),
                read_fn=lambda _fd, _size: b"\x00\x00\x00~\x01",
                waitpid_fn=lambda _pid, _options: (42, 0),
                close_fn=lambda _fd: None,
                clock_fn=lambda: 0.0,
            )

    def test_production_exec_commands_are_engine_bound_and_exact(self) -> None:
        image_id = "sha256:" + ("b" * 64)
        config = AGENT.DockerInstallationConfig(
            "/var/run/docker.sock",
            "postgres:17-alpine",
            image_id,
            "run-fixture",
            "volume-fixture",
            "target-fixture",
        )
        client = AGENT.UnixSocketHTTPClient()
        calls: list[tuple[str, str, object]] = []
        next_exec = iter(("locator-exec", "restore-exec"))

        def request(method: str, path: str, body: object = None) -> tuple[int, dict[str, object]]:
            calls.append((method, path, body))
            return 201, {"Id": next(next_exec)}

        client.request = request  # type: ignore[method-assign]
        backend = AGENT.ProductionDockerBackend(config, client=client)
        backend._resources = AGENT._OwnedDockerResources(
            "container-fixture",
            "swooshz-recovery-target-target-fixture",
            "swooshz-recovery-volume-volume-fixture",
            "run-fixture",
        )
        backend._metadata_source = {
            "source_id": "metadata-source-fixture",
            "source_name": "coolify-db",
            "readback_count": 1,
        }
        peers: list[socket.socket] = []

        def socket_for_exec(*_args: object, **_kwargs: object) -> socket.socket:
            local, peer = socket.socketpair()
            peer.shutdown(socket.SHUT_WR)
            peers.append(peer)
            return local

        try:
            with mock.patch.object(AGENT, "_open_hijacked_socket", side_effect=socket_for_exec):
                locator = backend.open_locator_process()
                restore = backend._open_restore_process()
            self.assertEqual(calls[0][0:2], ("POST", "/containers/metadata-source-fixture/exec"))
            self.assertEqual(calls[0][2]["Cmd"], ["/bin/sh", "-c", AGENT._canonical_locator_shell_wrapper()])
            self.assertEqual(calls[0][2]["Env"], list(AGENT.DOCKER_EXEC_ENVIRONMENT))
            self.assertEqual(calls[1][2]["Cmd"], list(AGENT.RESTORE_COMMAND))
            self.assertEqual(calls[1][2]["Env"], list(AGENT.DOCKER_EXEC_ENVIRONMENT))
            for body in (calls[0][2], calls[1][2]):
                self.assertEqual(
                    {key: body[key] for key in ("AttachStdin", "AttachStdout", "AttachStderr", "Tty")},
                    {"AttachStdin": True, "AttachStdout": True, "AttachStderr": True, "Tty": False},
                )
            locator.close()
            restore.close()
        finally:
            for peer in peers:
                peer.close()

    def test_docker_commitment_vectors_use_one_terminal_cj_lf(self) -> None:
        def lp(*parts: str) -> bytes:
            return b"".join(
                len(part.encode("utf-8")).to_bytes(4, "big") + part.encode("utf-8")
                for part in parts
            )

        def independent(domain: str, payload: bytes) -> str:
            preimage = lp("recovery-commitment.v1", domain) + len(payload).to_bytes(4, "big") + payload
            return "sha256:v1:" + hashlib.sha256(preimage).hexdigest()

        vectors = (
            ("image-evidence", {"schema": "cj-vector.v1", "value": 1}),
            ("target-evidence", {"schema": "cj-vector.v1", "value": 1}),
            ("isolation-evidence", {"schema": "cj-vector.v1", "value": 1}),
        )
        expected = b'{"schema":"cj-vector.v1","value":1}\n'
        for domain, value in vectors:
            payload = AGENT.canonical_json(value, terminal_lf=True)
            self.assertEqual(payload, expected)
            self.assertEqual(payload.count(b"\n"), 1)
            self.assertEqual(AGENT._docker_commitment(domain, value), independent(domain, payload))
            self.assertNotEqual(AGENT._docker_commitment(domain, value), independent(domain, payload[:-1]))

    def test_production_orchestration_uses_backend_and_engine_doubles(self) -> None:
        image_id = "sha256:" + ("c" * 64)
        config = AGENT.DockerInstallationConfig(
            "/var/run/docker.sock",
            "postgres:17-alpine",
            image_id,
            "epoch-fixture",
            "volume-fixture",
            "target-fixture",
        )

        class DeterministicProcess:
            def __init__(self) -> None:
                self.stdin = io.BytesIO()
                self.stdout = io.BytesIO()
                self.stderr = io.BytesIO()
                self._reader_error = None
                self._stream_eof = True
                self._reader_done = threading.Event()
                self._reader_done.set()
                self.closed = False

            def wait(self, timeout: float | None = None) -> int:
                return 0

            def close(self) -> None:
                self.closed = True

        class EngineDouble:
            def __init__(self) -> None:
                self.calls: list[tuple[str, str, object]] = []
                self.target_exists = False
                self.volume_exists = False
                self.processes: list[DeterministicProcess] = []

            def request(self, method: str, path: str, body: object = None) -> tuple[int, dict[str, object]]:
                self.calls.append((method, path, body))
                if method == "GET" and path.startswith("/images/"):
                    return 200, {"Id": image_id, "Os": "linux", "Architecture": "amd64"}
                if method == "GET" and path == "/containers/coolify-db/json":
                    return 200, {
                        "Id": "metadata-source-fixture",
                        "Name": "/coolify-db",
                        "State": {"Running": True},
                    }
                if path == "/volumes/swooshz-recovery-volume-volume-fixture":
                    if method == "GET":
                        if not self.volume_exists:
                            return 404, {}
                        return 200, {
                            "Name": "swooshz-recovery-volume-volume-fixture",
                            "Labels": {"com.swooshz.recovery.run": "epoch-fixture"},
                        }
                    if method == "DELETE":
                        self.volume_exists = False
                        return 204, {}
                if path == "/containers/swooshz-recovery-target-target-fixture/json" and method == "GET":
                    if not self.target_exists:
                        return 404, {}
                    return 200, self.target_readback("container-fixture")
                if path == "/volumes/create" and method == "POST":
                    self.volume_exists = True
                    return 201, {"Name": "swooshz-recovery-volume-volume-fixture"}
                if path.startswith("/containers/create") and method == "POST":
                    self.target_exists = True
                    return 201, {"Id": "container-fixture"}
                if path == "/containers/container-fixture/json" and method == "GET":
                    if not self.target_exists:
                        return 404, {}
                    return 200, self.target_readback("container-fixture")
                if path == "/containers/container-fixture/start" and method == "POST":
                    return 204, {}
                if path == "/containers/container-fixture?force=true" and method == "DELETE":
                    self.target_exists = False
                    return 204, {}
                raise AssertionError((method, path, body))

            @staticmethod
            def target_readback(container_id: str) -> dict[str, object]:
                return {
                    "Id": container_id,
                    "Name": "/swooshz-recovery-target-target-fixture",
                    "State": {"Running": True},
                    "Config": {
                        "Image": image_id,
                        "Env": ["POSTGRES_DB=coolify"],
                        "Labels": {"com.swooshz.recovery.run": "epoch-fixture"},
                    },
                    "HostConfig": {
                        "NetworkMode": "none",
                        "Privileged": False,
                        "ReadonlyRootfs": True,
                        "CapDrop": ["ALL"],
                        "CapAdd": [],
                        "PublishAllPorts": False,
                        "PortBindings": {},
                        "ExtraHosts": [],
                        "SecurityOpt": [],
                        "Binds": ["swooshz-recovery-volume-volume-fixture:/var/lib/postgresql/data:rw"],
                    },
                    "Mounts": [{
                        "Destination": "/var/lib/postgresql/data",
                        "RW": True,
                        "Name": "swooshz-recovery-volume-volume-fixture",
                        "Type": "volume",
                    }],
                    "NetworkSettings": {"Networks": {}},
                }

            def open_exec_process(self, container_id: str, command: tuple[str, ...], *, environment: tuple[str, ...]) -> DeterministicProcess:
                self.calls.append(("EXEC", container_id, {"Cmd": command, "Env": environment}))
                process = DeterministicProcess()
                self.processes.append(process)
                return process

        engine = EngineDouble()
        backend = AGENT.ProductionDockerBackend(config, client=engine)
        source = (ROOT / "scripts" / "platform-recovery-remote-agent.py").read_bytes()
        source_commitments = AGENT.fixed_source_commitments()
        n_local = bytes(range(32))
        boot = boot_payload(n_local)
        boot.update({
            "bundle_commitment": source_commitments["bundle_commitment"],
            "launcher_commitment": source_commitments["launcher_commitment"],
            "agent_commitment": source_commitments["agent_commitment"],
        })

        def build_proceed() -> bytes:
            image_commitment = AGENT._docker_commitment("image-evidence", backend._image)
            target_commitment = AGENT._docker_commitment("target-evidence", backend._target)
            isolation_commitment = AGENT._docker_commitment("isolation-evidence", backend._isolation)
            artifact_commitment = backend._artifact_evidence["artifact_commitment"]
            artifact_stream_commitment = AGENT.artifact_stream_evidence_commitment(backend._artifact_evidence)
            proceed = {
                "type": "PROCEED",
                "version": AGENT.SWZFRM02_VERSION,
                "schema": AGENT.SCHEMA_WIRE,
                "epoch_ref": boot["epoch_ref"],
                "authority_ref": boot["authority_ref"],
                "barrier_utc": boot["barrier_utc"],
                "epoch_commitment": boot["epoch_commitment"],
                "authority_commitment": boot["authority_commitment"],
                "barrier_commitment": boot["barrier_commitment"],
                "runner_commitment": boot["runner_commitment"],
                "bundle_commitment": boot["bundle_commitment"],
                "launcher_commitment": boot["launcher_commitment"],
                "agent_commitment": boot["agent_commitment"],
                "image_commitment": image_commitment,
                "target_commitment": target_commitment,
                "isolation_commitment": isolation_commitment,
                "artifact_commitment": artifact_commitment,
                "artifact_stream_commitment": artifact_stream_commitment,
                "transition_id": "restore-v2-" + ("0" * 48),
                "pre_cas_ledger_digest": commitment("pre-cas-ledger"),
                "transition_data_commitment": commitment("transition"),
                "consumed_record_commitment": commitment("consumed-record"),
                "restore_begin_commitment": commitment("restore-begin"),
            }
            _data, data_bytes = AGENT._transition_data_from_proceed(proceed)
            digest = hashlib.sha256(AGENT._length_prefixed(("restore-transition-id.v2", data_bytes))).hexdigest()
            proceed["transition_id"] = "restore-v2-" + digest[:48]
            proceed["transition_data_commitment"] = AGENT.bytes_commitment("restore-ledger-transition", data_bytes)
            return AGENT.encode_frame(AGENT.DIRECTION_LOCAL_TO_REMOTE, AGENT.MESSAGE_PROCEED, 3, n_local, proceed)

        class DeferredInput:
            def __init__(self) -> None:
                self.pending = bytearray(AGENT.encode_frame(AGENT.DIRECTION_LOCAL_TO_REMOTE, AGENT.MESSAGE_BOOT, 0, n_local, boot))
                self.proceed_sent = False

            def read(self, size: int = -1) -> bytes:
                if not self.pending:
                    if self.proceed_sent:
                        return b""
                    self.pending.extend(build_proceed())
                    self.proceed_sent = True
                if size < 0:
                    size = len(self.pending)
                value = bytes(self.pending[:size])
                del self.pending[:size]
                return value

        def deterministic_locator(_barrier: str) -> types.SimpleNamespace:
            process = AGENT.fixed_process_factory()
            process.close()
            return types.SimpleNamespace(classification="EXACTLY_ONE", execution_id=1, filename="backup.tar")

        with tempfile.TemporaryDirectory(prefix="run358-artifact-") as temp:
            artifact_path = pathlib.Path(temp) / "backup.tar"
            artifact_path.write_bytes(b"offline-production-artifact")
            with mock.patch.object(AGENT, "assert_isolated_runtime"), \
                    mock.patch.object(AGENT, "attest_agent_descriptor", return_value=AGENT.AttestedAgent(3, source, (1, 2, len(source), 0o100555, 0, 0), (1, 2, len(source), 0o100555, 0, 0), source_commitments["agent_commitment"])), \
                    mock.patch.object(AGENT, "invoke_canonical_locator_once", side_effect=deterministic_locator), \
                    mock.patch.object(AGENT, "open_artifact_descriptor", side_effect=lambda _root, _filename: os.open(artifact_path, os.O_RDONLY)):
                output_stream = io.BytesIO()
                with self.assertRaisesRegex(AGENT.DockerAdmissionError, "SYNTHETIC_BACKEND_OPERATIONAL_SUCCESS_FORBIDDEN"):
                    AGENT.run_agent_protocol(
                        DeferredInput(),
                        output_stream,
                        backend=backend,
                        environment={"SWZ_RECOVERY_AGENT_FD": "3"},
                        test_mode=True,
                    )

        output_stream.seek(0)
        emitted = []
        while True:
            frame = AGENT.read_frame(output_stream, eof_ok=True)
            if frame is None:
                break
            emitted.append(frame)
        self.assertEqual([frame.message for frame in emitted], [AGENT.MESSAGE_READY, AGENT.MESSAGE_DISCOVERY])
        exec_calls = [call for call in engine.calls if call[0] == "EXEC"]
        self.assertEqual(len(exec_calls), 2)
        self.assertEqual(exec_calls[-1][2]["Cmd"], AGENT.RESTORE_COMMAND)
        self.assertTrue(all(process.closed for process in engine.processes))

    def test_test_mode_protocol_emits_no_operational_success(self) -> None:
        n_local = bytes(range(32))
        boot = boot_payload(n_local)
        source = AGENT.fixed_source_commitments()
        boot.update({
            "bundle_commitment": source["bundle_commitment"],
            "launcher_commitment": source["launcher_commitment"],
            "agent_commitment": source["agent_commitment"],
        })
        discovery = AGENT.DockerDiscovery(
            commitment("image"),
            commitment("target"),
            commitment("isolation"),
            1,
            "backup.tar",
            commitment("artifact-row"),
            commitment("artifact-stream"),
        )
        discovery_payload = AGENT.build_discovery_payload("epoch-fixture", "authority-fixture", discovery)
        proceed = {
            "type": "PROCEED",
            "version": AGENT.SWZFRM02_VERSION,
            "schema": AGENT.SCHEMA_WIRE,
            "epoch_ref": boot["epoch_ref"],
            "authority_ref": boot["authority_ref"],
            "barrier_utc": boot["barrier_utc"],
            "epoch_commitment": boot["epoch_commitment"],
            "authority_commitment": boot["authority_commitment"],
            "barrier_commitment": boot["barrier_commitment"],
            "runner_commitment": boot["runner_commitment"],
            "bundle_commitment": boot["bundle_commitment"],
            "launcher_commitment": boot["launcher_commitment"],
            "agent_commitment": boot["agent_commitment"],
            "image_commitment": discovery_payload["image_commitment"],
            "target_commitment": discovery_payload["target_commitment"],
            "isolation_commitment": discovery_payload["isolation_commitment"],
            "artifact_commitment": discovery_payload["artifact_commitment"],
            "artifact_stream_commitment": discovery_payload["artifact_stream_commitment"],
            "transition_id": "restore-v2-" + ("0" * 48),
            "pre_cas_ledger_digest": commitment("ledger"),
            "transition_data_commitment": commitment("transition"),
            "consumed_record_commitment": commitment("record"),
            "restore_begin_commitment": commitment("restore-begin"),
        }
        _data, data_bytes = AGENT._transition_data_from_proceed(proceed)
        proceed["transition_id"] = "restore-v2-" + hashlib.sha256(
            AGENT._length_prefixed(("restore-transition-id.v2", data_bytes))
        ).hexdigest()[:48]
        proceed["transition_data_commitment"] = AGENT.bytes_commitment("restore-ledger-transition", data_bytes)
        input_stream = io.BytesIO(
            AGENT.encode_frame(AGENT.DIRECTION_LOCAL_TO_REMOTE, AGENT.MESSAGE_BOOT, 0, n_local, boot)
            + AGENT.encode_frame(AGENT.DIRECTION_LOCAL_TO_REMOTE, AGENT.MESSAGE_PROCEED, 3, n_local, proceed)
        )
        output_stream = io.BytesIO()
        with self.assertRaisesRegex(AGENT.DockerAdmissionError, "TEST_SUCCESS_NOT_OPERATIONAL"):
            AGENT.run_agent_protocol(
                input_stream,
                output_stream,
                backend=AGENT.TestOnlyDockerBackend(discovery=discovery),
                environment={"SWZ_RECOVERY_AGENT_FD": "3"},
                test_mode=True,
            )
        output_stream.seek(0)
        emitted = []
        while True:
            frame = AGENT.read_frame(output_stream, eof_ok=True)
            if frame is None:
                break
            emitted.append(frame)
        self.assertEqual([frame.message for frame in emitted], [AGENT.MESSAGE_READY, AGENT.MESSAGE_DISCOVERY])
if __name__ == "__main__":
    unittest.main()
