from __future__ import annotations

import dataclasses
import hashlib
import importlib.util
import io
import os
import pathlib
import stat
import sys
import tempfile
import types
import unittest


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
                qualified = AGENT.qualify_artifact_descriptor(fd)
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



    def test_docker_socket_only_image_target_isolation_and_no_fake_success(self) -> None:
        image_id = "sha256:" + ("a" * 64)
        class FakeClient:
            def __init__(self) -> None:
                self.calls: list[tuple[str, str, object]] = []
            def request(self, method: str, path: str, body: object = None) -> tuple[int, dict[str, object]]:
                self.calls.append((method, path, body))
                if method == "GET":
                    return 200, {"Id": image_id, "Os": "linux", "Architecture": "amd64"}
                if path == "/volumes/create":
                    return 201, {"Name": "swooshz-recovery-volume-volume-fixture"}
                if path.startswith("/containers/create"):
                    return 201, {"Id": "container-fixture"}
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
if __name__ == "__main__":
    unittest.main()
