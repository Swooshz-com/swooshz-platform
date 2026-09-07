"""One-use managed recovery controller.

The controller intentionally keeps the canonical Store and persisted locator
as separate imported authorities.  It never creates Store state while
admission is still being evaluated.  The disposable runtime path below is
the integration subject used by qualification: its restore worker is a
native process that receives one canonical PROCEED frame and one stdin
half-close.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import secrets
import socket
import subprocess
import sys
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[2]


def _load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"module-unavailable:{name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


BACKEND = _load_module("swz_managed_backend", Path(__file__).with_name("backend.py"))
STORE = _load_module("swz_controller_store", ROOT / "scripts" / "platform-recovery-controller-store.py")
LOCATOR = _load_module("swz_persisted_locator", ROOT / "scripts" / "platform-persisted-locator-adapter.py")


class ControllerError(RuntimeError):
    pass


class QualificationProviderHold(ControllerError):
    pass


@dataclass(frozen=True)
class AdmissionContext:
    session_hex: str
    generation_hex: str
    connection_cookie_hex: str
    controller_validated: bool
    remote_accept: bool

    def validate(self) -> None:
        for label, value in (
            ("session", self.session_hex),
            ("generation", self.generation_hex),
            ("connection-cookie", self.connection_cookie_hex),
        ):
            if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
                raise ControllerError(f"{label}-binding-invalid")
        if self.session_hex == "0" * 64 or self.generation_hex == "0" * 64 or self.connection_cookie_hex == "0" * 64:
            raise ControllerError("zero-binding-invalid")
        if not self.controller_validated:
            raise ControllerError("controller-validation-required")
        if not self.remote_accept:
            raise ControllerError("remote-accept-required")


@dataclass(frozen=True)
class QualifiedRecoveryInputs:
    barrier_utc: str
    bundle_commitment: str
    image_commitment: str
    target_commitment: str
    isolation_commitment: str
    artifact_stream_commitment: str


@dataclass(frozen=True)
class SessionResult:
    epoch_ref: str
    transition_id: str
    transition_data_commitment: str
    restore_begin_commitment: str
    proceed_commitment_hex: str
    result_commitment_hex: str
    target_sha256: str
    stdin_half_closes: int
    remote_eof: bool
    trailing_input_bytes: int
    final_state: str
    locator_classification: str | None


def _raw_hex(text: str, label: str) -> bytes:
    try:
        raw = bytes.fromhex(text)
    except ValueError as error:
        raise ControllerError(f"{label}-hex-invalid") from error
    if len(raw) != 32:
        raise ControllerError(f"{label}-length-invalid")
    return raw


def _tagged(value: str, label: str) -> str:
    try:
        BACKEND.strict_store_digest(value)
    except Exception as error:
        raise ControllerError(f"{label}-store-commitment-invalid") from error
    return value


def _qualified_commitment(domain: str, value: bytes) -> str:
    return BACKEND.store_commitment(domain, value)


def disposable_inputs(barrier_utc: str = "2026-09-07T00:00:00Z") -> QualifiedRecoveryInputs:
    """Return explicitly qualified disposable values; no production defaults."""

    return QualifiedRecoveryInputs(
        barrier_utc=barrier_utc,
        bundle_commitment=_qualified_commitment("qualified-bundle", b"swz-managed-disposable-bundle-v1"),
        image_commitment=_qualified_commitment("qualified-image", b"swz-managed-disposable-image-v1"),
        target_commitment=_qualified_commitment("qualified-target", b"swz-managed-disposable-target-v1"),
        isolation_commitment=_qualified_commitment("qualified-isolation", b"swz-managed-disposable-isolation-v1"),
        artifact_stream_commitment="",
    )


def _private_identities() -> dict[str, str]:
    return {
        "container_identity": "swz-disposable-container-001",
        "volume_identity": "swz-disposable-volume-001",
        "runner_identity": "swz-disposable-runner-001",
        "salt": "swz-disposable-salt-only",
        "spool_hmac_key": "swz-disposable-spool-hmac-key-only",
    }


def _artifact_stream_commitment(path: Path) -> str:
    try:
        content = path.read_bytes()
    except OSError as error:
        raise ControllerError("artifact-read-failed") from error
    return BACKEND.store_commitment("artifact-stream", content)


def _frame_nonce() -> bytes:
    return secrets.token_bytes(32)


def _frame_nonce_from(value: bytes | None) -> bytes:
    if value is None:
        return _frame_nonce()
    if not isinstance(value, bytes) or len(value) != 32:
        raise ControllerError("nonce-length-invalid")
    return value


class ManagedController:
    def __init__(self, context: AdmissionContext) -> None:
        context.validate()
        self.context = context
        self.store: Any | None = None
        self.accepted = False
        self.stdin_half_closes = 0
        self.remote_eof = False
        self.trailing_input_bytes = 0

    def accept(self) -> None:
        if self.accepted:
            raise ControllerError("accept-replay")
        self.accepted = True

    def _require_accepted(self) -> None:
        if not self.accepted:
            raise ControllerError("accepted-admission-required")

    def _create_store_epoch(
        self,
        root: Path,
        epoch_ref: str,
        authority_ref: str,
        execution_row_id: int,
        filename: str,
    ) -> Any:
        self._require_accepted()
        store = STORE.ControllerStore.for_disposable_test_root(root)
        store.create_epoch_v2(epoch_ref, authority_ref, prebackup_identities=_private_identities())
        store.bind_artifact_v2(epoch_ref, execution_row_id, filename)
        store.mark_ready(epoch_ref)
        store.activate(epoch_ref)
        store.ingest_frame(epoch_ref, store.prepare_runner_frame(epoch_ref, "EPOCH_READY", {"ref": "epoch-ready-qualified"}))
        store.ingest_frame(epoch_ref, store.prepare_runner_frame(epoch_ref, "RUNNER_STARTED", {"ref": "runner-started-qualified"}))
        self.store = store
        return store

    def execute_locator(self, barrier_utc: str) -> Any:
        """Invoke the canonical persisted locator against the real process path."""

        self._require_accepted()
        outcome = LOCATOR.execute_operation(barrier_utc)
        if not isinstance(outcome, LOCATOR.OperationSuccess):
            raise ControllerError(f"locator-failed:{outcome.classification}")
        if outcome.classification != LOCATOR.EXACTLY_ONE or not outcome.filename:
            raise ControllerError("locator-not-exactly-one")
        return outcome

    def _run_native_agent(
        self,
        *,
        agent_binary: Path,
        source: Path,
        target: Path,
        transition_id: str,
        transition_data_commitment: str,
        restore_begin_frame_hash: bytes,
        artifact_stream_commitment: str,
        proceed_frame: bytes,
        result_payload: bytes,
    ) -> None:
        self._require_accepted()
        if os.name == "nt":
            raise QualificationProviderHold("native-posix-agent-unavailable")
        if not agent_binary.is_file():
            raise QualificationProviderHold("native-agent-binary-unavailable")
        child_socket, controller_socket = socket.socketpair()
        child_socket.set_inheritable(True)
        env = os.environ.copy()
        env.update(
            {
                "SWZ_ACCEPTED": "1",
                "SWZ_PROCEED_AUTHORIZED": "1",
                "SWZ_SESSION": self.context.session_hex,
                "SWZ_GENERATION": self.context.generation_hex,
                "SWZ_CONNECTION_COOKIE": self.context.connection_cookie_hex,
                "SWZ_LIFECYCLE": "ACTIVE",
            }
        )
        command = [
            str(agent_binary),
            "--source", str(source),
            "--target", str(target),
            "--session", self.context.session_hex,
            "--generation", self.context.generation_hex,
            "--cookie", self.context.connection_cookie_hex,
            "--owner-pid", str(os.getpid()),
            "--transition", transition_id,
            "--transition-data", transition_data_commitment,
            "--artifact-stream", artifact_stream_commitment,
            "--restore-begin-frame", restore_begin_frame_hash.hex(),
            "--result-payload", result_payload.hex(),
        ]
        try:
            process = subprocess.Popen(
                command,
                stdin=child_socket,
                stdout=child_socket,
                stderr=subprocess.PIPE,
                close_fds=True,
                env=env,
            )
        except OSError as error:
            child_socket.close()
            controller_socket.close()
            raise QualificationProviderHold("native-agent-launch-unavailable") from error
        child_socket.close()
        raise_if = False
        try:
            controller_socket.settimeout(10.0)
            controller_socket.sendall(proceed_frame)
            controller_socket.shutdown(socket.SHUT_WR)
            self.stdin_half_closes += 1
            received = bytearray()
            while True:
                chunk = controller_socket.recv(4096)
                if not chunk:
                    self.remote_eof = True
                    break
                received.extend(chunk)
                if len(received) > BACKEND.MAX_FRAME_BYTES:
                    raise ControllerError("agent-output-oversized")
            self.trailing_input_bytes = 0
            if not received:
                raise ControllerError("agent-result-missing")
            frame = BACKEND.decode_frame(bytes(received))
            parsed = BACKEND.parse_managed_json(frame.payload)
            if (
                frame.message != "RESULT"
                or frame.direction != BACKEND.DIRECTION_REMOTE_TO_LOCAL
                or frame.sequence != 9
                or frame.payload != result_payload
                or not isinstance(parsed, list)
            ):
                raise ControllerError("agent-result-invalid")
        except (OSError, TimeoutError) as error:
            raise_if = True
            raise ControllerError("agent-transport-failed") from error
        finally:
            controller_socket.close()
            try:
                return_code = process.wait(timeout=10)
            except subprocess.TimeoutExpired as error:
                process.kill()
                process.wait(timeout=2)
                raise_if = True
                raise ControllerError("agent-finality-timeout") from error
            stderr = process.stderr.read() if process.stderr is not None else b""
            if return_code != 0 or stderr:
                raise_if = True
                raise ControllerError("agent-restore-failed")
        if raise_if:
            raise ControllerError("agent-failed")

    def run(
        self,
        *,
        store_root: Path,
        artifact_source: Path,
        artifact_target: Path,
        agent_binary: Path,
        epoch_ref: str = "epoch-qualified-001",
        authority_ref: str = "authority-qualified-001",
        inputs: QualifiedRecoveryInputs | None = None,
        locator_outcome: Any | None = None,
        discovery_nonce: bytes | None = None,
        restore_begin_nonce: bytes | None = None,
        proceed_nonce: bytes | None = None,
        result_nonce: bytes | None = None,
    ) -> SessionResult:
        if not self.accepted:
            self.accept()
        if not artifact_source.is_file() or artifact_source.is_symlink():
            raise ControllerError("artifact-source-invalid")
        inputs = inputs or disposable_inputs()
        stream_commitment = _artifact_stream_commitment(artifact_source)
        inputs = QualifiedRecoveryInputs(
            inputs.barrier_utc, inputs.bundle_commitment, inputs.image_commitment,
            inputs.target_commitment, inputs.isolation_commitment, stream_commitment,
        )
        filename = artifact_source.name
        if locator_outcome is not None:
            if not isinstance(locator_outcome, LOCATOR.OperationSuccess) or locator_outcome.classification != LOCATOR.EXACTLY_ONE:
                raise ControllerError("locator-outcome-invalid")
            if locator_outcome.filename != filename:
                raise ControllerError("locator-artifact-name-mismatch")
            execution_row_id = int(locator_outcome.execution_id)
        else:
            execution_row_id = 23
        store = self._create_store_epoch(
            store_root, epoch_ref, authority_ref, execution_row_id, filename,
        )
        snapshot = store.load_epoch(epoch_ref)
        record = snapshot.record
        artifact_commitment = _tagged(record["artifact_commitment"], "artifact")
        barrier_commitment = _tagged(record["supersession_barrier_commitment"], "barrier")
        runner_commitment = _tagged(record["runner_commitment"], "runner")
        pre_cas_ledger_digest = _tagged(store.ledger_digest(epoch_ref), "pre-cas-ledger")
        transition = OrderedDict(
            (
                ("schema", "restore-ledger-transition-data.v2"),
                ("version", 2),
                ("epoch_ref", epoch_ref),
                ("authority_ref", authority_ref),
                ("barrier_utc", inputs.barrier_utc),
                ("barrier_commitment", barrier_commitment),
                ("runner_commitment", runner_commitment),
                ("bundle_commitment", _tagged(inputs.bundle_commitment, "bundle")),
                ("image_commitment", _tagged(inputs.image_commitment, "image")),
                ("target_commitment", _tagged(inputs.target_commitment, "target")),
                ("isolation_commitment", _tagged(inputs.isolation_commitment, "isolation")),
                ("artifact_commitment", artifact_commitment),
                ("artifact_stream_commitment", _tagged(inputs.artifact_stream_commitment, "artifact-stream")),
                ("pre_cas_ledger_digest", pre_cas_ledger_digest),
            )
        )
        transition_bytes = BACKEND.store_bytes(transition)
        transition_wire = BACKEND.StoreWire.from_bytes("restore-ledger-transition-data.v2", transition_bytes)
        transition_data_commitment = _tagged(
            BACKEND.store_commitment("restore-ledger-transition", transition_bytes),
            "transition-data",
        )
        transition_id = BACKEND.transition_id(transition_bytes)
        permit = store.consume_restore(
            epoch_ref,
            transition_id,
            expected_digest=pre_cas_ledger_digest,
            data=transition,
        )
        if permit.state != "CONSUMED" or permit.transition_id != transition_id:
            raise ControllerError("cas-a-not-consumed")
        consumed_record_commitment = _tagged(store.record_digest(epoch_ref), "consumed-record")
        store_after_cas = store.load_epoch(epoch_ref)
        prepared_store_frame = store.prepare_runner_frame(
            epoch_ref,
            "RESTORE_BEGIN",
            {"transition_id": transition_id, "transition_data_commitment": transition_data_commitment},
        )
        evidence = OrderedDict(
            (
                ("schema", "restore-begin-evidence.v2"),
                ("epoch_ref", epoch_ref),
                ("transition_id", transition_id),
                ("transition_data_commitment", transition_data_commitment),
                ("artifact_commitment", artifact_commitment),
                ("artifact_stream_commitment", _tagged(inputs.artifact_stream_commitment, "artifact-stream")),
                ("ledger_state", store_after_cas.ledger["state"]),
                ("record_state", store_after_cas.record["state"]),
                ("spool_previous_stage", store_after_cas.spool["last_stage"]),
                ("frame_sequence", prepared_store_frame["sequence"]),
                ("previous_frame_hash", store_after_cas.spool["last_frame_hash"]),
                ("frame_hash", prepared_store_frame["frame_hash"]),
                ("spool_commitment", store_after_cas.spool["spool_commitment"]),
                ("ledger_after_digest", _tagged(store.ledger_digest(epoch_ref), "ledger-after")),
                ("durability", OrderedDict(store_after_cas.record["durability"].items())),
            )
        )
        evidence_bytes = BACKEND.store_bytes(evidence)
        evidence_wire = BACKEND.StoreWire.from_bytes("restore-begin-evidence.v2", evidence_bytes)
        restore_begin_commitment = _tagged(
            BACKEND.store_commitment("restore-begin-evidence", evidence_bytes),
            "restore-begin",
        )
        store.ingest_frame(epoch_ref, prepared_store_frame)
        discovery_payload, _ = BACKEND.build_discovery(
            _raw_hex(self.context.session_hex, "session"),
            execution_row_id,
            filename,
            inputs.image_commitment,
            inputs.target_commitment,
            inputs.isolation_commitment,
            artifact_commitment,
            inputs.artifact_stream_commitment,
        )
        discovery_frame = BACKEND.build_frame(
            BACKEND.DIRECTION_LOCAL_TO_REMOTE, "DISCOVERY", 6,
            _frame_nonce_from(discovery_nonce), discovery_payload,
        )
        restore_begin_payload = BACKEND.build_restore_begin(
            _raw_hex(self.context.session_hex, "session"),
            BACKEND.frame_hash(discovery_frame),
            transition_wire,
            evidence_wire,
            consumed_record_commitment,
        )
        restore_begin_frame = BACKEND.build_frame(
            BACKEND.DIRECTION_REMOTE_TO_LOCAL, "RESTORE_BEGIN", 7,
            _frame_nonce_from(restore_begin_nonce), restore_begin_payload,
        )
        proceed_payload, proceed_commitment = BACKEND.build_proceed(
            _raw_hex(self.context.session_hex, "session"),
            transition_id,
            transition_data_commitment,
            BACKEND.frame_hash(restore_begin_frame),
        )
        proceed_frame = BACKEND.build_frame(
            BACKEND.DIRECTION_LOCAL_TO_REMOTE, "PROCEED", 8,
            _frame_nonce_from(proceed_nonce), proceed_payload,
        )
        try:
            artifact_bytes = artifact_source.read_bytes()
        except OSError as error:
            raise ControllerError("artifact-read-failed") from error
        result_record = OrderedDict(
            (
                ("schema", "swz-recovery-result.v2"),
                ("classification", "SUCCESS"),
                ("stage", "RESTORE"),
                ("epoch_ref", epoch_ref),
                ("authority_ref", authority_ref),
                ("barrier_utc", inputs.barrier_utc),
                ("ssh_endpoint_commitment", _qualified_commitment("ssh-endpoint", b"192.0.2.10:22222")),
                ("epoch_commitment", _tagged(store.record_digest(epoch_ref), "epoch")),
                ("authority_commitment", _qualified_commitment("authority", authority_ref.encode("utf-8"))),
                ("barrier_commitment", barrier_commitment),
                ("runner_commitment", runner_commitment),
                ("bundle_commitment", inputs.bundle_commitment),
                ("launcher_commitment", _qualified_commitment("launcher", b"swz-launch-base")),
                ("agent_commitment", _qualified_commitment("agent", b"swz-agent")),
                ("image_commitment", inputs.image_commitment),
                ("target_commitment", inputs.target_commitment),
                ("isolation_commitment", inputs.isolation_commitment),
                ("artifact_commitment", artifact_commitment),
                ("artifact_stream_commitment", inputs.artifact_stream_commitment),
                ("transition_id", transition_id),
                ("pre_cas_ledger_digest", pre_cas_ledger_digest),
                ("transition_data_commitment", transition_data_commitment),
                ("consumed_record_commitment", consumed_record_commitment),
                ("restore_begin_commitment", restore_begin_commitment),
                ("process_commitment", _qualified_commitment("process", b"swz-agent:exit=0")),
                ("restore_commitment", _qualified_commitment("restore", artifact_bytes)),
                ("cleanup_commitment", _qualified_commitment("cleanup", b"socket-closed;generation-retired")),
                ("stdout_capture_commitment", _qualified_commitment("stdout-capture", b"")),
                ("stderr_capture_commitment", _qualified_commitment("stderr-capture", b"")),
                ("result_code", 0),
                ("restore_count", 1),
                ("exit_status", 0),
                ("stdin_eof", True),
                ("stdout_eof", True),
                ("stderr_eof", True),
                ("trailing_unframed_bytes", False),
                ("terminal_input_eof", True),
                ("terminal_input_trailing_bytes", False),
                ("cleanup_state", "CLEAN"),
            )
        )
        result_bytes = BACKEND.store_bytes(result_record)
        result_wire = BACKEND.StoreWire.from_bytes("swz-recovery-result.v2", result_bytes)
        result_payload, result_commitment = BACKEND.build_result(
            _raw_hex(self.context.session_hex, "session"),
            transition_id,
            BACKEND.frame_hash(proceed_frame),
            proceed_commitment,
            result_wire,
        )
        self._run_native_agent(
            agent_binary=agent_binary,
            source=artifact_source,
            target=artifact_target,
            transition_id=transition_id,
            transition_data_commitment=transition_data_commitment,
            restore_begin_frame_hash=BACKEND.frame_hash(restore_begin_frame),
            artifact_stream_commitment=inputs.artifact_stream_commitment,
            proceed_frame=proceed_frame,
            result_payload=result_payload,
        )
        target_bytes = artifact_target.read_bytes()
        if target_bytes != artifact_bytes:
            raise ControllerError("restore-bytes-mismatch")
        store.ingest_frame(
            epoch_ref,
            store.prepare_runner_frame(
                epoch_ref,
                "COMMIT",
                {"result_commitment": BACKEND.managed_hex(result_commitment), "restore_count": 1},
            ),
        )
        final_snapshot = store.load_epoch(epoch_ref)
        if final_snapshot.record["state"] != "CONSUMED" or final_snapshot.spool["state"] != "COMMITTED":
            raise ControllerError("store-finality-invalid")
        if self.stdin_half_closes != 1 or not self.remote_eof or self.trailing_input_bytes != 0:
            raise ControllerError("one-use-io-finality-invalid")
        return SessionResult(
            epoch_ref=epoch_ref,
            transition_id=transition_id,
            transition_data_commitment=transition_data_commitment,
            restore_begin_commitment=restore_begin_commitment,
            proceed_commitment_hex=proceed_commitment.hex(),
            result_commitment_hex=result_commitment.hex(),
            target_sha256=hashlib.sha256(target_bytes).hexdigest(),
            stdin_half_closes=self.stdin_half_closes,
            remote_eof=self.remote_eof,
            trailing_input_bytes=self.trailing_input_bytes,
            final_state=final_snapshot.record["state"],
            locator_classification=None if locator_outcome is None else locator_outcome.classification,
        )


def make_admitted_context(
    session_hex: str,
    generation_hex: str,
    connection_cookie_hex: str,
) -> AdmissionContext:
    context = AdmissionContext(session_hex, generation_hex, connection_cookie_hex, True, True)
    context.validate()
    return context


__all__ = [
    "AdmissionContext",
    "ControllerError",
    "ManagedController",
    "QualificationProviderHold",
    "QualifiedRecoveryInputs",
    "SessionResult",
    "disposable_inputs",
    "make_admitted_context",
]
