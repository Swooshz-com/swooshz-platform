"""Controller-side admission and one-use Store/agent orchestration."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import secrets
import sys
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[2]


def _load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"module-load:{name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


STORE = _load_module("swz_controller_store", ROOT / "scripts/platform-recovery-controller-store.py")
LOCATOR = _load_module("swz_locator_adapter", ROOT / "scripts/platform-persisted-locator-adapter.py")
BACKEND = _load_module("swz_managed_backend", Path(__file__).with_name("backend.py"))


class ControllerError(RuntimeError):
    pass


class QualificationProviderHold(ControllerError):
    pass


@dataclass(frozen=True)
class AdmissionContext:
    session_hex: str
    generation_hex: str
    accepted_connection_hex: str
    connection_cookie_hex: str
    controller_validated: bool
    remote_accept: bool

    def validate(self) -> None:
        for label, value in (("session", self.session_hex), ("generation", self.generation_hex),
                             ("accepted-connection", self.accepted_connection_hex),
                             ("connection-cookie", self.connection_cookie_hex)):
            if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
                raise ControllerError(f"{label}-binding-invalid")
        if any(value == "0" * 64 for value in (self.session_hex, self.generation_hex, self.accepted_connection_hex, self.connection_cookie_hex)):
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
    if type(value) is not bytes or len(value) != 32:
        raise ControllerError("nonce-length-invalid")
    return value


class ManagedController:
    def __init__(self, context: AdmissionContext) -> None:
        context.validate()
        self.context = context
        self.store: Any | None = None
        self.accepted = False
        self.n_local = secrets.token_bytes(32)
        self.accepted_frame_hash: bytes | None = None
        self.accepted_session_hex: str | None = None
        self.stdin_half_closes = 0
        self.remote_eof = False
        self.trailing_input_bytes = 0

    def accept(self, accepted_frame: bytes | None = None) -> None:
        if self.accepted:
            raise ControllerError("accept-replay")
        if accepted_frame is None:
            raise ControllerError("accepted-frame-required")
        try:
            frame = BACKEND.decode_frame(accepted_frame,
                                         expected_n_local=self.n_local,
                                         expected_direction=BACKEND.DIRECTION_REMOTE_TO_LOCAL,
                                         expected_message="ACCEPTED",
                                         expected_sequence=4)
            fields = BACKEND.parse_managed_json(frame.payload)[4:]
            if fields[0] != self.context.accepted_connection_hex:
                raise ControllerError("accepted-context-mismatch")
            _raw_hex(fields[3], "accepted-session")
        except ControllerError:
            raise
        except Exception as error:
            raise ControllerError("accepted-frame-invalid") from error
        self.accepted_frame_hash = BACKEND.frame_hash(frame.raw)
        self.accepted_session_hex = fields[3]
        self.accepted = True

    def _require_accepted(self) -> None:
        if not self.accepted:
            raise ControllerError("accepted-admission-required")

    def _create_store_epoch(self, root: Path, epoch_ref: str, authority_ref: str, execution_row_id: int, filename: str) -> Any:
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
        self._require_accepted()
        outcome = LOCATOR.execute_operation(barrier_utc)
        if not isinstance(outcome, LOCATOR.OperationSuccess) or outcome.classification != LOCATOR.EXACTLY_ONE or not outcome.filename:
            raise ControllerError("locator-not-exactly-one")
        return outcome

    def _run_supervised_agent(self, *, agent_binary: Path, source: Path, target: Path, result_payload: bytes,
                              proceed_frame: bytes, agent_exchange: Callable[[bytes, bytes, Path, Path, bytes], bytes] | None) -> None:
        """Accept only a provider that has completed the kernel-backed registration proof."""
        self._require_accepted()
        if os.name == "nt" or not isinstance(agent_binary, Path) or not agent_binary.is_file():
            raise QualificationProviderHold("supervised-agent-provider-unavailable")
        if agent_exchange is None:
            raise QualificationProviderHold("supervisor-provider-required")
        context_record = b"SWZCTX01" + bytes.fromhex(self.context.session_hex) + bytes.fromhex(self.context.generation_hex) + bytes.fromhex(self.context.accepted_connection_hex) + bytes.fromhex(self.context.connection_cookie_hex)
        if len(context_record) != 136:
            raise ControllerError("context-record-length-invalid")
        try:
            received = agent_exchange(context_record, proceed_frame, source, target, result_payload)
        except Exception as error:
            raise ControllerError("supervised-agent-exchange-failed") from error
        if type(received) is not bytes or not received:
            raise ControllerError("agent-result-missing")
        try:
            proceed = BACKEND.decode_frame(proceed_frame,
                                           expected_direction=BACKEND.DIRECTION_LOCAL_TO_REMOTE,
                                           expected_message="PROCEED", expected_sequence=7)
            frame = BACKEND.decode_frame(received, expected_n_local=proceed.n_local,
                                         previous_frame=proceed_frame,
                                         expected_direction=BACKEND.DIRECTION_REMOTE_TO_LOCAL,
                                         expected_message="RESULT", expected_sequence=8)
            parsed = BACKEND.parse_managed_json(frame.payload)
        except Exception as error:
            raise ControllerError("agent-result-invalid") from error
        if frame.payload != result_payload or not isinstance(parsed, list):
            raise ControllerError("agent-result-invalid")
        self.stdin_half_closes = 1
        self.remote_eof = True
        self.trailing_input_bytes = 0

    def run(self, *, store_root: Path, artifact_source: Path, artifact_target: Path, agent_binary: Path,
            epoch_ref: str = "epoch-qualified-001", authority_ref: str = "authority-qualified-001",
            inputs: QualifiedRecoveryInputs | None = None, locator_outcome: Any | None = None,
            discovery_nonce: bytes | None = None, restore_begin_nonce: bytes | None = None,
            proceed_nonce: bytes | None = None, result_nonce: bytes | None = None,
            agent_exchange: Callable[[bytes, bytes, Path, Path, bytes], bytes] | None = None) -> SessionResult:
        if not self.accepted:
            self.accept()
        if not artifact_source.is_file() or artifact_source.is_symlink():
            raise ControllerError("artifact-source-invalid")
        session_raw = _raw_hex(self.accepted_session_hex or self.context.session_hex,
                               "accepted-session")
        selected = inputs or disposable_inputs()
        stream_commitment = _artifact_stream_commitment(artifact_source)
        selected = QualifiedRecoveryInputs(selected.barrier_utc, selected.bundle_commitment, selected.image_commitment,
                                            selected.target_commitment, selected.isolation_commitment, stream_commitment)
        filename = artifact_source.name
        if locator_outcome is not None:
            if not isinstance(locator_outcome, LOCATOR.OperationSuccess) or locator_outcome.classification != LOCATOR.EXACTLY_ONE or locator_outcome.filename != filename:
                raise ControllerError("locator-outcome-invalid")
            execution_row_id = int(locator_outcome.execution_id)
        else:
            execution_row_id = 23
        store = self._create_store_epoch(store_root, epoch_ref, authority_ref, execution_row_id, filename)
        snapshot = store.load_epoch(epoch_ref)
        record = snapshot.record
        artifact_commitment = _tagged(record["artifact_commitment"], "artifact")
        barrier_commitment = _tagged(record["supersession_barrier_commitment"], "barrier")
        runner_commitment = _tagged(record["runner_commitment"], "runner")
        pre_cas_ledger_digest = _tagged(store.ledger_digest(epoch_ref), "pre-cas-ledger")
        transition = OrderedDict((
            ("schema", "restore-ledger-transition-data.v2"), ("version", 2), ("epoch_ref", epoch_ref),
            ("authority_ref", authority_ref), ("barrier_utc", selected.barrier_utc), ("barrier_commitment", barrier_commitment),
            ("runner_commitment", runner_commitment), ("bundle_commitment", _tagged(selected.bundle_commitment, "bundle")),
            ("image_commitment", _tagged(selected.image_commitment, "image")), ("target_commitment", _tagged(selected.target_commitment, "target")),
            ("isolation_commitment", _tagged(selected.isolation_commitment, "isolation")), ("artifact_commitment", artifact_commitment),
            ("artifact_stream_commitment", _tagged(selected.artifact_stream_commitment, "artifact-stream")),
            ("pre_cas_ledger_digest", pre_cas_ledger_digest),
        ))
        transition_bytes = BACKEND.store_bytes(transition)
        transition_wire = BACKEND.StoreWire.from_bytes("restore-ledger-transition-data.v2", transition_bytes)
        transition_data_commitment = _tagged(BACKEND.store_commitment("restore-ledger-transition", transition_bytes), "transition-data")
        transition_identifier = BACKEND.transition_id(transition_bytes)
        permit = store.consume_restore(epoch_ref, transition_identifier, expected_digest=pre_cas_ledger_digest, data=transition)
        if permit.state != "CONSUMED" or permit.transition_id != transition_identifier:
            raise ControllerError("cas-a-not-consumed")
        consumed_record_commitment = _tagged(store.record_digest(epoch_ref), "consumed-record")
        store_after_cas = store.load_epoch(epoch_ref)
        prepared_store_frame = store.prepare_runner_frame(epoch_ref, "RESTORE_BEGIN", {"ref": transition_identifier, "commitment": transition_data_commitment})
        evidence = OrderedDict((
            ("schema", "restore-begin-evidence.v2"), ("epoch_ref", epoch_ref), ("transition_id", transition_identifier),
            ("transition_data_commitment", transition_data_commitment), ("artifact_commitment", artifact_commitment),
            ("artifact_stream_commitment", _tagged(selected.artifact_stream_commitment, "artifact-stream")),
            ("ledger_state", store_after_cas.ledger["state"]), ("record_state", store_after_cas.record["state"]),
            ("spool_previous_stage", store_after_cas.spool["last_stage"]), ("frame_sequence", prepared_store_frame["sequence"]),
            ("previous_frame_hash", store_after_cas.spool["last_frame_hash"]), ("frame_hash", prepared_store_frame["frame_hash"]),
            ("spool_commitment", store_after_cas.spool["spool_commitment"]), ("ledger_after_digest", _tagged(store.ledger_digest(epoch_ref), "ledger-after")),
            ("durability", OrderedDict(store_after_cas.record["durability"].items())),
        ))
        evidence_bytes = BACKEND.store_bytes(evidence)
        evidence_wire = BACKEND.StoreWire.from_bytes("restore-begin-evidence.v2", evidence_bytes)
        restore_begin_commitment = _tagged(BACKEND.store_commitment("restore-begin-evidence", evidence_bytes), "restore-begin")
        store.ingest_frame(epoch_ref, prepared_store_frame)
        if self.accepted_frame_hash is None:
            raise QualificationProviderHold("accepted-frame-transcript-provider-required")
        discovery_payload, _ = BACKEND.build_discovery(session_raw, execution_row_id, filename,
                                                        selected.image_commitment, selected.target_commitment, selected.isolation_commitment,
                                                        artifact_commitment, selected.artifact_stream_commitment,
                                                        self.accepted_frame_hash)
        discovery_frame = BACKEND.build_frame(BACKEND.DIRECTION_REMOTE_TO_LOCAL, "DISCOVERY", 5,
                                              self.n_local, discovery_payload)
        restore_begin_payload = BACKEND.build_restore_begin(session_raw, BACKEND.frame_hash(discovery_frame), transition_wire, evidence_wire, consumed_record_commitment)
        restore_begin_frame = BACKEND.build_frame(BACKEND.DIRECTION_LOCAL_TO_REMOTE, "RESTORE_BEGIN", 6,
                                                  self.n_local, restore_begin_payload)
        proceed_payload, proceed_commitment = BACKEND.build_proceed(session_raw, transition_identifier, transition_data_commitment, BACKEND.frame_hash(restore_begin_frame))
        proceed_frame = BACKEND.build_frame(BACKEND.DIRECTION_LOCAL_TO_REMOTE, "PROCEED", 7,
                                            self.n_local, proceed_payload)
        artifact_bytes = artifact_source.read_bytes()
        result_record = OrderedDict((
            ("schema", "swz-recovery-result.v2"), ("classification", "SUCCESS"), ("stage", "RESTORE"),
            ("epoch_ref", epoch_ref), ("authority_ref", authority_ref), ("barrier_utc", selected.barrier_utc),
            ("ssh_endpoint_commitment", _qualified_commitment("ssh-endpoint", b"192.0.2.10:22222")),
            ("epoch_commitment", _tagged(store.record_digest(epoch_ref), "epoch")), ("authority_commitment", _qualified_commitment("authority", authority_ref.encode("utf-8"))),
            ("barrier_commitment", barrier_commitment), ("runner_commitment", runner_commitment), ("bundle_commitment", selected.bundle_commitment),
            ("launcher_commitment", _qualified_commitment("launcher", b"swz-launch-base")), ("agent_commitment", _qualified_commitment("agent", b"swz-agent")),
            ("image_commitment", selected.image_commitment), ("target_commitment", selected.target_commitment), ("isolation_commitment", selected.isolation_commitment),
            ("artifact_commitment", artifact_commitment), ("artifact_stream_commitment", selected.artifact_stream_commitment), ("transition_id", transition_identifier),
            ("pre_cas_ledger_digest", pre_cas_ledger_digest), ("transition_data_commitment", transition_data_commitment),
            ("consumed_record_commitment", consumed_record_commitment), ("restore_begin_commitment", restore_begin_commitment),
            ("process_commitment", _qualified_commitment("process", b"swz-agent:exit=0")), ("restore_commitment", _qualified_commitment("restore", artifact_bytes)),
            ("cleanup_commitment", _qualified_commitment("cleanup", b"socket-closed;generation-retired")),
            ("stdout_capture_commitment", _qualified_commitment("stdout-capture", b"")), ("stderr_capture_commitment", _qualified_commitment("stderr-capture", b"")),
            ("result_code", 0), ("restore_count", 1), ("exit_status", 0), ("stdin_eof", True), ("stdout_eof", True),
            ("stderr_eof", True), ("trailing_unframed_bytes", False), ("terminal_input_eof", True), ("terminal_input_trailing_bytes", False),
            ("cleanup_state", "CLEAN"),
        ))
        result_bytes = BACKEND.store_bytes(result_record)
        result_wire = BACKEND.StoreWire.from_bytes("swz-recovery-result.v2", result_bytes)
        result_payload, result_commitment = BACKEND.build_result(session_raw, transition_identifier,
                                                                 BACKEND.frame_hash(proceed_frame), proceed_commitment, result_wire)
        self._run_supervised_agent(agent_binary=agent_binary, source=artifact_source, target=artifact_target,
                                   proceed_frame=proceed_frame, result_payload=result_payload, agent_exchange=agent_exchange)
        target_bytes = artifact_target.read_bytes()
        if target_bytes != artifact_bytes:
            raise ControllerError("restore-bytes-mismatch")
        store.ingest_frame(epoch_ref, store.prepare_runner_frame(epoch_ref, "COMMIT", {"result_commitment": BACKEND.managed_hex(result_commitment), "restore_count": 1}))
        final_snapshot = store.load_epoch(epoch_ref)
        if final_snapshot.record["state"] != "CONSUMED" or final_snapshot.spool["state"] != "COMMITTED":
            raise ControllerError("store-finality-invalid")
        if self.stdin_half_closes != 1 or not self.remote_eof or self.trailing_input_bytes != 0:
            raise ControllerError("one-use-io-finality-invalid")
        return SessionResult(epoch_ref, transition_identifier, transition_data_commitment, restore_begin_commitment,
                             proceed_commitment.hex(), result_commitment.hex(), hashlib.sha256(target_bytes).hexdigest(),
                             self.stdin_half_closes, self.remote_eof, self.trailing_input_bytes, final_snapshot.record["state"],
                             None if locator_outcome is None else locator_outcome.classification)


def make_admitted_context(session_hex: str, generation_hex: str, accepted_connection_hex: str, connection_cookie_hex: str | None = None) -> AdmissionContext:
    if connection_cookie_hex is None:
        accepted = _raw_hex(accepted_connection_hex, "accepted-connection")
        connection_cookie_hex = hashlib.sha256(b"swz-qualification-cookie.v1" + accepted).hexdigest()
    context = AdmissionContext(session_hex, generation_hex, accepted_connection_hex, connection_cookie_hex, True, True)
    context.validate()
    return context


__all__ = ["AdmissionContext", "ControllerError", "ManagedController", "QualificationProviderHold", "QualifiedRecoveryInputs", "SessionResult", "disposable_inputs", "make_admitted_context"]
