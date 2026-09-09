"""Controller-side admission and one-use Store/agent orchestration."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import secrets
import stat
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


@dataclass(frozen=True)
class NativeAgentExchange:
    """Raw streams returned only after a real native agent reaches EOF.

    The provider must return the complete managed stdout stream and the
    complete fd6 BIND/FINAL stream.  It does not receive, and cannot supply,
    a controller-created RESULT payload.
    """

    result_stream: bytes
    result_context_stream: bytes

    def __post_init__(self) -> None:
        if type(self.result_stream) is not bytes or not self.result_stream:
            raise ControllerError("native-result-stream-invalid")
        if type(self.result_context_stream) is not bytes or not self.result_context_stream:
            raise ControllerError("native-context-stream-invalid")


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


def disposable_inputs(barrier_utc: str = "2026-09-07T00:00:00.000000Z") -> QualifiedRecoveryInputs:
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


def _artifact_stream_digest(path: Path) -> bytes:
    """Match the native 64 KiB length-prefixed artifact-stream digest."""
    digest = hashlib.sha256()

    def update(value: bytes) -> None:
        digest.update(len(value).to_bytes(4, "big"))
        digest.update(value)

    try:
        with path.open("rb") as stream:
            update(b"recovery-commitment.v1")
            update(b"artifact-stream")
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                update(chunk)
    except OSError as error:
        raise ControllerError("artifact-read-failed") from error
    return digest.digest()


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

    def _run_supervised_agent(self, *, agent_binary: Path, source: Path, target: Path,
                              proceed_frame: bytes, transition_id: str,
                              epoch_ref: str, authority_ref: str,
                              expected_bind_commitments: tuple[bytes, ...],
                              barrier_utc: str,
                              agent_exchange: Callable[[bytes, bytes, Path, Path], NativeAgentExchange] | None
                              ) -> tuple[BACKEND.Frame, BACKEND.StoreWire, OrderedDict[str, Any], bytes]:
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
            exchange = agent_exchange(context_record, proceed_frame, source, target)
        except Exception as error:
            raise ControllerError("supervised-agent-exchange-failed") from error
        if not isinstance(exchange, NativeAgentExchange):
            raise ControllerError("native-agent-exchange-shape")
        try:
            proceed = BACKEND.decode_frame(proceed_frame,
                                           expected_direction=BACKEND.DIRECTION_LOCAL_TO_REMOTE,
                                           expected_message="PROCEED", expected_sequence=7)
            proceed_fields = BACKEND.parse_managed_json(proceed.payload)
            bind, final = BACKEND.decode_result_context_stream(exchange.result_context_stream)
            session = bytes.fromhex(self.accepted_session_hex or self.context.session_hex)
            generation = bytes.fromhex(self.context.generation_hex)
            connection = bytes.fromhex(self.context.accepted_connection_hex)
            restore_begin_hash = _raw_hex(proceed_fields[3], "restore-begin-frame")
            transition_commitment = BACKEND.strict_store_digest(proceed_fields[6])
            if (proceed_fields[0:3] != ["PROCEED", 2, BACKEND.MANAGED_SCHEMA] or
                    proceed_fields[4] != session.hex() or proceed_fields[5] != transition_id or
                    proceed_fields[7] != restore_begin_hash.hex() or
                    type(transition_commitment) is not bytes or len(transition_commitment) != 32):
                raise ControllerError("native-proceed-binding-invalid")
            expected_proceed_commitment = BACKEND.managed_hash(
                "proceed.v1", session, transition_id.encode("ascii"),
                transition_commitment, restore_begin_hash)
            if proceed_fields[8] != expected_proceed_commitment.hex():
                raise ControllerError("native-proceed-commitment-invalid")
            if (bind.n_local != self.n_local or bind.session != session or
                    bind.generation != generation or bind.connection != connection or
                    bind.transition_id != transition_id or
                    bind.epoch_ref != epoch_ref or bind.authority_ref != authority_ref or
                    bind.restore_begin_frame_hash != restore_begin_hash):
                raise ControllerError("native-context-binding-invalid")
            if (bind.epoch_ref == "" or bind.authority_ref == "" or
                    bind.barrier_utc != barrier_utc or
                    bind.commitments != expected_bind_commitments or
                    not stat.S_ISFIFO(bind.target.mode) or
                    stat.S_IMODE(bind.target.mode) != 0o600):
                raise ControllerError("native-context-authority-invalid")
            source_stat = source.stat()
            if (source.is_symlink() or not stat.S_ISREG(source_stat.st_mode) or
                    source_stat.st_nlink != 1 or
                    bind.source.dev != source_stat.st_dev or
                    bind.source.ino != source_stat.st_ino or
                    bind.source.size != source_stat.st_size or
                    bind.source.mode != source_stat.st_mode or
                    bind.source.uid != source_stat.st_uid or
                    bind.source.gid != source_stat.st_gid or
                    bind.source.nlink != source_stat.st_nlink or
                    bind.source.offset != 0 or
                    bind.source.content_sha256 != hashlib.sha256(source.read_bytes()).digest() or
                    bind.source.artifact_stream_digest != _artifact_stream_digest(source)):
                raise ControllerError("native-source-descriptor-invalid")
            frame, result_wire, result_record, result_commitment = BACKEND.validate_native_result_frame(
                exchange.result_stream, n_local=self.n_local, proceed_frame=proceed_frame,
                session=session, transition_id=transition_id,
                proceed_commitment=expected_proceed_commitment,
                bind=bind, final=final)
        except Exception as error:
            if isinstance(error, ControllerError):
                raise
            raise ControllerError("agent-result-invalid") from error
        if result_record["classification"] != "SUCCESS":
            raise ControllerError("native-result-not-success")
        try:
            target_bytes = target.read_bytes()
        except OSError as error:
            raise ControllerError("native-target-readback-failed") from error
        expected_sink_ack = hashlib.sha256(hashlib.sha256(target_bytes).digest()).digest()
        if (target.is_symlink() or target_bytes != source.read_bytes() or
                final.source_sha256 != hashlib.sha256(source.read_bytes()).digest() or
                final.sink_ack_digest != expected_sink_ack or
                final.source_bytes_read != len(target_bytes) or
                final.sink_bytes_accepted != len(target_bytes)):
            raise ControllerError("native-final-observation-invalid")
        self.stdin_half_closes = 1
        self.remote_eof = True
        self.trailing_input_bytes = 0
        return frame, result_wire, result_record, result_commitment

    def run(self, *, store_root: Path, artifact_source: Path, artifact_target: Path, agent_binary: Path,
            epoch_ref: str = "epoch-qualified-001", authority_ref: str = "authority-qualified-001",
            inputs: QualifiedRecoveryInputs | None = None, locator_outcome: Any | None = None,
            discovery_nonce: bytes | None = None, restore_begin_nonce: bytes | None = None,
            proceed_nonce: bytes | None = None, result_nonce: bytes | None = None,
            agent_exchange: Callable[[bytes, bytes, Path, Path], NativeAgentExchange] | None = None) -> SessionResult:
        if not self.accepted:
            self.accept()
        if not artifact_source.is_file() or artifact_source.is_symlink():
            raise ControllerError("artifact-source-invalid")
        session_raw = _raw_hex(self.accepted_session_hex or self.context.session_hex,
                               "accepted-session")
        selected = inputs or disposable_inputs()
        try:
            BACKEND.validate_utc6(selected.barrier_utc)
        except Exception as error:
            raise ControllerError("barrier-utc-invalid") from error
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
        expected_bind_commitments = (
            BACKEND.strict_store_digest(_qualified_commitment("ssh-endpoint", b"10.0.2.15:22222")),
            BACKEND.strict_store_digest(_qualified_commitment("epoch", epoch_ref.encode("ascii"))),
            BACKEND.strict_store_digest(_qualified_commitment("authority", authority_ref.encode("ascii"))),
            BACKEND.strict_store_digest(barrier_commitment),
            BACKEND.strict_store_digest(runner_commitment),
            BACKEND.strict_store_digest(selected.bundle_commitment),
            BACKEND.strict_store_digest(_qualified_commitment("launcher", b"swz-launch-base")),
            BACKEND.strict_store_digest(_qualified_commitment("agent", b"swz-agent")),
            BACKEND.strict_store_digest(selected.image_commitment),
            BACKEND.strict_store_digest(selected.target_commitment),
            BACKEND.strict_store_digest(selected.isolation_commitment),
            BACKEND.strict_store_digest(artifact_commitment),
            BACKEND.strict_store_digest(selected.artifact_stream_commitment),
            BACKEND.strict_store_digest(pre_cas_ledger_digest),
            BACKEND.strict_store_digest(transition_data_commitment),
            BACKEND.strict_store_digest(consumed_record_commitment),
            BACKEND.strict_store_digest(restore_begin_commitment),
        )
        _, _, result_record, result_commitment = self._run_supervised_agent(
            agent_binary=agent_binary, source=artifact_source, target=artifact_target,
            proceed_frame=proceed_frame, transition_id=transition_identifier,
            epoch_ref=epoch_ref, authority_ref=authority_ref,
            expected_bind_commitments=expected_bind_commitments,
            barrier_utc=selected.barrier_utc, agent_exchange=agent_exchange)
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


__all__ = ["AdmissionContext", "ControllerError", "ManagedController", "NativeAgentExchange", "QualificationProviderHold", "QualifiedRecoveryInputs", "SessionResult", "disposable_inputs", "make_admitted_context"]
