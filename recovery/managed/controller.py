"""Fail-closed RecoveryController orchestration for the managed boundary.

The controller owns ordering and admission state. It deliberately does not
perform a restore itself: the only callable restore hook is exposed after
remote EOF has been observed and all typed transcript commitments have been
validated. A failure after CAS-A consumes uncertainty permanently.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from backend import (
    AdmissionLifecycle,
    AdmissionState,
    BoundaryError,
    BrokerLifecycle,
    BrokerState,
    StateTransitionError,
    StoreWire,
    build_proceed,
    build_restore_begin,
    build_result,
    frame_hash,
    store_commitment,
    strict_store_digest,
    transition_id,
)


class ControllerError(RuntimeError):
    """A controller operation was rejected without widening authority."""


@dataclass(frozen=True)
class RestoreTranscript:
    restore_begin_payload: bytes
    proceed_payload: bytes
    result_payload: bytes
    transition_id: str
    transition_data_commitment: str
    proceed_commitment: bytes
    result_commitment: bytes


@dataclass(frozen=True)
class ControllerSnapshot:
    admission_state: AdmissionState
    broker_state: BrokerState
    store_mutations: int
    restore_count: int
    half_close_count: int
    restore_authorized: bool
    consumed_uncertainty: bool


class RecoveryController:
    """The only stateful production boundary in this fresh implementation."""

    def __init__(
        self,
        accepted_session_raw32: bytes,
        discovery_frame_hash_raw32: bytes,
        *,
        bindings: Mapping[str, Any] | None = None,
    ) -> None:
        if not isinstance(accepted_session_raw32, bytes) or len(accepted_session_raw32) != 32:
            raise ControllerError("accepted-session")
        if not isinstance(discovery_frame_hash_raw32, bytes) or len(discovery_frame_hash_raw32) != 32:
            raise ControllerError("discovery-frame-hash")
        self.accepted_session = bytes(accepted_session_raw32)
        self.discovery_frame_hash = bytes(discovery_frame_hash_raw32)
        self.bindings = dict(bindings or {})
        self.admission = AdmissionLifecycle()
        self.broker = BrokerLifecycle()
        self._store_mutations = 0
        self._restore_count = 0
        self._cas_commitment: str | None = None
        self._transition_store: StoreWire | None = None
        self._evidence_store: StoreWire | None = None
        self._transition_id: str | None = None
        self._transition_data_commitment: str | None = None
        self._restore_begin_payload: bytes | None = None
        self._restore_begin_frame_hash: bytes | None = None
        self._proceed_payload: bytes | None = None
        self._proceed_frame_hash: bytes | None = None
        self._proceed_commitment: bytes | None = None
        self._result_payload: bytes | None = None
        self._result_commitment: bytes | None = None

    @property
    def restore_authorized(self) -> bool:
        return self.broker.state in {
            BrokerState.RESTORE_AUTHORIZED,
            BrokerState.RESULT,
            BrokerState.FINAL,
        }

    @property
    def restore_count(self) -> int:
        return self._restore_count

    @property
    def state(self) -> BrokerState:
        return self.broker.state

    def snapshot(self) -> ControllerSnapshot:
        return ControllerSnapshot(
            admission_state=self.admission.state,
            broker_state=self.broker.state,
            store_mutations=self._store_mutations,
            restore_count=self._restore_count,
            half_close_count=self.broker.half_close_count,
            restore_authorized=self.restore_authorized,
            consumed_uncertainty=self.broker.state == BrokerState.CONSUMED_UNCERTAINTY,
        )

    def validate_admission(self) -> bool:
        """Validate the accepted session while proving no Store path is open."""

        if self._store_mutations != 0 or self.broker.state != BrokerState.REMOTE_ACCEPTED:
            raise ControllerError("admission-after-store")
        if self.admission.state == AdmissionState.FAILED:
            raise ControllerError("admission-failed")
        return True

    def admit(self) -> ControllerSnapshot:
        """Complete two-sided admission; ACCEPT never authorizes restore."""

        self.validate_admission()
        for target in (
            AdmissionState.SSH_AUTHENTICATED,
            AdmissionState.BOOTSTRAP,
            AdmissionState.CHALLENGE,
            AdmissionState.EVIDENCE,
            AdmissionState.CONTROLLER_VALIDATED,
            AdmissionState.ACCEPT_SENT,
            AdmissionState.REMOTE_ACCEPTED,
            AdmissionState.OPERATIONAL,
        ):
            self.admission.advance(target)
        return self.snapshot()

    accept = admit

    def _require_operational(self) -> None:
        if self.admission.state != AdmissionState.OPERATIONAL:
            raise ControllerError("accepted-admission-required")
        if self.broker.state != BrokerState.REMOTE_ACCEPTED:
            raise ControllerError("broker-not-at-accept")

    def _mark_uncertainty(self, error: BaseException) -> ControllerError:
        if self.broker.state not in {BrokerState.FINAL, BrokerState.CONSUMED_UNCERTAINTY}:
            self.broker.consumed_uncertainty()
        return ControllerError(f"consumed-uncertainty:{type(error).__name__}")

    def cas_a(self, consumed_record_commitment: str) -> ControllerSnapshot:
        """Consume CAS-A only after accepted admission and typed validation."""

        self._require_operational()
        try:
            strict_store_digest(consumed_record_commitment)
        except BoundaryError as error:
            raise ControllerError("cas-a-commitment") from error
        self.broker.advance(BrokerState.DISCOVERY)
        self.broker.advance(BrokerState.CAS_A)
        self._cas_commitment = consumed_record_commitment
        self._store_mutations = 1
        return self.snapshot()

    def _validate_bindings(self, transition: StoreWire, evidence: StoreWire, transition_digest: str, tid: str) -> None:
        transition_values = transition.semantic
        evidence_values = evidence.semantic
        if evidence_values["transition_data_commitment"] != transition_digest:
            raise ControllerError("evidence-transition-commitment")
        if evidence_values["transition_id"] != tid:
            raise ControllerError("evidence-transition-id")
        for key in (
            "epoch_ref",
            "authority_ref",
            "barrier_utc",
            "artifact_commitment",
            "artifact_stream_commitment",
        ):
            if key in self.bindings and key in transition_values and transition_values[key] != self.bindings[key]:
                raise ControllerError(f"transition-binding:{key}")
            if key in self.bindings and key in evidence_values and evidence_values[key] != self.bindings[key]:
                raise ControllerError(f"evidence-binding:{key}")
            if key in transition_values and key in evidence_values and transition_values[key] != evidence_values[key]:
                raise ControllerError(f"cross-store-binding:{key}")
        if self.bindings.get("transition_id") not in (None, tid):
            raise ControllerError("binding:transition-id")

    def restore_begin(self, transition_store: StoreWire, evidence_store: StoreWire) -> bytes:
        """Validate retained bytes and durably enter RESTORE_BEGIN."""

        if self.broker.state != BrokerState.CAS_A or self._cas_commitment is None:
            raise ControllerError("cas-a-required")
        try:
            if not isinstance(transition_store, StoreWire) or not isinstance(evidence_store, StoreWire):
                raise ControllerError("store-wire-type")
            if transition_store.schema_id != "restore-ledger-transition-data.v2":
                raise ControllerError("transition-profile")
            if evidence_store.schema_id != "restore-begin-evidence.v2":
                raise ControllerError("evidence-profile")
            transition_digest = store_commitment("restore-ledger-transition", transition_store.store_bytes)
            tid = transition_id(transition_store.store_bytes)
            self._validate_bindings(transition_store, evidence_store, transition_digest, tid)
            payload = build_restore_begin(
                self.discovery_frame_hash,
                self.accepted_session,
                transition_store,
                evidence_store,
                self._cas_commitment,
            )
            self._transition_store = transition_store
            self._evidence_store = evidence_store
            self._transition_id = tid
            self._transition_data_commitment = transition_digest
            self._restore_begin_payload = payload
            self.broker.advance(BrokerState.RESTORE_BEGIN_DURABLE)
            return payload
        except (BoundaryError, ControllerError, StateTransitionError, TypeError, KeyError) as error:
            raise self._mark_uncertainty(error) from error

    def proceed(self, restore_begin_frame_hash_raw32: bytes) -> tuple[bytes, bytes]:
        if self.broker.state != BrokerState.RESTORE_BEGIN_DURABLE:
            raise ControllerError("restore-begin-not-durable")
        if self._transition_id is None or self._transition_data_commitment is None:
            raise ControllerError("transition-not-retained")
        try:
            payload, commitment = build_proceed(
                self.accepted_session,
                self._transition_id,
                self._transition_data_commitment,
                restore_begin_frame_hash_raw32,
            )
            self._restore_begin_frame_hash = bytes(restore_begin_frame_hash_raw32)
            self._proceed_payload = payload
            self._proceed_commitment = commitment
            self.broker.advance(BrokerState.PROCEED)
            return payload, commitment
        except (BoundaryError, StateTransitionError, TypeError) as error:
            raise self._mark_uncertainty(error) from error

    def controller_half_close(self) -> int:
        if self.broker.state != BrokerState.PROCEED or self.broker.half_close_count != 0:
            raise ControllerError("single-half-close-required")
        try:
            self.broker.advance(BrokerState.HALF_CLOSED)
        except StateTransitionError as error:
            raise self._mark_uncertainty(error) from error
        return self.broker.half_close_count

    def remote_eof(self, trailing_input_bytes: int = 0) -> ControllerSnapshot:
        if self.broker.state != BrokerState.HALF_CLOSED:
            if self.broker.state in {
                BrokerState.CAS_A,
                BrokerState.RESTORE_BEGIN_DURABLE,
                BrokerState.PROCEED,
            }:
                error = ControllerError("half-close-required")
                raise self._mark_uncertainty(error) from error
            raise ControllerError("half-close-required")
        if type(trailing_input_bytes) is not int or trailing_input_bytes < 0:
            error = ControllerError("trailing-input-count")
            raise self._mark_uncertainty(error) from error
        if trailing_input_bytes != 0:
            self.broker.consumed_uncertainty()
            raise ControllerError("remote-trailing-input")
        self.broker.advance(BrokerState.REMOTE_EOF)
        return self.snapshot()

    def authorize_restore(self) -> None:
        """Open the restore hook only after remote EOF and zero trailing input."""

        if self.broker.state != BrokerState.REMOTE_EOF:
            raise ControllerError("restore-not-authorized")
        self.broker.advance(BrokerState.RESTORE_AUTHORIZED)

    def run_authorized_restore(self, restore_hook: Callable[[], Any]) -> Any:
        if self.broker.state != BrokerState.RESTORE_AUTHORIZED or self._restore_count != 0:
            raise ControllerError("authorized-restore-required")
        if not callable(restore_hook):
            raise ControllerError("restore-hook-required")
        try:
            result = restore_hook()
        except Exception as error:  # the consumed state is never rolled back
            raise self._mark_uncertainty(error) from error
        self._restore_count = 1
        return result

    def result(self, result_store: StoreWire) -> tuple[bytes, bytes]:
        if self.broker.state != BrokerState.RESTORE_AUTHORIZED or self._restore_count != 1:
            raise ControllerError("restore-effect-required")
        if self._proceed_commitment is None or self._proceed_payload is None:
            raise ControllerError("proceed-not-retained")
        try:
            if not isinstance(result_store, StoreWire):
                raise ControllerError("result-store-wire-type")
            if self._proceed_frame_hash is None:
                raise ControllerError("proceed-frame-hash-required")
            payload, commitment = build_result(
                self.accepted_session,
                self._transition_id or "",
                self._proceed_frame_hash,
                self._proceed_commitment,
                result_store,
            )
            self._result_payload = payload
            self._result_commitment = commitment
            self.broker.advance(BrokerState.RESULT)
            return payload, commitment
        except (BoundaryError, ControllerError, StateTransitionError, TypeError) as error:
            raise self._mark_uncertainty(error) from error

    def set_proceed_frame_hash(self, proceed_frame_raw: bytes) -> bytes:
        if self.broker.state != BrokerState.PROCEED:
            raise ControllerError("proceed-frame-required")
        try:
            self._proceed_frame_hash = frame_hash(proceed_frame_raw)
        except BoundaryError as error:
            raise self._mark_uncertainty(error) from error
        return self._proceed_frame_hash

    def finalize(self) -> ControllerSnapshot:
        if self.broker.state != BrokerState.RESULT or self._result_payload is None:
            raise ControllerError("result-required")
        self.broker.advance(BrokerState.FINAL)
        return self.snapshot()

    def transcript(self) -> RestoreTranscript:
        if (
            self._restore_begin_payload is None
            or self._proceed_payload is None
            or self._result_payload is None
            or self._transition_id is None
            or self._transition_data_commitment is None
            or self._proceed_commitment is None
            or self._result_commitment is None
        ):
            raise ControllerError("transcript-incomplete")
        return RestoreTranscript(
            restore_begin_payload=self._restore_begin_payload,
            proceed_payload=self._proceed_payload,
            result_payload=self._result_payload,
            transition_id=self._transition_id,
            transition_data_commitment=self._transition_data_commitment,
            proceed_commitment=self._proceed_commitment,
            result_commitment=self._result_commitment,
        )
