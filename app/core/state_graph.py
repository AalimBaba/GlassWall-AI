"""Thread-safe dynamic graph for threat progression and audit history."""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Iterable, Mapping, Optional

from app.core.temporal_engine import ThreatCorrelation


class ThreatState(str, Enum):
    SECURE = "secure"
    PHONE_DETECTED = "phone_detected"
    OBSERVER_DETECTED = "observer_detected"
    OBSERVER_LOOKING = "observer_looking"
    THREAT_CONFIRMED = "threat_confirmed"
    WARNING = "warning"
    LOCKDOWN = "lockdown"
    RECOVERED = "recovered"


class ThreatGraphError(Exception):
    """Base error for state-graph operations."""


class InvalidTransitionError(ThreatGraphError):
    """Raised when an edge is absent from the graph or continuity is broken."""


class SnapshotValidationError(ThreatGraphError):
    """Raised when a snapshot cannot be safely restored."""


Metadata = tuple[tuple[str, str], ...]


def _freeze_metadata(metadata: Optional[Mapping[str, object]]) -> Metadata:
    if not metadata:
        return ()
    return tuple(sorted((str(key), str(value)) for key, value in metadata.items()))


@dataclass(frozen=True, slots=True)
class StateTransition:
    source: ThreatState
    target: ThreatState
    timestamp: float
    actor_id: Optional[str] = None
    session_id: Optional[str] = None
    confidence: Optional[float] = None
    metadata: Metadata | Mapping[str, object] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.confidence is not None and not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be in [0.0, 1.0]")
        if self.timestamp < 0:
            raise ValueError("timestamp must be non-negative")
        frozen = _freeze_metadata(self.metadata) if isinstance(self.metadata, Mapping) else tuple(sorted(self.metadata))
        object.__setattr__(self, "metadata", frozen)

    @property
    def metadata_dict(self) -> dict[str, str]:
        return dict(self.metadata)


@dataclass(frozen=True, slots=True)
class TransitionHistory:
    transitions: tuple[StateTransition, ...] = ()

    def __len__(self) -> int:
        return len(self.transitions)

    def for_actor(self, actor_id: str) -> "TransitionHistory":
        return TransitionHistory(tuple(t for t in self.transitions if t.actor_id == actor_id))

    def replayed_state(self, initial_state: ThreatState = ThreatState.SECURE) -> ThreatState:
        state = initial_state
        for transition in self.transitions:
            if transition.source is not state:
                raise InvalidTransitionError(
                    f"history expected source {state.value}, got {transition.source.value}"
                )
            state = transition.target
        return state


@dataclass(frozen=True, slots=True)
class GraphSnapshot:
    current_state: ThreatState
    initial_state: ThreatState
    history: TransitionHistory
    adjacency: tuple[tuple[ThreatState, tuple[ThreatState, ...]], ...]
    session_id: Optional[str] = None


@dataclass(frozen=True, slots=True)
class StateTransitionResult:
    transition: StateTransition
    current_state: ThreatState
    history_length: int


DEFAULT_TRANSITIONS: tuple[tuple[ThreatState, ThreatState], ...] = (
    (ThreatState.SECURE, ThreatState.PHONE_DETECTED),
    (ThreatState.PHONE_DETECTED, ThreatState.OBSERVER_DETECTED),
    (ThreatState.OBSERVER_DETECTED, ThreatState.OBSERVER_LOOKING),
    (ThreatState.OBSERVER_LOOKING, ThreatState.THREAT_CONFIRMED),
    (ThreatState.THREAT_CONFIRMED, ThreatState.WARNING),
    (ThreatState.WARNING, ThreatState.LOCKDOWN),
    (ThreatState.LOCKDOWN, ThreatState.RECOVERED),
    (ThreatState.RECOVERED, ThreatState.SECURE),
)


class ThreatStateGraph:
    """Adjacency-list state graph with atomic transitions and replayable history."""

    def __init__(
        self,
        *,
        initial_state: ThreatState = ThreatState.SECURE,
        session_id: Optional[str] = None,
        transitions: Iterable[tuple[ThreatState, ThreatState]] = DEFAULT_TRANSITIONS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._initial_state = initial_state
        self._current_state = initial_state
        self._session_id = session_id
        self._clock = clock
        self._adjacency: dict[ThreatState, dict[ThreatState, None]] = {
            state: {} for state in ThreatState
        }
        for source, target in transitions:
            self._adjacency[source][target] = None
        self._history: list[StateTransition] = []
        self._lock = threading.RLock()

    @property
    def current_state(self) -> ThreatState:
        with self._lock:
            return self._current_state

    @property
    def allowed_transitions(self) -> tuple[tuple[ThreatState, ThreatState], ...]:
        with self._lock:
            return tuple(
                (source, target)
                for source in ThreatState
                for target in self._adjacency[source]
            )

    def can_transition(self, target: ThreatState) -> bool:
        with self._lock:
            return target in self._adjacency[self._current_state]

    def add_transition(self, source: ThreatState, target: ThreatState) -> None:
        with self._lock:
            self._adjacency[source][target] = None

    def transition(
        self,
        target: ThreatState,
        *,
        timestamp: Optional[float] = None,
        actor_id: Optional[str] = None,
        confidence: Optional[float] = None,
        metadata: Optional[Mapping[str, object]] = None,
    ) -> StateTransitionResult:
        with self._lock:
            source = self._current_state
            if target not in self._adjacency[source]:
                raise InvalidTransitionError(f"transition {source.value} -> {target.value} is not allowed")
            transition = StateTransition(
                source=source,
                target=target,
                timestamp=self._clock() if timestamp is None else timestamp,
                actor_id=actor_id,
                session_id=self._session_id,
                confidence=confidence,
                metadata=_freeze_metadata(metadata),
            )
            self._history.append(transition)
            self._current_state = target
            return StateTransitionResult(transition, target, len(self._history))

    def transition_from_correlation(
        self, correlation: ThreatCorrelation, *, metadata: Optional[Mapping[str, object]] = None
    ) -> StateTransitionResult:
        actor_ids = {event.actor_id for event in correlation.events}
        actor_id = next(iter(actor_ids)) if len(actor_ids) == 1 else None
        details: dict[str, object] = {
            "event_ids": ",".join(sorted(event.event_id for event in correlation.events)),
            "overlap_duration": correlation.duration,
        }
        if metadata:
            details.update(metadata)
        return self.transition(
            ThreatState.THREAT_CONFIRMED,
            timestamp=correlation.overlap_end,
            actor_id=actor_id,
            confidence=correlation.combined_confidence,
            metadata=details,
        )

    def history(self) -> TransitionHistory:
        with self._lock:
            return TransitionHistory(tuple(self._history))

    def snapshot(self) -> GraphSnapshot:
        with self._lock:
            adjacency = tuple(
                (state, tuple(self._adjacency[state])) for state in ThreatState
            )
            return GraphSnapshot(
                current_state=self._current_state,
                initial_state=self._initial_state,
                history=TransitionHistory(tuple(self._history)),
                adjacency=adjacency,
                session_id=self._session_id,
            )

    def restore(self, snapshot: GraphSnapshot) -> None:
        adjacency = {source: dict.fromkeys(targets) for source, targets in snapshot.adjacency}
        if set(adjacency) != set(ThreatState):
            raise SnapshotValidationError("snapshot adjacency does not contain every threat state")
        state = snapshot.initial_state
        for transition in snapshot.history.transitions:
            if transition.source is not state or transition.target not in adjacency[state]:
                raise SnapshotValidationError("snapshot contains an invalid transition history")
            state = transition.target
        if state is not snapshot.current_state:
            raise SnapshotValidationError("snapshot current state does not match replayed history")
        with self._lock:
            self._initial_state = snapshot.initial_state
            self._current_state = snapshot.current_state
            self._session_id = snapshot.session_id
            self._adjacency = adjacency
            self._history = list(snapshot.history.transitions)

    def replay(self, transitions: Iterable[StateTransition]) -> ThreatState:
        records = tuple(transitions)
        with self._lock:
            state = self._initial_state
            for transition in records:
                if transition.source is not state or transition.target not in self._adjacency[state]:
                    raise InvalidTransitionError("transition history cannot be replayed on this graph")
                state = transition.target
            self._history = list(records)
            self._current_state = state
            return state

    def bfs(self, start: ThreatState = ThreatState.SECURE) -> tuple[ThreatState, ...]:
        with self._lock:
            adjacency = {state: tuple(targets) for state, targets in self._adjacency.items()}
        visited = {start}
        queue = deque([start])
        order: list[ThreatState] = []
        while queue:
            state = queue.popleft()
            order.append(state)
            for target in adjacency[state]:
                if target not in visited:
                    visited.add(target)
                    queue.append(target)
        return tuple(order)

    def dfs(self, start: ThreatState = ThreatState.SECURE) -> tuple[ThreatState, ...]:
        with self._lock:
            adjacency = {state: tuple(targets) for state, targets in self._adjacency.items()}
        visited: set[ThreatState] = set()
        order: list[ThreatState] = []

        def visit(state: ThreatState) -> None:
            visited.add(state)
            order.append(state)
            for target in adjacency[state]:
                if target not in visited:
                    visit(target)

        visit(start)
        return tuple(order)
