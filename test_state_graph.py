"""Tests for the dynamic threat state graph."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace

import pytest

from app.core.models import ThreatEvent, ThreatType
from app.core.state_graph import (
    GraphSnapshot,
    InvalidTransitionError,
    SnapshotValidationError,
    StateTransition,
    ThreatState,
    ThreatStateGraph,
)
from app.core.temporal_engine import ThreatCorrelation


def advance_to_looking(graph: ThreatStateGraph) -> None:
    graph.transition(ThreatState.PHONE_DETECTED, timestamp=1)
    graph.transition(ThreatState.OBSERVER_DETECTED, timestamp=2)
    graph.transition(ThreatState.OBSERVER_LOOKING, timestamp=3)


def test_full_progression_and_immutable_timestamped_history() -> None:
    graph = ThreatStateGraph(session_id="session-1")
    states = list(ThreatState)[1:] + [ThreatState.SECURE]
    for timestamp, state in enumerate(states, 1):
        graph.transition(state, timestamp=float(timestamp), actor_id="actor-1", confidence=0.8)
    history = graph.history()
    assert graph.current_state is ThreatState.SECURE
    assert len(history) == 8
    assert history.transitions[0].session_id == "session-1"
    with pytest.raises(FrozenInstanceError):
        history.transitions[0].timestamp = 99  # type: ignore[misc]


def test_invalid_transition_is_rejected_without_mutation() -> None:
    graph = ThreatStateGraph()
    with pytest.raises(InvalidTransitionError):
        graph.transition(ThreatState.LOCKDOWN)
    assert graph.current_state is ThreatState.SECURE
    assert len(graph.history()) == 0


def test_confidence_and_timestamp_validation() -> None:
    graph = ThreatStateGraph()
    with pytest.raises(ValueError):
        graph.transition(ThreatState.PHONE_DETECTED, confidence=1.1)
    with pytest.raises(ValueError):
        graph.transition(ThreatState.PHONE_DETECTED, timestamp=-1)
    assert graph.current_state is ThreatState.SECURE


def test_direct_transition_record_freezes_mapping_metadata() -> None:
    metadata = {"count": 2}
    record = StateTransition(ThreatState.SECURE, ThreatState.PHONE_DETECTED, 1, metadata=metadata)
    metadata["count"] = 3
    assert record.metadata_dict == {"count": "2"}


def test_snapshot_restore_and_replay() -> None:
    source = ThreatStateGraph(session_id="s")
    advance_to_looking(source)
    snapshot = source.snapshot()
    restored = ThreatStateGraph()
    restored.restore(snapshot)
    assert restored.snapshot() == snapshot

    replayed = ThreatStateGraph(session_id="s")
    assert replayed.replay(source.history().transitions) is ThreatState.OBSERVER_LOOKING
    assert replayed.history() == source.history()
    assert source.history().replayed_state() is ThreatState.OBSERVER_LOOKING
    assert source.allowed_transitions[0] == (ThreatState.SECURE, ThreatState.PHONE_DETECTED)


def test_injected_clock_is_used_when_timestamp_is_omitted() -> None:
    graph = ThreatStateGraph(clock=lambda: 42.5)
    result = graph.transition(ThreatState.PHONE_DETECTED)
    assert result.transition.timestamp == 42.5


def test_tampered_snapshot_rejected_atomically() -> None:
    graph = ThreatStateGraph()
    advance_to_looking(graph)
    original = graph.snapshot()
    bad = replace(original, current_state=ThreatState.LOCKDOWN)
    with pytest.raises(SnapshotValidationError):
        graph.restore(bad)
    assert graph.snapshot() == original


def test_snapshot_with_missing_states_or_invalid_history_is_rejected() -> None:
    graph = ThreatStateGraph()
    original = graph.snapshot()
    missing_state = replace(original, adjacency=original.adjacency[:-1])
    with pytest.raises(SnapshotValidationError):
        graph.restore(missing_state)

    invalid_record = StateTransition(ThreatState.SECURE, ThreatState.LOCKDOWN, 1)
    invalid_history = replace(
        original,
        current_state=ThreatState.LOCKDOWN,
        history=replace(original.history, transitions=(invalid_record,)),
    )
    with pytest.raises(SnapshotValidationError):
        graph.restore(invalid_history)
    assert graph.snapshot() == original


def test_replay_rejects_discontinuous_history_without_mutation() -> None:
    graph = ThreatStateGraph()
    invalid = StateTransition(ThreatState.WARNING, ThreatState.LOCKDOWN, 1.0)
    with pytest.raises(InvalidTransitionError):
        graph.replay([invalid])
    assert graph.current_state is ThreatState.SECURE

    with pytest.raises(InvalidTransitionError):
        replace(graph.history(), transitions=(invalid,)).replayed_state()


def test_bfs_and_dfs_are_deterministic_and_complete() -> None:
    graph = ThreatStateGraph()
    expected = tuple(ThreatState)
    assert graph.bfs() == expected
    assert graph.dfs() == expected
    assert graph.bfs() == graph.bfs()


def test_dynamic_edge_insertion_is_immediately_available() -> None:
    graph = ThreatStateGraph(transitions=())
    assert not graph.can_transition(ThreatState.WARNING)
    graph.add_transition(ThreatState.SECURE, ThreatState.WARNING)
    assert graph.transition(ThreatState.WARNING, timestamp=1).current_state is ThreatState.WARNING


def test_temporal_correlation_integration() -> None:
    graph = ThreatStateGraph(session_id="s")
    advance_to_looking(graph)
    phone = ThreatEvent(1, 5, ThreatType.PHONE_VISIBLE, 0.9, "actor", "phone")
    gaze = ThreatEvent(2, 6, ThreatType.OBSERVER_GAZE_ON_SCREEN, 0.8, "actor", "gaze")
    correlation = ThreatCorrelation(2, 5, (phone, gaze), 0.72)
    result = graph.transition_from_correlation(correlation, metadata={"source": "temporal"})
    assert result.current_state is ThreatState.THREAT_CONFIRMED
    assert result.transition.actor_id == "actor"
    assert result.transition.confidence == pytest.approx(0.72)
    assert result.transition.metadata_dict["event_ids"] == "gaze,phone"
    assert result.transition.metadata_dict["source"] == "temporal"


def test_cross_actor_correlation_has_no_single_actor_attribution() -> None:
    graph = ThreatStateGraph()
    advance_to_looking(graph)
    phone = ThreatEvent(1, 5, ThreatType.PHONE_VISIBLE, 0.9, "a", "phone")
    gaze = ThreatEvent(2, 6, ThreatType.OBSERVER_GAZE_ON_SCREEN, 0.8, "b", "gaze")
    result = graph.transition_from_correlation(ThreatCorrelation(2, 5, (phone, gaze), 0.72))
    assert result.transition.actor_id is None


def test_history_actor_filter_and_metadata_defensive_copy() -> None:
    graph = ThreatStateGraph()
    metadata = {"device": "phone"}
    graph.transition(ThreatState.PHONE_DETECTED, timestamp=1, actor_id="a", metadata=metadata)
    metadata["device"] = "changed"
    graph.transition(ThreatState.OBSERVER_DETECTED, timestamp=2, actor_id="b")
    assert len(graph.history().for_actor("a")) == 1
    assert graph.history().transitions[0].metadata_dict == {"device": "phone"}


def test_concurrent_attempts_produce_one_atomic_transition() -> None:
    graph = ThreatStateGraph()

    def attempt() -> bool:
        try:
            graph.transition(ThreatState.PHONE_DETECTED, timestamp=1)
            return True
        except InvalidTransitionError:
            return False

    with ThreadPoolExecutor(max_workers=16) as pool:
        outcomes = list(pool.map(lambda _: attempt(), range(64)))
    assert sum(outcomes) == 1
    assert graph.current_state is ThreatState.PHONE_DETECTED
    assert len(graph.history()) == 1
