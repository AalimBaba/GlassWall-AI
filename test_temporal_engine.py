"""Unit tests for app.core.temporal_engine."""

import pytest

from app.core.models import ThreatEvent, ThreatType
from app.core.temporal_engine import TemporalThreatAnalyzer, ThreatCorrelation


class TestTemporalThreatAnalyzerBasics:
    def test_record_and_active_at(self) -> None:
        analyzer = TemporalThreatAnalyzer()
        analyzer.record_event(
            ThreatEvent(1.0, 5.0, ThreatType.PHONE_VISIBLE, 0.9, "actor-1", event_id="e1")
        )
        assert len(analyzer) == 1
        active = analyzer.active_at(3.0)
        assert len(active) == 1
        assert active[0].event_id == "e1"

    def test_remove_event(self) -> None:
        analyzer = TemporalThreatAnalyzer()
        analyzer.record_event(
            ThreatEvent(1.0, 5.0, ThreatType.PHONE_VISIBLE, 0.9, "actor-1", event_id="e1")
        )
        assert analyzer.remove_event("e1") is True
        assert len(analyzer) == 0

    def test_active_during_window(self) -> None:
        analyzer = TemporalThreatAnalyzer()
        analyzer.record_event(
            ThreatEvent(0.0, 2.0, ThreatType.PHONE_VISIBLE, 0.9, "a", event_id="e1")
        )
        analyzer.record_event(
            ThreatEvent(10.0, 12.0, ThreatType.PHONE_VISIBLE, 0.9, "a", event_id="e2")
        )
        result = analyzer.active_during(0.0, 3.0)
        ids = {e.event_id for e in result}
        assert ids == {"e1"}


class TestFindCorrelationsWorkedExample:
    """Directly implements the spec's worked example:

        Phone Visible        12.2s -> 14.5s
        Second Face Looking  13.0s -> 15.8s
        Overlap               13.0 -> 14.5
        => Threat Confirmed
    """

    def test_spec_worked_example(self) -> None:
        analyzer = TemporalThreatAnalyzer()
        analyzer.record_event(
            ThreatEvent(
                start_time=12.2,
                end_time=14.5,
                threat_type=ThreatType.PHONE_VISIBLE,
                confidence=0.95,
                actor_id="observer-1",
                event_id="phone-event",
            )
        )
        analyzer.record_event(
            ThreatEvent(
                start_time=13.0,
                end_time=15.8,
                threat_type=ThreatType.OBSERVER_GAZE_ON_SCREEN,
                confidence=0.88,
                actor_id="observer-1",
                event_id="gaze-event",
            )
        )

        correlations = analyzer.find_correlations(0.0, 20.0)

        assert len(correlations) == 1
        correlation = correlations[0]
        assert correlation.overlap_start == pytest.approx(13.0)
        assert correlation.overlap_end == pytest.approx(14.5)
        assert correlation.duration == pytest.approx(1.5)
        assert ThreatType.PHONE_VISIBLE in correlation.threat_types
        assert ThreatType.OBSERVER_GAZE_ON_SCREEN in correlation.threat_types
        assert correlation.combined_confidence == pytest.approx(0.95 * 0.88)


class TestFindCorrelationsEdgeCases:
    def test_no_correlation_when_no_overlap(self) -> None:
        analyzer = TemporalThreatAnalyzer()
        analyzer.record_event(
            ThreatEvent(0.0, 2.0, ThreatType.PHONE_VISIBLE, 0.9, "a", event_id="e1")
        )
        analyzer.record_event(
            ThreatEvent(5.0, 7.0, ThreatType.OBSERVER_GAZE_ON_SCREEN, 0.9, "a", event_id="e2")
        )
        correlations = analyzer.find_correlations(0.0, 10.0)
        assert correlations == []

    def test_same_type_overlap_is_not_a_correlation(self) -> None:
        # Two PHONE_VISIBLE detections overlapping (e.g. from two
        # detector passes) should not be reported as a cross-signal
        # correlation -- that would be double-counting one signal type.
        analyzer = TemporalThreatAnalyzer()
        analyzer.record_event(
            ThreatEvent(0.0, 5.0, ThreatType.PHONE_VISIBLE, 0.9, "a", event_id="e1")
        )
        analyzer.record_event(
            ThreatEvent(2.0, 6.0, ThreatType.PHONE_VISIBLE, 0.9, "a", event_id="e2")
        )
        correlations = analyzer.find_correlations(0.0, 10.0)
        assert correlations == []

    def test_min_overlap_seconds_filters_brief_overlaps(self) -> None:
        analyzer = TemporalThreatAnalyzer(min_overlap_seconds=1.0)
        # Overlap window is [4.9, 5.0] -> 0.1s, below the 1.0s threshold.
        analyzer.record_event(
            ThreatEvent(0.0, 5.0, ThreatType.PHONE_VISIBLE, 0.9, "a", event_id="e1")
        )
        analyzer.record_event(
            ThreatEvent(4.9, 10.0, ThreatType.OBSERVER_GAZE_ON_SCREEN, 0.9, "a", event_id="e2")
        )
        assert analyzer.find_correlations(0.0, 10.0) == []

        # Now widen the overlap to 2s -> should pass the threshold.
        analyzer2 = TemporalThreatAnalyzer(min_overlap_seconds=1.0)
        analyzer2.record_event(
            ThreatEvent(0.0, 5.0, ThreatType.PHONE_VISIBLE, 0.9, "a", event_id="e1")
        )
        analyzer2.record_event(
            ThreatEvent(3.0, 10.0, ThreatType.OBSERVER_GAZE_ON_SCREEN, 0.9, "a", event_id="e2")
        )
        assert len(analyzer2.find_correlations(0.0, 10.0)) == 1

    def test_multiple_pairs_all_reported(self) -> None:
        analyzer = TemporalThreatAnalyzer()
        analyzer.record_event(
            ThreatEvent(0.0, 10.0, ThreatType.PHONE_VISIBLE, 0.9, "a", event_id="phone")
        )
        analyzer.record_event(
            ThreatEvent(1.0, 4.0, ThreatType.OBSERVER_GAZE_ON_SCREEN, 0.8, "a", event_id="gaze")
        )
        analyzer.record_event(
            ThreatEvent(2.0, 8.0, ThreatType.SECOND_FACE_PRESENT, 0.7, "a", event_id="face")
        )
        correlations = analyzer.find_correlations(0.0, 10.0)
        # phone-gaze, phone-face, gaze-face -> 3 pairwise correlations
        assert len(correlations) == 3

    def test_correlations_sorted_by_overlap_start(self) -> None:
        analyzer = TemporalThreatAnalyzer()
        analyzer.record_event(
            ThreatEvent(10.0, 15.0, ThreatType.PHONE_VISIBLE, 0.9, "a", event_id="phone-late")
        )
        analyzer.record_event(
            ThreatEvent(11.0, 16.0, ThreatType.OBSERVER_GAZE_ON_SCREEN, 0.9, "a", event_id="gaze-late")
        )
        analyzer.record_event(
            ThreatEvent(0.0, 3.0, ThreatType.PHONE_VISIBLE, 0.9, "b", event_id="phone-early")
        )
        analyzer.record_event(
            ThreatEvent(0.5, 4.0, ThreatType.SECOND_FACE_PRESENT, 0.9, "b", event_id="face-early")
        )
        correlations = analyzer.find_correlations(0.0, 20.0)
        starts = [c.overlap_start for c in correlations]
        assert starts == sorted(starts)


class TestFindCorrelationsForActor:
    def test_restricts_to_single_actor(self) -> None:
        analyzer = TemporalThreatAnalyzer()
        # Actor A: overlapping phone + gaze -> should correlate.
        analyzer.record_event(
            ThreatEvent(0.0, 5.0, ThreatType.PHONE_VISIBLE, 0.9, "actor-A", event_id="a-phone")
        )
        analyzer.record_event(
            ThreatEvent(1.0, 6.0, ThreatType.OBSERVER_GAZE_ON_SCREEN, 0.9, "actor-A", event_id="a-gaze")
        )
        # Actor B: overlapping phone + gaze at the same time -> must NOT
        # be cross-correlated with actor A's events.
        analyzer.record_event(
            ThreatEvent(0.0, 5.0, ThreatType.PHONE_VISIBLE, 0.9, "actor-B", event_id="b-phone")
        )

        correlations = analyzer.find_correlations_for_actor("actor-A", 0.0, 10.0)
        assert len(correlations) == 1
        involved_ids = {e.event_id for e in correlations[0].events}
        assert involved_ids == {"a-phone", "a-gaze"}

    def test_no_events_for_actor_returns_empty(self) -> None:
        analyzer = TemporalThreatAnalyzer()
        analyzer.record_event(
            ThreatEvent(0.0, 5.0, ThreatType.PHONE_VISIBLE, 0.9, "actor-A", event_id="a-phone")
        )
        assert analyzer.find_correlations_for_actor("actor-Z", 0.0, 10.0) == []


class TestThreatCorrelationDataclass:
    def test_duration_and_threat_types(self) -> None:
        e1 = ThreatEvent(0.0, 5.0, ThreatType.PHONE_VISIBLE, 0.9, "a", event_id="e1")
        e2 = ThreatEvent(2.0, 8.0, ThreatType.OBSERVER_GAZE_ON_SCREEN, 0.8, "a", event_id="e2")
        correlation = ThreatCorrelation(
            overlap_start=2.0,
            overlap_end=5.0,
            events=(e1, e2),
            combined_confidence=0.72,
        )
        assert correlation.duration == pytest.approx(3.0)
        assert correlation.threat_types == (ThreatType.PHONE_VISIBLE, ThreatType.OBSERVER_GAZE_ON_SCREEN)
