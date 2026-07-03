"""Unit tests for app.core.models."""

import pytest

from app.core.models import ThreatEvent, ThreatType


class TestThreatEvent:
    def test_valid_construction(self) -> None:
        event = ThreatEvent(
            start_time=1.0,
            end_time=2.0,
            threat_type=ThreatType.PHONE_VISIBLE,
            confidence=0.9,
            actor_id="actor-1",
        )
        assert event.start_time == 1.0
        assert event.event_id  # auto-generated, non-empty

    def test_end_before_start_raises(self) -> None:
        with pytest.raises(ValueError):
            ThreatEvent(
                start_time=5.0,
                end_time=1.0,
                threat_type=ThreatType.PHONE_VISIBLE,
                confidence=0.5,
                actor_id="actor-1",
            )

    @pytest.mark.parametrize("confidence", [-0.1, 1.1, 2.0])
    def test_invalid_confidence_raises(self, confidence: float) -> None:
        with pytest.raises(ValueError):
            ThreatEvent(
                start_time=0.0,
                end_time=1.0,
                threat_type=ThreatType.PHONE_VISIBLE,
                confidence=confidence,
                actor_id="actor-1",
            )

    def test_explicit_event_id_preserved(self) -> None:
        event = ThreatEvent(
            start_time=0.0,
            end_time=1.0,
            threat_type=ThreatType.PHONE_VISIBLE,
            confidence=0.5,
            actor_id="actor-1",
            event_id="fixed-id",
        )
        assert event.event_id == "fixed-id"

    def test_auto_generated_ids_are_unique(self) -> None:
        e1 = ThreatEvent(0, 1, ThreatType.PHONE_VISIBLE, 0.5, "a")
        e2 = ThreatEvent(0, 1, ThreatType.PHONE_VISIBLE, 0.5, "a")
        assert e1.event_id != e2.event_id

    @pytest.mark.parametrize(
        "a_start,a_end,b_start,b_end,expected",
        [
            (0, 5, 3, 8, True),      # partial overlap
            (0, 5, 5, 8, True),      # touching at boundary counts as overlap
            (0, 5, 6, 8, False),     # disjoint
            (0, 10, 3, 6, True),     # fully contains
            (3, 6, 0, 10, True),     # fully contained
        ],
    )
    def test_overlaps(
        self, a_start: float, a_end: float, b_start: float, b_end: float, expected: bool
    ) -> None:
        event = ThreatEvent(a_start, a_end, ThreatType.PHONE_VISIBLE, 0.9, "a")
        assert event.overlaps(b_start, b_end) is expected

    def test_sort_key_orders_by_start_then_id(self) -> None:
        e1 = ThreatEvent(1.0, 2.0, ThreatType.PHONE_VISIBLE, 0.5, "a", event_id="aaa")
        e2 = ThreatEvent(1.0, 2.0, ThreatType.PHONE_VISIBLE, 0.5, "a", event_id="bbb")
        e3 = ThreatEvent(2.0, 3.0, ThreatType.PHONE_VISIBLE, 0.5, "a", event_id="000")
        assert e1.sort_key() < e2.sort_key()  # same start_time, tiebreak by id
        assert e2.sort_key() < e3.sort_key()  # later start_time always sorts after
