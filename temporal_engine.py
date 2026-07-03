"""
temporal_engine.py
===================

Domain layer built on top of `IntervalTree`: correlates independently
detected threat signals (e.g. "phone visible", "second face looking at
screen") that overlap in time into a single confirmed threat window.

This exists to avoid false positives from single, momentary signals — a
phone glimpsed for one frame, or a face that passes through the frame
edge, should not alone trigger a lockdown. A *sustained overlap* between
two distinct signal types is a much stronger indicator, which is exactly
what an interval-overlap query is for.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations

from app.core.interval_tree import IntervalTree
from app.core.models import ThreatEvent, ThreatType


@dataclass(frozen=True, slots=True)
class ThreatCorrelation:
    """A confirmed overlap between two distinct threat signals.

    Attributes:
        overlap_start: Start of the overlapping time window.
        overlap_end: End of the overlapping time window.
        events: The two ThreatEvents whose intervals overlap.
        combined_confidence: A conservative combined confidence score
            (product of the two individual confidences), reflecting that
            *both* signals must be correct for the correlation to hold.
    """

    overlap_start: float
    overlap_end: float
    events: tuple[ThreatEvent, ThreatEvent]
    combined_confidence: float

    @property
    def duration(self) -> float:
        return self.overlap_end - self.overlap_start

    @property
    def threat_types(self) -> tuple[ThreatType, ThreatType]:
        return (self.events[0].threat_type, self.events[1].threat_type)


class TemporalThreatAnalyzer:
    """Tracks threat signal intervals over the lifetime of a session and
    reports confirmed correlations between distinct, overlapping signal
    types.

    One instance is intended to be scoped to a single monitoring session
    (e.g. one active workstation session). It wraps an `IntervalTree`
    rather than subclassing it, so the tree's generic data-structure
    concerns stay fully decoupled from threat-domain concerns (Single
    Responsibility Principle).
    """

    def __init__(self, min_overlap_seconds: float = 0.0) -> None:
        """
        Args:
            min_overlap_seconds: Minimum overlap duration required before
                two overlapping events are reported as a correlation.
                Filters out momentary, likely-spurious overlaps (e.g. two
                signals that overlap for 4 milliseconds due to frame
                timing jitter).
        """
        self._tree: IntervalTree[ThreatEvent] = IntervalTree()
        self._min_overlap_seconds = min_overlap_seconds

    def __len__(self) -> int:
        return len(self._tree)

    def record_event(self, event: ThreatEvent) -> None:
        """Add a new threat signal interval to the session timeline.

        Complexity: O(log N).
        """
        self._tree.insert(event)

    def remove_event(self, event_id: str) -> bool:
        """Remove a previously recorded event (e.g. a detector correction
        or a duplicate). Complexity: O(N) — see IntervalTree.delete docs;
        this is an infrequent correction path, not the hot path."""
        return self._tree.delete(event_id)

    def active_at(self, instant: float) -> list[ThreatEvent]:
        """All threat signals active at a single point in time.

        Complexity: O(log N + K).
        """
        return self._tree.query_point(instant)

    def active_during(self, start_time: float, end_time: float) -> list[ThreatEvent]:
        """All threat signals overlapping the given window.

        Complexity: O(log N + K).
        """
        return self._tree.query_overlap(start_time, end_time)

    def find_correlations(
        self, start_time: float, end_time: float
    ) -> list[ThreatCorrelation]:
        """Find all pairs of *distinct-type* threat signals that overlap
        within [start_time, end_time], meeting the configured minimum
        overlap duration.

        This is the direct implementation of the spec's worked example:
        a "phone_visible" interval and a "second_face_present" interval
        that overlap for >= min_overlap_seconds together constitute a
        confirmed correlation, even though neither alone would be.

        Args:
            start_time: Inclusive lower bound of the window to analyze.
            end_time: Inclusive upper bound of the window to analyze.

        Returns:
            List of ThreatCorrelation, sorted by overlap_start ascending.

        Complexity: O(log N + K + K^2) where K is the number of events in
            the window — the interval tree query is O(log N + K); pairing
            up K candidate events is the usual O(K^2) combinatorial cost of
            all-pairs correlation. K is expected to be small (a handful of
            concurrent signals per actor), so this remains fast in
            practice; if K becomes large, correlations should be
            restricted to same-actor pairs first (see `actor_id` filter
            below) to shrink K before pairing.
        """
        candidates = self.active_during(start_time, end_time)
        return self._pair_correlations(candidates)

    def find_correlations_for_actor(
        self, actor_id: str, start_time: float, end_time: float
    ) -> list[ThreatCorrelation]:
        """Same as `find_correlations`, but restricted to signals
        attributed to a single actor_id. Use this in the hot path once
        multiple actors are being tracked simultaneously, to avoid
        spurious cross-actor pairings and to keep K small.

        Complexity: O(log N + K) for the query, O(k^2) for pairing where
        k <= K is the number of events for this specific actor.
        """
        candidates = [e for e in self.active_during(start_time, end_time) if e.actor_id == actor_id]
        return self._pair_correlations(candidates)

    def _pair_correlations(self, candidates: list[ThreatEvent]) -> list[ThreatCorrelation]:
        """Shared all-pairs correlation logic for a candidate event list."""
        correlations: list[ThreatCorrelation] = []

        for event_a, event_b in combinations(candidates, 2):
            if event_a.threat_type == event_b.threat_type:
                continue  # same-type overlap isn't a correlation, just duplication

            overlap_start = max(event_a.start_time, event_b.start_time)
            overlap_end = min(event_a.end_time, event_b.end_time)
            if overlap_end < overlap_start:
                continue  # candidates were both in-window but don't overlap each other

            if (overlap_end - overlap_start) < self._min_overlap_seconds:
                continue

            correlations.append(
                ThreatCorrelation(
                    overlap_start=overlap_start,
                    overlap_end=overlap_end,
                    events=(event_a, event_b),
                    combined_confidence=event_a.confidence * event_b.confidence,
                )
            )

        correlations.sort(key=lambda c: c.overlap_start)
        return correlations
