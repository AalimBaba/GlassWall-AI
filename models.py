"""
models.py
=========

Shared domain data types used across the temporal analysis engine, the
dynamic threat state graph, and the command framework. Centralizing these
here avoids each module inventing its own slightly-different event shape.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum


class ThreatType(str, Enum):
    """Classification of a single detected threat signal.

    Deliberately a flat enum of *signals*, not *conclusions* — e.g.
    PHONE_VISIBLE is a raw detection, not "exfiltration occurred". Whether
    a combination of overlapping signals constitutes a confirmed threat is
    decided by the temporal/state-graph layers, not by this type.
    """

    PHONE_VISIBLE = "phone_visible"
    CAMERA_DEVICE_VISIBLE = "camera_device_visible"
    SECOND_FACE_PRESENT = "second_face_present"
    OBSERVER_GAZE_ON_SCREEN = "observer_gaze_on_screen"
    UNKNOWN_FACE_DETECTED = "unknown_face_detected"
    RECORDING_DEVICE_DETECTED = "recording_device_detected"


@dataclass(frozen=True, slots=True)
class ThreatEvent:
    """A single timed threat signal.

    Attributes:
        start_time: Session-relative start time in seconds (monotonic clock).
        end_time: Session-relative end time in seconds. Must be >= start_time.
        threat_type: What kind of signal this is.
        confidence: Detector confidence in [0.0, 1.0].
        actor_id: Tracking ID of the person/object this event concerns
            (e.g. a face-tracking ID from the CV pipeline).
        event_id: Unique identifier for this event instance. Auto-generated
            if not supplied, so callers only need to provide it when they
            need a stable, predictable ID (e.g. in tests).
    """

    start_time: float
    end_time: float
    threat_type: ThreatType
    confidence: float
    actor_id: str
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self) -> None:
        if self.end_time < self.start_time:
            raise ValueError(
                f"ThreatEvent end_time ({self.end_time}) must be >= "
                f"start_time ({self.start_time})"
            )
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence must be in [0.0, 1.0], got {self.confidence}")

    def overlaps(self, start_time: float, end_time: float) -> bool:
        """True if this event's interval overlaps [start_time, end_time] (inclusive)."""
        return self.start_time <= end_time and start_time <= self.end_time

    def sort_key(self) -> tuple[float, str]:
        """Total-ordering key used by the interval tree (start_time, then event_id
        as a tiebreaker so events with identical start_time remain distinct
        and consistently ordered)."""
        return (self.start_time, self.event_id)
