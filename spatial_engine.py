"""
spatial_engine.py
==================

The Spatial Threat Engine determines whether an observer's line of sight
intersects a sensitive on-screen bounding box, given:

    * The physical geometry of the monitored screen (as a Rect3).
    * An observer's estimated eye position and gaze direction, derived
      upstream from MediaPipe Face Mesh head-pose / eye-vector output.

This module is deliberately decoupled from MediaPipe/OpenCV: it accepts
plain geometric inputs (Vector3 positions/directions) so it can be unit
tested without any camera, video, or CV dependency, and so the gaze
source can later be swapped (e.g. a different landmark model) with zero
change to this file (Open/Closed Principle).

Coordinate convention: a single shared world-space frame, in centimeters,
established once per session via camera calibration (calibration itself
is out of scope for this module).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from app.core.geometry import (
    Ray,
    Rect3,
    Vector3,
    point_in_rectangle,
    ray_plane_intersection,
)


class GazeIntersectionResult(str, Enum):
    """Outcome classification for a single gaze-vs-screen evaluation."""

    NO_INTERSECTION = "no_intersection"       # gaze parallel to / diverging from screen plane
    BEHIND_OBSERVER = "behind_observer"       # screen plane is behind the observer
    OUTSIDE_BOUNDS = "outside_bounds"         # intersects the plane, but misses the rect
    ON_SCREEN = "on_screen"                   # gaze ray intersects the sensitive rectangle


@dataclass(frozen=True, slots=True)
class GazeEvaluation:
    """Full result of evaluating one observer's gaze against one screen.

    Attributes:
        result: Classification of the intersection outcome.
        distance: World-space distance from the observer's eye to the
            intersection point, if one exists (None otherwise). Useful
            for downstream confidence weighting (closer observers reading
            a screen are a stronger signal than distant, oblique ones).
        intersection_point: The world-space point where the gaze ray
            meets the screen's plane, if any.
    """

    result: GazeIntersectionResult
    distance: Optional[float]
    intersection_point: Optional[Vector3]

    @property
    def is_threat(self) -> bool:
        """Convenience predicate: True only for a confirmed on-screen gaze."""
        return self.result is GazeIntersectionResult.ON_SCREEN


class SpatialThreatEngine:
    """Stateless evaluator for observer-gaze-vs-sensitive-screen intersection.

    One instance is safe to share across threads/requests: it holds no
    mutable state, only the immutable screen geometry it was configured
    with. This satisfies the thread-safety requirement without needing
    locks, since there is nothing to mutate.
    """

    def __init__(self, sensitive_screen: Rect3) -> None:
        """
        Args:
            sensitive_screen: The physical bounding rectangle of the
                monitored screen region, in world-space coordinates.
        """
        self._screen = sensitive_screen
        self._screen_plane = sensitive_screen.to_plane()

    @property
    def screen(self) -> Rect3:
        return self._screen

    def evaluate_gaze(self, eye_position: Vector3, gaze_direction: Vector3) -> GazeEvaluation:
        """Evaluate whether a single observer's gaze intersects the screen.

        Args:
            eye_position: World-space position of the observer's eye
                (midpoint of estimated left/right eye positions is
                recommended upstream).
            gaze_direction: World-space direction the observer is looking,
                need not be pre-normalized (Ray normalizes internally).

        Returns:
            A GazeEvaluation describing the outcome.

        Complexity:
            O(1) — a single ray-plane intersection plus a single
            point-in-rectangle test, both O(1).
        """
        ray = Ray(origin=eye_position, direction=gaze_direction)

        t = ray_plane_intersection(ray, self._screen_plane)
        if t is None:
            return GazeEvaluation(
                result=GazeIntersectionResult.NO_INTERSECTION,
                distance=None,
                intersection_point=None,
            )

        if t < 0:
            # The screen's plane is mathematically behind the observer's
            # eye given their current gaze direction -- they cannot be
            # looking at it, regardless of where the (extrapolated
            # backwards) line would otherwise land.
            return GazeEvaluation(
                result=GazeIntersectionResult.BEHIND_OBSERVER,
                distance=None,
                intersection_point=None,
            )

        intersection = ray.point_at(t)

        if point_in_rectangle(intersection, self._screen):
            return GazeEvaluation(
                result=GazeIntersectionResult.ON_SCREEN,
                distance=t,
                intersection_point=intersection,
            )

        return GazeEvaluation(
            result=GazeIntersectionResult.OUTSIDE_BOUNDS,
            distance=t,
            intersection_point=intersection,
        )

    def evaluate_many(
        self, observers: dict[str, tuple[Vector3, Vector3]]
    ) -> dict[str, GazeEvaluation]:
        """Batch-evaluate multiple tracked observers in a single call.

        Args:
            observers: Mapping of tracking_id -> (eye_position, gaze_direction).

        Returns:
            Mapping of tracking_id -> GazeEvaluation.

        Complexity:
            O(N) in the number of observers, O(1) per observer.
        """
        return {
            tracking_id: self.evaluate_gaze(eye_pos, gaze_dir)
            for tracking_id, (eye_pos, gaze_dir) in observers.items()
        }
