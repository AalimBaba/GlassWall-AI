"""Unit tests for app.core.spatial_engine."""

import pytest

from app.core.geometry import Rect3, Vector3
from app.core.spatial_engine import GazeIntersectionResult, SpatialThreatEngine


@pytest.fixture
def screen_engine() -> SpatialThreatEngine:
    """A 60cm x 34cm monitor, centered at x=0, standing upright,
    with its face pointing toward -z (toward the room)."""
    screen = Rect3(
        origin=Vector3(-30, 0, 0),
        u_axis=Vector3(60, 0, 0),
        v_axis=Vector3(0, 34, 0),
    )
    return SpatialThreatEngine(sensitive_screen=screen)


class TestSpatialThreatEngine:
    def test_direct_gaze_on_screen(self, screen_engine: SpatialThreatEngine) -> None:
        # Observer standing directly in front of screen center, looking straight at it.
        eye = Vector3(0, 17, -100)
        gaze = Vector3(0, 0, 1)
        evaluation = screen_engine.evaluate_gaze(eye, gaze)
        assert evaluation.result is GazeIntersectionResult.ON_SCREEN
        assert evaluation.is_threat
        assert evaluation.distance == pytest.approx(100.0)

    def test_gaze_parallel_to_screen_no_intersection(
        self, screen_engine: SpatialThreatEngine
    ) -> None:
        eye = Vector3(0, 17, -100)
        gaze = Vector3(1, 0, 0)  # looking sideways, parallel to screen plane
        evaluation = screen_engine.evaluate_gaze(eye, gaze)
        assert evaluation.result is GazeIntersectionResult.NO_INTERSECTION
        assert not evaluation.is_threat

    def test_gaze_away_from_screen_is_behind_observer(
        self, screen_engine: SpatialThreatEngine
    ) -> None:
        eye = Vector3(0, 17, -100)
        gaze = Vector3(0, 0, -1)  # looking away from the screen entirely
        evaluation = screen_engine.evaluate_gaze(eye, gaze)
        assert evaluation.result is GazeIntersectionResult.BEHIND_OBSERVER
        assert not evaluation.is_threat

    def test_gaze_hits_plane_but_misses_bounds(
        self, screen_engine: SpatialThreatEngine
    ) -> None:
        # Observer far off to the side, gaze reaches the screen's plane
        # but well outside its physical rectangle.
        eye = Vector3(200, 17, -100)
        gaze = Vector3(0, 0, 1)
        evaluation = screen_engine.evaluate_gaze(eye, gaze)
        assert evaluation.result is GazeIntersectionResult.OUTSIDE_BOUNDS
        assert not evaluation.is_threat
        assert evaluation.intersection_point is not None

    def test_oblique_shoulder_surfer_angle(self, screen_engine: SpatialThreatEngine) -> None:
        # Classic "shoulder surfer" case: observer positioned off to the
        # side and slightly behind the primary user, gaze angled toward
        # the screen -> should still register as on-screen.
        eye = Vector3(50, 17, -60)
        # Gaze vector aimed roughly at screen center (0, 17, 0).
        target = Vector3(0, 17, 0)
        gaze = target - eye
        evaluation = screen_engine.evaluate_gaze(eye, gaze)
        assert evaluation.result is GazeIntersectionResult.ON_SCREEN

    def test_evaluate_many_batch(self, screen_engine: SpatialThreatEngine) -> None:
        observers = {
            "user-primary": (Vector3(0, 17, -100), Vector3(0, 0, 1)),
            "observer-side": (Vector3(200, 17, -100), Vector3(0, 0, 1)),
        }
        results = screen_engine.evaluate_many(observers)
        assert results["user-primary"].is_threat
        assert not results["observer-side"].is_threat

    def test_engine_is_stateless_and_reusable(self, screen_engine: SpatialThreatEngine) -> None:
        # Calling evaluate_gaze repeatedly must not mutate engine state
        # or produce different results for identical inputs (idempotence
        # required for thread-safety across concurrent requests).
        eye = Vector3(0, 17, -100)
        gaze = Vector3(0, 0, 1)
        first = screen_engine.evaluate_gaze(eye, gaze)
        second = screen_engine.evaluate_gaze(eye, gaze)
        assert first == second
