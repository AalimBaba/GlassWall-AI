"""Unit tests for app.core.geometry."""

import math

import pytest

from app.core.geometry import (
    GeometryError,
    Plane,
    Ray,
    Rect3,
    Vector3,
    point_in_rectangle,
    ray_plane_intersection,
    transform_point,
)


class TestVector3:
    def test_add_sub_mul(self) -> None:
        a = Vector3(1, 2, 3)
        b = Vector3(4, 5, 6)
        assert a + b == Vector3(5, 7, 9)
        assert b - a == Vector3(3, 3, 3)
        assert a * 2 == Vector3(2, 4, 6)
        assert 2 * a == Vector3(2, 4, 6)

    def test_dot(self) -> None:
        assert Vector3(1, 0, 0).dot(Vector3(0, 1, 0)) == 0
        assert Vector3(1, 2, 3).dot(Vector3(1, 2, 3)) == 14

    def test_cross_orthogonality(self) -> None:
        x = Vector3(1, 0, 0)
        y = Vector3(0, 1, 0)
        z = x.cross(y)
        assert z == Vector3(0, 0, 1)

    def test_length(self) -> None:
        assert Vector3(3, 4, 0).length() == pytest.approx(5.0)

    def test_normalize(self) -> None:
        v = Vector3(3, 4, 0).normalized()
        assert v.length() == pytest.approx(1.0)

    def test_normalize_zero_vector_raises(self) -> None:
        with pytest.raises(GeometryError):
            Vector3(0, 0, 0).normalized()

    def test_is_zero(self) -> None:
        assert Vector3(0, 0, 0).is_zero()
        assert not Vector3(1e-3, 0, 0).is_zero()


class TestRay:
    def test_direction_is_normalized_on_construction(self) -> None:
        ray = Ray(origin=Vector3(0, 0, 0), direction=Vector3(0, 0, 5))
        assert ray.direction.length() == pytest.approx(1.0)
        assert ray.direction == Vector3(0, 0, 1)

    def test_point_at(self) -> None:
        ray = Ray(origin=Vector3(0, 0, 0), direction=Vector3(1, 0, 0))
        assert ray.point_at(5) == Vector3(5, 0, 0)


class TestRect3:
    def test_normal_right_hand_rule(self) -> None:
        rect = Rect3(
            origin=Vector3(0, 0, 0),
            u_axis=Vector3(1, 0, 0),
            v_axis=Vector3(0, 1, 0),
        )
        assert rect.normal == Vector3(0, 0, 1)

    def test_width_height(self) -> None:
        rect = Rect3(
            origin=Vector3(0, 0, 0),
            u_axis=Vector3(3, 0, 0),
            v_axis=Vector3(0, 4, 0),
        )
        assert rect.width == pytest.approx(3.0)
        assert rect.height == pytest.approx(4.0)

    def test_zero_length_axis_raises(self) -> None:
        with pytest.raises(GeometryError):
            Rect3(origin=Vector3(0, 0, 0), u_axis=Vector3(0, 0, 0), v_axis=Vector3(0, 1, 0))


class TestRayPlaneIntersection:
    def test_perpendicular_hit(self) -> None:
        plane = Plane(point=Vector3(0, 0, 5), normal=Vector3(0, 0, -1))
        ray = Ray(origin=Vector3(0, 0, 0), direction=Vector3(0, 0, 1))
        t = ray_plane_intersection(ray, plane)
        assert t == pytest.approx(5.0)

    def test_parallel_ray_returns_none(self) -> None:
        plane = Plane(point=Vector3(0, 0, 5), normal=Vector3(0, 0, -1))
        ray = Ray(origin=Vector3(0, 0, 0), direction=Vector3(1, 0, 0))
        assert ray_plane_intersection(ray, plane) is None

    def test_plane_behind_ray_returns_negative_t(self) -> None:
        # Not "no intersection" -- the plane is mathematically behind the
        # ray's origin, which is a distinct case callers must be able to
        # detect (e.g. "observer facing away" vs "observer facing sideways").
        plane = Plane(point=Vector3(0, 0, -5), normal=Vector3(0, 0, -1))
        ray = Ray(origin=Vector3(0, 0, 0), direction=Vector3(0, 0, 1))
        t = ray_plane_intersection(ray, plane)
        assert t is not None
        assert t < 0

    def test_angled_hit(self) -> None:
        # Screen plane at z=10, facing -z. Observer at origin looking
        # diagonally (1, 0, 1) normalized -> should hit at x=10, z=10.
        plane = Plane(point=Vector3(0, 0, 10), normal=Vector3(0, 0, -1))
        ray = Ray(origin=Vector3(0, 0, 0), direction=Vector3(1, 0, 1))
        t = ray_plane_intersection(ray, plane)
        assert t is not None
        hit = ray.point_at(t)
        assert hit.x == pytest.approx(10.0)
        assert hit.z == pytest.approx(10.0)


class TestPointInRectangle:
    def setup_method(self) -> None:
        self.rect = Rect3(
            origin=Vector3(0, 0, 0),
            u_axis=Vector3(10, 0, 0),
            v_axis=Vector3(0, 5, 0),
        )

    def test_center_point_inside(self) -> None:
        assert point_in_rectangle(Vector3(5, 2.5, 0), self.rect)

    def test_corner_points_inside(self) -> None:
        assert point_in_rectangle(Vector3(0, 0, 0), self.rect)
        assert point_in_rectangle(Vector3(10, 5, 0), self.rect)

    def test_point_outside_bounds(self) -> None:
        assert not point_in_rectangle(Vector3(11, 2.5, 0), self.rect)
        assert not point_in_rectangle(Vector3(5, 6, 0), self.rect)
        assert not point_in_rectangle(Vector3(-1, 2.5, 0), self.rect)

    def test_boundary_tolerance(self) -> None:
        # Exactly on the edge should count as inside.
        assert point_in_rectangle(Vector3(10, 0, 0), self.rect)


class TestTransformPoint:
    def test_identity_frame(self) -> None:
        basis = (Vector3(1, 0, 0), Vector3(0, 1, 0), Vector3(0, 0, 1))
        p = transform_point(Vector3(3, 4, 5), origin=Vector3(0, 0, 0), basis=basis)
        assert p == Vector3(3, 4, 5)

    def test_translated_frame(self) -> None:
        basis = (Vector3(1, 0, 0), Vector3(0, 1, 0), Vector3(0, 0, 1))
        p = transform_point(Vector3(3, 4, 5), origin=Vector3(1, 1, 1), basis=basis)
        assert p == Vector3(2, 3, 4)

    def test_rotated_frame(self) -> None:
        # Local frame rotated 90 degrees about Z: right=(0,1,0), up=(-1,0,0)
        basis = (Vector3(0, 1, 0), Vector3(-1, 0, 0), Vector3(0, 0, 1))
        p = transform_point(Vector3(1, 0, 0), origin=Vector3(0, 0, 0), basis=basis)
        # World +X should map to local (right=0, up=-1, forward=0)
        assert p.x == pytest.approx(0.0)
        assert p.y == pytest.approx(-1.0)
        assert p.z == pytest.approx(0.0)
