"""
geometry.py
===========

Manual, dependency-free 3D vector and geometry primitives used by the
Spatial Threat Engine.

Design constraints (per architecture spec):
    * No external geometry libraries (no numpy, no glm, no trimesh).
    * O(1) per-operation vector math.
    * Immutable value objects (frozen dataclasses) so results can be
      safely shared across worker threads without defensive copying.

These primitives are intentionally minimal and self-contained: they are
the mathematical foundation for ray-plane intersection and point-in-
rectangle tests used to determine whether an observer's gaze intersects
a sensitive on-screen region.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Optional


class GeometryError(ValueError):
    """Raised for invalid geometric inputs (e.g. zero-length vectors)."""


@dataclass(frozen=True, slots=True)
class Vector3:
    """An immutable 3D vector / point in world space.

    Attributes:
        x: X component.
        y: Y component.
        z: Z component.
    """

    x: float
    y: float
    z: float

    def __add__(self, other: "Vector3") -> "Vector3":
        return Vector3(self.x + other.x, self.y + other.y, self.z + other.z)

    def __sub__(self, other: "Vector3") -> "Vector3":
        return Vector3(self.x - other.x, self.y - other.y, self.z - other.z)

    def __mul__(self, scalar: float) -> "Vector3":
        return Vector3(self.x * scalar, self.y * scalar, self.z * scalar)

    __rmul__ = __mul__

    def dot(self, other: "Vector3") -> float:
        """Dot product. O(1)."""
        return self.x * other.x + self.y * other.y + self.z * other.z

    def cross(self, other: "Vector3") -> "Vector3":
        """Cross product. O(1)."""
        return Vector3(
            self.y * other.z - self.z * other.y,
            self.z * other.x - self.x * other.z,
            self.x * other.y - self.y * other.x,
        )

    def length(self) -> float:
        """Euclidean norm. O(1)."""
        return math.sqrt(self.dot(self))

    def length_squared(self) -> float:
        """Squared norm (avoids sqrt where only comparison is needed)."""
        return self.dot(self)

    def normalized(self) -> "Vector3":
        """Return a unit-length copy of this vector.

        Raises:
            GeometryError: if the vector has (near) zero length.
        """
        length = self.length()
        if length < 1e-9:
            raise GeometryError("Cannot normalize a zero-length vector")
        inv = 1.0 / length
        return Vector3(self.x * inv, self.y * inv, self.z * inv)

    def is_zero(self, epsilon: float = 1e-9) -> bool:
        return self.length_squared() < epsilon * epsilon


@dataclass(frozen=True, slots=True)
class Ray:
    """A half-line defined by an origin and a (not necessarily unit) direction.

    Attributes:
        origin: Starting point of the ray in world space.
        direction: Direction the ray travels. Normalized on construction.
    """

    origin: Vector3
    direction: Vector3

    def __post_init__(self) -> None:
        # Normalize direction eagerly so downstream math (t along the ray
        # equals world-space distance) is always valid.
        normalized = self.direction.normalized()
        object.__setattr__(self, "direction", normalized)

    def point_at(self, t: float) -> Vector3:
        """Return the world-space point at parametric distance `t` along the ray."""
        return self.origin + self.direction * t


@dataclass(frozen=True, slots=True)
class Plane:
    """An infinite plane defined by a point on the plane and a unit normal.

    Attributes:
        point: Any point that lies on the plane.
        normal: Unit normal vector of the plane.
    """

    point: Vector3
    normal: Vector3

    def __post_init__(self) -> None:
        object.__setattr__(self, "normal", self.normal.normalized())


@dataclass(frozen=True, slots=True)
class Rect3:
    """A planar rectangle embedded in 3D space, used to represent the
    physical bounds of a sensitive screen region.

    Defined by an origin corner and two orthogonal edge vectors (u, v)
    that span the rectangle. The rectangle occupies:

        origin + s*u + t*v   for s in [0, |u|], t in [0, |v|]

    Attributes:
        origin: Bottom-left corner of the rectangle in world space.
        u_axis: Vector along the rectangle's width (not normalized).
        v_axis: Vector along the rectangle's height (not normalized).
    """

    origin: Vector3
    u_axis: Vector3
    v_axis: Vector3

    def __post_init__(self) -> None:
        if self.u_axis.is_zero() or self.v_axis.is_zero():
            raise GeometryError("Rect3 edges must be non-zero vectors")

    @property
    def normal(self) -> Vector3:
        """Unit normal of the rectangle's plane (right-hand rule: u x v)."""
        return self.u_axis.cross(self.v_axis).normalized()

    @property
    def width(self) -> float:
        return self.u_axis.length()

    @property
    def height(self) -> float:
        return self.v_axis.length()

    def to_plane(self) -> Plane:
        """Return the infinite Plane this rectangle lies within."""
        return Plane(point=self.origin, normal=self.normal)


def ray_plane_intersection(ray: Ray, plane: Plane) -> Optional[float]:
    """Compute the parametric distance `t` at which `ray` intersects `plane`.

    Solves: dot(normal, (origin + t*dir) - plane.point) = 0
        =>  t = dot(normal, plane.point - origin) / dot(normal, dir)

    Args:
        ray: The ray being cast (e.g. an observer's gaze vector).
        plane: The plane being tested (e.g. the plane containing the screen).

    Returns:
        The signed distance `t` along the ray to the intersection point,
        or None if the ray is parallel to the plane (no intersection
        exists at all). Callers that only care about forward-facing
        intersections must check `t >= 0` themselves — a negative `t`
        means the plane lies behind the ray's origin, which is a
        meaningfully different case from "parallel, no intersection"
        (e.g. an observer facing away from the screen vs. one facing
        exactly sideways), and callers such as the threat engine need
        to distinguish the two.

    Complexity:
        O(1).
    """
    denom = plane.normal.dot(ray.direction)
    if abs(denom) < 1e-9:
        # Ray is parallel (or nearly parallel) to the plane -> no intersection.
        return None

    return plane.normal.dot(plane.point - ray.origin) / denom


def point_in_rectangle(point: Vector3, rect: Rect3, epsilon: float = 1e-6) -> bool:
    """Determine whether a world-space `point` (assumed to already lie on
    the plane of `rect`) falls within the rectangle's bounds.

    Projects the point onto the rectangle's local (u, v) coordinate basis
    using dot products, then checks both coordinates fall within
    [0, |axis|].

    Args:
        point: A point known to lie on `rect`'s plane (e.g. the result of
            `ray_plane_intersection`).
        rect: The rectangle to test against.
        epsilon: Numerical tolerance for the boundary check.

    Returns:
        True if the point lies within (or on the boundary of) the rectangle.

    Complexity:
        O(1).
    """
    local = point - rect.origin

    u_unit = rect.u_axis.normalized()
    v_unit = rect.v_axis.normalized()

    s = local.dot(u_unit)  # projected distance along width axis
    t = local.dot(v_unit)  # projected distance along height axis

    return (
        -epsilon <= s <= rect.width + epsilon
        and -epsilon <= t <= rect.height + epsilon
    )


def transform_point(point: Vector3, origin: Vector3, basis: tuple[Vector3, Vector3, Vector3]) -> Vector3:
    """Transform a point from world space into a local coordinate frame.

    Given a local frame defined by an `origin` and an orthonormal
    `basis` (right, up, forward), returns the point's coordinates
    expressed in that local frame. This is a manual implementation of a
    change-of-basis / affine transform (no matrix library required,
    since we only ever need this single operation, not general matrix
    algebra).

    Args:
        point: World-space point to transform.
        origin: World-space origin of the local frame.
        basis: Tuple of three orthonormal Vector3 axes (right, up, forward).

    Returns:
        Vector3 whose (x, y, z) are the point's coordinates along
        (right, up, forward) respectively.

    Complexity:
        O(1).
    """
    right, up, forward = basis
    relative = point - origin
    return Vector3(relative.dot(right), relative.dot(up), relative.dot(forward))
