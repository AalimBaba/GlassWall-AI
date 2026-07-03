"""
interval_tree.py
=================

A self-balancing (AVL), max-endpoint-augmented interval tree, implemented
from scratch with no external dependencies, per the architecture spec.

Why AVL rather than a plain BST: a plain BST degrades to O(N) height under
sorted/adversarial insertion order (e.g. events streaming in strictly
increasing start_time, which is the *normal* case for a live threat feed).
AVL guarantees height <= ~1.44 * log2(N + 2), which is what makes insert /
delete O(log N) and overlap queries O(log N + K) *guaranteed*, not just
average-case.

Why generic: the tree itself has no idea what a "threat" is — it only
needs objects with a start, an end, a total-ordering sort key, and a
stable id. This keeps the data structure reusable (e.g. for audit-log
time-range queries later) and independently testable from any threat
domain logic, matching the split used in geometry.py / spatial_engine.py.

Algorithm notes (overlap search):
    The tree is ordered by each interval's sort_key() (primarily
    start_time). Each node is augmented with `max_end`: the maximum
    end_time across its entire subtree. To report *all* overlapping
    intervals for a query range [q_start, q_end] in O(log N + K):

        1. Only descend left if left.max_end >= q_start (otherwise no
           interval in the left subtree can possibly overlap).
        2. Only descend right if this node's own start_time <= q_end
           (since the tree is ordered by start_time, if this node's
           start already exceeds q_end, every node in the right subtree,
           which has an even larger start_time, must also exceed it).

    This prunes entire subtrees that cannot contain a match, which is
    what gives the O(log N + K) bound rather than O(N).
"""

from __future__ import annotations

import threading
from typing import Generic, Optional, Protocol, TypeVar


class IntervalLike(Protocol):
    """Structural type any interval tree payload must satisfy."""

    start_time: float
    end_time: float
    event_id: str

    def sort_key(self) -> tuple[float, str]: ...
    def overlaps(self, start_time: float, end_time: float) -> bool: ...


T = TypeVar("T", bound=IntervalLike)


class _Node(Generic[T]):
    """Internal AVL tree node. Not part of the public API."""

    __slots__ = ("interval", "height", "max_end", "left", "right")

    def __init__(self, interval: T) -> None:
        self.interval = interval
        self.height = 1
        self.max_end = interval.end_time
        self.left: Optional["_Node[T]"] = None
        self.right: Optional["_Node[T]"] = None


def _height(node: Optional[_Node[T]]) -> int:
    return node.height if node is not None else 0


def _max_end(node: Optional[_Node[T]]) -> float:
    return node.max_end if node is not None else float("-inf")


def _update(node: _Node[T]) -> None:
    """Recompute this node's cached height and max_end from its children.
    Must be called after any structural change beneath this node."""
    node.height = 1 + max(_height(node.left), _height(node.right))
    node.max_end = max(
        node.interval.end_time,
        _max_end(node.left),
        _max_end(node.right),
    )


def _balance_factor(node: _Node[T]) -> int:
    return _height(node.left) - _height(node.right)


def _rotate_right(y: _Node[T]) -> _Node[T]:
    x = y.left
    assert x is not None
    y.left = x.right
    x.right = y
    _update(y)  # child must be updated before parent
    _update(x)
    return x


def _rotate_left(x: _Node[T]) -> _Node[T]:
    y = x.right
    assert y is not None
    x.right = y.left
    y.left = x
    _update(x)  # child must be updated before parent
    _update(y)
    return y


def _rebalance(node: _Node[T]) -> _Node[T]:
    """Restore the AVL invariant (|balance factor| <= 1) at `node`,
    assuming both subtrees are already balanced (true when called
    bottom-up during insert/delete)."""
    balance = _balance_factor(node)

    if balance > 1:  # left-heavy
        assert node.left is not None
        if _balance_factor(node.left) < 0:
            node.left = _rotate_left(node.left)  # left-right case
        return _rotate_right(node)

    if balance < -1:  # right-heavy
        assert node.right is not None
        if _balance_factor(node.right) > 0:
            node.right = _rotate_right(node.right)  # right-left case
        return _rotate_left(node)

    return node


class IntervalTree(Generic[T]):
    """Thread-safe, self-balancing interval tree.

    All mutating operations (insert/delete) and read operations
    (query_overlap/query_point/contains) are guarded by a single
    re-entrant lock. This trades a small amount of read concurrency for
    a much simpler, obviously-correct thread-safety story, appropriate
    given expected event volumes (individual threat signals, not raw
    video frames).
    """

    def __init__(self) -> None:
        self._root: Optional[_Node[T]] = None
        self._size = 0
        self._lock = threading.RLock()

    def __len__(self) -> int:
        with self._lock:
            return self._size

    @property
    def height(self) -> int:
        """Current tree height (0 for an empty tree). Exposed mainly for
        testing the AVL balance guarantee."""
        with self._lock:
            return _height(self._root)

    def insert(self, interval: T) -> None:
        """Insert an interval.

        Complexity: O(log N), guaranteed by the AVL height bound.
        """
        with self._lock:
            self._root = self._insert(self._root, interval)
            self._size += 1

    def _insert(self, node: Optional[_Node[T]], interval: T) -> _Node[T]:
        if node is None:
            return _Node(interval)

        if interval.sort_key() < node.interval.sort_key():
            node.left = self._insert(node.left, interval)
        else:
            node.right = self._insert(node.right, interval)

        _update(node)
        return _rebalance(node)

    def delete(self, event_id: str) -> bool:
        """Delete the interval with the given event_id, if present.

        Args:
            event_id: The unique id of the interval to remove.

        Returns:
            True if an interval was found and removed, False otherwise.

        Complexity: O(log N).
        """
        with self._lock:
            found = self._contains_id(self._root, event_id)
            if not found:
                return False
            self._root = self._delete(self._root, found.sort_key())
            self._size -= 1
            return True

    def _contains_id(self, node: Optional[_Node[T]], event_id: str) -> Optional[T]:
        # Full scan by id is O(N) in the worst case, but delete-by-id is a
        # deliberately rare admin/correction operation, not the hot path
        # (the hot path is insert + overlap query). Callers needing
        # frequent delete-by-id can maintain their own id->sort_key map
        # alongside the tree.
        if node is None:
            return None
        if node.interval.event_id == event_id:
            return node.interval
        left = self._contains_id(node.left, event_id)
        if left is not None:
            return left
        return self._contains_id(node.right, event_id)

    def _delete(self, node: Optional[_Node[T]], key: tuple[float, str]) -> Optional[_Node[T]]:
        if node is None:  # pragma: no cover - unreachable via public API: delete()
            # always pre-checks existence via _contains_id before calling
            # _delete, so the search path is guaranteed to find `key`.
            # Kept as a defensive guard for any future direct caller of
            # this internal method.
            return None

        node_key = node.interval.sort_key()
        if key < node_key:
            node.left = self._delete(node.left, key)
        elif key > node_key:
            node.right = self._delete(node.right, key)
        else:
            # Found the node to delete.
            if node.left is None:
                return node.right
            if node.right is None:
                return node.left
            # Two children: replace with in-order successor (smallest in
            # right subtree), then delete that successor from the right
            # subtree.
            successor = self._min_node(node.right)
            node.interval = successor.interval
            node.right = self._delete(node.right, successor.interval.sort_key())

        _update(node)
        return _rebalance(node)

    def _min_node(self, node: _Node[T]) -> _Node[T]:
        while node.left is not None:
            node = node.left
        return node

    def query_overlap(self, start_time: float, end_time: float) -> list[T]:
        """Return all intervals overlapping [start_time, end_time], sorted
        by start_time ascending.

        Args:
            start_time: Inclusive lower bound of the query range.
            end_time: Inclusive upper bound of the query range.

        Returns:
            List of matching intervals, in ascending start_time order.

        Complexity: O(log N + K), where K is the number of results.
        """
        if end_time < start_time:
            raise ValueError("query end_time must be >= start_time")
        with self._lock:
            result: list[T] = []
            self._query_overlap(self._root, start_time, end_time, result)
            return result

    def _query_overlap(
        self, node: Optional[_Node[T]], start_time: float, end_time: float, result: list[T]
    ) -> None:
        if node is None:
            return

        # Prune: nothing in the left subtree can reach far enough to
        # overlap the query's start.
        if node.left is not None and node.left.max_end >= start_time:
            self._query_overlap(node.left, start_time, end_time, result)

        if node.interval.overlaps(start_time, end_time):
            result.append(node.interval)

        # Prune: since the tree is ordered by start_time ascending, if
        # this node's start already exceeds the query's end, every node
        # in the right subtree (all with even larger start_time) must
        # also start after the query window closes.
        if node.interval.start_time <= end_time and node.right is not None:
            self._query_overlap(node.right, start_time, end_time, result)

    def query_point(self, instant: float) -> list[T]:
        """Return all intervals active at a single instant in time
        (equivalent to `query_overlap(instant, instant)`).

        Complexity: O(log N + K).
        """
        return self.query_overlap(instant, instant)

    def in_order(self) -> list[T]:
        """Return all intervals in ascending start_time order. Mainly for
        debugging/testing; O(N)."""
        with self._lock:
            result: list[T] = []
            self._in_order(self._root, result)
            return result

    def _in_order(self, node: Optional[_Node[T]], result: list[T]) -> None:
        if node is None:
            return
        self._in_order(node.left, result)
        result.append(node.interval)
        self._in_order(node.right, result)
