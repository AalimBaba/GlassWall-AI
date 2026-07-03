"""Unit tests for app.core.interval_tree.

Uses ThreatEvent as the concrete payload type for convenience, but these
tests exercise the generic tree mechanics (insert/delete/query/balance),
not threat-domain logic -- that's covered in test_temporal_engine.py.
"""

import math
import random
import threading

import pytest

from app.core.interval_tree import IntervalTree, _height  # noqa: SLF001 (testing internals intentionally)
from app.core.models import ThreatEvent, ThreatType


def make_event(start: float, end: float, event_id: str, actor: str = "actor-1") -> ThreatEvent:
    return ThreatEvent(
        start_time=start,
        end_time=end,
        threat_type=ThreatType.PHONE_VISIBLE,
        confidence=0.9,
        actor_id=actor,
        event_id=event_id,
    )


def assert_avl_balanced(tree: IntervalTree) -> None:
    """Recursively verify every node satisfies |balance factor| <= 1,
    and that cached heights/max_end are consistent with the actual
    subtree contents. This directly tests the property the O(log N)
    complexity guarantee depends on."""

    def check(node) -> tuple[int, float]:
        if node is None:
            return 0, float("-inf")

        left_h, left_max = check(node.left)
        right_h, right_max = check(node.right)

        assert abs(left_h - right_h) <= 1, "AVL balance invariant violated"

        expected_height = 1 + max(left_h, right_h)
        assert node.height == expected_height, "cached height out of sync"

        expected_max_end = max(node.interval.end_time, left_max, right_max)
        assert node.max_end == expected_max_end, "cached max_end out of sync"

        return node.height, node.max_end

    check(tree._root)  # noqa: SLF001


class TestInsertAndBalance:
    def test_empty_tree(self) -> None:
        tree: IntervalTree[ThreatEvent] = IntervalTree()
        assert len(tree) == 0
        assert tree.height == 0

    def test_single_insert(self) -> None:
        tree: IntervalTree[ThreatEvent] = IntervalTree()
        tree.insert(make_event(1.0, 2.0, "e1"))
        assert len(tree) == 1
        assert tree.height == 1

    def test_sequential_ascending_inserts_stay_balanced(self) -> None:
        # This is the adversarial case for a plain (non-balancing) BST:
        # strictly increasing keys degrade a plain BST to a linked list
        # (O(N) height). An AVL tree must stay logarithmic.
        tree: IntervalTree[ThreatEvent] = IntervalTree()
        n = 1000
        for i in range(n):
            tree.insert(make_event(float(i), float(i) + 1, f"e{i}"))

        assert_avl_balanced(tree)
        # AVL height bound: height <= 1.44 * log2(n + 2)
        assert tree.height <= math.ceil(1.44 * math.log2(n + 2))

    def test_random_inserts_stay_balanced(self) -> None:
        rng = random.Random(42)
        tree: IntervalTree[ThreatEvent] = IntervalTree()
        n = 500
        for i in range(n):
            start = rng.uniform(0, 1000)
            end = start + rng.uniform(0.1, 20)
            tree.insert(make_event(start, end, f"e{i}"))

        assert_avl_balanced(tree)
        assert len(tree) == n


class TestDelete:
    def test_delete_existing_event(self) -> None:
        tree: IntervalTree[ThreatEvent] = IntervalTree()
        tree.insert(make_event(1.0, 2.0, "e1"))
        tree.insert(make_event(3.0, 4.0, "e2"))
        assert tree.delete("e1") is True
        assert len(tree) == 1
        assert tree.query_point(1.5) == []

    def test_delete_nonexistent_event_returns_false(self) -> None:
        tree: IntervalTree[ThreatEvent] = IntervalTree()
        tree.insert(make_event(1.0, 2.0, "e1"))
        assert tree.delete("does-not-exist") is False
        assert len(tree) == 1

    def test_delete_stays_balanced(self) -> None:
        rng = random.Random(7)
        tree: IntervalTree[ThreatEvent] = IntervalTree()
        events = []
        for i in range(300):
            start = rng.uniform(0, 500)
            end = start + rng.uniform(0.1, 10)
            event = make_event(start, end, f"e{i}")
            events.append(event)
            tree.insert(event)

        rng.shuffle(events)
        for event in events[:150]:
            assert tree.delete(event.event_id) is True

        assert len(tree) == 150
        assert_avl_balanced(tree)

    def test_delete_all_empties_tree(self) -> None:
        tree: IntervalTree[ThreatEvent] = IntervalTree()
        ids = []
        for i in range(50):
            e = make_event(float(i), float(i) + 1, f"e{i}")
            ids.append(e.event_id)
            tree.insert(e)

        for eid in ids:
            tree.delete(eid)

        assert len(tree) == 0
        assert tree.height == 0
        assert tree.query_overlap(-1000, 1000) == []


class TestOverlapQuery:
    def setup_method(self) -> None:
        self.tree: IntervalTree[ThreatEvent] = IntervalTree()
        # Matches the spec's worked example intervals.
        self.phone = make_event(12.2, 14.5, "phone-1")
        self.face = make_event(13.0, 15.8, "face-1")
        self.unrelated = make_event(100.0, 110.0, "unrelated-1")
        for e in (self.phone, self.face, self.unrelated):
            self.tree.insert(e)

    def test_overlap_query_finds_overlapping_events(self) -> None:
        result = self.tree.query_overlap(13.0, 14.5)
        ids = {e.event_id for e in result}
        assert ids == {"phone-1", "face-1"}

    def test_overlap_query_excludes_disjoint_events(self) -> None:
        result = self.tree.query_overlap(0.0, 20.0)
        ids = {e.event_id for e in result}
        assert "unrelated-1" not in ids

    def test_overlap_query_results_sorted_by_start(self) -> None:
        result = self.tree.query_overlap(0.0, 200.0)
        starts = [e.start_time for e in result]
        assert starts == sorted(starts)

    def test_query_point_inside_both_intervals(self) -> None:
        result = self.tree.query_point(13.5)
        ids = {e.event_id for e in result}
        assert ids == {"phone-1", "face-1"}

    def test_query_point_outside_all_intervals(self) -> None:
        result = self.tree.query_point(50.0)
        assert result == []

    def test_boundary_touching_counts_as_overlap(self) -> None:
        tree: IntervalTree[ThreatEvent] = IntervalTree()
        tree.insert(make_event(0.0, 5.0, "a"))
        tree.insert(make_event(5.0, 10.0, "b"))
        result = tree.query_point(5.0)
        ids = {e.event_id for e in result}
        assert ids == {"a", "b"}

    def test_invalid_range_raises(self) -> None:
        with pytest.raises(ValueError):
            self.tree.query_overlap(10.0, 5.0)

    def test_in_order_returns_ascending_start_time(self) -> None:
        result = self.tree.in_order()
        starts = [e.start_time for e in result]
        assert starts == sorted(starts)
        assert len(result) == 3

    def test_in_order_empty_tree(self) -> None:
        empty_tree: IntervalTree[ThreatEvent] = IntervalTree()
        assert empty_tree.in_order() == []


class TestOverlapQueryCorrectnessAgainstBruteForce:
    def test_matches_brute_force_on_random_data(self) -> None:
        rng = random.Random(123)
        tree: IntervalTree[ThreatEvent] = IntervalTree()
        events = []
        for i in range(200):
            start = rng.uniform(0, 1000)
            end = start + rng.uniform(0.1, 50)
            e = make_event(start, end, f"e{i}")
            events.append(e)
            tree.insert(e)

        for _ in range(30):
            q_start = rng.uniform(0, 1000)
            q_end = q_start + rng.uniform(0, 100)

            tree_result_ids = {e.event_id for e in tree.query_overlap(q_start, q_end)}
            brute_force_ids = {e.event_id for e in events if e.overlaps(q_start, q_end)}

            assert tree_result_ids == brute_force_ids


class TestThreadSafety:
    def test_concurrent_inserts_do_not_corrupt_tree(self) -> None:
        tree: IntervalTree[ThreatEvent] = IntervalTree()
        n_threads = 8
        inserts_per_thread = 100

        def worker(thread_id: int) -> None:
            for i in range(inserts_per_thread):
                start = thread_id * 1000 + i
                tree.insert(make_event(float(start), float(start) + 1, f"t{thread_id}-e{i}"))

        threads = [threading.Thread(target=worker, args=(tid,)) for tid in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(tree) == n_threads * inserts_per_thread
        assert_avl_balanced(tree)
