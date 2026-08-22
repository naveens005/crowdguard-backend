"""
Tests for offline_queue.OfflineQueue - the local disk-backed queue
detection_client.py uses to hold count/zone reports that couldn't reach the
server (feature 7, offline resilience).

Pure-stdlib (sqlite3/json/threading only), so unlike detection_client.py
itself this needs none of cv2/numpy/ultralytics/torch to import and test.

Run with:
    python -m unittest discover tests
or, for just this file:
    python -m unittest tests.test_offline_queue -v
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from offline_queue import OfflineQueue  # noqa: E402


class OfflineQueueTests(unittest.TestCase):
    def setUp(self):
        # A fresh temp file per test - each test gets its own empty queue,
        # and Windows/posix both allow reopening the path via sqlite3
        # after closing the handle from mkstemp.
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.remove(self.db_path)  # OfflineQueue.__init__ creates it fresh

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_starts_empty(self):
        q = OfflineQueue(self.db_path)
        self.assertEqual(q.pending_count(), 0)
        self.assertEqual(q.peek_batch(10), [])

    def test_enqueue_increments_pending_count(self):
        q = OfflineQueue(self.db_path)
        q.enqueue({"count": 5, "camera_id": "cam1"})
        q.enqueue({"count": 7, "camera_id": "cam1"})
        self.assertEqual(q.pending_count(), 2)

    def test_peek_batch_is_oldest_first_and_nondestructive(self):
        q = OfflineQueue(self.db_path)
        for i in range(5):
            q.enqueue({"count": i, "camera_id": "cam1"})
        batch = q.peek_batch(3)
        self.assertEqual(len(batch), 3)
        self.assertEqual([payload["count"] for _id, payload in batch], [0, 1, 2])
        # peeking doesn't remove anything
        self.assertEqual(q.pending_count(), 5)

    def test_remove_deletes_only_given_ids(self):
        q = OfflineQueue(self.db_path)
        for i in range(4):
            q.enqueue({"count": i, "camera_id": "cam1"})
        batch = q.peek_batch(2)
        ids = [row_id for row_id, _payload in batch]
        q.remove(ids)
        self.assertEqual(q.pending_count(), 2)
        remaining = q.peek_batch(10)
        self.assertEqual([payload["count"] for _id, payload in remaining], [2, 3])

    def test_remove_empty_list_is_a_noop(self):
        q = OfflineQueue(self.db_path)
        q.enqueue({"count": 1, "camera_id": "cam1"})
        q.remove([])
        self.assertEqual(q.pending_count(), 1)

    def test_ring_buffer_drops_oldest_when_over_capacity(self):
        q = OfflineQueue(self.db_path, max_items=3)
        for i in range(5):
            q.enqueue({"count": i, "camera_id": "cam1"})
        # capped at max_items, and it's the OLDEST entries (0, 1) that got
        # dropped - the most recent readings are what's worth keeping
        self.assertEqual(q.pending_count(), 3)
        remaining = q.peek_batch(10)
        self.assertEqual([payload["count"] for _id, payload in remaining], [2, 3, 4])

    def test_payload_round_trips_through_json(self):
        q = OfflineQueue(self.db_path)
        payload = {
            "count": 12,
            "camera_id": "gate1",
            "client_ts": 1712345678.5,
            "zone_counts": [1, 2, 3, 4],
            "zone_rows": 2,
            "zone_cols": 2,
        }
        q.enqueue(payload)
        [(row_id, stored)] = q.peek_batch(10)
        self.assertIsInstance(row_id, int)
        self.assertEqual(stored, payload)

    def test_survives_reopening_the_same_file(self):
        # A restarted detection_client.py should pick up wherever the
        # queue was left off, not start from empty.
        q1 = OfflineQueue(self.db_path)
        q1.enqueue({"count": 42, "camera_id": "cam1"})

        q2 = OfflineQueue(self.db_path)
        self.assertEqual(q2.pending_count(), 1)
        [(_id, payload)] = q2.peek_batch(10)
        self.assertEqual(payload["count"], 42)


if __name__ == "__main__":
    unittest.main()
