"""
Offline resilience (feature 7) - local disk-backed queue for reports that
couldn't reach the server, used by detection_client.py.

Deliberately kept in its own module with only stdlib dependencies (sqlite3,
json, threading, time) - detection_client.py additionally needs cv2/numpy/
ultralytics/torch just to run, none of which this class needs, so keeping
it separate means it can be imported and unit-tested (see
tests/test_offline_queue.py) without any of that heavier stack installed.
"""

import json
import sqlite3
import threading
import time


class OfflineQueue:
    """Local, disk-backed queue for count/zone reports that couldn't reach
    the server. Deliberately simple (one SQLite table, oldest-first) since
    the failure mode it's protecting against is short/occasional network
    gaps, not an indefinitely offline device - the ring-buffer cap in
    enqueue() keeps a long outage bounded rather than trying to remember
    every reading forever.

    Frames are intentionally never queued: they're the bulkiest part of a
    report by far, and only the dashboard's live view needs one - nothing
    analytical (history/analytics charts, alerts, SMS) depends on a frame
    image from ten minutes ago the way it depends on the count itself.
    That decision lives in the caller (detection_client.py's send_update);
    this class just stores whatever dict it's given.
    """

    def __init__(self, db_path, max_items=5000):
        self.db_path = db_path
        self.max_items = max_items
        self.lock = threading.Lock()
        conn = self._connect()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS pending_updates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payload TEXT NOT NULL,
                created_ts REAL NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    def _connect(self):
        return sqlite3.connect(self.db_path, check_same_thread=False, timeout=5)

    def enqueue(self, payload: dict):
        with self.lock:
            conn = self._connect()
            conn.execute("INSERT INTO pending_updates (payload, created_ts) VALUES (?, ?)",
                         (json.dumps(payload), time.time()))
            total = conn.execute("SELECT COUNT(*) FROM pending_updates").fetchone()[0]
            if total > self.max_items:
                excess = total - self.max_items
                conn.execute(
                    "DELETE FROM pending_updates WHERE id IN "
                    "(SELECT id FROM pending_updates ORDER BY id ASC LIMIT ?)", (excess,))
                print(f"\n[offline] queue exceeded {self.max_items} pending reports - "
                      f"dropped the {excess} oldest")
            conn.commit()
            conn.close()

    def pending_count(self) -> int:
        with self.lock:
            conn = self._connect()
            n = conn.execute("SELECT COUNT(*) FROM pending_updates").fetchone()[0]
            conn.close()
            return n

    def peek_batch(self, limit: int):
        """Oldest-first, without removing them - removal only happens once
        the server has actually confirmed it received the batch."""
        with self.lock:
            conn = self._connect()
            rows = conn.execute(
                "SELECT id, payload FROM pending_updates ORDER BY id ASC LIMIT ?", (limit,)).fetchall()
            conn.close()
            return [(row[0], json.loads(row[1])) for row in rows]

    def remove(self, ids):
        if not ids:
            return
        with self.lock:
            conn = self._connect()
            conn.executemany("DELETE FROM pending_updates WHERE id = ?", [(i,) for i in ids])
            conn.commit()
            conn.close()
