"""
Tests for the server-side half of offline resilience (feature 7):

- POST /api/update/batch - every item except the last is backfilled into
  `history` only; the last item runs the full live pipeline (current_count/
  risk/alerts), same as a normal /api/update.
- client_id idempotency on /api/alerts/<id>/ack and /api/official/report -
  retrying the same client_id replays the original result instead of
  recording a duplicate ack or a duplicate incident report.

Requires the full stack in requirements.txt (flask, flask-socketio, pyjwt)
since, unlike tests/test_logic.py's pure functions, these exercise real
Flask routes end-to-end via app.test_client().

Run with:
    python -m unittest discover tests
or, for just this file:
    python -m unittest tests.test_offline_sync -v
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as crowdguard  # noqa: E402


class OfflineSyncTestCase(unittest.TestCase):
    """Common setup: a fresh temp SQLite file per test (so tests can't see
    each other's rows) and a clean in-memory CAMERAS/ALERTS state."""

    def setUp(self):
        fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.remove(db_path)
        self._db_path = db_path
        self._orig_db_path = crowdguard.DB_PATH
        crowdguard.DB_PATH = db_path
        crowdguard.init_db()

        crowdguard.CAMERAS.clear()
        crowdguard.ALERTS.clear()

        self.client = crowdguard.app.test_client()
        self.admin_headers = {"X-API-Key": crowdguard.ADMIN_API_KEY}

    def tearDown(self):
        crowdguard.DB_PATH = self._orig_db_path
        if os.path.exists(self._db_path):
            os.remove(self._db_path)

    def _query(self, sql, params=()):
        conn = crowdguard.get_db()
        rows = conn.execute(sql, params).fetchall()
        conn.close()
        return rows


class UpdateBatchTests(OfflineSyncTestCase):
    def test_only_last_item_updates_live_state(self):
        camera_id = "batch-cam"
        items = [
            {"count": 5, "camera_id": camera_id, "client_ts": 1000.0},
            {"count": 9, "camera_id": camera_id, "client_ts": 1005.0},
            {"count": 14, "camera_id": camera_id, "client_ts": 1010.0},
        ]
        resp = self.client.post("/api/update/batch", json={"items": items},
                                 headers=self.admin_headers)
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["processed"], 3)
        self.assertTrue(all(r["ok"] for r in body["results"]))

        # Only the LAST item's count should be reflected in current state -
        # the earlier two were stale-by-the-time-they-synced readings.
        self.assertEqual(crowdguard.CAMERAS[camera_id]["current_count"], 14)

        # But all three should have landed in history, at their own
        # client_ts, so the Analytics tab doesn't have a hole for the
        # outage that caused them to queue in the first place.
        rows = self._query(
            "SELECT ts, count FROM history WHERE camera_id = ? ORDER BY ts", (camera_id,))
        self.assertEqual([r["count"] for r in rows], [5, 9, 14])
        self.assertEqual([r["ts"] for r in rows], [1000.0, 1005.0, 1010.0])

    def test_backfilled_items_do_not_raise_alerts(self):
        # A count high enough to be CRITICAL, but queued as a STALE (non-
        # last) item - shouldn't fire an alert for something that already
        # happened and, per the actual live pipeline, may already have
        # been handled (or superseded) by the time it synced.
        camera_id = "batch-cam-2"
        crowdguard.get_or_create_camera(camera_id)
        crowdguard.CAMERAS[camera_id]["max_capacity"] = 10
        items = [
            {"count": 50, "camera_id": camera_id, "client_ts": 2000.0},  # stale, backfilled only
            {"count": 1, "camera_id": camera_id, "client_ts": 2010.0},   # "now" - back to SAFE
        ]
        resp = self.client.post("/api/update/batch", json={"items": items},
                                 headers=self.admin_headers)
        self.assertEqual(resp.status_code, 200)
        alerts = self._query("SELECT severity FROM alerts")
        self.assertEqual(len(alerts), 0)
        self.assertEqual(crowdguard.CAMERAS[camera_id]["current_count"], 1)
        self.assertEqual(crowdguard.CAMERAS[camera_id]["risk_level"], "SAFE")

    def test_requires_admin_or_device_auth(self):
        resp = self.client.post("/api/update/batch",
                                 json={"items": [{"count": 1, "camera_id": "x"}]})
        self.assertEqual(resp.status_code, 401)

    def test_rejects_empty_or_oversized_batches(self):
        resp = self.client.post("/api/update/batch", json={"items": []},
                                 headers=self.admin_headers)
        self.assertEqual(resp.status_code, 400)

        too_many = [{"count": 1, "camera_id": "x"}] * (crowdguard.MAX_BATCH_UPDATE_ITEMS + 1)
        resp = self.client.post("/api/update/batch", json={"items": too_many},
                                 headers=self.admin_headers)
        self.assertEqual(resp.status_code, 400)


class OfficialAckIdempotencyTests(OfflineSyncTestCase):
    def _make_official_and_token(self):
        crowdguard.add_official("Officer Test", "+910000000000", None, None, "Testville")
        officials = crowdguard.list_officials()
        official_id = officials[0]["id"]
        token = crowdguard.issue_official_token(official_id, hours=1)
        return official_id, token

    def test_repeated_client_id_does_not_duplicate_ack(self):
        alert_id = crowdguard.push_alert("test alert", "WARNING", "cam1", "Cam 1")
        official_id, token = self._make_official_and_token()
        headers = {"Authorization": f"Bearer {token}"}

        payload = {"status": "acknowledged", "client_id": "queued-ack-1"}
        resp1 = self.client.post(f"/api/alerts/{alert_id}/ack", json=payload, headers=headers)
        self.assertEqual(resp1.status_code, 200)
        ack1 = resp1.get_json()["ack"]

        # Simulate the mobile app retrying because it never saw the first
        # response (classic "queued while offline" scenario) - same
        # client_id, sent again.
        resp2 = self.client.post(f"/api/alerts/{alert_id}/ack", json=payload, headers=headers)
        self.assertEqual(resp2.status_code, 200)
        ack2 = resp2.get_json()["ack"]

        self.assertEqual(ack1, ack2)
        rows = self._query("SELECT * FROM alert_acks WHERE alert_id = ?", (alert_id,))
        self.assertEqual(len(rows), 1)

    def test_different_client_id_creates_a_new_ack(self):
        alert_id = crowdguard.push_alert("test alert", "WARNING", "cam1", "Cam 1")
        official_id, token = self._make_official_and_token()
        headers = {"Authorization": f"Bearer {token}"}

        self.client.post(f"/api/alerts/{alert_id}/ack",
                          json={"status": "acknowledged", "client_id": "ack-a"}, headers=headers)
        self.client.post(f"/api/alerts/{alert_id}/ack",
                          json={"status": "en_route", "client_id": "ack-b"}, headers=headers)

        rows = self._query("SELECT status FROM alert_acks WHERE alert_id = ? ORDER BY ts", (alert_id,))
        self.assertEqual([r["status"] for r in rows], ["acknowledged", "en_route"])


class OfficialReportIdempotencyTests(OfflineSyncTestCase):
    def _make_official_and_token(self):
        crowdguard.add_official("Officer Test", "+910000000000", None, None, "Testville")
        official_id = crowdguard.list_officials()[0]["id"]
        token = crowdguard.issue_official_token(official_id, hours=1)
        return official_id, token

    def test_repeated_client_id_does_not_duplicate_report(self):
        official_id, token = self._make_official_and_token()
        headers = {"Authorization": f"Bearer {token}"}
        payload = {"message": "Crowd surge at Gate 2", "client_id": "queued-report-1"}

        resp1 = self.client.post("/api/official/report", json=payload, headers=headers)
        self.assertEqual(resp1.status_code, 200)
        alert_id_1 = resp1.get_json()["alert_id"]

        resp2 = self.client.post("/api/official/report", json=payload, headers=headers)
        self.assertEqual(resp2.status_code, 200)
        alert_id_2 = resp2.get_json()["alert_id"]

        self.assertEqual(alert_id_1, alert_id_2)
        rows = self._query("SELECT * FROM alerts WHERE severity = 'REPORT'")
        self.assertEqual(len(rows), 1)


class SyncQueueBatchTests(OfflineSyncTestCase):
    def test_mixed_ack_and_report_batch(self):
        crowdguard.add_official("Officer Test", "+910000000000", None, None, "Testville")
        official_id = crowdguard.list_officials()[0]["id"]
        token = crowdguard.issue_official_token(official_id, hours=1)
        headers = {"Authorization": f"Bearer {token}"}

        alert_id = crowdguard.push_alert("test alert", "WARNING", "cam1", "Cam 1")
        items = [
            {"type": "ack", "alert_id": alert_id, "status": "acknowledged", "client_id": "sq-1"},
            {"type": "report", "message": "Fire near Gate 3", "client_id": "sq-2"},
        ]
        resp = self.client.post("/api/official/sync-queue", json={"items": items}, headers=headers)
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["processed"], 2)
        self.assertTrue(all(r["ok"] for r in body["results"]))

        # Retrying the whole batch (e.g. the app lost signal again before
        # reading the response) must not duplicate either item.
        resp2 = self.client.post("/api/official/sync-queue", json={"items": items}, headers=headers)
        self.assertEqual(resp2.status_code, 200)
        acks = self._query("SELECT * FROM alert_acks WHERE alert_id = ?", (alert_id,))
        reports = self._query("SELECT * FROM alerts WHERE severity = 'REPORT'")
        self.assertEqual(len(acks), 1)
        self.assertEqual(len(reports), 1)


if __name__ == "__main__":
    unittest.main()
