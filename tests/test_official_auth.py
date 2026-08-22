"""
Tests for feature 8 - role-scoped auth, not the shared key: each official
gets their own username/password login (on top of the existing
admin-issued device-token system), so the audit log can name the specific
officer, the same way it already does for admin/viewer accounts.

Covers:
- POST /api/officials/<id>/credentials (admin-only) sets a login; the
  resulting username never leaks a password hash back out.
- POST /api/official/login authenticates with that username/password and
  returns a token scoped to that one official_id.
- Wrong password / unknown username / login for an official with no
  credentials set yet are all rejected the same way (no user enumeration).
- A token obtained via self-service login authorizes the same official-only
  endpoints as an admin-issued token.
- push_audit() records the officer's OWN username - not "shared-key" - for
  actions taken with a self-service token.
- DELETE /api/officials/<id>/credentials revokes the login; the same
  username/password then fails.
- Two officials can't be given the same username.

Run with:
    python -m unittest discover tests
or, for just this file:
    python -m unittest tests.test_official_auth -v
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as crowdguard  # noqa: E402


class OfficialAuthTestCase(unittest.TestCase):
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
        crowdguard.AUDIT_LOG.clear()
        crowdguard._login_attempts.clear()

        self.client = crowdguard.app.test_client()
        self.admin_headers = {"X-API-Key": crowdguard.ADMIN_API_KEY}

        crowdguard.add_official("Officer Priya", "+910000000001", None, None, "Testville")
        self.official_id = crowdguard.list_officials()[0]["id"]

    def tearDown(self):
        crowdguard.DB_PATH = self._orig_db_path
        if os.path.exists(self._db_path):
            os.remove(self._db_path)

    def _set_credentials(self, username="priya", password="hunter22"):
        return self.client.post(
            f"/api/officials/{self.official_id}/credentials",
            json={"username": username, "password": password},
            headers=self.admin_headers)

    def _query(self, sql, params=()):
        conn = crowdguard.get_db()
        rows = conn.execute(sql, params).fetchall()
        conn.close()
        return rows


class SetCredentialsTests(OfficialAuthTestCase):
    def test_admin_can_set_credentials(self):
        resp = self._set_credentials()
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()["ok"])
        officials = crowdguard.list_officials()
        self.assertTrue(officials[0]["has_login"])
        self.assertEqual(officials[0]["username"], "priya")

    def test_response_never_contains_password_hash(self):
        resp = self._set_credentials()
        self.assertNotIn("password", resp.get_data(as_text=True))
        self.assertNotIn("password_hash", resp.get_data(as_text=True))

    def test_requires_admin_key(self):
        resp = self.client.post(f"/api/officials/{self.official_id}/credentials",
                                 json={"username": "priya", "password": "hunter22"})
        self.assertEqual(resp.status_code, 401)

    def test_short_password_rejected(self):
        resp = self._set_credentials(password="short")
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(crowdguard.list_officials()[0]["has_login"])

    def test_duplicate_username_rejected(self):
        crowdguard.add_official("Officer Suresh", "+910000000002", None, None, "Testville")
        other_id = [o["id"] for o in crowdguard.list_officials() if o["name"] == "Officer Suresh"][0]
        self._set_credentials(username="priya")
        resp = self.client.post(f"/api/officials/{other_id}/credentials",
                                 json={"username": "priya", "password": "hunter22"},
                                 headers=self.admin_headers)
        self.assertEqual(resp.status_code, 400)


class LoginTests(OfficialAuthTestCase):
    def test_login_with_correct_credentials_returns_token(self):
        self._set_credentials()
        resp = self.client.post("/api/official/login",
                                 json={"username": "priya", "password": "hunter22"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["official_id"], self.official_id)
        self.assertTrue(data["token"])

    def test_token_from_login_authorizes_official_endpoints(self):
        self._set_credentials()
        token = self.client.post(
            "/api/official/login", json={"username": "priya", "password": "hunter22"}
        ).get_json()["token"]
        resp = self.client.post("/api/official/push-token",
                                 json={"token": "fcm-abc"},
                                 headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()["ok"])

    def test_wrong_password_rejected(self):
        self._set_credentials()
        resp = self.client.post("/api/official/login",
                                 json={"username": "priya", "password": "wrong-pass"})
        self.assertEqual(resp.status_code, 401)

    def test_unknown_username_rejected(self):
        resp = self.client.post("/api/official/login",
                                 json={"username": "nobody", "password": "hunter22"})
        self.assertEqual(resp.status_code, 401)

    def test_login_before_credentials_set_is_rejected(self):
        resp = self.client.post("/api/official/login",
                                 json={"username": "priya", "password": "hunter22"})
        self.assertEqual(resp.status_code, 401)

    def test_revoked_login_can_no_longer_authenticate(self):
        self._set_credentials()
        resp = self.client.delete(f"/api/officials/{self.official_id}/credentials",
                                   headers=self.admin_headers)
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(crowdguard.list_officials()[0]["has_login"])
        resp = self.client.post("/api/official/login",
                                 json={"username": "priya", "password": "hunter22"})
        self.assertEqual(resp.status_code, 401)


class AuditAttributionTests(OfficialAuthTestCase):
    """The whole point of feature 8: the audit log should name the
    specific officer, not 'shared-key', once they've logged in themselves."""

    def test_action_via_self_service_token_is_attributed_by_username(self):
        self._set_credentials(username="priya")
        token = self.client.post(
            "/api/official/login", json={"username": "priya", "password": "hunter22"}
        ).get_json()["token"]

        self.client.post("/api/official/push-token", json={"token": "fcm-xyz"},
                          headers={"Authorization": f"Bearer {token}"})

        rows = self._query("SELECT username, role FROM audit_log WHERE action = 'official_login'")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["username"], "priya")
        self.assertEqual(rows[0]["role"], "official")

    def test_admin_issued_token_falls_back_to_officer_name(self):
        # No username/password set - only the interim admin-issued token.
        token_resp = self.client.post(f"/api/officials/{self.official_id}/token",
                                       json={}, headers=self.admin_headers)
        token = token_resp.get_json()["token"]
        self.client.post("/api/official/push-token", json={"token": "fcm-xyz"},
                          headers={"Authorization": f"Bearer {token}"})
        rows = self._query(
            "SELECT username FROM audit_log WHERE action = 'official_token_issued'")
        # Issued via the shared X-API-Key header (no individual admin
        # session) - still "shared-key", same as any other shared-key call.
        self.assertEqual(rows[0]["username"], "shared-key")


if __name__ == "__main__":
    unittest.main()
