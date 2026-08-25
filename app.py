# Railway optimized version
"""
CROWD GUARD 3.0 - Live Backend Server (multi-camera, SQLite persistence)
----------------------------------------------------------------------
Receives real people-count data from one or more detection_client.py
instances (each running YOLO on its own camera feed) and broadcasts it
live to every connected dashboard.

NEW in this version:
  - Multi-camera support: each detection_client.py tags its posts with a
    camera_id. The dashboard aggregates all cameras into one combined risk
    level and lets you switch the live-feed panel between cameras.
  - Individual admin/viewer accounts (username + password) on top of the
    original shared-key auth, so the audit log can say WHO did something,
    not just "an admin". The shared ADMIN_API_KEY/VIEWER_API_KEY still
    work for machine clients (detection_client.py) and as a login fallback.
  - Configurable alert/SMS cooldown windows, editable from the dashboard
    instead of only in code.
  - Day-over-day history comparison (/api/history/compare).
  - Coarse zone/grid density: detection_client.py can report a per-cell
    person count (e.g. a 3x3 grid) alongside the total, so a local crush
    near one exit isn't hidden inside a venue-wide average.

Run this FIRST, then run detection_client.py separately (once per camera).
"""

import base64
import csv
import io
import json
import math
import os
import re
import secrets
import sqlite3
import sys
import time
from collections import deque

ASSET_VERSION = str(int(time.time()))
from functools import wraps

from flask import (Flask, jsonify, render_template, request, Response,
                    session, redirect, url_for)
from flask_socketio import SocketIO
from werkzeug.security import generate_password_hash, check_password_hash

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["PERMANENT_SESSION_LIFETIME"] = int(os.environ.get("SESSION_LIFETIME_SECONDS", 12 * 3600))
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_CONTENT_LENGTH_MB", 8)) * 1024 * 1024


@app.errorhandler(413)
def _payload_too_large(_e):
    return jsonify({"ok": False, "error": "Request body too large."}), 413


@app.route("/health")
def health_check():
    """Simple health check for cloud platforms like Railway."""
    return jsonify({"status": "healthy", "ts": time.time()}), 200


socketio = SocketIO(app, cors_allowed_origins="*", async_mode="gevent")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "crowdguard.db")

DEFAULT_CAMERA_ID = "cam1"
RISK_ORDER = {"SAFE": 0, "WARNING": 1, "CRITICAL": 2}

# Plain-language version of the same risk signal (feature: "Crowd Level"
# wording for operators who scan faster on LOW/MEDIUM/HIGH than on
# SAFE/WARNING/CRITICAL). Deliberately NOT a separate metric or a separate
# color - same computed risk, same red/amber/green, just relabeled text -
# two badges with different color codes for the same underlying number
# would be more confusing than helpful.
CROWD_LEVEL_LABEL = {"SAFE": "LOW", "WARNING": "MEDIUM", "CRITICAL": "HIGH"}

# ---------------------------------------------------------------------------
# Auth - two layers that coexist:
#   1. Shared keys (ADMIN_API_KEY / VIEWER_API_KEY) - unchanged from before.
#      Still required for machine clients (detection_client.py -> X-API-Key
#      header) and still works as a login fallback (leave username blank).
#   2. Individual accounts (users table, username+password) - NEW. Lets the
#      audit log attribute an action to a specific person instead of just
#      "admin" or "viewer". Bootstrapped automatically on first run (see
#      bootstrap_default_users below) so a fresh checkout still logs in
#      out of the box with zero setup.
# ---------------------------------------------------------------------------
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY")
if not ADMIN_API_KEY:
    ADMIN_API_KEY = secrets.token_hex(24)
    print("\n" + "=" * 70)
    print("[warning] ADMIN_API_KEY not set - generated one for THIS RUN ONLY:")
    print(f"    {ADMIN_API_KEY}")
    print("Use this to log in at /login (username 'admin'), and to configure")
    print("detection_client.py. It will be DIFFERENT next restart.")
    print("Set ADMIN_API_KEY yourself in the environment/.env for a stable value.")
    print("=" * 70 + "\n")

VIEWER_API_KEY = os.environ.get("VIEWER_API_KEY")

# ---------------------------------------------------------------------------
# Device tokens (JWT) - a narrower alternative to ADMIN_API_KEY for
# detection_client.py instances specifically. Where the shared admin key can
# do anything (change thresholds, manage users, trigger panic demos), a
# device token issued here can ONLY post headcounts for the one camera_id it
# was issued for, and expires on its own. Useful once you have more than one
# camera: each gets its own revocable credential instead of every device
# sharing the one all-powerful key. Optional - /api/update still accepts the
# shared key too, so nothing breaks if you don't use this.
try:
    import jwt as pyjwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False

JWT_SECRET = os.environ.get("JWT_SECRET") or app.config["SECRET_KEY"]
JWT_ALGO = "HS256"


def issue_device_token(camera_id: str, hours: float = 24) -> str:
    payload = {"camera_id": camera_id, "scope": "device",
               "iat": time.time(), "exp": time.time() + hours * 3600}
    return pyjwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def verify_device_token(token: str, camera_id: str) -> bool:
    """True only if `token` is a currently-valid device token issued for
    EXACTLY this camera_id - a token for camera A can't be replayed to post
    updates for camera B."""
    if not JWT_AVAILABLE:
        return False
    try:
        payload = pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except Exception:
        return False  # expired, malformed, or wrong secret
    return payload.get("scope") == "device" and payload.get("camera_id") == camera_id


# ---------------------------------------------------------------------------
# Official tokens (JWT) - same idea as the per-camera device token above,
# but issued to one official for the mobile app. Scoped to that one
# official_id only (can't register a push token or ack an alert as anyone
# else), and expires on its own. Verification doesn't care how the token
# was obtained, which is what lets feature 8 (role-scoped auth) add a real
# per-official username/password login (POST /api/official/login) as the
# normal way to get one, alongside the admin-issued fallback
# (POST /api/officials/<id>/token), without changing anything below.
def issue_official_token(official_id: int, hours: float = 24 * 30) -> str:
    payload = {"official_id": official_id, "scope": "official",
               "iat": time.time(), "exp": time.time() + hours * 3600}
    return pyjwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def verify_official_token(token: str):
    """Returns the official_id encoded in `token` if it's a currently-valid
    official token, else None."""
    if not JWT_AVAILABLE or not token:
        return None
    try:
        payload = pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except Exception:
        return None  # expired, malformed, or wrong secret
    if payload.get("scope") != "official":
        return None
    return payload.get("official_id")


def require_official_token(view_func):
    """Auth for the official mobile app's own endpoints (register push
    token, ack an alert) - separate from require_admin_key/
    require_viewer_or_admin, which are for the admin dashboard. Expects
    `Authorization: Bearer <token>` from /api/officials/<id>/token."""
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not JWT_AVAILABLE:
            return jsonify({"ok": False, "error": "PyJWT isn't installed on the server "
                             "(pip install pyjwt) - official tokens aren't available."}), 501
        auth = request.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else request.headers.get("X-Official-Token")
        official_id = verify_official_token(token)
        if official_id is None:
            return jsonify({"ok": False, "error": "Missing or expired official token."}), 401
        request.official_id = official_id
        # Resolve who this actually is, for push_audit() - prefer their own
        # login username; fall back to their plain name if this token was
        # admin-issued (interim /token endpoint) rather than from a real
        # login, so the audit log still names a person, not just an id.
        official_row = get_official(official_id)
        if official_row is not None:
            request.official_username = official_row["username"] if "username" in official_row.keys() and official_row["username"] else official_row["name"]
            request.official_name = official_row["name"]
        else:
            request.official_username = None
            request.official_name = None
        return view_func(*args, **kwargs)
    return wrapped

MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SEC = 300
_login_attempts = {}


def _login_rate_limited(ip: str) -> bool:
    now = time.time()
    attempts = [t for t in _login_attempts.get(ip, []) if now - t < LOGIN_WINDOW_SEC]
    _login_attempts[ip] = attempts
    return len(attempts) >= MAX_LOGIN_ATTEMPTS


def _record_login_failure(ip: str):
    _login_attempts.setdefault(ip, []).append(time.time())


def _authorized_role():
    """Returns 'admin', 'viewer', or None for this request - checks the
    browser session first, then a supplied shared key (header/query param)
    for machine clients."""
    role = session.get("role")
    if role in ("admin", "viewer"):
        return role
    supplied = request.headers.get("X-API-Key") or request.args.get("key")
    if not supplied:
        return None
    if secrets.compare_digest(supplied, ADMIN_API_KEY):
        return "admin"
    if VIEWER_API_KEY and secrets.compare_digest(supplied, VIEWER_API_KEY):
        return "viewer"
    return None


def _is_authorized() -> bool:
    return _authorized_role() is not None


def _current_username() -> str:
    return session.get("username") or "shared-key"


_UNAUTHORIZED_RESPONSE = ({"ok": False, "error": "Unauthorized - log in at /login, "
                           "or send a valid X-API-Key header/?key= param."}, 401)


def require_admin_key(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        role = _authorized_role()
        if role is None:
            body, code = _UNAUTHORIZED_RESPONSE
            return jsonify(body), code
        if role != "admin":
            return jsonify({"ok": False, "error": "This action requires an "
                             "admin key - viewer sessions are read-only."}), 403
        return view_func(*args, **kwargs)
    return wrapped


def require_viewer_or_admin(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if _authorized_role() is None:
            body, code = _UNAUTHORIZED_RESPONSE
            return jsonify(body), code
        return view_func(*args, **kwargs)
    return wrapped


def require_official_or_dashboard(view_func):
    """Accepts EITHER an official's own Bearer token (mobile app) OR an
    admin/viewer dashboard session/key - for endpoints both sides need to
    read. Used by GET /api/roster/now: the officer app's Roster screen only
    ever has an official token (never an admin/viewer session), and
    require_viewer_or_admin alone made this endpoint unreachable from the
    mobile app despite the README documenting it as mobile-facing. Sets
    request.official_id when the caller authenticated as an official (None
    for a dashboard caller), same as require_official_token, in case a
    future handler wants to scope its response by who's asking."""
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else request.headers.get("X-Official-Token")
        official_id = verify_official_token(token) if token else None
        if official_id is not None:
            request.official_id = official_id
            return view_func(*args, **kwargs)
        if _authorized_role() is not None:
            request.official_id = None
            return view_func(*args, **kwargs)
        return jsonify({"ok": False, "error": "Unauthorized - log in at /login, send a valid "
                         "X-API-Key header/?key= param, or a valid official Bearer token."}), 401
    return wrapped


def require_web_session(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("authorized"):
            supplied = request.args.get("key")
            role = None
            if supplied and secrets.compare_digest(supplied, ADMIN_API_KEY):
                role = "admin"
            elif supplied and VIEWER_API_KEY and secrets.compare_digest(supplied, VIEWER_API_KEY):
                role = "viewer"
            if role:
                session.permanent = True
                session["authorized"] = True
                session["role"] = role
                session["username"] = "shared-key"
            else:
                return redirect(url_for("login", next=request.path))
        return view_func(*args, **kwargs)
    return wrapped


@socketio.on("connect")
def _socketio_require_auth():
    if not session.get("authorized"):
        return False

# ---------------------------------------------------------------------------
# SMS (Twilio) credentials
# ---------------------------------------------------------------------------
TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
TWILIO_FROM_NUMBER = os.environ.get("TWILIO_FROM_NUMBER")

# ---------------------------------------------------------------------------
# Push notifications (Firebase Cloud Messaging) for the official mobile app.
# This is ADDITIVE to SMS, never a replacement - send_push_alert() below is
# always called alongside send_sms_alert(), not instead of it, so an
# official with no app installed (no push_token on file) still only ever
# relies on SMS, exactly as before this feature existed.
# ---------------------------------------------------------------------------
FCM_SERVER_KEY = os.environ.get("FCM_SERVER_KEY")

# ---------------------------------------------------------------------------
# Global settings (shared across every camera) + per-camera state.
# ---------------------------------------------------------------------------
STATE = {
    "warning_pct": 60,
    "critical_pct": 85,
    "default_max_capacity": 10000,  # used for a camera the first time it's seen

    "ratio_safe": 40,
    "ratio_warning": 25,
    "ratio_critical": 12,
    "min_officers": 2,

    "officials_phone": "",

    # Configurable alert/SMS re-trigger windows (feature: alert cooldown).
    # alert_cooldown gates on-screen Threat Timeline entries; sms_cooldown
    # is kept longer by default so a sustained WARNING/CRITICAL period
    # doesn't spam officials' phones while the on-screen timeline still
    # updates more often. Both editable from Alerts & Controls.
    "alert_cooldown": 30,
    "sms_cooldown": 120,

    "last_history_save": 0,
    "history_save_interval": 1.0,
}

# camera_id -> per-camera live state. Created on first /api/update or
# /api/config touch for that camera_id (see get_or_create_camera).
CAMERAS = {}
LATEST_FRAMES = {}              # camera_id -> last annotated JPEG bytes
ALERTS = deque(maxlen=80)       # {time, message, severity, camera_id, camera_label}
SMS_LOG = deque(maxlen=50)      # {time, to, message, sent, detail}
AUDIT_LOG = deque(maxlen=150)   # {time, role, username, ip, action, details}


def get_or_create_camera(camera_id: str, label: str = None):
    cam = CAMERAS.get(camera_id)
    if cam is None:
        cam = {
            "camera_id": camera_id,
            "label": label or camera_id,
            "latitude": None,
            "longitude": None,
            "max_capacity": STATE["default_max_capacity"],
            "current_count": 0,
            "risk_level": "SAFE",
            "recommended_police": 0,
            "police_reason": "",
            "clearance_plan": [],
            "zone_counts": [],
            "zone_rows": 0,
            "zone_cols": 0,
            "history": deque(maxlen=300),
            "last_seen": 0,
            "last_alert_time": 0,
            "last_sms_time": 0,
            "last_history_save": 0,
        }
        CAMERAS[camera_id] = cam
    if label and not cam.get("_label_set"):
        cam["label"] = label
        cam["_label_set"] = True
    return cam


CAMERA_STALE_AFTER_SEC = 15  # a camera not heard from in this long doesn't
                              # count toward the combined/venue-wide risk


def combined_risk_level():
    """Highest risk tier among cameras that have posted recently. A camera
    that's gone stale (detection_client.py crashed / lost the feed) drops
    out of the combined figure instead of freezing it at its last value."""
    now = time.time()
    best = "SAFE"
    for cam in CAMERAS.values():
        if now - cam["last_seen"] > CAMERA_STALE_AFTER_SEC:
            continue
        if RISK_ORDER.get(cam["risk_level"], 0) > RISK_ORDER.get(best, 0):
            best = cam["risk_level"]
    return best


def combined_current_count():
    now = time.time()
    return sum(c["current_count"] for c in CAMERAS.values()
               if now - c["last_seen"] <= CAMERA_STALE_AFTER_SEC)


def camera_summary(cam):
    now = time.time()
    return {
        "camera_id": cam["camera_id"],
        "label": cam["label"],
        "current_count": cam["current_count"],
        "max_capacity": cam["max_capacity"],
        "risk_level": cam["risk_level"],
        "latitude": cam["latitude"],
        "longitude": cam["longitude"],
        "zone_counts": cam["zone_counts"],
        "zone_rows": cam["zone_rows"],
        "zone_cols": cam["zone_cols"],
        "online": (now - cam["last_seen"]) <= CAMERA_STALE_AFTER_SEC,
        "last_seen_ago": round(now - cam["last_seen"], 1) if cam["last_seen"] else None,
    }


# ---------------------------------------------------------------------------
# SQLite persistence
# ---------------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS history (
            ts REAL, count INTEGER, risk TEXT, camera_id TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            ts REAL, time TEXT, message TEXT, severity TEXT, camera_id TEXT,
            location TEXT, action TEXT, recommendation TEXT
        )
    """)
    # Migration for databases created before location/action/recommendation
    # existed - SQLite has no "ADD COLUMN IF NOT EXISTS", so just try each
    # and ignore the error if the column is already there.
    for col in ("location TEXT", "action TEXT", "recommendation TEXT"):
        try:
            conn.execute(f"ALTER TABLE alerts ADD COLUMN {col}")
        except sqlite3.OperationalError:
            pass  # column already exists - fine
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sms_log (
            ts REAL, time TEXT, recipients TEXT, message TEXT, sent INTEGER, detail TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY, value TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS camera_settings (
            camera_id TEXT PRIMARY KEY, label TEXT, latitude REAL,
            longitude REAL, max_capacity REAL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            ts REAL, time TEXT, role TEXT, username TEXT, ip TEXT,
            action TEXT, details TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            created_ts REAL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS officials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            latitude REAL,
            longitude REAL,
            created_ts REAL
        )
    """)
    # Migration for databases created before "location" (locality name,
    # e.g. "Tambaram") existed on officials.
    try:
        conn.execute("ALTER TABLE officials ADD COLUMN location TEXT")
    except sqlite3.OperationalError:
        pass  # column already exists - fine
    # Migration for the official mobile app: a push token (FCM registration
    # id) so alerts can be pushed to that official's phone, alongside -
    # never instead of - the existing SMS. NULL until the official logs
    # into the app and registers one.
    try:
        conn.execute("ALTER TABLE officials ADD COLUMN push_token TEXT")
    except sqlite3.OperationalError:
        pass  # column already exists - fine
    # Migration for the official mobile app's live situational view
    # (feature 3): which camera this official is assigned to watch. NULL
    # means "not assigned to one in particular" - the scoped view then
    # falls back to all cameras (still read-only, still no admin controls).
    try:
        conn.execute("ALTER TABLE officials ADD COLUMN assigned_camera_id TEXT")
    except sqlite3.OperationalError:
        pass  # column already exists - fine
    # Migration for GPS-based officer assignment (feature 4): whether this
    # official is currently available for dispatch. Defaults to 1 (on
    # duty) so existing officials keep showing up in "nearest officer"
    # results exactly as before this column existed.
    try:
        conn.execute("ALTER TABLE officials ADD COLUMN on_duty INTEGER DEFAULT 1")
    except sqlite3.OperationalError:
        pass  # column already exists - fine
    # Migration for role-scoped auth (feature 8): each official can have
    # their own username + password, the same login model as the admin/
    # viewer `users` table above, instead of every officer's phone sharing
    # one admin-issued token. NULL until an admin sets credentials for
    # that officer (or the officer hasn't been migrated yet) - the
    # admin-issued /token endpoint keeps working as a fallback for anyone
    # without a username/password set, so nothing breaks for existing
    # officials.
    try:
        conn.execute("ALTER TABLE officials ADD COLUMN username TEXT")
    except sqlite3.OperationalError:
        pass  # column already exists - fine
    try:
        conn.execute("ALTER TABLE officials ADD COLUMN password_hash TEXT")
    except sqlite3.OperationalError:
        pass  # column already exists - fine
    # Partial unique index (NULLs excluded) - many officials can have no
    # username yet, but no two can claim the same one.
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_officials_username "
        "ON officials(username) WHERE username IS NOT NULL")
    # Shift/duty roster (feature 9): which official is scheduled to cover
    # which zone/gate (camera_id) and when, so the "nearest available"
    # dispatch logic (feature 4) can prefer whoever is actually SUPPOSED to
    # be at that gate right now over someone who merely happens to be
    # standing closer at this instant. day_of_week is 0 (Monday) - 6
    # (Sunday), matching time.localtime().tm_wday; NULL means "every day".
    # start_time/end_time are 24-hour "HH:MM" strings; an end_time earlier
    # than start_time is an overnight shift that crosses midnight (e.g.
    # 22:00-06:00). This is purely a schedule - it never overrides an
    # officer's own on_duty toggle or replaces their live GPS ping, it just
    # adds a "should be here right now" signal on top of both.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS duty_roster (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            official_id INTEGER NOT NULL,
            camera_id TEXT NOT NULL,
            day_of_week INTEGER,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            created_ts REAL
        )
    """)
    # Live location (feature 4) - separate from the static latitude/
    # longitude on `officials` (which is the official's registered duty
    # post/locality, set once by the admin). This table holds each
    # official's most recent GPS ping from the mobile app, sent only with
    # their explicit consent. One row per official (latest ping only, not
    # a location history log) - upserted on every /api/official/location
    # call, same "just the current value" pattern as push_token.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS official_locations (
            official_id INTEGER PRIMARY KEY,
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            accuracy_m REAL,
            ts REAL,
            time TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS push_log (
            ts REAL, time TEXT, recipients TEXT, message TEXT, sent INTEGER, detail TEXT
        )
    """)
    # Acknowledge/respond workflow: one row per official action on a given
    # alert (Acknowledged / En Route / On Site / Resolved). alert_id is the
    # SQLite rowid of the corresponding row in `alerts` - that table has no
    # explicit INTEGER PRIMARY KEY, but every SQLite table has an implicit
    # rowid unless created WITHOUT ROWID, so it's a stable reference without
    # needing to migrate the alerts table itself.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alert_acks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER NOT NULL,
            official_id INTEGER NOT NULL,
            official_name TEXT,
            status TEXT NOT NULL,
            ts REAL,
            time TEXT
        )
    """)
    # Two-way incident reporting (feature 5) - an official-submitted alert
    # (e.g. "Crowd surge at Gate 2") is a normal row in `alerts` itself, so
    # it shows up in the Alerts tab and CSV export with zero extra code
    # there. Only the optional photo needs its own table, kept separate so
    # a plain GET of the alerts list never has to drag a base64 blob along
    # for alerts that don't have one.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alert_photos (
            alert_id INTEGER PRIMARY KEY,
            photo_b64 TEXT NOT NULL,
            content_type TEXT,
            ts REAL
        )
    """)
    # Offline resilience (feature 7): the official mobile app queues acks
    # and incident reports locally while signal is patchy, then retries
    # each one (individually via /api/alerts/<id>/ack + /api/official/report,
    # or in bulk via /api/official/sync-queue) until the server confirms
    # it. A retried request needs to be safe to receive twice - e.g. the
    # app got the request through but never saw the response before losing
    # signal again - so every one of those calls carries a client-generated
    # client_id, and this table remembers which client_ids have already
    # been processed and what the result was, so a repeat is answered with
    # the SAME result instead of creating a duplicate ack/incident report.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS offline_sync_log (
            client_id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            official_id INTEGER,
            result_json TEXT NOT NULL,
            ts REAL
        )
    """)
    conn.commit()
    conn.close()


def bootstrap_default_users():
    """First run only: auto-provisions an 'admin' account (password =
    ADMIN_API_KEY) and, if set, a 'viewer' account (password =
    VIEWER_API_KEY), so a fresh checkout keeps working with zero setup
    while individual accounts can be added on top via Alerts & Controls."""
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
    if count == 0:
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_ts) VALUES (?, ?, ?, ?)",
            ("admin", generate_password_hash(ADMIN_API_KEY), "admin", time.time()))
        if VIEWER_API_KEY:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_ts) VALUES (?, ?, ?, ?)",
                ("viewer", generate_password_hash(VIEWER_API_KEY), "viewer", time.time()))
        conn.commit()
    conn.close()


def find_user(username):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return row


def list_users():
    conn = get_db()
    rows = conn.execute("SELECT username, role, created_ts FROM users ORDER BY created_ts").fetchall()
    conn.close()
    return [{"username": r["username"], "role": r["role"], "created_ts": r["created_ts"]} for r in rows]


def create_user(username, password, role):
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_ts) VALUES (?, ?, ?, ?)",
            (username, generate_password_hash(password), role, time.time()))
        conn.commit()
        return True, None
    except sqlite3.IntegrityError:
        return False, "That username already exists."
    finally:
        conn.close()


def delete_user(username):
    conn = get_db()
    conn.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    conn.close()


def list_officials():
    conn = get_db()
    rows = conn.execute("SELECT * FROM officials ORDER BY created_ts").fetchall()
    roster_rows = conn.execute("SELECT * FROM duty_roster").fetchall()
    conn.close()

    # Which camera_id (if any) each official's roster currently has them
    # scheduled for right now - shown as a badge in Alerts & Controls so an
    # admin can see roster coverage without opening the roster panel.
    now_struct = time.localtime()
    on_shift_camera = {}
    for r in roster_rows:
        if r["official_id"] not in on_shift_camera and \
                _shift_is_active(r["day_of_week"], r["start_time"], r["end_time"], now_struct):
            on_shift_camera[r["official_id"]] = r["camera_id"]

    return [{"id": r["id"], "name": r["name"], "phone": r["phone"],
              "latitude": r["latitude"], "longitude": r["longitude"],
              "location": r["location"] if "location" in r.keys() else None,
              "has_push_token": bool(r["push_token"]) if "push_token" in r.keys() else False,
              "assigned_camera_id": r["assigned_camera_id"] if "assigned_camera_id" in r.keys() else None,
              "on_duty": bool(r["on_duty"]) if "on_duty" in r.keys() and r["on_duty"] is not None else True,
              "username": r["username"] if "username" in r.keys() else None,
              "has_login": bool(r["username"]) if "username" in r.keys() else False,
              "on_shift_camera_id": on_shift_camera.get(r["id"])}
             for r in rows]


def find_official_by_username(username: str):
    """Case-sensitive lookup by the officer's own login username - separate
    namespace from the admin/viewer `users` table, so an officer and an
    admin can pick the same handle without conflicting."""
    if not username:
        return None
    conn = get_db()
    row = conn.execute("SELECT * FROM officials WHERE username = ?", (username,)).fetchone()
    conn.close()
    return row


def set_official_login(official_id: int, username: str, password: str):
    """Give one officer their own username/password, replacing the
    'everyone shares one admin-issued token' model with a real per-person
    login - same idea as create_user() above, just scoped to the
    officials table. Returns (ok, error_message_or_None)."""
    conn = get_db()
    try:
        cur = conn.execute(
            "UPDATE officials SET username = ?, password_hash = ? WHERE id = ?",
            (username, generate_password_hash(password), official_id))
        conn.commit()
        if cur.rowcount == 0:
            return False, "No official with that id."
        return True, None
    except sqlite3.IntegrityError:
        return False, "That username is already taken by another official."
    finally:
        conn.close()


def clear_official_login(official_id: int) -> bool:
    """Revoke an officer's self-service login (e.g. they lost their phone,
    or left the force) without deleting their record - they can be given a
    fresh username/password afterward, same as deleting+recreating a user
    account would do for admin/viewer."""
    conn = get_db()
    cur = conn.execute(
        "UPDATE officials SET username = NULL, password_hash = NULL WHERE id = ?",
        (official_id,))
    conn.commit()
    updated = cur.rowcount > 0
    conn.close()
    return updated


def set_assigned_camera(official_id: int, camera_id: str) -> bool:
    conn = get_db()
    cur = conn.execute("UPDATE officials SET assigned_camera_id = ? WHERE id = ?",
                        (camera_id, official_id))
    conn.commit()
    updated = cur.rowcount > 0
    conn.close()
    return updated


def set_on_duty(official_id: int, on_duty: bool) -> bool:
    conn = get_db()
    cur = conn.execute("UPDATE officials SET on_duty = ? WHERE id = ?",
                        (1 if on_duty else 0, official_id))
    conn.commit()
    updated = cur.rowcount > 0
    conn.close()
    return updated


LOCATION_STALE_AFTER_SEC = 15 * 60  # a live GPS ping older than this is treated as stale


def save_official_location(official_id: int, latitude: float, longitude: float, accuracy_m=None):
    ts = time.time()
    time_str = time.strftime("%H:%M:%S")
    conn = get_db()
    conn.execute(
        "INSERT INTO official_locations (official_id, latitude, longitude, accuracy_m, ts, time) "
        "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(official_id) DO UPDATE SET "
        "latitude=excluded.latitude, longitude=excluded.longitude, "
        "accuracy_m=excluded.accuracy_m, ts=excluded.ts, time=excluded.time",
        (official_id, latitude, longitude, accuracy_m, ts, time_str))
    conn.commit()
    conn.close()
    return {"official_id": official_id, "latitude": latitude, "longitude": longitude,
            "accuracy_m": accuracy_m, "ts": ts, "time": time_str}


def get_official_location(official_id: int):
    conn = get_db()
    row = conn.execute("SELECT * FROM official_locations WHERE official_id = ?", (official_id,)).fetchone()
    conn.close()
    return row


WEEKDAY_NAMES = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]


def _parse_hhmm(s):
    """Returns minutes-since-midnight for a valid 'HH:MM' string, else None."""
    try:
        h, m = s.split(":")
        h, m = int(h), int(m)
        if 0 <= h <= 23 and 0 <= m <= 59:
            return h * 60 + m
    except (ValueError, AttributeError):
        pass
    return None


def _shift_is_active(day_of_week, start_time, end_time, now_struct=None) -> bool:
    """Whether a roster shift (day_of_week: 0=Monday..6=Sunday, or None for
    every day) covering start_time-end_time (both 'HH:MM', local time) is
    active right now. Handles overnight shifts that cross midnight
    (end_time <= start_time, e.g. 22:00-06:00) by also checking whether
    "now" falls in the tail end of a shift that started the day before -
    that tail still belongs to the day_of_week the shift STARTED on."""
    now_struct = now_struct or time.localtime()
    start_min, end_min = _parse_hhmm(start_time), _parse_hhmm(end_time)
    if start_min is None or end_min is None:
        return False
    now_min = now_struct.tm_hour * 60 + now_struct.tm_min
    today_dow = now_struct.tm_wday  # 0=Monday..6=Sunday

    def matches_day(dow):
        return day_of_week is None or day_of_week == dow

    if start_min < end_min:
        return matches_day(today_dow) and start_min <= now_min < end_min
    yesterday_dow = (today_dow - 1) % 7
    return ((matches_day(today_dow) and now_min >= start_min) or
            (matches_day(yesterday_dow) and now_min < end_min))


def add_roster_shift(official_id: int, camera_id: str, day_of_week, start_time: str, end_time: str):
    conn = get_db()
    conn.execute(
        "INSERT INTO duty_roster (official_id, camera_id, day_of_week, start_time, end_time, created_ts) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (official_id, camera_id, day_of_week, start_time, end_time, time.time()))
    conn.commit()
    conn.close()


def list_roster_shifts(official_id: int = None, camera_id: str = None):
    """Every roster entry, optionally scoped to one official or one zone/
    gate, each tagged with whether it's active right now."""
    conn = get_db()
    query = ("SELECT r.*, o.name AS official_name, o.phone AS official_phone "
              "FROM duty_roster r JOIN officials o ON o.id = r.official_id WHERE 1=1")
    params = []
    if official_id is not None:
        query += " AND r.official_id = ?"
        params.append(official_id)
    if camera_id is not None:
        query += " AND r.camera_id = ?"
        params.append(camera_id)
    query += " ORDER BY r.camera_id, (r.day_of_week IS NULL), r.day_of_week, r.start_time"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    now_struct = time.localtime()
    return [{
        "id": r["id"], "official_id": r["official_id"], "official_name": r["official_name"],
        "official_phone": r["official_phone"], "camera_id": r["camera_id"],
        "day_of_week": r["day_of_week"],
        "day_label": WEEKDAY_NAMES[r["day_of_week"]] if r["day_of_week"] is not None else "Every day",
        "start_time": r["start_time"], "end_time": r["end_time"],
        "active_now": _shift_is_active(r["day_of_week"], r["start_time"], r["end_time"], now_struct),
    } for r in rows]


def delete_roster_shift(shift_id: int) -> bool:
    conn = get_db()
    cur = conn.execute("DELETE FROM duty_roster WHERE id = ?", (shift_id,))
    conn.commit()
    deleted = cur.rowcount > 0
    conn.close()
    return deleted


def officials_on_roster_now(camera_id: str):
    """Set of official_ids whose roster currently assigns them to this
    exact zone/gate, right now."""
    if not camera_id:
        return set()
    conn = get_db()
    rows = conn.execute("SELECT * FROM duty_roster WHERE camera_id = ?", (camera_id,)).fetchall()
    conn.close()
    now_struct = time.localtime()
    return {r["official_id"] for r in rows
            if _shift_is_active(r["day_of_week"], r["start_time"], r["end_time"], now_struct)}


def nearest_officials_for_camera(cam, limit: int = 3, on_duty_only: bool = True):
    """The 'who', not just the headcount recommend_police() gives - every
    officer ranked for this camera, preferring their live GPS ping (from
    the mobile app, with consent) when it's recent, and falling back to
    their registered static location otherwise. Off-duty officials are
    excluded by default so a dispatcher isn't pointed at someone who isn't
    working right now.

    Ranking (feature 9): anyone whose shift roster currently assigns them
    to THIS zone/gate is listed first (nearest-among-themselves), ahead of
    everyone else ranked by plain distance - they're scheduled to be here,
    not just physically closest at this instant."""
    cam_lat, cam_lon = cam.get("latitude"), cam.get("longitude")
    if cam_lat in (None, "") or cam_lon in (None, ""):
        return []  # can't rank distance without the camera's own GPS

    rostered_ids = officials_on_roster_now(cam.get("camera_id"))

    conn = get_db()
    rows = conn.execute("SELECT * FROM officials").fetchall()
    loc_rows = {r["official_id"]: r for r in conn.execute("SELECT * FROM official_locations").fetchall()}
    conn.close()

    now = time.time()
    ranked = []
    for o in rows:
        if on_duty_only and "on_duty" in o.keys() and o["on_duty"] == 0:
            continue

        loc = loc_rows.get(o["id"])
        if loc and (now - loc["ts"]) <= LOCATION_STALE_AFTER_SEC:
            lat, lon, source = loc["latitude"], loc["longitude"], "live"
            location_age_sec = round(now - loc["ts"], 1)
        elif o["latitude"] not in (None, "") and o["longitude"] not in (None, ""):
            lat, lon, source = o["latitude"], o["longitude"], "static"
            location_age_sec = None
        else:
            continue  # no location at all - can't be ranked

        dist = haversine_km(float(cam_lat), float(cam_lon), float(lat), float(lon))
        ranked.append({
            "id": o["id"], "name": o["name"], "phone": o["phone"],
            "distance_km": round(dist, 2), "source": source,
            "location_age_sec": location_age_sec,
            "on_duty": bool(o["on_duty"]) if "on_duty" in o.keys() and o["on_duty"] is not None else True,
            "on_roster": o["id"] in rostered_ids,
        })

    ranked.sort(key=lambda o: (not o["on_roster"], o["distance_km"]))
    for i, o in enumerate(ranked, start=1):
        o["priority"] = i
    return ranked[:limit] if limit else ranked


def get_official(official_id: int):
    conn = get_db()
    row = conn.execute("SELECT * FROM officials WHERE id = ?", (official_id,)).fetchone()
    conn.close()
    return row


def save_push_token(official_id: int, token: str) -> bool:
    conn = get_db()
    cur = conn.execute("UPDATE officials SET push_token = ? WHERE id = ?", (token, official_id))
    conn.commit()
    updated = cur.rowcount > 0
    conn.close()
    return updated


def get_synced_result(client_id: str):
    """Offline resilience (feature 7): if this client_id was already
    processed (e.g. the mobile app's earlier attempt succeeded server-side
    but it never saw the response, so it queued a retry), return the
    ORIGINAL result instead of letting the caller process it again."""
    if not client_id:
        return None
    conn = get_db()
    row = conn.execute("SELECT result_json FROM offline_sync_log WHERE client_id = ?",
                        (client_id,)).fetchone()
    conn.close()
    if row is None:
        return None
    return json.loads(row["result_json"])


def save_synced_result(client_id: str, kind: str, official_id, result: dict):
    if not client_id:
        return
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO offline_sync_log (client_id, kind, official_id, result_json, ts) "
            "VALUES (?, ?, ?, ?, ?)",
            (client_id, kind, official_id, json.dumps(result), time.time()))
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # another request with the same client_id landed first - fine, it "won"
    conn.close()


def save_alert_ack(alert_id: int, official_id: int, official_name: str, status: str):
    ts = time.time()
    time_str = time.strftime("%H:%M:%S")
    conn = get_db()
    conn.execute(
        "INSERT INTO alert_acks (alert_id, official_id, official_name, status, ts, time) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (alert_id, official_id, official_name, status, ts, time_str))
    conn.commit()
    conn.close()
    return {"alert_id": alert_id, "official_id": official_id, "official_name": official_name,
            "status": status, "ts": ts, "time": time_str}


def list_acks(alert_id: int = None):
    conn = get_db()
    if alert_id is not None:
        rows = conn.execute(
            "SELECT * FROM alert_acks WHERE alert_id = ? ORDER BY ts", (alert_id,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM alert_acks ORDER BY ts DESC LIMIT 200").fetchall()
    conn.close()
    return [{"id": r["id"], "alert_id": r["alert_id"], "official_id": r["official_id"],
              "official_name": r["official_name"], "status": r["status"],
              "ts": r["ts"], "time": r["time"]} for r in rows]


MAX_PHOTO_B64_CHARS = 7_000_000  # ~5MB decoded - keeps an official's phone photo from blowing up SQLite


def save_alert_photo(alert_id: int, photo_b64: str, content_type: str = None):
    ts = time.time()
    conn = get_db()
    conn.execute(
        "INSERT INTO alert_photos (alert_id, photo_b64, content_type, ts) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(alert_id) DO UPDATE SET photo_b64=excluded.photo_b64, "
        "content_type=excluded.content_type, ts=excluded.ts",
        (alert_id, photo_b64, content_type, ts))
    conn.commit()
    conn.close()


def get_alert_photo(alert_id: int):
    conn = get_db()
    row = conn.execute("SELECT * FROM alert_photos WHERE alert_id = ?", (alert_id,)).fetchone()
    conn.close()
    return row


def add_official(name, phone, latitude, longitude, location=None):
    conn = get_db()
    conn.execute(
        "INSERT INTO officials (name, phone, latitude, longitude, location, created_ts) VALUES (?, ?, ?, ?, ?, ?)",
        (name, phone, latitude, longitude, location, time.time()))
    conn.commit()
    conn.close()


def bootstrap_default_officials():
    """First run only: seeds 5 demo officials across nearby localities, so
    the priority-officials / nearest-first SMS feature has something to
    show immediately. Safe to delete any/all of these from Alerts &
    Controls - this only runs when the officials table is empty."""
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) AS n FROM officials").fetchone()["n"]
    if count == 0:
        demo_officials = [
            ("Officer Ramesh Kumar", "+919840000001", "Tambaram"),
            ("Officer Suresh Babu", "+919840000002", "Vandalur"),
            ("Officer Lakshmi Priya", "+919840000003", "Kodambakkam"),
            ("Officer Anitha Raj", "+919840000004", "Sanatorium"),
            ("Officer Vijay Anand", "+919840000005", "Chromepet"),
        ]
        for name, phone, locality in demo_officials:
            lat, lon = resolve_locality(locality)
            conn.execute(
                "INSERT INTO officials (name, phone, latitude, longitude, location, created_ts) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (name, phone, lat, lon, locality, time.time()))
        conn.commit()
    conn.close()


def delete_official(official_id):
    conn = get_db()
    conn.execute("DELETE FROM officials WHERE id = ?", (official_id,))
    conn.commit()
    conn.close()


def rank_officials_by_proximity(cam):
    """Every registered official with a location, sorted nearest-to-camera
    first, each tagged with its priority rank (1 = closest). Officials
    without a location can't be ranked - they're returned separately so
    callers can still notify them, just without a priority tag/logo, same
    as the old flat-list behavior for everyone before this feature existed."""
    cam_lat, cam_lon = cam.get("latitude"), cam.get("longitude")
    ranked, unranked = [], []
    for o in list_officials():
        if (cam_lat in (None, "") or cam_lon in (None, "") or
                o["latitude"] in (None, "") or o["longitude"] in (None, "")):
            unranked.append(o)
        else:
            dist = haversine_km(float(cam_lat), float(cam_lon), float(o["latitude"]), float(o["longitude"]))
            ranked.append({**o, "distance_km": round(dist, 2)})
    ranked.sort(key=lambda o: o["distance_km"])
    for i, o in enumerate(ranked, start=1):
        o["priority"] = i
    return ranked, unranked


SETTINGS_KEYS = (
    "warning_pct", "critical_pct", "default_max_capacity",
    "ratio_safe", "ratio_warning", "ratio_critical", "min_officers",
    "officials_phone", "alert_cooldown", "sms_cooldown",
)


def save_settings():
    conn = get_db()
    for key in SETTINGS_KEYS:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, json.dumps(STATE[key])))
    conn.commit()
    conn.close()


def load_settings():
    conn = get_db()
    rows = conn.execute("SELECT key, value FROM settings").fetchall()
    conn.close()
    for row in rows:
        if row["key"] in SETTINGS_KEYS:
            STATE[row["key"]] = json.loads(row["value"])


def save_camera_settings(cam):
    conn = get_db()
    conn.execute(
        "INSERT INTO camera_settings (camera_id, label, latitude, longitude, max_capacity) "
        "VALUES (?, ?, ?, ?, ?) ON CONFLICT(camera_id) DO UPDATE SET "
        "label=excluded.label, latitude=excluded.latitude, "
        "longitude=excluded.longitude, max_capacity=excluded.max_capacity",
        (cam["camera_id"], cam["label"], cam["latitude"], cam["longitude"], cam["max_capacity"]))
    conn.commit()
    conn.close()


def load_camera_settings():
    conn = get_db()
    rows = conn.execute("SELECT * FROM camera_settings").fetchall()
    conn.close()
    for r in rows:
        cam = get_or_create_camera(r["camera_id"], r["label"])
        cam["label"] = r["label"] or r["camera_id"]
        cam["_label_set"] = True
        cam["latitude"] = r["latitude"]
        cam["longitude"] = r["longitude"]
        cam["max_capacity"] = r["max_capacity"] or STATE["default_max_capacity"]


def clear_all_data():
    for cam in CAMERAS.values():
        cam["history"].clear()
    ALERTS.clear()
    SMS_LOG.clear()
    conn = get_db()
    conn.execute("DELETE FROM history")
    conn.execute("DELETE FROM alerts")
    conn.execute("DELETE FROM sms_log")
    conn.commit()
    conn.close()


def save_history_point(ts, count, risk, camera_id):
    conn = get_db()
    conn.execute("INSERT INTO history (ts, count, risk, camera_id) VALUES (?, ?, ?, ?)",
                 (ts, count, risk, camera_id))
    conn.commit()
    conn.close()


def save_alert(ts, time_str, message, severity, camera_id, location=None, action=None, recommendation=None):
    conn = get_db()
    cur = conn.execute("INSERT INTO alerts (ts, time, message, severity, camera_id, location, action, recommendation) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (ts, time_str, message, severity, camera_id, location, action, recommendation))
    conn.commit()
    alert_id = cur.lastrowid  # SQLite's implicit rowid - stable reference for acks
    conn.close()
    return alert_id


def load_recent_history(camera_id=None, limit=300):
    conn = get_db()
    if camera_id:
        rows = conn.execute(
            "SELECT ts, count, camera_id FROM history WHERE camera_id = ? ORDER BY ts DESC LIMIT ?",
            (camera_id, limit)).fetchall()
    else:
        rows = conn.execute(
            "SELECT ts, count, camera_id FROM history ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    rows = list(reversed(rows))
    return [{"t": r["ts"], "count": r["count"], "camera_id": r["camera_id"]} for r in rows]


def load_recent_alerts(limit=50):
    conn = get_db()
    rows = conn.execute(
        "SELECT time, message, severity, camera_id FROM alerts ORDER BY ts DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [{"time": r["time"], "message": r["message"], "severity": r["severity"],
              "camera_id": r["camera_id"]} for r in rows]


def save_audit_entry(ts, time_str, role, username, ip, action, details):
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_log (ts, time, role, username, ip, action, details) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (ts, time_str, role, username, ip, action, details))
    conn.commit()
    conn.close()


def load_recent_audit_log(limit=100):
    conn = get_db()
    rows = conn.execute(
        "SELECT time, role, username, ip, action, details FROM audit_log ORDER BY ts DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [{"time": r["time"], "role": r["role"], "username": r["username"] or r["role"],
              "ip": r["ip"], "action": r["action"], "details": r["details"]} for r in rows]


def push_audit(action, details="", role=None, username=None):
    ts = time.time()
    time_str = time.strftime("%H:%M:%S")
    if role is None:
        role = session.get("role") or _authorized_role() or "unknown"
    if username is None:
        # Browser dashboard: session["username"], set at /login.
        # Official mobile app: request.official_username, set by
        # require_official_token below from the officer's own login (or
        # their plain name, for an admin-issued token with no login yet) -
        # so an ack/report/SOS from officer Priya shows "Priya", not
        # "shared-key", the same way an admin's actions show their name.
        username = session.get("username") or getattr(request, "official_username", None) or "shared-key"
    ip = request.remote_addr or "unknown"
    entry = {"time": time_str, "role": role, "username": username, "ip": ip,
              "action": action, "details": details}
    AUDIT_LOG.appendleft(entry)
    save_audit_entry(ts, time_str, role, username, ip, action, details)
    socketio.emit("audit_entry", entry)
    return entry


def save_sms_log(ts, time_str, recipients, message, sent, detail):
    conn = get_db()
    conn.execute(
        "INSERT INTO sms_log (ts, time, recipients, message, sent, detail) VALUES (?, ?, ?, ?, ?, ?)",
        (ts, time_str, recipients, message, 1 if sent else 0, detail))
    conn.commit()
    conn.close()


def load_recent_sms(limit=50):
    conn = get_db()
    rows = conn.execute(
        "SELECT time, recipients, message, sent, detail FROM sms_log ORDER BY ts DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [{"time": r["time"], "to": r["recipients"], "message": r["message"],
             "sent": bool(r["sent"]), "detail": r["detail"]} for r in rows]


def get_peak_count(camera_id=None):
    conn = get_db()
    if camera_id:
        row = conn.execute("SELECT MAX(count) AS peak FROM history WHERE camera_id = ?",
                            (camera_id,)).fetchone()
    else:
        row = conn.execute("SELECT MAX(count) AS peak FROM history").fetchone()
    conn.close()
    return row["peak"] if row and row["peak"] is not None else 0


def get_daily_comparison(camera_id=None, days=7):
    """Day-over-day trend: for each of the last N days, the peak and
    average count seen that day (feature: historical/trend analytics
    beyond the current live session)."""
    conn = get_db()
    if camera_id:
        rows = conn.execute(
            "SELECT date(ts, 'unixepoch', 'localtime') AS day, "
            "MAX(count) AS peak, AVG(count) AS avg_count, COUNT(*) AS n "
            "FROM history WHERE camera_id = ? "
            "GROUP BY day ORDER BY day DESC LIMIT ?", (camera_id, days)).fetchall()
    else:
        rows = conn.execute(
            "SELECT date(ts, 'unixepoch', 'localtime') AS day, "
            "MAX(count) AS peak, AVG(count) AS avg_count, COUNT(*) AS n "
            "FROM history GROUP BY day ORDER BY day DESC LIMIT ?", (days,)).fetchall()
    conn.close()
    out = [{"day": r["day"], "peak": r["peak"], "avg": round(r["avg_count"], 1), "samples": r["n"]}
           for r in rows]
    return list(reversed(out))


# ---------------------------------------------------------------------------
# Risk / recommendation logic
# ---------------------------------------------------------------------------
def compute_risk(count: int, max_capacity: float) -> str:
    pct = (count / max_capacity) * 100 if max_capacity else 0
    if pct >= STATE["critical_pct"]:
        return "CRITICAL"
    if pct >= STATE["warning_pct"]:
        return "WARNING"
    return "SAFE"


def compute_growth_rate(cam):
    recent = list(cam["history"])[-5:]
    if len(recent) >= 2:
        dt = recent[-1]["t"] - recent[0]["t"]
        growth = recent[-1]["count"] - recent[0]["count"]
        if dt > 0:
            return growth / dt
    return 0.0


def gps_maps_link(cam):
    lat, lon = cam.get("latitude"), cam.get("longitude")
    if lat in (None, "") or lon in (None, ""):
        return None
    return f"https://maps.google.com/?q={lat},{lon}"


def gps_alert_suffix(cam):
    lat, lon = cam.get("latitude"), cam.get("longitude")
    if lat in (None, "") or lon in (None, ""):
        return ""
    label = cam.get("label") or "Camera"
    link = gps_maps_link(cam)
    return f" | \U0001F4CD {label} ({lat}, {lon}) - {link}"


# Known localities -> approximate (latitude, longitude), so an official can
# be registered with just a locality name (e.g. "Tambaram") instead of
# hunting down exact GPS coordinates. Coordinates are approximate town-center
# points, good enough for nearest-official ranking in a demo/prototype -
# for production use, prefer exact duty-post coordinates when known.
KNOWN_LOCALITIES = {
    "tambaram": (12.9249, 80.1000),
    "sanatorium": (12.9160, 80.1160),
    "tambaram sanatorium": (12.9160, 80.1160),
    "vandalur": (12.8930, 80.0827),
    "kodambakkam": (13.0524, 80.2246),
    "chromepet": (12.9516, 80.1462),
    "pallavaram": (12.9675, 80.1491),
    "guindy": (13.0067, 80.2206),
    "perungalathur": (12.8975, 80.0956),
    "selaiyur": (12.9107, 80.1298),
    "medavakkam": (12.9186, 80.1875),
    "velachery": (12.9789, 80.2201),
    "adyar": (13.0012, 80.2565),
    "tirusulam": (12.9847, 80.1670),
    "pammal": (12.9720, 80.1327),
}


def resolve_locality(name):
    """Look up a locality name (case/space-insensitive) in KNOWN_LOCALITIES.
    Returns (lat, lon) or (None, None) if it isn't a recognized name - the
    official/camera can still be registered, just without an auto-filled
    location, same as leaving lat/lon blank today."""
    if not name:
        return None, None
    key = " ".join(str(name).strip().lower().split())
    return KNOWN_LOCALITIES.get(key, (None, None))


def haversine_km(lat1, lon1, lat2, lon2):
    """Great-circle distance between two GPS points, in kilometers. Used to
    rank officials by how close they are to a camera that's raising an
    alert, for priority-ordered SMS notifications."""
    R = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * R * math.asin(min(1.0, math.sqrt(a)))


PRIORITY_LABELS = {1: "\U0001F947 PRIORITY 1 (nearest)", 2: "\U0001F948 PRIORITY 2",
                   3: "\U0001F949 PRIORITY 3"}


def priority_label(rank: int) -> str:
    return PRIORITY_LABELS.get(rank, f"\U0001F514 PRIORITY {rank}")


def recommend_police(count: int, risk: str, cam):
    if count <= 0:
        return 0, "No crowd currently detected."
    ratio = {
        "SAFE": STATE["ratio_safe"],
        "WARNING": STATE["ratio_warning"],
        "CRITICAL": STATE["ratio_critical"],
    }.get(risk, STATE["ratio_safe"])
    base = max(STATE["min_officers"], math.ceil(count / ratio)) if ratio else STATE["min_officers"]
    surge_multiplier = 1.2 if compute_growth_rate(cam) > 0.5 else 1.0
    recommended = math.ceil(base * surge_multiplier)
    reason = (f"{base} base officers ({count} people / {ratio}:1 ratio for {risk}, "
              f"min {STATE['min_officers']})")
    if surge_multiplier > 1.0:
        reason += " + 20% surge buffer (crowd growing quickly)"
    return recommended, reason


def recommend_clearance_plan(count: int, risk: str, cam):
    if count <= 0:
        return ["No crowd currently detected - no action needed."]
    plan = []
    if risk == "SAFE":
        plan.append("Continue routine monitoring - no dispersal action required.")
    elif risk == "WARNING":
        plan += [
            "Position standby officers at key entry/exit points near this camera.",
            "Begin gentle crowd-flow announcements to slow further inflow.",
            "Open secondary walkways/gates to spread density across a wider area.",
            "Increase monitoring frequency at this location.",
        ]
    elif risk == "CRITICAL":
        plan += [
            "Deploy all available officers to this location immediately.",
            "Temporarily pause new entries at this zone's gates.",
            "Open emergency exits and direct flow away from the densest area.",
            "Broadcast clear dispersal instructions over PA / megaphone.",
            "Alert on-site medical/first-aid team to stand by.",
            "Escalate to the central control room for additional unit deployment.",
        ]
    if compute_growth_rate(cam) > 0.5 and risk != "SAFE":
        plan.append("Crowd is growing quickly - consider a preemptive gate slowdown.")

    zone_hot = hottest_zone(cam)
    if zone_hot is not None and risk != "SAFE":
        plan.append(f"Densest zone is grid cell {zone_hot['index']} "
                    f"({zone_hot['count']} people) - prioritize that area first.")
    return plan


def whatif_projection(cam, extra_people: int, capacity_pct: float):
    """Feature: what-if scenario planning. Answers "what happens if N more
    people arrive" or "what happens if we lose X% capacity (e.g. a gate
    closes)" by running the SAME rule engine used for live monitoring
    against a hypothetical headcount/capacity - never touches the camera's
    real state, history, or triggers real alerts/SMS. This is a rule-based
    projection, not a simulation of how a crowd would actually move."""
    hypothetical_count = max(0, cam["current_count"] + extra_people)
    hypothetical_capacity = max(1.0, cam["max_capacity"] * (capacity_pct / 100.0))
    risk = compute_risk(hypothetical_count, hypothetical_capacity)
    officers, reason = recommend_police(hypothetical_count, risk, cam)
    plan = recommend_clearance_plan(hypothetical_count, risk, cam)
    return {
        "hypothetical_count": hypothetical_count,
        "hypothetical_capacity": round(hypothetical_capacity),
        "risk_level": risk,
        "crowd_level": CROWD_LEVEL_LABEL.get(risk, risk),
        "recommended_police": officers,
        "police_reason": reason,
        "top_action": plan[0] if plan else "No action needed.",
        "plan": plan,
    }


def hottest_zone(cam):
    """Feature: zone/density mapping. Returns the busiest grid cell from
    the last zone_counts report, or None if this camera hasn't sent any."""
    zc = cam.get("zone_counts") or []
    if not zc:
        return None
    idx = max(range(len(zc)), key=lambda i: zc[i])
    return {"index": idx, "count": zc[idx]}


def zone_risk_levels(cam):
    """Per-cell risk (SAFE/WARNING/CRITICAL), using an even share of the
    camera's max_capacity across all cells as that cell's local capacity."""
    zc = cam.get("zone_counts") or []
    rows, cols = cam.get("zone_rows") or 0, cam.get("zone_cols") or 0
    if not zc or not rows or not cols:
        return []
    per_cell_capacity = (cam["max_capacity"] / (rows * cols)) if (rows * cols) else 0
    return [compute_risk(c, per_cell_capacity) for c in zc]


def push_alert(message: str, severity: str, camera_id: str, camera_label: str,
               action: str = None, recommendation: str = None):
    ts = time.time()
    time_str = time.strftime("%H:%M:%S")
    alert_id = save_alert(ts, time_str, message, severity, camera_id, camera_label, action, recommendation)
    entry = {"id": alert_id, "time": time_str, "message": message, "severity": severity,
              "camera_id": camera_id, "camera_label": camera_label,
              "location": camera_label, "action": action, "recommendation": recommendation}
    ALERTS.appendleft(entry)
    socketio.emit("new_alert", entry)
    return alert_id


def send_sms_alert(count: int, risk: str, recommended_police: int, plan: list, cam):
    legacy_numbers = [n.strip() for n in STATE.get("officials_phone", "").split(",") if n.strip()]
    ranked, unranked = rank_officials_by_proximity(cam)
    # Don't double-text someone who's in both the old flat list AND the new
    # registered-officials table.
    registered_phones = {o["phone"] for o in ranked + unranked}
    legacy_only = [n for n in legacy_numbers if n not in registered_phones]

    # Only text the nearest official + one backup (2nd-nearest), not every
    # registered official - keeps alerts targeted to whoever's actually
    # closest to the incident instead of a venue-wide blast. Officials with
    # no location on file can't be ranked, so they're still notified
    # separately below (same as before this change).
    ranked = ranked[:2]

    maps_link = gps_maps_link(cam)
    location = cam.get("label") or "Camera location"
    lat, lon = cam.get("latitude"), cam.get("longitude")
    gps_line = f"{lat}, {lon}" if lat not in (None, "") and lon not in (None, "") else "Not configured"

    def build_body(priority_line: str = None) -> str:
        lines = [f"CROWD GUARD ALERT [{risk}]"]
        if priority_line:
            lines.append(priority_line)
        lines += [
            f"{location}: {count} people ({int(cam['max_capacity'])} cap)",
            f"Recommended officers: {recommended_police}",
            f"GPS: {gps_line}",
            f"Map: {maps_link or 'GPS not configured'}",
            f"Action: {plan[0] if plan else 'Monitor'}",
        ]
        return "\n".join(lines)

    # recipients: list of (phone, message_body, display_label)
    recipients = []
    for o in ranked:
        label = priority_label(o["priority"])
        where = f" [{o['location']}]" if o.get("location") else ""
        body = build_body(f"{label} - {o['name']}{where} ({o['distance_km']} km away)")
        recipients.append((o["phone"], body, f"{o['name']} [{label}]"))
    for o in unranked:
        body = build_body(f"{o['name']} (location not set - unranked)")
        recipients.append((o["phone"], body, o["name"]))
    for n in legacy_only:
        recipients.append((n, build_body(), n))

    ts = time.time()
    time_str = time.strftime("%H:%M:%S")

    if not recipients:
        detail = "No officials configured (add them in Alerts & Controls)."
        sent = False
        ok_parts, fail_parts = [], []
    elif not (TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_FROM_NUMBER):
        preview = "\n\n".join(f"To {lbl}:\n{body}" for _, body, lbl in recipients)
        print(f"\n[SMS log-only mode] Would send:\n{preview}\n")
        detail = "Twilio credentials not set - logged only, not actually sent."
        sent = False
        ok_parts, fail_parts = [], []
    else:
        ok_parts, fail_parts = [], []
        from twilio.rest import Client
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        for phone, body, label in recipients:
            try:
                msg = client.messages.create(body=body, from_=TWILIO_FROM_NUMBER, to=phone)
                ok_parts.append(f"{label} (sid {msg.sid})")
            except Exception as e:
                fail_parts.append(f"{label} ({e})")
        sent = bool(ok_parts)
        if ok_parts and not fail_parts:
            detail = f"Sent via Twilio to: {', '.join(ok_parts)}"
        elif ok_parts and fail_parts:
            detail = f"Sent to: {', '.join(ok_parts)} | Failed: {', '.join(fail_parts)}"
        else:
            detail = f"Failed for all recipients: {', '.join(fail_parts)}"

    to_summary = ", ".join(lbl for _, _, lbl in recipients) or "(none configured)"
    body_summary = recipients[0][1] if recipients else build_body()
    entry = {"time": time_str, "to": to_summary, "message": body_summary, "sent": sent, "detail": detail}
    SMS_LOG.appendleft(entry)
    save_sms_log(ts, time_str, entry["to"], body_summary, sent, detail)
    socketio.emit("sms_status", entry)
    return entry


def send_push_alert(alert_id, count: int, risk: str, recommended_police: int, plan: list, cam):
    """Push, sent in parallel with send_sms_alert() - never instead of it.
    Unlike SMS (kept targeted to the nearest 1-2 officials, since it costs
    money per message), push is sent to every official who has the app and
    a registered push_token, since venue-wide situational awareness is
    free. Officials with no push_token on file simply don't get one - they
    still get SMS exactly as before, so nothing regresses for them."""
    conn = get_db()
    rows = conn.execute(
        "SELECT id, name, push_token FROM officials WHERE push_token IS NOT NULL AND push_token != ''"
    ).fetchall()
    conn.close()
    tokens = [r["push_token"] for r in rows]

    ts = time.time()
    time_str = time.strftime("%H:%M:%S")
    location = cam.get("label") or "Camera location"
    title = f"CROWD GUARD [{risk}]"
    body = f"{location}: {count} people ({int(cam['max_capacity'])} cap) - recommend {recommended_police} officers"
    data = {"alert_id": str(alert_id), "camera_id": cam.get("camera_id", ""),
            "risk": risk, "count": str(count), "action": plan[0] if plan else "Monitor"}

    if not tokens:
        detail = "No officials have registered a push token yet (app not installed/logged in)."
        sent = False
    elif not FCM_SERVER_KEY:
        print(f"\n[Push log-only mode] Would send to {len(tokens)} device(s): {title} - {body}\n")
        detail = "FCM_SERVER_KEY not set - logged only, not actually sent."
        sent = False
    else:
        try:
            import requests
            resp = requests.post(
                "https://fcm.googleapis.com/fcm/send",
                headers={"Authorization": f"key={FCM_SERVER_KEY}", "Content-Type": "application/json"},
                json={"registration_ids": tokens,
                      "notification": {"title": title, "body": body},
                      "data": data},
                timeout=10)
            ok = resp.status_code == 200
            detail = f"FCM responded {resp.status_code}" if ok else f"FCM error {resp.status_code}: {resp.text[:200]}"
            sent = ok
        except Exception as e:
            detail = f"Push send failed: {e}"
            sent = False

    entry = {"time": time_str, "to": f"{len(tokens)} device(s)", "message": body, "sent": sent, "detail": detail}
    conn = get_db()
    conn.execute("INSERT INTO push_log (ts, time, recipients, message, sent, detail) VALUES (?, ?, ?, ?, ?, ?)",
                 (ts, time_str, entry["to"], body, sent, detail))
    conn.commit()
    conn.close()
    socketio.emit("push_status", entry)
    return entry


def send_sos_broadcast(sos_official_id: int, sos_name: str, custom_message: str, lat, lon):
    """Officer's own emergency (feature 6) - distinct from the admin's demo
    panic button in /api/simulate/panic, which simulates a CROWD emergency
    at a camera. This is a real person signaling THEIR OWN emergency, so it
    bypasses every normal targeting/cooldown rule: no nearest-2-only
    limit like routine SMS, no alert/sms_cooldown gate - it goes out
    immediately, every time it's pressed, to EVERY other official, by both
    SMS and push in parallel (not gated on push_token presence the way
    routine alerts are - if only SMS reaches someone, that's fine, this is
    exactly the "SMS as unconditional fallback" case)."""
    maps_link = f"https://maps.google.com/?q={lat},{lon}" if lat is not None and lon is not None else None
    location_line = f"Location: {lat}, {lon} ({maps_link})" if maps_link else "Location: not shared"
    body = (f"\U0001F6A8 CROWD GUARD SOS \U0001F6A8\n"
            f"{sos_name} has triggered an officer emergency and needs immediate assistance.\n"
            + (f"{custom_message}\n" if custom_message else "")
            + f"{location_line}\nRespond immediately.")

    conn = get_db()
    others = conn.execute(
        "SELECT id, name, phone, push_token FROM officials WHERE id != ?", (sos_official_id,)).fetchall()
    conn.close()

    ts = time.time()
    time_str = time.strftime("%H:%M:%S")

    # --- SMS to every other official with a phone (no nearest-2 limit -
    # an officer emergency isn't something to only tell the closest one) ---
    phones = [o["phone"] for o in others if o["phone"]]
    if not phones:
        sms_detail = "No other officials registered."
        sms_sent = False
    elif not (TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_FROM_NUMBER):
        print(f"\n[SMS log-only mode] SOS would send to {len(phones)} official(s):\n{body}\n")
        sms_detail = "Twilio credentials not set - logged only, not actually sent."
        sms_sent = False
    else:
        from twilio.rest import Client
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        ok_parts, fail_parts = [], []
        for o in others:
            if not o["phone"]:
                continue
            try:
                client.messages.create(body=body, from_=TWILIO_FROM_NUMBER, to=o["phone"])
                ok_parts.append(o["name"])
            except Exception as e:
                fail_parts.append(f"{o['name']} ({e})")
        sms_sent = bool(ok_parts)
        sms_detail = f"Sent to: {', '.join(ok_parts)}" + (f" | Failed: {', '.join(fail_parts)}" if fail_parts else "")

    sms_entry = {"time": time_str, "to": f"{len(phones)} official(s)", "message": body,
                 "sent": sms_sent, "detail": sms_detail}
    SMS_LOG.appendleft(sms_entry)
    save_sms_log(ts, time_str, sms_entry["to"], body, sms_sent, sms_detail)
    socketio.emit("sms_status", sms_entry)

    # --- Push to every other official who has a token ---
    tokens = [o["push_token"] for o in others if o["push_token"]]
    if not tokens:
        push_detail = "No other officials have a push token registered."
        push_sent = False
    elif not FCM_SERVER_KEY:
        print(f"\n[Push log-only mode] SOS would send to {len(tokens)} device(s)\n")
        push_detail = "FCM_SERVER_KEY not set - logged only, not actually sent."
        push_sent = False
    else:
        try:
            import requests
            resp = requests.post(
                "https://fcm.googleapis.com/fcm/send",
                headers={"Authorization": f"key={FCM_SERVER_KEY}", "Content-Type": "application/json"},
                json={"registration_ids": tokens,
                      "notification": {"title": "\U0001F6A8 OFFICER SOS", "body": body},
                      "data": {"type": "sos", "sos_official_id": str(sos_official_id)}},
                timeout=10)
            push_sent = resp.status_code == 200
            push_detail = f"FCM responded {resp.status_code}" if push_sent else f"FCM error {resp.status_code}: {resp.text[:200]}"
        except Exception as e:
            push_sent = False
            push_detail = f"Push send failed: {e}"

    push_entry = {"time": time_str, "to": f"{len(tokens)} device(s)", "message": body,
                  "sent": push_sent, "detail": push_detail}
    conn = get_db()
    conn.execute("INSERT INTO push_log (ts, time, recipients, message, sent, detail) VALUES (?, ?, ?, ?, ?, ?)",
                 (ts, time_str, push_entry["to"], body, push_sent, push_detail))
    conn.commit()
    conn.close()
    socketio.emit("push_status", push_entry)

    return {"sms": sms_entry, "push": push_entry, "notified_count": len(others)}


# ---------------------------------------------------------------------------
# Routes for the dashboard itself
# ---------------------------------------------------------------------------
@app.route("/")
@require_web_session
def index():
    return render_template("index.html", v=ASSET_VERSION, role=session.get("role", "admin"),
                            username=session.get("username", "shared-key"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    next_path = request.args.get("next") or request.form.get("next") or url_for("index")
    if not next_path.startswith("/"):
        next_path = url_for("index")

    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        if _login_rate_limited(ip):
            error = "Too many attempts - try again in a few minutes."
        else:
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password", "")
            legacy_key = request.form.get("key", "")

            role = None
            login_username = "shared-key"

            if username:
                # Individual-account login.
                user = find_user(username)
                if user and check_password_hash(user["password_hash"], password):
                    role = user["role"]
                    login_username = user["username"]
            elif legacy_key:
                # Backward-compatible shared-key login.
                if secrets.compare_digest(legacy_key, ADMIN_API_KEY):
                    role = "admin"
                elif VIEWER_API_KEY and secrets.compare_digest(legacy_key, VIEWER_API_KEY):
                    role = "viewer"

            if role:
                session.permanent = True
                session["authorized"] = True
                session["role"] = role
                session["username"] = login_username
                push_audit("login", "", role=role)
                return redirect(next_path)
            _record_login_failure(ip)
            push_audit("login_failed", username or "(shared key)", role="unknown")
            error = "Incorrect credentials."
    return render_template("login.html", error=error, next_path=next_path, v=ASSET_VERSION)


@app.route("/logout")
def logout():
    if session.get("authorized"):
        push_audit("logout", "", role=session.get("role", "unknown"))
    session.clear()
    return redirect(url_for("login"))


@app.route("/api/state")
@require_viewer_or_admin
def api_state():
    """Initial snapshot a browser loads on first connect. camera_id picks
    which camera's live-feed panel / per-camera fields to focus on; every
    camera's summary is included too so the dashboard can render the
    camera switcher and combined risk."""
    camera_id = request.args.get("camera_id") or DEFAULT_CAMERA_ID
    cam = get_or_create_camera(camera_id)

    return jsonify({
        "camera_id": camera_id,
        "current_count": cam["current_count"],
        "max_capacity": cam["max_capacity"],
        "warning_pct": STATE["warning_pct"],
        "critical_pct": STATE["critical_pct"],
        "risk_level": cam["risk_level"],
        "peak_count": get_peak_count(camera_id),
        "recommended_police": cam["recommended_police"],
        "police_reason": cam["police_reason"],
        "ratio_safe": STATE["ratio_safe"],
        "ratio_warning": STATE["ratio_warning"],
        "ratio_critical": STATE["ratio_critical"],
        "min_officers": STATE["min_officers"],
        "alert_cooldown": STATE["alert_cooldown"],
        "sms_cooldown": STATE["sms_cooldown"],
        "cam_location_label": cam["label"],
        "cam_latitude": cam["latitude"],
        "cam_longitude": cam["longitude"],
        "cam_maps_link": gps_maps_link(cam),
        "officials_phone": STATE["officials_phone"],
        "officials": list_officials(),
        "clearance_plan": cam["clearance_plan"],
        "zone_counts": cam["zone_counts"],
        "zone_rows": cam["zone_rows"],
        "zone_cols": cam["zone_cols"],
        "zone_risk": zone_risk_levels(cam),
        "history": list(cam["history"]),
        "alerts": list(ALERTS),
        "sms_log": list(SMS_LOG),
        "combined_risk_level": combined_risk_level(),
        "combined_current_count": combined_current_count(),
        "cameras": [camera_summary(c) for c in CAMERAS.values()],
    })


@app.route("/api/cameras")
@require_viewer_or_admin
def api_cameras():
    return jsonify({
        "cameras": [camera_summary(c) for c in CAMERAS.values()],
        "combined_risk_level": combined_risk_level(),
        "combined_current_count": combined_current_count(),
    })


@app.route("/api/whatif", methods=["POST"])
@require_viewer_or_admin
def api_whatif():
    """Feature: what-if scenario planning (see whatif_projection). Pure
    calculation - reads the target camera's current numbers but writes
    nothing, so viewers can explore scenarios too, not just admins."""
    data = request.get_json(silent=True) or {}
    camera_id = data.get("camera_id") or DEFAULT_CAMERA_ID
    cam = get_or_create_camera(camera_id)

    try:
        extra_people = int(data.get("extra_people", 0))
    except (TypeError, ValueError):
        extra_people = 0
    try:
        capacity_pct = float(data.get("capacity_pct", 100))
    except (TypeError, ValueError):
        capacity_pct = 100.0

    extra_people = max(-cam["current_count"], min(5000, extra_people))
    capacity_pct = max(10.0, min(200.0, capacity_pct))

    result = whatif_projection(cam, extra_people, capacity_pct)
    push_audit("whatif", f"[{camera_id}] {extra_people:+d} people, capacity {capacity_pct:.0f}%")
    return jsonify(result)


@app.route("/api/history/compare")
@require_viewer_or_admin
def api_history_compare():
    """Day-over-day trend (feature: historical/trend analytics beyond the
    current live session). ?camera_id= to scope to one camera, otherwise
    all cameras combined. ?days=N (default 7, max 90)."""
    camera_id = request.args.get("camera_id") or None
    try:
        days = min(90, max(1, int(request.args.get("days", 7))))
    except (TypeError, ValueError):
        days = 7
    return jsonify({"days": get_daily_comparison(camera_id, days)})


@app.route("/api/audit-log")
@require_admin_key
def api_audit_log():
    return jsonify({"audit_log": list(AUDIT_LOG)})


@app.route("/api/frame.jpg")
@require_viewer_or_admin
def api_frame():
    camera_id = request.args.get("camera_id") or DEFAULT_CAMERA_ID
    jpeg = LATEST_FRAMES.get(camera_id)
    if jpeg is None:
        return "", 204
    return Response(jpeg, mimetype="image/jpeg")


# ---------------------------------------------------------------------------
# CSV export - lets you pull history/alerts/audit log into a spreadsheet for
# after-action review (e.g. reconstructing a timeline after an incident,
# reporting to a venue safety committee, etc.) instead of only being able to
# see the live/recent-only view the dashboard itself shows. Reads straight
# from SQLite (not the in-memory deques, which are capped/session-only), so
# an export covers everything that's ever been persisted, not just what's
# currently loaded in the running server.
# ---------------------------------------------------------------------------
EXPORT_ROW_LIMIT = int(os.environ.get("EXPORT_ROW_LIMIT", 50000))


def _csv_response(fieldnames, rows, filename):
    """Builds a downloadable CSV Response from a list of dicts. Using
    Content-Disposition: attachment (rather than returning JSON) makes a
    plain link click - or curl/wget - download a normal .csv file, no
    special client-side handling needed."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    resp = Response(buf.getvalue(), mimetype="text/csv")
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp


@app.route("/api/export/history.csv")
@require_viewer_or_admin
def export_history_csv():
    """Full persisted crowd-count history, one row per reading. Optional
    ?camera_id= scopes it to a single camera; otherwise every camera's
    readings are included (with camera_id as its own column so they can
    still be filtered/pivoted afterward in a spreadsheet)."""
    camera_id = request.args.get("camera_id") or None
    conn = get_db()
    if camera_id:
        rows = conn.execute(
            "SELECT ts, camera_id, count, risk FROM history "
            "WHERE camera_id = ? ORDER BY ts ASC LIMIT ?",
            (camera_id, EXPORT_ROW_LIMIT)).fetchall()
    else:
        rows = conn.execute(
            "SELECT ts, camera_id, count, risk FROM history "
            "ORDER BY ts ASC LIMIT ?", (EXPORT_ROW_LIMIT,)).fetchall()
    conn.close()

    out_rows = [{
        "timestamp_utc": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(r["ts"])),
        "epoch_seconds": r["ts"],
        "camera_id": r["camera_id"],
        "count": r["count"],
        "risk": r["risk"],
    } for r in rows]

    push_audit("export_csv", f"history ({len(out_rows)} rows"
               + (f", camera={camera_id}" if camera_id else ", all cameras") + ")")
    fname = f"crowdguard_history_{camera_id or 'all'}_{time.strftime('%Y%m%d_%H%M%S')}.csv"
    return _csv_response(["timestamp_utc", "epoch_seconds", "camera_id", "count", "risk"],
                          out_rows, fname)


@app.route("/api/export/alerts.csv")
@require_viewer_or_admin
def export_alerts_csv():
    """Every WARNING/CRITICAL/simulated-emergency alert ever raised, in
    order - useful for reconstructing exactly when and where risk
    escalated during an incident, what was recommended, and what was
    actually done about it."""
    conn = get_db()
    rows = conn.execute(
        "SELECT ts, time, camera_id, severity, message, location, action, recommendation "
        "FROM alerts ORDER BY ts ASC LIMIT ?", (EXPORT_ROW_LIMIT,)).fetchall()
    conn.close()

    out_rows = [{
        "timestamp_utc": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(r["ts"])),
        "local_time": r["time"],
        "camera_id": r["camera_id"],
        "location": r["location"] or "",
        "severity": r["severity"],
        "message": r["message"],
        "action_taken": r["action"] or "",
        "recommendation": r["recommendation"] or "",
    } for r in rows]

    push_audit("export_csv", f"alerts ({len(out_rows)} rows)")
    fname = f"crowdguard_alerts_{time.strftime('%Y%m%d_%H%M%S')}.csv"
    return _csv_response(["timestamp_utc", "local_time", "camera_id", "location", "severity",
                           "message", "action_taken", "recommendation"],
                          out_rows, fname)


@app.route("/api/export/audit.csv")
@require_admin_key
def export_audit_csv():
    """Full audit trail (logins, config changes, demo/panic triggers, user
    management) - admin-only, matching /api/audit-log's access level."""
    conn = get_db()
    rows = conn.execute(
        "SELECT ts, time, role, username, ip, action, details FROM audit_log "
        "ORDER BY ts ASC LIMIT ?", (EXPORT_ROW_LIMIT,)).fetchall()
    conn.close()

    out_rows = [{
        "timestamp_utc": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(r["ts"])),
        "local_time": r["time"],
        "role": r["role"],
        "username": r["username"] or r["role"],
        "ip": r["ip"],
        "action": r["action"],
        "details": r["details"],
    } for r in rows]

    push_audit("export_csv", f"audit_log ({len(out_rows)} rows)")
    fname = f"crowdguard_audit_{time.strftime('%Y%m%d_%H%M%S')}.csv"
    return _csv_response(["timestamp_utc", "local_time", "role", "username", "ip",
                           "action", "details"], out_rows, fname)


# ---------------------------------------------------------------------------
# Individual account management (admin-only) - feature: individual admin
# accounts instead of everyone sharing one key.
# ---------------------------------------------------------------------------
@app.route("/api/users", methods=["GET", "POST"])
@require_admin_key
def api_users():
    if request.method == "GET":
        return jsonify({"users": list_users()})

    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    role = data.get("role") or "viewer"

    if not re.fullmatch(r"[A-Za-z0-9_.\-]{3,32}", username):
        return jsonify({"ok": False, "error":
                         "Username must be 3-32 characters: letters, numbers, "
                         "underscore, dot, or hyphen."}), 400
    if len(password) < 6:
        return jsonify({"ok": False, "error": "Password must be at least 6 characters."}), 400
    if role not in ("admin", "viewer"):
        return jsonify({"ok": False, "error": "role must be 'admin' or 'viewer'."}), 400

    ok, err = create_user(username, password, role)
    if not ok:
        return jsonify({"ok": False, "error": err}), 400
    push_audit("user_created", f"{username} ({role})")
    return jsonify({"ok": True})


@app.route("/api/users/<username>", methods=["DELETE"])
@require_admin_key
def api_delete_user(username):
    if username == session.get("username"):
        return jsonify({"ok": False, "error": "You can't delete your own account while logged in as it."}), 400
    delete_user(username)
    push_audit("user_deleted", username)
    return jsonify({"ok": True})


@app.route("/api/config", methods=["POST"])
@require_admin_key
def api_config():
    """Updates global thresholds/ratios/cooldowns AND (if camera_id is
    supplied) that specific camera's label/GPS/capacity."""
    data = request.get_json(force=True)
    camera_id = data.get("camera_id") or DEFAULT_CAMERA_ID
    cam = get_or_create_camera(camera_id)

    GLOBAL_POSITIVE_FIELDS = ("ratio_safe", "ratio_warning", "ratio_critical", "min_officers",
                               "alert_cooldown", "sms_cooldown")
    GLOBAL_NUMERIC_FIELDS = GLOBAL_POSITIVE_FIELDS + ("warning_pct", "critical_pct")
    CAMERA_POSITIVE_FIELDS = ("max_capacity",)

    parsed = {}
    for key in GLOBAL_NUMERIC_FIELDS:
        if key in data and data[key] not in (None, ""):
            try:
                parsed[key] = float(data[key])
            except (TypeError, ValueError):
                return jsonify({"ok": False, "error": f"{key} must be a number."}), 400
    for key in GLOBAL_POSITIVE_FIELDS:
        if key in parsed and parsed[key] <= 0:
            return jsonify({"ok": False, "error": f"{key} must be greater than 0."}), 400

    effective_warning = parsed.get("warning_pct", STATE["warning_pct"])
    effective_critical = parsed.get("critical_pct", STATE["critical_pct"])
    if effective_warning >= effective_critical:
        return jsonify({"ok": False, "error":
                         "warning_pct must be less than critical_pct "
                         "(otherwise WARNING can never be reached)."}), 400

    cam_parsed = {}
    for key in CAMERA_POSITIVE_FIELDS:
        if key in data and data[key] not in (None, ""):
            try:
                cam_parsed[key] = float(data[key])
            except (TypeError, ValueError):
                return jsonify({"ok": False, "error": f"{key} must be a number."}), 400
            if cam_parsed[key] <= 0:
                return jsonify({"ok": False, "error": f"{key} must be greater than 0."}), 400

    parsed_gps = {}
    for key in ("cam_latitude", "cam_longitude"):
        if key in data and data[key] not in (None, ""):
            try:
                parsed_gps[key] = float(data[key])
            except (TypeError, ValueError):
                return jsonify({"ok": False, "error": f"{key} must be a number."}), 400
        elif key in data:
            parsed_gps[key] = None

    if "officials_phone" in data and data["officials_phone"] not in (None, ""):
        phone_str = str(data["officials_phone"])
        if not re.fullmatch(r"[0-9+,\s]*", phone_str):
            return jsonify({"ok": False, "error":
                             "officials_phone may only contain digits, '+', "
                             "commas, and spaces."}), 400

    changes = []
    for key, value in parsed.items():
        old = STATE.get(key)
        if old != value:
            changes.append(f"{key}: {old} -> {value}")
    for key, value in cam_parsed.items():
        old = cam.get(key)
        if old != value:
            changes.append(f"[{camera_id}] {key}: {old} -> {value}")
    if "cam_latitude" in parsed_gps and parsed_gps["cam_latitude"] != cam.get("latitude"):
        changes.append(f"[{camera_id}] latitude: {cam.get('latitude')} -> {parsed_gps['cam_latitude']}")
    if "cam_longitude" in parsed_gps and parsed_gps["cam_longitude"] != cam.get("longitude"):
        changes.append(f"[{camera_id}] longitude: {cam.get('longitude')} -> {parsed_gps['cam_longitude']}")
    if "cam_location_label" in data and data["cam_location_label"] != cam.get("label"):
        changes.append(f"[{camera_id}] label: {cam.get('label')!r} -> {data['cam_location_label']!r}")
    if "officials_phone" in data and data["officials_phone"] != STATE.get("officials_phone"):
        changes.append("officials_phone: changed")

    for key, value in parsed.items():
        STATE[key] = value
    for key, value in cam_parsed.items():
        cam[key] = value
    if "cam_latitude" in parsed_gps:
        cam["latitude"] = parsed_gps["cam_latitude"]
    if "cam_longitude" in parsed_gps:
        cam["longitude"] = parsed_gps["cam_longitude"]
    if "cam_location_label" in data:
        cam["label"] = data["cam_location_label"]
        cam["_label_set"] = True
    if "officials_phone" in data:
        STATE["officials_phone"] = data["officials_phone"]

    save_settings()
    save_camera_settings(cam)
    if changes:
        push_audit("config_change", "; ".join(changes))
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Priority officials (feature 6) - registered recipients with a location, so
# SMS alerts can be ranked "nearest to this camera first" with a priority
# tag, instead of everyone getting an identical, unordered blast. Anyone
# still only in the plain officials_phone field keeps getting the old
# unranked message - this is purely additive.
# ---------------------------------------------------------------------------
@app.route("/api/officials", methods=["GET"])
@require_viewer_or_admin
def api_officials_list():
    return jsonify({"ok": True, "officials": list_officials()})


@app.route("/api/officials", methods=["POST"])
@require_admin_key
def api_officials_add():
    data = request.get_json(force=True) or {}
    name = str(data.get("name", "")).strip()[:80]
    phone = str(data.get("phone", "")).strip()[:32]
    if not name or not phone:
        return jsonify({"ok": False, "error": "name and phone are both required"}), 400
    if not re.fullmatch(r"[+\d][\d\s\-]{5,30}", phone):
        return jsonify({"ok": False, "error": "phone looks invalid - use digits, '+', "
                         "spaces, or '-' only"}), 400

    location = str(data.get("location", "")).strip()[:80] or None

    lat, lon = data.get("latitude"), data.get("longitude")
    try:
        lat = float(lat) if lat not in (None, "") else None
        lon = float(lon) if lon not in (None, "") else None
        if (lat is None) != (lon is None):
            return jsonify({"ok": False, "error": "set both latitude and longitude, or neither"}), 400
        if lat is not None and not (-90 <= lat <= 90 and -180 <= lon <= 180):
            return jsonify({"ok": False, "error": "latitude/longitude out of range"}), 400
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "latitude/longitude must be numbers"}), 400

    # No lat/lon given but a recognized locality name was - auto-fill from
    # the known-localities table so the admin never has to type coordinates
    # by hand for common areas (e.g. "Tambaram", "Vandalur").
    if lat is None and location:
        auto_lat, auto_lon = resolve_locality(location)
        if auto_lat is not None:
            lat, lon = auto_lat, auto_lon

    add_official(name, phone, lat, lon, location)
    push_audit("official_added", f"{name} ({phone})" + (f" at {location}" if location else "")
               + (" with GPS" if lat is not None else " no location"))
    return jsonify({"ok": True, "officials": list_officials()})


@app.route("/api/officials/<int:official_id>", methods=["DELETE"])
@require_admin_key
def api_officials_delete(official_id):
    delete_official(official_id)
    push_audit("official_removed", f"id={official_id}")
    return jsonify({"ok": True, "officials": list_officials()})


# ---------------------------------------------------------------------------
# Shift/duty roster (feature 9): which official is scheduled to cover which
# zone/gate (camera_id) and when. Feeds directly into feature 4's "nearest
# available" logic - see nearest_officials_for_camera()'s on_roster ranking
# above - without touching an officer's own on_duty toggle or live GPS ping.
# ---------------------------------------------------------------------------
ROSTER_TIME_RE = re.compile(r"([01]\d|2[0-3]):([0-5]\d)")


@app.route("/api/roster", methods=["GET"])
@require_viewer_or_admin
def api_roster_list():
    """Every roster entry, optionally narrowed with ?official_id= or
    ?camera_id=."""
    official_id = request.args.get("official_id")
    camera_id = request.args.get("camera_id") or None
    try:
        official_id = int(official_id) if official_id is not None else None
    except ValueError:
        return jsonify({"ok": False, "error": "official_id must be an integer"}), 400
    return jsonify({"ok": True, "roster": list_roster_shifts(official_id, camera_id)})


@app.route("/api/roster", methods=["POST"])
@require_admin_key
def api_roster_add():
    data = request.get_json(force=True) or {}
    try:
        official_id = int(data.get("official_id"))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "official_id is required and must be an integer"}), 400
    if get_official(official_id) is None:
        return jsonify({"ok": False, "error": "No official with that id - add them above first."}), 404

    camera_id = str(data.get("camera_id", "")).strip()[:64]
    if not camera_id:
        return jsonify({"ok": False, "error": "camera_id is required (which zone/gate this shift covers)"}), 400
    if camera_id not in CAMERAS:
        return jsonify({"ok": False, "error": f"Unknown camera_id '{camera_id}' - "
                         "it must already have posted at least one update."}), 400

    day_of_week = data.get("day_of_week", None)
    if day_of_week is not None and day_of_week != "":
        try:
            day_of_week = int(day_of_week)
            if not (0 <= day_of_week <= 6):
                raise ValueError
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error":
                             "day_of_week must be 0 (Monday) - 6 (Sunday), or omitted for every day"}), 400
    else:
        day_of_week = None

    start_time = str(data.get("start_time", "")).strip()
    end_time = str(data.get("end_time", "")).strip()
    if not ROSTER_TIME_RE.fullmatch(start_time) or not ROSTER_TIME_RE.fullmatch(end_time):
        return jsonify({"ok": False, "error": "start_time/end_time must be 24-hour 'HH:MM' (e.g. '18:00'); "
                         "an end_time earlier than start_time is treated as an overnight shift"}), 400
    if start_time == end_time:
        return jsonify({"ok": False, "error": "start_time and end_time can't be the same (zero-length shift)"}), 400

    add_roster_shift(official_id, camera_id, day_of_week, start_time, end_time)
    push_audit("roster_shift_added",
               f"official_id={official_id} camera_id={camera_id} "
               f"{WEEKDAY_NAMES[day_of_week] if day_of_week is not None else 'every day'} "
               f"{start_time}-{end_time}")
    return jsonify({"ok": True, "roster": list_roster_shifts()})


@app.route("/api/roster/<int:shift_id>", methods=["DELETE"])
@require_admin_key
def api_roster_delete(shift_id):
    if not delete_roster_shift(shift_id):
        return jsonify({"ok": False, "error": "No roster shift with that id."}), 404
    push_audit("roster_shift_removed", f"id={shift_id}")
    return jsonify({"ok": True, "roster": list_roster_shifts()})


@app.route("/api/roster/now", methods=["GET"])
@require_official_or_dashboard
def api_roster_now():
    """Who's scheduled where right now, across every zone/gate that has a
    roster entry - the board a dispatcher glances at. For one specific
    gate's ranked dispatch order, use /api/officials/nearest instead, which
    factors this roster in automatically."""
    on_shift = [s for s in list_roster_shifts() if s["active_now"]]
    return jsonify({"ok": True, "on_shift_now": on_shift})


# ---------------------------------------------------------------------------
# Official mobile app auth (feature 8 - role-scoped auth, not the shared
# key). Two ways to get the same official token, same as admins have two
# ways in at /login:
#   1. Self-service: the officer signs in with their OWN username/password
#      at POST /api/official/login, same model as the admin/viewer `users`
#      table. This is now the primary path.
#   2. Admin-issued (POST /api/officials/<id>/token, below): kept as a
#      fallback for onboarding (e.g. a one-time QR code) or for an officer
#      who hasn't been given a username/password yet. Either way the
#      token only works for that one official_id, and either way
#      push_audit() below can now name the specific officer - not just
#      "admin" or "shared-key" - because require_official_token resolves
#      the officer's own username onto the request.
# ---------------------------------------------------------------------------
OFFICIAL_USERNAME_RE = re.compile(r"[A-Za-z0-9_.\-]{3,32}")


@app.route("/api/official/login", methods=["POST"])
def api_official_login():
    """Self-service login for an officer's own account - the mobile-app
    equivalent of POST /login for the admin dashboard. No admin needed
    once credentials exist; an admin only has to set them once via
    POST /api/officials/<id>/credentials."""
    if not JWT_AVAILABLE:
        return jsonify({"ok": False, "error": "PyJWT isn't installed on the server "
                         "(pip install pyjwt) - official tokens aren't available."}), 501
    ip = request.remote_addr or "unknown"
    if _login_rate_limited(ip):
        return jsonify({"ok": False, "error": "Too many attempts - try again in a few minutes."}), 429

    data = request.get_json(force=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    official = find_official_by_username(username)
    if (official is None or not official["password_hash"]
            or not check_password_hash(official["password_hash"], password)):
        _record_login_failure(ip)
        push_audit("official_login_failed", username or "(blank)", role="unknown", username=username or "(blank)")
        return jsonify({"ok": False, "error": "Incorrect username or password."}), 401

    try:
        hours = float(data.get("hours", 24 * 30))  # default: 30 days, same as admin-issued
    except (TypeError, ValueError):
        hours = 24 * 30
    token = issue_official_token(official["id"], hours)
    push_audit("official_login", "", role="official", username=official["username"])
    return jsonify({"ok": True, "token": token, "official_id": official["id"],
                     "name": official["name"], "expires_in_hours": hours})


@app.route("/api/officials/<int:official_id>/credentials", methods=["POST"])
@require_admin_key
def api_officials_set_credentials(official_id):
    """Admin sets (or resets) one officer's own username/password, so they
    can log in themselves at /api/official/login instead of everyone
    carrying an admin-issued token. Give the officer their new password
    out of band (in person, SMS, etc.) - it's never stored or returned in
    plain text after this response."""
    if get_official(official_id) is None:
        return jsonify({"ok": False, "error": "No official with that id - add them in Alerts & Controls first."}), 404
    data = request.get_json(force=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not OFFICIAL_USERNAME_RE.fullmatch(username):
        return jsonify({"ok": False, "error":
                         "Username must be 3-32 characters: letters, numbers, "
                         "underscore, dot, or hyphen."}), 400
    if len(password) < 6:
        return jsonify({"ok": False, "error": "Password must be at least 6 characters."}), 400

    ok, err = set_official_login(official_id, username, password)
    if not ok:
        return jsonify({"ok": False, "error": err}), 400
    push_audit("official_credentials_set", f"official_id={official_id} username={username}")
    return jsonify({"ok": True, "officials": list_officials()})


@app.route("/api/officials/<int:official_id>/credentials", methods=["DELETE"])
@require_admin_key
def api_officials_clear_credentials(official_id):
    """Revoke an officer's self-service login (lost phone, off-boarded,
    etc.) without deleting their record - existing tokens they already
    hold keep working until they expire, same as revoking a `users`
    account doesn't retroactively invalidate an already-open admin
    session. Give them fresh credentials afterward to re-enable login."""
    if not clear_official_login(official_id):
        return jsonify({"ok": False, "error": "No official with that id."}), 404
    push_audit("official_credentials_revoked", f"official_id={official_id}")
    return jsonify({"ok": True, "officials": list_officials()})


@app.route("/api/officials/<int:official_id>/token", methods=["POST"])
@require_admin_key
def api_officials_issue_token(official_id):
    """Admin-issued login credential for the official mobile app - a
    fallback for onboarding (e.g. a QR code) or an officer who hasn't set
    up their own username/password yet. Prefer giving the officer their
    own login via POST /api/officials/<id>/credentials instead, so the
    audit log can name them by their own username rather than lumping
    every admin-issued token under the officer's plain name. Either way,
    the token can only register a push token and ack alerts as this one
    official_id, nothing else."""
    if not JWT_AVAILABLE:
        return jsonify({"ok": False, "error": "PyJWT isn't installed on the server "
                         "(pip install pyjwt) - official tokens aren't available."}), 501
    if get_official(official_id) is None:
        return jsonify({"ok": False, "error": "No official with that id - add them in Alerts & Controls first."}), 404
    data = request.get_json(force=True) or {}
    try:
        hours = float(data.get("hours", 24 * 30))  # default: 30 days
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "hours must be a number"}), 400
    token = issue_official_token(official_id, hours)
    push_audit("official_token_issued", f"official_id={official_id}, hours={hours}")
    return jsonify({"ok": True, "token": token, "official_id": official_id, "expires_in_hours": hours})


@app.route("/api/official/push-token", methods=["POST"])
@require_official_token
def api_official_register_push_token():
    """Called by the mobile app on login/token-refresh to register (or
    clear, with an empty token) this official's FCM push token. Does NOT
    touch anything SMS-related - an official with no push token, or who
    never calls this, still gets every alert exactly as before, by SMS."""
    data = request.get_json(force=True) or {}
    token = str(data.get("token", "")).strip()[:512] or None
    if not save_push_token(request.official_id, token):
        return jsonify({"ok": False, "error": "Unknown official_id."}), 404
    return jsonify({"ok": True, "registered": token is not None})


@app.route("/api/official/alerts/sync", methods=["GET"])
@require_official_token
def api_official_sync_alerts():
    """'Sync missed alerts' - called on app open (and can be polled) so an
    official never has to trust push delivery alone. Returns alerts newer
    than ?since_ts=, oldest first, straight from the alerts table rather
    than the in-memory ALERTS deque, so it survives a server restart too."""
    try:
        since_ts = float(request.args.get("since_ts", 0))
    except (TypeError, ValueError):
        since_ts = 0
    conn = get_db()
    rows = conn.execute(
        "SELECT rowid AS id, ts, time, message, severity, camera_id, location, action, recommendation "
        "FROM alerts WHERE ts > ? ORDER BY ts ASC LIMIT 200", (since_ts,)).fetchall()
    conn.close()
    alerts = [{"id": r["id"], "ts": r["ts"], "time": r["time"], "message": r["message"],
               "severity": r["severity"], "camera_id": r["camera_id"], "location": r["location"],
               "action": r["action"], "recommendation": r["recommendation"]} for r in rows]
    return jsonify({"ok": True, "alerts": alerts, "server_ts": time.time()})


ALLOWED_ACK_STATUSES = {"acknowledged", "en_route", "on_site", "resolved"}


def _process_official_ack(official_id: int, alert_id, ack_status: str):
    """Shared by /api/alerts/<id>/ack and /api/official/sync-queue (feature
    7's batch flush). Returns (ok, body_dict, status_code)."""
    try:
        alert_id = int(alert_id)
    except (TypeError, ValueError):
        return False, {"error": "alert_id must be an integer"}, 400
    if ack_status not in ALLOWED_ACK_STATUSES:
        return False, {"error": f"status must be one of: {', '.join(sorted(ALLOWED_ACK_STATUSES))}"}, 400

    official = get_official(official_id)
    if official is None:
        return False, {"error": "Unknown official_id."}, 404

    ack = save_alert_ack(alert_id, official_id, official["name"], ack_status)
    socketio.emit("alert_ack", ack)
    push_audit("alert_ack", f"alert_id={alert_id} official={official['name']} status={ack_status}", role="official")
    return True, {"ack": ack}, 200


@app.route("/api/alerts/<int:alert_id>/ack", methods=["POST"])
@require_official_token
def api_alert_ack(alert_id):
    """Official taps Acknowledged / En Route / On Site / Resolved. Visible
    live on the admin dashboard via the alert_acks socket event, and stored
    so GET /api/alerts/acks (and the CSV export) can show it after the
    fact too.

    Offline resilience (feature 7): accepts an optional client_id, set by
    the mobile app when this ack was created while offline and queued for
    later. If the same client_id shows up again (e.g. the first send
    actually went through but the app never saw the response before
    losing signal), the ORIGINAL result is replayed instead of recording
    a second, duplicate ack."""
    data = request.get_json(force=True) or {}
    ack_status = str(data.get("status", "")).strip().lower()
    client_id = str(data.get("client_id") or "").strip()[:128] or None

    cached = get_synced_result(client_id) if client_id else None
    if cached is not None:
        return jsonify({"ok": True, **cached})

    ok, body, http_status = _process_official_ack(request.official_id, alert_id, ack_status)
    if ok and client_id:
        save_synced_result(client_id, "ack", request.official_id, body)
    return jsonify({"ok": ok, **body}), http_status


@app.route("/api/alerts/acks", methods=["GET"])
@require_viewer_or_admin
def api_alerts_acks():
    """For the admin dashboard: current ack status per alert. Optional
    ?alert_id= narrows to one alert's full history (e.g. acknowledged by
    officer A at 10:02, resolved by officer B at 10:15)."""
    alert_id = request.args.get("alert_id")
    try:
        alert_id = int(alert_id) if alert_id is not None else None
    except ValueError:
        return jsonify({"ok": False, "error": "alert_id must be an integer"}), 400
    return jsonify({"ok": True, "acks": list_acks(alert_id)})


@app.route("/api/officials/<int:official_id>/assign-camera", methods=["POST"])
@require_admin_key
def api_officials_assign_camera(official_id):
    """Admin sets which camera an official's mobile app should show on its
    live view (feature 3). Pass {"camera_id": null} to unassign - the
    official's app then falls back to a read-only summary of every
    camera instead of one in particular."""
    if get_official(official_id) is None:
        return jsonify({"ok": False, "error": "No official with that id."}), 404
    data = request.get_json(force=True) or {}
    camera_id = data.get("camera_id")
    camera_id = str(camera_id).strip()[:64] if camera_id else None
    if camera_id and camera_id not in CAMERAS:
        return jsonify({"ok": False, "error": f"Unknown camera_id '{camera_id}' - "
                         "it must already have posted at least one update."}), 400
    set_assigned_camera(official_id, camera_id)
    push_audit("official_camera_assigned", f"official_id={official_id} -> camera_id={camera_id}")
    return jsonify({"ok": True, "official_id": official_id, "assigned_camera_id": camera_id})


@app.route("/api/official/state", methods=["GET"])
@require_official_token
def api_official_state():
    """Live situational view for the mobile app (feature 3) - a scoped,
    read-only slice of /api/state and /api/cameras. No admin controls, no
    other officials' contact details, no SMS log - just headcount, zone
    density, and risk tier for whichever camera(s) this official cares
    about. If they're assigned one camera, that's all they get; otherwise
    they get the same read-only summary for every camera, still without
    anything admin-only."""
    official = get_official(request.official_id)
    if official is None:
        return jsonify({"ok": False, "error": "Unknown official_id."}), 404

    assigned = official["assigned_camera_id"] if "assigned_camera_id" in official.keys() else None

    if assigned and assigned in CAMERAS:
        cam = CAMERAS[assigned]
        return jsonify({
            "ok": True,
            "scope": "assigned_camera",
            "camera": {
                **camera_summary(cam),
                "zone_risk": zone_risk_levels(cam),
                "recommended_police": cam["recommended_police"],
                "police_reason": cam["police_reason"],
            },
            "warning_pct": STATE["warning_pct"],
            "critical_pct": STATE["critical_pct"],
            "server_ts": time.time(),
        })

    # Unassigned (or assigned camera no longer exists) - fall back to a
    # read-only summary of every camera, same fields, no per-camera detail
    # beyond what camera_summary()/zone_risk_levels() already expose.
    return jsonify({
        "ok": True,
        "scope": "all_cameras",
        "cameras": [{**camera_summary(c), "zone_risk": zone_risk_levels(c)} for c in CAMERAS.values()],
        "combined_risk_level": combined_risk_level(),
        "combined_current_count": combined_current_count(),
        "warning_pct": STATE["warning_pct"],
        "critical_pct": STATE["critical_pct"],
        "server_ts": time.time(),
    })


@app.route("/api/official/location", methods=["POST"])
@require_official_token
def api_official_location():
    """GPS-based officer assignment (feature 4), the officer's side: the
    mobile app calls this periodically (e.g. every 30-60s while the app is
    open) to share a live location ping. Requires explicit consent=true in
    the body on every call - there's no way to start/continue receiving
    location pings without it, and the app should stop calling this the
    moment the officer turns location sharing off."""
    data = request.get_json(force=True) or {}
    if data.get("consent") is not True:
        return jsonify({"ok": False, "error": "consent must be explicitly true to share location - "
                         "the app should stop calling this endpoint if the officer has location "
                         "sharing turned off."}), 400
    try:
        lat = float(data.get("latitude"))
        lon = float(data.get("longitude"))
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "latitude/longitude are required and must be valid GPS coordinates"}), 400
    accuracy_m = data.get("accuracy_m")
    try:
        accuracy_m = float(accuracy_m) if accuracy_m is not None else None
    except (TypeError, ValueError):
        accuracy_m = None

    if get_official(request.official_id) is None:
        return jsonify({"ok": False, "error": "Unknown official_id."}), 404

    loc = save_official_location(request.official_id, lat, lon, accuracy_m)
    return jsonify({"ok": True, "location": loc})


@app.route("/api/official/duty", methods=["POST"])
@require_official_token
def api_official_duty():
    """Official marks themselves on/off duty - off-duty officials are
    skipped by GET /api/officials/nearest below, so a dispatcher never gets
    pointed at someone who isn't actually working right now."""
    data = request.get_json(force=True) or {}
    on_duty = data.get("on_duty")
    if not isinstance(on_duty, bool):
        return jsonify({"ok": False, "error": "on_duty must be true or false"}), 400
    if not set_on_duty(request.official_id, on_duty):
        return jsonify({"ok": False, "error": "Unknown official_id."}), 404
    return jsonify({"ok": True, "official_id": request.official_id, "on_duty": on_duty})


@app.route("/api/officials/nearest", methods=["GET"])
@require_viewer_or_admin
def api_officials_nearest():
    """The 'who' that recommend_police() doesn't provide - on-duty
    officials ranked for a camera, preferring each officer's live GPS ping
    over their static registered location when a recent one is on file.
    Anyone whose shift roster (feature 9) currently assigns them to this
    exact camera_id is ranked first (on_roster: true), ahead of everyone
    else by plain distance. ?camera_id= is required; ?limit= defaults to 3."""
    camera_id = request.args.get("camera_id")
    if not camera_id:
        return jsonify({"ok": False, "error": "camera_id is required"}), 400
    cam = CAMERAS.get(camera_id)
    if cam is None:
        return jsonify({"ok": False, "error": f"Unknown camera_id '{camera_id}'"}), 404
    try:
        limit = int(request.args.get("limit", 3))
    except ValueError:
        return jsonify({"ok": False, "error": "limit must be an integer"}), 400
    nearest = nearest_officials_for_camera(cam, limit=limit)
    return jsonify({"ok": True, "camera_id": camera_id, "nearest_officials": nearest})


MAX_REPORT_MESSAGE_CHARS = 300


def _process_official_report(official_id: int, data: dict):
    """Shared by /api/official/report and /api/official/sync-queue
    (feature 7's batch flush). Returns (ok, body_dict, status_code)."""
    official = get_official(official_id)
    if official is None:
        return False, {"error": "Unknown official_id."}, 404

    message = str(data.get("message", "")).strip()[:MAX_REPORT_MESSAGE_CHARS]
    if not message:
        return False, {"error": "message is required"}, 400

    camera_id = str(data.get("camera_id") or "").strip()[:64] or None
    if camera_id and camera_id not in CAMERAS:
        return False, {"error": f"Unknown camera_id '{camera_id}'"}, 400
    if camera_id is None:
        # Fall back to whichever camera this official is assigned to watch,
        # same scoping as their live view (feature 3) - not required, but
        # saves the app from having to ask "which camera?" every time.
        camera_id = official["assigned_camera_id"] if "assigned_camera_id" in official.keys() else None

    if camera_id and camera_id in CAMERAS:
        camera_label = CAMERAS[camera_id]["label"]
    else:
        camera_label = official["location"] if "location" in official.keys() and official["location"] else "Unspecified location"

    photo_b64 = data.get("photo_b64")
    content_type = str(data.get("content_type") or "image/jpeg")[:32]
    if photo_b64 is not None:
        photo_b64 = str(photo_b64)
        if len(photo_b64) > MAX_PHOTO_B64_CHARS:
            return False, {"error": "photo is too large (max ~5MB)"}, 413

    full_message = f"OFFICIAL REPORT from {official['name']}: {message}"
    alert_id = push_alert(full_message, "REPORT", camera_id or "unassigned", camera_label,
                           action="Reported by official - needs review",
                           recommendation=None)

    if photo_b64:
        save_alert_photo(alert_id, photo_b64, content_type)

    push_audit("official_report", f"official={official['name']} camera={camera_id or 'unassigned'}: "
               f"{message[:80]}" + (" [with photo]" if photo_b64 else ""), role="official")

    return True, {"alert_id": alert_id, "has_photo": bool(photo_b64)}, 200


@app.route("/api/official/report", methods=["POST"])
@require_official_token
def api_official_report():
    """Two-way incident reporting (feature 5) - an official-initiated
    report ('Crowd surge at Gate 2', optional photo), flowing into the
    SAME alerts/audit_log tables as system-raised alerts via the existing
    push_alert()/push_audit(), so it shows up in the admin's Alerts tab,
    the live socket feed, and the CSV export with no separate code path
    there. Distinguished from system alerts by severity='REPORT'.

    Offline resilience (feature 7): accepts an optional client_id, set by
    the mobile app when this report was written while offline and queued
    for later. A retry with the same client_id replays the original
    result (same alert_id) instead of filing the same incident twice."""
    data = request.get_json(force=True) or {}
    client_id = str(data.get("client_id") or "").strip()[:128] or None

    cached = get_synced_result(client_id) if client_id else None
    if cached is not None:
        return jsonify({"ok": True, **cached})

    ok, body, http_status = _process_official_report(request.official_id, data)
    if ok and client_id:
        save_synced_result(client_id, "report", request.official_id, body)
    return jsonify({"ok": ok, **body}), http_status


MAX_SYNC_QUEUE_ITEMS = 200


@app.route("/api/official/sync-queue", methods=["POST"])
@require_official_token
def api_official_sync_queue():
    """Offline resilience (feature 7): the mobile app's single flush call
    for whatever it queued locally while signal was patchy - any mix of
    acks (see _process_official_ack) and incident reports (see
    _process_official_report), oldest first. Each item still carries its
    own client_id (the same one it would've used sending individually), so
    a retry of the WHOLE batch - e.g. the app lost signal again partway
    through reading the response - is just as safe as retrying one item:
    anything already processed comes back with its original result instead
    of being recorded twice. Every item is processed and reported on
    individually rather than failing the whole call for one bad item, so a
    few days' worth of queued actions aren't all lost because one of them
    (e.g. a very old alert_id) has since become invalid."""
    data = request.get_json(force=True) or {}
    items = data.get("items")
    if not isinstance(items, list) or not items:
        return jsonify({"ok": False, "error": "items must be a non-empty list"}), 400
    if len(items) > MAX_SYNC_QUEUE_ITEMS:
        return jsonify({"ok": False, "error": f"too many items in one batch "
                         f"(max {MAX_SYNC_QUEUE_ITEMS})"}), 400

    results = []
    for item in items:
        if not isinstance(item, dict):
            results.append({"ok": False, "error": "each item must be an object"})
            continue
        client_id = str(item.get("client_id") or "").strip()[:128] or None
        item_type = str(item.get("type") or "").strip().lower()

        cached = get_synced_result(client_id) if client_id else None
        if cached is not None:
            results.append({"ok": True, "client_id": client_id, **cached})
            continue

        if item_type == "ack":
            ack_status = str(item.get("status", "")).strip().lower()
            ok, body, _http = _process_official_ack(request.official_id, item.get("alert_id"), ack_status)
        elif item_type == "report":
            ok, body, _http = _process_official_report(request.official_id, item)
        else:
            ok, body = False, {"error": "type must be 'ack' or 'report'"}

        if ok and client_id:
            save_synced_result(client_id, item_type, request.official_id, body)

        results.append({"ok": ok, "client_id": client_id, **body})

    push_audit("official_queue_synced", f"official_id={request.official_id}: "
               f"{len(items)} queued item(s) flushed ({sum(1 for r in results if r['ok'])} ok)",
               role="official")
    return jsonify({"ok": True, "processed": len(results), "results": results})


@app.route("/api/alerts/<int:alert_id>/photo", methods=["GET"])
@require_viewer_or_admin
def api_alert_photo(alert_id):
    """Fetch the optional photo attached to an official's incident report.
    Kept out of the main alerts list response so a plain GET /api/state
    never has to drag a base64 blob along for every alert that doesn't
    have one."""
    photo = get_alert_photo(alert_id)
    if photo is None:
        return jsonify({"ok": False, "error": "No photo for that alert_id."}), 404
    return jsonify({"ok": True, "alert_id": alert_id, "photo_b64": photo["photo_b64"],
                     "content_type": photo["content_type"]})


@app.route("/api/official/sos", methods=["POST"])
@require_official_token
def api_official_sos():
    """Officer's own emergency (feature 6) - distinct from the admin's
    demo panic button (/api/simulate/panic), which simulates a crowd
    surge at a camera. This is a real official signaling THEIR OWN
    emergency: it raises a CRITICAL-equivalent alert visible to the admin
    instantly, and broadcasts to every other official by SMS + push,
    bypassing the normal nearest-2/cooldown targeting rules entirely - see
    send_sos_broadcast(). location is optional but recommended: pass
    latitude/longitude directly in this call (a genuine emergency is
    itself the consent to share location for it - separate from the
    ongoing consent-gated periodic pings in /api/official/location)."""
    official = get_official(request.official_id)
    if official is None:
        return jsonify({"ok": False, "error": "Unknown official_id."}), 404

    data = request.get_json(force=True) or {}
    custom_message = str(data.get("message", "")).strip()[:200]

    lat, lon = data.get("latitude"), data.get("longitude")
    try:
        lat = float(lat) if lat not in (None, "") else None
        lon = float(lon) if lon not in (None, "") else None
        if (lat is None) != (lon is None):
            lat = lon = None  # need both or neither
    except (TypeError, ValueError):
        lat = lon = None

    if lat is None:
        # No location in this request - fall back to their most recent
        # live ping on file, if any (e.g. they had location sharing on
        # from feature 4 already).
        loc = get_official_location(request.official_id)
        if loc is not None:
            lat, lon = loc["latitude"], loc["longitude"]

    camera_id = official["assigned_camera_id"] if "assigned_camera_id" in official.keys() else None
    camera_label = (CAMERAS[camera_id]["label"] if camera_id and camera_id in CAMERAS
                     else (official["location"] if "location" in official.keys() and official["location"] else "Unspecified location"))

    alert_message = f"\U0001F6A8 OFFICER SOS from {official['name']}" + (f": {custom_message}" if custom_message else "")
    alert_id = push_alert(alert_message, "SOS", camera_id or "unassigned", camera_label,
                           action="IMMEDIATE - locate and assist this officer",
                           recommendation=f"Last known location: {lat}, {lon}" if lat is not None else None)

    broadcast = send_sos_broadcast(request.official_id, official["name"], custom_message, lat, lon)
    push_audit("official_sos", f"official={official['name']} notified {broadcast['notified_count']} "
               f"other official(s)", role="official")

    return jsonify({"ok": True, "alert_id": alert_id, "notified_officials": broadcast["notified_count"]})


# ---------------------------------------------------------------------------
# Route the detection script(s) post to
# ---------------------------------------------------------------------------
MAX_REASONABLE_COUNT = int(os.environ.get("MAX_REASONABLE_COUNT", 5000))


@app.route("/api/device-token", methods=["POST"])
@require_admin_key
def api_device_token():
    """Issue a device JWT for one camera_id, valid for `hours` (default 24).
    Give this to that camera's detection_client.py instead of the shared
    ADMIN_API_KEY - it can only post updates for this one camera_id, and
    stops working on its own once it expires (no separate revoke needed for
    the common case of "this camera's laptop got lost/stolen" - just don't
    reissue it a new one)."""
    if not JWT_AVAILABLE:
        return jsonify({"ok": False, "error": "PyJWT isn't installed on the server "
                         "(pip install pyjwt) - device tokens aren't available; "
                         "detection_client.py can still use the shared admin key."}), 501
    data = request.get_json(force=True) or {}
    camera_id = str(data.get("camera_id") or "").strip()[:64]
    if not camera_id:
        return jsonify({"ok": False, "error": "camera_id is required"}), 400
    try:
        hours = float(data.get("hours", 24))
        hours = max(0.1, min(hours, 24 * 30))  # clamp: 6 minutes to 30 days
    except (TypeError, ValueError):
        hours = 24
    token = issue_device_token(camera_id, hours)
    push_audit("device_token_issued", f"camera_id={camera_id} hours={hours}")
    return jsonify({"ok": True, "camera_id": camera_id, "token": token,
                     "expires_in_hours": hours})


def _authorize_camera_update(camera_id_for_auth: str) -> bool:
    """Two ways in: the shared ADMIN_API_KEY (unchanged), or a per-camera
    device token scoped to exactly this camera_id. Shared by /api/update
    and /api/update/batch (feature 7) so a queued/replayed batch can't be
    used to post as a camera_id the caller's token isn't scoped to."""
    bearer = request.headers.get("Authorization", "")
    device_token = bearer[7:] if bearer.startswith("Bearer ") else None
    return _is_authorized() or bool(device_token and verify_device_token(device_token, camera_id_for_auth))


def _apply_live_update(data: dict):
    """The full 'this reading is happening right now' pipeline: updates
    current_count/risk, runs alert+SMS+push logic, and broadcasts
    state_update over the socket. Used by /api/update directly, and by
    /api/update/batch (feature 7) for the single most-recent item in a
    queued batch - everything earlier in that batch is a stale reading
    that already happened, so it's backfilled via _apply_backfill_point
    instead of re-running alerts/SMS for something in the past.
    Returns (ok, body_dict, status_code)."""
    try:
        count = int(data.get("count", 0))
    except (TypeError, ValueError):
        return False, {"ok": False, "error": "count must be an integer"}, 400
    if count < 0 or count > MAX_REASONABLE_COUNT:
        return False, {"ok": False, "error": f"count out of range "
                        f"(0-{MAX_REASONABLE_COUNT})"}, 400

    camera_id = str(data.get("camera_id") or DEFAULT_CAMERA_ID)[:64]
    cam = get_or_create_camera(camera_id, label=data.get("label"))

    # Zone/density payload (feature 5): a flat list of per-cell counts plus
    # the grid shape. Optional - cameras that don't send it just show a
    # single venue-wide count, same as before.
    zone_counts = data.get("zone_counts")
    zone_rows = data.get("zone_rows")
    zone_cols = data.get("zone_cols")
    if isinstance(zone_counts, list) and isinstance(zone_rows, int) and isinstance(zone_cols, int) \
            and len(zone_counts) == zone_rows * zone_cols and zone_rows * zone_cols > 0:
        try:
            cam["zone_counts"] = [max(0, int(z)) for z in zone_counts]
            cam["zone_rows"], cam["zone_cols"] = zone_rows, zone_cols
        except (TypeError, ValueError):
            pass  # malformed zone data just gets ignored, count still applies

    frame_b64 = data.get("frame")
    is_black = data.get("is_black", False)

    cam["current_count"] = count
    now = time.time()
    cam["last_seen"] = now
    cam["is_black"] = is_black

    # The reading's own capture time (offline resilience, feature 7): when
    # this came from a queued-then-flushed batch (see /api/update/batch),
    # data may carry the client_ts it was actually captured at, which can
    # be well before "now" (the moment the batch finally reached the
    # server after an outage). The history point/row should be timestamped
    # at THAT moment, not at replay time - otherwise every outage recovery
    # would leave the most recent Analytics point mistimed and skew
    # compute_growth_rate() right when it matters most. A normal live
    # /api/update call has no client_ts, so this is just `now`, same as
    # before. Cooldowns and last_seen above intentionally keep using real
    # wall-clock `now` - they gate real-world alert/SMS frequency and
    # camera-liveness tracking, not "when was this reading captured".
    try:
        event_ts = float(data.get("client_ts"))
        if event_ts <= 0:
            raise ValueError
    except (TypeError, ValueError):
        event_ts = now

    point = {"t": event_ts, "count": count}
    cam["history"].append(point)

    new_risk = compute_risk(count, cam["max_capacity"])
    risk_changed = new_risk != cam["risk_level"]
    cam["risk_level"] = new_risk

    if now - cam["last_history_save"] >= STATE["history_save_interval"]:
        save_history_point(event_ts, count, new_risk, camera_id)
        cam["last_history_save"] = now

    if frame_b64:
        LATEST_FRAMES[camera_id] = base64.b64decode(frame_b64)

    recommended, reason = recommend_police(count, new_risk, cam)
    cam["recommended_police"] = recommended
    cam["police_reason"] = reason

    plan = recommend_clearance_plan(count, new_risk, cam)
    cam["clearance_plan"] = plan

    # Alert cooldown (feature 4): both windows now come from STATE, which
    # is editable live from Alerts & Controls instead of fixed in code.
    new_alert_id = None
    if new_risk in ("WARNING", "CRITICAL") and (
        risk_changed or now - cam["last_alert_time"] > STATE["alert_cooldown"]
    ):
        new_alert_id = push_alert(f"{new_risk}: {count} people detected at {cam['label']} "
                   f"({count}/{int(cam['max_capacity'])} capacity) - "
                   f"recommend {recommended} officers on site"
                   f"{gps_alert_suffix(cam)}", new_risk, camera_id, cam["label"],
                   action=f"Recommend {recommended} officers on site ({reason})" if recommended else "Monitor",
                   recommendation="; ".join(plan) if plan else None)
        cam["last_alert_time"] = now

    if new_risk in ("WARNING", "CRITICAL") and (
        risk_changed or now - cam["last_sms_time"] > STATE["sms_cooldown"]
    ):
        send_sms_alert(count, new_risk, recommended, plan, cam)
        send_push_alert(new_alert_id, count, new_risk, recommended, plan, cam)
        cam["last_sms_time"] = now

    socketio.emit("state_update", {
        "camera_id": camera_id,
        "current_count": count,
        "risk_level": new_risk,
        "max_capacity": cam["max_capacity"],
        "recommended_police": recommended,
        "police_reason": reason,
        "clearance_plan": plan,
        "point": point,
        "zone_counts": cam["zone_counts"],
        "zone_rows": cam["zone_rows"],
        "zone_cols": cam["zone_cols"],
        "zone_risk": zone_risk_levels(cam),
        "is_black": is_black,
        "combined_risk_level": combined_risk_level(),
        "combined_current_count": combined_current_count(),
        "cameras": [camera_summary(c) for c in CAMERAS.values()],
    })
    return True, {"ok": True}, 200


def _apply_backfill_point(data: dict):
    """Offline resilience (feature 7): writes one stale/queued reading
    straight into the `history` table so it still shows up in the
    Analytics tab's day-over-day chart, WITHOUT touching current_count,
    risk_level, alerts, SMS, or the live socket feed - that reading's
    moment has already passed, so treating it as 'now' would either
    flicker the live dashboard with an old number or fire a stale alert.
    Used for every item in a /api/update/batch flush except the last.
    Returns (ok, body_dict, status_code)."""
    try:
        count = int(data.get("count", 0))
    except (TypeError, ValueError):
        return False, {"ok": False, "error": "count must be an integer"}, 400
    if count < 0 or count > MAX_REASONABLE_COUNT:
        return False, {"ok": False, "error": f"count out of range "
                        f"(0-{MAX_REASONABLE_COUNT})"}, 400

    camera_id = str(data.get("camera_id") or DEFAULT_CAMERA_ID)[:64]
    cam = get_or_create_camera(camera_id, label=data.get("label"))

    try:
        ts = float(data.get("client_ts"))
        if ts <= 0:
            raise ValueError
    except (TypeError, ValueError):
        ts = time.time()  # no/garbled client_ts - still record it, just without exact backdating

    risk = compute_risk(count, cam["max_capacity"])
    save_history_point(ts, count, risk, camera_id)
    return True, {"ok": True, "backfilled": True, "ts": ts}, 200


@app.route("/api/update", methods=["POST"])
def api_update():
    # Checked manually here (rather than a blanket @require_admin_key)
    # because the device token's validity depends on the camera_id inside
    # the body, which we don't have until after parsing it.
    data = request.get_json(force=True)
    camera_id_for_auth = str(data.get("camera_id") or DEFAULT_CAMERA_ID)[:64]
    if not _authorize_camera_update(camera_id_for_auth):
        body, code = _UNAUTHORIZED_RESPONSE
        return jsonify(body), code
    ok, body, status = _apply_live_update(data)
    return jsonify(body), status


MAX_BATCH_UPDATE_ITEMS = 500  # generous - a queued outage of e.g. one reading/sec for a
                              # few minutes is still well under this; caps one call's work


@app.route("/api/update/batch", methods=["POST"])
def api_update_batch():
    """Offline resilience (feature 7): detection_client.py now queues each
    reading locally (SQLite) whenever it can't reach /api/update - patchy
    venue wifi, server restart, network blip - instead of silently
    dropping it. Once the connection is back, it flushes the whole queue
    here in one call, oldest first. Every item except the last is
    backfilled into history only (see _apply_backfill_point); the last
    item - the most recent reading - runs the full live pipeline (see
    _apply_live_update), same as a normal /api/update, since that one
    really does represent 'right now'. Each item is authorized exactly
    like a standalone /api/update for its own camera_id, so a device
    token still can't be used to post readings for a camera it wasn't
    issued for, queued or not."""
    data = request.get_json(force=True) or {}
    items = data.get("items")
    if not isinstance(items, list) or not items:
        return jsonify({"ok": False, "error": "items must be a non-empty list"}), 400
    if len(items) > MAX_BATCH_UPDATE_ITEMS:
        return jsonify({"ok": False, "error": f"too many items in one batch "
                         f"(max {MAX_BATCH_UPDATE_ITEMS}) - send smaller batches"}), 400

    for item in items:
        if not isinstance(item, dict):
            return jsonify({"ok": False, "error": "each item must be an object"}), 400
        camera_id_for_auth = str(item.get("camera_id") or DEFAULT_CAMERA_ID)[:64]
        if not _authorize_camera_update(camera_id_for_auth):
            body, code = _UNAUTHORIZED_RESPONSE
            return jsonify(body), code

    results = []
    last_index = len(items) - 1
    for i, item in enumerate(items):
        if i == last_index:
            ok, body, status = _apply_live_update(item)
        else:
            ok, body, status = _apply_backfill_point(item)
        result = {"ok": ok}
        if not ok:
            result["error"] = body.get("error")
        results.append(result)

    push_audit("update_batch_synced", f"{len(items)} queued reading(s) flushed "
               f"({sum(1 for r in results if r['ok'])} ok)")
    return jsonify({"ok": True, "processed": len(results), "results": results})


# ---------------------------------------------------------------------------
# Demo controls
# ---------------------------------------------------------------------------
@app.route("/api/simulate/<action>", methods=["POST"])
@require_admin_key
def api_simulate(action):
    camera_id = request.args.get("camera_id") or DEFAULT_CAMERA_ID
    cam = get_or_create_camera(camera_id)
    count = cam["current_count"]
    panic_alert_id = None
    if action == "add":
        count += 50
    elif action == "remove":
        count = max(0, count - 50)
    elif action == "panic":
        count = int(cam["max_capacity"] * 1.1)
        panic_risk = compute_risk(count, cam["max_capacity"])
        panic_officers, panic_reason = recommend_police(count, panic_risk, cam)
        panic_plan = recommend_clearance_plan(count, panic_risk, cam)
        panic_alert_id = push_alert("SIMULATED EMERGENCY: Rapid crowd surge detected" + gps_alert_suffix(cam),
                   "CRITICAL", camera_id, cam["label"],
                   action=f"Recommend {panic_officers} officers on site ({panic_reason})",
                   recommendation="; ".join(panic_plan) if panic_plan else None)
    elif action == "clear":
        count = 0
        clear_all_data()
        cam["clearance_plan"] = []

    cam["current_count"] = count
    cam["last_seen"] = time.time()
    cam["risk_level"] = compute_risk(count, cam["max_capacity"])
    recommended, reason = recommend_police(count, cam["risk_level"], cam)
    cam["recommended_police"] = recommended
    cam["police_reason"] = reason
    plan = recommend_clearance_plan(count, cam["risk_level"], cam)
    cam["clearance_plan"] = plan
    now = time.time()
    point = {"t": now, "count": count}
    cam["history"].append(point)
    save_history_point(now, count, cam["risk_level"], camera_id)

    if action == "panic":
        send_sms_alert(count, cam["risk_level"], recommended, plan, cam)
        send_push_alert(panic_alert_id, count, cam["risk_level"], recommended, plan, cam)

    push_audit(f"simulate_{action}", f"[{camera_id}] count -> {count}")

    socketio.emit("state_update", {
        "camera_id": camera_id,
        "current_count": count,
        "risk_level": cam["risk_level"],
        "max_capacity": cam["max_capacity"],
        "recommended_police": recommended,
        "police_reason": reason,
        "clearance_plan": plan,
        "point": point,
        "zone_counts": cam["zone_counts"],
        "zone_rows": cam["zone_rows"],
        "zone_cols": cam["zone_cols"],
        "zone_risk": zone_risk_levels(cam),
        "is_black": is_black,
        "combined_risk_level": combined_risk_level(),
        "combined_current_count": combined_current_count(),
        "cameras": [camera_summary(c) for c in CAMERAS.values()],
    })
    return jsonify({"ok": True})


# Runs on import, not just when this file is executed directly, so that
# production servers like gunicorn (which import `app.py` as a module and
# never hit __name__ == "__main__") still create tables, seed default
# users/officials, and load state before serving any requests.
init_db()
bootstrap_default_users()
bootstrap_default_officials()
load_settings()
load_camera_settings()

_all_history = load_recent_history(limit=1500)
for _p in _all_history:
    _cam = get_or_create_camera(_p["camera_id"] or DEFAULT_CAMERA_ID)
    _cam["history"].append({"t": _p["t"], "count": _p["count"]})
for _a in reversed(load_recent_alerts(50)):
    ALERTS.appendleft(_a)
for _s in reversed(load_recent_sms(50)):
    SMS_LOG.appendleft(_s)
for _e in reversed(load_recent_audit_log(150)):
    AUDIT_LOG.appendleft(_e)

for _cam in CAMERAS.values():
    if _cam["history"]:
        _last = _cam["history"][-1]
        _cam["current_count"] = _last["count"]
        _cam["risk_level"] = compute_risk(_last["count"], _cam["max_capacity"])

if not CAMERAS:
    get_or_create_camera(DEFAULT_CAMERA_ID)


if __name__ == "__main__":
    print("\nCROWD GUARD 2.0 server starting...")
    print("Open this on the SAME device:   http://localhost:5000")
    print("Open this from phone/tablet/other laptop on the same Wi-Fi:")
    print("  -> find your PC's local IP with 'ipconfig' (look for IPv4 Address)")
    print("  -> then visit  http://<that-ip>:5000  from the other device\n")

    # --https : local-testing-only self-signed TLS (needs `pip install
    # pyopenssl`). Real deployments (Render, a reverse proxy, etc.) should
    # terminate TLS there instead - see README.md's Deployment section.
    ssl_context = None
    if "--https" in sys.argv:
        ssl_context = "adhoc"
        print("[https] Using a self-signed certificate for LOCAL TESTING ONLY.")
        print("        Your browser will show a security warning - that's expected;")
        print("        click through it (e.g. \"Advanced -> Proceed\"). Requires")
        print("        `pip install pyopenssl`. Do not use --https for a real")
        print("        deployment - see README.md instead.\n")

    run_args = {
        "app": app,
        "host": "0.0.0.0",
        "port": int(os.environ.get("PORT", 5000)),
        "debug": False,
        "allow_unsafe_werkzeug": True
    }
    if ssl_context:
        run_args["ssl_context"] = ssl_context

    socketio.run(**run_args)
