# CROWD GUARD 3.0

Real-time crowd detection and monitoring dashboard, with optional SMS alerts
to officials when crowd risk crosses a threshold.

## What's new in this version

- **Multi-camera support.** Run one `detection_client.py` per physical
  camera (each with its own `CAMERA_ID` in its `.env`). The dashboard's
  camera switcher shows every camera that has ever posted, with a combined
  venue-wide risk pill that reflects the worst risk tier among currently
  online cameras.
- **Zone/density grid.** Each camera can divide its frame into a
  `ZONE_ROWS` x `ZONE_COLS` grid and report a per-cell headcount, so a
  local crush near one exit shows up on the dashboard's Zone Density Map
  even while the overall average still reads SAFE.
- **Individual admin/viewer accounts.** username + password logins on top
  of the original shared-key auth, managed from Alerts & Controls, so the
  activity log can name a specific person instead of just "admin". The
  shared `ADMIN_API_KEY`/`VIEWER_API_KEY` still work (required for
  `detection_client.py`, and as a login fallback).
- **Configurable alert/SMS cooldowns**, editable from Alerts & Controls
  instead of fixed in code.
- **Day-over-day analytics.** The Analytics tab now includes a peak/average
  chart comparing the last 7/14/30 days, not just the live session.
- **Shift/duty roster.** Schedule which official covers which zone/gate and
  when, from Alerts & Controls - a shift can repeat every day or run on one
  specific weekday, and an end time earlier than the start time (e.g.
  22:00 → 06:00) is an overnight shift. `GET /api/officials/nearest`'s
  "nearest available" dispatch ranking now lists whoever's roster currently
  covers that exact gate first (ahead of anyone merely standing closer at
  that moment); `GET /api/roster/now` shows who's on shift where, across
  every gate, right now. The roster is purely a schedule - it never
  overrides an officer's own on/off-duty toggle or their live GPS ping.

## Setup

1. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

   If you have an NVIDIA GPU and want CUDA-accelerated detection, install the
   CUDA build of `torch` from https://pytorch.org instead of the default CPU
   build that `pip install` pulls in.

2. **Create your `.env` file**

   Copy `.env.example` to `.env` and fill in real values:

   ```bash
   cp .env.example .env
   ```

   - `ADMIN_API_KEY` / `SECRET_KEY` — set these to your own long random
     strings. If left unset, the app generates temporary ones on every
     restart (fine for a quick local test, but you'll be logged out and
     `detection_client.py` will need updating every time you restart).
   - `TWILIO_ACCOUNT_SID` / `TWILIO_AUTH_TOKEN` / `TWILIO_FROM_NUMBER` — only
     needed if you want SMS alerts to actually send. Get these from
     https://www.twilio.com/console. Without them, the app still runs fine —
     alerts are just logged instead of texted.

3. **First run downloads the detection model**

   `detection_client.py` uses the YOLO11n model (`yolo11n.pt`). This file
   isn't bundled with the project — `ultralytics` downloads it automatically
   the first time you run the detection client, provided you have internet
   access at that point. After the first run, it's cached locally and no
   further downloads happen.

4. **Run it**

   ```bash
   python app.py
   ```

   In a separate terminal:

   ```bash
   python detection_client.py
   ```

   Then open `http://localhost:5000` (or whatever host/port `app.py` prints)
   and log in - either with an individual account (a default `admin`
   account is auto-created on first run, password = your `ADMIN_API_KEY`),
   or the shared key directly.

   **Running more than one camera:** copy `detection_client.py`'s folder
   (or just set environment variables per-terminal) and give each instance
   its own `CAMERA_ID` - e.g.

   ```bash
   CAMERA_ID=gate1 CAMERA_LABEL="Main Gate" VIDEO_URL=http://192.168.1.20:8080/video python detection_client.py
   CAMERA_ID=gate2 CAMERA_LABEL="Back Gate" VIDEO_URL=http://192.168.1.21:8080/video python detection_client.py
   ```

   Both point at the same `ADMIN_API_KEY` and the same running `app.py`.
   They'll show up as separate cards in the dashboard's camera switcher.

## Offline resilience

Venue wifi and phone hotspots are often patchy. Both client-facing pieces
now cope with a dead spot instead of silently losing data:

- **`detection_client.py`** queues each count/zone reading to a small local
  SQLite file (`offline_queue_<CAMERA_ID>.db`, next to the script) whenever
  `/api/update` can't be reached — connection error, timeout, or a 5xx from
  the server. A background thread keeps retrying to flush the queue, oldest
  first, to `/api/update/batch` every `QUEUE_FLUSH_INTERVAL_SEC` (default
  5s) once the server's reachable again. Every queued reading except the
  very last is backfilled straight into the history table (so the
  Analytics tab's day-over-day chart doesn't have a hole for the outage)
  without re-triggering alerts/SMS for something that already happened;
  only the most recent queued reading runs the normal live pipeline. The
  queue is a bounded ring buffer (`MAX_QUEUE_ITEMS`, default 5000) so a very
  long outage drops its oldest entries instead of growing forever. Frames
  are never queued — only the count/zone data, which is what actually
  matters for risk/analytics.
- **The official mobile app's endpoints** (`/api/alerts/<id>/ack` and
  `/api/official/report`) accept an optional `client_id` set by the app
  when an ack or incident report is created while offline. If the same
  `client_id` is retried later (e.g. it went through once but the app never
  saw the response before losing signal again), the server replays the
  original result instead of recording a duplicate ack or report. A new
  `POST /api/official/sync-queue` endpoint lets the app flush a whole
  queued batch of acks/reports (any mix, oldest first) in one call once
  it's back online, with the same per-item `client_id` de-duplication.

## Security

- **Login required for everything** — the dashboard page, `/api/state`, and
  `/api/frame.jpg` all require a valid session (or `?key=`/`X-API-Key` for
  machine clients). Nothing data-bearing is reachable without the key.
- **Sessions expire.** A login stays valid for `SESSION_LIFETIME_SECONDS`
  (default 12h) — after that, or after `/logout`, you'll need to sign in
  again. Wrong keys are rejected and rate-limited (5 attempts / 5 minutes
  per IP).
- **`ADMIN_API_KEY` fails closed** — if you don't set one, a random key is
  generated each run and printed to the console. There's no "unset = open"
  mode.
- **Optional read-only viewer role** — set `VIEWER_API_KEY` to let someone
  sign in and watch the dashboard (counts, charts, alerts, SMS log) without
  being able to change settings, run demo controls, or trigger the panic
  button. Leave it unset and every key holder stays a full admin, same as
  before this option existed.
- **XSS-safe rendering** — every piece of server-supplied text (alert
  messages, camera label, officials' phone numbers, SMS log entries) is
  HTML-escaped in `script.js` before being inserted into the page.
- **Input validation** — `/api/update`'s `count` is bounded by
  `MAX_REASONABLE_COUNT` (default 5000) so a bogus huge value can't force
  CRITICAL and trigger a real SMS; `MAX_CONTENT_LENGTH_MB` (default 8MB)
  caps request body size. `/api/config` rejects non-numeric or non-positive
  values, an unreachable `warning_pct`/`critical_pct` pairing, and malformed
  phone-number strings, returning a clear `400` instead of silently
  accepting them.
- **Admin activity log** — logins (success and failure), config changes
  (with a before/after diff), demo controls, and panic-button triggers are
  all recorded with a timestamp, role, and IP, visible on the Alerts &
  Controls tab (admin sessions only) and persisted in
  `crowdguard.db`'s `audit_log` table. Since every admin shares one key
  rather than having an individual account, this is what lets you trace a
  mistaken or malicious action back to roughly who/where/when afterward.
- **Per-camera device tokens (JWT), optional** — `ADMIN_API_KEY` can do
  *everything* (change thresholds, manage users, trigger the panic demo).
  If you'd rather each camera's `detection_client.py` only be able to post
  its own headcount, an admin can mint a narrower, expiring token for it:
  ```
  curl -X POST http://localhost:5000/api/device-token \
       -H "X-API-Key: <your admin key>" \
       -H "Content-Type: application/json" \
       -d '{"camera_id": "gate1", "hours": 24}'
  ```
  Put the returned `token` in that camera's `DEVICE_TOKEN` env var instead
  of `ADMIN_API_KEY`. It stops working on its own once it expires, and it's
  rejected outright if used for any camera_id other than the one it was
  issued for. Requires `pip install pyjwt` on the server; without it,
  `/api/device-token` returns a clear error and the shared admin key keeps
  working exactly as before.
- **HTTPS** — in production, get TLS from whatever's in front of the app
  (Render/Heroku terminate it for you automatically; a reverse proxy like
  nginx if you're self-hosting). For local testing only, run
  `python app.py --https` for a self-signed certificate (needs
  `pip install pyopenssl`) — useful because some browsers only allow the
  Live GPS feature's location permission over a secure context. Your
  browser will show a certificate warning for the self-signed cert; that's
  expected for local testing and safe to click through on your own machine.

## Deployment

`python app.py` runs Flask's built-in dev server. That's fine on your own
machine, but it isn't meant for a public deploy (Render, Heroku, a VPS,
etc.):

- It's single-threaded by default and not hardened for real internet
  traffic - it will happily serve a local demo but isn't built to handle
  concurrent connections, slow clients, or malformed requests safely.
- This app also uses Socket.IO for live updates, which needs a
  concurrency model (eventlet's cooperative greenlets) the dev server
  doesn't provide - under a plain dev server, many simultaneously
  connected dashboards can start blocking each other.
- Flask itself prints a warning that its dev server "should not be used in
  a production deployment."

For a public deploy, run it behind `gunicorn` with the `eventlet` worker
class instead, which this repo is already set up for:

```bash
pip install -r requirements.txt   # now includes gunicorn + eventlet
gunicorn --worker-class eventlet -w 1 app:app
```

A `Procfile` with that exact command is included, so Render/Heroku-style
platforms will pick it up automatically - you shouldn't need to configure
a start command by hand. Keep `-w 1` (one worker): `STATE`, `HISTORY`,
etc. live in that process's memory, so multiple worker processes would
each keep their own separate (and diverging) copy of the live state.

Everything else still applies on a public deploy: set real `ADMIN_API_KEY`
and `SECRET_KEY` values (don't rely on the auto-generated ones), and make
sure `.env` is never committed or shipped alongside the deployed code.

## Testing

Automated tests cover the rule-based decision logic - `compute_risk()`,
`compute_growth_rate()`, and `recommend_police()` - since these are what
actually decide the risk level, the officer count, and whether an SMS goes
out, and they're plain pure functions (no Flask request, no database, no
camera needed), so they're cheap to test and the part of the system where a
silent bug would matter most.

They also cover offline resilience (feature 7): `tests/test_offline_queue.py`
exercises `OfflineQueue` directly (enqueue/flush ordering, the ring-buffer
cap, surviving a restart) with no dependency beyond the standard library,
and `tests/test_offline_sync.py` exercises `/api/update/batch` and the
`client_id`-based idempotency on `/api/alerts/<id>/ack`, `/api/official/report`,
and `/api/official/sync-queue` end-to-end via Flask's test client (this file
does need the full stack - flask-socketio, pyjwt - already in
`requirements.txt`).

```bash
python -m unittest discover tests -v
```

Importing `app.py` for testing does **not** touch the database, start the
server, or send any SMS - all of that only happens inside `if __name__ ==
"__main__":`, which doesn't run when the module is imported rather than
executed directly. Tests are plain `unittest` (standard library) - no extra
dependency needed beyond what's already in `requirements.txt`.

## Data Export

The Analytics tab has an **Export Data (CSV)** panel with three downloads:

- **History** - every persisted crowd-count reading (optionally scoped to
  one camera), straight from SQLite - not just the last-300-points window
  the live chart shows.
- **Alerts** - every WARNING/CRITICAL/simulated-emergency alert ever
  raised, across all cameras - now including the location, the
  action taken (e.g. "Recommend 3 officers on site"), and the full
  clearance-plan recommendation active at that moment, so the export
  reads as a proper incident log (Time / Location / Crowd / Alert /
  Action), not just a bare message string.
- **Audit log** (admin only) - the full audit trail (logins, config
  changes, demo/panic triggers, user management).

These are useful for after-action review (reconstructing a timeline once an
incident's over) or reporting to a venue safety committee. Each export is
itself logged to the audit trail. Row count is capped by `EXPORT_ROW_LIMIT`
(default 50,000) as a safety net against an unbounded download.

## Notes

- `crowdguard.db` is created automatically on first run (`init_db()`) and
  isn't included in this package — you'll start with an empty history/alerts
  database.
- Never commit or share your real `.env` file — it contains your Twilio
  credentials and admin key. `.gitignore` already excludes it from git, but
  that doesn't protect you if you zip/share the whole project folder by hand.
