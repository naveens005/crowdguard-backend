"""
CROWD GUARD 3.0 - Detection Client
--------------------------------------------------
Reads live video (a phone IP camera by default, or a laptop webcam) and runs
YOLO person-detection on each frame, then posts the current headcount to
app.py so the dashboard/SMS/clearance-plan pipeline can react to it.

  - current_count  -> how many people are in frame RIGHT NOW (drives risk
                       level / capacity % / SMS alerts / clearance plan)

(There used to also be a "unique visitors" running tally, built on top of a
fairly involved re-identification/tracking layer. That feature has been
removed entirely by request - this file now does plain per-frame detection,
which is both simpler and noticeably lighter/faster since there's no tracker,
appearance-matching, or ID-relinking overhead on every frame anymore.)

Offline resilience (feature 7): venue wifi/hotspots are often patchy. If a
report can't reach the server right now, it's queued locally (see
OfflineQueue below, backed by a small SQLite file next to this script) and
retried in the background until it goes through - so a dead spot delays
readings instead of silently losing them. Nothing here blocks the live
detection loop; queuing and flushing both happen on background threads.

Run app.py FIRST, then run this.
"""

import base64
import os
import threading
import time
from collections import deque

from offline_queue import OfflineQueue

import cv2
import numpy as np
import requests
from ultralytics import YOLO

# Load variables from a local .env file (if present) into os.environ - same
# mechanism app.py uses, so ADMIN_API_KEY (and anything else you put in
# .env) is picked up automatically here too instead of needing to be
# exported in the shell separately, or set correctly in app.py's .env only
# to silently NOT apply here.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ---------------------------------------------------------------------------
# CONFIG - edit these for your setup
# ---------------------------------------------------------------------------
VIDEO_URL = os.environ.get("VIDEO_URL", "http://192.168.31.66:8080/video")
                # phone IP camera app URL (use 0 instead for the laptop's
                # built-in webcam). Overridable via VIDEO_URL in .env so
                # each camera's instance of this script can point at its
                # own feed without editing the file.
MODEL_PATH = "yolo11n.pt"

# ---------------------------------------------------------------------------
# Multi-camera support: every /api/update this script sends is tagged with
# CAMERA_ID, so the server can track this feed separately from any other
# detection_client.py instances pointed at the same server. Run one of
# these processes per physical camera, each with its own CAMERA_ID (and,
# if not on the same machine, its own VIDEO_URL) set in that instance's
# environment/.env.
# ---------------------------------------------------------------------------
CAMERA_ID = os.environ.get("CAMERA_ID", "cam1")
CAMERA_LABEL = os.environ.get("CAMERA_LABEL", "")   # optional human-readable
                # name (e.g. "Main Gate"); sent once so the server doesn't
                # need it configured by hand for a new camera to show up
                # with a sensible label.

# ---------------------------------------------------------------------------
# Zone/density grid: instead of only reporting one venue-wide headcount,
# divide the frame into ZONE_ROWS x ZONE_COLS cells and count how many
# detected people fall in each, by bounding-box center. This surfaces a
# local crush (e.g. packed near one exit) that a single average count
# would hide. Set ZONE_ROWS/ZONE_COLS to 1 to disable and report only the
# total, same as before.
# ---------------------------------------------------------------------------
ZONE_ROWS = int(os.environ.get("ZONE_ROWS", 3))
ZONE_COLS = int(os.environ.get("ZONE_COLS", 3))


def compute_zone_counts(boxes, frame_shape):
    """Buckets each detected person into a ZONE_ROWS x ZONE_COLS grid cell
    by their bounding-box center point. Returns a flat list of length
    ZONE_ROWS*ZONE_COLS (row-major), so cell (r, c) is at index r*ZONE_COLS+c."""
    h, w = frame_shape[:2]
    counts = [0] * (ZONE_ROWS * ZONE_COLS)
    if h <= 0 or w <= 0:
        return counts
    for x1, y1, x2, y2 in boxes:
        cx, cy = (x1 + x2) / 2, (y1 + y2) / 2
        col = min(ZONE_COLS - 1, max(0, int((cx / w) * ZONE_COLS)))
        row = min(ZONE_ROWS - 1, max(0, int((cy / h) * ZONE_ROWS)))
        counts[row * ZONE_COLS + col] += 1
    return counts


def draw_zone_grid(frame, zone_counts):
    """Overlays faint grid lines and each cell's count on the annotated
    frame, so the zone breakdown is visible locally too, not just on the
    dashboard."""
    if ZONE_ROWS <= 1 and ZONE_COLS <= 1:
        return frame
    h, w = frame.shape[:2]
    cell_h, cell_w = h / ZONE_ROWS, w / ZONE_COLS
    for r in range(1, ZONE_ROWS):
        y = int(r * cell_h)
        cv2.line(frame, (0, y), (w, y), (90, 90, 90), 1)
    for c in range(1, ZONE_COLS):
        x = int(c * cell_w)
        cv2.line(frame, (x, 0), (x, h), (90, 90, 90), 1)
    for r in range(ZONE_ROWS):
        for c in range(ZONE_COLS):
            idx = r * ZONE_COLS + c
            cnt = zone_counts[idx] if idx < len(zone_counts) else 0
            tx, ty = int(c * cell_w) + 6, int(r * cell_h) + 18
            cv2.putText(frame, str(cnt), (tx, ty), cv2.FONT_HERSHEY_SIMPLEX,
                        0.5, (200, 200, 200), 1)
    return frame
CONFIDENCE = 0.40                      # higher = fewer borderline/flickery
                                        # detections. Lower toward ~0.30 if
                                        # real people in frame aren't being
                                        # picked up.
IMAGE_SIZE = 640                       # lower (e.g. 480) = faster inference,
                                        # slightly less accurate on small/far
                                        # people. Raise (e.g. 736) for the
                                        # opposite trade-off.

try:
    import torch
    DEVICE = 0 if torch.cuda.is_available() else "cpu"
except ImportError:
    DEVICE = "cpu"
# Biggest single latency lever: inference on GPU (DEVICE=0) is typically
# 5-10x faster than CPU for this model. If you have an NVIDIA GPU, make sure
# you installed the CUDA build of torch (see requirements.txt / PyTorch's
# site) - otherwise this silently falls back to CPU and nothing changes.

BOX_COLOR = (255, 141, 76)  # BGR signal-blue - same color for every detected
                              # person, since we no longer track individual
                              # identity. Matches the dashboard's palette
                              # (the "signal" accent, #4c8dff) so the on-feed
                              # legend swatch and the actual boxes agree.


def draw_people(frame, boxes):
    """Plain overlay: every detected person gets a box + 'person' label.
    No per-identity color or ID number anymore - detection is per-frame
    only, with no tracking/identity layer above it."""
    annotated = frame.copy()
    for x1, y1, x2, y2 in boxes:
        x1, y1, x2, y2 = int(x1), int(y1), int(x2), int(y2)
        cv2.rectangle(annotated, (x1, y1), (x2, y2), BOX_COLOR, 2)
        label = "person"
        (tw, th), _ = cv2.getTextSize(label, cv2.FONT_HERSHEY_SIMPLEX, 0.55, 2)
        cv2.rectangle(annotated, (x1, max(0, y1 - th - 10)),
                      (x1 + tw + 10, y1), BOX_COLOR, -1)
        cv2.putText(annotated, label, (x1 + 5, max(12, y1 - 5)),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.55, (15, 15, 15), 2)
    return annotated


SERVER_URL = os.environ.get("SERVER_URL", "http://127.0.0.1:5000")
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "")   # must match the server's
                                        # ADMIN_API_KEY (printed in its console
                                        # on startup, or set in its .env) - the
                                        # server now requires this on every
                                        # /api/update request; without it every
                                        # post gets rejected with 401 and the
                                        # dashboard silently stops updating.
DEVICE_TOKEN = os.environ.get("DEVICE_TOKEN", "")   # optional, narrower
                                        # alternative to ADMIN_API_KEY: a
                                        # per-camera token minted by an admin
                                        # via POST /api/device-token on the
                                        # server (needs pip install pyjwt
                                        # there). Unlike the admin key, a
                                        # device token can only post updates
                                        # for the ONE camera_id it was issued
                                        # for, and expires on its own - set
                                        # this instead of ADMIN_API_KEY if you
                                        # don't want this device to be able to
                                        # do anything else (change thresholds,
                                        # trigger the panic demo, etc). If
                                        # both are set, DEVICE_TOKEN is used.
SEND_FRAME_EVERY_N = 3                 # send an annotated frame every Nth
                                        # detection to keep bandwidth low -
                                        # lower this (e.g. 1 or 2) for a
                                        # smoother-looking live feed on the
                                        # dashboard at the cost of more
                                        # network traffic; it does NOT affect
                                        # count accuracy, only how often the
                                        # video image itself updates.
SHOW_LOCAL_WINDOW = False              # also show the classic cv2.imshow window

# ---------------------------------------------------------------------------
# Offline resilience (feature 7): if /api/update can't be reached (patchy
# venue wifi, server restart, etc.), the count/zone reading is queued to a
# local SQLite file instead of being dropped, and a background thread keeps
# retrying to flush it via /api/update/batch until the server's reachable
# again. Frames are NOT queued - see OfflineQueue's docstring in
# offline_queue.py.
# ---------------------------------------------------------------------------
OFFLINE_QUEUE_DB = os.environ.get("OFFLINE_QUEUE_DB", f"offline_queue_{os.environ.get('CAMERA_ID', 'cam1')}.db")
MAX_QUEUE_ITEMS = int(os.environ.get("MAX_QUEUE_ITEMS", 5000))      # ring-buffer cap - a long
                                        # outage stops growing the file past this many
                                        # reports and starts dropping the OLDEST ones instead
QUEUE_FLUSH_INTERVAL_SEC = float(os.environ.get("QUEUE_FLUSH_INTERVAL_SEC", 5))  # how often
                                        # the background thread checks for anything to sync
QUEUE_FLUSH_BATCH_SIZE = 200           # reports per /api/update/batch call while catching up

OFFLINE_QUEUE = OfflineQueue(OFFLINE_QUEUE_DB, max_items=MAX_QUEUE_ITEMS)


class LatestFrame:
    """Continuously reads the stream so the detector receives only the newest frame."""

    def __init__(self, source):
        self.snapshot_url = None
        self.frame = None
        self.lock = threading.Lock()
        self.running = True

        if isinstance(source, str) and "/video" in source:
            # Use snapshot polling instead of the raw MJPEG stream -
            # more reliable with OpenCV/FFmpeg for phone IP-cam apps.
            self.snapshot_url = source.replace("/video", "/shot.jpg")
            self.cap = None
            test = requests.get(self.snapshot_url, timeout=3)
            if test.status_code != 200:
                raise RuntimeError("Unable to open the camera stream.")
            self.thread = threading.Thread(target=self._read_snapshots, daemon=True)
        else:
            backend = cv2.CAP_DSHOW if isinstance(source, int) else cv2.CAP_FFMPEG
            self.cap = cv2.VideoCapture(source, backend)
            self.cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
            if not self.cap.isOpened():
                raise RuntimeError("Unable to open the camera stream.")
            self.thread = threading.Thread(target=self._read_frames, daemon=True)

        self.thread.start()

    def _read_snapshots(self):
        while self.running:
            try:
                resp = requests.get(self.snapshot_url, timeout=3)
                arr = np.frombuffer(resp.content, dtype=np.uint8)
                frame = cv2.imdecode(arr, cv2.IMREAD_COLOR)
                if frame is not None:
                    with self.lock:
                        self.frame = frame
            except requests.exceptions.RequestException:
                time.sleep(0.1)

    def _read_frames(self):
        while self.running:
            ok, frame = self.cap.read()
            if not ok:
                time.sleep(0.02)
                continue
            with self.lock:
                self.frame = frame

    def get(self):
        with self.lock:
            return None if self.frame is None else self.frame.copy()

    def close(self):
        self.running = False
        self.thread.join(timeout=1)
        if self.cap is not None:
            self.cap.release()


def _auth_headers():
    if DEVICE_TOKEN:
        return {"Authorization": f"Bearer {DEVICE_TOKEN}"}
    elif ADMIN_API_KEY:
        return {"X-API-Key": ADMIN_API_KEY}
    return {}


def send_update(count, annotated_frame=None, zone_counts=None):
    """POST the latest count (and optionally a frame / zone breakdown) to
    the server. Runs in a background thread so a slow/failed network call
    never blocks the detection loop.

    Offline resilience (feature 7): built as two payloads - `core_payload`
    (count/zone/camera_id/client_ts, no frame) and `live_payload` (that
    plus the frame, best-effort). If the live POST can't get through at
    all (connection error/timeout) or the server reports a problem on its
    end (5xx), `core_payload` is queued locally via OFFLINE_QUEUE instead
    of being lost - _flush_offline_queue() (started in main()) keeps
    retrying it in the background. A rejected request (401/400) is NOT
    queued - retrying the same bad auth or malformed data would just fail
    again, so that's still surfaced as a warning like before."""
    core_payload = {"count": count, "camera_id": CAMERA_ID, "client_ts": time.time()}
    if CAMERA_LABEL:
        core_payload["label"] = CAMERA_LABEL
    if zone_counts is not None:
        core_payload["zone_counts"] = zone_counts
        core_payload["zone_rows"] = ZONE_ROWS
        core_payload["zone_cols"] = ZONE_COLS

    live_payload = dict(core_payload)
    if annotated_frame is not None:
        ok, buf = cv2.imencode(".jpg", annotated_frame, [cv2.IMWRITE_JPEG_QUALITY, 60])
        if ok:
            live_payload["frame"] = base64.b64encode(buf).decode("ascii")

    def _post():
        try:
            r = requests.post(f"{SERVER_URL}/api/update", json=live_payload,
                               headers=_auth_headers(), timeout=2)
            if r.status_code == 401:
                print(f"\n[warning] server rejected this update (401 Unauthorized) - "
                      f"set ADMIN_API_KEY or DEVICE_TOKEN here to match the server's "
                      f"(printed in its console on startup, or in its .env). If using "
                      f"DEVICE_TOKEN, also check it hasn't expired and matches CAMERA_ID.")
            elif r.status_code >= 500:
                OFFLINE_QUEUE.enqueue(core_payload)
        except requests.exceptions.RequestException as e:
            print(f"\n[warning] could not reach server ({e}) - queuing this report "
                  f"({OFFLINE_QUEUE.pending_count() + 1} pending)")
            OFFLINE_QUEUE.enqueue(core_payload)

    threading.Thread(target=_post, daemon=True).start()


def _flush_offline_queue():
    """Offline resilience (feature 7): background loop, started once in
    main(), that keeps trying to sync whatever's queued to
    /api/update/batch, oldest first, in chunks of QUEUE_FLUSH_BATCH_SIZE.
    A no-op (just sleeps) whenever the queue is empty, so it's cheap to
    leave running for the life of the process rather than starting/
    stopping it around detected outages."""
    while True:
        time.sleep(QUEUE_FLUSH_INTERVAL_SEC)
        if OFFLINE_QUEUE.pending_count() == 0:
            continue
        batch = OFFLINE_QUEUE.peek_batch(QUEUE_FLUSH_BATCH_SIZE)
        if not batch:
            continue
        ids = [row_id for row_id, _payload in batch]
        items = [payload for _row_id, payload in batch]
        try:
            r = requests.post(f"{SERVER_URL}/api/update/batch", json={"items": items},
                               headers=_auth_headers(), timeout=10)
            if r.status_code == 200:
                OFFLINE_QUEUE.remove(ids)
                remaining = OFFLINE_QUEUE.pending_count()
                print(f"\n[offline] synced {len(ids)} queued report(s)"
                      + (f" - {remaining} still pending" if remaining else ""))
            elif r.status_code == 401:
                print("\n[warning] queued reports rejected (401 Unauthorized) - check "
                      "ADMIN_API_KEY/DEVICE_TOKEN; will keep retrying")
            # any other status: leave this batch queued and just try again next interval
        except requests.exceptions.RequestException:
            pass  # still offline - stay quiet here, send_update() already warned once


def main():
    model = YOLO(MODEL_PATH)
    print(f"Camera ID: {CAMERA_ID}" + (f"  (\"{CAMERA_LABEL}\")" if CAMERA_LABEL else ""))
    print(f"Running inference on: {DEVICE} "
          f"({'GPU - fast' if DEVICE != 'cpu' else 'CPU - consider a GPU for lower latency'})")
    if ZONE_ROWS > 1 or ZONE_COLS > 1:
        print(f"Zone grid: {ZONE_ROWS}x{ZONE_COLS} (per-cell density reported to the server)")
    pending = OFFLINE_QUEUE.pending_count()
    if pending:
        print(f"Offline queue: {pending} report(s) left over from a previous outage - "
              f"will sync automatically once the server's reachable")
    threading.Thread(target=_flush_offline_queue, daemon=True).start()
    stream = LatestFrame(VIDEO_URL)
    frame_counter = 0
    frame_times = deque(maxlen=30)   # for a live FPS readout - lets you actually
                                      # SEE the effect of DEVICE/IMAGE_SIZE changes
                                      # instead of guessing whether it got faster

    try:
        while True:
            frame = stream.get()
            if frame is None:
                cv2.waitKey(1)
                continue

            result = model.predict(frame, classes=[0], conf=CONFIDENCE,
                                    imgsz=IMAGE_SIZE, device=DEVICE,
                                    half=(DEVICE != "cpu"), verbose=False)[0]

            frame_times.append(time.time())
            fps = 0.0
            if len(frame_times) >= 2:
                fps = (len(frame_times) - 1) / (frame_times[-1] - frame_times[0])

            boxes = [] if result.boxes is None else result.boxes.xyxy.cpu().tolist()
            people_count = len(boxes)

            print(f"\rPeople in frame: {people_count}   FPS: {fps:4.1f}   ",
                  end="", flush=True)

            zone_counts = compute_zone_counts(boxes, frame.shape) \
                if (ZONE_ROWS > 1 or ZONE_COLS > 1) else None

            annotated = draw_people(frame, boxes)
            cv2.putText(annotated, f"In frame: {people_count}", (25, 45),
                        cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 141, 76), 2)
            if zone_counts is not None:
                draw_zone_grid(annotated, zone_counts)

            frame_counter += 1
            send_frame = annotated if frame_counter % SEND_FRAME_EVERY_N == 0 else None
            send_update(people_count, send_frame, zone_counts)

            if SHOW_LOCAL_WINDOW:
                cv2.imshow("Crowd Detection - Low Latency", annotated)
                if cv2.waitKey(1) & 0xFF == ord("q"):
                    break
    finally:
        stream.close()
        cv2.destroyAllWindows()


if __name__ == "__main__":
    main()
