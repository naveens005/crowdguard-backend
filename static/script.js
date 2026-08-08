const socket = io();
socket.on("connect_error", () => {
  // The server's connect handler rejects unauthenticated sockets (see
  // @socketio.on("connect") in app.py) - if that happens, the session
  // cookie is missing/expired, so send the user to log back in rather than
  // leaving a dashboard on screen that will never receive another update.
  window.location.href = "/login";
});

// ---------- Theme toggle (dark/light) ----------
// Persisted in localStorage so it survives refreshes/restarts, same as any
// other UI preference - applied immediately on load (before most of the
// page even renders) to avoid a flash of the wrong theme.
(function () {
  const THEME_KEY = "cg_theme";
  const saved = localStorage.getItem(THEME_KEY) || "dark";
  applyTheme(saved);

  function applyTheme(theme) {
    if (theme === "light") {
      document.documentElement.setAttribute("data-theme", "light");
    } else {
      document.documentElement.removeAttribute("data-theme");
    }
    const icon = document.getElementById("theme-toggle-icon");
    const label = document.getElementById("theme-toggle-label");
    if (icon) icon.textContent = theme === "light" ? "\u2600" : "\u263D";
    if (label) label.textContent = theme === "light" ? "Light theme" : "Dark theme";
  }

  document.addEventListener("DOMContentLoaded", () => {
    const btn = document.getElementById("theme-toggle");
    if (!btn) return;
    btn.addEventListener("click", () => {
      const current = localStorage.getItem(THEME_KEY) || "dark";
      const next = current === "light" ? "dark" : "light";
      localStorage.setItem(THEME_KEY, next);
      applyTheme(next);
    });
  });
})();

// ---------- Admin API key ----------
// /api/config and /api/simulate/* are protected server-side by ADMIN_API_KEY
// (X-API-Key header). A logged-in browser already authenticates via its
// session cookie for most things, but this covers any request made before
// that cookie exists, or from a context that needs the header explicitly.
function getAdminKey() {
  return sessionStorage.getItem("cg_admin_key") || "";
}
function setAdminKey(key) {
  sessionStorage.setItem("cg_admin_key", key);
}
function adminHeaders(extra = {}) {
  const key = getAdminKey();
  return key ? { ...extra, "X-API-Key": key } : extra;
}
// Wraps fetch(): retries once with a freshly-entered key if the server
// responds 401 (key missing/wrong), instead of just silently failing.
async function adminFetch(url, options = {}) {
  const headers = adminHeaders(options.headers || {});
  let res = await fetch(url, { ...options, headers });
  if (res.status === 401) {
    const key = prompt("This action needs the admin API key (printed in the server's console, or set as ADMIN_API_KEY). Enter it:");
    if (key) {
      setAdminKey(key);
      res = await fetch(url, { ...options, headers: adminHeaders(options.headers || {}) });
    }
  }
  return res;
}

// ---------- Tab switching ----------
document.querySelectorAll(".nav-item").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".nav-item").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("tab-" + btn.dataset.tab).classList.add("active");
  });
});

// ---------- Clock ----------
function tickClock() {
  document.getElementById("clock").textContent = new Date().toLocaleTimeString();
}
setInterval(tickClock, 1000);
tickClock();

// ---------- Uptime ----------
const startTime = Date.now();
setInterval(() => {
  const s = Math.floor((Date.now() - startTime) / 1000);
  const hh = String(Math.floor(s / 3600)).padStart(2, "0");
  const mm = String(Math.floor((s % 3600) / 60)).padStart(2, "0");
  const ss = String(s % 60).padStart(2, "0");
  document.getElementById("uptime").textContent = `${hh}:${mm}:${ss}`;
}, 1000);

// ---------- Multi-camera: which camera the dashboard is currently focused on ----------
let activeCameraId = "cam1";

// ---------- Live feed polling (works across devices without MJPEG hassles) ----------
const feedImg = document.getElementById("live-feed");
const feedEmpty = document.getElementById("feed-empty");
// Setting img.src directly and reacting to its own load/error events
// downloads each frame exactly once (a separate fetch() call here used to
// download every frame a second time for no reason).
feedImg.addEventListener("load", () => { feedEmpty.style.display = "none"; });
feedImg.addEventListener("error", () => { feedEmpty.style.display = "block"; });
setInterval(() => {
  feedImg.src = "/api/frame.jpg?camera_id=" + encodeURIComponent(activeCameraId) + "&t=" + Date.now();
}, 700);

// ---------- Charts ----------
const miniChart = new Chart(document.getElementById("miniChart"), {
  type: "line",
  data: { labels: [], datasets: [{ data: [], borderColor: "#ffffff", backgroundColor: "rgba(255,255,255,0.08)", fill: true, tension: 0.3, pointRadius: 0 }] },
  options: {
    responsive: true,
    plugins: { legend: { display: false } },
    scales: { x: { display: false }, y: { beginAtZero: true, grid: { color: "rgba(255,255,255,0.08)" }, ticks: { color: "rgba(246,246,247,0.56)", font: { family: "IBM Plex Mono", size: 10 } } } }
  }
});

const historyChart = new Chart(document.getElementById("historyChart"), {
  type: "line",
  data: { labels: [], datasets: [{ label: "People Count", data: [], borderColor: "#ffffff", backgroundColor: "rgba(255,255,255,0.08)", fill: true, tension: 0.3, pointRadius: 0 }] },
  options: {
    responsive: true,
    plugins: { legend: { labels: { color: "#f6f6f7", font: { family: "Inter" } } } },
    scales: {
      x: { ticks: { color: "rgba(246,246,247,0.56)", font: { family: "IBM Plex Mono", size: 10 } }, grid: { color: "rgba(255,255,255,0.08)" } },
      y: { beginAtZero: true, ticks: { color: "rgba(246,246,247,0.56)", font: { family: "IBM Plex Mono", size: 10 } }, grid: { color: "rgba(255,255,255,0.08)" } }
    }
  }
});

function fmtTime(t) {
  return new Date(t * 1000).toLocaleTimeString();
}

// The Dashboard mini-chart is a small "last minute or so" glance, so it's
// capped tight at 60 points. The Analytics history chart is labeled as
// showing everything "persisted in SQLite" - the server keeps (and sends,
// via /api/state's "history") up to 300 points, so this chart should show
// that whole window instead of being truncated down to the mini-chart's
// limit. Each chart now has its own cap instead of sharing one.
const MINI_CHART_MAX_POINTS = 60;
const HISTORY_CHART_MAX_POINTS = 300;

function pushPoint(point) {
  const label = fmtTime(point.t);
  [[miniChart, MINI_CHART_MAX_POINTS], [historyChart, HISTORY_CHART_MAX_POINTS]].forEach(([chart, maxPoints]) => {
    chart.data.labels.push(label);
    chart.data.datasets[0].data.push(point.count);
    if (chart.data.labels.length > maxPoints) {
      chart.data.labels.shift();
      chart.data.datasets[0].data.shift();
    }
    chart.update("none");
  });
}

// ---------- State rendering ----------
let maxCapacity = 100;

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function applyState(count, risk, recommendedPolice, policeReason) {
  setText("current-count", count);
  const pill = document.getElementById("risk-pill");
  pill.textContent = risk;
  pill.className = "card-value pill " + risk;
  const pct = maxCapacity ? Math.min(100, Math.round((count / maxCapacity) * 100)) : 0;
  setText("capacity-pct", pct + "%");
  markDetectorFresh();

  if (recommendedPolice !== undefined) {
    setText("police-count", recommendedPolice);
    setText("analytics-police-count", recommendedPolice);
  }
  if (policeReason) {
    setText("police-reason", policeReason);
  }
}

// ---------- Detector "last update" freshness (stale dot) ----------
// The CSS for a stale/no-signal state (.dot.stale, in style.css) already
// existed but nothing ever set it - the dot was hardcoded to "ok" in the
// HTML and never changed. This tracks the last time a real update arrived
// (initial /api/state load or a "state_update" socket event) and, on an
// interval, flips the dot + label to stale if too much time has passed -
// e.g. detection_client.py crashed or lost its camera feed.
const DETECTOR_STALE_AFTER_MS = 12000;   // no update in ~12s -> stale
const DETECTOR_CHECK_INTERVAL_MS = 5000; // how often we check
let lastDetectorUpdate = Date.now();

function markDetectorFresh() {
  lastDetectorUpdate = Date.now();
  const dot = document.getElementById("detector-dot");
  if (dot) dot.className = "dot ok";
  setText("detector-status", "Receiving data");
}

function checkDetectorFreshness() {
  if (Date.now() - lastDetectorUpdate > DETECTOR_STALE_AFTER_MS) {
    const dot = document.getElementById("detector-dot");
    if (dot) dot.className = "dot stale";
    setText("detector-status", "No data (stale)");
  }
}
setInterval(checkDetectorFreshness, DETECTOR_CHECK_INTERVAL_MS);

// Shared HTML-escaping helper - every place below that inserts server- or
// user-supplied text into innerHTML runs it through this first. Previously
// linkifyMessage() (alerts) had its own inline escaping but renderSms() and
// renderCamLocation() didn't - meaning the officials' phone-number string
// and the camera location label (both editable via /api/config) could
// contain raw HTML/JS that would execute in the dashboard. All three now
// share this one function instead of each sink deciding for itself.
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Turns a bare "https://maps.google.com/..." URL inside an alert's plain-text
// message into a tap-through link, so the GPS location mentioned in a Threat
// Timeline entry is clickable, not just readable text. The message itself
// still comes from the server as plain text (escaped below) - only the URL
// portion becomes a real <a> tag.
function linkifyMessage(message) {
  const escaped = escapeHtml(message);
  return escaped.replace(/(https?:\/\/[^\s]+)/g,
    '<a href="$1" target="_blank" rel="noopener">$1</a>');
}

function renderAlert(a) {
  const list = document.getElementById("alert-list");
  const div = document.createElement("div");
  div.className = "alert-item " + a.severity;
  const metaBits = [];
  if (a.location) metaBits.push(`&#128205; ${escapeHtml(a.location)}`);
  if (a.action) metaBits.push(`&#9989; ${escapeHtml(a.action)}`);
  const metaHtml = metaBits.length ? `<div class="alert-meta">${metaBits.join(" &nbsp;|&nbsp; ")}</div>` : "";
  div.innerHTML = `<div>${linkifyMessage(a.message)}</div>${metaHtml}<div class="alert-time">${escapeHtml(a.time)}</div>`;
  list.prepend(div);
  setText("active-alerts", list.children.length);
}

function renderSms(entry) {
  const list = document.getElementById("sms-list");
  if (!list) return;
  const div = document.createElement("div");
  div.className = "alert-item " + (entry.sent ? "SAFE" : "WARNING");
  div.innerHTML = `<div>${entry.sent ? "&#9989; Sent" : "&#9203; Logged"} to ${escapeHtml(entry.to)}</div>` +
                  `<div class="alert-time">${escapeHtml(entry.detail || "")} - ${escapeHtml(entry.time)}</div>`;
  list.prepend(div);
}

// Admin activity log - only rendered when #audit-log-list exists in the DOM
// (i.e. an admin session; viewers never get this panel or the underlying
// /api/audit-log data).
function renderAuditEntry(entry) {
  const list = document.getElementById("audit-log-list");
  if (!list) return;
  const div = document.createElement("div");
  div.className = "alert-item";
  div.innerHTML = `<div>${escapeHtml(entry.role)} - ${escapeHtml(entry.action)}` +
                  `${entry.details ? ": " + escapeHtml(entry.details) : ""}</div>` +
                  `<div class="alert-time">${escapeHtml(entry.time)} - ${escapeHtml(entry.ip)}</div>`;
  list.prepend(div);
}

// Feature: plain-language "Current Status / Action" headline on the
// dashboard - same risk value as the RISK LEVEL card (LOW/MEDIUM/HIGH
// wording, same red/amber/green color), Action is just the first step of
// the clearance plan so it doesn't duplicate/contradict that list.
const CROWD_LEVEL_LABELS = { SAFE: "LOW", WARNING: "MEDIUM", CRITICAL: "HIGH" };
function updateStatusSummary(risk, plan) {
  const pill = document.getElementById("status-crowdlevel");
  if (pill) {
    pill.textContent = (CROWD_LEVEL_LABELS[risk] || risk || "-") + " CROWD";
    pill.className = "card-value pill " + (risk || "SAFE");
  }
  setText("status-action", (plan && plan.length) ? plan[0] : "No action needed.");
}

function renderPlan(plan) {
  const list = document.getElementById("clearance-plan");
  if (!list) return;
  list.innerHTML = "";
  if (!plan || plan.length === 0) {
    list.innerHTML = '<li class="plan-empty">Waiting for live data...</li>';
    return;
  }
  plan.forEach(step => {
    const li = document.createElement("li");
    li.textContent = step;   // textContent, not innerHTML - already safe
    list.appendChild(li);
  });
}

// ---------- Multi-camera switcher ----------
let lastKnownCameras = [];  // camera_id/label pairs, used to populate the roster's zone/gate dropdown
function renderCameraSwitcher(cameras, combinedRisk) {
  const combinedPill = document.getElementById("combined-risk-pill");
  if (combinedPill) {
    combinedPill.textContent = combinedRisk || "SAFE";
    combinedPill.className = "card-value pill " + (combinedRisk || "SAFE");
  }
  if (cameras && cameras.length) {
    lastKnownCameras = cameras;
    refreshRosterCameraOptions();
  }
  const wrap = document.getElementById("cam-switcher");
  if (!wrap || !cameras || !cameras.length) return;
  wrap.innerHTML = "";
  cameras.forEach(cam => {
    const chip = document.createElement("div");
    chip.className = "cam-chip risk-" + cam.risk_level +
      (cam.camera_id === activeCameraId ? " active" : "") +
      (cam.online ? "" : " offline");
    chip.dataset.cameraId = cam.camera_id;
    chip.innerHTML = `${escapeHtml(cam.label || cam.camera_id)} <span class="cam-chip-count">${cam.current_count}</span>`;
    chip.addEventListener("click", () => switchCamera(cam.camera_id));
    wrap.appendChild(chip);
  });
}

function switchCamera(cameraId) {
  if (cameraId === activeCameraId) return;
  activeCameraId = cameraId;
  document.querySelectorAll(".cam-chip").forEach(chip => {
    chip.classList.toggle("active", chip.dataset.cameraId === cameraId);
  });
  [miniChart, historyChart].forEach(chart => {
    chart.data.labels = [];
    chart.data.datasets[0].data = [];
    chart.update("none");
  });
  loadCameraState(cameraId);
  refreshExportHistoryLink();
}

// ---------- Zone/density grid ----------
function renderZoneGrid(zoneCounts, rows, cols, zoneRisk) {
  const panel = document.getElementById("zone-panel");
  const grid = document.getElementById("zone-grid");
  if (!panel || !grid) return;
  if (!zoneCounts || !zoneCounts.length || !rows || !cols) {
    panel.style.display = "none";
    return;
  }
  panel.style.display = "";
  grid.style.gridTemplateColumns = `repeat(${cols}, 1fr)`;
  grid.innerHTML = "";
  zoneCounts.forEach((count, i) => {
    const cell = document.createElement("div");
    const risk = (zoneRisk && zoneRisk[i]) || "SAFE";
    cell.className = "zone-cell " + risk;
    cell.textContent = count;
    cell.title = `Zone ${i}: ${count} people (${risk})`;
    grid.appendChild(cell);
  });
}

function renderCamLocation(label, lat, lon, mapsLink) {
  const el = document.getElementById("cam-location");
  if (!el) return;
  if (lat == null || lon == null || lat === "" || lon === "") {
    el.innerHTML = "&#128205; Location not configured";
    return;
  }
  const name = escapeHtml(label || "Camera");
  if (mapsLink) {
    // mapsLink itself is server-built from validated numeric lat/long (see
    // /api/config's float() conversion), so it can't carry arbitrary text -
    // only the free-text `name` label needed escaping above.
    el.innerHTML = `&#128205; ${name} (${lat}, ${lon}) - <a href="${escapeHtml(mapsLink)}" target="_blank" rel="noopener">View on map</a>`;
  } else {
    el.innerHTML = `&#128205; ${name} (${lat}, ${lon})`;
  }
}

// ---------- Initial load / camera switch ----------
function loadCameraState(cameraId) {
  fetch("/api/state?camera_id=" + encodeURIComponent(cameraId)).then(r => {
    if (r.status === 401) { window.location.href = "/login"; return Promise.reject("unauthorized"); }
    return r.json();
  }).then(state => {
    activeCameraId = state.camera_id || cameraId;
    maxCapacity = state.max_capacity;
    setText("max-cap-label", state.max_capacity);
    const setVal = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
    setVal("cfg-max", state.max_capacity);
    setVal("cfg-warn", state.warning_pct);
    setVal("cfg-crit", state.critical_pct);
    setVal("cfg-ratio-safe", state.ratio_safe);
    setVal("cfg-ratio-warn", state.ratio_warning);
    setVal("cfg-ratio-crit", state.ratio_critical);
    setVal("cfg-min-officers", state.min_officers);
    setVal("cfg-alert-cooldown", state.alert_cooldown);
    setVal("cfg-sms-cooldown", state.sms_cooldown);
    setVal("cfg-cam-label", state.cam_location_label || "");
    setVal("cfg-cam-lat", state.cam_latitude ?? "");
    setVal("cfg-cam-lon", state.cam_longitude ?? "");
    setVal("cfg-officials-phone", state.officials_phone || "");
    setText("peak-count", state.peak_count || 0);
    applyState(state.current_count, state.risk_level,
               state.recommended_police, state.police_reason);
    renderPlan(state.clearance_plan);
    updateStatusSummary(state.risk_level, state.clearance_plan);
    renderCamLocation(state.cam_location_label, state.cam_latitude, state.cam_longitude, state.cam_maps_link);
    renderZoneGrid(state.zone_counts, state.zone_rows, state.zone_cols, state.zone_risk);
    renderCameraSwitcher(state.cameras, state.combined_risk_level);
    state.history.forEach(pushPoint);
    document.getElementById("alert-list").innerHTML = "";
    document.getElementById("sms-list").innerHTML = "";
    state.alerts.slice().reverse().forEach(renderAlert);
    (state.sms_log || []).slice().reverse().forEach(renderSms);
    refreshExportHistoryLink();
  });
}
loadCameraState(activeCameraId);

// Admin activity log - only fetched if the panel exists (admin sessions;
// viewers never get #audit-log-list or /api/audit-log access).
if (document.getElementById("audit-log-list")) {
  adminFetch("/api/audit-log").then(r => (r.ok ? r.json() : null)).then(data => {
    if (data && data.audit_log) {
      data.audit_log.slice().reverse().forEach(renderAuditEntry);
    }
  }).catch(() => {});
}

// ---------- Live socket updates ----------
socket.on("state_update", data => {
  // Every camera's update broadcasts here - always refresh the camera
  // switcher chips + combined risk pill, but only apply the detailed
  // dashboard state (feed stats, chart, clearance plan, zone grid) when
  // the update is for whichever camera is currently focused.
  renderCameraSwitcher(data.cameras, data.combined_risk_level);
  if (data.camera_id && data.camera_id !== activeCameraId) return;

  maxCapacity = data.max_capacity;
  applyState(data.current_count, data.risk_level,
             data.recommended_police, data.police_reason);
  renderPlan(data.clearance_plan);
  updateStatusSummary(data.risk_level, data.clearance_plan);
  renderZoneGrid(data.zone_counts, data.zone_rows, data.zone_cols, data.zone_risk);
  pushPoint(data.point);
  const peakEl = document.getElementById("peak-count");
  if (peakEl && data.current_count > parseInt(peakEl.textContent || "0", 10)) {
    peakEl.textContent = data.current_count;
  }
});

socket.on("audit_entry", renderAuditEntry);

socket.on("new_alert", renderAlert);
socket.on("sms_status", entry => {
  renderSms(entry);
  const status = document.getElementById("sms-status");
  if (status) {
    status.textContent = entry.sent ? `SMS sent ${entry.time}` : `SMS logged ${entry.time} (not sent)`;
  }
});

// ---------- Controls ----------
document.querySelectorAll("[data-action]").forEach(btn => {
  btn.addEventListener("click", () => {
    adminFetch("/api/simulate/" + btn.dataset.action + "?camera_id=" + encodeURIComponent(activeCameraId),
               { method: "POST" });
    if (btn.dataset.action === "clear") {
      // The server-side database/history is wiped by this call, but the
      // browser had already drawn the old alert/SMS entries and chart
      // points - those don't disappear on their own, so clear them here too.
      document.getElementById("alert-list").innerHTML = "";
      document.getElementById("sms-list").innerHTML = "";
      setText("peak-count", 0);
      [miniChart, historyChart].forEach(chart => {
        chart.data.labels = [];
        chart.data.datasets[0].data = [];
        chart.update("none");
      });
    }
  });
});
// btn-panic and (further below) btn-save-cfg are only rendered for admin
// sessions - a viewer's page never has them in the DOM, so these listeners
// are guarded rather than assuming the element always exists.
const btnPanic = document.getElementById("btn-panic");
if (btnPanic) {
  btnPanic.addEventListener("click", () => {
    adminFetch("/api/simulate/panic?camera_id=" + encodeURIComponent(activeCameraId), { method: "POST" });
  });
}

// ---------- What-if scenario planner ----------
// Plain fetch (not adminFetch) - /api/whatif only reads the target camera
// and computes a projection, so it's viewer_or_admin like /api/state, and
// authenticates the same way (session cookie), not the admin API key.
const btnWhatif = document.getElementById("btn-whatif-run");
if (btnWhatif) {
  btnWhatif.addEventListener("click", () => {
    const extraPeople = parseInt(document.getElementById("whatif-extra-people").value, 10) || 0;
    const capacityPct = parseFloat(document.getElementById("whatif-capacity-pct").value) || 100;
    btnWhatif.disabled = true;
    btnWhatif.textContent = "Running...";
    fetch("/api/whatif", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        camera_id: activeCameraId,
        extra_people: extraPeople,
        capacity_pct: capacityPct,
      }),
    })
      .then(r => (r.status === 401 ? Promise.reject("unauthorized") : r.json()))
      .then(result => {
        const resultBox = document.getElementById("whatif-result");
        resultBox.style.display = "";
        const pill = document.getElementById("whatif-crowdlevel");
        pill.textContent = result.crowd_level + " CROWD";
        pill.className = "card-value pill " + result.risk_level;
        setText("whatif-counts",
          `${result.hypothetical_count} people / ${result.hypothetical_capacity} effective capacity`);
        setText("whatif-action", result.top_action);
        setText("whatif-police",
          `${result.recommended_police} officers recommended - ${result.police_reason}`);
      })
      .catch(() => {})
      .finally(() => {
        btnWhatif.disabled = false;
        btnWhatif.textContent = "Run Simulation";
      });
  });
}

// ---------- Live GPS (real-time coordinates from this device) ----------
// Lets whoever is physically at the camera (e.g. on a phone standing at the
// gate, or in a moving vehicle/drone ground-control laptop) turn on their
// own device's GPS instead of typing lat/long in by hand. While enabled, the
// browser's location is re-read continuously and pushed to the server, so
// cam_latitude/cam_longitude - and therefore every alert/SMS map link - track
// the device's real position live.
let gpsWatchId = null;
let lastGpsPush = 0;
const GPS_PUSH_INTERVAL_MS = 5000; // throttle server writes to once/5s

function pushLiveGps(lat, lon) {
  const now = Date.now();
  if (now - lastGpsPush < GPS_PUSH_INTERVAL_MS) return;
  lastGpsPush = now;
  adminFetch("/api/config", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ cam_latitude: lat, cam_longitude: lon })
  }).then(() => fetch("/api/state")).then(r => r.json()).then(state => {
    renderCamLocation(state.cam_location_label, state.cam_latitude, state.cam_longitude, state.cam_maps_link);
  }).catch(err => console.error("Live GPS push failed:", err));
}

function setLiveGpsStatus(text) {
  const el = document.getElementById("live-gps-status");
  if (el) el.textContent = text;
}

function startLiveGps() {
  if (!navigator.geolocation) {
    setLiveGpsStatus("Geolocation isn't supported in this browser.");
    document.getElementById("cfg-cam-live-gps").checked = false;
    return;
  }
  setLiveGpsStatus("Requesting location permission...");
  gpsWatchId = navigator.geolocation.watchPosition(
    pos => {
      const lat = pos.coords.latitude.toFixed(6);
      const lon = pos.coords.longitude.toFixed(6);
      document.getElementById("cfg-cam-lat").value = lat;
      document.getElementById("cfg-cam-lon").value = lon;
      setLiveGpsStatus(`Live - accuracy \u00b1${Math.round(pos.coords.accuracy)}m, updated ${new Date().toLocaleTimeString()}`);
      pushLiveGps(lat, lon);
    },
    err => {
      setLiveGpsStatus("Location error: " + err.message);
    },
    { enableHighAccuracy: true, maximumAge: 4000, timeout: 15000 }
  );
}

function stopLiveGps() {
  if (gpsWatchId !== null) {
    navigator.geolocation.clearWatch(gpsWatchId);
    gpsWatchId = null;
  }
  setLiveGpsStatus("Off - lat/long above can be entered manually.");
}

const liveGpsToggle = document.getElementById("cfg-cam-live-gps");
if (liveGpsToggle) {
  liveGpsToggle.addEventListener("change", () => {
    if (liveGpsToggle.checked) {
      startLiveGps();
    } else {
      stopLiveGps();
    }
  });
}

const btnSaveCfg = document.getElementById("btn-save-cfg");
if (btnSaveCfg) {
btnSaveCfg.addEventListener("click", () => {
  const body = {
    camera_id: activeCameraId,
    max_capacity: document.getElementById("cfg-max").value,
    warning_pct: document.getElementById("cfg-warn").value,
    critical_pct: document.getElementById("cfg-crit").value,
    ratio_safe: document.getElementById("cfg-ratio-safe").value,
    ratio_warning: document.getElementById("cfg-ratio-warn").value,
    ratio_critical: document.getElementById("cfg-ratio-crit").value,
    min_officers: document.getElementById("cfg-min-officers").value,
    alert_cooldown: document.getElementById("cfg-alert-cooldown").value,
    sms_cooldown: document.getElementById("cfg-sms-cooldown").value,
    cam_location_label: document.getElementById("cfg-cam-label").value,
    cam_latitude: document.getElementById("cfg-cam-lat").value,
    cam_longitude: document.getElementById("cfg-cam-lon").value,
    officials_phone: document.getElementById("cfg-officials-phone").value,
  };
  adminFetch("/api/config", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
    .then(() => {
      maxCapacity = parseFloat(body.max_capacity);
      setText("max-cap-label", body.max_capacity);
      loadCameraState(activeCameraId);
    });
});
}

// ---------- Day-over-day analytics (Analytics tab) ----------
const dayCompareChart = new Chart(document.getElementById("dayCompareChart"), {
  type: "bar",
  data: {
    labels: [],
    datasets: [
      { label: "Peak", data: [], backgroundColor: "rgba(255,141,76,0.7)" },
      { label: "Average", data: [], backgroundColor: "rgba(255,255,255,0.35)" }
    ]
  },
  options: {
    responsive: true,
    plugins: { legend: { labels: { color: "#f6f6f7", font: { family: "Inter" } } } },
    scales: {
      x: { ticks: { color: "rgba(246,246,247,0.56)", font: { family: "IBM Plex Mono", size: 10 } }, grid: { display: false } },
      y: { beginAtZero: true, ticks: { color: "rgba(246,246,247,0.56)", font: { family: "IBM Plex Mono", size: 10 } }, grid: { color: "rgba(255,255,255,0.08)" } }
    }
  }
});

function loadDayComparison() {
  const days = document.getElementById("cmp-days")?.value || 7;
  fetch("/api/history/compare?days=" + days).then(r => r.json()).then(data => {
    const rows = data.days || [];
    dayCompareChart.data.labels = rows.map(r => r.day);
    dayCompareChart.data.datasets[0].data = rows.map(r => r.peak);
    dayCompareChart.data.datasets[1].data = rows.map(r => r.avg);
    dayCompareChart.update("none");
  });
}
document.getElementById("cmp-days")?.addEventListener("change", loadDayComparison);
document.querySelector('[data-tab="analytics"]')?.addEventListener("click", loadDayComparison);
loadDayComparison();

// ---------- Individual admin/viewer accounts ----------
function renderUsers(users) {
  const list = document.getElementById("users-list");
  if (!list) return;
  list.innerHTML = "";
  (users || []).forEach(u => {
    const row = document.createElement("div");
    row.className = "user-row";
    row.innerHTML = `<div>${escapeHtml(u.username)} <span class="user-role">${escapeHtml(u.role)}</span></div>` +
                     `<button title="Delete account" data-username="${escapeHtml(u.username)}">&#10005;</button>`;
    row.querySelector("button").addEventListener("click", () => {
      if (!confirm(`Remove account "${u.username}"?`)) return;
      adminFetch("/api/users/" + encodeURIComponent(u.username), { method: "DELETE" })
        .then(r => r.json()).then(() => loadUsers());
    });
    list.appendChild(row);
  });
}

function loadUsers() {
  if (!document.getElementById("users-list")) return;
  adminFetch("/api/users").then(r => (r.ok ? r.json() : null)).then(data => {
    if (data) renderUsers(data.users);
  }).catch(() => {});
}
loadUsers();

const btnAddUser = document.getElementById("btn-add-user");
if (btnAddUser) {
  btnAddUser.addEventListener("click", () => {
    const username = document.getElementById("new-user-name").value.trim();
    const password = document.getElementById("new-user-pass").value;
    const role = document.getElementById("new-user-role").value;
    adminFetch("/api/users", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password, role })
    }).then(r => r.json()).then(data => {
      if (data.ok) {
        document.getElementById("new-user-name").value = "";
        document.getElementById("new-user-pass").value = "";
        loadUsers();
      } else {
        alert(data.error || "Could not add account.");
      }
    });
  });
}

// ---------- Priority officials (nearest-first SMS ranking) ----------
function renderOfficials(officials) {
  const list = document.getElementById("officials-list");
  if (!list) return;
  list.innerHTML = "";
  (officials || []).forEach(o => {
    const hasLocation = o.latitude !== null && o.latitude !== undefined && o.latitude !== "";
    const localityTag = o.location ? ` <span class="user-role">&#128205; ${escapeHtml(o.location)}</span>` :
                         (hasLocation ? ` <span class="user-role">&#128205; located</span>` :
                                        ` <span class="user-role">unranked</span>`);
    const loginTag = o.has_login
      ? ` <span class="user-role login-badge">&#128273; ${escapeHtml(o.username)}</span>`
      : ` <span class="user-role login-badge none">&#128273; no login</span>`;
    const shiftTag = o.on_shift_camera_id
      ? ` <span class="user-role roster-live">&#128994; ON SHIFT (${escapeHtml(
          (lastKnownCameras.find(c => c.camera_id === o.on_shift_camera_id) || {}).label || o.on_shift_camera_id)})</span>`
      : "";
    const row = document.createElement("div");
    row.className = "user-row";
    row.innerHTML = `<div>${escapeHtml(o.name)} <span class="user-role">${escapeHtml(o.phone)}</span>` +
                     localityTag + loginTag + shiftTag + `</div>` +
                     `<div class="row-actions">` +
                     `<button class="login-btn" title="${o.has_login ? 'Reset or revoke login' : 'Set up mobile login'}" data-id="${o.id}">` +
                     (o.has_login ? "Reset login" : "Set login") + `</button>` +
                     `<button title="Remove official" data-id="${o.id}">&#10005;</button>` +
                     `</div>`;
    row.querySelector(".login-btn").addEventListener("click", () => openOfficialLoginDialog(o));
    row.querySelector('button:not(.login-btn)').addEventListener("click", () => {
      if (!confirm(`Remove "${o.name}" from priority officials?`)) return;
      adminFetch("/api/officials/" + o.id, { method: "DELETE" })
        .then(r => r.json()).then(() => loadOfficials());
    });
    list.appendChild(row);
  });
}

// Set, reset, or revoke one official's own username/password for the
// mobile app - the point of feature 8 (role-scoped auth). Uses simple
// prompt() dialogs rather than new persistent form fields, since this is
// an occasional admin action, not something typed every session.
function openOfficialLoginDialog(o) {
  if (o.has_login) {
    const choice = prompt(
      `${o.name} logs in as "${o.username}".\n\n` +
      `Type a NEW password to reset it, or type REVOKE to remove this login entirely ` +
      `(their phone can't sign in again until you set a new one). Cancel to leave it as is.`);
    if (choice === null) return;
    if (choice.trim().toUpperCase() === "REVOKE") {
      adminFetch("/api/officials/" + o.id + "/credentials", { method: "DELETE" })
        .then(r => r.json()).then(data => {
          if (data.ok) loadOfficials();
          else alert(data.error || "Could not revoke login.");
        });
      return;
    }
    adminFetch("/api/officials/" + o.id + "/credentials", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: o.username, password: choice })
    }).then(r => r.json()).then(data => {
      if (data.ok) { alert("Password reset."); loadOfficials(); }
      else alert(data.error || "Could not reset password.");
    });
    return;
  }

  const username = prompt(`Choose a login username for ${o.name} (3-32 characters: letters, numbers, _ . -):`);
  if (!username) return;
  const password = prompt(`Choose a password for ${o.name} (at least 6 characters). Share this with them directly - it won't be shown again.`);
  if (!password) return;
  adminFetch("/api/officials/" + o.id + "/credentials", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: username.trim(), password })
  }).then(r => r.json()).then(data => {
    if (data.ok) loadOfficials();
    else alert(data.error || "Could not set login.");
  });
}

function loadOfficials() {
  if (!document.getElementById("officials-list")) return;
  adminFetch("/api/officials").then(r => (r.ok ? r.json() : null)).then(data => {
    if (data) {
      renderOfficials(data.officials);
      refreshRosterOfficialOptions(data.officials);
    }
  }).catch(() => {});
}
loadOfficials();

const btnAddOfficial = document.getElementById("btn-add-official");
if (btnAddOfficial) {
  btnAddOfficial.addEventListener("click", () => {
    const name = document.getElementById("official-name").value.trim();
    const phone = document.getElementById("official-phone").value.trim();
    const location = document.getElementById("official-location").value.trim();
    const latitude = document.getElementById("official-lat").value.trim();
    const longitude = document.getElementById("official-lon").value.trim();
    adminFetch("/api/officials", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name, phone, location: location || null,
        latitude: latitude || null, longitude: longitude || null
      })
    }).then(r => r.json()).then(data => {
      if (data.ok) {
        document.getElementById("official-name").value = "";
        document.getElementById("official-phone").value = "";
        document.getElementById("official-location").value = "";
        document.getElementById("official-lat").value = "";
        document.getElementById("official-lon").value = "";
        loadOfficials();
      } else {
        alert(data.error || "Could not add official.");
      }
    });
  });
}

// ---------- Shift/duty roster (feature 9) ----------
// Keeps the roster's zone/gate dropdown in sync with whatever cameras have
// actually posted so far - it's rebuilt whenever either the camera list or
// the roster panel itself refreshes, and preserves the current selection.
function refreshRosterCameraOptions() {
  const sel = document.getElementById("roster-camera");
  if (!sel) return;
  const prev = sel.value;
  sel.innerHTML = '<option value="">Zone/gate...</option>';
  lastKnownCameras.forEach(cam => {
    const opt = document.createElement("option");
    opt.value = cam.camera_id;
    opt.textContent = cam.label || cam.camera_id;
    sel.appendChild(opt);
  });
  if (prev && lastKnownCameras.some(c => c.camera_id === prev)) sel.value = prev;
}

function refreshRosterOfficialOptions(officials) {
  const sel = document.getElementById("roster-official");
  if (!sel) return;
  const prev = sel.value;
  sel.innerHTML = '<option value="">Official...</option>';
  (officials || []).forEach(o => {
    const opt = document.createElement("option");
    opt.value = o.id;
    opt.textContent = o.name;
    sel.appendChild(opt);
  });
  if (prev && (officials || []).some(o => String(o.id) === prev)) sel.value = prev;
}

function renderRoster(roster) {
  const list = document.getElementById("roster-list");
  if (!list) return;
  list.innerHTML = "";
  if (!roster || !roster.length) {
    list.innerHTML = '<div class="deploy-note">No shifts scheduled yet.</div>';
    return;
  }
  roster.forEach(s => {
    const camLabel = (lastKnownCameras.find(c => c.camera_id === s.camera_id) || {}).label || s.camera_id;
    const liveTag = s.active_now
      ? ` <span class="user-role roster-live">&#128994; ON SHIFT NOW</span>`
      : "";
    const row = document.createElement("div");
    row.className = "user-row roster-row" + (s.active_now ? " active-now" : "");
    row.innerHTML =
      `<div>${escapeHtml(s.official_name)} <span class="user-role">&#128205; ${escapeHtml(camLabel)}</span>` +
      ` <span class="user-role">${escapeHtml(s.day_label)} ${escapeHtml(s.start_time)}-${escapeHtml(s.end_time)}</span>` +
      liveTag + `</div>` +
      `<div class="row-actions"><button title="Remove shift" data-id="${s.id}">&#10005;</button></div>`;
    row.querySelector("button").addEventListener("click", () => {
      if (!confirm(`Remove ${s.official_name}'s ${s.day_label} ${s.start_time}-${s.end_time} shift at ${camLabel}?`)) return;
      adminFetch("/api/roster/" + s.id, { method: "DELETE" })
        .then(r => r.json()).then(() => loadRoster());
    });
    list.appendChild(row);
  });
}

function loadRoster() {
  if (!document.getElementById("roster-list")) return;
  adminFetch("/api/roster").then(r => (r.ok ? r.json() : null)).then(data => {
    if (data) renderRoster(data.roster);
  }).catch(() => {});
}
loadRoster();
// Refresh roster's "ON SHIFT NOW" badges periodically, since a shift can
// start/end without any other admin action happening to trigger a reload.
setInterval(loadRoster, 60000);

const btnAddRoster = document.getElementById("btn-add-roster");
if (btnAddRoster) {
  btnAddRoster.addEventListener("click", () => {
    const official_id = document.getElementById("roster-official").value;
    const camera_id = document.getElementById("roster-camera").value;
    const day_of_week = document.getElementById("roster-day").value;
    const start_time = document.getElementById("roster-start").value;
    const end_time = document.getElementById("roster-end").value;
    if (!official_id || !camera_id || !start_time || !end_time) {
      alert("Pick an official, a zone/gate, and both start/end times.");
      return;
    }
    adminFetch("/api/roster", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        official_id: Number(official_id), camera_id,
        day_of_week: day_of_week === "" ? null : Number(day_of_week),
        start_time, end_time
      })
    }).then(r => r.json()).then(data => {
      if (data.ok) {
        renderRoster(data.roster);
      } else {
        alert(data.error || "Could not add shift.");
      }
    });
  });
}

// "History - current camera" export link needs to know WHICH camera is
// currently selected, which only exists client-side (activeCameraId) - a
// static Jinja-rendered href can't know that ahead of time, so its href is
// (re)built just before the click actually navigates, and refreshed every
// time the camera selection changes so it never points at a stale camera.
const exportHistoryCurrentLink = document.getElementById("export-history-current");
function refreshExportHistoryLink() {
  if (exportHistoryCurrentLink) {
    exportHistoryCurrentLink.href = "/api/export/history.csv?camera_id=" + encodeURIComponent(activeCameraId);
    exportHistoryCurrentLink.textContent = "History - " + activeCameraId + " only";
  }
}
refreshExportHistoryLink();

