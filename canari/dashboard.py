from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import metadata
from urllib.parse import parse_qs, urlparse

from canari.registry import CanaryRegistry
from canari.reporting import ForensicReporter

try:
    _VERSION = metadata.version("canari")
except Exception:
    _VERSION = "0.1.0"

_HTML = """<!doctype html>
<html>
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Canari Dashboard</title>
  <style>
    :root { --bg:#0f172a; --card:#111827; --ink:#e5e7eb; --muted:#9ca3af; --accent:#22c55e; --warn:#f59e0b; --crit:#ef4444; }
    body{margin:0;font-family:ui-sans-serif,system-ui;background:linear-gradient(135deg,#0b1020,#111827);color:var(--ink)}
    .wrap{max-width:1100px;margin:24px auto;padding:0 16px}
    .grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
    .card{background:rgba(17,24,39,.8);backdrop-filter:blur(4px);border:1px solid #1f2937;border-radius:12px;padding:12px}
    .k{font-size:12px;color:var(--muted)}
    .v{font-size:22px;font-weight:700}
    table{width:100%;border-collapse:collapse;font-size:13px}
    th,td{padding:8px;border-bottom:1px solid #1f2937;text-align:left;vertical-align:top}
    .pill{padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700;display:inline-block}
    .low{background:#1f2937}.medium{background:#374151}.high{background:#7c2d12}.critical{background:#7f1d1d}
  </style>
</head>
<body>
  <div class=\"wrap\">
    <h1>Canari Dashboard <small id=\"version\" style=\"color:#9ca3af\"></small></h1>
    <div class=\"grid\" id=\"stats\"></div>
    <h2>Recent Alerts</h2>
    <div class=\"card\"><table><thead><tr><th>Time</th><th>Severity</th><th>Surface</th><th>Conversation</th><th>Incident</th><th>Snippet</th></tr></thead><tbody id=\"alerts\"></tbody></table></div>
    <h2>Recent Incidents</h2>
    <div class=\"card\"><table><thead><tr><th>Incident</th><th>Conversation</th><th>Events</th><th>Max Severity</th><th>Surfaces</th><th>Last Seen</th></tr></thead><tbody id=\"incidents\"></tbody></table></div>
  </div>
<script>
async function refresh(){
  const summary = await (await fetch('/api/summary?limit=2000')).json();
  const alerts = await (await fetch('/api/alerts?limit=30')).json();
  const incidents = await (await fetch('/api/incidents?limit=20')).json();
  document.getElementById('version').textContent = 'v'+(summary.version||'');

  const total = summary.alerts?.total_alerts || 0;
  const crit = summary.alerts?.by_severity?.critical || 0;
  const high = summary.alerts?.by_severity?.high || 0;
  const active = summary.tokens?.active_tokens || 0;
  document.getElementById('stats').innerHTML = [
    ['Active Canaries', active],
    ['Total Alerts', total],
    ['High Alerts', high],
    ['Critical Alerts', crit],
  ].map(([k,v])=>`<div class=card><div class=k>${k}</div><div class=v>${v}</div></div>`).join('');

  document.getElementById('alerts').innerHTML = alerts.map(a=>`
    <tr>
      <td>${a.triggered_at}</td>
      <td><span class="pill ${a.severity}">${a.severity}</span></td>
      <td>${a.detection_surface}</td>
      <td>${a.conversation_id||''}</td>
      <td>${a.incident_id||''}</td>
      <td>${(a.output_snippet||'').replaceAll('<','&lt;')}</td>
    </tr>`).join('');

  document.getElementById('incidents').innerHTML = incidents.map(i=>`
    <tr>
      <td>${i.incident_id}</td>
      <td>${i.conversation_id}</td>
      <td>${i.event_count}</td>
      <td><span class="pill ${i.max_severity}">${i.max_severity}</span></td>
      <td>${(i.surfaces||[]).join(', ')}</td>
      <td>${i.last_seen}</td>
    </tr>`).join('');
}
refresh(); setInterval(refresh, 5000);
</script>
</body></html>
"""


@dataclass
class DashboardServer:
    db_path: str
    host: str = "127.0.0.1"
    port: int = 8080
    api_token: str | None = None

    def __post_init__(self):
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> tuple[str, int]:
        if self._httpd is not None:
            return self.host, self._httpd.server_address[1]

        registry = CanaryRegistry(self.db_path)
        reporter = ForensicReporter(registry)

        handler = _make_handler(registry, reporter, api_token=self.api_token)
        self._httpd = ThreadingHTTPServer((self.host, self.port), handler)

        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self.host, self._httpd.server_address[1]

    def stop(self) -> None:
        if self._httpd is None:
            return
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)
        self._thread = None
        self._httpd = None


def _make_handler(registry: CanaryRegistry, reporter: ForensicReporter, api_token: str | None = None):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)

            if parsed.path == "/":
                return self._send_html(_HTML)
            if parsed.path == "/api/health":
                return self._send_json({"ok": True, "version": _VERSION})
            if parsed.path.startswith("/api/") and not _is_authorized(api_token, qs, self.headers):
                return self._send_json({"ok": False, "error": "unauthorized"}, status=401)
            if parsed.path == "/api/summary":
                limit = _as_int(qs.get("limit", ["5000"])[0], 5000)
                payload = reporter.forensic_summary(
                    limit=limit,
                    tenant_id=_first(qs, "tenant"),
                    application_id=_first(qs, "app"),
                )
                payload["version"] = _VERSION
                return self._send_json(payload)
            if parsed.path == "/api/alerts":
                limit = _as_int(qs.get("limit", ["50"])[0], 50)
                alerts = registry.list_alerts(
                    limit=limit,
                    severity=_first(qs, "severity"),
                    detection_surface=_first(qs, "surface"),
                    conversation_id=_first(qs, "conversation"),
                    incident_id=_first(qs, "incident"),
                    since=_first(qs, "since"),
                    until=_first(qs, "until"),
                    tenant_id=_first(qs, "tenant"),
                    application_id=_first(qs, "app"),
                )
                return self._send_json([a.model_dump(mode="json") for a in alerts])
            if parsed.path == "/api/incidents":
                limit = _as_int(qs.get("limit", ["20"])[0], 20)
                incidents = reporter.registry.list_alerts(
                    limit=5000,
                    tenant_id=_first(qs, "tenant"),
                    application_id=_first(qs, "app"),
                )
                grouped = {}
                for a in incidents:
                    if not a.incident_id:
                        continue
                    grouped.setdefault(a.incident_id, []).append(a)
                rows = []
                for inc_id, events in grouped.items():
                    events.sort(key=lambda x: x.triggered_at)
                    rows.append(
                        {
                            "incident_id": inc_id,
                            "conversation_id": events[0].conversation_id,
                            "event_count": len(events),
                            "max_severity": max(events, key=lambda e: _sev_rank(e.severity.value)).severity.value,
                            "surfaces": sorted({e.detection_surface for e in events}),
                            "last_seen": events[-1].triggered_at.isoformat(),
                        }
                    )
                rows.sort(key=lambda r: r["last_seen"], reverse=True)
                return self._send_json(rows[:limit])

            self.send_response(404)
            self.end_headers()

        def _send_json(self, payload, status: int = 200):
            raw = json.dumps(payload, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _send_html(self, html: str):
            raw = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    return Handler


def _as_int(raw: str, default: int) -> int:
    try:
        return int(raw)
    except Exception:
        return default


def _first(qs: dict[str, list[str]], key: str) -> str | None:
    vals = qs.get(key)
    if not vals:
        return None
    return vals[0]


def _sev_rank(sev: str) -> int:
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    return order.get(sev, -1)


def _is_authorized(api_token: str | None, qs: dict[str, list[str]], headers) -> bool:
    if not api_token:
        return True
    q_token = _first(qs, "token")
    h_token = headers.get("X-Canari-Token") if headers is not None else None
    return api_token in {q_token, h_token}
