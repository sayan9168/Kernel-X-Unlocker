"""
kernel_x.dashboard
===================

Module 5 - Local Visualization Dashboard Framework.

A lightweight, **localhost-only** web UI built on Flask (with an automatic
fallback to :mod:`http.server` when Flask is unavailable) that renders:

* the system/device fingerprint and a **risk heatmap summary**
  (subsystem contribution grid + severity gauge),
* the timeline of simulated events from the dry-run scenario batteries,
* the plugin manifest and per-hook status,
* an **Export report** action that writes Markdown/JSON artifacts through the
  reporter module and links them for download.

Security posture of the dashboard itself
----------------------------------------
* Binds to ``127.0.0.1`` by default; ``--host 0.0.0.0`` is refused unless the
  operator passes an explicit acknowledgement flag, because the page discloses
  audit telemetry.
* All template rendering goes through Jinja2 autoescaping (Flask path) or HTML
  escaping (fallback path); no user input reaches ``eval``/shell.
* Exported files are written inside the configured report directory only; the
  download endpoint resolves paths with ``safe_join`` semantics and rejects
  traversal attempts.
"""

from __future__ import annotations

import argparse
import html
import json
import logging
import os
import re
import socketserver
import threading
from dataclasses import asdict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, SimpleHTTPRequestHandler
from typing import Any, Dict, List, Optional, Tuple

try:  # optional dependency - fallback keeps the toolkit dependency-free
    from flask import Flask, abort, jsonify, render_template_string, request, send_from_directory
except ImportError:  # pragma: no cover - exercised in fallback mode
    Flask = None  # type: ignore[assignment]

from .plugin_manager import PluginContext, PluginManager
from .reporter import AcademicReportGenerator, AuditSession
from .risk_engine import DeviceFingerprinter, VulnerabilitySurfaceMapper
from .simulator import ScenarioRunner

logger = logging.getLogger("kernel_x.dashboard")

DASHBOARD_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Kernel-X Research Toolkit — {{ session_id }}</title>
<style>
:root{--bg:#0f141b;--panel:#161d27;--ink:#e6edf3;--muted:#8b98a8;--accent:#4fc3f7;
--ok:#3fb950;--warn:#d29922;--bad:#f85149;--line:#243040}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif}
header{padding:18px 24px;border-bottom:1px solid var(--line);display:flex;
justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}
h1{font-size:18px;margin:0}h2{font-size:14px;color:var(--accent);text-transform:uppercase;
letter-spacing:.08em;margin:0 0 10px}
.badge{padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600}
main{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:16px;padding:16px 24px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:5px 7px;
border-bottom:1px solid var(--line)}tr:last-child td{border-bottom:none}
.gauge{height:14px;background:#222c38;border-radius:7px;overflow:hidden;margin:8px 0}
.gauge>div{height:100%}
.heat{display:grid;grid-template-columns:repeat(6,1fr);gap:6px;margin-top:8px}
.cell{border-radius:6px;padding:10px 6px;font-size:11px;text-align:center;color:#0b0f14;
font-weight:600;line-height:1.25}
.tl{list-style:none;margin:0;padding:0;font-size:12px}
.tl li{padding:4px 0;border-bottom:1px dashed var(--line);display:flex;gap:8px}
.tl time{color:var(--muted);min-width:64px;font-variant-numeric:tabular-nums}
.denied{color:var(--bad)}.granted{color:var(--ok)}.info{color:var(--muted)}
button,a.btn{background:var(--accent);color:#04121c;border:none;border-radius:6px;padding:8px 14px;
font-weight:700;cursor:pointer;text-decoration:none;font-size:13px;display:inline-block;margin-top:8px}
pre{white-space:pre-wrap;font-size:12px;color:var(--muted)}
footer{padding:14px 24px;color:var(--muted);font-size:11px;border-top:1px solid var(--line)}
</style>
</head>
<body>
<header>
  <div>
    <h1>Kernel-X Research Toolkit</h1>
    <span class="info">session {{ session_id }} · static-analysis &amp; simulation only</span>
  </div>
  <div>
    <span class="badge" style="background:{{ sev_color }}">{{ severity }} · {{ '%.1f'|format(risk_score) }}/10</span>
    <form method="post" action="/export" style="display:inline">
      <input type="hidden" name="fmt" value="md"><button type="submit">Export report (.md)</button>
    </form>
    <form method="post" action="/export" style="display:inline">
      <input type="hidden" name="fmt" value="json"><button type="submit">Export (.json)</button>
    </form>
  </div>
</header>
<main>
  <section class="card"><h2>Device Fingerprint</h2>
    <table>
      {% for k, v in fingerprint_rows %}<tr><th>{{ k }}</th><td>{{ v }}</td></tr>{% endfor %}
    </table>
  </section>
  <section class="card"><h2>Risk Heatmap</h2>
    <div class="gauge"><div style="width:{{ gauge_pct }}%;background:{{ sev_color }}"></div></div>
    <div class="heat">
      {% for name, value, color in heat_cells %}
      <div class="cell" style="background:{{ color }}" title="{{ name }}">{{ name }}<br>{{ '%.1f'|format(value) }}</div>
      {% endfor %}
      {% if not heat_cells %}<p class="info">no subsystem contributions</p>{% endif %}
    </div>
    <h2 style="margin-top:14px">Top findings</h2>
    <table><tr><th>CVE</th><th>Status</th><th>Contrib.</th></tr>
      {% for f in top_findings %}<tr><td>{{ f.cve_id }}</td><td>{{ f.status }}</td><td>{{ '%.2f'|format(f.contribution) }}</td></tr>{% endfor %}
    </table>
  </section>
  <section class="card"><h2>Simulation Timeline</h2>
    {% for scenario in scenarios %}
      <h3 style="margin:10px 0 4px">{{ scenario.name }}
        <span class="badge" style="background:{{ '#3fb950' if scenario.passed else '#f85149' }};color:#04121c">
          {{ 'PASS' if scenario.passed else 'FAIL' }}</span></h3>
      <ul class="tl">
        {% for ev in scenario.events %}
        <li><time>t+{{ '%.3f'|format(ev.t_offset) }}s</time>
            <span class="{{ 'denied' if 'DENIED' in ev.outcome or 'LOCKED' in ev.outcome else ('granted' if ev.outcome in ('OK','GRANTED','VERIFIED','CONFIRMED') else 'info') }}">
            [{{ ev.outcome }}]</span> <b>{{ ev.actor }}</b> {{ ev.action }}
            <span class="info">{{ ev.note }}</span></li>
        {% endfor %}
      </ul>
    {% endfor %}
    {% if not scenarios %}<p class="info">no scenarios executed yet</p>{% endif %}
  </section>
  <section class="card"><h2>Plugins</h2>
    <table><tr><th>Plugin</th><th>Version</th><th>State</th></tr>
      {% for p in plugins %}<tr><td>{{ p.name }}</td><td>{{ p.version }}</td><td>{{ p.state }}</td></tr>{% endfor %}
    </table>
  </section>
  <section class="card"><h2>API endpoints</h2>
    <pre>GET /api/state      full JSON snapshot
GET /api/risk       risk assessment JSON
GET /api/timeline   simulation events JSON
POST /export        write md/json artifact (fmt field)
GET /reports/&lt;file&gt; download exported artifact</pre>
  </section>
</main>
<footer>Defensive research instrument — no exploitation capability. Generated {{ generated_at }}.</footer>
</body>
</html>
"""


def _severity_color(score: float) -> str:
    if score >= 7.0:
        return "#f85149"
    if score >= 5.0:
        return "#db6d28"
    if score >= 3.0:
        return "#d29922"
    if score >= 1.0:
        return "#3fb950"
    return "#58a6ff"


class DashboardController:
    """Owns the analysis state and serves it through a local web UI."""

    def __init__(
        self,
        mock_properties: Optional[Dict[str, str]] = None,
        sysroot: Optional[str] = None,
        report_dir: str = "reports",
        plugins_dir: Optional[str] = None,
    ) -> None:
        self.fingerprinter = DeviceFingerprinter(mock_properties=mock_properties, sysroot=sysroot)
        self.mapper = VulnerabilitySurfaceMapper()
        self.report_gen = AcademicReportGenerator(output_dir=report_dir)
        self.plugin_manager = PluginManager(plugins_dir=plugins_dir)
        self.report_dir = os.path.abspath(report_dir)
        self.lock = threading.RLock()
        self.session: Optional[AuditSession] = None
        self.context: Optional[PluginContext] = None
        self.load_report: Optional[Dict[str, Any]] = None
        self.last_export: Dict[str, str] = {}

    # -- pipeline ------------------------------------------------------------

    def run_analysis(self) -> AuditSession:
        """Full pipeline: fingerprint → assess → simulate → plugins → session."""
        with self.lock:
            started = datetime.now(timezone.utc).isoformat(timespec="seconds")
            fingerprint = self.fingerprinter.run()
            assessment = self.mapper.assess(fingerprint)

            runner = ScenarioRunner()
            outcomes = runner.run_all_defaults()

            context = PluginContext(
                session_id=f"sess-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
                fingerprint=fingerprint,
                assessment=assessment,
                scenarios=list(outcomes),
                simulator=runner.simulator,
            )
            self.load_report = self.plugin_manager.load_plugins().as_dict()
            self.plugin_manager.run_pipeline(context)

            session = AuditSession(
                session_id=context.session_id,
                started_at=started,
                fingerprint=fingerprint,
                assessment=assessment,
                scenarios=context.scenarios,
                plugin_observations={
                    name: {hook: res.as_dict() for hook, res in hooks.items()}
                    for name, hooks in (
                        (plugin.name, {
                            entry["hook"]: PluginHookResultProxy(entry)
                            for entry in plugin.invocations
                        })
                        for plugin in self.plugin_manager.plugins
                    )
                },
            )
            sections = self.plugin_manager.collect_report_sections(context)
            session.plugin_observations["_report_sections"] = {
                name: section["report_data"].get("markdown_lines", "") for name, section in sections.items()
            }
            session.plugin_observations["_load_report"] = self.load_report
            session.plugin_observations["_knowledge_base_digest"] = (
                self.report_gen.knowledge_base_digest(self.mapper.knowledge_base)
            )
            self.context = context
            self.session = session
            logger.info("dashboard analysis complete: risk=%s (%s)", assessment.risk_score, assessment.severity)
            return session

    def ensure_session(self) -> AuditSession:
        if self.session is None:
            self.run_analysis()
        assert self.session is not None
        return self.session

    # -- view models -------------------------------------------------------------

    def view_model(self) -> Dict[str, Any]:
        session = self.ensure_session()
        fingerprint = session.fingerprint
        assessment = session.assessment
        assert fingerprint is not None and assessment is not None

        fingerprint_rows: List[Tuple[str, str]] = [
            ("Device", f"{fingerprint.manufacturer} {fingerprint.model}"),
            ("Android / SDK", f"{fingerprint.android_version or 'n/a'} / {fingerprint.sdk_level or 'n/a'}"),
            ("Patch level", f"{fingerprint.security_patch_level or 'n/a'}"
             + (f" ({fingerprint.patch_age_days}d)" if fingerprint.patch_age_days is not None else "")),
            ("Kernel", f"{fingerprint.kernel_version} ({fingerprint.gki_variant})"),
            ("SoC", f"{fingerprint.soc_vendor} {fingerprint.soc_codename}"),
            ("Bootloader / AVB", f"{fingerprint.bootloader_state} / {fingerprint.avb_version}"),
            ("FBE", f"{fingerprint.fbe_encryption_type} · {fingerprint.fbe_content_mode}"),
            ("Metadata enc.", fingerprint.fbe_metadata_mode),
            ("Keystore", fingerprint.keystore2_backend),
            ("Kconfig visible", fingerprint.extra.get("kconfig_available", "no")),
        ]

        max_value = max(assessment.subsystem_scores.values(), default=1.0) or 1.0
        heat_cells: List[Tuple[str, float, str]] = []
        for name, value in sorted(assessment.subsystem_scores.items(), key=lambda kv: -kv[1]):
            ratio = min(1.0, value / max_value)
            red = int(0x3f + (0xf8 - 0x3f) * ratio)
            green = int(0xb9 - (0xb9 - 0x51) * ratio)
            blue = int(0x50 - (0x50 - 0x49) * ratio)
            heat_cells.append((name, value, f"#{red:02x}{green:02x}{blue:02x}"))

        scenarios = [
            {
                "name": outcome.scenario,
                "passed": outcome.passed,
                "events": outcome.events,
            }
            for outcome in session.scenarios
        ]
        return {
            "session_id": session.session_id,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "risk_score": assessment.risk_score,
            "severity": assessment.severity,
            "sev_color": _severity_color(assessment.risk_score),
            "gauge_pct": round(assessment.risk_score * 10.0, 1),
            "fingerprint_rows": fingerprint_rows,
            "heat_cells": heat_cells,
            "top_findings": [f.as_dict() for f in assessment.findings[:8]],
            "scenarios": scenarios,
            "plugins": [plugin.manifest() for plugin in self.plugin_manager.plugins],
            "last_export": dict(self.last_export),
        }

    def api_state(self) -> Dict[str, Any]:
        session = self.ensure_session()
        assert session.fingerprint is not None and session.assessment is not None
        return {
            "session": session.summary(),
            "fingerprint": session.fingerprint.as_dict(),
            "assessment": session.assessment.as_dict(),
            "simulation": [outcome.as_dict() for outcome in session.scenarios],
            "plugins": self.plugin_manager.manifest_all(),
            "load_report": self.load_report or {},
        }

    def export(self, fmt: str = "md") -> Dict[str, str]:
        session = self.ensure_session()
        fmt = (fmt or "md").lower()
        if fmt not in {"md", "json", "html", "pdf"}:
            raise ValueError(f"unsupported export format '{fmt}'")
        return self.report_gen.export(session, [fmt])

    # -- servers ------------------------------------------------------------------

    def build_flask_app(self) -> "Flask":
        if Flask is None:
            raise RuntimeError("Flask is not installed")
        app = Flask(__name__, static_folder=None)
        controller = self

        @app.route("/")
        def index() -> str:  # noqa: D401 - route handler
            model = controller.view_model()
            return render_template_string(DASHBOARD_TEMPLATE, **model)

        @app.route("/api/state")
        def api_state() -> Any:
            return jsonify(controller.api_state())

        @app.route("/api/risk")
        def api_risk() -> Any:
            session = controller.ensure_session()
            assert session.assessment is not None
            return jsonify(session.assessment.as_dict())

        @app.route("/api/timeline")
        def api_timeline() -> Any:
            session = controller.ensure_session()
            return jsonify([outcome.as_dict() for outcome in session.scenarios])

        @app.route("/export", methods=["POST"])
        def export() -> Any:
            fmt = request.form.get("fmt", "md") if request.form else (request.args.get("fmt", "md"))
            try:
                written = controller.export(fmt)
            except ValueError as exc:
                abort(400, description=str(exc))
                return ""
            link = f"/reports/{os.path.basename(next(iter(written.values())))}"
            return (
                "<!doctype html><meta charset='utf-8'><body style='font-family:sans-serif;"
                f"background:#0f141b;color:#e6edf3;padding:2rem'>Report exported.<br>"
                f"<a href='{link}' style='color:#4fc3f7'>Download {html.escape(os.path.basename(next(iter(written.values()))))}</a>"
                " · <a href='/' style='color:#4fc3f7'>back</a></body>"
            )

        @app.route("/reports/<path:filename>")
        def reports(filename: str) -> Any:
            safe = os.path.normpath(filename)
            if safe.startswith("..") or os.path.isabs(safe):
                abort(404)
            return send_from_directory(controller.report_dir, safe, as_attachment=True)

        @app.route("/refresh", methods=["POST"])
        def refresh() -> Any:
            controller.run_analysis()
            return jsonify({"status": "re-analysed"})

        return app

    def serve(self, host: str = "127.0.0.1", port: int = 8765, acknowledge_remote: bool = False) -> None:
        """Start the dashboard. Blocks until interrupted."""
        if host not in {"127.0.0.1", "localhost", "::1"} and not acknowledge_remote:
            raise PermissionError(
                "refusing to bind beyond loopback without --allow-non-local: the dashboard "
                "exposes device-audit telemetry"
            )
        self.ensure_session()
        if Flask is not None:
            app = self.build_flask_app()
            logger.info("Kernel-X dashboard (Flask) at http://%s:%d/", host, port)
            app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)
            return
        logger.warning("Flask unavailable - serving minimal stdlib dashboard")
        self._serve_stdlib(host, port)

    def _serve_stdlib(self, host: str, port: int) -> None:
        controller = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: Any) -> None:  # quiet logger bridge
                logger.debug("dashboard-http: " + fmt, *args)

            def _send(self, code: int, body: bytes, ctype: str = "text/html; charset=utf-8") -> None:
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802
                path = self.path.split("?", 1)[0]
                try:
                    if path == "/":
                        model = controller.view_model()
                        self._send(200, self._render(model).encode("utf-8"))
                    elif path.startswith("/api/"):
                        payload = controller.api_state()
                        if path == "/api/risk" and payload.get("assessment"):
                            payload = payload["assessment"]
                        elif path == "/api/timeline":
                            payload = payload["simulation"]
                        self._send(200, json.dumps(payload, indent=2, default=str).encode(), "application/json")
                    elif path.startswith("/reports/"):
                        name = os.path.basename(path)
                        full = os.path.join(controller.report_dir, name)
                        if os.path.isfile(full):
                            with open(full, "rb") as handle:
                                self._send(200, handle.read(), "text/plain; charset=utf-8")
                        else:
                            self._send(404, b"not found", "text/plain")
                    else:
                        self._send(404, b"not found", "text/plain")
                except Exception as exc:  # noqa: BLE001 - never crash the server
                    self._send(500, f"dashboard error: {exc}".encode(), "text/plain")

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0") or "0")
                raw = self.rfile.read(length).decode("utf-8") if length else ""
                fmt = "md"
                match = re.search(r"fmt=([^&]+)", raw)
                if match:
                    fmt = match.group(1)
                try:
                    written = controller.export(fmt)
                    name = os.path.basename(next(iter(written.values())))
                    body = f"exported -> /reports/{name}".encode()
                    self._send(200, body, "text/plain")
                except Exception as exc:  # noqa: BLE001
                    self._send(400, f"export failed: {exc}".encode(), "text/plain")

            @staticmethod
            def _render(model: Dict[str, Any]) -> str:
                esc = html.escape
                rows = "".join(
                    f"<tr><th>{esc(k)}</th><td>{esc(str(v))}</td></tr>"
                    for k, v in model["fingerprint_rows"]
                )
                heat = "".join(
                    f"<div style='background:{color};padding:8px;border-radius:6px;margin:4px;"
                    f"display:inline-block;font-size:12px'>{esc(name)} {value:.1f}</div>"
                    for name, value, color in model["heat_cells"]
                )
                timelines = ""
                for scenario in model["scenarios"]:
                    events = "".join(
                        f"<li>t+{ev['t_offset']:.3f}s <b>[{esc(ev['outcome'])}]</b> "
                        f"{esc(ev['actor'])} {esc(ev['action'])} <i>{esc(ev['note'])}</i></li>"
                        for ev in scenario["events"]
                    )
                    timelines += (
                        f"<h3>{esc(scenario['name'])} — {'PASS' if scenario['passed'] else 'FAIL'}</h3>"
                        f"<ul>{events}</ul>"
                    )
                findings = "".join(
                    f"<tr><td>{esc(f['cve_id'])}</td><td>{esc(f['status'])}</td>"
                    f"<td>{f['contribution']:.2f}</td></tr>"
                    for f in model["top_findings"]
                )
                return (
                    "<!doctype html><meta charset='utf-8'><style>body{font-family:sans-serif;"
                    "background:#0f141b;color:#e6edf3;margin:2rem}table{border-collapse:collapse}"
                    "td,th{border:1px solid #243040;padding:4px 8px;text-align:left}</style>"
                    f"<h1>Kernel-X Research Toolkit — {esc(model['session_id'])}</h1>"
                    f"<h2>Risk: {model['risk_score']}/10 ({esc(model['severity'])})</h2>"
                    f"<table><tr><th>Attribute</th><th>Value</th></tr>{rows}</table>"
                    f"<h2>Heatmap</h2>{heat}<h2>Top findings</h2>"
                    f"<table><tr><th>CVE</th><th>Status</th><th>Contrib</th></tr>{findings}</table>"
                    f"<h2>Simulated event timeline</h2>{timelines}"
                    "<h2>Export</h2><form method='post' action='/export'>"
                    "<select name='fmt'><option>md</option><option>json</option><option>html</option></select>"
                    "<button>Export report</button></form>"
                )

        class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
            allow_reuse_address = True
            daemon_threads = True

        httpd = Server((host, port), Handler)
        logger.info("Kernel-X dashboard (stdlib) at http://%s:%d/ — Ctrl+C to stop", host, port)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            httpd.shutdown()


class PluginHookResultProxy(dict):
    """Adapter exposing recorded invocations with an ``as_dict()`` interface."""

    def __init__(self, entry: Dict[str, Any]) -> None:
        super().__init__(entry)

    def as_dict(self) -> Dict[str, Any]:
        return dict(self)


# ---------------------------------------------------------------------------
# CLI entry point for the dashboard module
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Kernel-X local visualization dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="bind address (loopback recommended)")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--report-dir", default="reports")
    parser.add_argument("--sysroot", default=None, help="audit an Android filesystem snapshot statically")
    parser.add_argument("--mock-props", default=None, help="JSON file of lab properties (emulator mode)")
    parser.add_argument("--allow-non-local", action="store_true",
                        help="explicitly permit binding beyond loopback (discloses audit telemetry)")
    parser.add_argument("--export-only", action="store_true", help="run pipeline, export, exit (no server)")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    mock_props: Optional[Dict[str, str]] = None
    if args.mock_props:
        try:
            with open(args.mock_props, "r", encoding="utf-8") as handle:
                loaded = json.load(handle)
            mock_props = {str(k): str(v) for k, v in loaded.items()}
        except (OSError, json.JSONDecodeError) as exc:
            parser.error(f"cannot read --mock-props: {exc}")

    controller = DashboardController(
        mock_properties=mock_props, sysroot=args.sysroot, report_dir=args.report_dir
    )
    if args.export_only:
        written = controller.export("md")
        written.update(controller.export("json"))
        print(json.dumps(written, indent=2))
        return 0
    controller.serve(host=args.host, port=args.port, acknowledge_remote=args.allow_non_local)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["DashboardController", "DASHBOARD_TEMPLATE", "main"]
