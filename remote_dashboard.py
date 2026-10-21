#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
remote_dashboard.py  (v2)
=========================

Kernel-X Research Toolkit - LOCAL-ONLY monitoring dashboard for the
educational memory-forensics lab.

Security posture (enforced, not aspirational):
  * Binds to 127.0.0.1 ONLY. There is no option string that binds to 0.0.0.0;
    attempts to override are refused with a logged error.
  * Token-based authentication: a per-session token is generated at startup
    (or read from $KX_DASHBOARD_TOKEN), required on every page load
    (?token=...), every REST call (X-Auth-Token header) and every WebSocket
    handshake (connection args). Tokens are compared with hmac.compare_digest.
  * The "scanner backend" is wired to the READ-ONLY modules
    memory_scanner_advanced / ai_pattern_predictor / bin/avb_analyzer. No
    endpoint can trigger writes, injection or device flashing.
  * Report generation renders HTML directly; PDF is produced by the browser's
    own print-to-PDF ("PDF (print)" button). No untrusted external binaries
    are invoked.

Run:  python remote_dashboard.py            (prints the one-time token)
      then open http://127.0.0.1:5013/?token=<token>
"""

from __future__ import annotations

import argparse
import functools
import hmac
import json
import logging
import os
import platform
import secrets
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional

from flask import (Flask, Response, abort, jsonify, redirect,
                   render_template_string, request, session)
from flask_socketio import SocketIO, emit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import memory_scanner_advanced as msa
except ImportError:
    msa = None
try:
    import ai_pattern_predictor as app_mod
except ImportError:
    app_mod = None

logger = logging.getLogger("kernel_x.dashboard")

BIND_HOST = "127.0.0.1"          # hardcoded - see module docstring
DEFAULT_PORT = 5013
TOKEN_SESSION_KEY = "kx_auth_ok"
MAX_LOG_LINES = 500

app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_bytes(32)
socketio = SocketIO(app, cors_allowed_origins=None, logger=False,
                    engineio_logger=False)

STATE: Dict[str, Any] = {
    "scan_running": False,
    "progress": 0.0,
    "last_scan": None,        # type: Optional[Dict[str, Any]]
    "last_prediction": None,  # type: Optional[Dict[str, Any]]
    "last_avb": None,
    "started_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
}
LOG_BUFFER: Deque[Dict[str, str]] = deque(maxlen=MAX_LOG_LINES)
LOG_LOCK = threading.Lock()
AUTH_TOKEN = ""               # set in main()


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def issue_token() -> str:
    env = os.environ.get("KX_DASHBOARD_TOKEN", "").strip()
    return env if env else secrets.token_urlsafe(24)


def token_matches(candidate: str) -> bool:
    return bool(candidate) and bool(AUTH_TOKEN) and \
        hmac.compare_digest(candidate, AUTH_TOKEN)


def check_auth_or_none() -> bool:
    """Accept: valid header token, valid ?token= query, or prior OK session."""
    hdr = request.headers.get("X-Auth-Token", "")
    q = request.args.get("token", "")
    if token_matches(hdr) or token_matches(q):
        session[TOKEN_SESSION_KEY] = True
        return True
    return bool(session.get(TOKEN_SESSION_KEY))


def require_auth(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if not check_auth_or_none():
            if request.path.startswith("/api/"):
                abort(401, description="missing or invalid token")
            return redirect("/login?next=" + request.path, code=302)
        return fn(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Live log plumbing (WebSocket broadcast)
# ---------------------------------------------------------------------------

def push_log(level: str, message: str) -> None:
    entry = {"ts": datetime.now(timezone.utc).strftime("%H:%M:%S"),
             "level": level, "message": message[:400]}
    with LOG_LOCK:
        LOG_BUFFER.append(entry)
    try:
        socketio.emit("log_line", entry)
    except Exception:  # never let logging break a scan
        logger.debug("ws emit failed", exc_info=True)
    getattr(logger, "warning" if level == "warn" else
            "error" if level == "error" else "info")(message)


class _SocketIOSink(logging.StreamHandler):
    """Mirror selected stdlib logs into the live console."""
    def emit(self, record: logging.LogRecord) -> None:  # pragma: no cover
        try:
            msg = self.format(record)
            lvl = "error" if record.levelno >= logging.ERROR else \
                  ("warn" if record.levelno >= logging.WARNING else "info")
            push_log(lvl, msg)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Backend jobs (all READ-ONLY operations)
# ---------------------------------------------------------------------------

def _set_progress(value: float) -> None:
    STATE["progress"] = max(0.0, min(1.0, value))
    try:
        socketio.emit("scan_progress",
                      {"progress": round(STATE["progress"] * 100, 1)})
    except Exception:
        pass


def run_scan_job(pid: Optional[int]) -> None:
    if STATE["scan_running"]:
        push_log("warn", "scan already running; request ignored")
        return
    if msa is None:
        push_log("error", "memory_scanner_advanced module unavailable")
        return
    STATE["scan_running"] = True
    _set_progress(0.02)
    push_log("info", f"read-only forensic scan started (pid={pid or 'auto'})")
    try:
        if pid is not None:
            report = {"tool": "memory_scanner_advanced",
                      "mode": "read-only-forensic",
                      "generated_utc": msa._now_iso(),
                      "platform": msa.get_platform_notes(),
                      "targets": [msa.scan_memory_patterns(pid)]}
        else:
            report = msa.scan_all_targets()
        _set_progress(0.75)
        STATE["last_scan"] = report
        s = report.get("summary", {})
        push_log("info",
                 "scan complete: scanned=%s denied=%s hits=%s" % (
                     s.get("scanned", len(report.get("targets", []))),
                     s.get("denied", "n/a"),
                     s.get("signature_hits", "n/a")))
        # feed the AI predictor with the structural signal (no raw bytes)
        if app_mod is not None:
            try:
                predictor = app_mod.VulnerabilityRiskPredictor()
                predictor.train_default_corpus()
                dev = app_mod.DeviceInfo(kernel_version=platform.release())
                pred = predictor.predict_risk(dev, report)
                STATE["last_prediction"] = pred
                push_log("info", f"AI exposure class: {pred['prediction']} "
                                 f"(conf {pred['confidence']})")
            except Exception as exc:
                push_log("warn", f"AI step skipped: {exc}")
        _set_progress(1.0)
        socketio.emit("scan_finished", {"report": STATE["last_scan"]})
    except Exception as exc:  # defensive outer shell
        push_log("error", f"scan aborted safely: {exc}")
        _set_progress(0.0)
    finally:
        STATE["scan_running"] = False


def run_avb_job() -> None:
    binary = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "bin", "avb_analyzer")
    if not os.path.isfile(binary):
        push_log("error", "bin/avb_analyzer missing - build it first")
        return
    try:
        proc = subprocess.run([binary], capture_output=True, text=True,
                              timeout=30, check=False)
        if proc.returncode == 0 and proc.stdout.strip():
            data = json.loads(proc.stdout)
            STATE["last_avb"] = data
            push_log("info", "AVB analyzer finished: state=%s" %
                     data.get("avb", {}).get("state", "unknown"))
            socketio.emit("avb_updated", {"avb": data})
        else:
            push_log("error", f"AVB analyzer rc={proc.returncode}: "
                              f"{proc.stderr[:200]}")
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as exc:
        push_log("error", f"AVB job failed safely: {type(exc).__name__}")


# ---------------------------------------------------------------------------
# HTML UI (Tailwind via CDN, dark security-console theme)
# ---------------------------------------------------------------------------

LOGIN_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Kernel-X Lab :: Login</title>
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-slate-950 text-slate-200 flex items-center justify-center h-screen">
<div class="bg-slate-900 border border-slate-700 rounded-xl p-8 w-96 shadow-2xl">
  <h1 class="text-xl font-bold mb-1 text-cyan-400">Kernel-X Lab Dashboard</h1>
  <p class="text-xs text-slate-400 mb-6">Localhost-only &middot; educational forensics</p>
  {% if error %}<p class="text-red-400 text-sm mb-3">{{ error }}</p>{% endif %}
  <form method="post" action="/login">
    <input name="token" type="password" placeholder="session token"
           class="w-full bg-slate-800 border border-slate-600 rounded px-3 py-2 mb-4 text-sm focus:outline-none focus:border-cyan-500">
    <button class="w-full bg-cyan-600 hover:bg-cyan-500 rounded py-2 font-semibold text-sm">Authenticate</button>
  </form>
</div></body></html>"""

DASH_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Kernel-X Lab Dashboard</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.5/socket.io.min.js"></script>
</head>
<body class="bg-slate-950 text-slate-200 min-h-screen">
<nav class="border-b border-slate-800 px-6 py-3 flex items-center justify-between bg-slate-900">
  <span class="font-bold text-cyan-400">Kernel-X <span class="text-slate-400 font-normal">Memory Forensics Lab</span></span>
  <div class="flex gap-3 text-sm">
    <button id="btnScan" onclick="startScan()" class="bg-emerald-600 hover:bg-emerald-500 rounded px-3 py-1">Run Read-Only Scan</button>
    <button onclick="runAvb()" class="bg-indigo-600 hover:bg-indigo-500 rounded px-3 py-1">AVB Analyze</button>
    <button onclick="genReport()" class="bg-slate-700 hover:bg-slate-600 rounded px-3 py-1">Export HTML Report</button>
    <button onclick="window.print()" class="bg-slate-700 hover:bg-slate-600 rounded px-3 py-1">PDF (print)</button>
  </div>
</nav>
<main class="p-6 grid grid-cols-1 lg:grid-cols-3 gap-6">
  <section class="lg:col-span-1 bg-slate-900 border border-slate-800 rounded-lg p-4">
    <h2 class="text-sm font-semibold text-slate-400 uppercase mb-3">Device Information</h2>
    <dl id="deviceInfo" class="text-sm space-y-1"><dt class="text-slate-500">Loading...</dt></dl>
  </section>
  <section class="lg:col-span-1 bg-slate-900 border border-slate-800 rounded-lg p-4">
    <h2 class="text-sm font-semibold text-slate-400 uppercase mb-3">Scan Progress</h2>
    <div class="w-full bg-slate-800 rounded h-4 overflow-hidden">
      <div id="progBar" class="bg-cyan-500 h-4 transition-all duration-300" style="width:0%"></div>
    </div>
    <p id="progText" class="text-xs text-slate-400 mt-2">idle</p>
    <div id="scanSummary" class="text-xs mt-3 space-y-1 text-slate-300"></div>
  </section>
  <section class="lg:col-span-1 bg-slate-900 border border-slate-800 rounded-lg p-4">
    <h2 class="text-sm font-semibold text-slate-400 uppercase mb-3">AI Prediction Confidence</h2>
    <div id="aiBox" class="text-sm text-slate-300">No prediction yet - run a scan.</div>
  </section>
  <section class="lg:col-span-3 bg-slate-900 border border-slate-800 rounded-lg p-4">
    <h2 class="text-sm font-semibold text-slate-400 uppercase mb-3">Live Scanner Log</h2>
    <pre id="logs" class="text-xs font-mono bg-black rounded p-3 h-64 overflow-auto"></pre>
  </section>
</main>
<script>
 const TOKEN = {{ token_json|safe }};
 const socket = io("/", {auth: {token: TOKEN}, transports: ["websocket","polling"]});
 function esc(s){return String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}
 socket.on("connect_error", () => appendLog("error","socket auth failed - reload with ?token=..."));
 socket.on("log_line", l => appendLog(l.level, "["+l.ts+"] "+l.message));
 socket.on("scan_progress", d => {document.getElementById("progBar").style.width=d.progress+"%";
   document.getElementById("progText").textContent="scanning... "+d.progress+"%";});
 socket.on("scan_finished", d => {document.getElementById("progText").textContent="complete";
   renderScan(d.report); refreshState();});
 socket.on("avb_updated", d => {const el=document.getElementById("scanSummary");
   el.innerHTML += "<div>AVB state: <b>"+esc(d.avb.avb.state)+"</b> &middot; rollback ok: "+
     (d.avb.rollback.monotonic_ok?"yes":"NO")+"</div>";});
 function appendLog(level,msg){const pre=document.getElementById("logs");
   const color=level==="error"?"text-red-400":(level==="warn"?"text-amber-400":"text-slate-300");
   pre.innerHTML += '<span class="'+color+'">'+esc(msg)+"</span>\\n"; pre.scrollTop=pre.scrollHeight;}
 function startScan(){fetch("/api/scan",{method:"POST",headers:{"X-Auth-Token":TOKEN},
   body:JSON.stringify({})}).then(r=>{if(r.status==401)alert("unauthorized");
   document.getElementById("progText").textContent="queued...";});}
 function runAvb(){fetch("/api/avb",{method:"POST",headers:{"X-Auth-Token":TOKEN}});}
 function genReport(){window.open("/api/report.html?token="+encodeURIComponent(TOKEN),"_blank");}
 function renderScan(rep){const s=rep.summary||{};
   document.getElementById("scanSummary").innerHTML =
     "<div>targets: "+(rep.targets||[]).length+" &middot; scanned: "+(s.scanned!==undefined?s.scanned:(rep.targets||[]).length)+
     " &middot; denied: "+(s.denied!==undefined?s.denied:"-")+" &middot; signature hits: "+(s.signature_hits!==undefined?s.signature_hits:"-")+
     " &middot; high-entropy regions: "+(s.high_entropy_regions!==undefined?s.high_entropy_regions:"-")+"</div>";}
 async function refreshState(){
   const r=await fetch("/api/state",{headers:{"X-Auth-Token":TOKEN}});
   if(!r.ok)return; const d=await r.json();
   const info=[]; const p=d.platform||{};
   info.push(["Host OS", (p.os||"-")+" "+(p.release||"")]);
   info.push(["Machine", p.machine||"-"]);
   info.push(["Kernel (lab host)", d.kernel_release||"-"]);
   info.push(["Android SPL", d.security_patch||"- (lab host)"]);
   info.push(["psutil", p.psutil_available?"available":"missing"]);
   document.getElementById("deviceInfo").innerHTML =
     info.map(([k,v])=>"<div><span class='text-slate-500'>"+esc(k)+":</span> "+esc(v)+"</div>").join("");
   if(d.last_prediction){const pr=d.last_prediction;
     document.getElementById("aiBox").innerHTML =
       "<div class='text-lg font-bold'>"+esc(pr.prediction)+"</div>"+
       "<div class='text-xs text-slate-400'>confidence "+((pr.confidence||0)*100).toFixed(1)+"%</div>"+
       Object.entries(pr.class_probabilities||{}).map(([k,v])=>
         "<div class='flex items-center gap-2 mt-1'><span class='w-40 text-xs'>"+esc(k)+
         "</span><div class='flex-1 bg-slate-800 h-2 rounded'><div class='bg-fuchsia-500 h-2 rounded' style='width:"+
         (v*100).toFixed(0)+"%'></div></div><span class='text-xs'>"+(v*100).toFixed(0)+"%</span></div>").join("")+
       "<div class='text-[10px] text-slate-500 mt-2'>"+esc(pr.advisory||"")+"</div>";}
   if(d.last_scan) renderScan(d.last_scan);
   if(d.last_avb){const el=document.getElementById("scanSummary");
     el.innerHTML += "<div>AVB last: <b>"+esc(d.last_avb.avb.state)+
       "</b> &middot; rollback monotonic: "+(d.last_avb.rollback.monotonic_ok?"yes":"NO")+"</div>";}
   for(const l of (d.logs||[])) appendLog(l.level, "["+l.ts+"] "+l.message);}
 refreshState();
</script></body></html>"""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if token_matches(request.form.get("token", "")):
            session[TOKEN_SESSION_KEY] = True
            return redirect("/")
        error = "Invalid token."
    if check_auth_or_none():
        return redirect("/")
    return render_template_string(LOGIN_HTML, error=error)


@app.route("/")
@require_auth
def index():
    return render_template_string(DASH_HTML,
                                  token_json=json.dumps(AUTH_TOKEN))


@app.route("/api/state")
@require_auth
def api_state():
    platform_notes = msa.get_platform_notes() if msa else {
        "os": platform.system(), "release": platform.release(),
        "machine": platform.machine(), "psutil_available": False}
    spl = ""
    if app_mod is not None:
        try:
            props = {}
            override = os.environ.get("KX_PROP_OVERRIDE_FILE")
            if override and os.path.isfile(override):
                with open(override, "r", encoding="utf-8") as fh:
                    for line in fh:
                        if "=" in line and not line.startswith("#"):
                            k, v = line.split("=", 1)
                            props[k.strip()] = v.strip()
            spl = props.get("ro.build.version.security_patch", "")
        except OSError:
            pass
    with LOG_LOCK:
        logs = list(LOG_BUFFER)[-50:]
    return jsonify({
        "running": STATE["scan_running"],
        "progress": STATE["progress"],
        "platform": platform_notes,
        "kernel_release": platform_notes.get("release", ""),
        "security_patch": spl,
        "last_scan": STATE["last_scan"],
        "last_prediction": STATE["last_prediction"],
        "last_avb": STATE["last_avb"],
        "logs": logs,
        "started_utc": STATE["started_utc"],
    })


@app.route("/api/scan", methods=["POST"])
@require_auth
def api_scan():
    if STATE["scan_running"]:
        return jsonify({"status": "busy"}), 409
    body = request.get_json(silent=True) or {}
    pid = body.get("pid")
    if pid is not None:
        try:
            pid = int(pid)
            if pid <= 0 or pid > 0x7FFFFF:
                raise ValueError
        except (TypeError, ValueError):
            return jsonify({"status": "invalid pid"}), 400
    t = threading.Thread(target=run_scan_job, args=(pid,), daemon=True)
    t.start()
    return jsonify({"status": "started"})


@app.route("/api/avb", methods=["POST"])
@require_auth
def api_avb():
    t = threading.Thread(target=run_avb_job, daemon=True)
    t.start()
    return jsonify({"status": "started"})


@app.route("/api/report.html")
@require_auth
def api_report_html():
    """Static, printable HTML export (browser Print -> Save as PDF)."""
    scan = STATE.get("last_scan") or {}
    pred = STATE.get("last_prediction") or {}
    avb = STATE.get("last_avb") or {}
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    rows = []
    for tgt in scan.get("targets", []):
        rows.append(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                tgt.get("pid"), tgt.get("process_name"), tgt.get("status"),
                tgt.get("bytes_scanned"), len(tgt.get("signature_hits", []))))
    findings = "".join(
        "<li><b>%s</b> %s: %s</li>" % (f.get("severity", ""),
                                       f.get("code", ""), f.get("detail", ""))
        for f in avb.get("findings", []))
    html = f"""<!doctype html><html><head><meta charset="utf-8">
<title>Kernel-X Lab Report {ts}</title>
<style>body{{font-family:sans-serif;margin:2em;color:#111}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:6px;font-size:13px}}
h1{{color:#0e7490}} .muted{{color:#666}}</style></head><body>
<h1>Kernel-X Educational Forensics Report</h1>
<p class="muted">Generated {ts} &middot; localhost lab &middot; read-only analysis &middot; no raw memory exported</p>
<h2>AI Exposure Prediction</h2>
<pre>{json.dumps(pred, indent=2)}</pre>
<h2>Memory Scan Targets</h2>
<table><tr><th>PID</th><th>Process</th><th>Status</th><th>Bytes observed</th><th>Signature hits</th></tr>
{''.join(rows) or '<tr><td colspan=5>no scans yet</td></tr>'}</table>
<h2>AVB Findings</h2><ul>{findings or '<li>none</li>'}</ul>
<p class="muted">For remediation guidance refer to AOSP Verified Boot and
Keystore documentation. This report intentionally contains no key material.</p>
</body></html>"""
    return Response(html, mimetype="text/html")


# ---------------------------------------------------------------------------
# WebSocket events
# ---------------------------------------------------------------------------

@socketio.on("connect")
def ws_connect(auth=None):
    token = ""
    if isinstance(auth, dict):
        token = str(auth.get("token", ""))
    if not token:
        token = str(request.args.get("token", "") if request.args else "")
    if not token_matches(token):
        push_log("warn", "WebSocket connection refused (bad token)")
        return False
    emit("hello", {"ok": True, "since": STATE["started_utc"]})


@socketio.on("ping")
def ws_ping():
    emit("pong", {"t": time.time()})


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def enforce_localhost(host: str) -> str:
    if host != BIND_HOST:
        print(f"[!] Refusing to bind to {host!r}: this dashboard is "
              f"localhost-only by design. Using {BIND_HOST}.", file=sys.stderr)
    return BIND_HOST


def main(argv: Optional[List[str]] = None) -> int:
    global AUTH_TOKEN
    parser = argparse.ArgumentParser(description="Localhost-only lab dashboard")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    sink = _SocketIOSink()
    sink.setLevel(logging.INFO)
    sink.setFormatter(logging.Formatter("%(name)s: %(message)s"))
    logging.getLogger().addHandler(sink)

    AUTH_TOKEN = issue_token()
    host = enforce_localhost(BIND_HOST)

    banner = (
        "\n=================================================\n"
        "  Kernel-X Lab Dashboard (EDUCATIONAL, LOCAL ONLY)\n"
        f"  URL   : http://{host}:{args.port}/\n"
        f"  TOKEN : {AUTH_TOKEN}\n"
        "  (keep this terminal private; token shown once)\n"
        "=================================================\n")
    print(banner)
    push_log("info", "dashboard starting; all scanner backends are read-only")

    try:
        # This is a LOCALHOST-ONLY lab server; the Werkzeug dev server is the
        # intended (and only reachable) stack. allow_unsafe_werkzeug is set
        # deliberately - the bind address is hardcoded to 127.0.0.1 above and
        # there is no code path that exposes it on any other interface.
        socketio.run(app, host=host, port=args.port, debug=False,
                     allow_unsafe_werkzeug=True, use_reloader=False)
    except OSError as exc:
        print(f"[!] could not start server: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
