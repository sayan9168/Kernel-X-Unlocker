#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
visualizer_dashboard.py
=======================

Kernel-X Unlocker - Educational Security Suite
MODULE 1: PyQt6 desktop dashboard for the local forensic lab.

This is a native GUI client for ``remote_dashboard.py`` (the localhost-only
Flask + Socket.IO lab server). It renders four live views:

  1. Hex Viewer widget   - classic Offset | Hex | ASCII dump of memory
                           samples streamed by the read-only scanner.
  2. Live Memory Map     - PID / process / start-end address / permissions,
                           refreshed on every scan (``scan_finished`` event).
  3. AI Prediction Graph - matplotlib canvas embedded in Qt plotting the
                           vulnerability probability score over time.
  4. Event log           - mirrors the server-side ``log_line`` stream.

Transport
---------
The server speaks **Socket.IO** (Engine.IO v4) rather than raw WebSocket
frames, so the client implements the minimal subset of that protocol it
needs on top of the standard library (``http.client`` + manual frame
parsing). This keeps the dependency surface tiny and works identically on
Arch Linux and Termux. The handshake is:

    GET /socket.io/?EIO=4&transport=websocket          (upgrade request)
    <- 0{"sid":"..."}                                  (open packet)
    -> 40{"token": "..."}                              (namespace connect)
    <- 42["hello", {...}]                              (event frames)

Authentication uses the same one-time token as the web UI; pass it with
``--token`` or export ``KX_DASHBOARD_TOKEN`` before launching the server.

Stability engineering
---------------------
* All network I/O runs inside a ``QThread`` (``SocketIoWorker``); the GUI
  thread never touches sockets. Communication is via Qt signals only, which
  are queued safely across threads.
* Connection drops are handled gracefully: exponential back-off reconnect
  (1 s .. 30 s), stale-data banner, and a status pill in the header.
* Every JSON payload is schema-checked defensively - a malformed frame can
  at worst drop one update, never crash the UI.

Safety posture
--------------
Read-only. This program displays data produced by the forensic scanner; it
has no capability to write process memory, flash partitions or inject code.
Authorized laboratory use on owned devices only.

Usage
-----
    python visualizer_dashboard.py --url ws://127.0.0.1:5013/socket.io/ \
        --token <one-time-token-printed-by-server>

Dependencies: PyQt6, matplotlib (with the Qt5Agg/QtAgg backend).
"""

from __future__ import annotations

import argparse
import base64
import http.client
import json
import logging
import os
import re
import socket as _socket
import ssl
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Deque, Dict, List, Optional, Tuple

try:
    from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
    from PyQt6.QtGui import QColor, QFont, QPalette
    from PyQt6.QtWidgets import (QAbstractItemView, QApplication, QFrame,
                                 QGridLayout, QHeaderView, QHBoxLayout, QLabel,
                                 QMainWindow, QPushButton, QSizePolicy,
                                 QSplitter, QTableWidget, QTableWidgetItem,
                                 QTextEdit, QVBoxLayout, QWidget)
except ImportError as exc:  # pragma: no cover - environment guidance
    sys.stderr.write(
        "[!] PyQt6 is required:  pip install PyQt6\n"
        f"    (import error: {exc})\n")
    raise SystemExit(2)

# matplotlib *must* have its backend selected before pyplot/canvas import.
import matplotlib

matplotlib.use("QtAgg")
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg  # noqa: E402
from matplotlib.figure import Figure  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402  (rcParams only)

plt.rcParams.update({"font.size": 8, "axes.grid": True,
                     "grid.alpha": 0.25, "figure.facecolor": "#0f172a",
                     "axes.facecolor": "#0f172a", "axes.edgecolor": "#334155",
                     "text.color": "#cbd5e1", "axes.labelcolor": "#cbd5e1",
                     "xtick.color": "#94a3b8", "ytick.color": "#94a3b8"})

logger = logging.getLogger("kx.visualizer")

DEFAULT_URL = "ws://127.0.0.1:5013/socket.io/"
RECONNECT_MIN_S, RECONNECT_MAX_S = 1.0, 30.0
BYTES_PER_HEX_ROW = 16
MAX_HEX_ROWS = 4096            # hard cap so a huge dump cannot eat RAM
MAX_GRAPH_POINTS = 240         # rolling window for the AI plot


# ===========================================================================
# Section 1 - Socket.IO (Engine.IO v4) minimal client
# ===========================================================================

@dataclass
class EngineConfig:
    """Server-advertised tuning values from the `0{...}` open packet."""
    ping_interval: float = 25.0
    ping_timeout: float = 60.0
    max_payload: int = 1_000_000


class SocketIoError(RuntimeError):
    """Raised for protocol-level failures (bad frame, refused namespace)."""


def split_frames(buffer: str) -> Tuple[List[str], str]:
    """Extract complete Engine.IO text frames from ``buffer``.

    Engine.IO v4 may coalesce several packets into one WS message separated
    by \\x1e (RS). Returns (complete_frames, remaining_buffer); the remainder
    is empty when the buffer ended on a frame boundary.
    """
    parts = buffer.split("\x1e")
    if len(parts) == 1:
        return [parts[0]], ""
    return parts[:-1], parts[-1]


class SocketIoClient:
    """Blocking Socket.IO-over-WebSocket client (runs inside a worker thread).

    Only what the lab server needs is implemented: websocket transport,
    auth-payload namespace connection, event reception and ``ping`` emission.
    """

    def __init__(self, url: str, token: str, timeout: float = 8.0):
        self.url = url
        self.token = token
        self.timeout = timeout
        self.cfg = EngineConfig()
        self._sock: Optional[_socket.socket] = None
        self._recv_buf = b""
        self._frame_buf = ""
        self._stop = threading.Event()
        self._send_lock = threading.Lock()
        self.sid: Optional[str] = None
        # Callbacks are installed by the QThread wrapper.
        self.on_event = lambda name, data: None
        self.on_log = lambda level, msg: None
        self.on_status = lambda connected: None

    # -- low-level websocket ------------------------------------------------

    def _ws_send(self, payload: bytes, opcode: int = 0x82) -> None:
        """Send one masked client->server frame (RFC 6455 requires masking)."""
        if self._sock is None:
            raise SocketIoError("socket closed")
        header = bytearray([0x80 | opcode])
        n = len(payload)
        # RFC 6455 only demands a nonzero client mask key; a fixed one is
        # acceptable for this localhost-only lab transport.
        mask_key = b"\x25\x4e\x3c\x7f"
        if n < 126:
            header.append(0x80 | n)
        elif n < (1 << 16):
            header.append(0x80 | 126)
            header += n.to_bytes(2, "big")
        else:
            header.append(0x80 | 127)
            header += n.to_bytes(8, "big")
        masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
        with self._send_lock:
            self._sock.sendall(bytes(header) + mask_key + masked)

    def _recv_exact(self, n: int) -> bytes:
        assert self._sock is not None
        while len(self._recv_buf) < n:
            chunk = self._sock.recv(65536)
            if not chunk:
                raise SocketIoError("connection closed by peer")
            self._recv_buf += chunk
        out, self._recv_buf = self._recv_buf[:n], self._recv_buf[n:]
        return out

    def _ws_recv_frame(self) -> Tuple[int, bytes]:
        """Read one server frame; transparently answers server pings."""
        while True:
            b0, b1 = self._recv_exact(2)
            opcode = b0 & 0x0F
            length = b1 & 0x7F
            if length == 126:
                length = int.from_bytes(self._recv_exact(2), "big")
            elif length == 127:
                length = int.from_bytes(self._recv_exact(8), "big")
            if length > self.cfg.max_payload:
                raise SocketIoError(f"oversized frame ({length} bytes)")
            payload = self._recv_exact(length) if length else b""
            if opcode == 0x9:            # ping -> pong
                self._ws_send(payload, opcode=0xA)
                continue
            if opcode == 0x8:            # close
                raise SocketIoError("server sent WS close frame")
            if opcode in (0x1, 0x2):
                return opcode, payload
            # continuation/rare opcodes: ignore defensively
            logger.debug("ignoring ws opcode 0x%x", opcode)

    # -- engine.io / socket.io layer ----------------------------------------

    def _handshake(self) -> None:
        parsed = re.match(r"(wss?)://([^/]+)(/.*)?$", self.url)
        if not parsed:
            raise SocketIoError(f"invalid websocket URL: {self.url}")
        scheme, hostport, path = parsed.group(1), parsed.group(2), \
            parsed.group(3) or "/socket.io/"
        host, _, port_s = hostport.partition(":")
        port = int(port_s or (443 if scheme == "wss" else 80))
        ctx: Optional[ssl.SSLContext] = None
        if scheme == "wss":
            ctx = ssl.create_default_context()
        self._sock = _socket.create_connection((host, port), self.timeout)
        if ctx is not None:
            self._sock = ctx.wrap_socket(self._sock, server_hostname=host)

        key = base64.b64encode(_socket.inet_aton("127.0.0.1")).decode()
        req = (f"GET {path}?EIO=4&transport=websocket HTTP/1.1\r\n"
               f"Host: {host}:{port}\r\nUpgrade: websocket\r\n"
               f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
               f"Sec-WebSocket-Version: 13\r\n\r\n")
        self._sock.sendall(req.encode())

        # Consume HTTP response headers byte-by-byte so we never swallow the
        # first websocket frame that follows them.
        hdr = b""
        while not hdr.endswith(b"\r\n\r\n"):
            b = self._sock.recv(1)
            if not b:
                raise SocketIoError("HTTP upgrade failed (EOF in headers)")
            hdr += b
        status_line = hdr.split(b"\r\n", 1)[0].decode(errors="replace")
        if "101" not in status_line:
            raise SocketIoError(f"expected '101 Switching Protocols', got "
                                f"{status_line!r} - is the server Socket.IO?")

        # First Engine.IO packet must be `0{"sid":..,"pingInterval":..}`
        _, payload = self._ws_recv_frame()
        text = payload.decode("utf-8", "replace")
        frames, self._frame_buf = split_frames(text)
        if not frames:
            raise SocketIoError("no open packet received")
        pkt = frames[0]
        if not pkt.startswith("0"):
            raise SocketIoError(f"unexpected first packet {pkt[:20]!r}")
        try:
            info = json.loads(pkt[1:])
            self.cfg.ping_interval = float(info.get("pingInterval", 25000)) / 1000
            self.cfg.ping_timeout = float(info.get("pingTimeout", 60000)) / 1000
            self.cfg.max_payload = int(info.get("maxPayload", 1_000_000))
            self.sid = info.get("sid")
        except (ValueError, TypeError) as exc:
            raise SocketIoError(f"malformed open packet: {exc}") from exc

        # Namespace connect with auth token: packet type 40 + JSON object.
        self._ws_send(b'40{"token":"' + self.token.encode() + b'"}')

        # The server answers with CONNECT_ACK (`40{"sid":...}`) or, on a bad
        # token, with a DISCONNECT frame (`44{...}`). Read exactly one more
        # frame here so an immediate rejection surfaces during the handshake
        # instead of masquerading as a successful connection.
        _, payload = self._ws_recv_frame()
        text = payload.decode("utf-8", "replace")
        frames, self._frame_buf = split_frames(self._frame_buf + text)
        for pkt in frames:
            if not pkt:
                continue
            if pkt.startswith("44"):           # DISCONNECT (namespace refused)
                raise SocketIoError("server disconnected the namespace "
                                    "(bad token?)")
            if pkt.startswith("40"):           # CONNECT_ACK -> note the sid
                try:
                    ack = json.loads(pkt[1:])
                    if isinstance(ack, dict) and "sid" in ack:
                        self.sid = str(ack["sid"])
                except ValueError:
                    pass                       # ack is optional; ignore noise

    def _consume_netstring(self, s: str, pos: int) -> Tuple[str, int]:
        """Parse Socket.IO v5 binary netstrings ('<len>-<bytes>')."""
        m = re.match(r"(\d+)-", s[pos:])
        if not m:
            raise SocketIoError("malformed netstring attachment")
        n = int(m.group(1))
        start = pos + m.end()
        return s[start:start + n], start + n

    def _dispatch_text(self, text: str) -> None:
        frames, self._frame_buf = split_frames(self._frame_buf + text)
        for pkt in frames:
            if not pkt:
                continue
            t, rest = pkt[0], pkt[1:]
            if t == "2":                       # engine ping -> engine pong
                self._ws_send(b"3")
            elif t == "6":                     # engine error (namespace refused)
                raise SocketIoError(f"engine.io error: {rest[:120]}")
            elif t == "4":                     # socket.io packet
                if rest.startswith("44"):      # DISCONNECT (namespace refused)
                    raise SocketIoError("server disconnected the namespace "
                                        "(bad token?)")
                if rest.startswith("4"):       # CONNECT_ACK -> note the sid
                    try:
                        ack = json.loads(rest[1:])
                        if isinstance(ack, dict) and "sid" in ack:
                            self.sid = str(ack["sid"])
                    except ValueError:
                        pass                   # ack is optional; ignore noise
                    continue
                if rest.startswith("2"):       # EVENT
                    body = rest[1:]
                    try:
                        if body.startswith("["):
                            arr = json.loads(body)
                        else:                  # binary ack format: ["ev",{..},"id"-..]
                            name, pos = self._consume_netstring(body, 1)
                            data_str, _ = self._consume_netstring(body, pos + 1)
                            arr = [json.loads(name), json.loads(data_str)]
                        name, data = arr[0], arr[1] if len(arr) > 1 else {}
                        self.on_event(str(name), data)
                    except (SocketIoError, ValueError, IndexError) as exc:
                        self.on_log("warn", f"dropped malformed frame: {exc}")

    def run(self) -> None:
        """Connect and pump frames until stopped or the link breaks."""
        self._handshake()
        self.on_status(True)
        self.on_log("info", f"connected to {self.url} (sid={self.sid})")
        last_ping = time.monotonic()
        try:
            while not self._stop.is_set():
                # Keepalive: emit a socket.io "ping" *event* periodically; the
                # server answers with a "pong" event, which we simply count as
                # liveness traffic.
                if time.monotonic() - last_ping > min(self.cfg.ping_interval, 20):
                    self._ws_send(b'42["ping"]')
                    last_ping = time.monotonic()
                self._sock.settimeout(max(1.0, self.cfg.ping_timeout / 2))
                try:
                    _, payload = self._ws_recv_frame()
                except _socket.timeout:
                    continue  # nothing arrived; loop re-checks stop flag
                self._dispatch_text(payload.decode("utf-8", "replace"))
        finally:
            self.on_status(False)
            self.close()

    def close(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                with self._send_lock:
                    self._sock.sendall(b"\x88\x80" + b"\x00" * 4)  # masked close
            except OSError:
                pass
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None


# ===========================================================================
# Section 2 - QThread data worker with graceful reconnect
# ===========================================================================

class SocketIoWorker(QThread):
    """Owns the blocking client; exposes parsed events as Qt signals."""

    event_received = pyqtSignal(str, object)      # (name, payload dict)
    status_changed = pyqtSignal(bool)             # connected?
    log_message = pyqtSignal(str, str)            # (level, text)

    def __init__(self, url: str, token: str, parent=None):
        super().__init__(parent)
        self.url, self.token = url, token
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:  # executed on the worker thread
        backoff = RECONNECT_MIN_S
        while not self._stop:
            try:
                client = SocketIoClient(self.url, self.token)
                client.on_event = self._on_event
                client.on_log = self.log_message.emit
                client.on_status = self.status_changed.emit
                client.run()                      # blocks until link breaks
                backoff = RECONNECT_MIN_S          # ran fine -> reset penalty
            except Exception as exc:               # noqa: BLE001 - worker shell
                if self._stop:
                    break
                self.status_changed.emit(False)
                self.log_message.emit(
                    "warn", f"link lost ({exc}); retrying in {backoff:.0f}s")
                # sleep in small slices so Stop clicks feel instant
                deadline = time.monotonic() + backoff
                while time.monotonic() < deadline and not self._stop:
                    time.sleep(0.2)
                backoff = min(backoff * 2, RECONNECT_MAX_S)
        self.log_message.emit("info", "worker thread exiting")

    def _on_event(self, name: str, data: Any) -> None:
        # Defensive: guarantee dict payloads downstream.
        if not isinstance(data, dict):
            data = {"value": data}
        self.event_received.emit(name, data)


# ===========================================================================
# Section 3 - Hex Viewer widget (Offset | Hex | ASCII)
# ===========================================================================

class HexViewer(QWidget):
    """Monospaced hex dump renderer with row-based dirty updates.

    Data arrives either as a full sample dict from the scanner
    (``load_sample``) or as base64 chunks appended progressively
    (``append_chunk``) - matching how ``memory_scanner_advanced`` ships
    bounded, read-only region excerpts.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._data = bytearray()
        self._base_addr = 0
        self.setSizePolicy(QSizePolicy.Policy.Expanding,
                           QSizePolicy.Policy.Expanding)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self._header = QLabel("Offset(h)   " + " ".join(f"{i:02X}" for i in range(16))
                              + "   Decoded")
        self._header.setFont(QFont("monospace", 9))
        self._header.setStyleSheet("color:#7dd3fc; padding:4px;")
        self._view = QTextEdit()
        self._view.setReadOnly(True)
        self._view.setFont(QFont("monospace", 9))
        self._view.setStyleSheet(
            "background:#0b1220; color:#d8e3f0; border:1px solid #1e293b;")
        lay.addWidget(self._header)
        lay.addWidget(self._view)

    # -- public API ----------------------------------------------------------

    def clear_view(self) -> None:
        self._data.clear()
        self._base_addr = 0
        self._view.clear()

    def load_sample(self, addr_hex: str, b64_data: str) -> bool:
        """Load one base64-encoded region excerpt. Returns success."""
        try:
            raw = base64.b64decode(b64_data, validate=True)
            self._base_addr = int(addr_hex, 16)
        except (ValueError, TypeError) as exc:
            logger.warning("bad hex sample (%s); ignoring", exc)
            return False
        self._data = bytearray(raw[:MAX_HEX_ROWS * BYTES_PER_HEX_ROW])
        self._render_all()
        return True

    def append_chunk(self, b64_data: str) -> None:
        """Append decoded bytes and redraw only the new rows."""
        try:
            raw = base64.b64decode(b64_data, validate=True)
        except (ValueError, TypeError):
            return
        start_row = len(self._data) // BYTES_PER_HEX_ROW
        self._data.extend(raw)
        if len(self._data) > MAX_HEX_ROWS * BYTES_PER_HEX_ROW:
            del self._data[:len(self._data) - MAX_HEX_ROWS * BYTES_PER_HEX_ROW]
            start_row = 0
            self._render_all()
            return
        end_row = (len(self._data) + BYTES_PER_HEX_ROW - 1) // BYTES_PER_HEX_ROW
        lines = [self._format_row(r) for r in range(start_row, end_row)]
        cursor = self._view.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        for line in lines:
            cursor.insertText("\n" + line)
        self._view.ensureCursorVisible()

    # -- rendering ------------------------------------------------------------

    @staticmethod
    def _ascii_of(chunk: bytes) -> str:
        return "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)

    def _format_row(self, row: int) -> str:
        off = row * BYTES_PER_HEX_ROW
        chunk = bytes(self._data[off:off + BYTES_PER_HEX_ROW])
        hexpart = " ".join(f"{b:02X}" for b in chunk)
        hexpart += "   " + "   " * (BYTES_PER_HEX_ROW - len(chunk))
        return (f"{self._base_addr + off:016X}  {hexpart}  |"
                f"{self._ascii_of(chunk)}|")

    def _render_all(self) -> None:
        rows = (len(self._data) + BYTES_PER_HEX_ROW - 1) // BYTES_PER_HEX_ROW
        self._view.setPlainText("\n".join(self._format_row(r)
                                          for r in range(rows)))


# ===========================================================================
# Section 4 - Live Memory Map table
# ===========================================================================

class MemoryMapTable(QTableWidget):
    """PID | Process | Start | End | Perms | Path, kept sorted & colored."""

    COLUMNS = ("PID", "Process", "Start Addr", "End Addr", "Perms", "Path")

    def __init__(self, parent=None):
        super().__init__(0, len(self.COLUMNS), parent)
        self.setHorizontalHeaderLabels(self.COLUMNS)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.setAlternatingRowColors(True)
        self.verticalHeader().setVisible(False)
        self.setFont(QFont("monospace", 9))
        hdr = self.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.setStyleSheet("background:#0b1220; color:#d8e3f0;"
                           "gridline-color:#1e293b;")

    def populate(self, targets: List[Dict[str, Any]]) -> None:
        """Rebuild the table from a scan report's per-target region maps."""
        rows: List[Tuple[int, str, str, str, str, str]] = []
        for tgt in targets:
            pid = int(tgt.get("pid", -1))
            name = str(tgt.get("process_name", "?"))
            for reg in tgt.get("region_map", []) or []:
                rows.append((
                    pid, name,
                    str(reg.get("addr_start", "")),
                    str(reg.get("addr_end", "")),
                    str(reg.get("perms", "---")),
                    str(reg.get("path", "")),
                ))
        rows.sort(key=lambda r: (r[0], r[2]))
        self.setRowCount(len(rows))
        for i, row in enumerate(rows):
            for j, value in enumerate(row):
                item = QTableWidgetItem(str(value))
                if j == 4:  # permission coloring: W+X is the scary combo
                    if "w" in value and "x" in value:
                        item.setForeground(QColor("#f87171"))
                    elif "x" in value:
                        item.setForeground(QColor("#facc15"))
                    else:
                        item.setForeground(QColor("#94a3b8"))
                self.setItem(i, j, item)


# ===========================================================================
# Section 5 - AI prediction graph (matplotlib embedded in Qt)
# ===========================================================================

class AIPredictionGraph(QWidget):
    """Rolling line chart of the AI vulnerability probability score.

    Points come from two sources merged on arrival order:
      * ``prediction_updated``-style payloads carrying ``probability`` /
        ``confidence`` from the rule-based predictor, and
      * anomaly scores pushed by ``unsupervised_ai_detector.py --serve``
        (same JSON shape), so the autoencoder feeds the very same plot.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.fig = Figure(figsize=(5, 2.6), dpi=100)
        self.canvas = FigureCanvasQTAgg(self.fig)
        self.ax = self.fig.add_subplot(111)
        self.scores: Deque[float] = deque(maxlen=MAX_GRAPH_POINTS)
        self.labels: Deque[str] = deque(maxlen=MAX_GRAPH_POINTS)
        self.line, = self.ax.plot([], [], lw=1.6, color="#38bdf8")
        self.thresh, = self.ax.plot([], [], "--", lw=1.0, color="#f87171")
        self.ax.set_ylim(-0.02, 1.02)
        self.ax.set_xlim(0, MAX_GRAPH_POINTS)
        self.ax.set_ylabel("vulnerability probability")
        self.ax.set_xlabel("sample #")
        self.ax.set_title("AI exposure / anomaly score (live)",
                          color="#7dd3fc", fontsize=9)
        self.fig.tight_layout(pad=1.2)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.canvas)
        self._pending: List[Tuple[float, str]] = []
        # Coalesce rapid-fire updates into one repaint (~8 fps is plenty).
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._flush)
        self._timer.start(120)

    def add_score(self, score: float, label: str = "") -> None:
        try:
            score = float(score)
        except (TypeError, ValueError):
            return
        self._pending.append((max(0.0, min(1.0, score)), label))

    def _flush(self) -> None:
        if not self._pending:
            return
        for score, label in self._pending:
            self.scores.append(score)
            self.labels.append(label)
        self._pending.clear()
        xs = list(range(len(self.scores)))
        self.line.set_data(xs, list(self.scores))
        self.thresh.set_data(xs, [0.7] * len(xs))
        self.ax.set_xlim(0, max(MAX_GRAPH_POINTS, len(xs) + 1))
        self.canvas.draw_idle()


# ===========================================================================
# Section 6 - Main window wiring everything together
# ===========================================================================

RISK_COLORS = {"LOW": "#4ade80", "MODERATE": "#facc15",
               "HIGH": "#fb923c", "CRITICAL": "#f87171"}


class DashboardWindow(QMainWindow):
    def __init__(self, url: str, token: str):
        super().__init__()
        self._url, self._token = url, token
        self.setWindowTitle("Kernel-X Lab Visualizer  (educational, read-only)")
        self.resize(1280, 800)

        central = QWidget()
        self.setCentralWidget(central)
        grid = QGridLayout(central)

        # --- header row: status pill + risk badge + stop/start -------------
        self.status_pill = QLabel("● offline")
        self.status_pill.setStyleSheet(
            f"color:{'#f87171'}; font-weight:bold; padding:6px;")
        self.risk_badge = QLabel("risk: n/a")
        self.risk_badge.setStyleSheet(
            "color:#94a3b8; font-weight:bold; padding:6px;")
        self.btn_toggle = QPushButton("Reconnect")
        self.btn_toggle.clicked.connect(self._toggle_worker)
        head = QHBoxLayout()
        head.addWidget(self.status_pill)
        head.addStretch(1)
        head.addWidget(self.risk_badge)
        head.addWidget(self.btn_toggle)
        head_w = QWidget()
        head_w.setLayout(head)
        grid.addWidget(head_w, 0, 0, 1, 2)

        # --- left column: hex viewer + memory map ---------------------------
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.hex_viewer = HexViewer()
        self.mem_table = MemoryMapTable()
        splitter.addWidget(self._wrap("Hex Viewer - read-only region excerpt",
                                      self.hex_viewer))
        splitter.addWidget(self._wrap("Live Memory Map", self.mem_table))
        splitter.setSizes([420, 300])
        grid.addWidget(splitter, 1, 0)

        # --- right column: AI graph + event log -----------------------------
        right = QSplitter(Qt.Orientation.Vertical)
        self.ai_graph = AIPredictionGraph()
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont("monospace", 9))
        self.log_view.setStyleSheet("background:#0b1220; color:#a5f3fc;"
                                    "border:1px solid #1e293b;")
        right.addWidget(self._wrap("AI Vulnerability Prediction", self.ai_graph))
        right.addWidget(self._wrap("Event Log", self.log_view))
        right.setSizes([320, 400])
        grid.addWidget(right, 1, 1)
        grid.setColumnStretch(0, 3)
        grid.setColumnStretch(1, 2)

        # --- worker thread ----------------------------------------------------
        # (self._url / self._token were captured at the top of __init__)
        self.worker: Optional[SocketIoWorker] = None
        self._start_worker()

    # -- layout helper ---------------------------------------------------------

    @staticmethod
    def _wrap(title: str, widget: QWidget) -> QFrame:
        frame = QFrame()
        lay = QVBoxLayout(frame)
        label = QLabel(title)
        label.setStyleSheet("color:#7dd3fc; font-weight:bold; padding:2px;")
        lay.addWidget(label)
        lay.addWidget(widget)
        return frame

    # -- worker lifecycle -------------------------------------------------------

    def _start_worker(self) -> None:
        if self.worker is not None and self.worker.isRunning():
            return
        self.worker = SocketIoWorker(self._url, self._token)
        self.worker.event_received.connect(self.on_event)
        self.worker.status_changed.connect(self.on_status)
        self.worker.log_message.connect(self.append_log)
        self.worker.start()

    def _toggle_worker(self) -> None:
        if self.worker is not None and self.worker.isRunning():
            self.worker.stop()
            self.append_log("info", "manual disconnect requested")
        else:
            self._start_worker()

    # -- slots -------------------------------------------------------------------

    def on_status(self, connected: bool) -> None:
        if connected:
            self.status_pill.setText("● live")
            self.status_pill.setStyleSheet(
                "color:#4ade80; font-weight:bold; padding:6px;")
        else:
            self.status_pill.setText("● offline (reconnecting…)")
            self.status_pill.setStyleSheet(
                "color:#f87171; font-weight:bold; padding:6px;")

    def append_log(self, level: str, text: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        color = {"error": "#f87171", "warn": "#facc15"}.get(level, "#94a3b8")
        self.log_view.append(
            f'<span style="color:{color}">[{stamp}] {level:>5}: '
            f'{self._html_escape(text)}</span>')

    @staticmethod
    def _html_escape(s: str) -> str:
        return (str(s).replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;"))

    def on_event(self, name: str, data: Dict[str, Any]) -> None:
        """Single entry point for all server events; each handler is guarded."""
        handlers = {
            "scan_finished": self.handle_scan,
            "prediction_updated": self.handle_prediction,
            "anomaly_score": self.handle_prediction,
            "hex_sample": self.handle_hex,
            "log_line": self.handle_log_event,
            "hello": lambda d: self.append_log(
                "info", f"server hello since {d.get('since', '?')}"),
        }
        handler = handlers.get(name)
        if handler is None:
            logger.debug("unhandled event %r", name)
            return
        try:
            handler(data)
        except Exception as exc:  # noqa: BLE001 - never let UI data kill us
            self.append_log("warn", f"event {name} parse failed: {exc}")

    def handle_log_event(self, data: Dict[str, Any]) -> None:
        self.append_log(str(data.get("level", "info")),
                        str(data.get("message", "")))

    def handle_scan(self, data: Dict[str, Any]) -> None:
        report = data.get("report") or {}
        targets = report.get("targets") or []
        self.mem_table.populate(targets)
        self.append_log("info", f"memory map refreshed from scan "
                                f"({sum(len(t.get('region_map', []) or []) for t in targets)} regions)")
        # Feed the graph with the report-level risk signal if present.
        summary = report.get("summary") or {}
        score = summary.get("risk_score")
        if isinstance(score, (int, float)):
            self.ai_graph.add_score(float(score), "scan")
        # Pull the latest prediction too (cheap REST call, guarded).
        threading.Thread(target=self._fetch_state_snapshot,
                         daemon=True).start()

    def _fetch_state_snapshot(self) -> None:
        """Best-effort GET /api/state for the current AI prediction."""
        try:
            host = self._url.split("//", 1)[-1].split("/", 1)[0]
            h, _, p = host.partition(":")
            conn = http.client.HTTPConnection(h, int(p or 80), timeout=5)
            conn.request("GET", f"/api/state?token={self._token}",
                         headers={"X-Auth-Token": self._token})
            resp = conn.getresponse()
            if resp.status == 200:
                payload = json.loads(resp.read().decode())
                pred = payload.get("last_prediction")
                if isinstance(pred, dict):
                    self._prediction_cache = pred
                    prob = pred.get("probability", pred.get("confidence"))
                    risk = str(pred.get("prediction", "n/a")).upper()
                    if prob is not None:
                        self.ai_graph.add_score(float(prob), "rule-model")
                    self.risk_badge.setText(f"risk: {risk}")
                    self.risk_badge.setStyleSheet(
                        f"color:{RISK_COLORS.get(risk, '#94a3b8')};"
                        "font-weight:bold; padding:6px;")
            conn.close()
        except Exception as exc:  # noqa: BLE001 - snapshot is optional sugar
            logger.debug("state snapshot fetch skipped: %s", exc)

    def handle_prediction(self, data: Dict[str, Any]) -> None:
        prob = data.get("probability", data.get("score"),
                        data.get("confidence"))
        if prob is None:
            return
        label = str(data.get("source", data.get("model", "ai")))
        self.ai_graph.add_score(float(prob), label)
        risk = str(data.get("prediction", data.get("class", ""))).upper()
        if risk:
            self.risk_badge.setText(f"risk: {risk}")
            self.risk_badge.setStyleSheet(
                f"color:{RISK_COLORS.get(risk, '#94a3b8')};"
                "font-weight:bold; padding:6px;")

    def handle_hex(self, data: Dict[str, Any]) -> None:
        if data.get("reset"):
            self.hex_viewer.clear_view()
        addr = str(data.get("addr_start", "0x0"))
        blob = data.get("data_base64", "")
        if blob and not self.hex_viewer.load_sample(addr, blob):
            self.append_log("warn", "hex sample rejected (malformed)")


# ===========================================================================
# Entry point
# ===========================================================================

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Kernel-X PyQt6 lab visualizer (read-only client)")
    parser.add_argument("--url", default=DEFAULT_URL,
                        help="Socket.IO websocket URL of remote_dashboard.py")
    parser.add_argument("--token", default="",
                        help="one-time auth token printed by the server "
                             "(or set KX_DASHBOARD_TOKEN)")
    args = parser.parse_args(argv)

    token = args.token or __import__("os").environ.get(
        "KX_DASHBOARD_TOKEN", "").strip()
    if not token:
        parser.error("auth token required: --token or $KX_DASHBOARD_TOKEN "
                     "(see the banner printed by remote_dashboard.py)")

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    app = QApplication(sys.argv[:1])
    app.setStyle("Fusion")
    dark = QPalette()
    dark.setColor(QPalette.ColorRole.Window, QColor("#0f172a"))
    dark.setColor(QPalette.ColorRole.Base, QColor("#0b1220"))
    dark.setColor(QPalette.ColorRole.Text, QColor("#e2e8f0"))
    app.setPalette(dark)

    win = DashboardWindow(args.url, token)
    win.show()
    ret = app.exec()
    if win.worker is not None:
        win.worker.stop()
        win.worker.wait(3000)
    return ret


if __name__ == "__main__":
    raise SystemExit(main())
