"""
kernel_x.tui_dashboard
======================

Live Risk Heatmap Dashboard — Termux TUI
========================================

A terminal UI (curses, standard library only) for the Kernel-X risk engine,
designed to run on Android/Termux where no browser or Flutter stack is
available.  It renders:

1. Device fingerprint (compact key/value table)
2. Live risk heatmap — subsystem contribution bars with severity colouring
3. Top findings register (CVE, status, contribution, confidence)
4. Simulated scenario timeline (keystore/FBE dry-run outcomes)
5. Plugin manifest and per-hook status

Controls
--------
q           quit
r           re-run the full analysis pipeline (refresh)
1-5         switch view (overview / heatmap / findings / timeline / plugins)
? / h       help

The TUI reads the same dashboard state as :mod:`kernel_x.dashboard`
(``DashboardController``), so web and terminal views show identical numbers.
"""

from __future__ import annotations

import curses
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .dashboard import DashboardController
from .risk_engine import severity_band

logger = logging.getLogger("kernel_x.tui_dashboard")

VIEW_OVERVIEW, VIEW_HEATMAP, VIEW_FINDINGS, VIEW_TIMELINE, VIEW_PLUGINS = range(5)
VIEW_NAMES = {
    VIEW_OVERVIEW: "OVERVIEW",
    VIEW_HEATMAP: "RISK HEATMAP",
    VIEW_FINDINGS: "FINDINGS",
    VIEW_TIMELINE: "SIMULATION TIMELINE",
    VIEW_PLUGINS: "PLUGINS",
}

SEVERITY_COLORS = {
    "INFORMATIONAL": 4,  # blue
    "LOW": 2,            # green
    "MODERATE": 3,       # yellow
    "ELEVATED": 3,
    "HIGH": 1,           # red
    "CRITICAL": 1,
}


def _severity_curses_color(severity: str) -> int:
    return SEVERITY_COLORS.get(severity.upper(), 6)


class TuiDashboard:
    """Curses-driven live dashboard."""

    def __init__(self, controller: DashboardController, refresh_s: float = 5.0) -> None:
        self.controller = controller
        self.refresh_s = max(1.0, float(refresh_s))
        self.view = VIEW_OVERVIEW
        self.running = True
        self.status_msg: str = ""
        self.status_error: bool = False

    # ------------------------------------------------------------------ run

    def run(self, stdscr) -> int:
        curses.curs_set(0)                 # hide cursor
        stdscr.nodelay(True)               # non-blocking input
        stdscr.timeout(100)                # 100 ms input poll
        self._init_colors(stdscr)

        last_refresh = 0.0
        self._ensure_session(stdscr)

        while self.running:
            now = time_monotonic()
            if now - last_refresh >= self.refresh_s:
                self._ensure_session(stdscr)
                last_refresh = now

            self._draw(stdscr)
            try:
                ch = stdscr.getch()
            except curses.error:
                ch = -1
            if ch != -1:
                self._handle_input(ch, stdscr)

        return 0

    # --------------------------------------------------------------- session

    def _ensure_session(self, stdscr) -> None:
        try:
            self.controller.ensure_session()
            self.status_msg = "session ready"
            self.status_error = False
        except Exception as exc:  # noqa: BLE001 - TUI must stay alive
            logger.error("session build failed: %s", exc)
            self.status_msg = f"session error: {exc}"
            self.status_error = True

    def session(self):
        return self.controller.session

    def view_model(self) -> Dict[str, Any]:
        return self.controller.view_model()

    # --------------------------------------------------------------- drawing

    def _init_colors(self, stdscr) -> None:
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_RED, -1)      # high/critical
        curses.init_pair(2, curses.COLOR_GREEN, -1)    # ok/low
        curses.init_pair(3, curses.COLOR_YELLOW, -1)   # moderate/elevated
        curses.init_pair(4, curses.COLOR_BLUE, -1)     # informational
        curses.init_pair(5, curses.COLOR_CYAN, -1)     # headers
        curses.init_pair(6, curses.COLOR_WHITE, -1)    # default

    def _draw(self, stdscr) -> None:
        stdscr.erase()
        height, width = stdscr.getmaxyx()
        self._draw_header(stdscr, width)
        body_top = 3
        if self.view == VIEW_OVERVIEW:
            self._draw_overview(stdscr, body_top, height, width)
        elif self.view == VIEW_HEATMAP:
            self._draw_heatmap(stdscr, body_top, height, width)
        elif self.view == VIEW_FINDINGS:
            self._draw_findings(stdscr, body_top, height, width)
        elif self.view == VIEW_TIMELINE:
            self._draw_timeline(stdscr, body_top, height, width)
        elif self.view == VIEW_PLUGINS:
            self._draw_plugins(stdscr, body_top, height, width)
        self._draw_footer(stdscr, height, width)
        stdscr.noutrefresh()
        curses.doupdate()

    def _draw_header(self, stdscr, width: int) -> None:
        stdscr.addnstr(0, 0, " " * width, width - 1, curses.color_pair(5) | curses.A_BOLD)
        title = " Kernel-X Research Toolkit — Live Risk Heatmap "
        stdscr.addnstr(0, max(0, (width - len(title)) // 2), title, width - 1,
                       curses.color_pair(5) | curses.A_BOLD)
        model = self.view_model()
        risk = model.get("risk_score", 0.0)
        severity = model.get("severity", "N/A")
        line = f"session: {model.get('session_id','-')}  risk: {risk}/10  [{severity}]"
        col = _severity_curses_color(severity)
        stdscr.addnstr(1, 2, line[: width - 4], width - 4,
                       curses.color_pair(col) | curses.A_BOLD)
        if self.status_msg:
            style = curses.color_pair(1) if self.status_error else curses.color_pair(2)
            stdscr.addnstr(1, width - len(self.status_msg) - 2,
                           self.status_msg[: width - 4], width - 4, style)

    def _draw_footer(self, stdscr, height: int, width: int) -> None:
        help_text = "q=quit  r=refresh  1-5=view"
        stdscr.addnstr(height - 1, 2, help_text[: width - 4], width - 4)
        view_indicator = f"view: {VIEW_NAMES[self.view]}"
        stdscr.addnstr(height - 1, width - len(view_indicator) - 2,
                       view_indicator[: width - 4], width - 4)

    # -- views ----------------------------------------------------------------

    def _draw_overview(self, stdscr, top: int, height: int, width: int) -> None:
        model = self.view_model()
        y = top
        stdscr.addnstr(y, 2, "Device fingerprint", width - 4,
                       curses.color_pair(5) | curses.A_BOLD)
        y += 1
        for name, value in model.get("fingerprint_rows", [])[:10]:
            line = f"  {name}: {value}"
            stdscr.addnstr(y, 2, line[: width - 4], width - 4)
            y += 1
        y += 1
        stdscr.addnstr(y, 2, "Summary", width - 4,
                       curses.color_pair(5) | curses.A_BOLD)
        y += 1
        summary = [
            ("risk_score", f"{model.get('risk_score', 0)}/10"),
            ("severity", model.get("severity", "N/A")),
            ("plugins", str(len(model.get("plugins", [])))),
            ("top_findings", str(len(model.get("top_findings", [])))),
        ]
        for name, value in summary:
            line = f"  {name}: {value}"
            stdscr.addnstr(y, 2, line[: width - 4], width - 4)
            y += 1

    def _draw_heatmap(self, stdscr, top: int, height: int, width: int) -> None:
        model = self.view_model()
        stdscr.addnstr(top, 2, "Subsystem exposure heatmap (contribution / 10)",
                       width - 4, curses.color_pair(5) | curses.A_BOLD)
        y = top + 1
        cells = model.get("heat_cells", [])
        if not cells:
            stdscr.addnstr(y, 2, "  no subsystem contributions", width - 4)
            return
        bar_w = max(10, min(40, width // 3))
        for name, value, color in cells:
            if y >= height - 1:
                break
            filled = int(round(max(0.0, min(10.0, value)) / 10.0 * bar_w))
            bar = "#" * filled + "." * (bar_w - filled)
            col = _severity_curses_color(severity_band(value))
            stdscr.addnstr(y, 2, f"  {name:<24}".encode()[: width - 4], width - 4,
                           curses.A_BOLD)
            stdscr.addnstr(y, 28, f"[{bar}] {value:.2f}".encode()[: width - 32],
                           width - 32, curses.color_pair(col) | curses.A_BOLD)
            y += 1

    def _draw_findings(self, stdscr, top: int, height: int, width: int) -> None:
        model = self.view_model()
        stdscr.addnstr(top, 2, "Top findings register", width - 4,
                       curses.color_pair(5) | curses.A_BOLD)
        y = top + 1
        header = f"  {'CVE':<16} {'Status':<14} {'Contrib':>8} {'Conf':>6}"
        stdscr.addnstr(y, 2, header[: width - 4], width - 4)
        y += 1
        for finding in model.get("top_findings", [])[: (height - top - 3)]:
            if y >= height - 1:
                break
            line = (f"  {str(finding.get('cve_id','')):<16} "
                    f"{str(finding.get('status','')):<14} "
                    f"{finding.get('contribution',0):>8.2f} "
                    f"{finding.get('confidence',0):>6.2f}")
            stdscr.addnstr(y, 2, line[: width - 4], width - 4)
            y += 1

    def _draw_timeline(self, stdscr, top: int, height: int, width: int) -> None:
        model = self.view_model()
        stdscr.addnstr(top, 2, "Simulated scenario timeline", width - 4,
                       curses.color_pair(5) | curses.A_BOLD)
        y = top + 1
        for scenario in model.get("scenarios", [])[:3]:
            if y >= height - 1:
                break
            passed = scenario.get("passed", False)
            stdscr.addnstr(y, 2, f"  {scenario.get('name','')} — "
                                 f"{'PASS' if passed else 'FAIL'}",
                           width - 4, curses.color_pair(2 if passed else 1) | curses.A_BOLD)
            y += 1
            for event in scenario.get("events", [])[: (height - y - 1)]:
                if y >= height - 1:
                    break
                line = (f"    t+{event.get('t_offset',0):.3f}s [{event.get('outcome','')}] "
                        f"{event.get('actor','')} {event.get('action','')}")
                stdscr.addnstr(y, 2, line[: width - 4], width - 4)
                y += 1
            y += 1

    def _draw_plugins(self, stdscr, top: int, height: int, width: int) -> None:
        model = self.view_model()
        stdscr.addnstr(top, 2, "Plugin manifest", width - 4,
                       curses.color_pair(5) | curses.A_BOLD)
        y = top + 1
        header = f"  {'Plugin':<26} {'Version':<12} {'State':<14}"
        stdscr.addnstr(y, 2, header[: width - 4], width - 4)
        y += 1
        for plugin in model.get("plugins", [])[: (height - top - 3)]:
            if y >= height - 1:
                break
            line = (f"  {str(plugin.get('name','')):<26} "
                    f"{str(plugin.get('version','')):<12} "
                    f"{str(plugin.get('state','')):<14}")
            stdscr.addnstr(y, 2, line[: width - 4], width - 4)
            y += 1

    # -- input ----------------------------------------------------------------

    def _handle_input(self, ch: int, stdscr) -> None:
        if ch in (ord("q"), ord("Q"), 3):          # q or Ctrl-C
            self.running = False
        elif ch in (ord("r"), ord("R")):
            self._ensure_session(stdscr)
        elif ch in (ord("1"),):
            self.view = VIEW_OVERVIEW
        elif ch in (ord("2"),):
            self.view = VIEW_HEATMAP
        elif ch in (ord("3"),):
            self.view = VIEW_FINDINGS
        elif ch in (ord("4"),):
            self.view = VIEW_TIMELINE
        elif ch in (ord("5"),):
            self.view = VIEW_PLUGINS
        elif ch in (ord("?"), ord("h"), ord("H")):
            self.status_msg = "help: q quit · r refresh · 1-5 switch view"


def time_monotonic() -> float:
    import time
    return time.monotonic()


def main(argv=None) -> int:
    import argparse
    import time as _time  # noqa: F401  (kept for clarity)

    parser = argparse.ArgumentParser(
        description="Kernel-X Termux TUI — live risk heatmap dashboard"
    )
    parser.add_argument("--refresh", type=float, default=5.0,
                        help="auto-refresh interval in seconds")
    parser.add_argument("--report-dir", default="reports")
    parser.add_argument("--sysroot", default=None,
                        help="audit an Android filesystem snapshot statically")
    parser.add_argument("--mock-props", default=None,
                        help="JSON file of lab properties (emulator mode)")
    args = parser.parse_args(argv)

    import json
    mock_props = None
    if args.mock_props:
        try:
            with open(args.mock_props, "r", encoding="utf-8") as handle:
                mock_props = {str(k): str(v) for k, v in json.load(handle).items()}
        except (OSError, json.JSONDecodeError) as exc:
            parser.error(f"cannot read --mock-props: {exc}")

    controller = DashboardController(
        mock_properties=mock_props, sysroot=args.sysroot,
        report_dir=args.report_dir,
    )
    app = TuiDashboard(controller, refresh_s=args.refresh)
    try:
        return curses.wrapper(app.run)
    except ImportError:  # pragma: no cover - no curses (e.g. minimal Windows)
        print("curses is not available on this platform; use the web dashboard instead")
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
