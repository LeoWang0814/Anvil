#!/usr/bin/env python3
from __future__ import annotations

import itertools
import locale
import os
import shutil
import subprocess
import sys
import time
import unicodedata
from typing import Any, Dict, List, Optional, Tuple


def _terminal_width(default: int = 100) -> int:
    return max(40, shutil.get_terminal_size((default, 24)).columns)


def _clip_ascii(text: str, width: int) -> str:
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width <= 3:
        return "." * width
    return text[: width - 3] + "..."


def _decode_console(data: bytes) -> str:
    for enc in ("utf-8", locale.getpreferredencoding(False), "latin-1"):
        try:
            return data.decode(enc)
        except Exception:
            continue
    return data.decode("utf-8", errors="ignore")


def _run_raw(cmd: List[str]) -> Tuple[int, bytes]:
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    p = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=False,
        env=env,
    )
    return p.returncode, p.stdout


def _run_raw_with_spinner(cmd: List[str], message: str) -> Tuple[int, bytes, float]:
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["LANG"] = "C"

    start = time.time()
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=False,
        env=env,
    )
    spinner = itertools.cycle(["|", "/", "-", "\\"])

    while proc.poll() is None:
        elapsed = time.time() - start
        line = f"{message} {next(spinner)} {elapsed:4.1f}s"
        width = _terminal_width()
        line = _clip_ascii(line, width - 1)
        clear = " " * max(0, width - len(line) - 1)
        sys.stdout.write(f"\r{line}{clear}")
        sys.stdout.flush()
        time.sleep(0.12)

    out, _ = proc.communicate()
    duration = time.time() - start
    done_line = _clip_ascii(f"{message} done in {duration:.2f}s", _terminal_width() - 1)
    sys.stdout.write(f"\r{done_line}\n")
    sys.stdout.flush()
    return proc.returncode, out or b"", duration


def _pick_wireless_iface() -> str:
    try:
        with open("/proc/net/wireless", "r", encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()
    except OSError:
        return ""

    for ln in lines[2:]:
        if ":" in ln:
            return ln.split(":", 1)[0].strip()
    return ""


def _parse_signal(value: str) -> Optional[int]:
    v = value.strip()
    if v.isdigit():
        return int(v)
    return None


def _parse_nmcli_multiline(raw: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    cur: Dict[str, str] = {}

    for line in raw.splitlines():
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        k = key.strip().upper()
        v = val.strip()

        if k == "NAME" and cur:
            rows.append(cur)
            cur = {}
        cur[k] = v

    if cur:
        rows.append(cur)

    out: List[Dict[str, Any]] = []
    for row in rows:
        ssid = row.get("SSID", "").strip()
        if ssid in ("", "--"):
            ssid = "<hidden>"

        security = row.get("SECURITY", "").strip()
        if security in ("", "--"):
            security = "OPEN"

        out.append(
            {
                "NAME": row.get("NAME", ""),
                "SSID": ssid,
                "BSSID": row.get("BSSID", "").lower(),
                "SECURITY": security,
                "SIGNAL": _parse_signal(row.get("SIGNAL", "")),
                "CHAN": row.get("CHAN", ""),
                "BANDWIDTH": row.get("BANDWIDTH", ""),
                "FREQ": row.get("FREQ", ""),
            }
        )

    return out


def _disp_width(text: str) -> int:
    w = 0
    for ch in text:
        w += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return w


def _pad(text: Any, width: int, ellipsis: str = "...") -> str:
    s = "" if text is None else str(text)
    w = _disp_width(s)
    if w <= width:
        return s + " " * (width - w)

    cut = width - _disp_width(ellipsis)
    out = ""
    acc = 0
    for ch in s:
        ch_w = 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
        if acc + ch_w > cut:
            break
        out += ch
        acc += ch_w
    return out + ellipsis


def _print_text_ui(rows: List[Dict[str, Any]]) -> None:
    rows.sort(key=lambda r: r["SIGNAL"] if r["SIGNAL"] is not None else -1, reverse=True)

    total = len(rows)
    hidden = sum(1 for r in rows if r["SSID"] == "<hidden>")
    open_count = sum(1 for r in rows if r["SECURITY"] == "OPEN")
    best_signal = max((r["SIGNAL"] for r in rows if r["SIGNAL"] is not None), default=0)
    term_width = _terminal_width()

    full_layout = [
        ("#", "index", 3, True),
        ("SSID", "SSID", 30, False),
        ("BSSID", "BSSID", 17, False),
        ("SEC", "SECURITY", 16, False),
        ("SIG", "SIGNAL", 4, True),
        ("BAR", "BAR", 10, False),
        ("CH", "CHAN", 4, False),
        ("BW", "BANDWIDTH", 8, False),
    ]
    medium_layout = [
        ("#", "index", 3, True),
        ("SSID", "SSID", 30, False),
        ("BSSID", "BSSID", 17, False),
        ("SEC", "SECURITY", 14, False),
        ("SIG", "SIGNAL", 4, True),
        ("CH", "CHAN", 4, False),
        ("BW", "BANDWIDTH", 8, False),
    ]
    compact_layout = [
        ("#", "index", 3, True),
        ("SSID", "SSID", 28, False),
        ("BSSID", "BSSID", 17, False),
        ("SIG", "SIGNAL", 4, True),
        ("CH", "CHAN", 4, False),
    ]
    tiny_layout = [
        ("#", "index", 3, True),
        ("SSID", "SSID", max(18, term_width - 18), False),
        ("SIG", "SIGNAL", 4, True),
        ("CH", "CHAN", 4, False),
    ]

    def layout_width(cols: List[Tuple[str, str, int, bool]]) -> int:
        return sum(c[2] for c in cols) + 2 * (len(cols) - 1)

    if layout_width(full_layout) <= term_width:
        cols = full_layout
    elif layout_width(medium_layout) <= term_width:
        cols = medium_layout
    elif layout_width(compact_layout) <= term_width:
        cols = compact_layout
    else:
        cols = tiny_layout

    table_width = min(term_width, layout_width(cols))
    summary = f"AP:{total}  Hidden:{hidden}  Open:{open_count}  Best:{best_signal}%"

    print()
    print("=" * table_width)
    print(_clip_ascii("Kali Wi-Fi Scan Result", table_width))
    print(_clip_ascii(summary, table_width))
    print("=" * table_width)

    print(_clip_ascii("Network List", table_width).center(table_width, "-"))
    print("  ".join(_pad(title, width) for title, _, width, _ in cols))
    print("-" * table_width)

    for idx, r in enumerate(rows, 1):
        signal_val = r["SIGNAL"]
        signal_text = "" if signal_val is None else str(signal_val)
        blocks = 0 if signal_val is None else int(max(0, min(100, signal_val)) / 10)
        bar = "#" * blocks

        fields: Dict[str, Any] = {
            "index": idx,
            "SSID": r["SSID"],
            "BSSID": r["BSSID"],
            "SECURITY": r["SECURITY"],
            "SIGNAL": signal_text,
            "BAR": bar,
            "CHAN": r["CHAN"],
            "BANDWIDTH": r["BANDWIDTH"],
        }

        line_parts: List[str] = []
        for _, key, width, right_align in cols:
            value = fields.get(key, "")
            if right_align:
                line_parts.append(f"{'' if value is None else value:>{width}}")
            else:
                line_parts.append(_pad(value, width))
        line = "  ".join(line_parts)
        print(_clip_ascii(line, table_width))

    print("-" * table_width)
    tip = "Tip: python3 kali.py --raw for original nmcli output."
    print(_clip_ascii(tip, table_width))


def main() -> int:
    if not sys.platform.startswith("linux"):
        print("This script is for Kali/Linux only.", file=sys.stderr)
        return 1

    raw_mode = "--raw" in sys.argv[1:]
    print("[1/3] Checking scanner backend...")

    if shutil.which("nmcli"):
        print("[2/3] Running Wi-Fi scan via NetworkManager (nmcli).")
        rc, out, cost = _run_raw_with_spinner(
            [
                "nmcli",
                "--colors",
                "no",
                "--escape",
                "no",
                "--mode",
                "multiline",
                "--fields",
                "all",
                "device",
                "wifi",
                "list",
                "--rescan",
                "yes",
            ],
            "Scanning nearby APs"
        )
        text = _decode_console(out)
        if raw_mode:
            sys.stdout.write(text)
            return rc

        print("[3/3] Rendering friendly view.")
        rows = _parse_nmcli_multiline(text)
        if rows:
            _print_text_ui(rows)
            print(f"Scan time: {cost:.2f}s")
            return rc

        sys.stdout.write(text)
        return rc

    if shutil.which("iwlist"):
        print("[2/3] nmcli not found, fallback to iwlist.")
        iface = _pick_wireless_iface()
        if iface:
            rc, out, cost = _run_raw_with_spinner(["iwlist", iface, "scanning"], f"Scanning on {iface}")
            print("[3/3] Printing raw iwlist output.")
            sys.stdout.write(_decode_console(out))
            print(f"\nScan time: {cost:.2f}s")
            return rc

    print("No usable scanner found. Install NetworkManager (nmcli) or wireless-tools (iwlist).", file=sys.stderr)
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
