# wifi_scan_win.py
# Windows only. Triggers real WLAN scan via wlanapi, waits for scan complete,
# then parses `netsh wlan show networks mode=bssid`.
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import locale
import re
import subprocess
import time
import unicodedata
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Tuple


# -------------------------
# Native Wi-Fi (wlanapi) bits
# -------------------------
wlanapi = ctypes.WinDLL("wlanapi")
kernel32 = ctypes.WinDLL("kernel32")

ERROR_SUCCESS = 0
WLAN_NOTIFICATION_SOURCE_ACM = 0x00000008
WLAN_NOTIFICATION_ACM_SCAN_COMPLETE = 0x00000007
WLAN_NOTIFICATION_ACM_SCAN_FAIL = 0x00000008

WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102

WLAN_MAX_NAME_LENGTH = 256  # WCHAR count


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wt.DWORD),
        ("Data2", wt.WORD),
        ("Data3", wt.WORD),
        ("Data4", wt.BYTE * 8),
    ]


class WLAN_INTERFACE_INFO(ctypes.Structure):
    _fields_ = [
        ("InterfaceGuid", GUID),
        ("strInterfaceDescription", wt.WCHAR * WLAN_MAX_NAME_LENGTH),
        ("isState", wt.DWORD),
    ]


class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
    _fields_ = [
        ("dwNumberOfItems", wt.DWORD),
        ("dwIndex", wt.DWORD),
        ("InterfaceInfo", WLAN_INTERFACE_INFO * 1),
    ]


class WLAN_NOTIFICATION_DATA(ctypes.Structure):
    _fields_ = [
        ("NotificationSource", wt.DWORD),
        ("NotificationCode", wt.DWORD),
        ("InterfaceGuid", GUID),
        ("dwDataSize", wt.DWORD),
        ("pData", wt.LPVOID),
    ]


WLAN_NOTIFICATION_CALLBACK = ctypes.WINFUNCTYPE(None, ctypes.POINTER(WLAN_NOTIFICATION_DATA), wt.LPVOID)


# prototypes
wlanapi.WlanOpenHandle.argtypes = [wt.DWORD, wt.LPVOID, ctypes.POINTER(wt.DWORD), ctypes.POINTER(wt.HANDLE)]
wlanapi.WlanOpenHandle.restype = wt.DWORD

wlanapi.WlanCloseHandle.argtypes = [wt.HANDLE, wt.LPVOID]
wlanapi.WlanCloseHandle.restype = wt.DWORD

wlanapi.WlanEnumInterfaces.argtypes = [wt.HANDLE, wt.LPVOID, ctypes.POINTER(ctypes.POINTER(WLAN_INTERFACE_INFO_LIST))]
wlanapi.WlanEnumInterfaces.restype = wt.DWORD

wlanapi.WlanFreeMemory.argtypes = [wt.LPVOID]
wlanapi.WlanFreeMemory.restype = None

wlanapi.WlanRegisterNotification.argtypes = [
    wt.HANDLE,
    wt.DWORD,
    wt.BOOL,
    WLAN_NOTIFICATION_CALLBACK,
    wt.LPVOID,
    wt.LPVOID,
    ctypes.POINTER(wt.DWORD),
]
wlanapi.WlanRegisterNotification.restype = wt.DWORD

wlanapi.WlanScan.argtypes = [wt.HANDLE, ctypes.POINTER(GUID), wt.LPVOID, wt.LPVOID, wt.LPVOID]
wlanapi.WlanScan.restype = wt.DWORD

kernel32.CreateEventW.argtypes = [wt.LPVOID, wt.BOOL, wt.BOOL, wt.LPCWSTR]
kernel32.CreateEventW.restype = wt.HANDLE

kernel32.SetEvent.argtypes = [wt.HANDLE]
kernel32.SetEvent.restype = wt.BOOL

kernel32.ResetEvent.argtypes = [wt.HANDLE]
kernel32.ResetEvent.restype = wt.BOOL

kernel32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
kernel32.WaitForSingleObject.restype = wt.DWORD

kernel32.CloseHandle.argtypes = [wt.HANDLE]
kernel32.CloseHandle.restype = wt.BOOL


def _iter_interfaces(p_list: ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)) -> List[WLAN_INTERFACE_INFO]:
    base = p_list.contents
    n = int(base.dwNumberOfItems)
    array_type = WLAN_INTERFACE_INFO * n
    addr_first = ctypes.addressof(base.InterfaceInfo)  # points to first element
    return list(ctypes.cast(addr_first, ctypes.POINTER(array_type)).contents)


class _ScanWaiter:
    def __init__(self) -> None:
        self.event = kernel32.CreateEventW(None, True, False, None)  # manual reset
        if not self.event:
            raise OSError("CreateEventW failed")
        self.last_code: Optional[int] = None

    def close(self) -> None:
        if self.event:
            kernel32.CloseHandle(self.event)
            self.event = None

    def reset(self) -> None:
        self.last_code = None
        kernel32.ResetEvent(self.event)

    def set(self, code: int) -> None:
        self.last_code = code
        kernel32.SetEvent(self.event)


def wlan_force_scan(timeout_ms: int = 6000, progress: bool = False) -> Dict[str, Any]:
    """
    Trigger scan on all WLAN interfaces and wait for SCAN_COMPLETE/SCAN_FAIL per interface.
    Returns debug info with return codes.
    """
    dbg: Dict[str, Any] = {"interfaces": []}
    negotiated = wt.DWORD(0)
    h = wt.HANDLE()

    rc = wlanapi.WlanOpenHandle(2, None, ctypes.byref(negotiated), ctypes.byref(h))
    dbg["WlanOpenHandle_rc"] = int(rc)
    dbg["WlanOpenHandle_version"] = int(negotiated.value)
    if rc != ERROR_SUCCESS:
        return dbg

    waiter = _ScanWaiter()

    @WLAN_NOTIFICATION_CALLBACK
    def _cb(pData, _ctx):
        data = pData.contents
        if data.NotificationSource == WLAN_NOTIFICATION_SOURCE_ACM and data.NotificationCode in (
            WLAN_NOTIFICATION_ACM_SCAN_COMPLETE,
            WLAN_NOTIFICATION_ACM_SCAN_FAIL,
        ):
            waiter.set(int(data.NotificationCode))

    prev_src = wt.DWORD(0)
    rc = wlanapi.WlanRegisterNotification(
        h, WLAN_NOTIFICATION_SOURCE_ACM, True, _cb, None, None, ctypes.byref(prev_src)
    )
    dbg["WlanRegisterNotification_rc"] = int(rc)
    dbg["prev_notif_src"] = int(prev_src.value)

    p_if_list = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
    rc = wlanapi.WlanEnumInterfaces(h, None, ctypes.byref(p_if_list))
    dbg["WlanEnumInterfaces_rc"] = int(rc)
    if rc != ERROR_SUCCESS or not p_if_list:
        try:
            waiter.close()
        finally:
            wlanapi.WlanCloseHandle(h, None)
        return dbg

    interfaces = _iter_interfaces(p_if_list)
    wlanapi.WlanFreeMemory(p_if_list)

    for idx, iface in enumerate(interfaces, 1):
        name = iface.strInterfaceDescription
        waiter.reset()

        if progress:
            print(f"  · {idx}/{len(interfaces)} {name} -> 触发扫描", end="", flush=True)

        rc_scan = wlanapi.WlanScan(h, ctypes.byref(iface.InterfaceGuid), None, None, None)
        wait_rc = kernel32.WaitForSingleObject(waiter.event, timeout_ms)

        if progress:
            status = {
                WLAN_NOTIFICATION_ACM_SCAN_COMPLETE: "完成",
                WLAN_NOTIFICATION_ACM_SCAN_FAIL: "失败",
                WAIT_TIMEOUT: "超时",
            }.get(wait_rc if waiter.last_code is None else waiter.last_code, "返回")
            print(f" -> {status}")

        dbg["interfaces"].append(
            {
                "name": str(name),
                "WlanScan_rc": int(rc_scan),
                "wait_rc": int(wait_rc),
                "notif_code": waiter.last_code,
            }
        )

    waiter.close()
    wlanapi.WlanCloseHandle(h, None)
    return dbg


# -------------------------
# netsh parsing
# -------------------------
@dataclass
class WifiBssid:
    bssid: str
    signal_pct: Optional[int] = None
    radio: Optional[str] = None
    band: Optional[str] = None
    channel: Optional[str] = None


@dataclass
class WifiNetwork:
    ssid: str
    auth: Optional[str] = None
    cipher: Optional[str] = None
    best_signal_pct: Optional[int] = None
    bssids: List[WifiBssid] = None
    raw_block: str = ""


def _run_netsh_bytes(args: List[str]) -> Tuple[int, bytes]:
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=False)
    return p.returncode, p.stdout


def _decode_console(b: bytes) -> str:
    # Try UTF-8 first (some systems use UTF-8 codepage), then fall back.
    for enc in ("utf-8", locale.getpreferredencoding(False), "mbcs", "gbk", "cp936"):
        try:
            return b.decode(enc)
        except Exception:
            continue
    return b.decode("utf-8", errors="ignore")


_RE_VISIBLE_CN = re.compile(r"当前有\s*(\d+)\s*个网络可见")
_RE_VISIBLE_EN = re.compile(r"There are\s*(\d+)\s*networks currently visible", re.I)

_RE_SSID = re.compile(r"^\s*SSID\s+\d+\s*:\s*(.*)\s*$", re.I)
_RE_AUTH = re.compile(r"^\s*(身份验证|Authentication)\s*:\s*(.*)\s*$", re.I)
_RE_CIPHER = re.compile(r"^\s*(加密|Encryption)\s*:\s*(.*)\s*$", re.I)
_RE_BSSID = re.compile(r"^\s*BSSID\s+\d+\s*:\s*([0-9a-f:]{17})\s*$", re.I)
_RE_SIGNAL = re.compile(r"^\s*(信号|Signal)\s*:\s*(\d+)\s*%\s*$", re.I)
_RE_RADIO = re.compile(r"^\s*(无线电类型|Radio type)\s*:\s*(.*)\s*$", re.I)
_RE_BAND = re.compile(r"^\s*(波段|Band)\s*:\s*(.*)\s*$", re.I)
_RE_CH = re.compile(r"^\s*(频道|Channel)\s*:\s*(.*)\s*$", re.I)


def parse_netsh_networks(raw: str) -> Tuple[List[WifiNetwork], Dict[str, Any]]:
    lines = raw.splitlines()
    visible = None
    for ln in lines[:20]:
        m = _RE_VISIBLE_CN.search(ln) or _RE_VISIBLE_EN.search(ln)
        if m:
            visible = int(m.group(1))
            break

    nets: List[WifiNetwork] = []
    cur: Optional[WifiNetwork] = None
    cur_lines: List[str] = []
    cur_bssid: Optional[WifiBssid] = None

    def flush():
        nonlocal cur, cur_lines, cur_bssid
        if cur:
            cur.raw_block = "\n".join(cur_lines).strip("\n")
            # compute best signal
            best = None
            if cur.bssids:
                for b in cur.bssids:
                    if b.signal_pct is not None:
                        best = b.signal_pct if best is None else max(best, b.signal_pct)
            cur.best_signal_pct = best
            nets.append(cur)
        cur = None
        cur_lines = []
        cur_bssid = None

    for ln in lines:
        m_ssid = _RE_SSID.match(ln)
        if m_ssid:
            flush()
            ssid = m_ssid.group(1).strip()
            # hidden SSID is blank
            cur = WifiNetwork(ssid=ssid if ssid else "<hidden>", bssids=[])
            cur_lines.append(ln)
            continue

        if cur is None:
            continue

        cur_lines.append(ln)

        m = _RE_AUTH.match(ln)
        if m:
            cur.auth = m.group(2).strip()
            continue
        m = _RE_CIPHER.match(ln)
        if m:
            cur.cipher = m.group(2).strip()
            continue

        m = _RE_BSSID.match(ln)
        if m:
            cur_bssid = WifiBssid(bssid=m.group(1).lower())
            cur.bssids.append(cur_bssid)
            continue

        if cur_bssid:
            m = _RE_SIGNAL.match(ln)
            if m:
                cur_bssid.signal_pct = int(m.group(2))
                continue
            m = _RE_RADIO.match(ln)
            if m:
                cur_bssid.radio = m.group(2).strip()
                continue
            m = _RE_BAND.match(ln)
            if m:
                cur_bssid.band = m.group(2).strip()
                continue
            m = _RE_CH.match(ln)
            if m:
                cur_bssid.channel = m.group(2).strip()
                continue

    flush()
    dbg = {"visible_count": visible, "parsed_count": len(nets)}
    return nets, dbg


# -------------------------
# small helpers for aligned terminal output
# -------------------------
def _disp_width(text: str) -> int:
    """Return visual width considering CJK wide chars."""
    w = 0
    for ch in text:
        w += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return w


def _pad(text: Any, width: int, ellipsis: str = "…") -> str:
    s = "" if text is None else str(text)
    w = _disp_width(s)
    if w <= width:
        return s + " " * (width - w)
    # truncate with ellipsis
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


def scan_wifi_full(
    max_tries: int = 5,
    timeout_ms: int = 6000,
    backoff: float = 0.6,
    progress: bool = False,
) -> Dict[str, Any]:
    """
    Best-effort:
    - native scan + wait
    - netsh dump + parse
    - retry, keep the attempt with largest visible_count/parsed_count
    """
    best: Dict[str, Any] = {"visible_count": -1, "parsed_count": -1}
    last_visible = None

    if progress:
        print(f"刷新 Wi‑Fi 列表中，最多尝试 {max_tries} 次…")

    for i in range(max_tries):
        if progress:
            print(f"尝试 {i + 1}/{max_tries}: 请求网卡扫描并等待返回 (≤{timeout_ms/1000:.1f}s)…")

        scan_dbg = wlan_force_scan(timeout_ms=timeout_ms, progress=progress)

        # tiny delay helps drivers finish updating internal tables after scan complete
        time.sleep(0.25)

        if progress:
            print("  读取 netsh 输出并解析…", end="", flush=True)

        code, out = _run_netsh_bytes(["netsh", "wlan", "show", "networks", "mode=bssid"])
        raw = _decode_console(out)

        # quick detection of 24H2 location block message (netsh prints it verbatim)
        location_block = "ms-settings:privacy-location" in raw or "location permission" in raw.lower()

        nets, parse_dbg = parse_netsh_networks(raw)
        visible = parse_dbg.get("visible_count")
        parsed = parse_dbg.get("parsed_count", 0)

        score_visible = visible if isinstance(visible, int) else -1
        improved = (score_visible, parsed) > (best["visible_count"], best["parsed_count"])
        if improved:
            best = {
                "attempt": i + 1,
                "netsh_returncode": code,
                "raw_netsh": raw,              # full raw output preserved
                "networks": [asdict(n) for n in nets],
                "visible_count": score_visible,
                "parsed_count": parsed,
                "scan_debug": scan_dbg,
                "location_block_hint": location_block,
            }

        if progress:
            vis_txt = "?" if visible is None else str(visible)
            print(f"  -> 可见网络: {vis_txt}，解析到: {parsed} {'(新纪录)' if improved else ''}")

        # stop early if stable and looks reasonable
        if visible is not None:
            if last_visible == visible and visible >= 3:
                break
            last_visible = visible

        time.sleep(backoff * (1.3 ** i))

    return best


if __name__ == "__main__":
    result = scan_wifi_full(max_tries=6, timeout_ms=6500, progress=True)

    # Build display rows with best BSSID (highest signal if available)
    rows = []
    for n in result.get("networks", []):
        bssid = ""
        bssids = n.get("bssids") or []
        if bssids:
            # pick BSSID with highest signal, else first
            best_b = max(bssids, key=lambda b: b.get("signal_pct") if b.get("signal_pct") is not None else -1)
            bssid = best_b.get("bssid", "")

        rows.append(
            {
                "SSID": n.get("ssid"),
                "BSSID": bssid,
                "Auth": n.get("auth"),
                "Cipher": n.get("cipher"),
                "BestSignal%": n.get("best_signal_pct"),
            }
        )

    # Sort rows by signal descending (None treated as lowest)
    rows.sort(key=lambda r: r["BestSignal%"] if r["BestSignal%"] is not None else -1, reverse=True)

    # Pretty table output with header, width-safe padding
    hdr = [
        ("SSID", 28),
        ("BSSID", 17),
        ("Auth", 12),
        ("Cipher", 10),
        ("Signal%", 7),
    ]
    total_width = sum(w for _, w in hdr) + len(hdr) * 2 - 2

    print()
    title = "扫描结果"
    print(title.center(total_width-4, "-"))
    print("  ".join(_pad(name, width) for name, width in hdr))
    print("-" * total_width)

    for r in rows:
        line = [
            _pad(r["SSID"], 28),
            _pad(r["BSSID"], 17),
            _pad(r["Auth"], 12),
            _pad(r["Cipher"], 10),
            f"{'' if r['BestSignal%'] is None else r['BestSignal%']:>7}",
        ]
        print("  ".join(line))

    print("-" * total_width)
    print(f"可见网络: {result.get('visible_count')}  解析成功: {result.get('parsed_count')}")
    
