import subprocess
import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class WifiNetwork:
    ssid: str
    security: Optional[str]
    signal: Optional[int]   # strongest signal among BSSIDs


def scan_wifi_windows_simple() -> List[WifiNetwork]:
    out = subprocess.check_output(
        ["netsh", "wlan", "show", "networks", "mode=bssid"],
        encoding="utf-8",
        errors="ignore"
    )

    ssid_re = re.compile(r"^\s*SSID\s+\d+\s*[:：]\s*(.*)$")
    auth_re = re.compile(r"^\s*身份验证\s*[:：]\s*(.*)$")
    signal_re = re.compile(r"^\s*信号\s*[:：]\s*(\d+)\s*%")

    networks: List[WifiNetwork] = []

    cur_ssid = None
    cur_auth = None
    cur_signals = []

    for line in out.splitlines():
        # 新 SSID
        m = ssid_re.match(line)
        if m:
            # flush 上一个
            if cur_ssid is not None:
                networks.append(
                    WifiNetwork(
                        ssid=cur_ssid if cur_ssid else "<hidden>",
                        security=cur_auth,
                        signal=max(cur_signals) if cur_signals else None
                    )
                )
            # reset
            cur_ssid = m.group(1).strip()
            cur_auth = None
            cur_signals = []
            continue

        if cur_ssid is None:
            continue

        m = auth_re.match(line)
        if m:
            cur_auth = m.group(1).strip()
            continue

        m = signal_re.match(line)
        if m:
            cur_signals.append(int(m.group(1)))
            continue

    # flush last
    if cur_ssid is not None:
        networks.append(
            WifiNetwork(
                ssid=cur_ssid if cur_ssid else "<hidden>",
                security=cur_auth,
                signal=max(cur_signals) if cur_signals else None
            )
        )

    return networks


if __name__ == "__main__":
    nets = scan_wifi_windows_simple()
    print(f"{'SSID':30} {'Signal%':7} {'Security'}")
    print("-" * 60)
    for n in nets:
        ssid = n.ssid if len(n.ssid) <= 30 else n.ssid[:27] + "..."
        sig = "" if n.signal is None else str(n.signal)
        sec = n.security or ""
        print(f"{ssid:30} {sig:7} {sec}")
