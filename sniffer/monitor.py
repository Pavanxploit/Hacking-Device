"""
monitor.py — Wi-Fi interface monitor mode manager
Handles: wlan0 → wlan0mon setup, teardown, and health checks.
Requires: aircrack-ng suite (airmon-ng), root privileges.
"""

import subprocess
import os
import re
import time
import logging

log = logging.getLogger("wifighost.monitor")


def _run(cmd: list[str], check=True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def require_root():
    if os.geteuid() != 0:
        raise PermissionError(
            "WiFiGhost sniffer must run as root.\n"
            "Use: sudo python3 -m sniffer.monitor"
        )


def list_wifi_interfaces() -> list[str]:
    """Return list of wireless interface names e.g. ['wlan0', 'wlan1']."""
    try:
        result = _run(["iw", "dev"], check=False)
        return re.findall(r"Interface\s+(\w+)", result.stdout)
    except FileNotFoundError:
        log.error("'iw' not found — install: sudo apt install iw")
        return []


def get_monitor_interface(base: str = "wlan0") -> str | None:
    """Return the monitor-mode interface name, or None if not found."""
    ifaces = list_wifi_interfaces()
    mon_candidates = [i for i in ifaces if "mon" in i]
    if mon_candidates:
        return mon_candidates[0]
    try:
        result = _run(["iw", "dev", base, "info"], check=False)
        if "type monitor" in result.stdout:
            return base
    except Exception:
        pass
    return None


def kill_interfering_processes():
    """Kill NetworkManager/wpa_supplicant that block monitor mode."""
    log.info("Killing processes that interfere with monitor mode...")
    _run(["airmon-ng", "check", "kill"], check=False)
    time.sleep(1)


def enable_monitor_mode(interface: str = "wlan0") -> str:
    """
    Put <interface> into monitor mode using airmon-ng.
    Returns the monitor interface name (e.g. 'wlan0mon').
    AR9271 (TL-WN722N v1) is fully supported — no extra driver needed.
    """
    require_root()
    log.info(f"Enabling monitor mode on {interface}...")
    kill_interfering_processes()

    result = _run(["airmon-ng", "start", interface], check=False)
    log.debug(result.stdout)

    if result.returncode != 0:
        raise RuntimeError(f"airmon-ng failed:\n{result.stderr}")

    time.sleep(1)
    mon_iface = get_monitor_interface(interface)

    if not mon_iface:
        # Fallback: set monitor mode manually via iw (works on AR9271)
        log.warning("airmon-ng didn't create monX — falling back to iw...")
        _run(["ip", "link", "set", interface, "down"])
        _run(["iw", interface, "set", "type", "monitor"])
        _run(["ip", "link", "set", interface, "up"])
        mon_iface = interface

    log.info(f"Monitor interface ready: {mon_iface}")
    return mon_iface


def disable_monitor_mode(mon_interface: str = "wlan0mon",
                          base_interface: str = "wlan0"):
    """Tear down monitor mode and restart NetworkManager."""
    require_root()
    log.info(f"Disabling monitor mode on {mon_interface}...")
    _run(["airmon-ng", "stop", mon_interface], check=False)
    _run(["systemctl", "start", "NetworkManager"], check=False)
    log.info("NetworkManager restarted — normal internet restored.")


def set_channel(interface: str, channel: int):
    """Set the Wi-Fi channel on the monitor interface."""
    _run(["iw", "dev", interface, "set", "channel", str(channel)], check=False)


def get_current_channel(interface: str) -> int:
    """Return current channel number, or -1 on failure."""
    try:
        result = _run(["iw", "dev", interface, "info"], check=False)
        m = re.search(r"channel\s+(\d+)", result.stdout)
        return int(m.group(1)) if m else -1
    except Exception:
        return -1
