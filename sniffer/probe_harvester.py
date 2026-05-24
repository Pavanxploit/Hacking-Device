"""
probe_harvester.py — Probe Request tracking and harvesting detection.

Probe Requests are sent by clients looking for known networks.
They leak device history (past SSIDs the device connected to).

Attackers use passive probe collection to:
  1. Build a list of SSIDs to impersonate (karma/evil-twin setup)
  2. Track devices by MAC (even with MAC randomisation, some devices
     still reveal their probe pattern)
  3. Wait until a client probes for a target SSID, then bring up a rogue AP

This module:
  - Tracks which clients are probing for which SSIDs
  - Detects suspiciously rapid probe bursts (device being targeted)
  - Detects non-randomised MACs probing for sensitive SSIDs
  - Exports a live probe map for the dashboard
"""

import time
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field

from .oui_lookup import lookup as oui_lookup, is_randomised_mac

log = logging.getLogger("wifighost.probe")

PROBE_BURST_WINDOW   = 5     # seconds
PROBE_BURST_THRESH   = 20    # probes from one client in window = burst
SSID_HARVEST_THRESH  = 10    # unique SSIDs probed by one client = harvesting


@dataclass
class ProbeAlert:
    alert_type:   str       # "PROBE_BURST" | "SSID_HARVESTING"
    client_mac:   str
    vendor:       str
    randomised:   bool
    ssid_count:   int
    probe_rate:   float     # probes per second
    ssids_seen:   list[str]
    confidence:   int
    ts:           float = field(default_factory=time.time)


class ProbeHarvester:
    """
    Feed it probe_req dicts from packet_parser.parse_probe_request.
    Maintains a live map of {client_mac: {ssid: last_seen_ts}}.
    """

    def __init__(self,
                 burst_window: float = PROBE_BURST_WINDOW,
                 burst_thresh: int   = PROBE_BURST_THRESH,
                 harvest_thresh: int = SSID_HARVEST_THRESH):
        self.burst_window  = burst_window
        self.burst_thresh  = burst_thresh
        self.harvest_thresh = harvest_thresh

        # client_mac → {ssid → last_ts}
        self._client_ssids: dict[str, dict[str, float]] = defaultdict(dict)
        # client_mac → deque of timestamps (for burst detection)
        self._client_times: dict[str, deque] = defaultdict(deque)
        # Already fired keys
        self._fired: set[str] = set()
        self._alerts: list[ProbeAlert] = []

    def feed(self, frame: dict):
        """Process one parsed probe_req frame dict."""
        mac   = frame.get("client_mac", "").lower()
        ssid  = frame.get("ssid_wanted", "")    # empty = wildcard
        ts    = frame.get("ts", time.time())

        if not mac:
            return

        # Update SSID map
        self._client_ssids[mac][ssid] = ts

        # Update burst window
        dq = self._client_times[mac]
        dq.append(ts)
        cutoff = ts - self.burst_window
        while dq and dq[0] < cutoff:
            dq.popleft()

        burst_count  = len(dq)
        unique_ssids = len(self._client_ssids[mac])
        vendor       = oui_lookup(mac)
        randomised   = is_randomised_mac(mac)

        # ── Probe burst ────────────────────────────────────────────────────
        if burst_count >= self.burst_thresh:
            key = f"burst_{mac}"
            if key not in self._fired:
                rate = burst_count / self.burst_window
                confidence = min(100, 50 + int(rate * 2))
                self._alerts.append(ProbeAlert(
                    alert_type  = "PROBE_BURST",
                    client_mac  = mac,
                    vendor      = vendor,
                    randomised  = randomised,
                    ssid_count  = unique_ssids,
                    probe_rate  = round(rate, 2),
                    ssids_seen  = list(self._client_ssids[mac])[:20],
                    confidence  = confidence,
                ))
                self._fired.add(key)
                log.info(
                    f"PROBE_BURST: {mac} ({vendor}) "
                    f"{burst_count} probes in {self.burst_window}s"
                )
            # Reset when rate drops
            if burst_count < self.burst_thresh // 2:
                self._fired.discard(f"burst_{mac}")

        # ── SSID harvesting ────────────────────────────────────────────────
        if unique_ssids >= self.harvest_thresh:
            key = f"harvest_{mac}"
            if key not in self._fired:
                confidence = min(100, 60 + unique_ssids * 2)
                self._alerts.append(ProbeAlert(
                    alert_type  = "SSID_HARVESTING",
                    client_mac  = mac,
                    vendor      = vendor,
                    randomised  = randomised,
                    ssid_count  = unique_ssids,
                    probe_rate  = 0.0,
                    ssids_seen  = list(self._client_ssids[mac])[:30],
                    confidence  = confidence,
                ))
                self._fired.add(key)
                log.info(
                    f"SSID_HARVESTING: {mac} ({vendor}) "
                    f"probed {unique_ssids} different SSIDs"
                )

    def get_probe_map(self) -> dict:
        """
        Return live probe map for dashboard.
        Format: {mac: {vendor, randomised, ssids, last_seen}}
        """
        now = time.time()
        result = {}
        for mac, ssids in self._client_ssids.items():
            # Only include clients seen in last 60s
            last = max(ssids.values()) if ssids else 0
            if now - last > 60:
                continue
            result[mac] = {
                "vendor":     oui_lookup(mac),
                "randomised": is_randomised_mac(mac),
                "ssids":      [s for s in ssids if s],   # exclude wildcard
                "wildcard":   "" in ssids,
                "last_seen":  last,
            }
        return result

    def get_alerts(self) -> list[ProbeAlert]:
        out = list(self._alerts)
        self._alerts.clear()
        return out

    def reset(self):
        self._client_ssids.clear()
        self._client_times.clear()
        self._fired.clear()
        self._alerts.clear()
