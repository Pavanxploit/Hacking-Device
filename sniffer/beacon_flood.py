"""
beacon_flood.py — Beacon flood and karma attack detector.

Beacon flood:
  Attacker broadcasts hundreds of fake SSIDs per second to overwhelm
  client Wi-Fi managers or create confusion. mdk3/mdk4 is the common tool.

Karma attack:
  Rogue AP responds to any Probe Request with a matching SSID, impersonating
  whatever network the client is looking for. Detection: a BSSID beaconing
  many different SSIDs in a short time.

SSID impersonation:
  Same SSID as a trusted AP but different BSSID — evil twin.
"""

import time
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field

log = logging.getLogger("wifighost.beacon")

# Tuning
BEACON_FLOOD_WINDOW  = 5      # seconds
BEACON_FLOOD_THRESH  = 50     # unique SSIDs from one source in window
KARMA_SSID_THRESH    = 5      # different SSIDs from one BSSID = karma suspicion
KARMA_WINDOW         = 30     # seconds for karma tracking


@dataclass
class BeaconAlert:
    alert_type:  str        # "BEACON_FLOOD" | "KARMA_AP" | "EVIL_TWIN"
    bssid:       str
    ssid:        str        # primary or most recent SSID involved
    ssid_count:  int        # how many different SSIDs seen
    confidence:  int
    channel:     int
    rssi:        int
    ts:          float = field(default_factory=time.time)
    extra:       dict = field(default_factory=dict)


class BeaconFloodDetector:
    """
    Feed it beacon frame dicts (from packet_parser.parse_beacon).
    Call register_trusted_ap() with your baseline SSID→BSSID map.
    Call get_alerts() to drain alerts.
    """

    def __init__(self,
                 flood_window: float = BEACON_FLOOD_WINDOW,
                 flood_thresh: int   = BEACON_FLOOD_THRESH,
                 karma_window: float = KARMA_WINDOW,
                 karma_thresh: int   = KARMA_SSID_THRESH):
        self.flood_window = flood_window
        self.flood_thresh = flood_thresh
        self.karma_window = karma_window
        self.karma_thresh = karma_thresh

        # For flood: src_mac → deque of (ts, ssid) tuples
        self._flood_window: dict[str, deque] = defaultdict(deque)
        # For karma: bssid → set of SSIDs seen in window
        self._karma_ssids:  dict[str, dict]  = defaultdict(dict)
        # Trusted SSID → set of known BSSIDs
        self._trusted: dict[str, set[str]] = defaultdict(set)
        # Already-fired alert keys
        self._fired: set[str] = set()
        self._alerts: list[BeaconAlert] = []

    def register_trusted_ap(self, ssid: str, bssid: str):
        """Mark an SSID+BSSID pair as trusted (from baseline)."""
        self._trusted[ssid.lower()].add(bssid.lower())

    def feed(self, frame: dict):
        """Process one parsed beacon frame dict."""
        bssid   = frame.get("bssid", "").lower()
        ssid    = frame.get("ssid", "")
        rssi    = frame.get("rssi", 0)
        channel = frame.get("channel", 0)
        ts      = frame.get("ts", time.time())

        self._check_flood(bssid, ssid, rssi, channel, ts)
        self._check_karma(bssid, ssid, rssi, channel, ts)
        self._check_evil_twin(bssid, ssid, rssi, channel, ts)

    # ── Beacon flood ────────────────────────────────────────────────────────
    def _check_flood(self, bssid, ssid, rssi, channel, ts):
        dq = self._flood_window[bssid]
        dq.append((ts, ssid))

        cutoff = ts - self.flood_window
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        unique_ssids = len({s for _, s in dq})

        if unique_ssids >= self.flood_thresh:
            key = f"flood_{bssid}"
            if key not in self._fired:
                confidence = min(100, 60 + unique_ssids)
                self._alerts.append(BeaconAlert(
                    alert_type = "BEACON_FLOOD",
                    bssid      = bssid,
                    ssid       = ssid,
                    ssid_count = unique_ssids,
                    confidence = confidence,
                    channel    = channel,
                    rssi       = rssi,
                    extra      = {"rate_per_sec": unique_ssids / self.flood_window},
                ))
                self._fired.add(key)
                log.warning(
                    f"BEACON_FLOOD: bssid={bssid} "
                    f"unique_ssids={unique_ssids} in {self.flood_window}s"
                )
        elif unique_ssids < self.flood_thresh // 2:
            self._fired.discard(f"flood_{bssid}")

    # ── Karma attack ────────────────────────────────────────────────────────
    def _check_karma(self, bssid, ssid, rssi, channel, ts):
        karma = self._karma_ssids[bssid]
        karma[ssid] = ts

        # Evict old entries
        cutoff = ts - self.karma_window
        expired = [s for s, t in karma.items() if t < cutoff]
        for s in expired:
            del karma[s]

        unique = len(karma)
        if unique >= self.karma_thresh:
            key = f"karma_{bssid}"
            if key not in self._fired:
                confidence = min(100, 55 + unique * 5)
                self._alerts.append(BeaconAlert(
                    alert_type = "KARMA_AP",
                    bssid      = bssid,
                    ssid       = ssid,
                    ssid_count = unique,
                    confidence = confidence,
                    channel    = channel,
                    rssi       = rssi,
                    extra      = {"ssids_seen": list(karma.keys())[:10]},
                ))
                self._fired.add(key)
                log.warning(
                    f"KARMA_AP: bssid={bssid} beaconing {unique} different SSIDs"
                )

    # ── Evil twin ───────────────────────────────────────────────────────────
    def _check_evil_twin(self, bssid, ssid, rssi, channel, ts):
        if not ssid:
            return  # hidden SSID — different detection path

        trusted_bssids = self._trusted.get(ssid.lower(), set())
        if not trusted_bssids:
            return  # SSID not in our baseline — nothing to compare

        if bssid not in trusted_bssids:
            key = f"evil_twin_{ssid.lower()}_{bssid}"
            if key not in self._fired:
                # Higher confidence if signal is strong (attacker is nearby)
                # or if trusted SSID is well-established in baseline
                confidence = 70 + min(20, len(trusted_bssids) * 10)
                if rssi > -50:
                    confidence = min(100, confidence + 10)

                self._alerts.append(BeaconAlert(
                    alert_type = "EVIL_TWIN",
                    bssid      = bssid,
                    ssid       = ssid,
                    ssid_count = 1,
                    confidence = confidence,
                    channel    = channel,
                    rssi       = rssi,
                    extra      = {
                        "trusted_bssids": list(trusted_bssids),
                        "impersonating":  ssid,
                    },
                ))
                self._fired.add(key)
                log.warning(
                    f"EVIL_TWIN: ssid='{ssid}' from unknown bssid={bssid} "
                    f"(trusted: {trusted_bssids}) conf={confidence}%"
                )

    def get_alerts(self) -> list[BeaconAlert]:
        out = list(self._alerts)
        self._alerts.clear()
        return out

    def reset(self):
        self._flood_window.clear()
        self._karma_ssids.clear()
        self._fired.clear()
        self._alerts.clear()
