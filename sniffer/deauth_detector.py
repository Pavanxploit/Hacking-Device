"""
deauth_detector.py — Deauthentication flood and disassociation attack detector.

Attack pattern:
  Attacker sends a burst of Deauth frames (forged as the real AP) to kick
  all clients off the network. Clients then reconnect — ideally to the
  attacker's evil twin AP instead of the real one.

Detection logic:
  - Count deauth/disassoc frames per (src_mac, bssid) pair in a sliding window
  - If count exceeds FLOOD_THRESHOLD in WINDOW_SECONDS → DEAUTH_FLOOD alert
  - If broadcast deauth seen from an unknown BSSID → ROGUE_DEAUTH alert
  - If same BSSID deauths then immediately beacons → EVIL_TWIN_PREP alert
"""

import time
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field

log = logging.getLogger("wifighost.deauth")

# Tuning constants
WINDOW_SECONDS   = 10     # sliding window duration
FLOOD_THRESHOLD  = 8      # deauth frames in window = flood
BURST_THRESHOLD  = 3      # quick bursts within 1s
BROADCAST_MAC    = "ff:ff:ff:ff:ff:ff"


@dataclass
class DeauthAlert:
    alert_type:    str         # "DEAUTH_FLOOD" | "BROADCAST_DEAUTH" | "EVIL_TWIN_PREP"
    src_mac:       str
    bssid:         str
    dst_mac:       str
    count:         int         # frames seen in window
    confidence:    int         # 0–100
    reason_codes:  list[int]
    ts:            float = field(default_factory=time.time)
    channel:       int = 0


class DeauthDetector:
    """
    Stateful deauth/disassoc flood detector.
    Feed it parsed deauth frame dicts (from packet_parser.parse_deauth).
    Call get_alerts() to drain the current alert queue.
    """

    def __init__(self,
                 window_sec: float = WINDOW_SECONDS,
                 flood_threshold: int = FLOOD_THRESHOLD,
                 trusted_bssids: set[str] | None = None):
        self.window_sec      = window_sec
        self.flood_threshold = flood_threshold
        self.trusted_bssids  = trusted_bssids or set()

        # (src_mac, bssid) → deque of timestamps
        self._frame_times: dict[tuple, deque] = defaultdict(deque)
        # (src_mac, bssid) → list of reason codes seen
        self._reason_codes: dict[tuple, list] = defaultdict(list)
        # Active alerts already fired (to avoid repeat spam)
        self._fired: set[tuple] = set()
        # Output queue
        self._alerts: list[DeauthAlert] = []

    def feed(self, frame: dict):
        """
        Process one parsed deauth/disassoc frame dict.
        Mutates internal state and may append to self._alerts.
        """
        src   = frame.get("src_mac", "").lower()
        bssid = frame.get("bssid", "").lower()
        dst   = frame.get("dst_mac", "").lower()
        rc    = frame.get("reason_code", 0)
        ts    = frame.get("ts", time.time())
        bcast = frame.get("broadcast", dst == BROADCAST_MAC)

        key = (src, bssid)

        # Update sliding window
        dq = self._frame_times[key]
        dq.append(ts)
        self._reason_codes[key].append(rc)

        # Evict frames outside window
        cutoff = ts - self.window_sec
        while dq and dq[0] < cutoff:
            dq.popleft()

        count = len(dq)

        # ── Alert 1: Deauth flood ─────────────────────────────────────────
        if count >= self.flood_threshold and key not in self._fired:
            confidence = min(100, 50 + (count - self.flood_threshold) * 5)
            alert = DeauthAlert(
                alert_type   = "DEAUTH_FLOOD",
                src_mac      = src,
                bssid        = bssid,
                dst_mac      = dst,
                count        = count,
                confidence   = confidence,
                reason_codes = list(set(self._reason_codes[key][-20:])),
                channel      = frame.get("channel", 0),
            )
            self._alerts.append(alert)
            self._fired.add(key)
            log.warning(
                f"DEAUTH_FLOOD: {src} → bssid={bssid} "
                f"count={count} conf={confidence}%"
            )

        # Reset fired flag when window clears below half threshold
        elif count < self.flood_threshold // 2 and key in self._fired:
            self._fired.discard(key)

        # ── Alert 2: Broadcast deauth from unknown BSSID ──────────────────
        if bcast and bssid and bssid not in self.trusted_bssids:
            broadcast_key = ("bcast", bssid)
            if broadcast_key not in self._fired:
                alert = DeauthAlert(
                    alert_type   = "BROADCAST_DEAUTH",
                    src_mac      = src,
                    bssid        = bssid,
                    dst_mac      = BROADCAST_MAC,
                    count        = count,
                    confidence   = 75,
                    reason_codes = [rc],
                    channel      = frame.get("channel", 0),
                )
                self._alerts.append(alert)
                self._fired.add(broadcast_key)
                log.warning(
                    f"BROADCAST_DEAUTH: bssid={bssid} src={src} rc={rc}"
                )

    def notify_beacon(self, bssid: str, ssid: str, channel: int):
        """
        Called by beacon handler when a new AP appears.
        If the same BSSID recently sent deauths → Evil Twin prep pattern.
        """
        bssid = bssid.lower()
        for (src, b), dq in self._frame_times.items():
            if b == bssid and len(dq) >= 2:
                et_key = ("evil_twin_prep", bssid)
                if et_key not in self._fired:
                    alert = DeauthAlert(
                        alert_type   = "EVIL_TWIN_PREP",
                        src_mac      = src,
                        bssid        = bssid,
                        dst_mac      = "",
                        count        = len(dq),
                        confidence   = 85,
                        reason_codes = list(set(self._reason_codes[(src, bssid)])),
                        channel      = channel,
                    )
                    self._alerts.append(alert)
                    self._fired.add(et_key)
                    log.warning(
                        f"EVIL_TWIN_PREP: bssid={bssid} ssid='{ssid}' "
                        f"deauths_then_beacon=True"
                    )

    def get_alerts(self) -> list[DeauthAlert]:
        """Drain and return all pending alerts."""
        out = list(self._alerts)
        self._alerts.clear()
        return out

    def reset(self):
        """Clear all state — call when interface is reset."""
        self._frame_times.clear()
        self._reason_codes.clear()
        self._fired.clear()
        self._alerts.clear()
