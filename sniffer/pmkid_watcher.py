"""
pmkid_watcher.py — EAPOL / WPA handshake and PMKID attack detection.

PMKID attack (Jens Steube, 2018):
  Attacker captures the first EAPOL frame (ANONCE in Message 1 of
  the 4-way handshake) and derives the PMKID from it — no deauth needed,
  no client interaction required. The PMKID can then be cracked offline.

Detection signals:
  1. EAPOL Message 1 (ANonce) seen from an AP to a client without prior
     association/auth frames in our window → suspicious
  2. Multiple EAPOL M1 frames to different clients from the same BSSID
     in a short window (attacker is probing all clients)
  3. EAPOL seen on a channel where we have no beacon from that BSSID
"""

import time
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field

log = logging.getLogger("wifighost.pmkid")

EAPOL_WINDOW    = 30     # seconds
PMKID_THRESHOLD = 3      # EAPOL M1 frames from same BSSID to diff clients


@dataclass
class PMKIDAlert:
    alert_type:   str      # "PMKID_ATTEMPT" | "HANDSHAKE_CAPTURE"
    bssid:        str
    client_mac:   str
    eapol_count:  int
    confidence:   int
    channel:      int
    ts:           float = field(default_factory=time.time)


class PMKIDWatcher:
    """
    Feed it eapol frame dicts from packet_parser.parse_eapol.
    Also call notify_auth() when auth frames are seen (reduces false positives).
    """

    def __init__(self, window: float = EAPOL_WINDOW,
                 threshold: int = PMKID_THRESHOLD):
        self.window    = window
        self.threshold = threshold

        # bssid → deque of (ts, client_mac)
        self._eapol_events: dict[str, deque] = defaultdict(deque)
        # Set of (bssid, client_mac) where we saw auth first (legit)
        self._seen_auth: set[tuple[str, str]] = set()
        # Auth timestamp cache to expire entries
        self._auth_ts: dict[tuple, float] = {}
        # Fired alerts
        self._fired: set[str] = set()
        self._alerts: list[PMKIDAlert] = []

    def notify_auth(self, src_mac: str, bssid: str):
        """Call this when an auth frame is seen — marks the pair as legit."""
        key = (src_mac.lower(), bssid.lower())
        self._seen_auth.add(key)
        self._auth_ts[key] = time.time()

    def feed(self, frame: dict):
        """Process one parsed eapol frame dict."""
        src   = frame.get("src_mac", "").lower()
        dst   = frame.get("dst_mac", "").lower()
        bssid = frame.get("bssid", "").lower()
        ts    = frame.get("ts", time.time())

        # Determine direction: AP→Client (M1/M3) or Client→AP (M2/M4)
        # If src == bssid → AP sent it (potential PMKID probe)
        ap_sent = (src == bssid)
        client  = dst if ap_sent else src

        pair_key = (client, bssid)

        # Expire old auth records
        now = time.time()
        expired = [k for k, t in self._auth_ts.items() if now - t > 60]
        for k in expired:
            self._seen_auth.discard(k)
            del self._auth_ts[k]

        # Update EAPOL window
        dq = self._eapol_events[bssid]
        dq.append((ts, client))
        cutoff = ts - self.window
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        unique_clients = len({c for _, c in dq})

        # ── PMKID attempt: EAPOL M1 to multiple clients with no prior auth ─
        if ap_sent and pair_key not in self._seen_auth:
            key = f"pmkid_{bssid}_{client}"
            if key not in self._fired:
                confidence = 65
                if unique_clients >= self.threshold:
                    confidence = 90  # AP probing many clients = very suspicious

                self._alerts.append(PMKIDAlert(
                    alert_type  = "PMKID_ATTEMPT",
                    bssid       = bssid,
                    client_mac  = client,
                    eapol_count = unique_clients,
                    confidence  = confidence,
                    channel     = frame.get("channel", 0),
                ))
                self._fired.add(key)
                log.warning(
                    f"PMKID_ATTEMPT: bssid={bssid} → client={client} "
                    f"(no prior auth, {unique_clients} clients in window)"
                )

        # ── Handshake capture: 2+ EAPOL frames between same pair ──────────
        pair_frames = [(t, c) for t, c in dq if c == client]
        if len(pair_frames) >= 2:
            key = f"handshake_{bssid}_{client}"
            if key not in self._fired:
                self._alerts.append(PMKIDAlert(
                    alert_type  = "HANDSHAKE_CAPTURE",
                    bssid       = bssid,
                    client_mac  = client,
                    eapol_count = len(pair_frames),
                    confidence  = 78,
                    channel     = frame.get("channel", 0),
                ))
                self._fired.add(key)
                log.info(
                    f"HANDSHAKE_CAPTURE: bssid={bssid} ↔ client={client} "
                    f"frames={len(pair_frames)}"
                )

    def get_alerts(self) -> list[PMKIDAlert]:
        out = list(self._alerts)
        self._alerts.clear()
        return out

    def reset(self):
        self._eapol_events.clear()
        self._seen_auth.clear()
        self._auth_ts.clear()
        self._fired.clear()
        self._alerts.clear()
