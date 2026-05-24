"""
feature_builder.py — Convert raw WiFiGhost scan and sniffer data into
numerical feature vectors for the ML models.

Two input sources:
  1. ESP32 scan payload  (dict with 'networks' list) — station-mode view
  2. Sniffer alert dict  (from SnifferEngine queue)  — monitor-mode view

Both are converted into a flat numpy array that the detectors consume.
Feature engineering is the most important ML step — garbage in, garbage out.
"""

import time
import math
import logging
from collections import defaultdict

import numpy as np

log = logging.getLogger("wifighost.features")


# ─── Feature names (in order) — used for model training and SHAP explanations
ESP32_FEATURE_NAMES = [
    # Network count features
    "total_aps",
    "open_aps",
    "wep_aps",
    "wpa_aps",
    "wpa2_aps",
    "hidden_aps",

    # RSSI distribution
    "rssi_mean",
    "rssi_std",
    "rssi_min",
    "rssi_max",
    "rssi_strong_count",    # APs with RSSI > -50 dBm

    # Channel distribution
    "channel_spread",       # unique channels used
    "channel_entropy",      # Shannon entropy of channel distribution
    "non_overlapping_count",# APs on channels 1, 6, 11

    # BSSID/SSID patterns
    "duplicate_ssid_count", # same SSID from multiple BSSIDs
    "ssid_bssid_ratio",     # SSIDs per BSSID (high = beacon flood)
    "oui_diversity",        # unique OUI prefixes (low = cloned MACs)
    "sequential_bssid",     # consecutive MAC addresses (cloning sign)

    # Encryption anomalies
    "open_ratio",           # fraction of open networks
    "wps_ratio",            # fraction with WPS (attack surface)

    # Signal anomalies
    "rssi_outlier_count",   # APs with unusually strong signal
    "rssi_variance",

    # Temporal
    "scan_duration_ms",
    "new_aps_since_last",   # delta from previous scan
    "disappeared_aps",      # APs gone since last scan
]

SNIFFER_FEATURE_NAMES = [
    # Deauth features
    "deauth_count_window",
    "deauth_unique_src",
    "deauth_broadcast_ratio",
    "deauth_reason_entropy",

    # Beacon features
    "beacon_rate",
    "unique_ssids_per_bssid",
    "evil_twin_candidates",
    "hidden_ssid_count",

    # Probe features
    "probe_client_count",
    "probe_wildcard_ratio",
    "randomised_mac_ratio",

    # EAPOL features
    "eapol_count_window",
    "eapol_without_auth",

    # Combined
    "deauth_then_beacon",   # deauth + new beacon within 30s (evil twin setup)
    "channel_concentration",# all attacks on one channel
]


def _shannon_entropy(counts: list[int]) -> float:
    """Shannon entropy of a frequency distribution."""
    total = sum(counts)
    if total == 0:
        return 0.0
    probs = [c / total for c in counts if c > 0]
    return -sum(p * math.log2(p) for p in probs)


def _mac_prefix(mac: str) -> str:
    """Return first 3 octets of a MAC as OUI prefix."""
    parts = mac.upper().replace("-", ":").split(":")
    return ":".join(parts[:3]) if len(parts) >= 3 else "00:00:00"


def _is_sequential_macs(macs: list[str]) -> int:
    """
    Count pairs of MACs that differ only in the last octet by 1.
    Attackers often clone sequential MACs to spoof AP fleets.
    """
    if len(macs) < 2:
        return 0
    count = 0
    sorted_macs = sorted(macs)
    for i in range(len(sorted_macs) - 1):
        a = sorted_macs[i].replace(":", "").replace("-", "")
        b = sorted_macs[i+1].replace(":", "").replace("-", "")
        try:
            if abs(int(a, 16) - int(b, 16)) == 1:
                count += 1
        except ValueError:
            pass
    return count


class ESP32FeatureBuilder:
    """
    Converts ESP32 scan payloads into ML feature vectors.
    Maintains state across scans for delta features.
    """

    def __init__(self):
        self._last_bssids: set[str] = set()
        self._last_scan_ts: float   = 0.0

    def build(self, scan: dict) -> np.ndarray:
        """
        Input: ESP32 scan dict with 'networks' list.
        Output: 1D numpy array of float32 with len(ESP32_FEATURE_NAMES) elements.
        """
        networks = scan.get("networks", [])
        ts_now   = time.time()
        duration = scan.get("scan_duration_ms", 0)

        # ── Count-based features ─────────────────────────────────────────
        total    = len(networks)
        open_n   = sum(1 for n in networks if n.get("enc_str") == "OPEN")
        wep_n    = sum(1 for n in networks if n.get("enc_str") == "WEP")
        wpa_n    = sum(1 for n in networks if "WPA" in str(n.get("enc_str","")))
        wpa2_n   = sum(1 for n in networks if n.get("enc_str") in ("WPA2","WPA/2"))
        hidden_n = sum(1 for n in networks if not n.get("ssid","").strip())

        # ── RSSI features ─────────────────────────────────────────────────
        rssi_vals = [n.get("rssi", -100) for n in networks]
        rssi_arr  = np.array(rssi_vals, dtype=np.float32) if rssi_vals else np.array([-100.0])
        rssi_mean = float(np.mean(rssi_arr))
        rssi_std  = float(np.std(rssi_arr))
        rssi_min  = float(np.min(rssi_arr))
        rssi_max  = float(np.max(rssi_arr))
        rssi_strong = sum(1 for r in rssi_vals if r > -50)
        rssi_variance = float(np.var(rssi_arr))

        # Outliers: APs more than 2 std above mean (suspiciously strong)
        rssi_outliers = sum(1 for r in rssi_vals
                            if r > rssi_mean + 2 * rssi_std + 1e-6)

        # ── Channel features ──────────────────────────────────────────────
        channels = [n.get("channel", 0) for n in networks]
        ch_counts: dict[int, int] = defaultdict(int)
        for ch in channels:
            ch_counts[ch] += 1
        ch_spread   = len(ch_counts)
        ch_entropy  = _shannon_entropy(list(ch_counts.values()))
        non_overlap = sum(ch_counts.get(c, 0) for c in [1, 6, 11])

        # ── BSSID / SSID anomaly features ─────────────────────────────────
        ssids  = [n.get("ssid", "").strip() for n in networks]
        bssids = [n.get("bssid", "").lower() for n in networks]

        # SSIDs appearing more than once (same SSID, different BSSID)
        ssid_counts: dict[str, int] = defaultdict(int)
        for s in ssids:
            if s:
                ssid_counts[s] += 1
        dup_ssid_count = sum(1 for c in ssid_counts.values() if c > 1)

        ssid_bssid_ratio = len(set(ssids)) / max(len(set(bssids)), 1)

        oui_prefixes = [_mac_prefix(b) for b in bssids if b]
        oui_diversity = len(set(oui_prefixes)) / max(len(oui_prefixes), 1)

        seq_bssid = _is_sequential_bssid = _is_sequential_macs(bssids)

        # ── Encryption ratios ─────────────────────────────────────────────
        open_ratio = open_n / max(total, 1)
        wps_ratio  = 0.0   # ESP32 doesn't report WPS — sniffer handles this

        # ── Delta features (vs previous scan) ─────────────────────────────
        current_bssids = set(bssids)
        new_aps  = len(current_bssids - self._last_bssids)
        gone_aps = len(self._last_bssids - current_bssids)
        self._last_bssids  = current_bssids
        self._last_scan_ts = ts_now

        # ── Assemble vector ───────────────────────────────────────────────
        vec = np.array([
            total, open_n, wep_n, wpa_n, wpa2_n, hidden_n,
            rssi_mean, rssi_std, rssi_min, rssi_max, rssi_strong,
            ch_spread, ch_entropy, non_overlap,
            dup_ssid_count, ssid_bssid_ratio, oui_diversity, seq_bssid,
            open_ratio, wps_ratio,
            rssi_outliers, rssi_variance,
            duration, new_aps, gone_aps,
        ], dtype=np.float32)

        assert len(vec) == len(ESP32_FEATURE_NAMES), \
            f"Feature count mismatch: {len(vec)} vs {len(ESP32_FEATURE_NAMES)}"

        return vec


class SnifferFeatureBuilder:
    """
    Builds features from a window of sniffer alert events.
    Call feed() for each alert, then build() to get the feature vector.
    Reset with reset_window() between inference cycles.
    """

    def __init__(self, window_sec: float = 30.0):
        self.window_sec = window_sec
        self._events: list[dict] = []

    def feed(self, alert: dict):
        self._events.append({**alert, "_ts": time.time()})

    def _current_events(self) -> list[dict]:
        cutoff = time.time() - self.window_sec
        return [e for e in self._events if e["_ts"] >= cutoff]

    def build(self) -> np.ndarray:
        """
        Build a feature vector from events in the current window.
        Returns zeros if no events (clean environment).
        """
        events = self._current_events()

        deauths = [e for e in events if "deauth" in e.get("frame_type","").lower()
                   or e.get("alert_type","") in ("DEAUTH_FLOOD","BROADCAST_DEAUTH")]
        beacons = [e for e in events if e.get("frame_type") == "beacon"
                   or e.get("alert_type") in ("BEACON_FLOOD","KARMA_AP","EVIL_TWIN")]
        probes  = [e for e in events if e.get("frame_type") == "probe_req"
                   or e.get("alert_type") in ("PROBE_BURST","SSID_HARVESTING")]
        eapols  = [e for e in events if e.get("frame_type") == "eapol"
                   or e.get("alert_type") in ("PMKID_ATTEMPT","HANDSHAKE_CAPTURE")]

        # ── Deauth features ───────────────────────────────────────────────
        deauth_count = len(deauths)
        deauth_srcs  = len({e.get("src_mac","") for e in deauths})
        bcast_ratio  = (sum(1 for e in deauths if e.get("broadcast",False))
                        / max(deauth_count, 1))
        reason_codes = [e.get("reason_code", 0) for e in deauths]
        reason_entropy = _shannon_entropy(
            list(defaultdict(int, {r: reason_codes.count(r)
                                   for r in set(reason_codes)}).values())
        )

        # ── Beacon features ───────────────────────────────────────────────
        beacon_rate  = len(beacons) / self.window_sec
        bssid_ssids: dict[str, set] = defaultdict(set)
        for e in beacons:
            if e.get("bssid") and e.get("ssid"):
                bssid_ssids[e["bssid"]].add(e["ssid"])
        max_ssids_per_bssid = max((len(v) for v in bssid_ssids.values()), default=0)
        evil_twin_cands = sum(1 for e in beacons
                              if e.get("alert_type") == "EVIL_TWIN")
        hidden_count    = sum(1 for e in beacons if not e.get("ssid",""))

        # ── Probe features ────────────────────────────────────────────────
        probe_clients   = len({e.get("client_mac","") for e in probes})
        wildcard_probes = sum(1 for e in probes if not e.get("ssid_wanted",""))
        wildcard_ratio  = wildcard_probes / max(len(probes), 1)
        rand_macs       = sum(1 for e in probes
                              if e.get("randomised", False))
        rand_ratio      = rand_macs / max(probe_clients, 1)

        # ── EAPOL features ────────────────────────────────────────────────
        eapol_count    = len(eapols)
        eapol_no_auth  = sum(1 for e in eapols
                             if e.get("alert_type") == "PMKID_ATTEMPT")

        # ── Combined features ─────────────────────────────────────────────
        deauth_then_beacon = int(
            deauth_count > 0 and
            any(e.get("alert_type") == "EVIL_TWIN" for e in beacons)
        )

        all_channels = (
            [e.get("channel", 0) for e in deauths] +
            [e.get("channel", 0) for e in beacons]
        )
        ch_counts = defaultdict(int)
        for ch in all_channels:
            if ch:
                ch_counts[ch] += 1
        # High concentration = all attacks on one channel
        if ch_counts:
            max_ch_count    = max(ch_counts.values())
            ch_concentration = max_ch_count / max(len(all_channels), 1)
        else:
            ch_concentration = 0.0

        vec = np.array([
            deauth_count, deauth_srcs, bcast_ratio, reason_entropy,
            beacon_rate, max_ssids_per_bssid, evil_twin_cands, hidden_count,
            probe_clients, wildcard_ratio, rand_ratio,
            eapol_count, eapol_no_auth,
            deauth_then_beacon, ch_concentration,
        ], dtype=np.float32)

        assert len(vec) == len(SNIFFER_FEATURE_NAMES), \
            f"Feature count mismatch: {len(vec)} vs {len(SNIFFER_FEATURE_NAMES)}"

        return vec

    def reset_window(self):
        cutoff = time.time() - self.window_sec
        self._events = [e for e in self._events if e["_ts"] >= cutoff]
