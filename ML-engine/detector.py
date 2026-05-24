"""
detector.py — Master ML detector for WiFiGhost AI.

This is the single class the backend imports and uses.
It orchestrates:
  ESP32FeatureBuilder  → extract features from scan payload
  SnifferFeatureBuilder→ extract features from sniffer event window
  IsoForestDetector    → anomaly score (no labels needed)
  LGBMDetector         → named attack type + confidence
  ThreatScorer         → fuse both into final ThreatResult
  AttackCorrelator     → detect multi-event attack chains

Usage (in Flask backend):
    from ml.detector import Detector

    detector = Detector()
    detector.load()   # load saved models

    # Process an ESP32 scan
    result = detector.process_esp32_scan(scan_dict)

    # Feed a sniffer alert
    detector.feed_sniffer_alert(alert_dict)

    # Get latest result (for WebSocket push)
    result = detector.latest_result
"""

import logging
import queue
import time
from threading import Lock

import numpy as np

from .feature_builder   import ESP32FeatureBuilder, SnifferFeatureBuilder
from .isolation_forest  import IsoForestDetector
from .lightgbm_model    import LGBMDetector
from .threat_scorer     import ThreatScorer, ThreatResult
from .attack_correlator import AttackCorrelator

log = logging.getLogger("wifighost.detector")


class Detector:
    """
    Thread-safe master ML detector.
    Safe to call from Flask request threads and sniffer thread simultaneously.
    """

    def __init__(self):
        self._lock    = Lock()

        # Feature builders
        self._esp32_fb   = ESP32FeatureBuilder()
        self._sniffer_fb = SnifferFeatureBuilder(window_sec=30.0)

        # Models
        self._iso   = IsoForestDetector()
        self._lgbm  = LGBMDetector()

        # Fusion + correlation
        self._scorer     = ThreatScorer()
        self._correlator = AttackCorrelator()

        # State
        self._latest: ThreatResult | None = None
        self._sniffer_alert_buffer: list[dict] = []

        # Stats
        self._stats = {
            "scans_processed":    0,
            "alerts_fired":       0,
            "chains_detected":    0,
            "lgbm_ready":         False,
            "isoforest_trained":  False,
        }

    def load(self):
        """Load saved models from disk. Call once at startup."""
        # IsoForest loads automatically in __init__
        # LightGBM loads automatically in __init__
        self._stats["lgbm_ready"]        = self._lgbm.is_ready
        self._stats["isoforest_trained"] = self._iso._trained
        log.info(
            f"Detector ready — "
            f"LightGBM={'ready' if self._lgbm.is_ready else 'not trained'}, "
            f"IsoForest={'trained' if self._iso._trained else 'collecting baseline'}"
        )

    # ─── Primary interfaces ────────────────────────────────────────────────

    def process_esp32_scan(self, scan: dict) -> dict:
        """
        Main entry point called by Flask /api/scan endpoint.

        Input: raw ESP32 scan dict
        Output: response dict with threat_score, alert (if any), explanation
        """
        with self._lock:
            self._stats["scans_processed"] += 1

            # 1. Build feature vectors
            esp32_feat   = self._esp32_fb.build(scan)
            sniffer_feat = self._sniffer_fb.build()

            # 2. Combined feature vector (for LightGBM)
            combined_feat = np.concatenate([esp32_feat, sniffer_feat])

            # 3. IsolationForest score (ESP32 features only)
            iso_result = self._iso.score(esp32_feat)

            # 4. LightGBM score (combined features)
            lgbm_result = self._lgbm.score(combined_feat)

            # 5. Extract best AP meta for alert annotation
            scan_meta = self._extract_scan_meta(scan, iso_result)

            # 6. Fuse scores
            ml_result = self._scorer.fuse(iso_result, lgbm_result, scan_meta)

            # 7. Merge pending sniffer alerts
            pending_sniffer = list(self._sniffer_alert_buffer)
            self._sniffer_alert_buffer.clear()

            final_result = self._scorer.merge_sniffer_and_ml(ml_result, pending_sniffer)

            # 8. Feed into correlator
            if final_result.is_threat:
                self._correlator.feed(final_result.to_dict())
                self._stats["alerts_fired"] += 1

            # Feed sniffer alerts to correlator too
            for a in pending_sniffer:
                self._correlator.feed(a)

            # 9. Check for attack chains
            chains = self._correlator.get_chains()
            if chains:
                self._stats["chains_detected"] += len(chains)
                # Upgrade result if a chain confirms it
                best_chain = max(chains, key=lambda c: c.confidence)
                if best_chain.confidence > final_result.threat_score:
                    final_result.threat_score = best_chain.confidence
                    final_result.attack_type  = best_chain.chain_type
                    final_result.explanation  = best_chain.description
                    final_result.source       = "chain_correlator"
                    log.warning(
                        f"[CHAIN] {best_chain.chain_type} elevated score to "
                        f"{final_result.threat_score}%"
                    )

            # 10. Update stats and cache
            self._stats["lgbm_ready"]        = self._lgbm.is_ready
            self._stats["isoforest_trained"] = self._iso._trained
            self._latest = final_result
            self._sniffer_fb.reset_window()

            return final_result.to_dict()

    def feed_sniffer_alert(self, alert: dict):
        """
        Called by the sniffer thread when a new alert fires.
        Thread-safe — buffers the alert for the next ESP32 scan cycle.
        """
        with self._lock:
            self._sniffer_alert_buffer.append(alert)
            # Also feed correlator immediately for chain detection
            self._correlator.feed(alert)
            self._sniffer_fb.feed(alert)

    def add_baseline_scan(self, scan: dict):
        """
        Explicitly mark a scan as clean baseline (trusted environment).
        Call this from setup/calibration mode.
        """
        with self._lock:
            feat = self._esp32_fb.build(scan)
            self._iso.add_baseline(feat)

    @property
    def latest_result(self) -> dict | None:
        """Return the most recent ThreatResult as a dict (for WebSocket push)."""
        with self._lock:
            return self._latest.to_dict() if self._latest else None

    def get_status(self) -> dict:
        """Return detector health/stats for the /api/health endpoint."""
        with self._lock:
            return {
                **self._stats,
                "buffer_size":      len(self._sniffer_alert_buffer),
                "correlator_events": self._correlator.get_event_summary(),
            }

    # ─── Internal helpers ──────────────────────────────────────────────────

    def _extract_scan_meta(self, scan: dict, iso_result: dict) -> dict:
        """
        Pull the most suspicious network from the scan for alert annotation.
        Priority: RSSI outliers → open networks → first network.
        """
        networks = scan.get("networks", [])
        if not networks:
            return {}

        # If IsoForest flagged rssi_outlier_count, find the strongest AP
        top = sorted(networks, key=lambda n: n.get("rssi", -100), reverse=True)

        # Prefer open networks (more suspicious)
        open_nets = [n for n in networks if n.get("enc_str") == "OPEN"]
        candidate = open_nets[0] if open_nets else top[0]

        return {
            "ssid":  candidate.get("ssid", ""),
            "bssid": candidate.get("bssid", ""),
            "rssi":  candidate.get("rssi", 0),
        }
