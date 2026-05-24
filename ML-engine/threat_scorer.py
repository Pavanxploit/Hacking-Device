"""
threat_scorer.py — Fuse IsolationForest and LightGBM outputs into a
single calibrated ThreatResult with confidence score and explanation.

Fusion strategy:
  1. If LightGBM is trained and confident (>= 60%):
       Use LightGBM attack type + confidence, boost by IsoForest score
  2. If LightGBM is trained but uncertain (< 60%):
       Blend: 40% LightGBM + 60% IsoForest
  3. If LightGBM not trained:
       Use IsoForest score only, attack type = "ANOMALY"

Final score is always 0–100. Threat level is derived from score thresholds.
"""

import time
import logging
from dataclasses import dataclass, field

log = logging.getLogger("wifighost.scorer")

# Confidence thresholds matching ESP32 config.h
THRESHOLD_LOW      = 30
THRESHOLD_MEDIUM   = 50
THRESHOLD_HIGH     = 70
THRESHOLD_CRITICAL = 88

# Weight of LightGBM vs IsoForest when blending
LGBM_WEIGHT      = 0.65
ISO_WEIGHT       = 0.35
LGBM_HIGH_THRESH = 60   # above this, trust LightGBM fully


@dataclass
class ThreatResult:
    """Final fused threat assessment for one scan/event cycle."""
    # Core
    threat_score:   int          # 0–100
    threat_level:   str          # "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    is_threat:      bool

    # Alert details (populated when is_threat=True)
    attack_type:    str          # e.g. "EVIL_TWIN", "DEAUTH_FLOOD", "ANOMALY"
    confidence:     int          # 0–100 — how sure we are of the attack type
    ssid:           str = ""
    bssid:          str = ""
    rssi:           int = 0

    # Explanation
    explanation:    str = ""     # plain-English reason
    top_features:   list = field(default_factory=list)
    all_probs:      dict = field(default_factory=dict)

    # Source info
    source:         str = "ml"   # "ml" | "sniffer" | "hybrid"
    ts:             float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "threat_score":  self.threat_score,
            "threat_level":  self.threat_level,
            "is_threat":     self.is_threat,
            "alert": {
                "type":       self.attack_type,
                "confidence": self.confidence,
                "ssid":       self.ssid,
                "bssid":      self.bssid,
                "rssi":       self.rssi,
            } if self.is_threat else None,
            "explanation":   self.explanation,
            "top_features":  self.top_features,
            "all_probs":     self.all_probs,
            "source":        self.source,
            "ts":            self.ts,
        }


def _threat_level(score: int) -> str:
    if score >= THRESHOLD_CRITICAL: return "CRITICAL"
    if score >= THRESHOLD_HIGH:     return "HIGH"
    if score >= THRESHOLD_MEDIUM:   return "MEDIUM"
    if score >= THRESHOLD_LOW:      return "LOW"
    return "NONE"


def _explain(attack_type: str, confidence: int,
             top_features: list, source: str) -> str:
    """Generate a plain-English explanation string."""
    explanations = {
        "EVIL_TWIN":
            "A rogue AP is broadcasting the same SSID as a trusted network "
            "but with a different MAC address. This is a classic man-in-the-middle setup.",
        "DEAUTH_FLOOD":
            "A burst of deauthentication frames was detected. An attacker is "
            "forcibly disconnecting clients — likely to redirect them to a rogue AP.",
        "BEACON_FLOOD":
            "Hundreds of fake SSID beacons are being broadcast. This is the mdk3/mdk4 "
            "beacon flood attack designed to overwhelm client Wi-Fi managers.",
        "KARMA_AP":
            "A rogue AP is responding to probe requests with matching SSIDs — "
            "impersonating any network a client device is searching for.",
        "PMKID_ATTEMPT":
            "EAPOL handshake frames were captured without a prior authentication. "
            "This matches the PMKID offline cracking attack (CVE-2018-PMKID).",
        "PROBE_HARVESTING":
            "A device is broadcasting rapid probe requests, harvesting SSID histories "
            "from nearby clients to profile target networks.",
        "ROGUE_AP":
            "An access point with anomalous properties was detected — "
            "wrong encryption, unusual signal strength, or unknown MAC vendor.",
        "ANOMALY":
            "The Wi-Fi environment deviates significantly from the learned baseline. "
            "The exact attack type is unknown — manual inspection recommended.",
        "NORMAL":
            "Wi-Fi environment is within normal parameters.",
    }
    base = explanations.get(attack_type, "Unusual wireless activity detected.")

    if top_features:
        feat_names = ", ".join(name for name, _ in top_features[:3])
        base += f" Key indicators: {feat_names}."

    base += f" Confidence: {confidence}%. Source: {source}."
    return base


class ThreatScorer:
    """
    Fuses IsolationForest and LightGBM outputs.
    Also accepts raw sniffer alerts (from SnifferEngine queue) and
    merges them with ML scores for a final result.
    """

    def fuse(self,
             iso_result:  dict,
             lgbm_result: dict | None,
             scan_meta:   dict | None = None) -> ThreatResult:
        """
        Fuse IsoForest + LightGBM outputs.

        iso_result:  output of IsoForestDetector.score()
        lgbm_result: output of LGBMDetector.score() or None
        scan_meta:   optional dict with ssid, bssid, rssi from the triggering scan
        """
        iso_score = iso_result.get("anomaly_score", 0)
        iso_feats = iso_result.get("top_features", [])

        # ── Case 1: LightGBM trained and confident ─────────────────────────
        if lgbm_result and lgbm_result.get("confidence", 0) >= LGBM_HIGH_THRESH:
            lgbm_conf    = lgbm_result["confidence"]
            attack_type  = lgbm_result["attack_type"]
            is_threat    = lgbm_result["is_threat"]
            # Blend: mostly LightGBM confidence, modulated by IsoForest
            blended = int(lgbm_conf * LGBM_WEIGHT + iso_score * ISO_WEIGHT)
            final_score = min(100, blended)
            source = "hybrid"

        # ── Case 2: LightGBM trained but uncertain ─────────────────────────
        elif lgbm_result:
            lgbm_conf   = lgbm_result.get("confidence", 0)
            attack_type = lgbm_result.get("attack_type", "ANOMALY")
            is_threat   = iso_score >= THRESHOLD_MEDIUM
            blended     = int(lgbm_conf * 0.4 + iso_score * 0.6)
            final_score = min(100, blended)
            source      = "hybrid_uncertain"

        # ── Case 3: IsolationForest only ───────────────────────────────────
        else:
            attack_type = "ANOMALY"
            is_threat   = iso_score >= THRESHOLD_MEDIUM
            final_score = iso_score
            lgbm_conf   = 0
            source      = "isolation_forest"

        # Override: if IsoForest is very confident, boost the score
        if iso_score >= 90 and final_score < 80:
            final_score = max(final_score, 80)

        threat_level = _threat_level(final_score)
        confidence   = lgbm_result["confidence"] if lgbm_result else iso_score

        meta = scan_meta or {}
        explanation = _explain(
            attack_type, confidence, iso_feats, source
        )

        return ThreatResult(
            threat_score = final_score,
            threat_level = threat_level,
            is_threat    = is_threat and final_score >= THRESHOLD_LOW,
            attack_type  = attack_type,
            confidence   = confidence,
            ssid         = meta.get("ssid", ""),
            bssid        = meta.get("bssid", ""),
            rssi         = meta.get("rssi", 0),
            explanation  = explanation,
            top_features = iso_feats,
            all_probs    = lgbm_result.get("all_probs", {}) if lgbm_result else {},
            source       = source,
        )

    def from_sniffer_alert(self, alert: dict) -> ThreatResult:
        """
        Convert a raw sniffer alert (from SnifferEngine) directly to a
        ThreatResult without going through ML models.
        Used when the sniffer rule engine is more certain than ML.
        """
        alert_type = alert.get("alert_type", "UNKNOWN")
        confidence = alert.get("confidence", 50)
        score      = confidence   # sniffer confidence IS the score

        # Sniffer alerts for these attack types are high-fidelity
        HIGH_FIDELITY = {"DEAUTH_FLOOD", "EVIL_TWIN", "BEACON_FLOOD",
                         "KARMA_AP", "PMKID_ATTEMPT", "BROADCAST_DEAUTH",
                         "EVIL_TWIN_PREP", "HANDSHAKE_CAPTURE"}

        if alert_type in HIGH_FIDELITY:
            score = min(100, confidence + 10)  # small boost for rule-based detection

        explanation = _explain(
            alert_type,
            confidence,
            [],
            "sniffer_rules",
        )

        return ThreatResult(
            threat_score = score,
            threat_level = _threat_level(score),
            is_threat    = score >= THRESHOLD_LOW,
            attack_type  = alert_type,
            confidence   = confidence,
            ssid         = alert.get("ssid", ""),
            bssid        = alert.get("bssid", ""),
            rssi         = alert.get("rssi", 0),
            explanation  = explanation,
            top_features = [],
            all_probs    = {},
            source       = "sniffer",
        )

    def merge_sniffer_and_ml(self,
                              ml_result:      ThreatResult,
                              sniffer_alerts: list[dict]) -> ThreatResult:
        """
        If sniffer alerts exist in the same cycle as ML result,
        take the maximum-confidence result and annotate it.
        """
        if not sniffer_alerts:
            return ml_result

        # Build sniffer ThreatResults
        sniffer_results = [self.from_sniffer_alert(a) for a in sniffer_alerts]
        best_sniffer    = max(sniffer_results, key=lambda r: r.threat_score)

        # Take whichever is higher confidence
        if best_sniffer.threat_score > ml_result.threat_score:
            best_sniffer.source = "sniffer+ml"
            # Annotate with ML probabilities if available
            best_sniffer.all_probs = ml_result.all_probs
            return best_sniffer

        ml_result.source = "ml+sniffer"
        return ml_result
