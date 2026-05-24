"""
lightgbm_model.py — Supervised LightGBM multi-class threat classifier.

Role in WiFiGhost AI:
  Where IsolationForest says "something is wrong", LightGBM says
  "here's EXACTLY what attack this is and at what confidence."

  Trained on labelled feature vectors (attack_type → feature vector).
  Falls back gracefully if no trained model exists (returns None score).

Classes (attack types):
  0 = NORMAL
  1 = EVIL_TWIN
  2 = DEAUTH_FLOOD
  3 = BEACON_FLOOD
  4 = KARMA_AP
  5 = PMKID_ATTEMPT
  6 = PROBE_HARVESTING
  7 = ROGUE_AP

Training data:
  Run train_model.py to generate synthetic training data and train.
  Or supply your own CSV via --dataset flag.

Features:
  Combined ESP32 + Sniffer feature vector
  (len(ESP32_FEATURE_NAMES) + len(SNIFFER_FEATURE_NAMES) = 40 features)
"""

import os
import pickle
import logging
import numpy as np

log = logging.getLogger("wifighost.lgbm")

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "lgbm_model.pkl")

# Class label map — index must match training
ATTACK_CLASSES = {
    0: "NORMAL",
    1: "EVIL_TWIN",
    2: "DEAUTH_FLOOD",
    3: "BEACON_FLOOD",
    4: "KARMA_AP",
    5: "PMKID_ATTEMPT",
    6: "PROBE_HARVESTING",
    7: "ROGUE_AP",
}

# Confidence thresholds — below MIN_CONFIDENCE, defer to IsoForest
MIN_CONFIDENCE = 45


class LGBMDetector:
    """
    Wraps a trained LightGBM classifier.
    If no model is found, score() returns None so the engine
    falls back to IsolationForest only.
    """

    def __init__(self, model_path: str = MODEL_PATH):
        self.model_path = model_path
        self._model     = None
        self._classes   = None
        self._try_load()

    @property
    def is_ready(self) -> bool:
        return self._model is not None

    def score(self, features: np.ndarray) -> dict | None:
        """
        Score a combined feature vector.
        Returns None if model not trained yet.

        Returns:
          {
            "attack_type": "EVIL_TWIN",
            "confidence":  87,
            "all_probs":   {"NORMAL": 0.05, "EVIL_TWIN": 0.87, ...},
            "is_threat":   True,
          }
        """
        if not self.is_ready:
            return None

        try:
            x     = features.reshape(1, -1)
            probs = self._model.predict_proba(x)[0]
            idx   = int(np.argmax(probs))
            conf  = int(probs[idx] * 100)

            attack_type = ATTACK_CLASSES.get(idx, "UNKNOWN")
            is_threat   = (attack_type != "NORMAL") and (conf >= MIN_CONFIDENCE)

            all_probs = {
                ATTACK_CLASSES.get(i, str(i)): round(float(p), 3)
                for i, p in enumerate(probs)
            }

            return {
                "attack_type": attack_type,
                "confidence":  conf,
                "all_probs":   all_probs,
                "is_threat":   is_threat,
                "class_idx":   idx,
            }
        except Exception as e:
            log.error(f"[LGBM] score() error: {e}")
            return None

    def load(self, path: str = None):
        """Reload model from disk (e.g. after train_model.py runs)."""
        self._try_load(path or self.model_path)

    # ─── Internal ──────────────────────────────────────────────────────────

    def _try_load(self, path: str = None):
        path = path or self.model_path
        if not os.path.exists(path):
            log.info(
                f"[LGBM] No trained model at {path}. "
                "Run ml/train_model.py to train. "
                "IsolationForest will handle detection until then."
            )
            return
        try:
            with open(path, "rb") as f:
                data = pickle.load(f)
            self._model   = data["model"]
            self._classes = data.get("classes", ATTACK_CLASSES)
            log.info(f"[LGBM] Model loaded from {path}")
        except Exception as e:
            log.warning(f"[LGBM] Could not load model: {e}")


def save_model(model, path: str = MODEL_PATH):
    """Save a trained LightGBM pipeline to disk."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        pickle.dump({"model": model, "classes": ATTACK_CLASSES}, f)
    log.info(f"[LGBM] Model saved to {path}")
