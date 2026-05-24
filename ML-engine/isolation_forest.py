"""
isolation_forest.py — Isolation Forest anomaly detector.

Role in WiFiGhost AI:
  This is the BASELINE model — it works from day 1 with zero labelled data.
  It learns what "normal" looks like in YOUR environment (home/office/lab)
  and flags deviations as anomalies.

  It runs on ESP32 scan features (station-mode view).
  LightGBM (lightgbm_model.py) runs in parallel for supervised detection.

Training:
  Feed it ~50-100 clean scans from a known-safe environment.
  It auto-trains on first run if a saved model isn't found.
  Re-trains every RETRAIN_INTERVAL new samples to adapt to environment changes.
"""

import os
import pickle
import logging
import time
from collections import deque

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

from .feature_builder import ESP32_FEATURE_NAMES

log = logging.getLogger("wifighost.isolation_forest")

# ── Config ─────────────────────────────────────────────────────────────────
MODEL_PATH       = os.path.join(os.path.dirname(__file__), "..", "data", "iso_forest.pkl")
MIN_TRAIN_SAMPLES = 30     # minimum scans needed before training
RETRAIN_INTERVAL  = 200    # retrain every N new samples
CONTAMINATION     = 0.05   # expected fraction of anomalies in training data
N_ESTIMATORS      = 200    # more trees = more stable scores
SCORE_SCALE       = 100    # map [-1, 0.5] → [0, 100]


class IsoForestDetector:
    """
    Wraps sklearn IsolationForest with:
      - Auto-train from accumulated normal scans
      - Persistent model save/load
      - Calibrated 0–100 confidence scores
      - Feature importance approximation via per-feature score delta
    """

    def __init__(self,
                 model_path:   str   = MODEL_PATH,
                 contamination: float = CONTAMINATION,
                 n_estimators: int   = N_ESTIMATORS):
        self.model_path    = model_path
        self.contamination = contamination
        self.n_estimators  = n_estimators

        self._model:   IsolationForest | None = None
        self._scaler:  RobustScaler | None    = None
        self._buffer:  deque                  = deque(maxlen=5000)
        self._n_seen:  int                    = 0
        self._trained: bool                   = False

        self._try_load()

    # ─── Public API ────────────────────────────────────────────────────────

    def score(self, features: np.ndarray) -> dict:
        """
        Score a feature vector.
        Returns:
          {
            "anomaly_score": 0–100,     # 0 = normal, 100 = very anomalous
            "is_anomaly": bool,
            "confidence": 0–100,        # alias for anomaly_score
            "trained": bool,
            "top_features": [(name, delta), ...]  # most anomalous features
          }
        """
        self._buffer.append(features.copy())
        self._n_seen += 1

        # Auto-train if we have enough data and aren't trained yet
        if not self._trained and len(self._buffer) >= MIN_TRAIN_SAMPLES:
            self.train(list(self._buffer))

        # Retrain periodically
        if self._trained and self._n_seen % RETRAIN_INTERVAL == 0:
            log.info(f"[IsoForest] Retraining on {len(self._buffer)} samples...")
            self.train(list(self._buffer))

        if not self._trained:
            return {
                "anomaly_score": 0,
                "is_anomaly":    False,
                "confidence":    0,
                "trained":       False,
                "top_features":  [],
                "note":          f"Collecting baseline ({len(self._buffer)}/{MIN_TRAIN_SAMPLES} scans)",
            }

        x      = self._scaler.transform(features.reshape(1, -1))
        raw    = float(self._model.score_samples(x)[0])
        score  = self._raw_to_score(raw)
        is_anom = self._model.predict(x)[0] == -1

        top_features = self._top_anomalous_features(features, score)

        return {
            "anomaly_score": score,
            "is_anomaly":    is_anom,
            "confidence":    score,
            "trained":       True,
            "top_features":  top_features,
            "raw_score":     round(raw, 4),
        }

    def train(self, samples: list[np.ndarray]):
        """Train (or retrain) on a list of feature vectors."""
        if len(samples) < MIN_TRAIN_SAMPLES:
            log.warning(f"[IsoForest] Not enough samples to train ({len(samples)})")
            return

        X = np.vstack(samples)

        self._scaler = RobustScaler()
        X_scaled     = self._scaler.fit_transform(X)

        self._model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            max_samples="auto",
            random_state=42,
            n_jobs=-1,
        )
        self._model.fit(X_scaled)
        self._trained = True

        self._save()
        log.info(f"[IsoForest] Trained on {len(samples)} samples.")

    def add_baseline(self, features: np.ndarray):
        """Explicitly add a known-clean scan to the training buffer."""
        self._buffer.append(features.copy())

    # ─── Internal ──────────────────────────────────────────────────────────

    def _raw_to_score(self, raw_score: float) -> int:
        """
        IsolationForest.score_samples returns values in [-0.5, 0].
        More negative = more anomalous.
        Map to [0, 100] where 100 = most anomalous.
        """
        # Typical range: [-0.15, 0.05] for this dataset
        clipped = max(-0.5, min(0.1, raw_score))
        normalised = (0.1 - clipped) / 0.6      # invert: lower raw = higher score
        return int(min(100, max(0, normalised * 100)))

    def _top_anomalous_features(self, features: np.ndarray,
                                 base_score: int,
                                 top_n: int = 5) -> list[tuple[str, int]]:
        """
        Approximate feature importance by ablation:
        replace each feature with its median and measure score delta.
        Features whose removal drops the score most = most anomalous.
        """
        if not self._trained or self._scaler is None:
            return []

        median = np.median(list(self._buffer), axis=0)
        deltas = []

        for i, name in enumerate(ESP32_FEATURE_NAMES):
            ablated       = features.copy()
            ablated[i]    = median[i]
            x_abl         = self._scaler.transform(ablated.reshape(1, -1))
            raw_abl       = float(self._model.score_samples(x_abl)[0])
            score_abl     = self._raw_to_score(raw_abl)
            delta         = base_score - score_abl   # positive = this feature contributed to anomaly
            deltas.append((name, delta))

        deltas.sort(key=lambda x: x[1], reverse=True)
        return [(name, int(d)) for name, d in deltas[:top_n] if d > 0]

    def _save(self):
        try:
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            with open(self.model_path, "wb") as f:
                pickle.dump({"model": self._model, "scaler": self._scaler}, f)
            log.info(f"[IsoForest] Model saved to {self.model_path}")
        except Exception as e:
            log.error(f"[IsoForest] Save failed: {e}")

    def _try_load(self):
        if not os.path.exists(self.model_path):
            return
        try:
            with open(self.model_path, "rb") as f:
                data = pickle.load(f)
            self._model   = data["model"]
            self._scaler  = data["scaler"]
            self._trained = True
            log.info(f"[IsoForest] Model loaded from {self.model_path}")
        except Exception as e:
            log.warning(f"[IsoForest] Could not load model: {e}")
