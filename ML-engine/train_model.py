"""
train_model.py — Train the LightGBM threat classifier for WiFiGhost AI.

Usage:
    # Train on synthetic data (works immediately, no real captures needed)
    python3 ml/train_model.py

    # Train on your own labelled CSV
    python3 ml/train_model.py --dataset data/captures.csv

    # Generate synthetic data only (no training)
    python3 ml/train_model.py --gen-only

Synthetic data:
    The generator creates realistic feature vectors for each attack class
    based on the documented signatures of each attack type.
    This gives the model a strong prior — real capture data will fine-tune it.

Output:
    data/lgbm_model.pkl   — trained model
    data/training_report.txt — accuracy, confusion matrix, feature importance
"""

import os
import sys
import argparse
import logging
import json
import pickle
from datetime import datetime

import numpy as np

# Try to import ML libraries, give clear error if missing
try:
    import lightgbm as lgb
    from sklearn.model_selection import StratifiedKFold, cross_val_score
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.preprocessing import LabelEncoder
except ImportError as e:
    print(f"\n[!] Missing ML library: {e}")
    print("    Install with: pip install lightgbm scikit-learn --break-system-packages\n")
    sys.exit(1)

from feature_builder import (
    ESP32_FEATURE_NAMES, SNIFFER_FEATURE_NAMES
)

log = logging.getLogger("wifighost.trainer")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s: %(message)s")

ALL_FEATURES = ESP32_FEATURE_NAMES + SNIFFER_FEATURE_NAMES
N_FEATURES   = len(ALL_FEATURES)

MODEL_PATH  = os.path.join(os.path.dirname(__file__), "..", "data", "lgbm_model.pkl")
REPORT_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "training_report.txt")

# ── Class definitions ───────────────────────────────────────────────────────
CLASSES = {
    "NORMAL":          0,
    "EVIL_TWIN":       1,
    "DEAUTH_FLOOD":    2,
    "BEACON_FLOOD":    3,
    "KARMA_AP":        4,
    "PMKID_ATTEMPT":   5,
    "PROBE_HARVESTING":6,
    "ROGUE_AP":        7,
}


def _rng(seed=None):
    return np.random.default_rng(seed)


# ── Synthetic data generators (one per class) ───────────────────────────────

def _normal(n: int, rng) -> np.ndarray:
    """Typical home/office scan: 5-20 APs, mostly WPA2, stable."""
    rows = []
    for _ in range(n):
        total  = rng.integers(5, 20)
        open_n = rng.integers(0, 2)
        row = [
            # ESP32 features
            total, open_n, 0, rng.integers(1,4), total-open_n-1, 0,
            float(rng.integers(-75,-40)), float(rng.integers(5,20)),
            float(rng.integers(-90,-70)), float(rng.integers(-35,-25)),
            rng.integers(0,2),
            rng.integers(2,6), float(rng.uniform(1.5,2.5)), rng.integers(3,8),
            0, float(rng.uniform(0.8,1.1)), float(rng.uniform(0.7,1.0)), 0,
            open_n/max(total,1), float(rng.uniform(0,0.2)),
            0, float(rng.integers(100,500)),
            rng.integers(0,2000), rng.integers(0,2), rng.integers(0,2),
            # Sniffer features
            0, 0, 0.0, 0.0,
            float(rng.uniform(0,5)), 1.0, 0, 0,
            rng.integers(0,3), float(rng.uniform(0.5,1.0)), float(rng.uniform(0.3,0.7)),
            0, 0,
            0, float(rng.uniform(0,0.3)),
        ]
        rows.append(row)
    return np.array(rows, dtype=np.float32)


def _evil_twin(n: int, rng) -> np.ndarray:
    """Evil twin: duplicate SSID, new unknown BSSID, often stronger signal."""
    rows = []
    for _ in range(n):
        total = rng.integers(8, 25)
        row = [
            total, 0, 0, rng.integers(1,3), total-2, 0,
            float(rng.integers(-60,-30)), float(rng.integers(20,40)),
            float(rng.integers(-85,-60)), float(rng.integers(-20,-10)),
            rng.integers(2,6),   # multiple strong signals
            rng.integers(2,5), float(rng.uniform(1.0,2.0)), rng.integers(3,8),
            rng.integers(1,4),   # duplicate SSIDs — KEY SIGNAL
            float(rng.uniform(1.2,2.0)),   # high ssid_bssid_ratio
            float(rng.uniform(0.4,0.7)),   # lower OUI diversity (cloned MACs)
            rng.integers(0,2),
            0.0, 0.1,
            rng.integers(1,3),   # RSSI outliers (strong rogue AP)
            float(rng.integers(400,900)),
            rng.integers(0,1000), rng.integers(1,4), 0,
            # Sniffer
            rng.integers(3,12),  # deauth activity
            rng.integers(1,3), float(rng.uniform(0.5,1.0)), float(rng.uniform(0.5,1.5)),
            float(rng.uniform(5,20)), float(rng.uniform(2,6)),
            rng.integers(1,3),   # evil twin candidates — KEY
            rng.integers(0,2),
            rng.integers(1,5), float(rng.uniform(0.3,0.7)), float(rng.uniform(0.3,0.6)),
            rng.integers(0,2), 0,
            1,                   # deauth_then_beacon — KEY
            float(rng.uniform(0.5,0.9)),
        ]
        rows.append(row)
    return np.array(rows, dtype=np.float32)


def _deauth_flood(n: int, rng) -> np.ndarray:
    """Deauth flood: burst of deauth frames, normal beacon environment."""
    rows = []
    for _ in range(n):
        total = rng.integers(5, 18)
        row = [
            total, 0, 0, rng.integers(1,3), total-2, 0,
            float(rng.integers(-75,-45)), float(rng.integers(8,18)),
            float(rng.integers(-85,-70)), float(rng.integers(-40,-25)),
            rng.integers(0,2),
            rng.integers(2,5), float(rng.uniform(1.5,2.2)), rng.integers(3,7),
            0, float(rng.uniform(0.9,1.1)), float(rng.uniform(0.8,1.0)), 0,
            0.0, 0.1,
            0, float(rng.integers(100,300)),
            rng.integers(0,1500), rng.integers(0,2), rng.integers(0,1),
            # Sniffer — KEY: high deauth counts
            rng.integers(10,50),  # deauth_count_window
            rng.integers(1,3),    # deauth_unique_src
            float(rng.uniform(0.6,1.0)),   # broadcast ratio
            float(rng.uniform(0.0,0.8)),   # reason entropy
            float(rng.uniform(0,3)), 1.0, 0, 0,
            rng.integers(1,4), float(rng.uniform(0.3,0.8)), float(rng.uniform(0.3,0.6)),
            0, 0,
            0, float(rng.uniform(0.6,1.0)),   # high channel concentration
        ]
        rows.append(row)
    return np.array(rows, dtype=np.float32)


def _beacon_flood(n: int, rng) -> np.ndarray:
    """Beacon flood (mdk3/mdk4): massive number of unique SSIDs."""
    rows = []
    for _ in range(n):
        total = rng.integers(50, 200)   # huge AP count — KEY
        row = [
            total, rng.integers(10,30), 0, rng.integers(5,15), total-40, rng.integers(5,15),
            float(rng.integers(-80,-50)), float(rng.integers(30,50)),
            float(rng.integers(-95,-80)), float(rng.integers(-35,-20)),
            rng.integers(2,8),
            rng.integers(8,13), float(rng.uniform(3.0,3.5)), rng.integers(10,25),
            rng.integers(20,80),     # huge duplicate SSID count — KEY
            float(rng.uniform(5,20)),  # very high ssid_bssid_ratio — KEY
            float(rng.uniform(0.1,0.3)),  # low OUI diversity (same MAC vendor) — KEY
            rng.integers(5,15),
            float(rng.uniform(0.3,0.8)), 0.2,
            rng.integers(5,20), float(rng.integers(800,2000)),
            rng.integers(500,3000), rng.integers(30,100), 0,
            # Sniffer
            0, 0, 0.0, 0.0,
            float(rng.uniform(30,100)),  # very high beacon rate — KEY
            float(rng.uniform(10,50)),   # many SSIDs per BSSID — KEY
            0, rng.integers(5,20),
            rng.integers(0,3), float(rng.uniform(0.5,1.0)), float(rng.uniform(0.3,0.6)),
            0, 0,
            0, float(rng.uniform(0.3,0.6)),
        ]
        rows.append(row)
    return np.array(rows, dtype=np.float32)


def _karma_ap(n: int, rng) -> np.ndarray:
    """Karma AP: one BSSID responding to many different probe SSIDs."""
    rows = []
    for _ in range(n):
        total = rng.integers(5, 15)
        row = [
            total, 0, 0, rng.integers(1,3), total-2, 0,
            float(rng.integers(-70,-40)), float(rng.integers(10,25)),
            float(rng.integers(-85,-65)), float(rng.integers(-30,-15)),
            rng.integers(1,4),
            rng.integers(2,5), float(rng.uniform(1.2,2.0)), rng.integers(3,7),
            rng.integers(2,6),
            float(rng.uniform(1.5,4.0)),   # high ssid per bssid
            float(rng.uniform(0.5,0.8)), 0,
            0.0, 0.1,
            rng.integers(1,3), float(rng.integers(200,500)),
            rng.integers(0,1500), rng.integers(1,5), 0,
            # Sniffer — KEY: karma indicators
            rng.integers(0,5), rng.integers(0,2), float(rng.uniform(0,0.3)), 0.0,
            float(rng.uniform(5,20)), float(rng.uniform(8,30)),   # many SSIDs per bssid — KEY
            0, rng.integers(0,3),
            rng.integers(5,20),   # high probe client count
            float(rng.uniform(0.3,0.8)),   # wildcard probe ratio
            float(rng.uniform(0.4,0.8)),
            0, 0,
            0, float(rng.uniform(0.4,0.8)),
        ]
        rows.append(row)
    return np.array(rows, dtype=np.float32)


def _pmkid(n: int, rng) -> np.ndarray:
    """PMKID attempt: EAPOL frames without prior auth."""
    rows = []
    for _ in range(n):
        total = rng.integers(5, 20)
        row = [
            total, 0, 0, rng.integers(1,3), total-2, 0,
            float(rng.integers(-75,-40)), float(rng.integers(8,20)),
            float(rng.integers(-85,-65)), float(rng.integers(-35,-20)),
            rng.integers(0,2),
            rng.integers(2,5), float(rng.uniform(1.5,2.5)), rng.integers(3,7),
            0, float(rng.uniform(0.9,1.1)), float(rng.uniform(0.7,1.0)), 0,
            0.0, 0.1,
            0, float(rng.integers(100,300)),
            rng.integers(0,1500), rng.integers(0,2), rng.integers(0,1),
            # Sniffer — KEY: EAPOL without auth
            rng.integers(0,5), rng.integers(0,2), float(rng.uniform(0,0.2)), 0.0,
            float(rng.uniform(0,3)), 1.0, 0, 0,
            rng.integers(0,3), float(rng.uniform(0.3,0.7)), float(rng.uniform(0.4,0.7)),
            rng.integers(3,15),    # eapol_count_window — KEY
            rng.integers(2,10),    # eapol_without_auth — KEY
            0, float(rng.uniform(0.5,0.9)),
        ]
        rows.append(row)
    return np.array(rows, dtype=np.float32)


def _probe_harvesting(n: int, rng) -> np.ndarray:
    """Probe harvesting: rapid probe requests from one or few clients."""
    rows = []
    for _ in range(n):
        total = rng.integers(5, 18)
        row = [
            total, 0, 0, rng.integers(1,3), total-2, 0,
            float(rng.integers(-75,-45)), float(rng.integers(8,18)),
            float(rng.integers(-85,-70)), float(rng.integers(-40,-25)),
            rng.integers(0,2),
            rng.integers(2,5), float(rng.uniform(1.5,2.2)), rng.integers(3,7),
            0, float(rng.uniform(0.9,1.1)), float(rng.uniform(0.8,1.0)), 0,
            0.0, 0.1,
            0, float(rng.integers(100,300)),
            rng.integers(0,1500), rng.integers(0,2), rng.integers(0,1),
            # Sniffer — KEY: probe features
            0, 0, 0.0, 0.0,
            float(rng.uniform(0,3)), 1.0, 0, 0,
            rng.integers(8,25),    # high probe_client_count — KEY
            float(rng.uniform(0.6,1.0)),   # high wildcard ratio — KEY
            float(rng.uniform(0.1,0.4)),   # low randomised ratio (real MACs)
            0, 0,
            0, float(rng.uniform(0.2,0.5)),
        ]
        rows.append(row)
    return np.array(rows, dtype=np.float32)


def _rogue_ap(n: int, rng) -> np.ndarray:
    """Rogue AP: unknown BSSID/OUI, open network, suspiciously strong signal."""
    rows = []
    for _ in range(n):
        total = rng.integers(6, 20)
        row = [
            total, rng.integers(1,3), 0, rng.integers(1,3), total-4, 0,
            float(rng.integers(-65,-30)), float(rng.integers(20,35)),
            float(rng.integers(-85,-65)), float(rng.integers(-15,-5)),   # strong RSSI
            rng.integers(2,5),
            rng.integers(2,5), float(rng.uniform(1.2,2.0)), rng.integers(2,5),
            rng.integers(1,3),
            float(rng.uniform(1.0,1.8)),
            float(rng.uniform(0.3,0.6)),   # low OUI diversity — KEY
            rng.integers(1,4),
            float(rng.uniform(0.1,0.4)),   # some open networks
            0.2,
            rng.integers(1,4),    # RSSI outliers — KEY
            float(rng.integers(400,800)),
            rng.integers(0,1500), rng.integers(1,4), 0,
            # Sniffer
            rng.integers(0,6), rng.integers(0,2), float(rng.uniform(0,0.4)), 0.0,
            float(rng.uniform(1,8)), float(rng.uniform(1,3)),
            rng.integers(0,2),   # some evil twin candidates
            rng.integers(0,2),
            rng.integers(1,5), float(rng.uniform(0.2,0.6)), float(rng.uniform(0.3,0.6)),
            0, 0,
            0, float(rng.uniform(0.3,0.6)),
        ]
        rows.append(row)
    return np.array(rows, dtype=np.float32)


# ── Data generation ─────────────────────────────────────────────────────────

def generate_dataset(n_per_class: int = 500, seed: int = 42) -> tuple:
    rng = _rng(seed)
    generators = [
        ("NORMAL",           _normal),
        ("EVIL_TWIN",        _evil_twin),
        ("DEAUTH_FLOOD",     _deauth_flood),
        ("BEACON_FLOOD",     _beacon_flood),
        ("KARMA_AP",         _karma_ap),
        ("PMKID_ATTEMPT",    _pmkid),
        ("PROBE_HARVESTING", _probe_harvesting),
        ("ROGUE_AP",         _rogue_ap),
    ]
    X_parts, y_parts = [], []
    for name, gen_fn in generators:
        label = CLASSES[name]
        data  = gen_fn(n_per_class, rng)
        # Add small noise to prevent overfitting
        data += rng.normal(0, 0.05, data.shape).astype(np.float32)
        X_parts.append(data)
        y_parts.append(np.full(n_per_class, label, dtype=np.int32))
        log.info(f"  Generated {n_per_class} samples for {name}")

    X = np.vstack(X_parts)
    y = np.concatenate(y_parts)
    return X, y


# ── Training ────────────────────────────────────────────────────────────────

def train(X: np.ndarray, y: np.ndarray) -> object:
    log.info(f"Training LightGBM on {len(X)} samples, {X.shape[1]} features...")

    model = lgb.LGBMClassifier(
        n_estimators      = 400,
        learning_rate     = 0.05,
        max_depth         = 8,
        num_leaves        = 63,
        min_child_samples = 10,
        subsample         = 0.8,
        colsample_bytree  = 0.8,
        class_weight      = "balanced",
        random_state      = 42,
        n_jobs            = -1,
        verbose           = -1,
    )

    # Cross-validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(model, X, y, cv=cv, scoring="f1_macro", n_jobs=-1)
    log.info(f"CV F1-macro: {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")

    model.fit(X, y)
    return model


# ── Report ──────────────────────────────────────────────────────────────────

def write_report(model, X: np.ndarray, y: np.ndarray, path: str):
    from sklearn.model_selection import train_test_split
    _, X_test, _, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    y_pred = model.predict(X_test)

    names = list(CLASSES.keys())
    report = classification_report(y_test, y_pred, target_names=names)
    cm     = confusion_matrix(y_test, y_pred)

    fi = sorted(
        zip(ALL_FEATURES, model.feature_importances_),
        key=lambda x: x[1], reverse=True
    )

    lines = [
        f"WiFiGhost AI — LightGBM Training Report",
        f"Generated: {datetime.now().isoformat()}",
        f"Samples: {len(X)} | Features: {X.shape[1]}",
        "", "Classification Report:", report,
        "", "Top 15 Feature Importances:",
        *[f"  {i+1:2}. {name:<35} {imp:.1f}" for i, (name, imp) in enumerate(fi[:15])],
        "", "Confusion Matrix (rows=actual, cols=predicted):",
        "       " + "  ".join(f"{n[:6]:>6}" for n in names),
    ]
    for i, row in enumerate(cm):
        lines.append(f"  {names[i][:6]:>6} " + "  ".join(f"{v:>6}" for v in row))

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write("\n".join(lines))

    log.info(f"Report written to {path}")
    print("\n" + "\n".join(lines))


# ── Entry point ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="WiFiGhost AI — LightGBM trainer")
    parser.add_argument("--n",        type=int, default=600, help="Samples per class")
    parser.add_argument("--seed",     type=int, default=42)
    parser.add_argument("--gen-only", action="store_true", help="Generate data only, no training")
    parser.add_argument("--dataset",  type=str, default=None, help="Path to real CSV dataset")
    args = parser.parse_args()

    os.makedirs(os.path.join(os.path.dirname(__file__), "..", "data"), exist_ok=True)

    if args.dataset:
        import pandas as pd
        log.info(f"Loading real dataset from {args.dataset}...")
        df = pd.read_csv(args.dataset)
        X  = df[ALL_FEATURES].values.astype(np.float32)
        y  = LabelEncoder().fit_transform(df["label"])
    else:
        log.info(f"Generating synthetic dataset ({args.n} samples/class)...")
        X, y = generate_dataset(n_per_class=args.n, seed=args.seed)

    if args.gen_only:
        log.info("--gen-only: skipping training.")
        return

    model = train(X, y)
    write_report(model, X, y, REPORT_PATH)

    # Save via lightgbm_model.save_model()
    from lightgbm_model import save_model
    save_model(model, MODEL_PATH)
    log.info(f"\n✓ Model saved to {MODEL_PATH}")
    log.info("✓ Reload in backend with: lgbm_detector.load()")


if __name__ == "__main__":
    main()
