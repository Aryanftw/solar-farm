"""
ML Anomaly Detector — B4
IsolationForest trained ONLY on normal lab traffic.
Features extracted per time window per source IP.

WARNING: This model is trained on synthetic lab baseline only.
         It has NOT been validated against real solar farm traffic.
         Use in conjunction with deterministic rules.
"""

import hashlib
import json
import logging
import os
import joblib
import numpy as np
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

_DEFAULT_MODEL_DIR = (
    "/app/data"
    if os.path.exists("/app/data") or (os.name != "nt" and os.path.exists("/app"))
    else os.path.abspath(os.path.join(os.path.dirname(__file__), "../../data"))
)
MODEL_DIR = os.getenv("MODEL_DIR", _DEFAULT_MODEL_DIR)
MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")
META_PATH = os.path.join(MODEL_DIR, "model_meta.json")

FEATURE_NAMES = [
    "total_requests",
    "read_count",
    "write_count",
    "write_to_read_ratio",
    "distinct_dst_devices",
    "new_source",
    "request_rate_deviation",
    "iec104_command_count",
]

RANDOM_SEED = 42
CONTAMINATION = 0.05   # expected fraction of anomalies


def _load_model() -> Tuple[Optional[IsolationForest], Optional[StandardScaler], Optional[dict]]:
    if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
        try:
            model = joblib.load(MODEL_PATH)
            scaler = joblib.load(SCALER_PATH)
            meta = {}
            if os.path.exists(META_PATH):
                with open(META_PATH) as f:
                    meta = json.load(f)
            logger.info("Loaded ML model from %s (version: %s)", MODEL_PATH, meta.get("version"))
            return model, scaler, meta
        except Exception as exc:
            logger.error("Failed to load ML model: %s", exc)
    return None, None, None


def _extract_features_from_windows(conn, window_s: int = 60) -> list:
    """Extract feature rows from baseline_windows table for training."""
    rows = conn.execute(
        "SELECT * FROM baseline_windows WHERE labelled='normal'"
    ).fetchall()
    features = []
    for r in rows:
        feat = [
            r["total_requests"] or 0,
            r["read_count"] or 0,
            r["write_count"] or 0,
            r["write_to_read_ratio"] or 0.0,
            r["distinct_dst_devices"] or 0,
            r["new_source"] or 0,
            r["request_rate_deviation"] or 0.0,
            r["iec104_command_count"] or 0,
        ]
        features.append(feat)
    return features


def train_model(conn) -> dict:
    """
    Train IsolationForest on normal baseline windows from the database.
    Persists model, scaler, and metadata.
    """
    logger.info("Starting IsolationForest training on normal baseline...")
    features = _extract_features_from_windows(conn)

    if len(features) < 10:
        raise ValueError(
            f"Need at least 10 normal baseline windows to train; got {len(features)}. "
            "Run 'make baseline' first to generate normal traffic data."
        )

    X = np.array(features, dtype=float)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=100,
        contamination=CONTAMINATION,
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )
    model.fit(X_scaled)

    # Save model + scaler
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    meta = {
        "version": hashlib.sha256(now.encode()).hexdigest()[:8],
        "trained_at_utc": now,
        "n_samples": len(features),
        "feature_names": FEATURE_NAMES,
        "contamination": CONTAMINATION,
        "random_seed": RANDOM_SEED,
        "warning": "Trained on synthetic lab baseline only. Not validated against real solar farm traffic.",
    }
    with open(META_PATH, "w") as f:
        json.dump(meta, f, indent=2)

    logger.info("Model trained on %d samples. Saved to %s", len(features), MODEL_PATH)
    return meta


def score_window(
    conn,
    src_ip: str,
    window_s: int = 60,
) -> Optional[Tuple[float, str, dict]]:
    """
    Compute features for the last window_s seconds from src_ip, score it.
    Returns (anomaly_score, explanation, feature_dict) or None if model not loaded.
    """
    model, scaler, meta = _load_model()
    if model is None:
        return None

    from datetime import timezone
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_s)).strftime("%Y-%m-%dT%H:%M:%SZ")
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Count requests in window
    rows = conn.execute(
        "SELECT * FROM events WHERE src_ip=? AND timestamp_utc >= ?",
        (src_ip, cutoff),
    ).fetchall()

    total = len(rows)
    reads = sum(1 for r in rows if r["function_code"] in (3, 4, 1, 2))
    writes = sum(1 for r in rows if r["function_code"] in (5, 6, 15, 16))
    wtr = writes / max(reads, 1)
    distinct_dst = len(set(r["dst_ip"] for r in rows if r["dst_ip"]))
    new_source = 0  # computed separately via inventory

    # Rate deviation: requests/minute vs expected 20/min
    expected_rate = 20.0
    observed_rate = total / (window_s / 60.0)
    rate_dev = abs(observed_rate - expected_rate) / max(expected_rate, 1)

    iec104_cmds = sum(1 for r in rows if r["protocol"] == "iec60870-5-104")

    feat_dict = {
        "total_requests": total,
        "read_count": reads,
        "write_count": writes,
        "write_to_read_ratio": wtr,
        "distinct_dst_devices": distinct_dst,
        "new_source": new_source,
        "request_rate_deviation": rate_dev,
        "iec104_command_count": iec104_cmds,
    }

    X = np.array([[feat_dict[f] for f in FEATURE_NAMES]], dtype=float)

    try:
        X_scaled = scaler.transform(X)
        score = float(model.score_samples(X_scaled)[0])

        # Identify elevated features (deviates from mean by > 1 std)
        top_features = []
        means = scaler.mean_
        stds = scaler.scale_
        for i, fname in enumerate(FEATURE_NAMES):
            if stds[i] > 0 and abs((X[0][i] - means[i]) / stds[i]) > 1.5:
                top_features.append(f"{fname}={X[0][i]:.2f}")

        explanation = (
            f"Anomaly score {score:.4f} (threshold ~-0.10). "
            f"Elevated features: {', '.join(top_features) if top_features else 'none above 1.5σ'}. "
            "Model trained on synthetic lab normal-only baseline."
        )

        return score, explanation, feat_dict
    except Exception as exc:
        logger.error("ML scoring failed: %s", exc)
        return None


def get_model_status() -> dict:
    """Return current model status for dashboard display."""
    model, scaler, meta = _load_model()
    if model is None:
        return {"loaded": False, "message": "Model not trained. Run 'make baseline' then the model will train automatically."}
    return {
        "loaded": True,
        "version": meta.get("version", "unknown"),
        "trained_at_utc": meta.get("trained_at_utc"),
        "n_samples": meta.get("n_samples"),
        "feature_names": meta.get("feature_names", FEATURE_NAMES),
        "contamination": meta.get("contamination"),
        "warning": meta.get("warning"),
    }
