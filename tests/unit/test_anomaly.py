"""
Unit tests — ML Anomaly Detector (B4)
Tests IsolationForest training, window feature extraction, scoring, and status.
"""

import json
import os
import sqlite3
import pytest

import anomaly


@pytest.fixture
def temp_model_dir(tmp_path, monkeypatch):
    """Point model file paths to a temporary directory for isolation."""
    model_dir = str(tmp_path / "model")
    os.makedirs(model_dir, exist_ok=True)
    monkeypatch.setattr(anomaly, "MODEL_DIR", model_dir)
    monkeypatch.setattr(anomaly, "MODEL_PATH", os.path.join(model_dir, "isolation_forest.pkl"))
    monkeypatch.setattr(anomaly, "SCALER_PATH", os.path.join(model_dir, "scaler.pkl"))
    monkeypatch.setattr(anomaly, "META_PATH", os.path.join(model_dir, "model_meta.json"))
    return model_dir


@pytest.fixture
def db_with_baseline():
    """Create in-memory SQLite DB with schema and sample baseline windows."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE baseline_windows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            window_start_utc TEXT NOT NULL,
            window_end_utc TEXT NOT NULL,
            src_ip TEXT,
            total_requests INTEGER DEFAULT 0,
            read_count INTEGER DEFAULT 0,
            write_count INTEGER DEFAULT 0,
            write_to_read_ratio REAL DEFAULT 0.0,
            distinct_dst_devices INTEGER DEFAULT 0,
            new_source INTEGER DEFAULT 0,
            request_rate_deviation REAL DEFAULT 0.0,
            protocol TEXT,
            iec104_command_count INTEGER DEFAULT 0,
            labelled TEXT DEFAULT 'normal',
            anomaly_score REAL
        );

        CREATE TABLE events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc TEXT NOT NULL,
            source TEXT NOT NULL,
            src_ip TEXT,
            dst_ip TEXT,
            dst_port INTEGER,
            protocol TEXT,
            function_code INTEGER,
            register_address INTEGER,
            raw_value INTEGER,
            direction TEXT,
            asdu_type TEXT,
            ioa INTEGER,
            extra_json TEXT,
            scenario_id TEXT
        );
    """)

    # Populate 15 normal baseline windows
    for i in range(15):
        conn.execute("""
            INSERT INTO baseline_windows (
                window_start_utc, window_end_utc, src_ip, total_requests,
                read_count, write_count, write_to_read_ratio, distinct_dst_devices,
                new_source, request_rate_deviation, protocol, iec104_command_count, labelled
            ) VALUES (?, ?, '172.20.0.40', ?, ?, ?, ?, 3, 0, 0.05, 'modbus-tcp', 0, 'normal')
        """, (
            f"2026-10-22T10:{i:02d}:00Z",
            f"2026-10-22T10:{i:02d}:59Z",
            20 + (i % 3),
            19 + (i % 3),
            1,
            0.05,
        ))
    conn.commit()
    yield conn
    conn.close()


def test_model_status_unloaded(temp_model_dir):
    status = anomaly.get_model_status()
    assert status["loaded"] is False
    assert "not trained" in status["message"]


def test_train_model_fails_with_insufficient_samples(temp_model_dir):
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE baseline_windows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            total_requests INTEGER, read_count INTEGER, write_count INTEGER,
            write_to_read_ratio REAL, distinct_dst_devices INTEGER,
            new_source INTEGER, request_rate_deviation REAL,
            iec104_command_count INTEGER, labelled TEXT
        );
    """)
    with pytest.raises(ValueError, match="at least 10 normal baseline windows"):
        anomaly.train_model(conn)
    conn.close()


def test_train_model_success(temp_model_dir, db_with_baseline):
    meta = anomaly.train_model(db_with_baseline)
    assert meta["n_samples"] == 15
    assert "version" in meta
    assert os.path.exists(anomaly.MODEL_PATH)
    assert os.path.exists(anomaly.SCALER_PATH)
    assert os.path.exists(anomaly.META_PATH)

    # Status should now report loaded
    status = anomaly.get_model_status()
    assert status["loaded"] is True
    assert status["n_samples"] == 15


def test_score_window(temp_model_dir, db_with_baseline):
    anomaly.train_model(db_with_baseline)

    # Insert events into the window for scoring
    from datetime import datetime, timezone
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    for _ in range(20):
        db_with_baseline.execute("""
            INSERT INTO events (timestamp_utc, source, src_ip, dst_ip, dst_port, function_code)
            VALUES (?, 'zeek', '172.20.0.40', '172.20.0.11', 502, 4)
        """, (now_str,))
    db_with_baseline.commit()

    result = anomaly.score_window(db_with_baseline, "172.20.0.40", window_s=60)
    assert result is not None
    score, explanation, feat_dict = result
    assert isinstance(score, float)
    assert "total_requests" in feat_dict
    assert feat_dict["total_requests"] == 20
    assert "Anomaly score" in explanation
