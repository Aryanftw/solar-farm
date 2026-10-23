"""
Unit tests — FastAPI Endpoints (In-memory TestClient)
Tests API routing, event normalization, alert queries, inventory, and health.
Runs entirely without Docker or external network dependencies.
"""

import os
import sqlite3
import pytest
from fastapi.testclient import TestClient

import database
import anomaly
import rules
from main import app


@pytest.fixture
def test_client(tmp_path, monkeypatch):
    """Setup a clean test database and isolated model dir for API testing."""
    test_db = str(tmp_path / "test_api.db")
    test_model_dir = str(tmp_path / "model")
    os.makedirs(test_model_dir, exist_ok=True)

    monkeypatch.setattr(database, "DB_PATH", test_db)
    monkeypatch.setattr(anomaly, "MODEL_DIR", test_model_dir)
    monkeypatch.setattr(anomaly, "MODEL_PATH", os.path.join(test_model_dir, "isolation_forest.pkl"))
    monkeypatch.setattr(anomaly, "SCALER_PATH", os.path.join(test_model_dir, "scaler.pkl"))
    monkeypatch.setattr(anomaly, "META_PATH", os.path.join(test_model_dir, "model_meta.json"))

    rules._dedupe_cache.clear()

    with TestClient(app) as client:
        yield client

    rules._dedupe_cache.clear()


def test_health_endpoint(test_client):
    r = test_client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert "timestamp_utc" in data


def test_root_endpoint(test_client):
    r = test_client.get("/")
    assert r.status_code == 200
    data = r.json()
    assert data["service"] == "Solar Farm OT Security Watchman API"


def test_inventory_initially_empty(test_client):
    r = test_client.get("/inventory")
    assert r.status_code == 200
    data = r.json()
    assert data["count"] == 0
    assert data["devices"] == []


def test_ingest_modbus_normal_read(test_client):
    event = {
        "timestamp_utc": "2026-10-22T10:00:00Z",
        "src_ip": "172.20.0.40",   # FUXA HMI
        "dst_ip": "172.20.0.11",   # Inverter 1
        "dst_port": 502,
        "function_code": 4,        # Read input registers
        "register_address": 0,
        "scenario_id": "TEST_READ",
        "source": "test",
    }
    r = test_client.post("/ingest/modbus", json=event)
    assert r.status_code == 202
    data = r.json()
    assert data["status"] == "accepted"
    assert data["alert_ids"] == []

    # Verify inventory now has devices
    inv_r = test_client.get("/inventory")
    assert inv_r.status_code == 200
    inv = inv_r.json()
    assert inv["count"] == 2


def test_ingest_unknown_device_creates_alert(test_client):
    event = {
        "timestamp_utc": "2026-10-22T10:00:00Z",
        "src_ip": "192.168.100.50",  # Rogue IP
        "dst_ip": "172.20.0.11",
        "dst_port": 502,
        "function_code": 4,
        "scenario_id": "TEST_ROGUE",
        "run_id": "run-test-rogue",
        "source": "test",
    }
    r = test_client.post("/ingest/modbus", json=event)
    assert r.status_code == 202
    data = r.json()
    assert len(data["alert_ids"]) > 0

    # Retrieve alert
    alerts_r = test_client.get("/alerts?scenario_id=TEST_ROGUE")
    assert alerts_r.status_code == 200
    alerts_data = alerts_r.json()
    assert alerts_data["total"] >= 1
    rule_names = [a["rule_name"] for a in alerts_data["alerts"]]
    assert "UNKNOWN_DEVICE" in rule_names


def test_sensor_health_endpoints(test_client):
    health_payload = {
        "sensor_running": True,
        "traffic_observed": True,
        "capture_mode": "pcap_replay",
        "packets_seen": 150,
        "last_protocol_seen": "modbus-tcp",
        "notes": "Healthy capture",
    }
    post_r = test_client.post("/sensor/health", json=health_payload)
    assert post_r.status_code == 200

    get_r = test_client.get("/sensor/health")
    assert get_r.status_code == 200
    data = get_r.json()
    assert data["sensor_running"] == 1 or data["sensor_running"] is True
    assert data["packets_seen"] == 150
    assert data["capture_mode"] == "pcap_replay"


def test_model_status_and_baseline_endpoints(test_client):
    status_r = test_client.get("/model/status")
    assert status_r.status_code == 200
    assert status_r.json()["loaded"] is False

    # Ingest 12 baseline windows
    for i in range(12):
        w = {
            "window_start_utc": f"2026-10-22T10:{i:02d}:00Z",
            "window_end_utc": f"2026-10-22T10:{i:02d}:59Z",
            "src_ip": "172.20.0.40",
            "total_requests": 20,
            "read_count": 19,
            "write_count": 1,
            "write_to_read_ratio": 0.05,
            "distinct_dst_devices": 3,
            "new_source": 0,
            "request_rate_deviation": 0.0,
            "protocol": "modbus-tcp",
            "iec104_command_count": 0,
            "labelled": "normal",
        }
        res = test_client.post("/baseline/window", json=w)
        assert res.status_code == 202

    # Train model
    train_r = test_client.post("/model/train")
    assert train_r.status_code == 200
    train_data = train_r.json()
    assert train_data["status"] == "trained"
    assert train_data["meta"]["n_samples"] == 12

    # Status should now be loaded
    status2_r = test_client.get("/model/status")
    assert status2_r.json()["loaded"] is True


def test_overview_endpoint(test_client):
    r = test_client.get("/overview")
    assert r.status_code == 200
    data = r.json()
    assert "devices" in data
    assert "alerts" in data
    assert "sensor" in data
    assert "protocols" in data


def test_baseline_peers_endpoints(test_client):
    # GET /baseline/peers
    r = test_client.get("/baseline/peers")
    assert r.status_code == 200
    data = r.json()
    assert data["total"] >= 5
    pairs = [(rel["src_ip"], rel["dst_ip"]) for rel in data["relationships"]]
    assert ("172.20.0.40", "172.20.0.11") in pairs

    # POST /baseline/peers/approve
    approve_payload = {
        "src_ip": "172.20.0.11",
        "dst_ip": "172.20.0.12",
        "protocol": "modbus-tcp",
        "dst_port": 502,
        "approved_by": "api_test_engineer",
        "notes": "Testing approval endpoint"
    }
    post_r = test_client.post("/baseline/peers/approve", json=approve_payload)
    assert post_r.status_code == 200
    res = post_r.json()
    assert res["status"] == "approved"
    assert res["relationship"]["approved"] is True

    # Check that relationship now exists in GET
    r2 = test_client.get("/baseline/peers")
    pairs2 = [(rel["src_ip"], rel["dst_ip"]) for rel in r2.json()["relationships"]]
    assert ("172.20.0.11", "172.20.0.12") in pairs2


def test_ingest_modbus_out_of_range_alert(test_client):
    event = {
        "timestamp_utc": "2026-10-22T10:00:00Z",
        "src_ip": "172.20.0.40",   # Authorized writer (HMI)
        "dst_ip": "172.20.0.11",   # Inverter 1
        "dst_port": 502,
        "function_code": 6,        # Write single register
        "register_address": 0,     # Active power setpoint (safe range: 0 - 250,000 W)
        "raw_value": 350000,       # Out of range!
        "scenario_id": "TEST_OUT_OF_RANGE",
        "run_id": "run-out-of-range",
        "source": "test",
    }
    r = test_client.post("/ingest/modbus", json=event)
    assert r.status_code == 202
    data = r.json()
    assert len(data["alert_ids"]) > 0

    alerts_r = test_client.get("/alerts?scenario_id=TEST_OUT_OF_RANGE")
    assert alerts_r.status_code == 200
    alerts = alerts_r.json()["alerts"]
    rules_fired = [a["rule_name"] for a in alerts]
    assert "OUT_OF_RANGE_SETPOINT" in rules_fired


def test_ingest_peer_drift_alert(test_client):
    # Inverter 1 sending Modbus query to Inverter 2 (not in baseline)
    event = {
        "timestamp_utc": "2026-10-22T10:00:00Z",
        "src_ip": "172.20.0.11",   # Inverter 1
        "dst_ip": "172.20.0.13",   # Inverter 3
        "dst_port": 502,
        "function_code": 4,
        "scenario_id": "TEST_PEER_DRIFT",
        "run_id": "run-peer-drift",
        "source": "test",
    }
    r = test_client.post("/ingest/modbus", json=event)
    assert r.status_code == 202
    data = r.json()
    assert len(data["alert_ids"]) > 0

    alerts_r = test_client.get("/alerts?scenario_id=TEST_PEER_DRIFT")
    assert alerts_r.status_code == 200
    alerts = alerts_r.json()["alerts"]
    rules_fired = [a["rule_name"] for a in alerts]
    assert "PROTOCOL_PEER_DRIFT" in rules_fired


def test_trials_summary_endpoint(test_client):
    # Check initially empty / not tested
    r0 = test_client.get("/trials/summary")
    assert r0.status_code == 200
    d0 = r0.json()
    assert d0["total_trials"] == 0
    assert d0["overall_status"] == "NOT TESTED"

    # Post 1 attack trial detected (TP)
    test_client.post("/trials", json={
        "scenario_id": "S1_ROGUE_DEVICE",
        "trial_number": 1,
        "expected_alert_rule": "RULE-001",
        "alert_generated": True,
        "alert_latency_seconds": 0.0125,
        "false_positive": False,
    })

    # Post 1 normal trial with no alert (TN)
    test_client.post("/trials", json={
        "scenario_id": "N1_NORMAL_POLL",
        "trial_number": 1,
        "expected_alert_rule": "NONE",
        "alert_generated": False,
        "false_positive": False,
    })

    r1 = test_client.get("/trials/summary")
    assert r1.status_code == 200
    d1 = r1.json()
    assert d1["total_trials"] == 2
    assert d1["true_positives"] == 1
    assert d1["false_negatives"] == 0
    assert d1["true_negatives"] == 1
    assert d1["false_positives"] == 0
    assert d1["detection_rate_pct"] == 100.0
    assert d1["false_alarm_rate_pct"] == 0.0
    assert d1["mean_alert_latency_ms"] == 12.5
    # Since total_trials < 5, status is INCONCLUSIVE
    assert d1["overall_status"] == "INCONCLUSIVE"


