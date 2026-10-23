"""
Integration tests — API endpoints
These tests require the API to be running at localhost:8000.
Skip automatically if API is unreachable.
"""

import json
import pytest
import requests

API_URL = "http://127.0.0.1:8000"


def api_reachable() -> bool:
    try:
        r = requests.get(f"{API_URL}/health", timeout=3)
        return r.ok
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not api_reachable(),
    reason="API not running — start the lab with 'make up' first",
)


def test_health_endpoint():
    r = requests.get(f"{API_URL}/health", timeout=5)
    assert r.ok
    data = r.json()
    assert data["status"] == "ok"
    assert "timestamp_utc" in data


def test_ingest_modbus_read():
    """Ingest a normal Modbus read — should be accepted, no alerts."""
    event = {
        "timestamp_utc": "2026-10-22T10:00:00Z",
        "src_ip": "172.20.0.40",   # FUXA HMI (authorised)
        "dst_ip": "172.20.0.11",
        "dst_port": 502,
        "function_code": 4,
        "register_address": 0,
        "raw_value": None,
        "scenario_id": "INTEGRATION_TEST",
        "source": "test",
    }
    r = requests.post(f"{API_URL}/ingest/modbus", json=event, timeout=5)
    assert r.status_code == 202
    data = r.json()
    assert data["status"] == "accepted"


def test_ingest_unknown_device_triggers_alert():
    """Ingest from an unknown IP should create UNKNOWN_DEVICE alert."""
    event = {
        "timestamp_utc": "2026-10-22T10:00:00Z",
        "src_ip": "192.168.255.99",   # definitely not in manifest
        "dst_ip": "172.20.0.11",
        "dst_port": 502,
        "function_code": 4,
        "scenario_id": "INTEGRATION_TEST",
        "source": "test",
    }
    r = requests.post(f"{API_URL}/ingest/modbus", json=event, timeout=5)
    assert r.status_code == 202
    data = r.json()
    assert len(data.get("alert_ids", [])) > 0, "Should generate at least one alert"

    # Verify alert is retrievable
    alerts_r = requests.get(
        f"{API_URL}/alerts",
        params={"scenario_id": "INTEGRATION_TEST"},
        timeout=5,
    )
    assert alerts_r.ok
    alerts = alerts_r.json()["alerts"]
    rule_names = [a["rule_name"] for a in alerts]
    assert "UNKNOWN_DEVICE" in rule_names


def test_inventory_endpoint():
    r = requests.get(f"{API_URL}/inventory", timeout=5)
    assert r.ok
    data = r.json()
    assert "devices" in data
    assert "count" in data


def test_alerts_endpoint():
    r = requests.get(f"{API_URL}/alerts?limit=10", timeout=5)
    assert r.ok
    data = r.json()
    assert "alerts" in data
    assert "total" in data


def test_sensor_health_post_and_get():
    health = {
        "sensor_running": True,
        "traffic_observed": False,
        "capture_mode": "pcap_replay",
        "packets_seen": 42,
        "last_protocol_seen": "modbus-tcp",
    }
    r = requests.post(f"{API_URL}/sensor/health", json=health, timeout=5)
    assert r.ok

    r2 = requests.get(f"{API_URL}/sensor/health", timeout=5)
    assert r2.ok
    data = r2.json()
    assert data["capture_mode"] == "pcap_replay"
    assert data["packets_seen"] == 42


def test_model_status_endpoint():
    r = requests.get(f"{API_URL}/model/status", timeout=5)
    assert r.ok
    data = r.json()
    assert "loaded" in data


def test_overview_endpoint():
    r = requests.get(f"{API_URL}/overview", timeout=5)
    assert r.ok
    data = r.json()
    assert "devices" in data
    assert "alerts" in data
    assert "sensor" in data
