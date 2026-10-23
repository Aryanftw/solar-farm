"""
Unit tests — Rule Engine
Tests all 7 detection rules with controlled inputs.
"""

import json
import sys
import os
import sqlite3
import pytest

# Allow importing from services/api
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../services/api"))

from rules import (
    evaluate_modbus_event,
    evaluate_iec104_event,
    check_write_burst,
    persist_alert,
    _check_dedupe,
    _dedupe_cache,
    _is_in_maintenance_window,
)


@pytest.fixture(autouse=True)
def clear_dedupe_cache():
    """Clear deduplication cache between tests."""
    _dedupe_cache.clear()
    yield
    _dedupe_cache.clear()


@pytest.fixture
def in_memory_db():
    """Create an in-memory SQLite DB with the required tables."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL,
            mac TEXT, hostname TEXT, role TEXT, protocols TEXT,
            first_seen_utc TEXT, last_seen_utc TEXT, authorised INTEGER DEFAULT 0,
            source TEXT, UNIQUE(ip)
        );
        CREATE TABLE events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp_utc TEXT,
            source TEXT, src_ip TEXT, dst_ip TEXT, dst_port INTEGER,
            protocol TEXT, function_code INTEGER, register_address INTEGER,
            raw_value INTEGER, direction TEXT, asdu_type TEXT, ioa INTEGER,
            extra_json TEXT, scenario_id TEXT
        );
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT UNIQUE, rule_id TEXT, rule_name TEXT,
            severity TEXT, timestamp_utc TEXT, src_ip TEXT, dst_ip TEXT,
            dst_port INTEGER, protocol TEXT, evidence_json TEXT,
            explanation TEXT, recommended_action TEXT, status TEXT,
            scenario_id TEXT, event_id INTEGER, anomaly_score REAL, top_features TEXT
        );
        CREATE TABLE communication_baseline (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL,
            protocol TEXT NOT NULL, dst_port INTEGER NOT NULL,
            approved INTEGER DEFAULT 1, approved_by TEXT DEFAULT 'manifest_init',
            approved_at_utc TEXT, notes TEXT,
            UNIQUE(src_ip, dst_ip, protocol, dst_port)
        );
    """)
    yield conn
    conn.close()



def make_event(**kwargs):
    base = {
        "timestamp_utc": "2026-10-22T10:00:00Z",
        "src_ip": "172.20.0.99",
        "dst_ip": "172.20.0.11",
        "dst_port": 502,
        "function_code": 4,
        "register_address": None,
        "raw_value": None,
        "scenario_id": "TEST",
        "source": "test",
    }
    base.update(kwargs)
    return base


# ── RULE-001: Unknown Device ──────────────────────────────────────────────────

def test_rule001_unknown_device_triggers(in_memory_db):
    event = make_event(src_ip="192.168.99.1")  # Not in manifest
    inv_result = {"ip": "192.168.99.1", "is_new": True, "authorised": False, "role": "unknown"}
    alerts = evaluate_modbus_event(in_memory_db, event, inv_result)
    assert any(a["rule_name"] == "UNKNOWN_DEVICE" for a in alerts), \
        "RULE-001 should fire for unknown device"


def test_rule001_authorised_device_no_alert(in_memory_db):
    event = make_event(src_ip="172.20.0.40")  # FUXA HMI — authorised
    inv_result = {"ip": "172.20.0.40", "is_new": False, "authorised": True, "role": "hmi"}
    alerts = evaluate_modbus_event(in_memory_db, event, inv_result)
    assert not any(a["rule_name"] == "UNKNOWN_DEVICE" for a in alerts), \
        "RULE-001 should NOT fire for authorised device"


def test_rule001_explanation_contains_ip(in_memory_db):
    rogue_ip = "10.0.0.5"
    event = make_event(src_ip=rogue_ip)
    inv_result = {"ip": rogue_ip, "is_new": True, "authorised": False, "role": "unknown"}
    alerts = evaluate_modbus_event(in_memory_db, event, inv_result)
    alert = next(a for a in alerts if a["rule_name"] == "UNKNOWN_DEVICE")
    assert rogue_ip in alert["explanation"], "Explanation must contain the rogue IP"


# ── RULE-002: Unauthorised Modbus Write ───────────────────────────────────────

@pytest.mark.parametrize("fc", [5, 6, 15, 16])
def test_rule002_unauthorised_write(in_memory_db, fc):
    event = make_event(src_ip="172.20.0.99", function_code=fc)
    inv_result = {"authorised": False}
    alerts = evaluate_modbus_event(in_memory_db, event, inv_result)
    assert any(a["rule_name"] == "UNAUTHORISED_MODBUS_WRITE" for a in alerts), \
        f"RULE-002 should fire for FC{fc} from rogue client"


def test_rule002_read_no_alert(in_memory_db):
    event = make_event(src_ip="172.20.0.99", function_code=3)  # read only
    inv_result = {"authorised": False}
    alerts = evaluate_modbus_event(in_memory_db, event, inv_result)
    assert not any(a["rule_name"] == "UNAUTHORISED_MODBUS_WRITE" for a in alerts), \
        "RULE-002 should NOT fire for read-only FC"


def test_rule002_authorised_writer_no_alert(in_memory_db):
    # 172.20.0.40 = FUXA HMI (authorised writer per device_manifest.yaml)
    event = make_event(src_ip="172.20.0.40", function_code=6, register_address=1)
    inv_result = {"authorised": True}
    alerts = evaluate_modbus_event(in_memory_db, event, inv_result)
    assert not any(a["rule_name"] == "UNAUTHORISED_MODBUS_WRITE" for a in alerts), \
        "RULE-002 should NOT fire for authorised writer"


# ── RULE-003: Protected Setpoint Change ────────────────────────────────────────

def test_rule003_protected_setpoint(in_memory_db):
    event = make_event(
        src_ip="172.20.0.99",
        function_code=6,
        register_address=0,  # HR0 = active_power_setpoint (protected)
        raw_value=1000,
    )
    inv_result = {"authorised": False}
    alerts = evaluate_modbus_event(in_memory_db, event, inv_result)
    assert any(a["rule_name"] == "PROTECTED_SETPOINT_CHANGE" for a in alerts)


def test_rule003_non_protected_register(in_memory_db):
    event = make_event(
        src_ip="172.20.0.99",
        function_code=6,
        register_address=2,  # HR2 = ramp_rate (not protected)
    )
    inv_result = {"authorised": False}
    alerts = evaluate_modbus_event(in_memory_db, event, inv_result)
    assert not any(a["rule_name"] == "PROTECTED_SETPOINT_CHANGE" for a in alerts)


# ── RULE-004: Out-of-Window Write ────────────────────────────────────────────

def test_maintenance_window_uses_event_timestamp():
    """Window checks must use the event timestamp, not wall-clock time."""
    assert _is_in_maintenance_window("172.20.0.40", "2026-01-01T03:00:00Z") is True
    assert _is_in_maintenance_window("172.20.0.40", "2026-01-01T12:00:00Z") is False
    # Unknown host is never inside a window.
    assert _is_in_maintenance_window("172.20.0.99", "2026-01-01T03:00:00Z") is False


def test_maintenance_emergency_window():
    """The Mon/Wed/Fri 20:00–20:30 UTC emergency window is honoured."""
    # 2026-01-05 is a Monday.
    assert _is_in_maintenance_window("172.20.0.40", "2026-01-05T20:15:00Z") is True
    assert _is_in_maintenance_window("172.20.0.40", "2026-01-05T21:00:00Z") is False


def test_rule004_out_of_window_write_triggers(in_memory_db):
    event = make_event(
        timestamp_utc="2026-01-01T12:00:00Z",
        src_ip="172.20.0.40",       # authorised HMI
        function_code=6,
        register_address=1,         # not a protected setpoint
        raw_value=2350,
    )
    inv_result = {"authorised": True}
    alerts = evaluate_modbus_event(in_memory_db, event, inv_result)
    assert any(a["rule_name"] == "OUT_OF_WINDOW_WRITE" for a in alerts)


def test_rule004_in_window_no_alert(in_memory_db):
    event = make_event(
        timestamp_utc="2026-01-01T03:00:00Z",
        src_ip="172.20.0.40",
        function_code=6,
        register_address=1,
        raw_value=2350,
    )
    inv_result = {"authorised": True}
    alerts = evaluate_modbus_event(in_memory_db, event, inv_result)
    assert not any(a["rule_name"] == "OUT_OF_WINDOW_WRITE" for a in alerts)


# ── RULE-005: Write Burst ────────────────────────────────────────────────────

def test_rule005_write_burst_triggers(in_memory_db):
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for i in range(10):
        in_memory_db.execute(
            """INSERT INTO events
               (timestamp_utc, source, src_ip, dst_ip, dst_port, protocol,
                function_code, register_address, raw_value, scenario_id)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (ts, "test", "172.20.0.99", "172.20.0.12", 502,
             "modbus-tcp", 6, 2, i, "RULE005_TEST"),
        )
    in_memory_db.commit()

    alert = check_write_burst(in_memory_db, "172.20.0.99", "172.20.0.12", "RULE005_TEST")
    assert alert is not None
    assert alert["rule_name"] == "MODBUS_WRITE_BURST"


def test_rule005_single_write_no_alert(in_memory_db):
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    in_memory_db.execute(
        """INSERT INTO events
           (timestamp_utc, source, src_ip, dst_ip, dst_port, protocol,
            function_code, register_address, raw_value, scenario_id)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (ts, "test", "172.20.0.40", "172.20.0.12", 502,
         "modbus-tcp", 6, 2, 1, "RULE005_TEST"),
    )
    in_memory_db.commit()

    assert check_write_burst(in_memory_db, "172.20.0.40", "172.20.0.12") is None


# ── RULE-006: IEC-104 Unexpected Control ─────────────────────────────────────

def test_rule006_unexpected_iec104_control(in_memory_db):
    event = {
        "src_ip": "172.20.0.88",  # rogue master
        "dst_ip": "172.20.0.30",
        "asdu_type": "C_SE_NC_1",
        "timestamp_utc": "2026-10-22T10:00:00Z",
        "scenario_id": "S4",
    }
    alerts = evaluate_iec104_event(in_memory_db, event)
    assert any(a["rule_name"] == "IEC104_UNEXPECTED_CONTROL" for a in alerts)


def test_rule006_authorised_master_no_alert(in_memory_db):
    event = {
        "src_ip": "172.20.0.31",  # authorised grid control centre
        "dst_ip": "172.20.0.30",
        "asdu_type": "C_SE_NC_1",
        "timestamp_utc": "2026-10-22T10:00:00Z",
    }
    alerts = evaluate_iec104_event(in_memory_db, event)
    assert not any(a["rule_name"] == "IEC104_UNEXPECTED_CONTROL" for a in alerts)


def test_rule006_non_control_asdu_no_alert(in_memory_db):
    event = {
        "src_ip": "172.20.0.88",
        "dst_ip": "172.20.0.30",
        "asdu_type": "M_ME_NC_1",  # measurement, not control
        "timestamp_utc": "2026-10-22T10:00:00Z",
    }
    alerts = evaluate_iec104_event(in_memory_db, event)
    assert not any(a["rule_name"] == "IEC104_UNEXPECTED_CONTROL" for a in alerts)


# ── Alert Persistence ─────────────────────────────────────────────────────────

def test_alert_persistence(in_memory_db):
    alert = {
        "rule_id": "RULE-TEST",
        "rule_name": "TEST_ALERT",
        "severity": "high",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "dst_port": 502,
        "protocol": "modbus-tcp",
        "explanation": "Test explanation",
        "recommended_action": "Test action",
        "evidence_json": json.dumps({"test": True}),
        "scenario_id": "TEST",
        "ts": "2026-10-22T10:00:00Z",
    }
    aid = persist_alert(in_memory_db, alert)
    assert aid.startswith("ALT-"), f"Alert ID should start with ALT-, got: {aid}"

    row = in_memory_db.execute("SELECT * FROM alerts WHERE alert_id=?", (aid,)).fetchone()
    assert row is not None, "Alert should be persisted in database"
    assert row["rule_name"] == "TEST_ALERT"
    assert row["severity"] == "high"


def test_alert_deduplication(in_memory_db):
    """Same rule+IPs within dedupe window should not create duplicate alerts."""
    event = make_event(src_ip="172.20.0.99")
    inv_result = {"authorised": False}

    alerts1 = evaluate_modbus_event(in_memory_db, event, inv_result)
    alerts2 = evaluate_modbus_event(in_memory_db, event, inv_result)

    rule001_count_1 = sum(1 for a in alerts1 if a["rule_name"] == "UNKNOWN_DEVICE")
    rule001_count_2 = sum(1 for a in alerts2 if a["rule_name"] == "UNKNOWN_DEVICE")

    assert rule001_count_1 == 1, "First call should generate exactly 1 UNKNOWN_DEVICE alert"
    assert rule001_count_2 == 0, "Second call within dedupe window should generate 0 alerts"


def test_dedupe_is_scoped_by_run_id(in_memory_db):
    """Separate scenario runs must not suppress each other's alerts."""
    event = make_event(src_ip="172.20.0.99", run_id="run-a")
    inv_result = {"authorised": False}

    first = evaluate_modbus_event(in_memory_db, event, inv_result)
    repeat = evaluate_modbus_event(in_memory_db, event, inv_result)
    second_run = evaluate_modbus_event(in_memory_db, {**event, "run_id": "run-b"}, inv_result)

    assert sum(1 for a in first if a["rule_name"] == "UNKNOWN_DEVICE") == 1
    assert sum(1 for a in repeat if a["rule_name"] == "UNKNOWN_DEVICE") == 0
    assert sum(1 for a in second_run if a["rule_name"] == "UNKNOWN_DEVICE") == 1


def test_alert_ids_are_unique_across_runs():
    from rules import _make_alert_id

    a = _make_alert_id("RULE-004", "172.20.0.40", "172.20.0.11", "2026-01-01T12:00:00Z", "run-a")
    b = _make_alert_id("RULE-004", "172.20.0.40", "172.20.0.11", "2026-01-01T12:00:00Z", "run-b")
    assert a != b


def test_alert_explanation_completeness(in_memory_db):
    """Every alert must have a non-empty explanation."""
    event = make_event(src_ip="172.20.0.99", function_code=6, register_address=0, raw_value=999)
    inv_result = {"authorised": False}
    alerts = evaluate_modbus_event(in_memory_db, event, inv_result)
    for alert in alerts:
        assert alert.get("explanation"), f"Alert {alert['rule_name']} has no explanation"
        assert len(alert["explanation"]) > 20, f"Alert {alert['rule_name']} explanation too short"


# ── RULE-007: IEC-104 Rate Anomaly ────────────────────────────────────────────

def _insert_iec104_events(conn, src_ip: str, count: int) -> None:
    """Helper: insert synthetic IEC-104 events to simulate a rate burst."""
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for i in range(count):
        conn.execute(
            """INSERT INTO events
               (timestamp_utc, source, src_ip, dst_ip, dst_port, protocol,
                function_code, register_address, raw_value, asdu_type, scenario_id)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (ts, "iec104", src_ip, "172.20.0.30", 2404,
             "iec60870-5-104", None, None, None, "C_SE_NC_1", "RULE007_TEST"),
        )
    conn.commit()


def test_rule007_rate_anomaly_triggers(in_memory_db):
    """RULE-007 should fire when IEC-104 rate >= 50 APDUs/min from one source."""
    rogue_ip = "172.20.0.88"
    _insert_iec104_events(in_memory_db, rogue_ip, 55)

    event = {
        "src_ip": rogue_ip,
        "dst_ip": "172.20.0.30",
        "asdu_type": "M_ME_NC_1",   # measurement, not control (avoids RULE-006)
        "timestamp_utc": "2026-10-22T10:00:00Z",
        "scenario_id": "RULE007_TEST",
    }
    alerts = evaluate_iec104_event(in_memory_db, event)
    assert any(a["rule_name"] == "IEC104_RATE_ANOMALY" for a in alerts), \
        "RULE-007 should fire when IEC-104 APDU rate exceeds threshold"


def test_rule007_rate_anomaly_not_triggered_at_normal_rate(in_memory_db):
    """RULE-007 should NOT fire for normal IEC-104 polling rates (< 50 APDUs/min)."""
    normal_ip = "172.20.0.31"
    _insert_iec104_events(in_memory_db, normal_ip, 5)   # only 5 events — well below threshold

    event = {
        "src_ip": normal_ip,
        "dst_ip": "172.20.0.30",
        "asdu_type": "M_ME_NC_1",
        "timestamp_utc": "2026-10-22T10:00:00Z",
    }
    alerts = evaluate_iec104_event(in_memory_db, event)
    assert not any(a["rule_name"] == "IEC104_RATE_ANOMALY" for a in alerts), \
        "RULE-007 should NOT fire for normal polling rates"


def test_rule007_explanation_contains_rate(in_memory_db):
    """RULE-007 alert explanation must be substantive."""
    rogue_ip = "172.20.0.77"
    _insert_iec104_events(in_memory_db, rogue_ip, 60)

    event = {
        "src_ip": rogue_ip,
        "dst_ip": "172.20.0.30",
        "asdu_type": "M_ME_NC_1",
        "timestamp_utc": "2026-10-22T10:00:00Z",
        "scenario_id": "RULE007_EXP",
    }
    alerts = evaluate_iec104_event(in_memory_db, event)
    rate_alerts = [a for a in alerts if a["rule_name"] == "IEC104_RATE_ANOMALY"]
    if rate_alerts:
        assert len(rate_alerts[0]["explanation"]) > 20, \
            "RULE-007 explanation must be substantive"


# ── RULE-008: Out-of-Range Setpoint Tests ────────────────────────────────────

def test_rule008_out_of_range_high_triggers(in_memory_db):
    """Writing 300,000 W to active_power_setpoint (max 250,000) must trigger RULE-008."""
    event = make_event(
        src_ip="172.20.0.40",   # HMI
        dst_ip="172.20.0.11",
        function_code=6,
        register_address=0,      # active_power_setpoint (min 0, max 250000)
        raw_value=300000,
        scenario_id="RULE008_HIGH",
    )
    inv = {"authorised": True, "role": "hmi"}
    alerts = evaluate_modbus_event(in_memory_db, event, inv)
    rule8_alerts = [a for a in alerts if a["rule_id"] == "RULE-008"]
    assert len(rule8_alerts) == 1, "Should generate exactly one RULE-008 alert"
    alert = rule8_alerts[0]
    assert alert["rule_name"] == "OUT_OF_RANGE_SETPOINT"
    assert alert["severity"] == "high"
    assert "300000" in alert["explanation"]
    assert "simulated lab limits" in alert["explanation"].lower()


def test_rule008_out_of_range_low_triggers(in_memory_db):
    """Writing negative power to active_power_setpoint (min 0) must trigger RULE-008."""
    event = make_event(
        src_ip="172.20.0.40",
        dst_ip="172.20.0.11",
        function_code=6,
        register_address=0,
        raw_value=-500,
        scenario_id="RULE008_LOW",
    )
    inv = {"authorised": True, "role": "hmi"}
    alerts = evaluate_modbus_event(in_memory_db, event, inv)
    assert any(a["rule_id"] == "RULE-008" for a in alerts)


def test_rule008_within_range_no_alert(in_memory_db):
    """Writing a valid value within safe range (150,000 W) must NOT trigger RULE-008."""
    event = make_event(
        src_ip="172.20.0.40",
        dst_ip="172.20.0.11",
        function_code=6,
        register_address=0,
        raw_value=150000,
        scenario_id="RULE008_NORMAL",
    )
    inv = {"authorised": True, "role": "hmi"}
    alerts = evaluate_modbus_event(in_memory_db, event, inv)
    assert not any(a["rule_id"] == "RULE-008" for a in alerts)


def test_rule008_boundary_values(in_memory_db):
    """Boundary testing: min (0) and max (250000) are valid; max+1 (250001) is out of range."""
    inv = {"authorised": True, "role": "hmi"}

    # Min boundary: 0 -> valid
    e_min = make_event(src_ip="172.20.0.40", dst_ip="172.20.0.11", function_code=6, register_address=0, raw_value=0, run_id="b1")
    assert not any(a["rule_id"] == "RULE-008" for a in evaluate_modbus_event(in_memory_db, e_min, inv))

    # Max boundary: 250000 -> valid
    e_max = make_event(src_ip="172.20.0.40", dst_ip="172.20.0.11", function_code=6, register_address=0, raw_value=250000, run_id="b2")
    assert not any(a["rule_id"] == "RULE-008" for a in evaluate_modbus_event(in_memory_db, e_max, inv))

    # Max + 1: 250001 -> out of range
    e_over = make_event(src_ip="172.20.0.40", dst_ip="172.20.0.11", function_code=6, register_address=0, raw_value=250001, run_id="b3")
    assert any(a["rule_id"] == "RULE-008" for a in evaluate_modbus_event(in_memory_db, e_over, inv))


def test_rule008_scaled_register_voltage(in_memory_db):
    """Voltage setpoint register 1 has scale 10, min 2000, max 2600. Commanded 3000 is out of range."""
    event = make_event(
        src_ip="172.20.0.40",
        dst_ip="172.20.0.11",
        function_code=6,
        register_address=1,
        raw_value=3000,  # 300.0 V, max is 260.0 V
        scenario_id="RULE008_VOLT",
    )
    inv = {"authorised": True, "role": "hmi"}
    alerts = evaluate_modbus_event(in_memory_db, event, inv)
    r8 = [a for a in alerts if a["rule_id"] == "RULE-008"]
    assert len(r8) == 1
    assert r8[0]["rule_name"] == "OUT_OF_RANGE_SETPOINT"


def test_rule008_malformed_and_missing_inputs(in_memory_db):
    """Malformed values (None, string, unknown register) must be handled safely without error."""
    inv = {"authorised": True, "role": "hmi"}

    # None raw_value
    e_none = make_event(src_ip="172.20.0.40", dst_ip="172.20.0.11", function_code=6, register_address=0, raw_value=None)
    assert not any(a["rule_id"] == "RULE-008" for a in evaluate_modbus_event(in_memory_db, e_none, inv))

    # String raw_value
    e_str = make_event(src_ip="172.20.0.40", dst_ip="172.20.0.11", function_code=6, register_address=0, raw_value="invalid")
    assert not any(a["rule_id"] == "RULE-008" for a in evaluate_modbus_event(in_memory_db, e_str, inv))

    # Unknown register address
    e_unk = make_event(src_ip="172.20.0.40", dst_ip="172.20.0.11", function_code=6, register_address=9999, raw_value=123)
    assert not any(a["rule_id"] == "RULE-008" for a in evaluate_modbus_event(in_memory_db, e_unk, inv))


def test_rule008_co_occurrence_with_protected_setpoint(in_memory_db):
    """Rogue client writing out-of-range value triggers BOTH RULE-002/003 AND RULE-008."""
    event = make_event(
        src_ip="172.20.0.99",   # Rogue IP
        dst_ip="172.20.0.11",
        function_code=6,
        register_address=0,      # Protected active power setpoint
        raw_value=500000,        # Out of range!
        scenario_id="RULE008_CO",
    )
    inv = {"authorised": False, "role": "unknown"}
    alerts = evaluate_modbus_event(in_memory_db, event, inv)
    rule_ids = {a["rule_id"] for a in alerts}
    assert "RULE-001" in rule_ids   # Unknown device
    assert "RULE-002" in rule_ids   # Unauthorised write
    assert "RULE-003" in rule_ids   # Protected setpoint change
    assert "RULE-008" in rule_ids   # Out-of-range setpoint write


# ── RULE-009: Protocol & Peer Drift Tests ────────────────────────────────────

def test_rule009_approved_relationship_no_alert(in_memory_db):
    """HMI to Inverter 1 (Modbus 502) is approved in baseline matrix -> no RULE-009 alert."""
    event = make_event(
        src_ip="172.20.0.40",   # HMI
        dst_ip="172.20.0.11",   # Inverter 1
        dst_port=502,
        protocol="modbus-tcp",
        function_code=4,
    )
    inv = {"authorised": True, "role": "hmi"}
    alerts = evaluate_modbus_event(in_memory_db, event, inv)
    assert not any(a["rule_id"] == "RULE-009" for a in alerts)


def test_rule009_peer_drift_triggers(in_memory_db):
    """Known Inverter 1 initiating Modbus to Inverter 2 is an unapproved peer relationship -> triggers RULE-009."""
    event = make_event(
        src_ip="172.20.0.11",   # Inverter 1 (known device)
        dst_ip="172.20.0.12",   # Inverter 2
        dst_port=502,
        protocol="modbus-tcp",
        function_code=4,
        scenario_id="DRIFT_PEER",
    )
    inv = {"authorised": True, "role": "inverter"}
    alerts = evaluate_modbus_event(in_memory_db, event, inv)
    r9 = [a for a in alerts if a["rule_id"] == "RULE-009"]
    assert len(r9) == 1, "Should generate PROTOCOL_PEER_DRIFT alert"
    assert r9[0]["rule_name"] == "PROTOCOL_PEER_DRIFT"
    assert "172.20.0.11" in r9[0]["explanation"]
    assert "172.20.0.12" in r9[0]["explanation"]


def test_rule009_distinguished_from_rule001(in_memory_db):
    """
    Rogue IP (not in manifest) triggers RULE-001 (UNKNOWN_DEVICE), NOT RULE-009.
    Known device with unapproved relationship triggers RULE-009, NOT RULE-001.
    """
    # Rogue device
    e_rogue = make_event(src_ip="192.168.1.99", dst_ip="172.20.0.11", function_code=4, run_id="dist1")
    inv_rogue = {"authorised": False, "role": "unknown"}
    alerts_rogue = evaluate_modbus_event(in_memory_db, e_rogue, inv_rogue)
    r_ids_rogue = {a["rule_id"] for a in alerts_rogue}
    assert "RULE-001" in r_ids_rogue
    assert "RULE-009" not in r_ids_rogue

    # Known device drifting
    e_drift = make_event(src_ip="172.20.0.11", dst_ip="172.20.0.13", function_code=4, run_id="dist2")
    inv_drift = {"authorised": True, "role": "inverter"}
    alerts_drift = evaluate_modbus_event(in_memory_db, e_drift, inv_drift)
    r_ids_drift = {a["rule_id"] for a in alerts_drift}
    assert "RULE-009" in r_ids_drift
    assert "RULE-001" not in r_ids_drift


def test_rule009_baseline_approval_suppresses_alert(in_memory_db):
    """Once an operator explicitly approves a communication relationship, it no longer triggers RULE-009."""
    import inventory
    # Approve Inverter 1 -> Inverter 2
    inventory.approve_relationship(
        in_memory_db,
        src_ip="172.20.0.11",
        dst_ip="172.20.0.12",
        protocol="modbus-tcp",
        dst_port=502,
        approved_by="lead_engineer",
        notes="Approved for inter-inverter telemetry sharing",
    )

    event = make_event(
        src_ip="172.20.0.11",
        dst_ip="172.20.0.12",
        dst_port=502,
        protocol="modbus-tcp",
        function_code=4,
        run_id="approved_run",
    )
    inv = {"authorised": True, "role": "inverter"}
    alerts = evaluate_modbus_event(in_memory_db, event, inv)
    assert not any(a["rule_id"] == "RULE-009" for a in alerts), \
        "Approved baseline relationship must not trigger RULE-009"

