"""
Unit tests — IEC 60870-5-104 Protocol Decoder & Detection Engine Integration.
Tests APDU decoding, ASDU type validation, error handling, and RULE-006 detection.
"""

import pytest
import sqlite3
import database
from iec104_decoder import (
    decode_iec104_apdu,
    decode_asdu,
    build_c_sc_na_1,
    build_c_se_nc_1,
    build_m_me_nc_1,
    IEC104DecodeError,
    CONTROL_TYPES,
)
from rules import evaluate_iec104_event


@pytest.fixture
def in_memory_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    database.init_db(conn)
    yield conn
    conn.close()


def test_decode_c_sc_na_1_single_command():
    """Verify decoding of a Type 45 Single Command (e.g. inverter trip command)."""
    raw = build_c_sc_na_1(common_address=1, ioa=200, state=1, tx_seq=1, rx_seq=0)
    decoded = decode_iec104_apdu(raw)

    assert decoded["apci_format"] == "I"
    assert decoded["tx_seq"] == 1
    assert decoded["asdu_type"] == "C_SC_NA_1"
    assert decoded["asdu_type_id"] == 45
    assert decoded["is_control_command"] is True
    assert decoded["common_address"] == 1
    assert decoded["ioa"] == 200
    assert decoded["command_state"] == 1
    assert decoded["cot"] == 6  # Activation


def test_decode_c_se_nc_1_float_setpoint():
    """Verify decoding of a Type 50 Float Set-Point Command."""
    raw = build_c_se_nc_1(common_address=1, ioa=201, float_val=250000.5, tx_seq=2, rx_seq=1)
    decoded = decode_iec104_apdu(raw)

    assert decoded["apci_format"] == "I"
    assert decoded["tx_seq"] == 2
    assert decoded["rx_seq"] == 1
    assert decoded["asdu_type"] == "C_SE_NC_1"
    assert decoded["asdu_type_id"] == 50
    assert decoded["is_control_command"] is True
    assert decoded["common_address"] == 1
    assert decoded["ioa"] == 201
    assert abs(decoded["value"] - 250000.5) < 0.1


def test_decode_m_me_nc_1_measurement():
    """Verify decoding of a Type 13 Measurement (non-control telemetry)."""
    raw = build_m_me_nc_1(common_address=1, ioa=102, float_val=50.02, tx_seq=5, rx_seq=2)
    decoded = decode_iec104_apdu(raw)

    assert decoded["apci_format"] == "I"
    assert decoded["asdu_type"] == "M_ME_NC_1"
    assert decoded["asdu_type_id"] == 13
    assert decoded["is_control_command"] is False
    assert decoded["ioa"] == 102
    assert abs(decoded["value"] - 50.02) < 0.01


def test_decode_u_format_startdt():
    """Verify APCI U-format handling for STARTDT act."""
    # STARTDT act: 68 04 07 00 00 00
    raw = bytes([0x68, 0x04, 0x07, 0x00, 0x00, 0x00])
    decoded = decode_iec104_apdu(raw)

    assert decoded["apci_format"] == "U"
    assert decoded["u_type"] == "STARTDT_ACT"
    assert decoded["length"] == 4


def test_decode_malformed_and_truncated_frames():
    """Verify robust error handling on corrupt or truncated bytes."""
    # Too short (< 6 bytes)
    with pytest.raises(IEC104DecodeError, match="too short"):
        decode_iec104_apdu(bytes([0x68, 0x04, 0x00]))

    # Invalid start byte
    with pytest.raises(IEC104DecodeError, match="Invalid start byte"):
        decode_iec104_apdu(bytes([0xAA, 0x04, 0x00, 0x00, 0x00, 0x00]))

    # Truncated length mismatch
    with pytest.raises(IEC104DecodeError, match="Truncated frame"):
        decode_iec104_apdu(bytes([0x68, 0x14, 0x00, 0x00, 0x00, 0x00]))


def test_rule006_fires_on_decoded_unauthorized_control(in_memory_db):
    """Verify decoded control packet from rogue IP triggers RULE-006."""
    raw = build_c_sc_na_1(common_address=1, ioa=200, state=1)
    decoded = decode_iec104_apdu(raw)

    event = {
        "timestamp_utc": "2026-10-22T12:00:00Z",
        "src_ip": "192.168.1.99",       # Rogue IP
        "dst_ip": "172.20.0.30",       # Grid controller
        "dst_port": 2404,
        "asdu_type": decoded["asdu_type"],
        "ioa": decoded["ioa"],
        "common_address": decoded["common_address"],
        "value": decoded["value"],
        "scenario_id": "S4_IEC104_ATTACK",
        "run_id": "test-run-1",
    }

    alerts = evaluate_iec104_event(in_memory_db, event)
    rule_ids = [a["rule_id"] for a in alerts]
    assert "RULE-006" in rule_ids

    alert_006 = next(a for a in alerts if a["rule_id"] == "RULE-006")
    assert alert_006["severity"].lower() == "critical"
    assert "192.168.1.99" in alert_006["explanation"]
    assert "C_SC_NA_1" in alert_006["explanation"]
    import json
    evidence = json.loads(alert_006["evidence_json"])
    assert evidence["ioa"] == 200
    assert evidence["asdu_type"] == "C_SC_NA_1"


def test_rule006_suppressed_for_authorized_grid_master(in_memory_db):
    """Verify decoded control packet from authorized master (172.20.0.31) is permitted."""
    raw = build_c_se_nc_1(common_address=1, ioa=201, float_val=200000.0)
    decoded = decode_iec104_apdu(raw)

    event = {
        "timestamp_utc": "2026-10-22T12:00:00Z",
        "src_ip": "172.20.0.31",       # Authorized grid master
        "dst_ip": "172.20.0.30",       # Grid controller
        "dst_port": 2404,
        "asdu_type": decoded["asdu_type"],
        "ioa": decoded["ioa"],
        "scenario_id": "TEST_AUTH_MASTER",
        "run_id": "test-run-1",
    }

    alerts = evaluate_iec104_event(in_memory_db, event)
    rule_ids = [a["rule_id"] for a in alerts]
    assert "RULE-006" not in rule_ids


def test_rule006_not_triggered_for_measurement_asdu(in_memory_db):
    """Verify measurement telemetry (Type 13) does not trigger control command alert."""
    raw = build_m_me_nc_1(common_address=1, ioa=100, float_val=450000.0)
    decoded = decode_iec104_apdu(raw)

    event = {
        "timestamp_utc": "2026-10-22T12:00:00Z",
        "src_ip": "172.20.0.31",
        "dst_ip": "172.20.0.30",
        "dst_port": 2404,
        "asdu_type": decoded["asdu_type"],
        "ioa": decoded["ioa"],
    }

    alerts = evaluate_iec104_event(in_memory_db, event)
    rule_ids = [a["rule_id"] for a in alerts]
    assert "RULE-006" not in rule_ids
