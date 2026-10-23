"""
Unit tests — Device Inventory & Manifest Loader (B3)
Tests passive device discovery, role tagging, and manifest loading.
"""

import json
import os
import sqlite3
import pytest

import database
from inventory import (
    _load_manifest,
    get_lab_manifest_ips,
    get_authorised_modbus_writers,
    get_authorised_iec104_masters,
    upsert_device,
    get_all_devices,
    get_device_by_ip,
    is_relationship_approved,
    approve_relationship,
    get_baseline_relationships,
)


@pytest.fixture
def in_memory_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    database.init_db(conn)
    yield conn
    conn.close()


def test_load_manifest_returns_valid_structure():
    manifest = _load_manifest()
    assert "devices" in manifest
    assert "authorised_modbus_writers" in manifest
    assert "authorised_iec104_masters" in manifest
    assert len(manifest["devices"]) >= 5


def test_manifest_helper_functions():
    ips = get_lab_manifest_ips()
    assert "172.20.0.11" in ips
    assert "172.20.0.12" in ips
    assert "172.20.0.13" in ips
    assert "172.20.0.20" in ips
    assert "172.20.0.40" in ips

    writers = get_authorised_modbus_writers()
    assert "172.20.0.40" in writers

    masters = get_authorised_iec104_masters()
    assert "172.20.0.31" in masters


def test_upsert_authorised_device(in_memory_db):
    result = upsert_device(in_memory_db, "172.20.0.11", protocol="modbus-tcp", port=502)
    assert result["ip"] == "172.20.0.11"
    assert result["is_new"] is True
    assert result["authorised"] is True
    assert result["role"] == "inverter"

    # Verify device persisted in DB
    dev = get_device_by_ip(in_memory_db, "172.20.0.11")
    assert dev is not None
    assert dev["role"] == "inverter"
    assert dev["authorised"] == 1
    assert "modbus-tcp:502" in dev["protocols"]


def test_upsert_existing_device_updates_last_seen(in_memory_db):
    upsert_device(in_memory_db, "172.20.0.12", protocol="modbus-tcp", port=502)
    dev_first = get_device_by_ip(in_memory_db, "172.20.0.12")

    result = upsert_device(in_memory_db, "172.20.0.12", protocol="modbus-tcp", port=502)
    assert result["is_new"] is False
    assert result["authorised"] is True

    dev_second = get_device_by_ip(in_memory_db, "172.20.0.12")
    assert dev_second["first_seen_utc"] == dev_first["first_seen_utc"]


def test_upsert_unknown_device_flagged(in_memory_db):
    rogue_ip = "192.168.1.100"
    result = upsert_device(in_memory_db, rogue_ip, protocol="modbus-tcp", port=502)
    assert result["ip"] == rogue_ip
    assert result["is_new"] is True
    assert result["authorised"] is False
    assert result["role"] == "unknown"

    dev = get_device_by_ip(in_memory_db, rogue_ip)
    assert dev["authorised"] == 0
    assert dev["role"] == "unknown"


def test_get_all_devices(in_memory_db):
    upsert_device(in_memory_db, "172.20.0.11", protocol="modbus-tcp", port=502)
    upsert_device(in_memory_db, "172.20.0.12", protocol="modbus-tcp", port=502)
    upsert_device(in_memory_db, "10.0.0.99", protocol="modbus-tcp", port=502)

    devices = get_all_devices(in_memory_db)
    assert len(devices) == 3
    ips = [d["ip"] for d in devices]
    assert "172.20.0.11" in ips
    assert "172.20.0.12" in ips
    assert "10.0.0.99" in ips


def test_upsert_tracks_peers(in_memory_db):
    upsert_device(in_memory_db, "172.20.0.11", protocol="modbus-tcp", port=502, peer_ip="172.20.0.40")
    dev = get_device_by_ip(in_memory_db, "172.20.0.11")
    peers = json.loads(dev["peers"])
    assert "172.20.0.40" in peers

    # Add second peer
    upsert_device(in_memory_db, "172.20.0.11", protocol="modbus-tcp", port=502, peer_ip="172.20.0.31")
    dev = get_device_by_ip(in_memory_db, "172.20.0.11")
    peers = json.loads(dev["peers"])
    assert len(peers) == 2
    assert "172.20.0.40" in peers
    assert "172.20.0.31" in peers


def test_baseline_relationships_seeded(in_memory_db):
    baseline = get_baseline_relationships(in_memory_db)
    assert len(baseline) >= 5
    # Check HMI -> Inverter 1 modbus-tcp 502
    hmi_rel = [r for r in baseline if r["src_ip"] == "172.20.0.40" and r["dst_ip"] == "172.20.0.11"]
    assert len(hmi_rel) == 1
    assert hmi_rel[0]["protocol"] == "modbus-tcp"
    assert hmi_rel[0]["dst_port"] == 502


def test_is_relationship_approved_and_manual_approval(in_memory_db):
    # Approved baseline relationship
    assert is_relationship_approved(in_memory_db, "172.20.0.40", "172.20.0.11", "modbus-tcp", 502) is True

    # Unapproved relationship
    assert is_relationship_approved(in_memory_db, "172.20.0.11", "172.20.0.12", "modbus-tcp", 502) is False

    # Approve relationship manually
    result = approve_relationship(
        in_memory_db,
        src_ip="172.20.0.11",
        dst_ip="172.20.0.12",
        protocol="modbus-tcp",
        dst_port=502,
        approved_by="soc_analyst",
        notes="Permitted inter-inverter telemetry check"
    )
    assert result["approved"] is True
    assert result["approved_by"] == "soc_analyst"
    assert is_relationship_approved(in_memory_db, "172.20.0.11", "172.20.0.12", "modbus-tcp", 502) is True


def test_inventory_confidence_and_mac(in_memory_db):
    # Known device
    upsert_device(in_memory_db, "172.20.0.11", protocol="modbus-tcp", port=502, mac="02:42:ac:14:00:0b")
    dev = get_device_by_ip(in_memory_db, "172.20.0.11")
    assert dev["confidence"] == "manifest_verified"
    assert dev["mac"] == "02:42:ac:14:00:0b"

    # Rogue device without MAC
    upsert_device(in_memory_db, "10.99.99.99", protocol="modbus-tcp", port=502)
    dev_rogue = get_device_by_ip(in_memory_db, "10.99.99.99")
    assert dev_rogue["confidence"] == "observed_unknown"
    assert dev_rogue["mac"] == "unknown/not_observable"

