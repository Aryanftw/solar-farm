"""
Unit tests — Modbus Register Map decoder
Verifies scale factors and address mappings from register_map.yaml.
"""

import os
import sys
import yaml
import pytest

REGISTER_MAP_PATH = os.path.join(os.path.dirname(__file__), "../../config/register_map.yaml")


@pytest.fixture
def register_map():
    with open(REGISTER_MAP_PATH) as f:
        return yaml.safe_load(f)


def test_register_map_loads(register_map):
    assert register_map is not None
    assert "input_registers" in register_map
    assert "holding_registers" in register_map


def test_active_power_register(register_map):
    regs = {r["name"]: r for r in register_map["input_registers"]}
    assert "active_power" in regs, "active_power register must exist"
    assert regs["active_power"]["address"] == 0, "active_power must be at address 0"
    assert regs["active_power"]["unit"] == "W"
    assert regs["active_power"]["scale"] == 1


def test_ac_voltage_scale(register_map):
    regs = {r["name"]: r for r in register_map["input_registers"]}
    assert regs["ac_voltage"]["scale"] == 10, "AC voltage scale must be 10 (raw/10 = V)"
    # Verify that raw 2300 → 230.0 V
    raw = 2300
    volts = raw / regs["ac_voltage"]["scale"]
    assert volts == 230.0


def test_temperature_scale(register_map):
    regs = {r["name"]: r for r in register_map["input_registers"]}
    assert regs["temperature"]["scale"] == 10, "Temperature scale must be 10 (raw/10 = °C)"
    raw = 452
    temp_c = raw / regs["temperature"]["scale"]
    assert temp_c == 45.2


def test_setpoint_register_protected(register_map):
    hold_regs = {r["name"]: r for r in register_map["holding_registers"]}
    assert "active_power_setpoint" in hold_regs
    assert hold_regs["active_power_setpoint"]["address"] == 0
    assert hold_regs["active_power_setpoint"]["writable"] is True
    assert hold_regs["active_power_setpoint"]["protected"] is True


def test_protected_address_matches_detection_config(register_map):
    """Detection config must match register map protected address."""
    detection = register_map.get("detection", {})
    protected_addr = detection.get("setpoint_register_address")
    hold_regs = {r["name"]: r for r in register_map["holding_registers"]}
    setpoint_addr = hold_regs["active_power_setpoint"]["address"]
    assert protected_addr == setpoint_addr, \
        "detection.setpoint_register_address must match holding_registers active_power_setpoint address"


def test_operating_status_enum_values(register_map):
    regs = {r["name"]: r for r in register_map["input_registers"]}
    status = regs["operating_status"]
    values = status.get("values", {})
    assert 0 in values and values[0] == "stopped"
    assert 2 in values and values[2] == "running"
    assert 3 in values and values[3] == "fault"


def test_all_required_registers_present(register_map):
    """B1 requirement: must have active_power, ac_voltage, operating_status, setpoint, temperature."""
    required_ir = {"active_power", "ac_voltage", "operating_status", "temperature"}
    required_hr = {"active_power_setpoint"}

    ir_names = {r["name"] for r in register_map["input_registers"]}
    hr_names = {r["name"] for r in register_map["holding_registers"]}

    for name in required_ir:
        assert name in ir_names, f"Required input register '{name}' missing from register map"
    for name in required_hr:
        assert name in hr_names, f"Required holding register '{name}' missing from register map"
