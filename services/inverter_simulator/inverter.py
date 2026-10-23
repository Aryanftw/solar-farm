"""
Inverter Simulator — PyModbus TCP Server
Simulates a solar photovoltaic inverter with realistic, slowly-changing telemetry.

Register map: see /config/register_map.yaml (single source of truth).
All addresses are zero-based PDU addresses.

Environment variables:
  INVERTER_ID    : 1, 2, or 3 (controls seed, power level)
  INVERTER_HOST  : bind address (default 0.0.0.0)
  INVERTER_PORT  : TCP port (default 502)
  MODBUS_UNIT_ID : Modbus unit/slave ID (default 1)
"""

import asyncio
import logging
import math
import os
import random
import time
from typing import Dict

from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.server import StartAsyncTcpServer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [inverter%(inverter_id)s] %(message)s",
)

INVERTER_ID = int(os.getenv("INVERTER_ID", "1"))
HOST = os.getenv("INVERTER_HOST", "0.0.0.0")
PORT = int(os.getenv("INVERTER_PORT", "502"))
UNIT_ID = int(os.getenv("MODBUS_UNIT_ID", "1"))

# Seed per inverter for reproducibility
random.seed(INVERTER_ID * 42)

logger = logging.getLogger("inverter")
logger = logging.LoggerAdapter(logger, {"inverter_id": INVERTER_ID})

# ── Register indices (zero-based PDU, from register_map.yaml) ─────────────
# Input Registers (FC04)
IR_ACTIVE_POWER = 0       # Watts
IR_AC_VOLTAGE = 1         # V * 10
IR_OPERATING_STATUS = 2   # enum: 0=stopped 1=starting 2=running 3=fault 4=standby
IR_TEMPERATURE = 3        # °C * 10
IR_DC_INPUT_VOLTAGE = 4   # V * 10
IR_AC_CURRENT = 5         # A * 100
IR_DAILY_ENERGY = 6       # Wh

# Holding Registers (FC03/FC06/FC16)
HR_ACTIVE_POWER_SETPOINT = 0   # Watts (protected write)
HR_VOLTAGE_SETPOINT = 1        # V * 10
HR_RAMP_RATE = 2               # W/s

# Base values per inverter (each inverter has slightly different capacity)
BASE_POWER = {1: 180_000, 2: 200_000, 3: 165_000}   # Watts
BASE_VOLTAGE = 2300   # 230.0 V * 10
BASE_DC_VOLTAGE = 4500  # 450.0 V * 10
BASE_TEMP = 420       # 42.0 °C * 10


def get_solar_irradiance(t: float) -> float:
    """Simulate day/night cycle — peaks at solar noon (t mod 86400 = 43200)."""
    hour_of_day = (t % 86400) / 3600
    # Sine curve, peaks at noon, zero at night
    angle = math.pi * (hour_of_day - 6) / 12   # 06:00 sunrise, 18:00 sunset
    irradiance = max(0.0, math.sin(angle))
    return irradiance


def build_registers(context: ModbusServerContext) -> Dict[str, int]:
    """Compute current register values and write them into the datastore."""
    t = time.time()
    irradiance = get_solar_irradiance(t)

    # Small slow noise
    noise = 1.0 + random.gauss(0, 0.01)

    # Determine setpoint from holding register
    slave = context[UNIT_ID]
    setpoint = slave.getValues(3, HR_ACTIVE_POWER_SETPOINT, count=1)[0]
    max_power = BASE_POWER[INVERTER_ID]
    if setpoint == 0:
        setpoint = max_power

    # Actual power is min(setpoint, irradiance * max_power)
    active_power = int(min(setpoint, irradiance * max_power * noise))

    # Operating status
    if irradiance < 0.01:
        status = 0  # stopped
    elif irradiance < 0.05:
        status = 1  # starting
    else:
        status = 2  # running

    ac_voltage = int(BASE_VOLTAGE + random.gauss(0, 5))
    temperature = int(BASE_TEMP + irradiance * 150 + random.gauss(0, 10))
    dc_voltage = int(BASE_DC_VOLTAGE + irradiance * 2000 + random.gauss(0, 20))
    ac_current_raw = int((active_power / (ac_voltage / 10)) * 100) if ac_voltage > 0 else 0
    daily_energy = int(irradiance * max_power * 6)   # rough estimate

    # Write input registers (FC04 = 4, datablock address offset is 0)
    slave.setValues(4, IR_ACTIVE_POWER, [active_power])
    slave.setValues(4, IR_AC_VOLTAGE, [ac_voltage])
    slave.setValues(4, IR_OPERATING_STATUS, [status])
    slave.setValues(4, IR_TEMPERATURE, [temperature])
    slave.setValues(4, IR_DC_INPUT_VOLTAGE, [dc_voltage])
    slave.setValues(4, IR_AC_CURRENT, [ac_current_raw])
    slave.setValues(4, IR_DAILY_ENERGY, [daily_energy])

    return {
        "active_power_W": active_power,
        "ac_voltage_V": ac_voltage / 10,
        "status": status,
        "temperature_C": temperature / 10,
        "irradiance": round(irradiance, 3),
    }


async def update_loop(context: ModbusServerContext) -> None:
    """Update register values every 2 seconds."""
    while True:
        try:
            values = build_registers(context)
            logger.info(
                "P=%dW V=%.1fV T=%.1f°C irr=%.3f status=%d",
                values["active_power_W"],
                values["ac_voltage_V"],
                values["temperature_C"],
                values["irradiance"],
                values["status"],
            )
        except Exception as exc:
            logger.error("Update loop error: %s", exc)
        await asyncio.sleep(2)


async def main() -> None:
    logger.info("Starting Modbus TCP server on %s:%d (unit_id=%d)", HOST, PORT, UNIT_ID)

    # Initialise datastore — 16 registers each for ir/hr/coil/di
    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [0] * 16),
        co=ModbusSequentialDataBlock(0, [0] * 16),
        hr=ModbusSequentialDataBlock(0, [0] * 16),
        ir=ModbusSequentialDataBlock(0, [0] * 16),
    )
    # Initialise holding register defaults
    store.setValues(3, HR_ACTIVE_POWER_SETPOINT, [BASE_POWER[INVERTER_ID]])
    store.setValues(3, HR_VOLTAGE_SETPOINT, [BASE_VOLTAGE])
    store.setValues(3, HR_RAMP_RATE, [1000])

    context = ModbusServerContext(slaves={UNIT_ID: store}, single=False)

    # Run update loop concurrently
    asyncio.ensure_future(update_loop(context))

    await StartAsyncTcpServer(
        context=context,
        address=(HOST, PORT),
    )


if __name__ == "__main__":
    asyncio.run(main())
