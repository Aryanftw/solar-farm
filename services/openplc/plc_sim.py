"""
OpenPLC Simulation — RTU/PLC Aggregator
Simulates the OpenPLC Runtime Modbus interface for a solar plant PLC.

This service aggregates data from all three inverters and exposes it
via Modbus TCP, mimicking what OpenPLC Runtime v4 would expose.

On Linux, replace this with the actual OpenPLC Runtime v4 container
from: https://github.com/Autonomy-Logic/openplc-runtime

Register map (see /config/register_map.yaml for inverter details):
  Input Registers (FC04):
    0: Total plant active power (W)
    1: Plant voltage average (V*10)
    2: Plant operating status
    3: Inverter 1 power (W)
    4: Inverter 2 power (W)
    5: Inverter 3 power (W)
    6: Grid frequency (Hz*100)
    7: Plant alarm word

  Holding Registers (FC03/FC06):
    0: Plant setpoint total (W) - writable
    1: Emergency stop flag - writable
    2: Polling interval (s)
"""

import asyncio
import logging
import math
import os
import time

from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.server import StartAsyncTcpServer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [openplc] %(message)s",
)
logger = logging.getLogger("openplc")

HOST = os.getenv("OPENPLC_HOST", "0.0.0.0")
PORT = int(os.getenv("OPENPLC_PORT", "502"))
UNIT_ID = int(os.getenv("MODBUS_UNIT_ID", "1"))

# Register indices for PLC aggregation
IR_TOTAL_POWER = 0
IR_AVG_VOLTAGE = 1
IR_PLANT_STATUS = 2
IR_INV1_POWER = 3
IR_INV2_POWER = 4
IR_INV3_POWER = 5
IR_GRID_FREQ = 6
IR_ALARM_WORD = 7

HR_PLANT_SETPOINT = 0
HR_EMERGENCY_STOP = 1
HR_POLL_INTERVAL = 2


def get_irradiance(t: float) -> float:
    hour = (t % 86400) / 3600
    angle = math.pi * (hour - 6) / 12
    return max(0.0, math.sin(angle))


async def update_loop(context: ModbusServerContext) -> None:
    """Simulate PLC scan cycle — updates aggregated plant values every 1 second."""
    import random
    random.seed(99)
    while True:
        try:
            t = time.time()
            irr = get_irradiance(t)

            slave = context[UNIT_ID]

            # Check emergency stop
            emergency_stop = slave.getValues(3, HR_EMERGENCY_STOP, count=1)[0]
            if emergency_stop:
                status = 0  # stopped
                total_power = 0
                inv_powers = [0, 0, 0]
            else:
                status = 2 if irr > 0.05 else (1 if irr > 0.01 else 0)
                base_powers = [180_000, 200_000, 165_000]
                inv_powers = [int(irr * bp * (1 + random.gauss(0, 0.01))) for bp in base_powers]
                total_power = sum(inv_powers)

            avg_voltage = int(2300 + random.gauss(0, 3))
            grid_freq = int(5000 + random.gauss(0, 5))   # 50.00 Hz * 100
            alarm_word = 0

            slave.setValues(4, IR_TOTAL_POWER, [min(total_power, 65535)])
            slave.setValues(4, IR_AVG_VOLTAGE, [avg_voltage])
            slave.setValues(4, IR_PLANT_STATUS, [status])
            slave.setValues(4, IR_INV1_POWER, [min(inv_powers[0], 65535)])
            slave.setValues(4, IR_INV2_POWER, [min(inv_powers[1], 65535)])
            slave.setValues(4, IR_INV3_POWER, [min(inv_powers[2], 65535)])
            slave.setValues(4, IR_GRID_FREQ, [grid_freq])
            slave.setValues(4, IR_ALARM_WORD, [alarm_word])

            # Update shared state for web UI
            _state["total_power"] = total_power
            _state["status"] = status
            _state["irradiance"] = round(irr, 3)

            logger.info(
                "Plant: total=%dW status=%d irr=%.3f freq=%.2fHz",
                total_power, status, irr, grid_freq / 100
            )
        except Exception as exc:
            logger.error("PLC scan error: %s", exc)
        await asyncio.sleep(1)



WEB_PORT = int(os.getenv("OPENPLC_WEB_PORT", "8080"))

# Shared state dict updated by update_loop for display in web UI
_state: dict = {"total_power": 0, "status": 0, "irradiance": 0.0}


async def _http_handler(reader, writer) -> None:
    """Minimal HTTP/1.0 status page for the OpenPLC web interface."""
    try:
        await asyncio.wait_for(reader.readline(), timeout=3)
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=1)
            if line in (b"\r\n", b"\n", b""):
                break
    except Exception:
        pass

    s = _state
    status_names = {0: "stopped", 1: "starting", 2: "running", 3: "fault", 4: "standby"}
    html = (
        "<!DOCTYPE html><html><head><title>OpenPLC Runtime (Simulation)</title>"
        "<style>body{font-family:monospace;background:#0d1117;color:#e6edf3;padding:2rem;}"
        "h1{color:#3fb950;}.kv{margin:0.3rem 0;}.k{color:#8b949e;}"
        ".warn{color:#d29922;background:#1c1000;padding:0.5rem 1rem;border-radius:4px;}"
        "</style></head><body>"
        "<h1>OpenPLC Runtime &mdash; Solar Farm Lab</h1>"
        "<p class='warn'>Simulation mode &mdash; isolated lab only. "
        "No connection to real OT systems.</p>"
        "<h2>Plant Status</h2>"
        f"<div class='kv'><span class='k'>Total Active Power:</span> {s['total_power']:,} W</div>"
        f"<div class='kv'><span class='k'>Plant Status:</span> {status_names.get(s['status'], str(s['status']))}</div>"
        f"<div class='kv'><span class='k'>Solar Irradiance:</span> {s['irradiance']:.3f}</div>"
        "<h2>Modbus TCP Interface</h2>"
        f"<div class='kv'><span class='k'>Port:</span> {PORT}</div>"
        f"<div class='kv'><span class='k'>Unit ID:</span> {UNIT_ID}</div>"
        "<h2>Holding Registers (FC03)</h2>"
        "<div class='kv'><span class='k'>HR[0] Plant Setpoint (W):</span> writable</div>"
        "<div class='kv'><span class='k'>HR[1] Emergency Stop:</span> writable</div>"
        "<p><small>Solar Farm OT Security Watchman &mdash; Isolated lab simulation</small></p>"
        "</body></html>"
    )
    resp = (
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(html.encode())}\r\n"
        "Connection: close\r\n\r\n"
    )
    writer.write(resp.encode() + html.encode())
    await writer.drain()
    writer.close()


async def _run_web_server() -> None:
    """Serve status page on WEB_PORT (default 8080)."""
    srv = await asyncio.start_server(_http_handler, "0.0.0.0", WEB_PORT)
    logger.info("OpenPLC web status page on port %d", WEB_PORT)
    async with srv:
        await srv.serve_forever()


async def main() -> None:
    logger.info("OpenPLC simulation starting on %s:%d", HOST, PORT)
    logger.info("NOTE: This is a simulation. On Linux, use the actual OpenPLC Runtime v4.")
    logger.info("See: https://github.com/Autonomy-Logic/openplc-runtime")

    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [0] * 16),
        co=ModbusSequentialDataBlock(0, [0] * 16),
        hr=ModbusSequentialDataBlock(0, [0] * 16),
        ir=ModbusSequentialDataBlock(0, [0] * 16),
    )
    store.setValues(3, HR_PLANT_SETPOINT, [595_000 % 65536])
    store.setValues(3, HR_EMERGENCY_STOP, [0])
    store.setValues(3, HR_POLL_INTERVAL, [5])

    context = ModbusServerContext(slaves={UNIT_ID: store}, single=False)
    asyncio.ensure_future(update_loop(context))
    asyncio.ensure_future(_run_web_server())

    await StartAsyncTcpServer(context=context, address=(HOST, PORT))


if __name__ == "__main__":
    asyncio.run(main())
