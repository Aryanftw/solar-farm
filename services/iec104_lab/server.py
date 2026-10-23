"""
IEC 60870-5-104 Server — Solar Farm Grid Endpoint
Uses c104 (Fraunhofer IEC104-Python, wrapping lib60870).

Exposes simulated IEC-104 data points representing solar farm grid values.
Also reports events to the FastAPI backend for inventory/alert tracking.

Port: 2404 (IEC-104 standard)
"""

import logging
import os
import signal
import sys
import time
import random
import requests

try:
    import c104
    HAS_C104 = True
except ImportError:
    HAS_C104 = False
    import types
    # Placeholder namespace so annotation evaluation succeeds in stub mode
    c104 = types.SimpleNamespace(
        Server=object,
        Point=object,
        IncomingMessage=object,
        ResponseState=object,
    )
    logging.warning("c104 not available — IEC-104 server running in stub mode")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [iec104_server] %(message)s",
)
logger = logging.getLogger("iec104_server")

IEC104_PORT = int(os.getenv("IEC104_PORT", "2404"))
API_URL = os.getenv("API_URL", "http://172.20.0.50:8000")

# IEC-104 Common Address of ASDU (station address)
COMMON_ADDRESS = 1

# Information Object Addresses (IOA)
IOA_PLANT_ACTIVE_POWER = 100   # M_ME_NC_1 — measured float, total plant power
IOA_PLANT_STATUS = 101          # M_SP_NA_1 — single-point: plant running
IOA_GRID_FREQUENCY = 102       # M_ME_NC_1 — grid frequency Hz
IOA_SETPOINT_ACK = 200         # C_SE_NC_1 — setpoint command echo

running = True


def report_event(event_type: str, data: dict) -> None:
    """Post an event to the FastAPI ingestor."""
    try:
        requests.post(
            f"{API_URL}/ingest/iec104_event",
            json={"event_type": event_type, "data": data},
            timeout=2,
        )
    except Exception as exc:
        logger.debug("API report failed: %s", exc)


def on_connect(server: c104.Server, ip: str) -> bool:
    """Callback when a client connects. Signature (c104.Server, ip) -> bool."""
    logger.info("New IEC-104 connection from %s", ip)
    report_event("iec104_connection", {
        "src_ip": ip,
        "dst_ip": "172.20.0.30",
        "port": IEC104_PORT,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })
    return True


def on_receive_point(
    point: c104.Point,
    previous_state: dict,
    message: c104.IncomingMessage,
) -> c104.ResponseState:
    """Callback when a control point is received (e.g., C_SE, C_SC)."""
    logger.info(
        "RECEIVED control: IOA=%s type=%s value=%s from connection",
        point.io_address,
        point.type,
        point.value,
    )
    # Report to API for detection
    report_event("iec104_control_received", {
        "ioa": point.io_address,
        "asdu_type": str(point.type),
        "value": str(point.value),
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })
    return c104.ResponseState.SUCCESS


def run_c104_server() -> None:
    """Start the real c104-based IEC-104 server."""
    server = c104.Server(ip="0.0.0.0", port=IEC104_PORT)
    server.on_connect(callable=on_connect)

    station = server.add_station(common_address=COMMON_ADDRESS)

    # Add measurement points (report_ms auto-transmits periodically to clients)
    plant_power = station.add_point(
        io_address=IOA_PLANT_ACTIVE_POWER,
        type=c104.Type.M_ME_NC_1,   # Measured value, short floating point
        report_ms=5000,
    )
    plant_status = station.add_point(
        io_address=IOA_PLANT_STATUS,
        type=c104.Type.M_SP_NA_1,   # Single-point information
        report_ms=5000,
    )
    grid_freq = station.add_point(
        io_address=IOA_GRID_FREQUENCY,
        type=c104.Type.M_ME_NC_1,
        report_ms=5000,
    )

    # Add writable setpoint point (for attack scenario S4)
    setpoint_cmd = station.add_point(
        io_address=IOA_SETPOINT_ACK,
        type=c104.Type.C_SE_NC_1,   # Set-point command, short floating point
        report_ms=0,
    )
    setpoint_cmd.on_receive(callable=on_receive_point)

    server.start()
    logger.info("IEC-104 server started on port %d", IEC104_PORT)

    total_power = 0.0
    freq = 50.0

    try:
        while running:
            # Simulate total plant power (sum of 3 inverters, roughly)
            import math
            t = time.time()
            hour = (t % 86400) / 3600
            irr = max(0.0, math.sin(math.pi * (hour - 6) / 12))
            total_power = irr * 595_000.0   # ~595 kW peak total

            # Update measurement points (auto-transmitted via report_ms)
            plant_power.value = total_power
            plant_status.value = 1.0 if irr > 0.01 else 0.0
            grid_freq.value = freq + random.uniform(-0.05, 0.05)

            time.sleep(5)
    except Exception as exc:
        logger.error("Server loop error: %s", exc)
    finally:
        server.stop()
        logger.info("IEC-104 server stopped")


def run_stub_server() -> None:
    """Fallback TCP stub when c104 is not available."""
    import socket
    logger.warning("Running IEC-104 stub TCP server on port %d", IEC104_PORT)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", IEC104_PORT))
        srv.listen(5)
        srv.settimeout(1)
        while running:
            try:
                conn, addr = srv.accept()
                logger.info("Stub connection from %s", addr)
                report_event("iec104_connection", {
                    "src_ip": addr[0],
                    "dst_ip": "172.20.0.30",
                    "port": IEC104_PORT,
                    "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "stub_mode": True,
                })
                conn.close()
            except socket.timeout:
                continue


def signal_handler(sig, frame) -> None:
    global running
    logger.info("Shutdown signal received")
    running = False
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    if HAS_C104:
        try:
            run_c104_server()
        except Exception as exc:
            logger.error("c104 server failed, falling back to stub mode: %s", exc)
            running = True
            run_stub_server()
    else:
        run_stub_server()
