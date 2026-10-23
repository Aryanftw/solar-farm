"""
IEC 60870-5-104 Client — Fake Grid Control Centre
Performs periodic interrogation and status exchange with the IEC-104 server.
Reports all transactions to the FastAPI backend.

SAFETY: Only connects to the lab's private IEC-104 server (172.20.0.30).
        Never connects to any real-world endpoint.
"""

import logging
import os
import signal
import sys
import time
import requests

try:
    import c104
    HAS_C104 = True
except ImportError:
    HAS_C104 = False
    import types
    # Placeholder namespace so annotation evaluation succeeds in stub mode
    c104 = types.SimpleNamespace(
        Connection=object,
        ConnectionState=object,
        Point=object,
        IncomingMessage=object,
        ResponseState=object,
    )

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [iec104_client] %(message)s",
)
logger = logging.getLogger("iec104_client")

SERVER_HOST = os.getenv("IEC104_SERVER_HOST", "172.20.0.30")
IEC104_PORT = int(os.getenv("IEC104_PORT", "2404"))
API_URL = os.getenv("API_URL", "http://172.20.0.50:8000")
COMMON_ADDRESS = 1
POLL_INTERVAL_S = 30   # interrogation every 30 seconds

running = True


def report_event(event_type: str, data: dict) -> None:
    try:
        requests.post(
            f"{API_URL}/ingest/iec104_event",
            json={"event_type": event_type, "data": data},
            timeout=2,
        )
    except Exception as exc:
        logger.debug("API report failed: %s", exc)


def on_receive_point(
    point: c104.Point,
    previous_state: dict,
    message: c104.IncomingMessage,
) -> c104.ResponseState:
    logger.info(
        "Received point IOA=%s type=%s value=%s",
        point.io_address,
        point.type,
        point.value,
    )
    report_event("iec104_measurement_received", {
        "ioa": point.io_address,
        "asdu_type": str(point.type),
        "value": str(point.value),
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "src_ip": "172.20.0.31",
        "dst_ip": SERVER_HOST,
    })
    return c104.ResponseState.SUCCESS


def on_state_change(
    connection: c104.Connection,
    state: c104.ConnectionState,
) -> None:
    logger.info(
        "Connection to %s:%d state changed: %s",
        SERVER_HOST,
        IEC104_PORT,
        state,
    )
    if state == c104.ConnectionState.OPEN:
        report_event("iec104_connection", {
            "src_ip": "172.20.0.31",
            "dst_ip": SERVER_HOST,
            "port": IEC104_PORT,
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })


def run_c104_client() -> None:
    client = c104.Client()
    connection = client.add_connection(
        ip=SERVER_HOST,
        port=IEC104_PORT,
        init=c104.Init.NONE,
    )
    connection.on_state_change(callable=on_state_change)
    station = connection.add_station(common_address=COMMON_ADDRESS)

    # Subscribe to measurement points (types must match the server side)
    point_types = {
        100: c104.Type.M_ME_NC_1,
        101: c104.Type.M_SP_NA_1,
        102: c104.Type.M_ME_NC_1,
    }
    for ioa, ptype in point_types.items():
        point = station.add_point(io_address=ioa, type=ptype)
        point.on_receive(callable=on_receive_point)

    client.start()
    connection.connect()
    logger.info(
        "IEC-104 client started, connecting to %s:%d", SERVER_HOST, IEC104_PORT
    )

    poll_count = 0
    while running:
        try:
            if connection.is_connected:
                # General interrogation
                connection.interrogation(common_address=COMMON_ADDRESS)
                poll_count += 1
                logger.info("Interrogation #%d sent to %s", poll_count, SERVER_HOST)
                report_event("iec104_interrogation", {
                    "src_ip": "172.20.0.31",
                    "dst_ip": SERVER_HOST,
                    "common_address": COMMON_ADDRESS,
                    "poll_count": poll_count,
                    "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                })
            else:
                logger.warning("Not connected to IEC-104 server, waiting...")
        except Exception as exc:
            logger.error("Client loop error: %s", exc)
        time.sleep(POLL_INTERVAL_S)

    client.stop()
    logger.info("IEC-104 client stopped")


def run_stub_client() -> None:
    """Fallback stub client."""
    import socket
    logger.warning("Running IEC-104 stub client — c104 not available")
    poll_count = 0
    while running:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((SERVER_HOST, IEC104_PORT))
                poll_count += 1
                logger.info("Stub connection #%d to %s:%d", poll_count, SERVER_HOST, IEC104_PORT)
                report_event("iec104_interrogation", {
                    "src_ip": "172.20.0.31",
                    "dst_ip": SERVER_HOST,
                    "common_address": COMMON_ADDRESS,
                    "poll_count": poll_count,
                    "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "stub_mode": True,
                })
                s.close()
        except Exception as exc:
            logger.warning("Stub connection failed: %s", exc)
        time.sleep(POLL_INTERVAL_S)


def signal_handler(sig, frame) -> None:
    global running
    logger.info("Shutdown signal received")
    running = False
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    # Wait for server to be ready
    logger.info("Waiting 15s for IEC-104 server to start...")
    time.sleep(15)

    if HAS_C104:
        try:
            run_c104_client()
        except Exception as exc:
            logger.error("c104 client failed, falling back to stub mode: %s", exc)
            running = True
            run_stub_client()
    else:
        run_stub_client()
