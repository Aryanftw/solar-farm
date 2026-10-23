"""
Attack Scenario Runner — B5
Local-only attack simulator. Targets ONLY containers in the private lab network.
All scenarios are bounded, finite, and repeatable.

SAFETY:
  - Only connects to hardcoded lab hostnames/IPs (172.20.0.0/24)
  - No internet access, no public IPs, no real PLCs
  - Each scenario stops after a finite number of requests
  - Run 'make reset' to restore clean lab state after scenarios

Usage:
  python run_scenario.py S1
  python run_scenario.py S2
  python run_scenario.py all
"""

import argparse
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [scenario] %(message)s",
)
logger = logging.getLogger("scenario_runner")

API_URL = "http://127.0.0.1:8000"

# Deduplicate alerts within a single scenario run; each invocation is distinct.
RUN_ID = f"scenario-{uuid.uuid4().hex[:12]}"

# ── Lab-only targets (private subnet) ────────────────────────────────────────
# When run inside Docker, use container IPs directly
DOCKER_INVERTER1 = "172.20.0.11"
DOCKER_INVERTER2 = "172.20.0.12"
DOCKER_IEC104_SERVER = "172.20.0.30"
ROGUE_IP = "172.20.0.99"   # simulated rogue IP (injected via scenario_id)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _out_of_window_ts() -> str:
    """
    Return a recent timestamp guaranteed to be outside the configured
    maintenance windows (02:00–04:00 and Mon/Wed/Fri 20:00–20:30 UTC).

    S5 must be deterministic: running the demo inside a maintenance window
    should still exercise the out-of-window rule. Noon is outside both windows.
    """
    now = datetime.now(timezone.utc)
    candidate = now.replace(hour=12, minute=0, second=0, microsecond=0)
    if candidate > now:
        candidate -= timedelta(days=1)
    return candidate.strftime("%Y-%m-%dT%H:%M:%SZ")


def _post_event(event: dict) -> dict:
    """Post a Modbus event to the API ingestor."""
    event.setdefault("run_id", RUN_ID)
    try:
        r = requests.post(f"{API_URL}/ingest/modbus", json=event, timeout=5)
        return r.json() if r.ok else {"error": r.text}
    except Exception as e:
        return {"error": str(e)}


def _post_iec104_event(event_type: str, data: dict) -> dict:
    """Post an IEC-104 event to the API ingestor."""
    data.setdefault("run_id", RUN_ID)
    try:
        r = requests.post(f"{API_URL}/ingest/iec104_event", json={"event_type": event_type, "data": data}, timeout=5)
        return r.json() if r.ok else {"error": r.text}
    except Exception as e:
        return {"error": str(e)}


def _record_trial(scenario_id: str, trial_number: int, expected_rule: str,
                  start_ts: str, alert_ids: list) -> None:
    """Record trial results for validation metrics."""
    end_ts = _now()
    alert_generated = len(alert_ids) > 0
    latency = None
    if alert_generated:
        try:
            t_start = datetime.strptime(start_ts, "%Y-%m-%dT%H:%M:%SZ").timestamp()
            t_end = datetime.strptime(end_ts, "%Y-%m-%dT%H:%M:%SZ").timestamp()
            latency = t_end - t_start
        except Exception:
            pass

    trial = {
        "scenario_id": scenario_id,
        "trial_number": trial_number,
        "started_utc": start_ts,
        "expected_alert_rule": expected_rule,
        "alert_generated": alert_generated,
        "alert_id": alert_ids[0] if alert_ids else None,
        "alert_latency_seconds": latency,
        "false_positive": False,
        "notes": f"Alert IDs: {alert_ids}",
    }
    try:
        requests.post(f"{API_URL}/trials", json=trial, timeout=5)
    except Exception as e:
        logger.warning("Could not record trial: %s", e)


def scenario_s1(trial: int = 1) -> list:
    """
    S1 — Rogue Device Joins
    A new, unapproved Modbus client (IP 172.20.0.99) performs read requests.
    Expected: UNKNOWN_DEVICE alert.
    """
    logger.info("=" * 60)
    logger.info("SCENARIO S1 — Rogue Device Joins (trial %d)", trial)
    logger.info("Target: Lab inverter1 | Rogue IP: %s", ROGUE_IP)
    logger.info("Expected alert: UNKNOWN_DEVICE")
    start_ts = _now()

    alert_ids = []
    # Simulate 5 read requests from rogue IP
    for i in range(5):
        event = {
            "timestamp_utc": _now(),
            "src_ip": ROGUE_IP,
            "dst_ip": DOCKER_INVERTER1,
            "dst_port": 502,
            "function_code": 4,  # Read Input Registers
            "register_address": 0,
            "raw_value": None,
            "scenario_id": "S1",
            "source": "scenario",
        }
        result = _post_event(event)
        if result.get("alert_ids"):
            alert_ids.extend(result["alert_ids"])
        logger.info("Request %d/5 posted, alerts: %s", i + 1, result.get("alert_ids", []))
        time.sleep(0.5)

    logger.info("S1 complete. Alert IDs: %s", alert_ids)
    _record_trial("S1", trial, "UNKNOWN_DEVICE", start_ts, alert_ids)
    return alert_ids


def scenario_s2(trial: int = 1) -> list:
    """
    S2 — Unauthorised Setpoint Write
    Rogue client writes to the protected setpoint register on inverter1.
    Expected: UNAUTHORISED_MODBUS_WRITE + PROTECTED_SETPOINT_CHANGE alerts.
    """
    logger.info("=" * 60)
    logger.info("SCENARIO S2 — Unauthorised Setpoint Write (trial %d)", trial)
    logger.info("Target: inverter1 HR[0] (active_power_setpoint)")
    logger.info("Expected alerts: UNAUTHORISED_MODBUS_WRITE, PROTECTED_SETPOINT_CHANGE")
    start_ts = _now()

    alert_ids = []
    # FC 6 = Write Single Register to holding register 0 (setpoint)
    event = {
        "timestamp_utc": _now(),
        "src_ip": ROGUE_IP,
        "dst_ip": DOCKER_INVERTER1,
        "dst_port": 502,
        "function_code": 6,   # Write Single Register
        "register_address": 0,  # active_power_setpoint (protected)
        "raw_value": 1000,      # set to only 1kW (attack: reduce output)
        "scenario_id": "S2",
        "source": "scenario",
    }
    result = _post_event(event)
    if result.get("alert_ids"):
        alert_ids.extend(result["alert_ids"])
    logger.info("Write posted, alerts: %s", result.get("alert_ids", []))

    logger.info("S2 complete. Alert IDs: %s", alert_ids)
    _record_trial("S2", trial, "PROTECTED_SETPOINT_CHANGE", start_ts, alert_ids)
    return alert_ids


def scenario_s3(trial: int = 1) -> list:
    """
    S3 — Write Burst
    Rogue client sends a burst of 15 writes to inverter2.
    Expected: MODBUS_WRITE_BURST alert.
    """
    logger.info("=" * 60)
    logger.info("SCENARIO S3 — Write Burst (trial %d)", trial)
    logger.info("Target: inverter2 | %d writes in 15 seconds", 15)
    logger.info("Expected alert: MODBUS_WRITE_BURST")
    start_ts = _now()

    alert_ids = []
    for i in range(15):
        event = {
            "timestamp_utc": _now(),
            "src_ip": ROGUE_IP,
            "dst_ip": DOCKER_INVERTER2,
            "dst_port": 502,
            "function_code": 6,
            "register_address": 2,   # ramp_rate register (not protected)
            "raw_value": i * 100,
            "scenario_id": "S3",
            "source": "scenario",
        }
        result = _post_event(event)
        if result.get("alert_ids"):
            alert_ids.extend(result["alert_ids"])
        if i % 5 == 4:
            logger.info("  Burst %d/15 sent, cumulative alerts: %d", i + 1, len(alert_ids))
        time.sleep(1)   # 15 writes in ~15 seconds → exceeds 10/30s threshold

    logger.info("S3 complete. Alert IDs: %s", alert_ids)
    _record_trial("S3", trial, "MODBUS_WRITE_BURST", start_ts, alert_ids)
    return alert_ids


def scenario_s4(trial: int = 1) -> list:
    """
    S4 — Unexpected IEC-104 Control
    An unapproved IEC-104 master (172.20.0.88) sends a control ASDU.
    Expected: IEC104_UNEXPECTED_CONTROL alert.
    """
    logger.info("=" * 60)
    logger.info("SCENARIO S4 — Unexpected IEC-104 Control (trial %d)", trial)
    logger.info("Rogue IEC-104 master: 172.20.0.88 → IEC-104 server")
    logger.info("Expected alert: IEC104_UNEXPECTED_CONTROL")
    start_ts = _now()

    alert_ids = []
    rogue_master_ip = "172.20.0.88"

    event_data = {
        "src_ip": rogue_master_ip,
        "src_port": 45123,
        "dst_ip": DOCKER_IEC104_SERVER,
        "asdu_type": "C_SE_NC_1",   # Set-point command, short floating point
        "ioa": 200,
        "value": "0.0",
        "timestamp_utc": _now(),
        "scenario_id": "S4",
    }
    result = _post_iec104_event("iec104_control_received", event_data)
    if result.get("alert_ids"):
        alert_ids.extend(result["alert_ids"])
    logger.info("IEC-104 control posted, alerts: %s", result.get("alert_ids", []))

    # Also make the rogue IP known as unknown device via Modbus
    modbus_event = {
        "timestamp_utc": _now(),
        "src_ip": rogue_master_ip,
        "dst_ip": DOCKER_IEC104_SERVER,
        "dst_port": 2404,
        "function_code": 0,
        "scenario_id": "S4",
        "source": "scenario",
    }
    r2 = _post_event(modbus_event)
    if r2.get("alert_ids"):
        alert_ids.extend(r2["alert_ids"])

    logger.info("S4 complete. Alert IDs: %s", alert_ids)
    _record_trial("S4", trial, "IEC104_UNEXPECTED_CONTROL", start_ts, alert_ids)
    return alert_ids


def scenario_s5(trial: int = 1) -> list:
    """
    S5 — Out-of-Window Write / ML Anomaly
    Authorised HMI IP writes outside maintenance window.
    Expected: OUT_OF_WINDOW_WRITE alert (and possibly ML_ANOMALY).
    """
    logger.info("=" * 60)
    logger.info("SCENARIO S5 — Out-of-Window Write (trial %d)", trial)
    logger.info("Source: HMI IP (authorised writer but outside window)")
    logger.info("Expected alert: OUT_OF_WINDOW_WRITE")
    start_ts = _now()

    alert_ids = []
    hmi_ip = "172.20.0.40"  # FUXA HMI — authorised writer
    event_ts = _out_of_window_ts()
    logger.info("Using out-of-window event timestamp: %s", event_ts)

    event = {
        "timestamp_utc": event_ts,
        "src_ip": hmi_ip,
        "dst_ip": DOCKER_INVERTER1,
        "dst_port": 502,
        "function_code": 6,
        "register_address": 1,   # voltage_setpoint (not protected, but write is out-of-window)
        "raw_value": 2350,
        "scenario_id": "S5",
        "source": "scenario",
    }
    result = _post_event(event)
    if result.get("alert_ids"):
        alert_ids.extend(result["alert_ids"])
    logger.info("Out-of-window write posted, alerts: %s", result.get("alert_ids", []))

    logger.info("S5 complete. Alert IDs: %s", alert_ids)
    _record_trial("S5", trial, "OUT_OF_WINDOW_WRITE", start_ts, alert_ids)
    return alert_ids


def scenario_s6(trial: int = 1) -> list:
    """
    S6 — Out-of-Range Setpoint Write
    Authorized HMI IP commands active power setpoint of 350,000 W (safe limit: 250,000 W).
    Expected: OUT_OF_RANGE_SETPOINT alert (with simulated lab limit explanation).
    """
    logger.info("=" * 60)
    logger.info("SCENARIO S6 — Out-of-Range Setpoint Write (trial %d)", trial)
    logger.info("Target: inverter1 HR[0] | Commanded: 350,000 W (safe range: 0 - 250,000 W)")
    logger.info("Expected alert: OUT_OF_RANGE_SETPOINT")
    start_ts = _now()

    alert_ids = []
    hmi_ip = "172.20.0.40"  # Authorized writer, but commanded value violates safety envelope

    event = {
        "timestamp_utc": _now(),
        "src_ip": hmi_ip,
        "dst_ip": DOCKER_INVERTER1,
        "dst_port": 502,
        "function_code": 6,
        "register_address": 0,    # active_power_setpoint
        "raw_value": 350000,      # Out of bounds (> 250,000 W)
        "scenario_id": "S6",
        "source": "scenario",
    }
    result = _post_event(event)
    if result.get("alert_ids"):
        alert_ids.extend(result["alert_ids"])
    logger.info("Out-of-range write posted, alerts: %s", result.get("alert_ids", []))

    logger.info("S6 complete. Alert IDs: %s", alert_ids)
    _record_trial("S6", trial, "OUT_OF_RANGE_SETPOINT", start_ts, alert_ids)
    return alert_ids


def scenario_s7(trial: int = 1) -> list:
    """
    S7 — Protocol and Peer Drift
    Inverter 1 sends an unexpected Modbus command to Inverter 2 (lateral movement / peer drift).
    Expected: PROTOCOL_PEER_DRIFT alert.
    """
    logger.info("=" * 60)
    logger.info("SCENARIO S7 — Protocol and Peer Drift (trial %d)", trial)
    logger.info("Source: Inverter 1 (172.20.0.11) -> Inverter 2 (172.20.0.12) [Unapproved peer relationship]")
    logger.info("Expected alert: PROTOCOL_PEER_DRIFT")
    start_ts = _now()

    alert_ids = []
    event = {
        "timestamp_utc": _now(),
        "src_ip": DOCKER_INVERTER1,
        "dst_ip": DOCKER_INVERTER2,
        "dst_port": 502,
        "function_code": 4,
        "register_address": 0,
        "scenario_id": "S7",
        "source": "scenario",
    }
    result = _post_event(event)
    if result.get("alert_ids"):
        alert_ids.extend(result["alert_ids"])
    logger.info("Lateral peer request posted, alerts: %s", result.get("alert_ids", []))

    logger.info("S7 complete. Alert IDs: %s", alert_ids)
    _record_trial("S7", trial, "PROTOCOL_PEER_DRIFT", start_ts, alert_ids)
    return alert_ids


def scenario_n1(trial: int = 1) -> list:
    """
    N1 — Legitimate Baseline Traffic (Normal SCADA Polling)
    Authorized FUXA HMI polls inverters and OpenPLC, OpenPLC polls inverters,
    and Grid Control interrogates the substation.
    Expected: 0 alerts (True Negative; any alert is a False Alarm).
    """
    logger.info("=" * 60)
    logger.info("SCENARIO N1 — Legitimate SCADA Polling Baseline (trial %d)", trial)
    logger.info("Normal traffic across all simulated solar farm assets")
    logger.info("Expected: 0 alerts")
    start_ts = _now()

    alert_ids = []

    # 1. FUXA HMI (172.20.0.40) polling inverters (FC4) and OpenPLC (FC3)
    for dst in [DOCKER_INVERTER1, DOCKER_INVERTER2, "172.20.0.13"]:
        event = {
            "timestamp_utc": _now(),
            "src_ip": "172.20.0.40",
            "dst_ip": dst,
            "dst_port": 502,
            "function_code": 4,   # Read input registers
            "register_address": 0,
            "scenario_id": "N1",
            "source": "scenario",
        }
        result = _post_event(event)
        if result.get("alert_ids"):
            alert_ids.extend(result["alert_ids"])

    # FUXA polling OpenPLC
    result = _post_event({
        "timestamp_utc": _now(),
        "src_ip": "172.20.0.40",
        "dst_ip": "172.20.0.20",
        "dst_port": 502,
        "function_code": 3,       # Read holding registers
        "register_address": 0,
        "scenario_id": "N1",
        "source": "scenario",
    })
    if result.get("alert_ids"):
        alert_ids.extend(result["alert_ids"])

    # 2. OpenPLC (172.20.0.20) polling inverters
    for dst in [DOCKER_INVERTER1, DOCKER_INVERTER2, "172.20.0.13"]:
        result = _post_event({
            "timestamp_utc": _now(),
            "src_ip": "172.20.0.20",
            "dst_ip": dst,
            "dst_port": 502,
            "function_code": 4,
            "register_address": 0,
            "scenario_id": "N1",
            "source": "scenario",
        })
        if result.get("alert_ids"):
            alert_ids.extend(result["alert_ids"])

    # 3. Grid Control (172.20.0.31) interrogating IEC-104 Substation (172.20.0.30)
    iec_result = _post_iec104_event("iec104_interrogation", {
        "src_ip": "172.20.0.31",
        "dst_ip": "172.20.0.30",
        "port": 2404,
        "asdu_type": "C_IC_NA_1",
        "ioa": 0,
        "qoi": 20,
        "value": "station_interrogation",
        "timestamp_utc": _now(),
        "scenario_id": "N1",
    })
    if iec_result.get("alert_ids"):
        alert_ids.extend(iec_result["alert_ids"])

    # 4. Sensor health report (172.20.0.60 -> 172.20.0.50)
    try:
        requests.post(
            f"{API_URL}/sensor/health",
            json={
                "sensor_running": True,
                "traffic_observed": True,
                "capture_mode": "passive_audit",
                "packets_seen": 150,
                "last_protocol_seen": "modbus-tcp",
            },
            timeout=3,
        )
    except Exception:
        pass

    logger.info("N1 complete. Alert IDs: %s (Expected: empty)", alert_ids)
    _record_trial("N1", trial, "NONE", start_ts, alert_ids)
    return alert_ids


SCENARIO_MAP = {
    "S1": scenario_s1,
    "S2": scenario_s2,
    "S3": scenario_s3,
    "S4": scenario_s4,
    "S5": scenario_s5,
    "S6": scenario_s6,
    "S7": scenario_s7,
    "N1": scenario_n1,
}


def print_summary(scenario_id: str, alert_ids: list) -> None:
    logger.info("")
    logger.info("-" * 60)
    logger.info("SCENARIO %s RESULT:", scenario_id)
    logger.info("  Start time   : %s", _now())
    logger.info("  Alert IDs    : %s", alert_ids if alert_ids else "NONE (expected for normal traffic or check API)")
    logger.info("  Dashboard    : http://127.0.0.1:8501 -> Alerts page")
    logger.info("  API alerts   : http://127.0.0.1:8000/alerts?scenario_id=%s", scenario_id)
    logger.info("-" * 60)


def main() -> None:
    parser = argparse.ArgumentParser(description="Solar Farm OT Security Lab Scenario Runner")
    parser.add_argument("scenario", choices=list(SCENARIO_MAP.keys()) + ["all"], help="Scenario to run")
    parser.add_argument("--trial", type=int, default=1, help="Trial number for validation tracking")
    args = parser.parse_args()

    if args.scenario == "all":
        all_alert_ids = []
        for sid, fn in SCENARIO_MAP.items():
            logger.info("\n>> Running %s...", sid)
            aids = fn(trial=args.trial)
            all_alert_ids.extend(aids)
            print_summary(sid, aids)
            time.sleep(2)  # brief pause between scenarios
        logger.info("\n[DONE] All scenarios complete. Total alerts generated: %d", len(all_alert_ids))
    else:
        fn = SCENARIO_MAP[args.scenario]
        aids = fn(trial=args.trial)
        print_summary(args.scenario, aids)


if __name__ == "__main__":
    main()

