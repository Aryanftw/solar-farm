"""
FastAPI Main Application — Solar Farm OT Security Watchman
Event normaliser, inventory, alerts, health, and ML model API.
"""

import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

import sys
_API_DIR = os.path.dirname(os.path.abspath(__file__))
if _API_DIR not in sys.path:
    sys.path.insert(0, _API_DIR)

import database
import inventory
import rules
import anomaly

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s [api] %(message)s",
)
logger = logging.getLogger("api")

_DEFAULT_CONFIG = (
    "/app/config"
    if os.path.exists("/app/config")
    else os.path.abspath(os.path.join(os.path.dirname(__file__), "../../config"))
)
CONFIG_DIR = os.getenv("CONFIG_DIR", _DEFAULT_CONFIG)


@asynccontextmanager
async def lifespan(app: FastAPI):
    database.init_db()
    logger.info("Database initialised at %s", database.DB_PATH)
    yield


app = FastAPI(
    title="Solar Farm OT Security Watchman API",
    description=(
        "Event normaliser, device inventory, alert engine, and ML anomaly detection "
        "for the solar farm SCADA security lab. All data is from the local simulation only."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


# ── Pydantic models ─────────────────────────────────────────────────────────

class ModbusEvent(BaseModel):
    timestamp_utc: Optional[str] = None
    src_ip: str
    dst_ip: str
    dst_port: int = 502
    function_code: int
    register_address: Optional[int] = None
    raw_value: Optional[int] = None
    scenario_id: Optional[str] = None
    run_id: Optional[str] = None
    source: str = "zeek"


class IEC104Event(BaseModel):
    event_type: str
    data: dict


class ZeekModbusEvent(BaseModel):
    """Matches Zeek ICSNPP Modbus log format."""
    model_config = ConfigDict(populate_by_name=True)

    ts: Optional[float] = None
    uid: Optional[str] = None
    id_orig_h: str
    id_orig_p: Optional[int] = None
    id_resp_h: str
    id_resp_p: int = 502
    func: Optional[str] = None
    function_code: Optional[int] = None
    register_address: Optional[int] = Field(default=None, alias="register")
    value: Optional[int] = None
    scenario_id: Optional[str] = None
    run_id: Optional[str] = None


class BaselineWindow(BaseModel):
    window_start_utc: str
    window_end_utc: str
    src_ip: str
    total_requests: int = 0
    read_count: int = 0
    write_count: int = 0
    write_to_read_ratio: float = 0.0
    distinct_dst_devices: int = 0
    new_source: int = 0
    request_rate_deviation: float = 0.0
    protocol: str = "modbus-tcp"
    iec104_command_count: int = 0
    labelled: str = "normal"


class SensorHealth(BaseModel):
    sensor_running: bool
    traffic_observed: bool
    capture_mode: str
    packets_seen: int = 0
    last_protocol_seen: Optional[str] = None
    notes: Optional[str] = None


class TrialResult(BaseModel):
    scenario_id: str
    trial_number: int = 1
    started_utc: Optional[str] = None
    expected_alert_rule: str = "RULE-001"
    alert_generated: bool = False
    alert_id: Optional[str] = None
    alert_latency_seconds: Optional[float] = None
    false_positive: bool = False
    notes: Optional[str] = None


# ── Health ───────────────────────────────────────────────────────────────────

@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok", "timestamp_utc": datetime.now(timezone.utc).isoformat()}


@app.get("/", tags=["meta"])
def root():
    return {
        "service": "Solar Farm OT Security Watchman API",
        "docs": "/docs",
        "health": "/health",
    }


# ── Event Ingestion ──────────────────────────────────────────────────────────

@app.post("/ingest/modbus", tags=["ingest"], status_code=202)
def ingest_modbus_event(event: ModbusEvent):
    """Ingest a Modbus event: normalise, update inventory, run detection, score ML."""
    ts = event.timestamp_utc or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    with database.get_db() as conn:
        # Update inventory (track communication peers)
        inv_result = inventory.upsert_device(
            conn, event.src_ip, "modbus-tcp", event.dst_port, peer_ip=event.dst_ip
        )
        # Also track the destination device
        inventory.upsert_device(
            conn, event.dst_ip, "modbus-tcp", event.dst_port, peer_ip=event.src_ip, src="observed_dst"
        )


        # Persist event
        conn.execute(
            """INSERT INTO events
               (timestamp_utc, source, src_ip, dst_ip, dst_port, protocol,
                function_code, register_address, raw_value, scenario_id)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                ts, event.source, event.src_ip, event.dst_ip, event.dst_port,
                "modbus-tcp", event.function_code, event.register_address,
                event.raw_value, event.scenario_id,
            ),
        )
        event_id = conn.execute("SELECT last_insert_rowid() as id").fetchone()["id"]

        # Run rule engine
        detected_alerts = rules.evaluate_modbus_event(conn, event.model_dump(), inv_result)

        # Check write burst
        burst_alert = rules.check_write_burst(conn, event.src_ip, event.dst_ip, event.scenario_id, event.run_id)
        if burst_alert:
            detected_alerts.append(burst_alert)

        alert_ids = []
        for alert in detected_alerts:
            aid = rules.persist_alert(conn, alert)
            alert_ids.append(aid)

        # ML anomaly scoring (async-ish: score every 60 events)
        count_row = conn.execute(
            "SELECT COUNT(*) as c FROM events WHERE src_ip=?", (event.src_ip,)
        ).fetchone()
        if count_row["c"] % 60 == 0:
            result = anomaly.score_window(conn, event.src_ip)
            if result:
                score, explanation, feat_dict = result
                threshold = -0.1
                if score < threshold:
                    ml_alert = {
                        "rule_id": "RULE-ML-001",
                        "rule_name": "ML_ANOMALY",
                        "severity": "medium",
                        "src_ip": event.src_ip,
                        "dst_ip": event.dst_ip,
                        "dst_port": event.dst_port,
                        "protocol": "modbus-tcp",
                        "explanation": explanation,
                        "recommended_action": "Review corroborating deterministic rule alerts. ML anomaly alone is not proof of attack.",
                        "evidence_json": json.dumps(feat_dict),
                        "scenario_id": event.scenario_id,
                        "run_id": event.run_id,
                        "anomaly_score": score,
                        "top_features": explanation,
                        "ts": ts,
                    }
                    aid = rules.persist_alert(conn, ml_alert)
                    alert_ids.append(aid)

    return {"status": "accepted", "alert_ids": alert_ids, "event_id": event_id}


@app.post("/ingest/zeek_modbus", tags=["ingest"], status_code=202)
def ingest_zeek_modbus(event: ZeekModbusEvent):
    """Ingest a Modbus event from Zeek ICSNPP log format."""
    ts = (
        datetime.fromtimestamp(event.ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if event.ts
        else datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    # Map Zeek func string to integer FC if needed
    fc = event.function_code
    if fc is None and event.func:
        fc_map = {"read_holding_registers": 3, "read_input_registers": 4,
                  "write_single_register": 6, "write_multiple_registers": 16,
                  "write_single_coil": 5, "write_multiple_coils": 15}
        fc = fc_map.get(event.func, 0)

    modbus_event = ModbusEvent(
        timestamp_utc=ts,
        src_ip=event.id_orig_h,
        dst_ip=event.id_resp_h,
        dst_port=event.id_resp_p,
        function_code=fc or 0,
        register_address=event.register_address,
        raw_value=event.value,
        scenario_id=event.scenario_id,
        run_id=event.run_id,
        source="zeek",
    )
    return ingest_modbus_event(modbus_event)


@app.post("/ingest/iec104_event", tags=["ingest"], status_code=202)
def ingest_iec104_event(event: IEC104Event):
    """Ingest an IEC-104 event from the IEC-104 server/client."""
    data = event.data
    ts = data.get("timestamp_utc", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    src_ip = data.get("src_ip", "")

    dst_ip = data.get("dst_ip", "172.20.0.30")
    with database.get_db() as conn:
        # Update inventory (track communication peers)
        inv_result = inventory.upsert_device(conn, src_ip, "iec60870-5-104", 2404, peer_ip=dst_ip)
        inventory.upsert_device(conn, dst_ip, "iec60870-5-104", 2404, peer_ip=src_ip, src="observed_dst")


        # Persist event
        conn.execute(
            """INSERT INTO events
               (timestamp_utc, source, src_ip, dst_ip, dst_port, protocol,
                asdu_type, ioa, extra_json)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                ts, "iec104", src_ip,
                data.get("dst_ip", "172.20.0.30"), 2404,
                "iec60870-5-104",
                data.get("asdu_type"), data.get("ioa"),
                json.dumps(data),
            ),
        )
        event_id = conn.execute("SELECT last_insert_rowid() as id").fetchone()["id"]

        # Run IEC-104 rules
        detected_alerts = rules.evaluate_iec104_event(conn, {**data, "scenario_id": data.get("scenario_id")})
        alert_ids = []
        for alert in detected_alerts:
            aid = rules.persist_alert(conn, alert)
            alert_ids.append(aid)

    return {"status": "accepted", "alert_ids": alert_ids, "event_id": event_id}


# ── Inventory ────────────────────────────────────────────────────────────────

@app.get("/inventory", tags=["inventory"])
def get_inventory(authorised: Optional[bool] = None):
    with database.get_db() as conn:
        devices = inventory.get_all_devices(conn)
    if authorised is not None:
        devices = [d for d in devices if bool(d["authorised"]) == authorised]
    return {"devices": devices, "count": len(devices)}


@app.get("/inventory/{ip}", tags=["inventory"])
def get_device(ip: str):
    with database.get_db() as conn:
        dev = inventory.get_device_by_ip(conn, ip)
    if not dev:
        raise HTTPException(status_code=404, detail=f"Device {ip} not found")
    return dev


# ── Alerts ───────────────────────────────────────────────────────────────────

@app.get("/alerts", tags=["alerts"])
def get_alerts(
    severity: Optional[str] = None,
    rule_name: Optional[str] = None,
    scenario_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(default=100, le=500),
    offset: int = 0,
):
    filters = []
    params: list = []

    if severity:
        filters.append("severity=?")
        params.append(severity)
    if rule_name:
        filters.append("rule_name=?")
        params.append(rule_name)
    if scenario_id:
        filters.append("scenario_id=?")
        params.append(scenario_id)
    if status:
        filters.append("status=?")
        params.append(status)

    where = ("WHERE " + " AND ".join(filters)) if filters else ""
    query = f"SELECT * FROM alerts {where} ORDER BY timestamp_utc DESC LIMIT ? OFFSET ?"
    params += [limit, offset]

    with database.get_db() as conn:
        rows = conn.execute(query, params).fetchall()
        total = conn.execute(f"SELECT COUNT(*) as c FROM alerts {where}", params[:-2]).fetchone()["c"]

    return {"alerts": [dict(r) for r in rows], "total": total, "limit": limit, "offset": offset}


@app.get("/alerts/summary", tags=["alerts"])
def get_alert_summary():
    with database.get_db() as conn:
        rows = conn.execute(
            "SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity"
        ).fetchall()
        recent = conn.execute(
            "SELECT * FROM alerts ORDER BY timestamp_utc DESC LIMIT 5"
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) as c FROM alerts").fetchone()["c"]
    return {
        "total": total,
        "by_severity": {r["severity"]: r["count"] for r in rows},
        "recent_alerts": [dict(r) for r in recent],
    }


# ── Events ───────────────────────────────────────────────────────────────────

@app.get("/events", tags=["events"])
def get_events(
    src_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    limit: int = Query(default=200, le=1000),
    offset: int = 0,
):
    filters = []
    params: list = []
    if src_ip:
        filters.append("src_ip=?")
        params.append(src_ip)
    if protocol:
        filters.append("protocol=?")
        params.append(protocol)
    where = ("WHERE " + " AND ".join(filters)) if filters else ""
    query = f"SELECT * FROM events {where} ORDER BY timestamp_utc DESC LIMIT ? OFFSET ?"
    params += [limit, offset]

    with database.get_db() as conn:
        rows = conn.execute(query, params).fetchall()
    return {"events": [dict(r) for r in rows]}


@app.get("/timeline", tags=["events"])
def get_timeline(hours: int = 2):
    """Return events + alerts for the last N hours for timeline display."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with database.get_db() as conn:
        events = conn.execute(
            "SELECT timestamp_utc, src_ip, dst_ip, protocol, function_code, scenario_id FROM events WHERE timestamp_utc >= ? ORDER BY timestamp_utc",
            (cutoff,),
        ).fetchall()
        alerts = conn.execute(
            "SELECT timestamp_utc, rule_name, severity, src_ip, dst_ip, scenario_id FROM alerts WHERE timestamp_utc >= ? ORDER BY timestamp_utc",
            (cutoff,),
        ).fetchall()
    return {
        "events": [dict(r) for r in events],
        "alerts": [dict(r) for r in alerts],
        "since_utc": cutoff,
    }


# ── Sensor Health ────────────────────────────────────────────────────────────

@app.post("/sensor/health", tags=["sensor"])
def post_sensor_health(h: SensorHealth):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with database.get_db() as conn:
        conn.execute(
            """INSERT INTO sensor_health
               (timestamp_utc, sensor_running, traffic_observed, capture_mode, packets_seen, last_protocol_seen, notes)
               VALUES (?,?,?,?,?,?,?)""",
            (ts, int(h.sensor_running), int(h.traffic_observed), h.capture_mode,
             h.packets_seen, h.last_protocol_seen, h.notes),
        )
    return {"status": "ok"}


@app.get("/sensor/health", tags=["sensor"])
def get_sensor_health():
    with database.get_db() as conn:
        row = conn.execute(
            "SELECT * FROM sensor_health ORDER BY timestamp_utc DESC LIMIT 1"
        ).fetchone()
    if not row:
        return {"status": "no_data", "message": "No sensor health reports yet"}
    return dict(row)


# ── ML Model ─────────────────────────────────────────────────────────────────

@app.get("/model/status", tags=["model"])
def model_status():
    return anomaly.get_model_status()


@app.post("/model/train", tags=["model"])
def trigger_training():
    with database.get_db() as conn:
        try:
            meta = anomaly.train_model(conn)
            return {"status": "trained", "meta": meta}
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))


# ── Baseline Windows ──────────────────────────────────────────────────────────

@app.post("/baseline/window", tags=["baseline"], status_code=202)
def ingest_baseline_window(w: BaselineWindow):
    with database.get_db() as conn:
        conn.execute(
            """INSERT INTO baseline_windows
               (window_start_utc, window_end_utc, src_ip, total_requests, read_count, write_count,
                write_to_read_ratio, distinct_dst_devices, new_source, request_rate_deviation,
                protocol, iec104_command_count, labelled)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                w.window_start_utc, w.window_end_utc, w.src_ip,
                w.total_requests, w.read_count, w.write_count,
                w.write_to_read_ratio, w.distinct_dst_devices, w.new_source,
                w.request_rate_deviation, w.protocol, w.iec104_command_count, w.labelled,
            ),
        )
    return {"status": "accepted"}


@app.get("/baseline/windows", tags=["baseline"])
def get_baseline_windows(limit: int = 200):
    with database.get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM baseline_windows ORDER BY window_start_utc DESC LIMIT ?", (limit,)
        ).fetchall()
    return {"windows": [dict(r) for r in rows]}


# ── Baseline Peer Relationships ───────────────────────────────────────────

class BaselinePeerApproval(BaseModel):
    src_ip: str
    dst_ip: str
    protocol: str = "modbus-tcp"
    dst_port: int = 502
    approved_by: str = "operator"
    notes: str = ""


@app.get("/baseline/peers", tags=["baseline"])
def get_baseline_peers():
    """Retrieve all approved baseline communication relationships."""
    with database.get_db() as conn:
        rels = inventory.get_baseline_relationships(conn)
        return {"relationships": rels, "total": len(rels)}


@app.post("/baseline/peers/approve", tags=["baseline"], status_code=200)
def approve_baseline_peer(req: BaselinePeerApproval):
    """Explicitly approve an observed peer communication relationship into the baseline."""
    with database.get_db() as conn:
        result = inventory.approve_relationship(
            conn, req.src_ip, req.dst_ip, req.protocol, req.dst_port, req.approved_by, req.notes
        )
    return {"status": "approved", "relationship": result}


# ── Trial Results (Validation) ────────────────────────────────────────────────

@app.post("/trials", tags=["validation"], status_code=201)
def record_trial(trial: TrialResult):
    started_utc = trial.started_utc or datetime.now(timezone.utc).isoformat()
    with database.get_db() as conn:
        conn.execute(
            """INSERT INTO trial_results
               (scenario_id, trial_number, started_utc, expected_alert_rule, alert_generated,
                alert_id, alert_latency_seconds, false_positive, notes)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                trial.scenario_id, trial.trial_number, started_utc,
                trial.expected_alert_rule, int(trial.alert_generated),
                trial.alert_id, trial.alert_latency_seconds,
                int(trial.false_positive), trial.notes,
            ),
        )
    return {"status": "recorded"}


@app.get("/trials/summary", tags=["validation"])
def get_trial_summary():
    """Compute formal B.2 acceptance metrics with documented denominators."""
    with database.get_db() as conn:
        rows = conn.execute("SELECT * FROM trial_results ORDER BY started_utc").fetchall()

    total = len(rows)
    if total == 0:
        return {
            "status": "NOT TESTED",
            "overall_status": "NOT TESTED",
            "total_trials": 0,
            "message": "No evaluation trials recorded yet. Run 'make evaluate' or '.\\scripts\\cognton.ps1 evaluate'.",
        }

    # Separate attack trials from normal traffic trials
    attack_trials = [r for r in rows if r["expected_alert_rule"] != "NONE" and not str(r["scenario_id"]).startswith("N")]
    normal_trials = [r for r in rows if r["expected_alert_rule"] == "NONE" or str(r["scenario_id"]).startswith("N")]

    tp = sum(1 for r in attack_trials if r["alert_generated"])
    fn = sum(1 for r in attack_trials if not r["alert_generated"])
    fp = sum(1 for r in normal_trials if r["alert_generated"]) + sum(1 for r in rows if r["false_positive"])
    tn = sum(1 for r in normal_trials if not r["alert_generated"])

    n_attack = len(attack_trials)
    n_normal = len(normal_trials)

    detection_rate_pct = round(tp / n_attack * 100, 1) if n_attack > 0 else None
    false_alarm_rate_pct = round(fp / n_normal * 100, 1) if n_normal > 0 else (0.0 if total > 0 and fp == 0 else None)

    latencies = [r["alert_latency_seconds"] for r in rows if r["alert_latency_seconds"] is not None]

    import statistics
    mean_latency_ms = round(statistics.mean(latencies) * 1000, 1) if latencies else None
    median_latency = round(statistics.median(latencies), 3) if latencies else None
    p95_latency = round(sorted(latencies)[int(len(latencies) * 0.95)], 3) if latencies else None
    worst_latency = round(max(latencies), 3) if latencies else None

    # Overall compliance status against B.2 acceptance criteria:
    # Detection rate >= 95%, False alarm < 5%, Latency < 900s (15 min)
    if total < 5:
        overall_status = "INCONCLUSIVE"
        status_note = "Sample size too small (< 5 trials) for statistical significance."
    elif (detection_rate_pct is not None and detection_rate_pct >= 95.0) and (false_alarm_rate_pct is not None and false_alarm_rate_pct < 5.0):
        overall_status = "PASS"
        status_note = "All measured metrics meet or exceed B.2 acceptance targets."
    else:
        overall_status = "FAIL"
        status_note = "One or more measured metrics failed to achieve B.2 acceptance criteria."

    return {
        "status": overall_status,
        "overall_status": overall_status,
        "status_note": status_note,
        "total_trials": total,
        "attack_trials_count": n_attack,
        "normal_trials_count": n_normal,
        "true_positives": tp,
        "false_negatives": fn,
        "false_positives": fp,
        "true_negatives": tn,
        "detection_rate_pct": detection_rate_pct,
        "detection_rate_fraction": f"{tp}/{n_attack}" if n_attack > 0 else "N/A",
        "detection_rate_denominator": "total_attack_trials",
        "false_alarm_rate_pct": false_alarm_rate_pct,
        "false_alarm_fraction": f"{fp}/{n_normal}" if n_normal > 0 else "0/0",
        "false_alarm_denominator": "total_normal_traffic_trials",
        "mean_alert_latency_ms": mean_latency_ms,
        "alert_latency_median_s": median_latency,
        "alert_latency_p95_s": p95_latency,
        "alert_latency_worst_s": worst_latency,
        "targets": {
            "detection_rate_min_pct": 95.0,
            "false_alarm_max_pct": 5.0,
            "latency_max_s": 900.0,
        },
        "by_scenario": {
            sid: {
                "detected": sum(1 for r in rows if r["scenario_id"] == sid and r["alert_generated"]),
                "total": sum(1 for r in rows if r["scenario_id"] == sid),
                "expected_rule": next((r["expected_alert_rule"] for r in rows if r["scenario_id"] == sid), "UNKNOWN"),
            }
            for sid in sorted(set(r["scenario_id"] for r in rows))
        },
    }



@app.get("/overview", tags=["dashboard"])
def overview():
    """Aggregated data for the dashboard Overview page."""
    with database.get_db() as conn:
        device_count = conn.execute("SELECT COUNT(*) as c FROM devices").fetchone()["c"]
        unknown_count = conn.execute("SELECT COUNT(*) as c FROM devices WHERE authorised=0").fetchone()["c"]
        alert_summary = conn.execute(
            "SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity"
        ).fetchall()
        recent_alerts = conn.execute(
            "SELECT * FROM alerts ORDER BY timestamp_utc DESC LIMIT 10"
        ).fetchall()
        sensor_health = conn.execute(
            "SELECT * FROM sensor_health ORDER BY timestamp_utc DESC LIMIT 1"
        ).fetchone()
        event_protocols = conn.execute(
            "SELECT protocol, COUNT(*) as count FROM events GROUP BY protocol"
        ).fetchall()
        last_alert = conn.execute(
            "SELECT timestamp_utc FROM alerts ORDER BY timestamp_utc DESC LIMIT 1"
        ).fetchone()

    return {
        "devices": {"total": device_count, "unknown": unknown_count, "authorised": device_count - unknown_count},
        "alerts": {
            "by_severity": {r["severity"]: r["count"] for r in alert_summary},
            "recent": [dict(r) for r in recent_alerts],
            "last_detection_utc": last_alert["timestamp_utc"] if last_alert else None,
        },
        "sensor": dict(sensor_health) if sensor_health else {"status": "no_data"},
        "protocols": {r["protocol"]: r["count"] for r in event_protocols},
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
