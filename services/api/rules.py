"""
Detection Rule Engine — B4
Evaluates all deterministic rules against incoming events.
Each alert includes: alert_id, rule_id, severity, evidence, explanation, recommendation.
Implements deduplication windows to avoid alert storms.
"""

import hashlib
import json
import logging
import os
import time
import yaml
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG = (
    "/app/config"
    if os.path.exists("/app/config")
    else os.path.abspath(os.path.join(os.path.dirname(__file__), "../../config"))
)
CONFIG_DIR = os.getenv("CONFIG_DIR", _DEFAULT_CONFIG)

# In-memory deduplication: {(rule_id, src_ip, dst_ip): last_alert_timestamp}
_dedupe_cache: dict = {}

WRITE_FCS = {5, 6, 15, 16}


def _get_config_dir() -> str:
    return os.getenv("CONFIG_DIR", _DEFAULT_CONFIG)


def _load_rules() -> dict:
    cfg = _get_config_dir()
    path = os.path.join(cfg, "detection_rules.yaml")
    with open(path) as f:
        return yaml.safe_load(f)


def _load_manifest() -> dict:
    cfg = _get_config_dir()
    path = os.path.join(cfg, "device_manifest.yaml")
    with open(path) as f:
        return yaml.safe_load(f)


def _load_windows() -> dict:
    cfg = _get_config_dir()
    path = os.path.join(cfg, "maintenance_windows.yaml")
    with open(path) as f:
        return yaml.safe_load(f)


def _load_register_map() -> dict:
    cfg = _get_config_dir()
    path = os.path.join(cfg, "register_map.yaml")
    if os.path.exists(path):
        with open(path) as f:
            return yaml.safe_load(f) or {}
    return {}


def _check_out_of_range(fc: int, reg_addr: Optional[int], raw_val) -> Optional[dict]:
    """
    Validate whether a commanded Modbus write value falls outside the documented
    safe operating limits for the relevant holding register in register_map.yaml.
    All safety limits are simulated lab limits, not real-world plant operating limits.
    Safely handles missing, malformed, non-numeric, or unsupported values.
    """
    if fc not in WRITE_FCS or reg_addr is None or raw_val is None:
        return None
    reg_map = _load_register_map()
    holding_regs = reg_map.get("holding_registers", [])
    target_reg = next((r for r in holding_regs if r.get("address") == reg_addr), None)
    if not target_reg:
        return None

    min_val = target_reg.get("min")
    max_val = target_reg.get("max")
    if min_val is None or max_val is None:
        return None

    try:
        val = float(raw_val)
    except (ValueError, TypeError):
        return None

    if val < min_val or val > max_val:
        scale = target_reg.get("scale", 1) or 1
        commanded_val = val / scale if scale != 1 else val
        return {
            "register_address": reg_addr,
            "register_name": target_reg.get("name", f"register_{reg_addr}"),
            "commanded_value": commanded_val,
            "raw_value": val,
            "min_value": min_val / scale if scale != 1 else min_val,
            "max_value": max_val / scale if scale != 1 else max_val,
            "unit": target_reg.get("unit", ""),
        }
    return None



def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_alert_id(
    rule_id: str,
    src_ip: str,
    dst_ip: str,
    ts: str,
    run_id: Optional[str] = None,
) -> str:
    raw = f"{rule_id}:{src_ip}:{dst_ip}:{ts}"
    if run_id:
        raw += f":{run_id}"
    return "ALT-" + hashlib.sha256(raw.encode()).hexdigest()[:12].upper()


def _check_dedupe(
    rule_id: str,
    src_ip: str,
    dst_ip: str,
    window_s: int,
    run_id: Optional[str] = None,
) -> bool:
    """
    Returns True if alert should be suppressed (deduplication).

    ``run_id`` scopes deduplication to a single attack scenario run. Live
    traffic has no run_id, so repeated packets from the same host are still
    suppressed normally. Demo/evaluation trials use a fresh run_id so a second
    run is not mistaken for a duplicate of the first.
    """
    key = (rule_id, src_ip, dst_ip, run_id) if run_id else (rule_id, src_ip, dst_ip)
    now = time.monotonic()
    last = _dedupe_cache.get(key)
    if last and (now - last) < window_s:
        return True
    _dedupe_cache[key] = now
    return False


def _parse_event_ts(ts: Optional[str]) -> datetime:
    """Parse an event timestamp as UTC, falling back to the current time."""
    if ts:
        candidates = [ts]
        if ts.endswith("Z"):
            candidates.append(ts[:-1] + "+00:00")
        for candidate in candidates:
            try:
                parsed = datetime.fromisoformat(candidate)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed.astimezone(timezone.utc)
            except ValueError:
                continue
    return datetime.now(timezone.utc)


def _window_applies(w: dict, src_ip: str, protocol: Optional[str]) -> bool:
    if src_ip not in w.get("applies_to_hosts", []):
        return False
    applies_to_protocols = w.get("applies_to_protocols")
    if applies_to_protocols and protocol and protocol not in applies_to_protocols:
        return False
    return True


def _is_in_maintenance_window(
    src_ip: str,
    ts: Optional[str] = None,
    protocol: str = "modbus-tcp",
) -> bool:
    """
    Check whether the event timestamp falls within a configured maintenance
    window for the source host. Uses the event time (not wall-clock time) so
    detection is deterministic and replayable. Windows may cross midnight.
    """
    windows_cfg = _load_windows()
    event_utc = _parse_event_ts(ts)
    day_name = event_utc.strftime("%A").lower()
    event_time = event_utc.strftime("%H:%M")
    previous_day = (event_utc - timedelta(days=1)).strftime("%A").lower()

    for w in windows_cfg.get("windows", []):
        if not _window_applies(w, src_ip, protocol):
            continue
        days = [d.lower() for d in w.get("days", [])]
        start = w.get("start_time", "")
        end = w.get("end_time", "")
        if not start or not end:
            continue
        if start <= end:
            if day_name in days and start <= event_time <= end:
                return True
        else:
            # Overnight window, e.g. 22:00–02:00
            if (event_time >= start and day_name in days) or (
                event_time <= end and previous_day in days
            ):
                return True
    return False


def _format_explanation(template: str, **kwargs) -> str:
    try:
        return template.format(**kwargs)
    except KeyError:
        return template


def evaluate_modbus_event(conn, event: dict, inventory_result: dict) -> list[dict]:
    """
    Evaluate a Modbus event against all applicable rules.
    Returns list of alert dicts to insert.
    """
    rules = _load_rules()
    manifest = _load_manifest()
    alerts = []

    src_ip = event.get("src_ip", "")
    dst_ip = event.get("dst_ip", "")
    dst_port = event.get("dst_port", 502)
    fc = event.get("function_code")
    reg_addr = event.get("register_address")
    raw_value = event.get("raw_value")
    ts = event.get("timestamp_utc", _now_utc())
    scenario_id = event.get("scenario_id")
    run_id = event.get("run_id")

    authorised_writers = [w["ip"] for w in manifest.get("authorised_modbus_writers", [])]
    protected_regs = [0]  # holding register 0 = active_power_setpoint

    # ── RULE-001: Unknown Device ──────────────────────────────────────────
    if not inventory_result.get("authorised"):
        rule = next((r for r in rules["rules"] if r["id"] == "RULE-001"), None)
        if rule and rule.get("enabled"):
            if not _check_dedupe("RULE-001", src_ip, dst_ip, rule.get("dedupe_window_seconds", 300), run_id):
                explanation = _format_explanation(
                    rule["explanation_template"],
                    src_ip=src_ip,
                    protocol="Modbus TCP",
                    first_seen_utc=ts,
                )
                alerts.append({
                    "rule_id": "RULE-001",
                    "rule_name": "UNKNOWN_DEVICE",
                    "severity": rule["severity"],
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "protocol": "modbus-tcp",
                    "explanation": explanation,
                    "recommended_action": rule.get("recommended_action", ""),
                    "evidence_json": json.dumps({"src_ip": src_ip, "protocol": "modbus-tcp", "event": event}),
                    "scenario_id": scenario_id,
                    "ts": ts,
                })

    # ── RULE-002: Unauthorised Modbus Write ───────────────────────────────
    if fc in WRITE_FCS and src_ip not in authorised_writers:
        rule = next((r for r in rules["rules"] if r["id"] == "RULE-002"), None)
        if rule and rule.get("enabled"):
            if not _check_dedupe("RULE-002", src_ip, dst_ip, rule.get("dedupe_window_seconds", 60), run_id):
                explanation = _format_explanation(
                    rule["explanation_template"],
                    src_ip=src_ip,
                    function_code=fc,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    register_address=reg_addr,
                )
                alerts.append({
                    "rule_id": "RULE-002",
                    "rule_name": "UNAUTHORISED_MODBUS_WRITE",
                    "severity": rule["severity"],
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "protocol": "modbus-tcp",
                    "explanation": explanation,
                    "recommended_action": rule.get("recommended_action", ""),
                    "evidence_json": json.dumps({"function_code": fc, "register": reg_addr, "src_ip": src_ip}),
                    "scenario_id": scenario_id,
                    "ts": ts,
                })

    # ── RULE-003: Protected Setpoint Change ───────────────────────────────
    if fc in WRITE_FCS and reg_addr in protected_regs and src_ip not in authorised_writers:
        rule = next((r for r in rules["rules"] if r["id"] == "RULE-003"), None)
        if rule and rule.get("enabled"):
            if not _check_dedupe("RULE-003", src_ip, dst_ip, rule.get("dedupe_window_seconds", 30), run_id):
                explanation = _format_explanation(
                    rule["explanation_template"],
                    src_ip=src_ip,
                    register_address=reg_addr,
                    dst_ip=dst_ip,
                    function_code=fc,
                    new_value=raw_value,
                )
                alerts.append({
                    "rule_id": "RULE-003",
                    "rule_name": "PROTECTED_SETPOINT_CHANGE",
                    "severity": rule["severity"],
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "protocol": "modbus-tcp",
                    "explanation": explanation,
                    "recommended_action": rule.get("recommended_action", ""),
                    "evidence_json": json.dumps({"register": reg_addr, "new_value": raw_value, "function_code": fc}),
                    "scenario_id": scenario_id,
                    "ts": ts,
                })

    # ── RULE-004: Out-of-Window Write ─────────────────────────────────────
    if fc in WRITE_FCS and src_ip in authorised_writers:
        if not _is_in_maintenance_window(src_ip, ts, "modbus-tcp"):
            windows_cfg = _load_windows()
            windows = [
                w for w in windows_cfg.get("windows", [])
                if _window_applies(w, src_ip, "modbus-tcp")
            ]
            w_start = windows[0]["start_time"] if windows else "02:00"
            w_end = windows[0]["end_time"] if windows else "04:00"
            w_days = ", ".join(windows[0]["days"]) if windows else "daily"
            rule = next((r for r in rules["rules"] if r["id"] == "RULE-004"), None)
            if rule and rule.get("enabled"):
                if not _check_dedupe("RULE-004", src_ip, dst_ip, rule.get("dedupe_window_seconds", 60), run_id):
                    explanation = _format_explanation(
                        rule["explanation_template"],
                        src_ip=src_ip,
                        function_code=fc,
                        dst_ip=dst_ip,
                        timestamp_utc=ts,
                        window_start=w_start,
                        window_end=w_end,
                        window_days=w_days,
                    )
                    alerts.append({
                        "rule_id": "RULE-004",
                        "rule_name": "OUT_OF_WINDOW_WRITE",
                        "severity": rule["severity"],
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "protocol": "modbus-tcp",
                        "explanation": explanation,
                        "recommended_action": rule.get("recommended_action", ""),
                        "evidence_json": json.dumps({"function_code": fc, "timestamp": ts, "window": f"{w_start}-{w_end}"}),
                        "scenario_id": scenario_id,
                        "ts": ts,
                    })

    # ── RULE-008: Out-of-Range Setpoint Write ─────────────────────────────
    if fc in WRITE_FCS and reg_addr is not None and raw_value is not None:
        range_info = _check_out_of_range(fc, reg_addr, raw_value)
        if range_info:
            rule8 = next((r for r in rules["rules"] if r["id"] == "RULE-008"), None)
            if rule8 and rule8.get("enabled"):
                if not _check_dedupe("RULE-008", src_ip, dst_ip, rule8.get("dedupe_window_seconds", 30), run_id):
                    explanation = _format_explanation(
                        rule8["explanation_template"],
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        commanded_value=range_info["commanded_value"],
                        raw_value=range_info["raw_value"],
                        register_address=range_info["register_address"],
                        register_name=range_info["register_name"],
                        min_value=range_info["min_value"],
                        max_value=range_info["max_value"],
                        unit=range_info["unit"],
                    )
                    alerts.append({
                        "rule_id": "RULE-008",
                        "rule_name": "OUT_OF_RANGE_SETPOINT",
                        "severity": rule8["severity"],
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "protocol": "modbus-tcp",
                        "explanation": explanation,
                        "recommended_action": rule8.get("recommended_action", ""),
                        "evidence_json": json.dumps({
                            "register_address": reg_addr,
                            "register_name": range_info["register_name"],
                            "commanded_value": range_info["commanded_value"],
                            "raw_value": range_info["raw_value"],
                            "allowed_range": [range_info["min_value"], range_info["max_value"]],
                            "unit": range_info["unit"],
                            "simulated_limits": True,
                            "disclaimer": "All safety limits are simulated lab limits, not real-world plant operating limits.",
                        }),
                        "scenario_id": scenario_id,
                        "ts": ts,
                    })

    # ── RULE-009: Protocol & Peer Drift Detection ─────────────────────────
    # Evaluated only for KNOWN/AUTHORISED devices (unknown devices trigger RULE-001)
    if inventory_result.get("authorised"):
        import inventory
        proto = event.get("protocol", "modbus-tcp")
        if not inventory.is_relationship_approved(conn, src_ip, dst_ip, proto, dst_port):
            rule9 = next((r for r in rules["rules"] if r["id"] == "RULE-009"), None)
            if rule9 and rule9.get("enabled"):
                dedupe_key = f"RULE-009:{src_ip}:{dst_ip}:{proto}:{dst_port}"
                if not _check_dedupe(dedupe_key, src_ip, dst_ip, rule9.get("dedupe_window_seconds", 60), run_id):
                    src_role = inventory_result.get("role", "known_device")
                    explanation = _format_explanation(
                        rule9["explanation_template"],
                        src_ip=src_ip,
                        src_role=src_role,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        protocol=proto,
                        first_seen_utc=ts,
                    )
                    alerts.append({
                        "rule_id": "RULE-009",
                        "rule_name": "PROTOCOL_PEER_DRIFT",
                        "severity": rule9["severity"],
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "protocol": proto,
                        "explanation": explanation,
                        "recommended_action": rule9.get("recommended_action", ""),
                        "evidence_json": json.dumps({
                            "src_ip": src_ip,
                            "src_role": src_role,
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                            "protocol": proto,
                            "status": "unapproved_relationship",
                            "baseline_check": "failed",
                        }),
                        "scenario_id": scenario_id,
                        "ts": ts,
                    })

    if run_id:
        for alert in alerts:
            alert["run_id"] = run_id
    return alerts


def evaluate_iec104_event(conn, event: dict) -> list[dict]:
    """Evaluate an IEC-104 event for RULE-006, RULE-007, and RULE-009."""
    rules = _load_rules()
    manifest = _load_manifest()
    alerts = []

    src_ip = event.get("src_ip", "")
    dst_ip = event.get("dst_ip", "172.20.0.30")
    dst_port = 2404
    asdu_type = event.get("asdu_type", "")
    ts = event.get("timestamp_utc", _now_utc())
    scenario_id = event.get("scenario_id")
    run_id = event.get("run_id")

    authorised_masters = [m["ip"] for m in manifest.get("authorised_iec104_masters", [])]
    manifest_ips = [d["ip"] for d in manifest.get("devices", [])]

    CONTROL_ASDU_PREFIXES = ["C_SC", "C_DC", "C_RC", "C_SE", "C_BO"]
    is_control = any(asdu_type.startswith(p) for p in CONTROL_ASDU_PREFIXES)

    # ── RULE-006: Unexpected IEC-104 Control ─────────────────────────────
    if is_control and src_ip not in authorised_masters:
        rule = next((r for r in rules["rules"] if r["id"] == "RULE-006"), None)
        if rule and rule.get("enabled"):
            if not _check_dedupe("RULE-006", src_ip, dst_ip, rule.get("dedupe_window_seconds", 60), run_id):
                authorised_master_ip = authorised_masters[0] if authorised_masters else "none"
                explanation = _format_explanation(
                    rule["explanation_template"],
                    asdu_type=asdu_type,
                    asdu_type_name=asdu_type,
                    src_ip=src_ip,
                    src_port=event.get("src_port", "?"),
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    authorised_master_ip=authorised_master_ip,
                )
                alerts.append({
                    "rule_id": "RULE-006",
                    "rule_name": "IEC104_UNEXPECTED_CONTROL",
                    "severity": rule["severity"],
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "protocol": "iec60870-5-104",
                    "explanation": explanation,
                    "recommended_action": rule.get("recommended_action", ""),
                    "evidence_json": json.dumps({
                        "asdu_type": asdu_type,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "ioa": event.get("ioa"),
                        "value": event.get("value"),
                    }),
                    "scenario_id": scenario_id,
                    "ts": ts,
                })

    # ── RULE-009: Check peer drift for known devices on IEC-104 port ──────
    if src_ip in manifest_ips:
        import inventory
        if not inventory.is_relationship_approved(conn, src_ip, dst_ip, "iec60870-5-104", dst_port):
            rule9 = next((r for r in rules["rules"] if r["id"] == "RULE-009"), None)
            if rule9 and rule9.get("enabled"):
                dedupe_key = f"RULE-009:{src_ip}:{dst_ip}:iec60870-5-104:{dst_port}"
                if not _check_dedupe(dedupe_key, src_ip, dst_ip, rule9.get("dedupe_window_seconds", 60), run_id):
                    dev = next((d for d in manifest.get("devices", []) if d["ip"] == src_ip), {})
                    explanation = _format_explanation(
                        rule9["explanation_template"],
                        src_ip=src_ip,
                        src_role=dev.get("role", "known_device"),
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        protocol="iec60870-5-104",
                        first_seen_utc=ts,
                    )
                    alerts.append({
                        "rule_id": "RULE-009",
                        "rule_name": "PROTOCOL_PEER_DRIFT",
                        "severity": rule9["severity"],
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "protocol": "iec60870-5-104",
                        "explanation": explanation,
                        "recommended_action": rule9.get("recommended_action", ""),
                        "evidence_json": json.dumps({
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "protocol": "iec60870-5-104",
                            "status": "unapproved_iec104_relationship",
                        }),
                        "scenario_id": scenario_id,
                        "ts": ts,
                    })

    # ── RULE-007: IEC-104 Rate Anomaly ───────────────────────────────
    rule7 = next((r for r in rules["rules"] if r["id"] == "RULE-007"), None)
    if rule7 and rule7.get("enabled"):
        window_s = 60  # 1-minute sliding window
        threshold = rule7.get("threshold_apdu_rate", 50)
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_s)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        row = conn.execute(
            """SELECT COUNT(*) as cnt FROM events
               WHERE src_ip=? AND protocol='iec60870-5-104'
               AND timestamp_utc >= ?""",
            (src_ip, cutoff),
        ).fetchone()
        observed_rate = row["cnt"] if row else 0

        if observed_rate >= threshold:
            if not _check_dedupe(
                "RULE-007", src_ip, dst_ip, rule7.get("dedupe_window_seconds", 120), run_id
            ):
                explanation = _format_explanation(
                    rule7["explanation_template"],
                    src_ip=src_ip,
                    observed_rate=observed_rate,

                    rate_unit="APDUs",
                    window_seconds=window_s,
                    threshold=threshold,
                )
                alerts.append(
                    {
                        "rule_id": "RULE-007",
                        "rule_name": "IEC104_RATE_ANOMALY",
                        "severity": rule7["severity"],
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "protocol": "iec60870-5-104",
                        "explanation": explanation,
                        "recommended_action": rule7.get("recommended_action", ""),
                        "evidence_json": json.dumps(
                            {
                                "observed_rate": observed_rate,
                                "threshold": threshold,
                                "window_seconds": window_s,
                            }
                        ),
                        "scenario_id": scenario_id,
                        "ts": ts,
                    }
                )

    if run_id:
        for alert in alerts:
            alert["run_id"] = run_id
    return alerts


def check_write_burst(conn, src_ip: str, dst_ip: str, scenario_id: Optional[str] = None, run_id: Optional[str] = None) -> Optional[dict]:
    """
    RULE-005: Check if src_ip has sent too many writes to dst_ip in the burst window.
    Reads recent event history from DB.
    """
    rules = _load_rules()
    rule = next((r for r in rules["rules"] if r["id"] == "RULE-005"), None)
    if not rule or not rule.get("enabled"):
        return None

    threshold = rule.get("threshold_writes", 10)
    window_s = rule.get("window_seconds", 30)

    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_s)
    cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")

    row = conn.execute(
        """SELECT COUNT(*) as cnt FROM events
           WHERE src_ip=? AND dst_ip=? AND function_code IN (5,6,15,16)
           AND timestamp_utc >= ?""",
        (src_ip, dst_ip, cutoff_str),
    ).fetchone()

    write_count = row["cnt"] if row else 0

    if write_count >= threshold:
        if not _check_dedupe("RULE-005", src_ip, dst_ip, rule.get("dedupe_window_seconds", 120), run_id):
            explanation = _format_explanation(
                rule["explanation_template"],
                src_ip=src_ip,
                write_count=write_count,
                dst_ip=dst_ip,
                window_seconds=window_s,
                threshold_writes=threshold,
            )
            return {
                "rule_id": "RULE-005",
                "rule_name": "MODBUS_WRITE_BURST",
                "severity": rule["severity"],
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": 502,
                "protocol": "modbus-tcp",
                "explanation": explanation,
                "recommended_action": rule.get("recommended_action", ""),
                "evidence_json": json.dumps({"write_count": write_count, "window_seconds": window_s, "threshold": threshold}),
                "scenario_id": scenario_id,
                "run_id": run_id,
                "ts": _now_utc(),
            }
    return None


def persist_alert(conn, alert: dict) -> str:
    """Persist an alert to the database. Returns alert_id."""
    ts = alert.get("ts", _now_utc())
    alert_id = _make_alert_id(
        alert["rule_id"],
        alert.get("src_ip", ""),
        alert.get("dst_ip", ""),
        ts,
        alert.get("run_id"),
    )

    try:
        conn.execute(
            """INSERT OR IGNORE INTO alerts
               (alert_id, rule_id, rule_name, severity, timestamp_utc, src_ip, dst_ip, dst_port,
                protocol, evidence_json, explanation, recommended_action, status, scenario_id,
                anomaly_score, top_features)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                alert_id,
                alert["rule_id"],
                alert["rule_name"],
                alert["severity"],
                ts,
                alert.get("src_ip"),
                alert.get("dst_ip"),
                alert.get("dst_port"),
                alert.get("protocol"),
                alert.get("evidence_json"),
                alert["explanation"],
                alert.get("recommended_action"),
                "open",
                alert.get("scenario_id"),
                alert.get("anomaly_score"),
                alert.get("top_features"),
            ),
        )
        logger.info("Alert persisted: %s [%s] %s", alert_id, alert["rule_name"], alert["severity"])
    except Exception as exc:
        logger.error("Failed to persist alert: %s", exc)

    return alert_id
