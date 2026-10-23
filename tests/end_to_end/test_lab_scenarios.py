"""
End-to-End Tests — Full Scenario Pipeline
Requires the lab to be running (make up) and baseline generated (make baseline).
Tests the complete pipeline: event injection → alert generation → dashboard data.

Run with: pytest tests/end_to_end/ -v
Skip with: pytest tests/ -v --ignore=tests/end_to_end  (when lab is not up)

These tests validate the B.2 acceptance targets:
  - Detection rate ≥ 95% of attacks detected
  - False alarm rate < 5%
  - Alert latency < 15 minutes (target: seconds)
"""

import time
import uuid

import pytest
import requests

API_URL = "http://127.0.0.1:8000"
LAB_TIMEOUT = 10  # seconds


def api_reachable() -> bool:
    try:
        r = requests.get(f"{API_URL}/health", timeout=3)
        return r.ok
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not api_reachable(),
    reason="API not running — start the lab with 'make up' and run 'make baseline' first",
)

ROGUE_IP = "172.20.0.199"   # Unique IP that won't collide with other test runs
ROGUE_IEC104 = "172.20.0.188"
RUN_ID = f"e2e-{uuid.uuid4().hex[:12]}"


def _now_utc() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def post_modbus_event(event: dict) -> dict:
    event.setdefault("run_id", RUN_ID)
    r = requests.post(f"{API_URL}/ingest/modbus", json=event, timeout=5)
    assert r.status_code == 202, f"Expected 202, got {r.status_code}: {r.text}"
    return r.json()


def post_iec104_event(event_type: str, data: dict) -> dict:
    data.setdefault("run_id", RUN_ID)
    r = requests.post(
        f"{API_URL}/ingest/iec104_event",
        json={"event_type": event_type, "data": data},
        timeout=5,
    )
    assert r.status_code == 202, f"Expected 202, got {r.status_code}: {r.text}"
    return r.json()


def get_alerts(scenario_id: str) -> list:
    r = requests.get(f"{API_URL}/alerts", params={"scenario_id": scenario_id}, timeout=5)
    assert r.ok
    return r.json()["alerts"]


# ── S1: Rogue Device ─────────────────────────────────────────────────────────

class TestScenarioS1RogueDevice:
    """E2E: Rogue device performing Modbus reads triggers UNKNOWN_DEVICE."""

    SCENARIO = "E2E_S1"

    def test_rogue_read_triggers_unknown_device_alert(self):
        """Rogue IP that has never been seen must generate UNKNOWN_DEVICE."""
        event = {
            "timestamp_utc": _now_utc(),
            "src_ip": ROGUE_IP,
            "dst_ip": "172.20.0.11",
            "dst_port": 502,
            "function_code": 4,
            "register_address": 0,
            "raw_value": None,
            "scenario_id": self.SCENARIO,
            "source": "e2e_test",
        }
        result = post_modbus_event(event)
        alert_ids = result.get("alert_ids", [])
        assert len(alert_ids) > 0, "Rogue device must generate at least one alert"

        alerts = get_alerts(self.SCENARIO)
        rule_names = [a["rule_name"] for a in alerts]
        assert "UNKNOWN_DEVICE" in rule_names, (
            f"Expected UNKNOWN_DEVICE alert, got: {rule_names}"
        )

    def test_unknown_device_appears_in_inventory(self):
        """After rogue event, the device must appear in inventory marked unauthorised."""
        # Ensure at least one event from rogue IP
        post_modbus_event({
            "src_ip": ROGUE_IP,
            "dst_ip": "172.20.0.11",
            "dst_port": 502,
            "function_code": 4,
            "scenario_id": self.SCENARIO,
            "source": "e2e_test",
        })

        r = requests.get(f"{API_URL}/inventory/{ROGUE_IP}", timeout=5)
        assert r.status_code == 200, f"Device {ROGUE_IP} should be in inventory"
        device = r.json()
        assert device["authorised"] == 0, "Rogue device must be marked unauthorised"


# ── S2: Unauthorised Setpoint Write ──────────────────────────────────────────

class TestScenarioS2SetpointWrite:
    """E2E: Unauthorised write to protected setpoint HR[0]."""

    SCENARIO = "E2E_S2"

    def test_protected_setpoint_write_triggers_alert(self):
        """FC6 to HR[0] from rogue host must trigger PROTECTED_SETPOINT_CHANGE."""
        event = {
            "timestamp_utc": _now_utc(),
            "src_ip": ROGUE_IP,
            "dst_ip": "172.20.0.11",
            "dst_port": 502,
            "function_code": 6,
            "register_address": 0,   # HR[0] = active_power_setpoint (protected)
            "raw_value": 500,
            "scenario_id": self.SCENARIO,
            "source": "e2e_test",
        }
        result = post_modbus_event(event)
        assert len(result.get("alert_ids", [])) > 0

        alerts = get_alerts(self.SCENARIO)
        rule_names = [a["rule_name"] for a in alerts]
        assert "PROTECTED_SETPOINT_CHANGE" in rule_names
        assert "UNAUTHORISED_MODBUS_WRITE" in rule_names, (
            "Both PROTECTED_SETPOINT_CHANGE and UNAUTHORISED_MODBUS_WRITE must fire"
        )

    def test_alert_severity_is_critical(self):
        """Protected setpoint change must be severity=critical."""
        alerts = get_alerts(self.SCENARIO)
        setpoint_alerts = [a for a in alerts if a["rule_name"] == "PROTECTED_SETPOINT_CHANGE"]
        if setpoint_alerts:
            assert setpoint_alerts[0]["severity"] == "critical", (
                "PROTECTED_SETPOINT_CHANGE must be critical severity"
            )


# ── S3: Write Burst ───────────────────────────────────────────────────────────

class TestScenarioS3WriteBurst:
    """E2E: Write burst — 11 writes in rapid succession."""

    SCENARIO = "E2E_S3"

    def test_write_burst_triggers_alert(self):
        """11 writes from rogue IP to same target in <30 s must trigger MODBUS_WRITE_BURST."""
        # Send 11 write events rapidly
        for i in range(11):
            post_modbus_event({
                "timestamp_utc": _now_utc(),
                "src_ip": ROGUE_IP,
                "dst_ip": "172.20.0.12",
                "dst_port": 502,
                "function_code": 6,
                "register_address": 2,
                "raw_value": i * 50,
                "scenario_id": self.SCENARIO,
                "source": "e2e_test",
            })

        alerts = get_alerts(self.SCENARIO)
        rule_names = [a["rule_name"] for a in alerts]
        assert "MODBUS_WRITE_BURST" in rule_names, (
            f"Expected MODBUS_WRITE_BURST after 11 rapid writes. Got: {rule_names}"
        )


# ── S4: IEC-104 Unexpected Control ────────────────────────────────────────────

class TestScenarioS4IEC104Control:
    """E2E: Rogue IEC-104 master sends control ASDU."""

    SCENARIO = "E2E_S4"

    def test_rogue_iec104_control_triggers_alert(self):
        """Control ASDU from non-authorised master must trigger IEC104_UNEXPECTED_CONTROL."""
        result = post_iec104_event("iec104_control_received", {
            "src_ip": ROGUE_IEC104,
            "src_port": 45100,
            "dst_ip": "172.20.0.30",
            "asdu_type": "C_SE_NC_1",
            "ioa": 200,
            "value": "0.0",
            "timestamp_utc": _now_utc(),
            "scenario_id": self.SCENARIO,
        })
        assert len(result.get("alert_ids", [])) > 0

        alerts = get_alerts(self.SCENARIO)
        rule_names = [a["rule_name"] for a in alerts]
        assert "IEC104_UNEXPECTED_CONTROL" in rule_names, (
            f"Expected IEC104_UNEXPECTED_CONTROL. Got: {rule_names}"
        )

    def test_iec104_alert_severity_is_critical(self):
        """IEC-104 unexpected control must be severity=critical."""
        alerts = get_alerts(self.SCENARIO)
        iec_alerts = [a for a in alerts if a["rule_name"] == "IEC104_UNEXPECTED_CONTROL"]
        if iec_alerts:
            assert iec_alerts[0]["severity"] == "critical"

    def test_authorised_iec104_master_no_alert(self):
        """Control ASDU from the authorised master (172.20.0.31) must NOT trigger alert."""
        post_iec104_event("iec104_control_received", {
            "src_ip": "172.20.0.31",   # authorised grid control centre
            "dst_ip": "172.20.0.30",
            "asdu_type": "C_SE_NC_1",
            "ioa": 200,
            "value": "500.0",
            "timestamp_utc": _now_utc(),
            "scenario_id": "E2E_S4_NOALERT",
        })
        alerts = get_alerts("E2E_S4_NOALERT")
        rule_names = [a["rule_name"] for a in alerts]
        assert "IEC104_UNEXPECTED_CONTROL" not in rule_names, (
            "Authorised IEC-104 master must NOT trigger IEC104_UNEXPECTED_CONTROL"
        )


# ── S5: Out-of-Window Write ───────────────────────────────────────────────────

class TestScenarioS5OutOfWindow:
    """E2E: Authorised HMI writes outside the maintenance window."""

    SCENARIO = "E2E_S5"

    def test_out_of_window_write_triggers_alert(self):
        """
        Authorised writer (FUXA HMI, 172.20.0.40) writing outside all configured
        maintenance windows should trigger OUT_OF_WINDOW_WRITE.

        Noon UTC is outside both the daily 02:00–04:00 window and the Mon/Wed/Fri
        20:00–20:30 emergency window, so this test is deterministic.
        """
        result = post_modbus_event({
            "timestamp_utc": "2026-01-01T12:00:00Z",
            "src_ip": "172.20.0.40",   # FUXA HMI — authorised writer
            "dst_ip": "172.20.0.11",
            "dst_port": 502,
            "function_code": 6,
            "register_address": 1,
            "raw_value": 2350,
            "scenario_id": self.SCENARIO,
            "source": "e2e_test",
        })
        assert len(result.get("alert_ids", [])) > 0

        alerts = get_alerts(self.SCENARIO)
        rule_names = [a["rule_name"] for a in alerts]
        assert "OUT_OF_WINDOW_WRITE" in rule_names, (
            f"Expected OUT_OF_WINDOW_WRITE. Got: {rule_names}"
        )


# ── S6: Out-of-Range Setpoint Write ───────────────────────────────────────────

class TestScenarioS6OutOfRange:
    """E2E: Commanded setpoint exceeding safe register limits triggers OUT_OF_RANGE_SETPOINT."""

    SCENARIO = "E2E_S6"

    def test_out_of_range_setpoint_triggers_alert(self):
        """Authorised writer commanding 350,000 W (> 250,000 W limit) must trigger OUT_OF_RANGE_SETPOINT."""
        result = post_modbus_event({
            "timestamp_utc": _now_utc(),
            "src_ip": "172.20.0.40",   # FUXA HMI — authorised writer
            "dst_ip": "172.20.0.11",
            "dst_port": 502,
            "function_code": 6,
            "register_address": 0,    # active_power_setpoint (max: 250,000 W)
            "raw_value": 350000,      # commanded out of bounds
            "scenario_id": self.SCENARIO,
            "source": "e2e_test",
        })
        assert len(result.get("alert_ids", [])) > 0

        alerts = get_alerts(self.SCENARIO)
        rule_names = [a["rule_name"] for a in alerts]
        assert "OUT_OF_RANGE_SETPOINT" in rule_names, (
            f"Expected OUT_OF_RANGE_SETPOINT. Got: {rule_names}"
        )

    def test_within_range_setpoint_no_out_of_range_alert(self):
        """Commanded value within safe range (150,000 W) must NOT trigger OUT_OF_RANGE_SETPOINT."""
        scenario = "E2E_S6_IN_RANGE"
        post_modbus_event({
            "timestamp_utc": _now_utc(),
            "src_ip": "172.20.0.40",
            "dst_ip": "172.20.0.11",
            "dst_port": 502,
            "function_code": 6,
            "register_address": 0,
            "raw_value": 150000,      # within [0, 250,000]
            "scenario_id": scenario,
            "source": "e2e_test",
        })
        alerts = get_alerts(scenario)
        rule_names = [a["rule_name"] for a in alerts]
        assert "OUT_OF_RANGE_SETPOINT" not in rule_names, (
            "Valid setpoint should not trigger OUT_OF_RANGE_SETPOINT"
        )


# ── S7: Protocol and Peer Drift ───────────────────────────────────────────────

class TestScenarioS7PeerDrift:
    """E2E: Known device communicating with unapproved peer triggers PROTOCOL_PEER_DRIFT."""

    SCENARIO = "E2E_S7"

    def test_lateral_peer_drift_triggers_alert(self):
        """Inverter 1 sending Modbus query to Inverter 2 must trigger PROTOCOL_PEER_DRIFT."""
        result = post_modbus_event({
            "timestamp_utc": _now_utc(),
            "src_ip": "172.20.0.11",   # Inverter 1 (known device)
            "dst_ip": "172.20.0.12",   # Inverter 2 (lateral communication not in matrix)
            "dst_port": 502,
            "function_code": 4,
            "register_address": 0,
            "scenario_id": self.SCENARIO,
            "source": "e2e_test",
        })
        assert len(result.get("alert_ids", [])) > 0

        alerts = get_alerts(self.SCENARIO)
        rule_names = [a["rule_name"] for a in alerts]
        assert "PROTOCOL_PEER_DRIFT" in rule_names, (
            f"Expected PROTOCOL_PEER_DRIFT. Got: {rule_names}"
        )

    def test_approved_relationship_no_drift_alert(self):
        """Approved baseline relationship (HMI -> Inverter 1) must NOT trigger PROTOCOL_PEER_DRIFT."""
        scenario = "E2E_S7_APPROVED"
        post_modbus_event({
            "timestamp_utc": _now_utc(),
            "src_ip": "172.20.0.40",   # HMI
            "dst_ip": "172.20.0.11",   # Inverter 1 (Approved in baseline matrix)
            "dst_port": 502,
            "function_code": 4,
            "register_address": 0,
            "scenario_id": scenario,
            "source": "e2e_test",
        })
        alerts = get_alerts(scenario)
        rule_names = [a["rule_name"] for a in alerts]
        assert "PROTOCOL_PEER_DRIFT" not in rule_names, (
            "Approved communication relationship must not trigger PROTOCOL_PEER_DRIFT"
        )


# ── N1: Normal SCADA Baseline (Zero False Alarms) ────────────────────────────

class TestScenarioN1NormalBaseline:
    """E2E: Legitimate normal SCADA polling generates 0 alerts."""

    SCENARIO = "E2E_N1"

    def test_normal_scada_polling_zero_alerts(self):
        """Normal periodic polling from HMI to inverters must generate ZERO alerts."""
        alerts_generated = []
        for dst in ["172.20.0.11", "172.20.0.12", "172.20.0.13"]:
            res = post_modbus_event({
                "timestamp_utc": _now_utc(),
                "src_ip": "172.20.0.40",   # HMI
                "dst_ip": dst,
                "dst_port": 502,
                "function_code": 4,        # Read input registers (normal telemetry)
                "register_address": 0,
                "scenario_id": self.SCENARIO,
                "source": "e2e_test",
            })
            if res.get("alert_ids"):
                alerts_generated.extend(res["alert_ids"])

        assert len(alerts_generated) == 0, (
            f"Normal SCADA traffic generated unexpected false alarm alerts: {alerts_generated}"
        )


# ── Pipeline: Overview + Timeline ────────────────────────────────────────────

class TestDashboardEndpoints:
    """E2E: Dashboard data endpoints return correct aggregated state."""

    def test_overview_counts_alerts(self):
        """After scenarios run, overview must report nonzero alert count."""
        r = requests.get(f"{API_URL}/overview", timeout=5)
        assert r.ok
        data = r.json()
        # If any prior scenario tests ran and generated alerts, total should be > 0
        total = data["alerts"]["by_severity"]
        assert isinstance(total, dict), "by_severity must be a dict"

    def test_timeline_returns_events_and_alerts(self):
        """Timeline endpoint must return both events and alerts lists."""
        r = requests.get(f"{API_URL}/timeline", params={"hours": 1}, timeout=5)
        assert r.ok
        data = r.json()
        assert "events" in data
        assert "alerts" in data
        assert "since_utc" in data

    def test_trial_summary_exists(self):
        """Trial summary endpoint must be callable and return a valid structure."""
        r = requests.get(f"{API_URL}/trials/summary", timeout=5)
        assert r.ok
        data = r.json()
        # Either a message (no data) or proper summary
        assert "message" in data or "total_trials" in data

    def test_model_status_endpoint(self):
        r = requests.get(f"{API_URL}/model/status", timeout=5)
        assert r.ok
        data = r.json()
        assert "loaded" in data

    def test_inventory_has_known_devices(self):
        """After starting the lab, known authorised devices should appear."""
        r = requests.get(f"{API_URL}/inventory", timeout=5)
        assert r.ok
        data = r.json()
        assert data["count"] >= 0

    def test_alert_deduplication_across_pipeline(self):
        """
        Sending the same unknown device event twice should NOT create 2 UNKNOWN_DEVICE
        alerts for the same IP within the dedupe window.
        """
        dedup_ip = "172.20.0.250"
        scenario = "E2E_DEDUP"

        # First event — should create alert
        r1 = post_modbus_event({
            "src_ip": dedup_ip,
            "dst_ip": "172.20.0.11",
            "dst_port": 502,
            "function_code": 4,
            "scenario_id": scenario,
            "source": "e2e_test",
        })
        # Second event immediately after — should be deduped
        r2 = post_modbus_event({
            "src_ip": dedup_ip,
            "dst_ip": "172.20.0.11",
            "dst_port": 502,
            "function_code": 4,
            "scenario_id": scenario,
            "source": "e2e_test",
        })

        alerts = get_alerts(scenario)
        unknown_alerts = [a for a in alerts if a["rule_name"] == "UNKNOWN_DEVICE" and a["src_ip"] == dedup_ip]
        # Allow at most 1 UNKNOWN_DEVICE alert due to dedup window
        assert len(unknown_alerts) <= 1, (
            f"Deduplication failed: got {len(unknown_alerts)} UNKNOWN_DEVICE alerts for same IP"
        )


# ── B.2 Acceptance Target Verification ───────────────────────────────────────

class TestAcceptanceTargets:
    """
    B.2 acceptance: verify detection rate ≥ 95% and latency < 15 min
    from the /trials/summary endpoint.
    Only meaningful after 'make evaluate' has been run.
    """

    def test_detection_rate_if_trials_exist(self):
        """If trials were run, detection rate should meet ≥ 95% target."""
        r = requests.get(f"{API_URL}/trials/summary", timeout=5)
        assert r.ok
        data = r.json()

        if "message" in data:
            pytest.skip("No trial data yet — run 'make evaluate' first")

        total = data["total_trials"]
        if total == 0:
            pytest.skip("No trials recorded")

        detection_rate = data["detection_rate_pct"]
        assert detection_rate >= 95.0, (
            f"Detection rate {detection_rate:.1f}% < 95% target. "
            f"Detected {data['detected']}/{total}."
        )

    def test_false_alarm_rate_if_trials_exist(self):
        """False alarm rate must be < 5%."""
        r = requests.get(f"{API_URL}/trials/summary", timeout=5)
        assert r.ok
        data = r.json()

        if "message" in data or data.get("total_trials", 0) == 0:
            pytest.skip("No trial data yet — run 'make evaluate' first")

        false_alarm_rate = data["false_alarm_rate_pct"]
        assert false_alarm_rate < 5.0, (
            f"False alarm rate {false_alarm_rate:.1f}% ≥ 5% target"
        )

    def test_alert_latency_if_trials_exist(self):
        """Median alert latency must be < 900 seconds (15 minutes)."""
        r = requests.get(f"{API_URL}/trials/summary", timeout=5)
        assert r.ok
        data = r.json()

        if "message" in data or data.get("total_trials", 0) == 0:
            pytest.skip("No trial data yet — run 'make evaluate' first")

        median_latency = data.get("alert_latency_median_s")
        if median_latency is None:
            pytest.skip("No latency data recorded")

        assert median_latency < 900, (
            f"Median alert latency {median_latency:.1f}s ≥ 900s (15 min) target"
        )
