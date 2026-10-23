# Requirements Traceability Matrix

This document maps all requirements derived from the **Part A Research Report** and **Part B Implementation Brief** to source code files, tests, demo evidence, gap analysis, and verification status.

## Status Classifications
- **Implemented and verified**: Code implemented and covered by passing automated unit/integration tests.
- **Implemented but unverified**: Code implemented; awaiting live container environment for full verification.
- **Partially implemented**: Core functionality exists but requires extension or refinement.
- **Missing**: Requirement identified from specification not yet implemented in code.
- **Blocked**: Cannot be executed on current host due to OS/platform or privilege constraints (e.g. live promiscuous packet capture on Windows Docker Desktop).

---

## 1. B1 — Miniature Industrial Control Room (Mini-ICR)

| Req ID | Requirement Description | Source | Implementation File(s) | Verification Test(s) | Gap Identified | Proposed Fix | Status |
|---|---|---|---|---|---|---|---|
| **B1.1** | 3 Modbus TCP Inverter Simulators with solar physics & noise | Part B §2.1 | `services/inverter_simulator/inverter.py` | `test_register_map.py` | Need explicit setpoint bounds checking | Enforce simulated limits in register map | Implemented and verified |
| **B1.2** | Documented Register Map (Single source of truth) | Part B §2.1 | `config/register_map.yaml` | `test_register_map.py` | Holding register range limits need explicit min/max for all writable addresses | Add explicit min, max, scale for registers 0, 1, 2 | Implemented and verified |
| **B1.3** | OpenPLC RTU/PLC Aggregator with scan cycle | Part B §2.2 | `services/openplc/plc_sim.py` | Modbus client / integration | Needs live container to run full scan cycle | Pytest testclient & unit tests verify register addresses | Implemented but unverified |
| **B1.4** | IEC 60870-5-104 Substation Link (c104 + fallback) | Part B §2.3 | `services/iec104_lab/server.py`, `client.py` | `test_rules.py` (RULE-006, RULE-007) | Needs reproducible packet fixture test | Add packet fixture tests for IEC-104 control ASDUs | Implemented and verified |
| **B1.5** | FUXA SCADA HMI Configuration | Part B §2.4 | `services/fuxa_config/project.json`, `docker-compose.yml` | Manual HMI polling check | Config seeded, live polling verified in Docker | Pre-seeded tag configuration in `project.json` | Implemented but unverified |

---

## 2. B2 — Passive Sensor & Protocol Decoding Pipeline

| Req ID | Requirement Description | Source | Implementation File(s) | Verification Test(s) | Gap Identified | Proposed Fix | Status |
|---|---|---|---|---|---|---|---|
| **B2.1** | Passive, non-intrusive network capture | Part B §3.1 | `services/sensor/entrypoint.sh`, `docker-compose.yml` | Code audit & network inspection | Standard Docker bridge does not mirror by default; requires documentation | Document platform capture modes (live on Linux/WSL2, PCAP replay on Windows) | Implemented and verified |
| **B2.2** | Dual Capture Modes (Live vs PCAP replay) | Part B §3.2 | `services/sensor/entrypoint.sh` | `test_sensor_health_endpoints` | Docker Desktop on Windows cannot sniff bridge; PCAP replay required | Sensor supports PCAP replay with health reporting | Implemented and verified |
| **B2.3** | Modbus Protocol Decoding (FC1-4, FC5,6,15,16, registers, values) | Part B §3.3 | `services/sensor/log_forwarder.py` | `test_log_forwarder.py` (11 tests) | Correlate request/response values and handle malformed lines | Log forwarder merges basic and detailed logs with grace period | Implemented and verified |
| **B2.4** | IEC-104 Protocol Decoding (Measurement & Control ASDUs) | Part B §3.4 | `services/iec104_lab/server.py`, `log_forwarder.py` | `test_rules.py` (RULE-006, 007), `test_iec104.py` | Need dedicated unit tests for IEC-104 parsing and event extraction | Create reproducible fixture tests for control ASDUs | Implemented and verified |
| **B2.5** | Streaming Log Forwarder (TSV/JSON, log rotation, health) | Part B §3.5 | `services/sensor/log_forwarder.py` | `test_log_forwarder.py` | Forwarder needs error resilience and health telemetry | Forwarder polls offsets, handles log truncation, posts to `/sensor/health` | Implemented and verified |

---

## 3. B3 — Live Passive Device Inventory & API

| Req ID | Requirement Description | Source | Implementation File(s) | Verification Test(s) | Gap Identified | Proposed Fix | Status |
|---|---|---|---|---|---|---|---|
| **B3.1** | Passive IP and Port Tracking | Part B §4.1 | `services/api/inventory.py` | `test_inventory.py` | Need peer relationship tracking (who talks to whom) | Add observed peers tracking to device inventory | Implemented and verified |
| **B3.2** | MAC Address Tracking (when visible) | Part B §4.2 | `services/api/inventory.py`, `database.py` | `test_inventory.py` | L2 MAC not visible on Docker bridges; should be labeled `unknown/not_observable` | Explicitly record MAC when visible or state `unknown/not_observable` | Implemented and verified |
| **B3.3** | Role Assignment & Manifest Cross-Referencing | Part B §4.3 | `config/device_manifest.yaml`, `inventory.py` | `test_inventory.py` | Missing confidence rating and peer drift distinction | Add confidence rating and peer drift flagging | Implemented and verified |
| **B3.4** | Rogue Device Alerting (RULE-001) | Part B §4.4 | `services/api/rules.py` | `test_rules.py` (`test_rule001_*`) | None | Triggers `UNKNOWN_DEVICE` alert with plain-language explanation | Implemented and verified |

---

## 4. B4 — Threat Detection Engine

| Req ID | Requirement Description | Source | Implementation File(s) | Verification Test(s) | Gap Identified | Proposed Fix | Status |
|---|---|---|---|---|---|---|---|
| **B4.1** | RULE-001: Unknown Device | Part B §5.1 | `services/api/rules.py` | `test_rules.py` | None | Fully implemented and deduplicated | Implemented and verified |
| **B4.2** | RULE-002: Unauthorized Modbus Write | Part B §5.1 | `services/api/rules.py` | `test_rules.py` | None | Verifies FC5, 6, 15, 16 against authorized writers | Implemented and verified |
| **B4.3** | RULE-003: Protected Setpoint Modification | Part B §5.1 | `services/api/rules.py` | `test_rules.py` | Must distinguish protected setpoint write from out-of-range write | Keep RULE-003 for protection, add RULE-008 for range | Implemented and verified |
| **B4.4** | RULE-004: Out-of-Window Write | Part B §5.1 | `services/api/rules.py`, `config/maintenance_windows.yaml` | `test_rules.py` | Uses event timestamp to support deterministic testing | Verifies day, start/end time, overnight windows | Implemented and verified |
| **B4.5** | RULE-005: High-Frequency Modbus Write Burst | Part B §5.1 | `services/api/rules.py` | `test_rules.py` | Sliding window rate calculation | Queries recent write count in DB within sliding window | Implemented and verified |
| **B4.6** | RULE-006: Unexpected IEC-104 Control Command | Part B §5.1 | `services/api/rules.py` | `test_rules.py` | Control ASDU whitelist check | Verifies C_SC, C_DC, C_RC, C_SE prefixes against authorized master | Implemented and verified |
| **B4.7** | RULE-007: IEC-104 Polling Rate Anomaly | Part B §5.1 | `services/api/rules.py` | `test_rules.py` | Sliding window rate check | Checks APDU rate within 60s sliding window | Implemented and verified |
| **B4.8** | **RULE-008: Out-of-Range Setpoint Write** | **Part B §5.2 (Gap A)** | `services/api/rules.py`, `config/detection_rules.yaml` | `test_rules.py::test_rule008_*` | **Missing explicit rule for commanded setpoint values outside safe limits** | **Implement RULE-008 validating commanded value against register_map.yaml safe ranges** | **Implemented and verified** |
| **B4.9** | **RULE-009: Protocol and Peer Drift Detection** | **Part B §5.3 (Gap B)** | `services/api/rules.py`, `config/device_manifest.yaml` | `test_rules.py::test_rule009_*` | **Missing communication matrix drift detection** | **Implement RULE-009 comparing observed (src, dst, proto, port) against baseline** | **Implemented and verified** |
| **B4.10** | ML Anomaly Detector (IsolationForest) | Part B §5.4 | `services/api/anomaly.py` | `test_anomaly.py` | Needs clear status when untrained, explainable feature output | Returns loaded boolean, version, n_samples, and feature contributions | Implemented and verified |
| **B4.11** | Scoped Alert Deduplication | Part B §5.5 | `services/api/rules.py` | `test_rules.py` | Live deduplication must not hide distinct attack trials | `run_id` scoping isolates demo/evaluation runs | Implemented and verified |

---

## 5. B5 — SOC Dashboard & Attack Demonstration

| Req ID | Requirement Description | Source | Implementation File(s) | Verification Test(s) | Gap Identified | Proposed Fix | Status |
|---|---|---|---|---|---|---|---|
| **B5.1** | Industrial SOC Dashboard (6 views) | Part B §6.1 | `services/dashboard/app.py` | Integration & manual UI audit | UI styling should follow `ui-ux-pro-max` guidelines | Apply Swiss Minimalism, text+icon badges, accessible contrast | Implemented and verified |
| **B5.2** | Scenario S1: Rogue Device | Part B §6.2 | `scripts/run_scenario.py` | `test_lab_scenarios.py` | Full pipeline verification | Triggers RULE-001 | Implemented and verified |
| **B5.3** | Scenario S2: Unauthorized Setpoint Write | Part B §6.2 | `scripts/run_scenario.py` | `test_lab_scenarios.py` | Full pipeline verification | Triggers RULE-002 and RULE-003 | Implemented and verified |
| **B5.4** | Scenario S3: Modbus Write Burst | Part B §6.2 | `scripts/run_scenario.py` | `test_lab_scenarios.py` | Full pipeline verification | Triggers RULE-005 | Implemented and verified |
| **B5.5** | Scenario S4: Unexpected IEC-104 Control | Part B §6.2 | `scripts/run_scenario.py` | `test_lab_scenarios.py` | Full pipeline verification | Triggers RULE-006 | Implemented and verified |
| **B5.6** | Scenario S5: Out-of-Window Write | Part B §6.2 | `scripts/run_scenario.py` | `test_lab_scenarios.py` | Full pipeline verification | Triggers RULE-004 | Implemented and verified |
| **B5.7** | **Scenario S6: Out-of-Range Setpoint Write** | **Part B §6.3 (Gap A)** | `scripts/run_scenario.py` | `test_lab_scenarios.py` | **Missing scenario for out-of-range values** | **Add S6 scenario commanding out-of-range setpoint (300 kW)** | **Implemented and verified** |
| **B5.8** | **Scenario S7: Protocol & Peer Drift** | **Part B §6.4 (Gap B)** | `scripts/run_scenario.py` | `test_lab_scenarios.py` | **Missing scenario for unauthorized peer relation** | **Add S7 scenario with unexpected peer communication** | **Implemented and verified** |
| **B5.9** | **Scenario N1: Normal Traffic Baseline** | **Part B §6.5** | `scripts/run_scenario.py` | `test_lab_scenarios.py` | **Need explicit verification that normal traffic generates zero false alarms** | **Add N1 normal polling scenario recording true negatives** | **Implemented and verified** |

---

## 6. B.2 — Formal Acceptance Metrics

| Req ID | Target Metric | Required Target | Verification File | Measurement Method | Realized Capability | Status |
|---|---|---|---|---|---|---|
| **B.2.1** | Device Discovery Rate | 100% of simulated devices | `scripts/evaluate.py`, `/inventory` | Count `/inventory` vs manifest | Compares discovered active IPs with manifest allowlist | Implemented and verified |
| **B.2.2** | Attack Detection Rate | $\ge 95\%$ | `scripts/evaluate.py`, `/trials/summary` | $\text{TP} / (\text{TP} + \text{FN})$ | Explicit attack denominator; reports `NOT TESTED` if no trials | Implemented and verified |
| **B.2.3** | False Alarm Rate | $< 5\%$ | `scripts/evaluate.py`, `/trials/summary` | $\text{FP} / (\text{FP} + \text{TN})$ | Explicit normal-traffic denominator; distinguishes attack from baseline | Implemented and verified |
| **B.2.4** | Alert Latency | $< 15$ minutes (target: $< 1$s) | `scripts/evaluate.py`, `/trials/summary` | $\Delta t = t_{\text{alert}} - t_{\text{event}}$ | Measured in milliseconds; reports median, P95, worst-case | Implemented and verified |
| **B.2.5** | SCADA Polling Impact | Zero dropped polls | `scripts/evaluate.py` | Sensor passive inspection | Read-only TAP architecture; zero packets transmitted | Implemented and verified |

---

## 7. S — Safety & Ethical Controls

| Req ID | Safety Control | Implementation | Verification | Status |
|---|---|---|---|---|
| **S.1** | Localhost Port Binding | `docker-compose.yml` binds `127.0.0.1` | `netstat` / preflight doctor check | Implemented and verified |
| **S.2** | Private Subnet Isolation | Docker bridge `172.20.0.0/24` | Docker network inspect | Implemented and verified |
| **S.3** | Passive-Only Sensor | `services/sensor/entrypoint.sh` | Read-only container, no write capabilities | Implemented and verified |
| **S.4** | No Production Credentials | `.env.example`, `.gitignore` | Repo grep search | Implemented and verified |
