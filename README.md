# Solar Farm OT Security Watchman

> **“Who is watching the solar farm’s network?”**
>
> An educational, local-only OT/ICS security lab that simulates a small photovoltaic plant and demonstrates passive network monitoring, asset inventory, rule-based detection, anomaly scoring, and a SOC-style dashboard.

## 1. Project at a glance

Solar Farm OT Security Watchman combines a simulated solar-farm control environment with a monitoring and detection pipeline. It is intended for learning, prototyping, and controlled demonstrations—not for protecting or testing a real industrial plant.

The lab includes:

- Three Python-based Modbus TCP inverter simulators.
- A PLC/RTU-style aggregator.
- An IEC 60870-5-104 server/client pair that simulates a grid-substation communications link.
- A FUXA web HMI for operator-style telemetry.
- A Zeek-based sensor pipeline with Modbus parsing support, a custom IEC-104 decoder, event normalization, and PCAP replay support.
- A FastAPI backend for event ingestion, asset inventory, alert queries, detection, metrics, and persistence.
- A Streamlit SOC dashboard.
- YAML configuration for the authorized device manifest, register map, maintenance windows, and detection rules.
- Unit, integration, and end-to-end test suites plus scripts for baseline generation, scenario execution, and evaluation.

**Important:** feature descriptions below describe the project’s intended design and available code. They do not imply that live packet capture, every attack scenario, or every acceptance metric has been independently verified in every environment. See [Known limitations and verification status](#13-known-limitations-and-verification-status).

## 2. Architecture

```text
                        SIMULATED SOLAR-FARM OT ENVIRONMENT
 ┌────────────────────┐  Modbus TCP  ┌────────────────────┐
 │ Inverter 1         │◄────────────►│                    │
 │ 172.20.0.11:502    │              │                    │
 ├────────────────────┤              │ OpenPLC / RTU      │
 │ Inverter 2         │◄────────────►│ 172.20.0.20        │
 │ 172.20.0.12:502    │              │ Aggregated values  │
 ├────────────────────┤              │ and register map   │
 │ Inverter 3         │◄────────────►│                    │
 │ 172.20.0.13:502    │              └────────────────────┘
 └────────────────────┘                         ▲
          ▲                                     │ Modbus
          │ Modbus polling                      │
 ┌────────┴───────────┐                 ┌────────┴───────────┐
 │ FUXA SCADA HMI     │                 │ IEC-104 client     │
 │ 172.20.0.40:1881*  │                 │ 172.20.0.31        │
 └────────────────────┘                 └────────┬───────────┘
                                                 │ IEC 60870-5-104
                                        ┌────────▼───────────┐
                                        │ IEC-104 server     │
                                        │ 172.20.0.30:2404   │
                                        └────────────────────┘

                  OBSERVATION / DETECTION PIPELINE
 ┌───────────────────────────────────────────────────────────┐
 │ Zeek sensor — 172.20.0.60                                 │
 │ Live capture where supported; PCAP replay for offline use │
 │ Zeek logs + Modbus parser + custom IEC-104 decoder         │
 └──────────────────────────────┬────────────────────────────┘
                                │ normalized events
                                ▼
 ┌───────────────────────────────────────────────────────────┐
 │ FastAPI backend — 172.20.0.50:8000                         │
 │                                                           │
 │  Event ingestion → inventory update → detection engine    │
 │                                   ├─ deterministic rules  │
 │                                   └─ IsolationForest ML   │
 │                         ↓                                 │
 │                 SQLite persistence                         │
 └──────────────────────────────┬────────────────────────────┘
                                │ REST API
                                ▼
 ┌───────────────────────────────────────────────────────────┐
 │ Streamlit SOC dashboard — 172.20.0.70:8501                │
 │ Overview | Inventory | Alerts | Timeline | Health/ML      │
 │ Validation                                                 │
 └───────────────────────────────────────────────────────────┘

 *The FUXA UI is exposed to the host at 127.0.0.1:1881.
```

The Docker Compose file defines a private bridge network (`172.20.0.0/24`) and binds published host ports to `127.0.0.1`. This is a local lab boundary, not a substitute for reviewing the host firewall, Docker configuration, and capture permissions.

### Component map

| Component | Source location | Responsibility |
|---|---|---|
| Inverter simulators | `services/inverter_simulator/inverter.py` | Simulate inverter telemetry and expose Modbus TCP registers |
| PLC / RTU simulator | `services/openplc/plc_sim.py` | Poll/aggregate simulated plant values and expose a register map |
| IEC-104 server/client | `services/iec104_lab/server.py`, `client.py` | Simulate the grid-substation telemetry/control link |
| FUXA HMI | `services/fuxa_config/project.json` | Browser-based operator HMI configuration |
| Sensor startup and capture | `services/sensor/entrypoint.sh` | Select sensor capture/replay workflow and launch the sensor components |
| Zeek site script | `services/sensor/zeek_scripts/` | Configure protocol logging/handling |
| Modbus event forwarder | `services/sensor/log_forwarder.py` | Read Zeek logs, normalize events, and forward them to the API |
| IEC-104 decoder | `services/sensor/iec104_decoder.py` | Decode IEC-104 APDU/ASDU information from captured payloads |
| PCAP generator | `services/sensor/generate_test_pcap.py` | Generate synthetic Modbus traffic captures for testing/replay |
| API | `services/api/main.py` | REST endpoints, event processing, health, alerts, and operational API |
| Inventory | `services/api/inventory.py` | Track observed hosts and enrich them with configured device information |
| Detection rules | `services/api/rules.py`, `config/detection_rules.yaml` | Evaluate protocol events against configured detection rules |
| ML anomaly detector | `services/api/anomaly.py` | Train/score IsolationForest traffic-window features |
| Persistence | `services/api/database.py` | SQLite-backed event, inventory, alert, and trial data |
| SOC dashboard | `services/dashboard/app.py` | Visualize assets, alerts, timeline, sensor/model health, and validation data |
| Scenario runner | `scripts/run_scenario.py` | Run bounded lab attack/baseline scenarios |
| Baseline generator | `scripts/generate_baseline.py` | Generate normal simulated traffic/training input |
| Acceptance evaluator | `scripts/evaluate.py` | Run/score configured acceptance trials |
| Lab helper | `scripts/cognton.ps1`, `Makefile` | Convenience commands for Windows and Make-supported shells |

## 3. Event and detection flow

The intended event path is:

1. **Traffic is generated.** The simulated inverters, PLC, HMI, and IEC-104 endpoints produce protocol traffic. Scenario scripts can generate bounded suspicious activity inside the lab.
2. **The sensor observes traffic.** Zeek and the sensor’s protocol-handling components process live traffic where supported, or a PCAP file in replay mode.
3. **Protocol events are normalized.** The log forwarder extracts available network/protocol fields and sends normalized event records to the API. IEC-104 payloads are handled by the custom decoder.
4. **The API ingests the event.** The backend updates relevant inventory state and passes event data through detection logic.
5. **Rules evaluate the event.** Enabled deterministic rules check attributes such as source identity, protocol/function code, register, timing, rates, and peer relationships.
6. **The anomaly model scores traffic windows.** The IsolationForest component evaluates its configured feature vector when the model is trained and scoring data is available.
7. **Results are persisted.** Events, inventory state, alerts, and evaluation records are stored in SQLite according to the backend’s database implementation.
8. **The dashboard reads from the API.** Operators can inspect inventory, alert evidence, timelines, health information, and available validation results.

**Interpretation note:** a configured path is not proof that every packet traverses every stage. To claim end-to-end detection for a scenario, verify the generated traffic, sensor output, API ingestion, resulting rule/ML decision, persisted alert, and dashboard/API result.

## 4. Deterministic detection rules

The rule definitions live in `config/detection_rules.yaml`; rule evaluation is implemented in `services/api/rules.py`. Thresholds, enabled flags, deduplication windows, explanations, and recommended actions are configuration-driven where defined.

| Rule ID | Rule name | Intended detection |
|---|---|---|
| `RULE-001` | `UNKNOWN_DEVICE` | Traffic from a source not present in the authorized device manifest |
| `RULE-002` | `UNAUTHORISED_MODBUS_WRITE` | Modbus write function codes from a client that is not an approved writer |
| `RULE-003` | `PROTECTED_SETPOINT_CHANGE` | Unauthorized write to a protected holding register, such as the configured active-power setpoint |
| `RULE-004` | `OUT_OF_WINDOW_WRITE` | Control writes outside configured maintenance windows or otherwise outside the configured authorization policy |
| `RULE-005` | `MODBUS_WRITE_BURST` | Excessive Modbus writes from a client within a configured time window |
| `RULE-006` | `IEC104_UNEXPECTED_CONTROL` | IEC-104 control ASDUs from an unauthorized master or outside the configured control allowlist |
| `RULE-007` | `IEC104_RATE_ANOMALY` | Abnormal IEC-104 connection or APDU/command rates |
| `RULE-008` | `OUT_OF_RANGE_SETPOINT` | A setpoint write outside configured simulated safe bounds |
| `RULE-009` | `PROTOCOL_PEER_DRIFT` | A known device communicating with an unapproved peer or protocol/port relationship |

Rule IDs and names should be checked against the current YAML configuration and implementation before changing documentation. These rules are for simulated lab values; they are not real-world operating limits or a substitute for plant engineering rules.

### Alert content and deduplication

The configuration includes per-rule severity, enablement, deduplication windows, explanation templates, and recommended actions. Exact evidence fields depend on the event available to the detection engine. A generated alert is a detection signal, not proof of malicious intent; investigate it in context.

## 5. Machine-learning anomaly detection

The project includes an unsupervised **IsolationForest** detector implemented in `services/api/anomaly.py` and associated with `RULE-ML-001` in the rule configuration.

The documented design uses traffic-window features such as:

- Request volume
- Read and write counts
- Write-to-read ratio
- Number of distinct destinations
- New-source indicator
- Rate deviation
- IEC-104 command activity

The model is intended to learn a baseline from normal simulated lab traffic and flag windows that differ from that baseline. Model artifacts/metadata may be stored under the project’s data directory.

**Limitations:** synthetic baseline training does not establish performance on real solar-farm traffic. The ML score is an anomaly indicator, not an attack classifier or proof of compromise. Use it alongside deterministic rules and human investigation.

## 6. Simulated attack and baseline scenarios

The README and scenario runner describe the following scenario family. Run each scenario only against the project’s isolated lab endpoints.

| Scenario | Intended behaviour | Expected detection area |
|---|---|---|
| `S1` | Rogue/unregistered device appears and sends traffic | `RULE-001` |
| `S2` | Unauthorized Modbus setpoint write | `RULE-002`, potentially `RULE-003` |
| `S3` | Burst of Modbus writes | `RULE-005` |
| `S4` | Unexpected IEC-104 control command | `RULE-006` |
| `S5` | Write outside an authorized maintenance window | `RULE-004` |
| `S6` | Setpoint value outside configured simulated range | `RULE-008` |
| `S7` | Known device communicates with an unapproved peer/protocol | `RULE-009` |
| `N1` | Normal simulated SCADA polling | Used to measure false alerts on the baseline |

These are **expected mappings**, not a guarantee that a scenario currently triggers every listed rule in a live run. Confirm outcomes using the scenario output and the persisted trial/alert records.

## 7. SOC dashboard

The Streamlit dashboard is defined in `services/dashboard/app.py`. Its intended views are:

1. **Overview** — high-level status, counts, and alert summaries.
2. **Inventory** — known/observed devices and their roles/authorization context.
3. **Alerts** — alert list, severity filtering, and available evidence/details.
4. **Timeline** — chronological event/alert exploration and visualizations.
5. **Sensor and ML health** — sensor state, capture mode, and model status where supplied by the API.
6. **Validation** — available acceptance metrics and trial summaries.

The dashboard depends on the API and its available data. A visible dashboard page does not, by itself, prove that sensor ingestion or end-to-end detection is functioning.

## 8. Configuration

| File | Purpose |
|---|---|
| `config/device_manifest.yaml` | Authorized lab devices, roles, and allowed communication relationships |
| `config/register_map.yaml` | Simulated Modbus registers, names, units, and configured ranges |
| `config/detection_rules.yaml` | Rule IDs, thresholds, severities, deduplication, explanations, and responses |
| `config/maintenance_windows.yaml` | Authorized maintenance windows for control writes |
| `.env.example` | Example environment configuration for local execution |
| `docker-compose.yml` | Service definitions, network addresses, ports, volumes, health checks, and capture-mode defaults |

Keep simulated safety limits clearly labelled as simulated. Do not copy them into a real control system.

## 9. Technology stack

| Layer | Technologies |
|---|---|
| Simulation | Python, PyModbus, Modbus TCP |
| PLC/RTU | Python-based simulator and register aggregation |
| Grid protocol | IEC 60870-5-104 server/client implementation with configured fallback behaviour |
| HMI | FUXA |
| Network monitoring | Zeek, Modbus protocol parsing support, custom IEC-104 decoder |
| API | FastAPI, Pydantic, Uvicorn |
| Persistence | SQLite |
| Detection | Python rule engine, scikit-learn IsolationForest, NumPy, joblib |
| Dashboard | Streamlit, Plotly |
| Packaging/orchestration | Docker, Docker Compose |
| Testing | pytest, AnyIO, FastAPI TestClient |

Exact dependency versions are maintained in the service-level requirements files and container definitions.

## 10. Repository layout

```text
.
├── config/
│   ├── device_manifest.yaml
│   ├── detection_rules.yaml
│   ├── maintenance_windows.yaml
│   └── register_map.yaml
├── data/
│   └── model_meta.json
├── docs/
│   ├── architecture.md
│   ├── known-limitations.md
│   ├── requirements-traceability.md
│   └── THIRD_PARTY_NOTICES.md
├── scripts/
│   ├── cognton.ps1
│   ├── doctor.py
│   ├── evaluate.py
│   ├── generate_baseline.py
│   └── run_scenario.py
├── services/
│   ├── api/
│   │   ├── anomaly.py
│   │   ├── database.py
│   │   ├── inventory.py
│   │   ├── main.py
│   │   └── rules.py
│   ├── dashboard/
│   │   └── app.py
│   ├── detection/
│   ├── fuxa_config/
│   │   └── project.json
│   ├── iec104_lab/
│   │   ├── client.py
│   │   └── server.py
│   ├── inverter_simulator/
│   │   └── inverter.py
│   ├── openplc/
│   │   └── plc_sim.py
│   └── sensor/
│       ├── entrypoint.sh
│       ├── generate_test_pcap.py
│       ├── iec104_decoder.py
│       ├── log_forwarder.py
│       └── zeek_scripts/
├── tests/
│   ├── unit/
│   ├── integration/
│   └── end_to_end/
├── docker-compose.yml
├── implementation_plan.md
├── readme.md
├── SECURITY.md
├── Makefile
└── pytest.ini
```

Some generated files, caches, and runtime data are intentionally omitted from this overview.

## 11. Setup and operation

### Prerequisites

- Docker Desktop with Docker Compose on Windows, or Docker Engine and Docker Compose on Linux.
- Python installed if running the local test/evaluation tools outside containers.
- Adequate local resources to build and run the containers.
- On Windows, use the configured PCAP replay workflow unless live capture has been deliberately configured and validated in a supported Linux/WSL2 environment.

### Start the lab

From the project root:

```bash
docker compose up --build -d
docker compose ps
```

Wait for health checks and service startup. If the repository’s helper script is available, it can also be used on Windows:

```powershell
.\scripts\cognton.ps1 status
```

### Local interfaces

| Service | URL |
|---|---|
| Streamlit SOC dashboard | http://127.0.0.1:8501 |
| FUXA HMI | http://127.0.0.1:1881 |
| OpenPLC web UI | http://127.0.0.1:8080 |
| FastAPI Swagger UI | http://127.0.0.1:8000/docs |
| API health | http://127.0.0.1:8000/health |

An endpoint is available only when its service is running and healthy.

### Baseline, scenarios, and evaluation

The repository includes helper commands and scripts for generating baseline data, running scenarios, and evaluating trials. On Windows, the helper script is:

```powershell
.\scripts\cognton.ps1 baseline
.\scripts\cognton.ps1 scenario S2
.\scripts\cognton.ps1 demo
```

The evaluator can be invoked with:

```bash
python scripts/evaluate.py --run-trials
```

These commands may require the API and lab services to be running. Read the output and check the trial records; a command being available is not evidence that all metrics passed.

### Stop the lab

```bash
docker compose down
```

Runtime state may be held in named Docker volumes. Review the compose file and helper script before removing volumes or running any reset command, as reset operations can delete generated database, log, or PCAP state.

## 12. Testing and verification

Run the test suite from the project root:

```bash
python -m pytest tests/ -v --tb=short
```

Test groups:

- `tests/unit/` — rule logic, API endpoints, inventory, anomaly detection, protocol decoding, log forwarding, PCAP generation, and register-map behaviour.
- `tests/integration/` — API integration checks.
- `tests/end_to_end/` — lab scenario pipeline checks.

Integration and end-to-end tests may require running services and the full lab. If these tests are skipped because the API or lab is unavailable, report them as skipped—not passed.

### Verification status from the source-code audit

In one observed test run, `python -m pytest tests/ -q` collected 125 tests and reported:

- **94 passed**
- **31 skipped**
- **0 failed**

The 31 skipped tests consisted of 8 integration tests and 23 end-to-end tests because the live API/full lab was not running in that run. These numbers describe that run only; they are not a promise about future environments.

The evaluator could not complete in that audit because the Watchman API was unavailable. Its reported metrics should be checked against actual trial records and measurement logic before presenting them as validated acceptance results.

### Acceptance metrics

The evaluator is intended to summarize areas such as:

- Device discovery coverage
- Attack-trial detection rate
- False alerts during normal baseline trials
- Alert latency
- Monitoring impact on simulated SCADA polling

Only publish numeric results when the evaluator ran successfully and the underlying trial data and calculation are available. In particular, zero dropped polls should not be inferred merely from a passive architecture; it requires a defined measurement method and supporting observations. Likewise, distinguish PCAP replay validation from live capture validation.

## 13. Known limitations and verification status

1. **Educational simulation only.** This project is not a production OT security product and must not be connected to real industrial equipment or networks.
2. **Synthetic traffic/model baseline.** ML behaviour is based on lab-generated traffic; performance on real solar-farm traffic has not been established.
3. **Live capture is environment-dependent.** Docker bridge traffic is not automatically visible to a sensor just because both containers share a network. Verify capture interface, packet visibility, and decoder output. PCAP replay and live capture are different test modes.
4. **End-to-end scenarios need live evidence.** A scenario definition or unit test alone does not prove that packets traversed the sensor, API, rule engine, persistence layer, and dashboard.
5. **Acceptance metrics need traceable evidence.** Do not treat hard-coded fallbacks, unavailable sensor data, or assumed zero packet loss as measured results.
6. **Alert interpretation requires context.** Unknown devices and anomalies can be benign; an alert is not proof of an incident.
7. **Simulation limits are not plant limits.** Register ranges and control actions apply only to the simulated lab.
8. **Documentation and implementation can drift.** Use the current source, configuration, test output, and trial data as the authority when updating claims.

## 14. Safety and intended use

This is an educational/research prototype for an isolated local Docker lab.

- Run it only against its own simulated endpoints.
- Do not connect it to real OT/ICS networks, PLCs, RTUs, inverters, substations, or public targets.
- Do not run scenario scripts against any target outside the lab.
- The sensor is designed for observation and event reporting; do not assume it can block attacks or enforce control policy.
- Review `SECURITY.md` before use or redistribution.

## 15. Further documentation

- [`docs/architecture.md`](docs/architecture.md) — architecture notes
- [`docs/known-limitations.md`](docs/known-limitations.md) — known limitations
- [`docs/requirements-traceability.md`](docs/requirements-traceability.md) — requirement mapping
- [`implementation_plan.md`](implementation_plan.md) — implementation plan and stage notes
- [`speak.md`](speak.md) — demo/screen-recording script
- [`SECURITY.md`](SECURITY.md) — safety boundaries

---

**Project name:** Solar Farm OT Security Watchman  
**Purpose:** Demonstrate a simulated OT/ICS monitoring and detection pipeline using industrial protocol traffic, deterministic rules, anomaly scoring, and an operator-facing dashboard.
