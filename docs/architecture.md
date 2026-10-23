# Architecture — Solar Farm OT Security Watchman

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Private Lab Network: 172.20.0.0/24               │
│                                                                          │
│  ┌──────────┐   Modbus TCP   ┌────────────┐                             │
│  │ FUXA HMI │ ──────────────►│ inverter1  │ 172.20.0.11:502             │
│  │172.20.0.40│               │            │                             │
│  │  :1881   │ ──────────────►│ inverter2  │ 172.20.0.12:502             │
│  └──────────┘               │            │                             │
│                              │ inverter3  │ 172.20.0.13:502             │
│                              └────────────┘                             │
│                                                                          │
│  ┌──────────┐   Modbus TCP   ┌────────────┐                             │
│  │ FUXA HMI │ ──────────────►│  openplc   │ 172.20.0.20:502             │
│  └──────────┘                │ (PLC/RTU)  │                             │
│                              └────────────┘                             │
│                                                                          │
│  ┌───────────────┐ IEC-104  ┌──────────────┐                           │
│  │ iec104_client │◄────────►│ iec104_server│ 172.20.0.30:2404           │
│  │ 172.20.0.31   │          │ 172.20.0.30  │                           │
│  │ (grid ctrl)   │          └──────────────┘                           │
│  └───────────────┘                                                      │
│                                                                          │
│  (All OT traffic) ──mirror──►┌────────────┐                            │
│                               │   sensor   │ 172.20.0.60                │
│                               │   (Zeek)   │ passive, read-only         │
│                               └─────┬──────┘                           │
│                                     │ HTTP POST /ingest/zeek_modbus     │
│                                     ▼                                   │
│                               ┌────────────┐◄── /ingest/iec104_event   │
│                               │    api     │    from iec104_server      │
│                               │ 172.20.0.50│                           │
│                               │   :8000    │  ┌───────────────────┐    │
│                               │            │  │   SQLite DB       │    │
│                               │ FastAPI    │  │   watchman.db     │    │
│                               │ +rules.py  │  │   (events,alerts, │    │
│                               │ +anomaly.py│  │    devices, ...)  │    │
│                               └─────┬──────┘  └───────────────────┘    │
│                                     │ HTTP GET /overview /alerts etc    │
│                                     ▼                                   │
│                               ┌────────────┐                           │
│                               │ dashboard  │ 172.20.0.70:8501           │
│                               │ (Streamlit)│ → host port 8501           │
│                               └────────────┘                           │
│                                                                          │
│  Host-exposed ports (127.0.0.1 only):                                   │
│    8501 → Streamlit Security Dashboard                                   │
│    8000 → FastAPI (+ /docs Swagger UI)                                   │
│    1881 → FUXA HMI                                                       │
│    8080 → OpenPLC Web Interface                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Services

| Service | Image | IP | Purpose |
|---|---|---|---|
| `inverter1` | custom/pymodbus | 172.20.0.11 | Modbus TCP server, simulates solar inverter #1 |
| `inverter2` | custom/pymodbus | 172.20.0.12 | Modbus TCP server, simulates solar inverter #2 |
| `inverter3` | custom/pymodbus | 172.20.0.13 | Modbus TCP server, simulates solar inverter #3 |
| `openplc` | custom/pymodbus | 172.20.0.20 | OpenPLC RTU simulation (PLC aggregation) |
| `iec104_server` | custom/c104-stub | 172.20.0.30 | IEC 60870-5-104 endpoint (grid interface) |
| `iec104_client` | custom/c104-stub | 172.20.0.31 | Fake grid control centre (IEC-104 interrogation) |
| `fuxa` | frangoteam/fuxa | 172.20.0.40 | HMI — polls all devices, visualises process |
| `api` | custom/fastapi | 172.20.0.50 | Event normaliser, rule engine, ML, REST API |
| `sensor` | zeek/zeek | 172.20.0.60 | Passive Zeek capture + log forwarder |
| `dashboard` | custom/streamlit | 172.20.0.70 | SOC dashboard (6 pages) |

## Data Flow

### Normal operation
1. **FUXA HMI** polls inverters every 2 s (Modbus FC4 / FC3)
2. **Zeek sensor** passively captures traffic on the bridge interface
3. **log_forwarder.py** tail-reads Zeek `modbus.log` and POSTs parsed events to `/ingest/zeek_modbus`
4. **API** normalises events → updates device inventory → runs rule engine → persists alerts
5. **IEC-104 server/client** exchange measurement/control APDUs; server POSTs events to `/ingest/iec104_event`
6. **Dashboard** polls `/overview`, `/alerts`, `/inventory`, `/timeline` every 15 s

### Attack scenario data flow
1. `scripts/run_scenario.py` directly POSTs crafted events to `/ingest/modbus` or `/ingest/iec104_event`
2. API rule engine evaluates and generates alerts
3. Alerts appear in dashboard within one 15 s refresh cycle
4. Trial results are recorded via `/trials`

## Detection Architecture

### B3 — Live Inventory
- Every event's `src_ip` / `dst_ip` is upserted into the `devices` table
- IPs are cross-referenced with `config/device_manifest.yaml` (authorised allowlist)
- Unknown IPs → `RULE-001: UNKNOWN_DEVICE` alert

### B4 — Detection (2-layer)

**Layer 1: Deterministic rule engine** (`services/api/rules.py`)

| Rule ID | Name | Trigger |
|---|---|---|
| RULE-001 | UNKNOWN_DEVICE | src_ip not in authorised manifest |
| RULE-002 | UNAUTHORISED_MODBUS_WRITE | FC5/6/15/16 from non-approved host |
| RULE-003 | PROTECTED_SETPOINT_CHANGE | Write to HR[0] from non-approved host |
| RULE-004 | OUT_OF_WINDOW_WRITE | Write from approved writer outside maintenance window |
| RULE-005 | MODBUS_WRITE_BURST | ≥10 writes from one host in 30 s |
| RULE-006 | IEC104_UNEXPECTED_CONTROL | C_SC/C_DC/C_SE/etc. from non-approved master |
| RULE-007 | IEC104_RATE_ANOMALY | IEC-104 APDU rate ≥50 per minute from one IP |

**Layer 2: ML anomaly detector** (`services/api/anomaly.py`)

- Algorithm: IsolationForest (scikit-learn)
- Trained on synthetic normal baseline (50 windows × 8 features)
- Features: total_requests, read_count, write_count, write_to_read_ratio, distinct_dst_devices, new_source, request_rate_deviation, iec104_command_count
- Threshold: anomaly_score < -0.10
- Scored every 60 events per source IP (sliding 60 s window)

### B5 — Attack Scenarios

| ID | Scenario | Expected Rule |
|---|---|---|
| S1 | Rogue device (172.20.0.99) performs Modbus reads | UNKNOWN_DEVICE |
| S2 | Rogue device writes to protected setpoint HR[0] | PROTECTED_SETPOINT_CHANGE |
| S3 | Rogue device sends 15 writes in 15 s | MODBUS_WRITE_BURST |
| S4 | Rogue IEC-104 master sends C_SE_NC_1 control ASDU | IEC104_UNEXPECTED_CONTROL |
| S5 | Authorised HMI writes outside 02:00–04:00 UTC window | OUT_OF_WINDOW_WRITE |

## Database Schema

```
devices         — passively-observed device inventory (IP, role, authorised flag)
events          — every normalised Modbus/IEC-104 event
alerts          — all rule/ML alerts (alert_id, rule_name, severity, explanation)
sensor_health   — Zeek sensor liveness reports
baseline_windows— feature windows used for ML training
trial_results   — validation trial results for B.2 acceptance metrics
schema_version  — DB schema migration tracking
```

## Capture Modes

| Mode | OS | How |
|---|---|---|
| `live` | Linux / WSL2 | Zeek `-i <bridge_interface>` — requires `NET_RAW` capability |
| `pcap_replay` | All (default) | Zeek `-r /pcaps/normal_baseline.pcap` — generated synthetically if absent |

## Network Security

- All host-exposed ports bind to `127.0.0.1` only
- The lab runs on an isolated Docker bridge `172.20.0.0/24`
- No route to the internet from lab containers
- The passive sensor has `NET_RAW` only; it cannot inject traffic
- See [SECURITY.md](../SECURITY.md) for the full safety statement
