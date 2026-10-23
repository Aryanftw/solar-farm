# Known Limitations

## Capture Limitations

### Windows / macOS Docker Desktop
**Limitation:** Live packet capture (CAPTURE_MODE=live) is not supported on Windows or macOS Docker Desktop. Docker Desktop's NAT-based networking does not provide a host-visible bridge interface that Zeek can capture from.

**Impact:** The Zeek sensor operates in `pcap_replay` mode, processing a pre-recorded PCAP file rather than live traffic.

**Workaround:** Use Linux or WSL2 as the Docker host. Set `CAPTURE_MODE=live` and `CAPTURE_INTERFACE=br-ot_lab` (the Docker bridge interface name).

**Dashboard indication:** The Model & Sensor Health page clearly labels the capture mode as "PCAP replay" vs "Live capture".

## OpenPLC Runtime v4

**Limitation:** OpenPLC Runtime v4 requires a Linux host with specific build dependencies (gcc, make, libssl, cmake). Building from source takes several minutes and is environment-sensitive.

**Impact:** The `openplc` container runs a Python-based Modbus TCP server (`plc_sim.py`) that exposes the same Modbus register interface as OpenPLC would. It is clearly labelled as a simulation.

**Workaround:** On a Linux host, replace the `openplc` Dockerfile with the official OpenPLC Runtime v4 build. Instructions: https://github.com/Autonomy-Logic/openplc-runtime

## IEC-104 c104 Python Bindings

**Limitation:** The `c104` Python package (Fraunhofer IEC104-Python) requires C/C++ compilation with cmake and libssl during the Docker build. Build times are longer than pure-Python packages.

**Impact:** If the c104 build fails (e.g., missing libssl), the IEC-104 server/client fall back to a TCP stub mode. The stub still reports events to the API for detection purposes, but does not implement the full IEC-104 APDU protocol.

**Workaround:** Ensure the Docker build environment has cmake and libssl available. On Alpine-based images, these may need to be installed explicitly.

## Zeek ICSNPP-Modbus

**Limitation:** The `icsnpp-modbus` Zeek package requires `zkg` and may have version compatibility requirements with specific Zeek versions.

**Impact:** If ICSNPP fails to install, Zeek falls back to standard built-in Modbus protocol support (which may parse fewer fields).

## ML Model

**Limitation:** The IsolationForest model is trained on synthetic lab baseline traffic only (50 windows). It has not been validated against real solar farm traffic or production OT environments.

**Impact:** The ML anomaly detector supplements deterministic rules but should not be used as a sole detection mechanism. The dashboard clearly labels this limitation.

## FUXA HMI Configuration

**Limitation:** FUXA requires project configuration to be seeded before first start. The Docker Compose mounts a `services/fuxa_config/` directory, but a complete FUXA project file requires manual creation through the FUXA web UI on first run.

**Workaround:** Start FUXA (`make up`), navigate to http://127.0.0.1:1881, and configure devices and tags using the documented register map. The register addresses are defined in `config/register_map.yaml`.

## Alert Latency on First Run

**Limitation:** The ML model is not available until `make baseline` has been run. Rule-based detection works immediately, but ML anomaly detection requires prior baseline generation.

**Impact:** ML_ANOMALY alerts will not fire until the model is trained.
