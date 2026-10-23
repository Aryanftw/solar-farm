"""
Doctor / Preflight Check -- Solar Farm OT Security Lab
Checks all prerequisites before starting the lab.

Usage: python doctor.py
Exit code 0 = all checks passed, 1 = at least one critical failure.
"""

import shutil
import socket
import subprocess
import sys
import os
import platform

CHECKS_PASSED = 0
CHECKS_FAILED = 0
CHECKS_WARN = 0

REQUIRED_PORTS = [
    ("127.0.0.1", 8000, "FastAPI"),
    ("127.0.0.1", 8501, "Streamlit"),
    ("127.0.0.1", 1881, "FUXA HMI"),
    ("127.0.0.1", 8080, "OpenPLC Web"),
]


def ok(msg: str) -> None:
    global CHECKS_PASSED
    print(f"  [PASS]  {msg}")
    CHECKS_PASSED += 1


def fail(msg: str) -> None:
    global CHECKS_FAILED
    print(f"  [FAIL]  {msg}")
    CHECKS_FAILED += 1


def warn(msg: str) -> None:
    global CHECKS_WARN
    print(f"  [WARN]  {msg}")
    CHECKS_WARN += 1


def section(title: str) -> None:
    bar = "-" * (54 - len(title))
    print(f"\n-- {title} {bar}")


section("System")
print(f"  Platform: {platform.system()} {platform.release()} ({platform.machine()})")
if platform.system() == "Linux":
    ok("Linux host - live packet capture supported")
elif "WSL" in platform.release() or "microsoft" in platform.uname().release.lower():
    ok("WSL2 detected - live packet capture may work with correct interface")
else:
    warn(
        f"{platform.system()} detected - live packet capture NOT supported. "
        "Use CAPTURE_MODE=pcap_replay (default)"
    )

section("Docker")
if shutil.which("docker"):
    try:
        result = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            ok(f"Docker installed: version {result.stdout.strip()}")
        else:
            fail("Docker not responding. Start Docker Desktop or the Docker daemon.")
    except Exception as e:
        fail(f"Docker check error: {e}")
else:
    fail("Docker not found in PATH. Install Docker Desktop.")

if shutil.which("docker"):
    try:
        result = subprocess.run(
            ["docker", "compose", "version"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            ok(f"Docker Compose: {result.stdout.strip()}")
        else:
            # Try old docker-compose
            result2 = subprocess.run(
                ["docker-compose", "--version"],
                capture_output=True, text=True, timeout=10,
            )
            if result2.returncode == 0:
                ok(f"docker-compose (legacy): {result2.stdout.strip()}")
            else:
                fail("Docker Compose not found. Install Docker Compose v2.")
    except Exception as e:
        warn(f"Could not check Docker Compose: {e}")

section("Python")
ver = sys.version_info
if ver >= (3, 11):
    ok(f"Python {ver.major}.{ver.minor}.{ver.micro}")
elif ver >= (3, 9):
    warn(f"Python {ver.major}.{ver.minor}.{ver.micro} - Python 3.11+ recommended")
else:
    fail(f"Python {ver.major}.{ver.minor}.{ver.micro} - Python 3.11+ required")

section("Environment")
env_file = os.path.join(os.path.dirname(__file__), "..", ".env")
if os.path.exists(env_file):
    ok(".env file found")
else:
    warn(
        ".env not found - defaults from .env.example will be used. "
        "Consider: cp .env.example .env"
    )

capture_mode = os.getenv("CAPTURE_MODE", "pcap_replay")
print(f"  CAPTURE_MODE: {capture_mode}")
if capture_mode == "live" and platform.system() != "Linux":
    fail(f"CAPTURE_MODE=live not supported on {platform.system()}. Set CAPTURE_MODE=pcap_replay")
else:
    ok(f"Capture mode: {capture_mode}")

section("Port Availability")
for host, port, service in REQUIRED_PORTS:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((host, port))
            if result == 0:
                warn(f"Port {port} ({service}) is already in use - stop conflicting services")
            else:
                ok(f"Port {port} ({service}) is available")
    except Exception as e:
        warn(f"Port {port} check failed: {e}")

section("Config Files")
config_dir = os.path.join(os.path.dirname(__file__), "..", "config")
required_configs = [
    "device_manifest.yaml",
    "register_map.yaml",
    "detection_rules.yaml",
    "maintenance_windows.yaml",
]
for cfg in required_configs:
    path = os.path.join(config_dir, cfg)
    if os.path.exists(path):
        ok(f"config/{cfg}")
    else:
        fail(f"config/{cfg} missing")

section("Service Files")
service_checks = [
    ("services/api/main.py", "API main"),
    ("services/api/rules.py", "Rule engine"),
    ("services/api/anomaly.py", "ML anomaly detector"),
    ("services/dashboard/app.py", "Streamlit dashboard"),
    ("services/sensor/entrypoint.sh", "Sensor entrypoint"),
    ("services/sensor/generate_test_pcap.py", "PCAP generator"),
    ("services/inverter_simulator/inverter.py", "Inverter simulator"),
    ("services/iec104_lab/server.py", "IEC-104 server"),
    ("docker-compose.yml", "Docker Compose file"),
]
repo_root = os.path.join(os.path.dirname(__file__), "..")
for rel_path, label in service_checks:
    full_path = os.path.join(repo_root, rel_path)
    if os.path.exists(full_path):
        ok(f"{label}: {rel_path}")
    else:
        fail(f"{label} missing: {rel_path}")

section("Data Directory")
data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
os.makedirs(data_dir, exist_ok=True)
ok(f"data/ directory ready: {os.path.abspath(data_dir)}")

section("Summary")
total = CHECKS_PASSED + CHECKS_FAILED + CHECKS_WARN
print(
    f"\n  Passed: {CHECKS_PASSED}  Failed: {CHECKS_FAILED}"
    f"  Warnings: {CHECKS_WARN}  (Total: {total})\n"
)

if CHECKS_FAILED > 0:
    print("  [FAIL] Doctor found critical issues. Fix failures before running 'make up'.\n")
    sys.exit(1)
elif CHECKS_WARN > 0:
    print("  [WARN] Doctor found warnings. Review them before running 'make up'.\n")
    sys.exit(0)
else:
    print("  [PASS] All checks passed. Run 'make up' to start the lab.\n")
    sys.exit(0)
