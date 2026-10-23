"""
conftest.py — pytest configuration for unit tests.
Sets CONFIG_DIR environment variable to the local config/ directory
so that rules.py and inventory.py can load YAML config files
when running tests outside Docker.

The env var must be set BEFORE any module is imported, so we set it
at module import time here (not via fixture).
"""
import os

# Resolve config/ relative to: tests/unit/ → ../../config
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_CONFIG_DIR = os.path.join(_REPO_ROOT, "config")

# Set at collection time so all subsequent imports of rules.py / inventory.py
# read the correct CONFIG_DIR from os.getenv() inside their functions.
os.environ.setdefault("CONFIG_DIR", _CONFIG_DIR)

import sys
_API_DIR = os.path.join(_REPO_ROOT, "services", "api")
if _API_DIR not in sys.path:
    sys.path.insert(0, _API_DIR)

_SENSOR_DIR = os.path.join(_REPO_ROOT, "services", "sensor")
if _SENSOR_DIR not in sys.path:
    sys.path.insert(0, _SENSOR_DIR)

