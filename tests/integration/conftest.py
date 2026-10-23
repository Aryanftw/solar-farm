"""
conftest.py — pytest configuration for integration tests.
Integration tests require the API to be running at localhost:8000.
All tests are auto-skipped when the API is not reachable.
Sets CONFIG_DIR so any module imports that need it resolve correctly.
"""
import os

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_CONFIG_DIR = os.path.join(_REPO_ROOT, "config")

os.environ.setdefault("CONFIG_DIR", _CONFIG_DIR)
