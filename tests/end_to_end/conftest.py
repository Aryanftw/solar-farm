"""
conftest.py -- pytest configuration for end-to-end tests.
E2E tests require the full lab to be running (make up + make baseline).
All tests are auto-skipped when the API is not reachable.
This conftest sets CONFIG_DIR for any modules that need it.
"""
import os

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_CONFIG_DIR = os.path.join(_REPO_ROOT, "config")

os.environ.setdefault("CONFIG_DIR", _CONFIG_DIR)
