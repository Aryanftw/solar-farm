"""
Database models and setup — SQLite via sqlite3.
All tables created here. Schema versioned in schema_version table.
"""

import sqlite3
import os
import logging
from contextlib import contextmanager
from typing import Generator, Optional

logger = logging.getLogger(__name__)

_DEFAULT_DB = (
    "/app/data/watchman.db"
    if os.path.exists("/app/data") or (os.name != "nt" and os.path.exists("/app"))
    else os.path.abspath(os.path.join(os.path.dirname(__file__), "../../data/watchman.db"))
)
DB_PATH = os.getenv("DB_PATH", _DEFAULT_DB)

SCHEMA_VERSION = 4

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL,
    applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    mac TEXT DEFAULT 'unknown/not_observable',
    hostname TEXT,
    role TEXT DEFAULT 'unknown',
    protocols TEXT DEFAULT '[]',
    peers TEXT DEFAULT '[]',
    first_seen_utc TEXT NOT NULL,
    last_seen_utc TEXT NOT NULL,
    authorised INTEGER DEFAULT 0,
    source TEXT DEFAULT 'passive',
    confidence TEXT DEFAULT 'observed',
    observation_notes TEXT,
    UNIQUE(ip)
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc TEXT NOT NULL,
    source TEXT NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    dst_port INTEGER,
    protocol TEXT,
    function_code INTEGER,
    register_address INTEGER,
    raw_value INTEGER,
    direction TEXT,
    asdu_type TEXT,
    ioa INTEGER,
    extra_json TEXT,
    scenario_id TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT UNIQUE NOT NULL,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    timestamp_utc TEXT NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    dst_port INTEGER,
    protocol TEXT,
    evidence_json TEXT,
    explanation TEXT NOT NULL,
    recommended_action TEXT,
    status TEXT DEFAULT 'open',
    scenario_id TEXT,
    event_id INTEGER REFERENCES events(id),
    anomaly_score REAL,
    top_features TEXT
);

CREATE TABLE IF NOT EXISTS sensor_health (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc TEXT NOT NULL,
    sensor_running INTEGER DEFAULT 0,
    traffic_observed INTEGER DEFAULT 0,
    capture_mode TEXT,
    packets_seen INTEGER DEFAULT 0,
    last_protocol_seen TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS baseline_windows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    window_start_utc TEXT NOT NULL,
    window_end_utc TEXT NOT NULL,
    src_ip TEXT,
    total_requests INTEGER DEFAULT 0,
    read_count INTEGER DEFAULT 0,
    write_count INTEGER DEFAULT 0,
    write_to_read_ratio REAL DEFAULT 0.0,
    distinct_dst_devices INTEGER DEFAULT 0,
    new_source INTEGER DEFAULT 0,
    request_rate_deviation REAL DEFAULT 0.0,
    protocol TEXT,
    iec104_command_count INTEGER DEFAULT 0,
    labelled TEXT DEFAULT 'normal',
    anomaly_score REAL
);

CREATE TABLE IF NOT EXISTS trial_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scenario_id TEXT NOT NULL,
    trial_number INTEGER NOT NULL,
    started_utc TEXT NOT NULL,
    expected_alert_rule TEXT NOT NULL,
    alert_generated INTEGER DEFAULT 0,
    alert_id TEXT,
    alert_latency_seconds REAL,
    false_positive INTEGER DEFAULT 0,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS communication_baseline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    protocol TEXT NOT NULL,
    dst_port INTEGER NOT NULL,
    approved INTEGER DEFAULT 1,
    approved_by TEXT DEFAULT 'manifest_init',
    approved_at_utc TEXT NOT NULL,
    notes TEXT,
    UNIQUE(src_ip, dst_ip, protocol, dst_port)
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);
CREATE INDEX IF NOT EXISTS idx_comm_baseline ON communication_baseline(src_ip, dst_ip, protocol, dst_port);
"""


def get_db_path() -> str:
    return DB_PATH


@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    """Yield a database connection with row_factory set."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _seed_baseline_relationships(conn: sqlite3.Connection) -> None:
    """Seed approved communication relationships from device_manifest.yaml if table is empty."""
    import yaml
    from datetime import datetime, timezone

    row_count = conn.execute("SELECT COUNT(*) as c FROM communication_baseline").fetchone()["c"]
    if row_count > 0:
        return

    _DEFAULT_CONFIG = (
        "/app/config"
        if os.path.exists("/app/config")
        else os.path.abspath(os.path.join(os.path.dirname(__file__), "../../config"))
    )
    cfg_dir = os.getenv("CONFIG_DIR", _DEFAULT_CONFIG)
    manifest_path = os.path.join(cfg_dir, "device_manifest.yaml")
    if not os.path.exists(manifest_path):
        return

    try:
        with open(manifest_path) as f:
            manifest = yaml.safe_load(f)
        matrix = manifest.get("baseline_communication_matrix", [])
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        for rel in matrix:
            src = rel.get("src")
            dst = rel.get("dst")
            proto = rel.get("protocol", "modbus-tcp")
            port = int(rel.get("port", 502))
            desc = rel.get("description", "Approved in initial manifest")
            if src and dst:
                conn.execute(
                    """INSERT OR IGNORE INTO communication_baseline
                       (src_ip, dst_ip, protocol, dst_port, approved, approved_by, approved_at_utc, notes)
                       VALUES (?, ?, ?, ?, 1, 'manifest_init', ?, ?)""",
                    (src, dst, proto, port, now, desc),
                )
        logger.info("Seeded %d baseline communication relationships from manifest", len(matrix))
    except Exception as exc:
        logger.warning("Could not seed baseline communication relationships: %s", exc)


def _apply_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)

    # Ensure peers column exists in devices table (migration for existing DBs)
    cols = [c["name"] for c in conn.execute("PRAGMA table_info(devices)").fetchall()]
    if "peers" not in cols:
        conn.execute("ALTER TABLE devices ADD COLUMN peers TEXT DEFAULT '[]'")

    # Check/set schema version
    row = conn.execute("SELECT MAX(version) as v FROM schema_version").fetchone()
    if row["v"] is None or row["v"] < SCHEMA_VERSION:
        conn.execute(
            "INSERT INTO schema_version(version) VALUES (?)", (SCHEMA_VERSION,)
        )
        logger.info("Database schema version set to %d", SCHEMA_VERSION)
    else:
        logger.info("Database schema version: %d", row["v"])

    _seed_baseline_relationships(conn)


def init_db(conn: Optional[sqlite3.Connection] = None) -> None:
    """Create tables and apply schema if needed."""
    if conn is not None:
        _apply_schema(conn)
        return
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with get_db() as c:
        _apply_schema(c)

