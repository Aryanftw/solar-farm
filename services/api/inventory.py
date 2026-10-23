"""
Inventory Manager — B3 Live Device Inventory
Builds and maintains device inventory from passive observations.
Joins against the authorised device manifest for role labels and baseline relationships.
Flags unknown devices and tracks communication peers.
"""

import json
import logging
import os
import yaml
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG = (
    "/app/config"
    if os.path.exists("/app/config")
    else os.path.abspath(os.path.join(os.path.dirname(__file__), "../../config"))
)
CONFIG_DIR = os.getenv("CONFIG_DIR", _DEFAULT_CONFIG)


def _load_manifest() -> dict:
    cfg = os.getenv("CONFIG_DIR", _DEFAULT_CONFIG)
    manifest_path = os.path.join(cfg, "device_manifest.yaml")
    if not os.path.exists(manifest_path):
        return {"devices": [], "authorised_modbus_writers": [], "authorised_iec104_masters": [], "baseline_communication_matrix": []}
    with open(manifest_path) as f:
        return yaml.safe_load(f) or {}


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _get_manifest_device(ip: str, manifest: dict) -> Optional[dict]:
    for dev in manifest.get("devices", []):
        if dev.get("ip") == ip:
            return dev
    return None


def is_relationship_approved(conn, src_ip: str, dst_ip: str, protocol: str, dst_port: int = 502) -> bool:
    """
    Check if a communication relationship is in the approved baseline.
    Queries the communication_baseline table first; falls back to device_manifest.yaml.
    """
    try:
        row = conn.execute(
            """SELECT approved FROM communication_baseline
               WHERE src_ip=? AND dst_ip=? AND protocol=? AND dst_port=?""",
            (src_ip, dst_ip, protocol, dst_port),
        ).fetchone()
        if row is not None:
            return bool(row["approved"])
    except Exception as exc:
        logger.debug("Database check for communication_baseline failed: %s", exc)

    # Fallback to manifest config
    manifest = _load_manifest()
    matrix = manifest.get("baseline_communication_matrix", [])
    for rel in matrix:
        if (
            rel.get("src") == src_ip
            and rel.get("dst") == dst_ip
            and rel.get("protocol") == protocol
            and int(rel.get("port", 502)) == int(dst_port)
        ):
            return True
    return False


def approve_relationship(
    conn,
    src_ip: str,
    dst_ip: str,
    protocol: str,
    dst_port: int,
    approved_by: str = "operator",
    notes: str = "",
) -> dict:
    """
    Explicitly approve a communication relationship in the baseline with audit metadata.
    """
    now = _now_utc()
    conn.execute(
        """INSERT INTO communication_baseline
           (src_ip, dst_ip, protocol, dst_port, approved, approved_by, approved_at_utc, notes)
           VALUES (?, ?, ?, ?, 1, ?, ?, ?)
           ON CONFLICT(src_ip, dst_ip, protocol, dst_port) DO UPDATE SET
           approved=1, approved_by=excluded.approved_by, approved_at_utc=excluded.approved_at_utc,
           notes=excluded.notes""",
        (src_ip, dst_ip, protocol, dst_port, approved_by, now, notes),
    )
    logger.info("AUDIT: Baseline relationship approved: %s -> %s (%s:%d) by %s", src_ip, dst_ip, protocol, dst_port, approved_by)
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "dst_port": dst_port,
        "approved": True,
        "approved_by": approved_by,
        "approved_at_utc": now,
        "notes": notes,
    }


def get_baseline_relationships(conn) -> list[dict]:
    """Return all recorded baseline communication relationships."""
    try:
        rows = conn.execute("SELECT * FROM communication_baseline ORDER BY id").fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []


def upsert_device(
    conn,
    ip: str,
    protocol: str,
    port: int = 502,
    peer_ip: Optional[str] = None,
    mac: Optional[str] = None,
    src: str = "passive",
) -> dict:
    """
    Insert or update a device observation.
    Tracks protocols, ports, communicating peers, MAC address, and confidence.
    """
    manifest = _load_manifest()
    manifest_dev = _get_manifest_device(ip, manifest)

    now = _now_utc()
    authorised = 1 if manifest_dev else 0
    role = manifest_dev.get("role", "unknown") if manifest_dev else "unknown"
    hostname = manifest_dev.get("hostname") if manifest_dev else None
    manifest_mac = manifest_dev.get("mac") if manifest_dev else None

    # Determine MAC address: prefer observed, then manifest, default unknown/not_observable
    resolved_mac = mac or manifest_mac or "unknown/not_observable"

    row = conn.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()

    protocols_set = set()
    peers_set = set()

    if row:
        existing_protos = json.loads(row["protocols"] or "[]")
        protocols_set = set(existing_protos)
        existing_peers = json.loads(row["peers"] or "[]") if "peers" in row.keys() else []
        peers_set = set(existing_peers)

    proto_entry = f"{protocol}:{port}"
    protocols_set.add(proto_entry)
    if peer_ip and peer_ip != ip:
        peers_set.add(peer_ip)

    protocols_json = json.dumps(sorted(protocols_set))
    peers_json = json.dumps(sorted(peers_set))

    # Determine confidence:
    # manifest_verified: IP and expected role in manifest
    # observed_unknown: IP not in manifest
    confidence = "manifest_verified" if authorised else "observed_unknown"

    if row is None:
        # New device
        conn.execute(
            """INSERT INTO devices
               (ip, mac, hostname, role, protocols, peers, first_seen_utc, last_seen_utc, authorised, source, confidence)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (ip, resolved_mac, hostname, role, protocols_json, peers_json, now, now, authorised, src, confidence),
        )
        logger.info("NEW device observed: %s role=%s authorised=%s confidence=%s", ip, role, bool(authorised), confidence)
        return {
            "ip": ip,
            "is_new": True,
            "authorised": bool(authorised),
            "role": role,
            "confidence": confidence,
            "peers": list(peers_set),
        }
    else:
        # Update existing device observation
        # Keep original first_seen_utc, update last_seen_utc, protocols, peers
        current_mac = row["mac"] if row["mac"] and row["mac"] != "unknown/not_observable" else resolved_mac
        conn.execute(
            """UPDATE devices SET
               last_seen_utc=?, protocols=?, peers=?, role=?, mac=?, confidence=?
               WHERE ip=?""",
            (now, protocols_json, peers_json, role, current_mac, confidence, ip),
        )
        return {
            "ip": ip,
            "is_new": False,
            "authorised": bool(authorised),
            "role": role,
            "confidence": confidence,
            "peers": list(peers_set),
        }


def get_all_devices(conn) -> list:
    rows = conn.execute("SELECT * FROM devices ORDER BY first_seen_utc").fetchall()
    return [dict(r) for r in rows]


def get_device_by_ip(conn, ip: str) -> Optional[dict]:
    row = conn.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()
    return dict(row) if row else None


def get_lab_manifest_ips() -> list:
    manifest = _load_manifest()
    return [d["ip"] for d in manifest.get("devices", [])]


def get_authorised_modbus_writers() -> list:
    manifest = _load_manifest()
    return [w["ip"] for w in manifest.get("authorised_modbus_writers", [])]


def get_authorised_iec104_masters() -> list:
    manifest = _load_manifest()
    return [m["ip"] for m in manifest.get("authorised_iec104_masters", [])]
