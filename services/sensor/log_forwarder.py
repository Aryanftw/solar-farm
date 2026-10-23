"""
Zeek Log Forwarder — reads Zeek Modbus logs and forwards events to FastAPI.

Supports:
  * Zeek's built-in ``modbus.log`` (request/response header records)
  * CISA ICSNPP ``modbus_detailed.log`` (request/response values + addresses)

The two logs are merged per transaction using (uid, tid, func) so a single
normalised event is sent to the API for each Modbus request. Request-only
traffic (for example a rogue client whose reads are never answered) is still
forwarded after a short grace period even when no detailed record exists.

Supports streaming (live) and one-shot (PCAP replay) modes.
"""

import argparse
import glob
import logging
import os
import time
from datetime import datetime, timezone

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s [forwarder] %(message)s")
logger = logging.getLogger("forwarder")

API_URL = os.getenv("API_URL", "http://172.20.0.50:8000")
LOG_DIR = os.getenv("ZEEK_LOG_DIR", "/var/log/zeek/current")
BASIC_LOG = "modbus.log"
DETAILED_LOG = "modbus_detailed.log"

# How long to wait for a matching detailed record before forwarding a request
# seen only in modbus.log. Detailed records are normally written immediately
# after the matching response packet arrives.
DETAIL_GRACE_S = 2.0

# Zeek function name -> Modbus function code
FUNCTION_CODES = {
    "READ_COILS": 1,
    "READ_DISCRETE_INPUTS": 2,
    "READ_HOLDING_REGISTERS": 3,
    "READ_INPUT_REGISTERS": 4,
    "WRITE_SINGLE_COIL": 5,
    "WRITE_SINGLE_REGISTER": 6,
    "READ_EXCEPTION_STATUS": 7,
    "DIAGNOSTICS": 8,
    "GET_COMM_EVENT_COUNTER": 11,
    "GET_COMM_EVENT_LOG": 12,
    "WRITE_MULTIPLE_COILS": 15,
    "WRITE_MULTIPLE_REGISTERS": 16,
    "REPORT_SERVER_ID": 17,
    "READ_FILE_RECORD": 20,
    "WRITE_FILE_RECORD": 21,
    "MASK_WRITE_REGISTER": 22,
    "READ_WRITE_MULTIPLE_REGISTERS": 23,
    "READ_FIFO_QUEUE": 24,
    "ENCAPSULATED_INTERFACE_TRANSPORT": 43,
}

ADDRESS_FIELDS = (
    "address",
    "start_address",
    "start_reg",
    "start_register",
    "write_start_address",
    "read_start_address",
    "track_address",
    "register",
    "register_address",
    "target_address",
)
VALUE_FIELDS = (
    "request_values",
    "request_value",
    "write_registers",
    "write_value",
    "values",
    "value",
    "raw_value",
)


def _unset(value) -> bool:
    return value is None or str(value).strip() in ("", "-", "(empty)")


def _function_code(func) -> int | None:
    """Return an integer Modbus function code from a Zeek log value."""
    if _unset(func):
        return None
    text = str(func).strip()
    if text.upper() in FUNCTION_CODES:
        return FUNCTION_CODES[text.upper()]
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text)
    except ValueError:
        return None


def _to_int(value) -> int | None:
    if _unset(value):
        return None
    text = str(value).strip()
    try:
        return int(text, 0)
    except ValueError:
        try:
            return int(float(text))
        except ValueError:
            return None


def _first_int(record: dict, names) -> int | None:
    for name in names:
        if name in record:
            parsed = _to_int(record[name])
            if parsed is not None:
                return parsed
    return None


def _first_value(record: dict) -> int | None:
    """Extract the first request value from a Zeek vector/list field."""
    for name in VALUE_FIELDS:
        raw = record.get(name)
        if _unset(raw):
            continue
        text = str(raw).strip()
        if text.startswith("[") and text.endswith("]"):
            text = text[1:-1]
        for part in text.replace(";", ",").split(","):
            parsed = _to_int(part)
            if parsed is not None:
                return parsed
    return None


def _is_response(record: dict) -> bool:
    direction = (
        record.get("pdu_type")
        or record.get("network_direction")
        or record.get("request_response")
        or record.get("direction")
    )
    if not direction:
        is_orig = record.get("is_orig")
        if is_orig is not None and str(is_orig).strip().upper() in ("F", "FALSE", "0"):
            return True
        return False
    return str(direction).strip().upper() in ("RESP", "RESPONSE", "REPLY", "R")


class ZeekModbusParser:
    """Stateful parser for a single Zeek TSV log file."""

    def __init__(self):
        self.fields: list[str] | None = None
        self.separator = "\t"

    def parse_line(self, line: str) -> dict | None:
        line = line.rstrip("\n")
        if not line:
            return None
        if line.startswith("#"):
            self._parse_meta(line)
            return None
        if self.fields is None:
            self.fields = _default_fields_for_basic()
        parts = line.split(self.separator)
        if len(parts) < len(self.fields):
            parts += [""] * (len(self.fields) - len(parts))
        record = dict(zip(self.fields, parts))
        return normalise_record(record)

    def _parse_meta(self, line: str) -> None:
        body = line[1:]
        if body.startswith("separator"):
            value = body.split(None, 1)[1] if len(body.split(None, 1)) > 1 else "\t"
            if value in ("\\x09", "\\t"):
                self.separator = "\t"
            else:
                self.separator = value
        elif body.startswith("fields"):
            self.fields = body.split(self.separator)[1:]


def _default_fields_for_basic() -> list[str]:
    """Fallback field order used when a log has no #fields header."""
    return [
        "ts", "uid",
        "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "tid", "unit", "func", "pdu_type", "exception",
    ]


def _normalise_address(record: dict) -> dict:
    address = _first_int(record, ADDRESS_FIELDS)
    value = _first_value(record)
    if address is not None:
        record["register"] = address
    if value is not None:
        record["value"] = value
    return record


def normalise_record(record: dict) -> dict | None:
    """Convert a raw Zeek TSV record into the API's event shape."""
    ts_raw = record.get("ts")
    if _unset(ts_raw):
        return None
    try:
        ts_epoch = float(ts_raw)
    except (TypeError, ValueError):
        return None

    if _is_response(record):
        return None

    func_raw = record.get("func") or record.get("function") or record.get("function_code")
    function_code = _function_code(func_raw)
    if function_code is None:
        return None

    src = record.get("source_h")
    src_port = record.get("source_p")
    dst = record.get("destination_h")
    dst_port = record.get("destination_p")
    if _unset(src) or _unset(dst):
        src = record.get("id.orig_h")
        src_port = record.get("id.orig_p")
        dst = record.get("id.resp_h")
        dst_port = record.get("id.resp_p")
    if _unset(src) or _unset(dst):
        return None

    record = _normalise_address(record)

    return {
        "ts": ts_epoch,
        "uid": record.get("uid"),
        "id_orig_h": src,
        "id_orig_p": _to_int(src_port) or 0,
        "id_resp_h": dst,
        "id_resp_p": _to_int(dst_port) or 502,
        "func": str(func_raw) if not _unset(func_raw) else "",
        "function_code": function_code,
        "register": record.get("register"),
        "value": record.get("value"),
        "tid": _to_int(record.get("tid")),
    }


def _event_key(event: dict) -> tuple:
    return (
        event.get("uid"),
        event.get("tid"),
        event.get("function_code"),
        event.get("ts"),
    )


def _merge_event(base: dict, detailed: dict) -> dict:
    merged = dict(base)
    for field in ("register", "value", "func", "function_code", "tid", "ts"):
        if detailed.get(field) is not None:
            merged[field] = detailed[field]
    return merged


def forward_event(event: dict) -> bool:
    payload = {
        "ts": event.get("ts"),
        "id_orig_h": event.get("id_orig_h"),
        "id_orig_p": event.get("id_orig_p"),
        "id_resp_h": event.get("id_resp_h"),
        "id_resp_p": event.get("id_resp_p"),
        "func": event.get("func"),
        "function_code": event.get("function_code"),
        "register": event.get("register"),
        "value": event.get("value"),
    }
    try:
        response = requests.post(f"{API_URL}/ingest/zeek_modbus", json=payload, timeout=3)
        return response.ok
    except Exception as exc:
        logger.debug("Forward failed: %s", exc)
        return False


def parse_file(path: str) -> list[dict]:
    """Parse all event records from one Zeek log file."""
    parser = ZeekModbusParser()
    events = []
    try:
        with open(path) as handle:
            for line in handle:
                event = parser.parse_line(line)
                if event:
                    events.append(event)
    except FileNotFoundError:
        return []
    return events


def _log_paths(log_dir: str) -> list[str]:
    """Return Modbus log files to read, preferring detailed records."""
    paths = []
    basic = os.path.join(log_dir, BASIC_LOG)
    detailed = os.path.join(log_dir, DETAILED_LOG)
    if os.path.exists(detailed):
        paths.append(detailed)
    if os.path.exists(basic):
        paths.append(basic)
    return paths


def merge_and_dedupe(events: list[dict]) -> list[dict]:
    """Merge basic + detailed records and return one event per request."""
    merged: dict[tuple, dict] = {}
    order: list[tuple] = []

    for event in events:
        key = _event_key(event)
        if key not in merged:
            merged[key] = event
            order.append(key)
        else:
            existing = merged[key]
            # A detailed record has an address/value; keep the richer copy.
            if event.get("register") is not None or event.get("value") is not None:
                merged[key] = _merge_event(existing, event)

    return [merged[key] for key in order]


def process_once(log_dir: str = LOG_DIR) -> int:
    """Process all currently available log files once (PCAP replay mode)."""
    events: list[dict] = []
    for path in _log_paths(log_dir):
        file_events = parse_file(path)
        logger.info("Parsed %d events from %s", len(file_events), path)
        events.extend(file_events)

    unique_events = merge_and_dedupe(events)
    forwarded = 0
    for event in unique_events:
        if forward_event(event):
            forwarded += 1
    logger.info("Forwarded %d/%d unique events", forwarded, len(unique_events))
    return forwarded


class LogTails:
    """Tail multiple Zeek logs, tracking per-file offsets and parser state."""

    def __init__(self, log_dir: str):
        self.log_dir = log_dir
        self.positions: dict[str, int] = {}
        self.parsers: dict[str, ZeekModbusParser] = {}
        self.pending: dict[tuple, dict] = {}
        self.deadlines: dict[tuple, float] = {}

    def _known_paths(self) -> set[str]:
        return set(self.positions)

    def poll(self) -> int:
        forwarded = 0
        for path in _log_paths(self.log_dir):
            forwarded += self._read_new_lines(path)
        forwarded += self._flush_expired()
        return forwarded

    def _read_new_lines(self, path: str) -> int:
        forwarded = 0
        try:
            size = os.path.getsize(path)
        except OSError:
            return 0
        position = self.positions.get(path, 0)
        if size < position:
            # Log rotated/truncated.
            position = 0
        if size == position:
            return 0

        parser = self.parsers.setdefault(path, ZeekModbusParser())
        with open(path) as handle:
            handle.seek(position)
            for line in handle:
                event = parser.parse_line(line)
                if event:
                    self._ingest(event)
            self.positions[path] = handle.tell()
        return forwarded

    def _ingest(self, event: dict) -> None:
        key = _event_key(event)
        now = time.monotonic()
        if key in self.pending:
            self.pending[key] = _merge_event(self.pending[key], event)
            # Once we have detailed data, the event can be forwarded promptly.
            if event.get("register") is not None or event.get("value") is not None:
                self.deadlines[key] = min(self.deadlines.get(key, now), now + 0.2)
        else:
            self.pending[key] = event
            self.deadlines[key] = now + DETAIL_GRACE_S

    def _flush_expired(self) -> int:
        now = time.monotonic()
        expired = [key for key, deadline in self.deadlines.items() if deadline <= now]
        forwarded = 0
        for key in expired:
            event = self.pending.pop(key)
            self.deadlines.pop(key, None)
            if forward_event(event):
                forwarded += 1
        return forwarded

    def flush_all(self) -> int:
        forwarded = 0
        for key in list(self.pending):
            event = self.pending.pop(key)
            self.deadlines.pop(key, None)
            if forward_event(event):
                forwarded += 1
        return forwarded


def tail_logs(log_dir: str = LOG_DIR, interval_s: float = 1.0) -> None:
    logger.info("Tailing Modbus logs in %s", log_dir)
    tails = LogTails(log_dir)
    try:
        while True:
            forwarded = tails.poll()
            if forwarded:
                logger.info("Forwarded %d events", forwarded)
            time.sleep(interval_s)
    except KeyboardInterrupt:
        tails.flush_all()


def parse_zeek_modbus_log(line: str) -> dict | None:
    """Backwards-compatible single-line parser (used by unit tests)."""
    return ZeekModbusParser().parse_line(line)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="Process logs once and exit (PCAP mode)")
    parser.add_argument("--log-dir", default=LOG_DIR, help="Directory containing Zeek logs")
    args = parser.parse_args()

    if args.once:
        process_once(args.log_dir)
    else:
        tail_logs(args.log_dir)


if __name__ == "__main__":
    main()
