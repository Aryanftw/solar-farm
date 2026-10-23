"""
Baseline Generator — B4 ML Training
Generates labelled normal-traffic baseline windows from running lab traffic.
Sends them to the API for storage, then triggers model training.

Run this BEFORE running attack scenarios to train the ML model on clean traffic.
Requires the lab (make up) to already be running and producing Modbus traffic.

Usage:
  python generate_baseline.py --minutes 10
"""

import argparse
import logging
import time
from datetime import datetime, timezone, timedelta

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("baseline")

API_URL = "http://127.0.0.1:8000"
WINDOW_S = 60   # 1-minute windows


def get_events_for_window(start_ts: str, end_ts: str, src_ip: str) -> dict:
    """Fetch events from API and compute window features."""
    try:
        r = requests.get(f"{API_URL}/events", params={"src_ip": src_ip, "limit": 1000}, timeout=5)
        events = r.json().get("events", []) if r.ok else []
    except Exception:
        events = []

    # Filter to window
    window_events = [
        e for e in events
        if start_ts <= e.get("timestamp_utc", "") <= end_ts
    ]

    total = len(window_events)
    reads = sum(1 for e in window_events if e.get("function_code") in (1, 2, 3, 4))
    writes = sum(1 for e in window_events if e.get("function_code") in (5, 6, 15, 16))
    wtr = writes / max(reads, 1)
    distinct_dst = len(set(e.get("dst_ip") for e in window_events if e.get("dst_ip")))
    expected_rate = 20.0
    observed_rate = total / (WINDOW_S / 60.0)
    rate_dev = abs(observed_rate - expected_rate) / max(expected_rate, 1)
    iec104 = sum(1 for e in window_events if e.get("protocol") == "iec60870-5-104")

    return {
        "window_start_utc": start_ts,
        "window_end_utc": end_ts,
        "src_ip": src_ip,
        "total_requests": total,
        "read_count": reads,
        "write_count": writes,
        "write_to_read_ratio": wtr,
        "distinct_dst_devices": distinct_dst,
        "new_source": 0,
        "request_rate_deviation": rate_dev,
        "protocol": "modbus-tcp",
        "iec104_command_count": iec104,
        "labelled": "normal",
    }


def generate_synthetic_normal_windows(n: int = 50) -> list:
    """
    Generate synthetic normal baseline windows for initial training.
    These represent typical SCADA polling: mostly reads, low write rate.
    """
    import random
    random.seed(42)
    windows = []
    now = datetime.now(timezone.utc)
    for i in range(n):
        t_start = now - timedelta(seconds=(n - i) * WINDOW_S)
        t_end = t_start + timedelta(seconds=WINDOW_S)
        total = random.randint(15, 25)
        reads = int(total * 0.95)
        writes = total - reads
        wtr = writes / max(reads, 1)
        windows.append({
            "window_start_utc": t_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "window_end_utc": t_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "src_ip": f"172.20.0.{40}",  # HMI
            "total_requests": total,
            "read_count": reads,
            "write_count": writes,
            "write_to_read_ratio": wtr,
            "distinct_dst_devices": random.randint(3, 4),
            "new_source": 0,
            "request_rate_deviation": abs(random.gauss(0, 0.1)),
            "protocol": "modbus-tcp",
            "iec104_command_count": random.randint(0, 2),
            "labelled": "normal",
        })
    return windows


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate normal baseline for ML training")
    parser.add_argument("--minutes", type=int, default=5, help="How many minutes to observe (0 = use synthetic)")
    parser.add_argument("--synthetic", action="store_true", help="Use synthetic baseline (when lab is not yet running)")
    args = parser.parse_args()

    # Check API connectivity
    try:
        r = requests.get(f"{API_URL}/health", timeout=5)
        if not r.ok:
            raise ConnectionError()
        logger.info("API reachable at %s", API_URL)
    except Exception:
        logger.error("Cannot reach API at %s. Is the lab running? Run 'make up' first.", API_URL)
        logger.error("Alternatively, run with --synthetic to generate synthetic baseline data.")
        return

    if args.synthetic or args.minutes == 0:
        logger.info("Generating 50 synthetic normal baseline windows...")
        windows = generate_synthetic_normal_windows(50)
    else:
        logger.info("Observing live traffic for %d minutes (%d windows)...", args.minutes, args.minutes)
        windows = []
        known_ips = ["172.20.0.40", "172.20.0.11", "172.20.0.12", "172.20.0.13"]
        for minute in range(args.minutes):
            logger.info("Window %d/%d...", minute + 1, args.minutes)
            start_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            time.sleep(WINDOW_S)
            end_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            for ip in known_ips:
                w = get_events_for_window(start_ts, end_ts, ip)
                if w["total_requests"] > 0:
                    windows.append(w)

    # Post all windows to API
    logger.info("Posting %d baseline windows to API...", len(windows))
    posted = 0
    for w in windows:
        try:
            r = requests.post(f"{API_URL}/baseline/window", json=w, timeout=5)
            if r.ok:
                posted += 1
        except Exception as e:
            logger.warning("Failed to post window: %s", e)

    logger.info("Posted %d/%d windows", posted, len(windows))

    # Trigger model training
    logger.info("Triggering ML model training...")
    try:
        r = requests.post(f"{API_URL}/model/train", timeout=30)
        if r.ok:
            meta = r.json().get("meta", {})
            logger.info("Model trained successfully!")
            logger.info("  Samples: %d", meta.get("n_samples", "?"))
            logger.info("  Version: %s", meta.get("version", "?"))
            logger.info("  Trained at: %s", meta.get("trained_at_utc", "?"))
        else:
            logger.error("Training failed: %s", r.text)
    except Exception as e:
        logger.error("Training request failed: %s", e)

    logger.info("Baseline generation complete. The ML model is now ready.")
    logger.info("You can now run attack scenarios: python scripts/run_scenario.py S1")


if __name__ == "__main__":
    main()
