#!/bin/bash
# Zeek sensor entrypoint — handles both live capture and PCAP replay modes
# Runs Zeek, then forwards parsed Modbus logs to the API.

set -e

CAPTURE_MODE="${CAPTURE_MODE:-pcap_replay}"
CAPTURE_INTERFACE="${CAPTURE_INTERFACE:-lo}"
PCAP_FILE="${PCAP_FILE:-/pcaps/normal_baseline.pcap}"
LOG_DIR="/var/log/zeek/current"
API_URL="${API_URL:-http://172.20.0.50:8000}"

mkdir -p "$LOG_DIR"
mkdir -p /pcaps

# Use the ICSNPP-enhanced script when the package is installed, otherwise fall
# back to Zeek's built-in Modbus parser so the sensor still starts.
ZEEK_SCRIPT="/etc/zeek/site/solar_farm/main.zeek"
if ! zkg list 2>/dev/null | grep -q "icsnpp-modbus"; then
    echo "[sensor] ICSNPP-Modbus not installed — using built-in Modbus parser"
    sed '/@load icsnpp-modbus/d' "$ZEEK_SCRIPT" > /tmp/solar_farm_fallback.zeek
    ZEEK_SCRIPT="/tmp/solar_farm_fallback.zeek"
fi

echo "[sensor] Starting in CAPTURE_MODE=$CAPTURE_MODE (script: $ZEEK_SCRIPT)"

# Report sensor health to API
report_health() {
    local running=$1
    local observed=$2
    local packets=$3
    local proto=$4
    curl -s -X POST "$API_URL/sensor/health" \
        -H "Content-Type: application/json" \
        -d "{\"sensor_running\": $running, \"traffic_observed\": $observed, \"capture_mode\": \"$CAPTURE_MODE\", \"packets_seen\": $packets, \"last_protocol_seen\": \"$proto\"}" || true
}

if [ "$CAPTURE_MODE" = "live" ]; then
    # ── Live capture mode (Linux/WSL2 only) ─────────────────────────────────
    echo "[sensor] Starting Zeek in live capture mode on interface: $CAPTURE_INTERFACE"
    
    # Verify packets are visible (doctor check)
    VISIBLE=$(timeout 5 tcpdump -i "$CAPTURE_INTERFACE" -c 1 -q 2>/dev/null && echo "yes" || echo "no")
    if [ "$VISIBLE" != "yes" ]; then
        echo "[sensor] ❌ No packets visible on $CAPTURE_INTERFACE. Live capture cannot proceed."
        echo "[sensor] ⚠️  On Windows/macOS, set CAPTURE_MODE=pcap_replay in .env"
        report_health false false 0 "none"
        # Don't exit — run in degraded mode and keep the container alive
        while true; do
            sleep 30
            report_health false false 0 "none"
        done
    fi
    
    report_health true false 0 "starting"
    
    cd "$LOG_DIR"
    zeek -i "$CAPTURE_INTERFACE" "$ZEEK_SCRIPT" &
    ZEEK_PID=$!
    
    echo "[sensor] Zeek PID: $ZEEK_PID"
    sleep 5
    
    # Start log forwarder
    python3 /app/log_forwarder.py &
    
    # Monitor Zeek
    packets_seen=0
    while kill -0 $ZEEK_PID 2>/dev/null; do
        packets=$(grep -c . "$LOG_DIR/modbus.log" 2>/dev/null || echo 0)
        report_health true $( [ "$packets" -gt 0 ] && echo true || echo false ) "$packets" "modbus-tcp"
        sleep 10
    done

elif [ "$CAPTURE_MODE" = "pcap_replay" ]; then
    # ── PCAP replay mode (Windows/macOS compatible) ───────────────────────
    echo "[sensor] Starting in PCAP replay mode"
    
    # Generate a minimal baseline PCAP if none exists
    if [ ! -f "$PCAP_FILE" ]; then
        echo "[sensor] No PCAP file found at $PCAP_FILE — generating minimal test PCAP"
        python3 /app/generate_test_pcap.py "$PCAP_FILE" || echo "[sensor] Could not generate test PCAP"
    fi
    
    if [ -f "$PCAP_FILE" ]; then
        echo "[sensor] Processing PCAP: $PCAP_FILE"
        report_health true false 0 "pcap_replay"
        
        # Run Zeek on PCAP
        cd "$LOG_DIR"
        zeek -r "$PCAP_FILE" "$ZEEK_SCRIPT" 2>&1 || echo "[sensor] Zeek PCAP processing finished"
        
        # Forward parsed logs
        python3 /app/log_forwarder.py --once
        
        packets=$(grep -c . "$LOG_DIR/modbus.log" 2>/dev/null || echo 0)
        report_health true true "$packets" "modbus-tcp"
        echo "[sensor] PCAP replay complete. Modbus events forwarded: $packets"
    else
        echo "[sensor] No PCAP available. Starting in standby mode."
        report_health true false 0 "pcap_replay_standby"
    fi
    
    # Keep container alive and periodically re-run if PCAP changes
    while true; do
        sleep 60
        report_health true true 0 "pcap_replay_idle"
    done
fi
