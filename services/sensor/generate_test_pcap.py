"""
Generate Test PCAP — Sensor Service
Creates a minimal Modbus TCP PCAP file for use in pcap_replay mode.

This script generates a synthetic PCAP containing:
  - Normal Modbus read (FC4) requests from FUXA HMI to each inverter
  - A few FC3 reads to the OpenPLC
  - Raw bytes are hand-crafted for simplicity (no external dependencies)

The PCAP is used by Zeek in pcap_replay mode when no real capture is available.
This is the Windows/macOS compatible mode.

Usage: python generate_test_pcap.py /pcaps/normal_baseline.pcap
"""

import struct
import sys
import os
import time
from datetime import datetime, timezone

# ── PCAP constants ────────────────────────────────────────────────────────────
PCAP_MAGIC = 0xA1B2C3D4  # little-endian
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_SNAPLEN = 65535
PCAP_LINK_TYPE = 1  # Ethernet

# IP + TCP layer base sizes
ETH_HEADER_LEN = 14
IP_HEADER_LEN = 20
TCP_HEADER_LEN = 20


def pcap_global_header() -> bytes:
    """Write global PCAP header (little-endian)."""
    return struct.pack(
        "<IHHiIII",
        PCAP_MAGIC,
        PCAP_VERSION_MAJOR,
        PCAP_VERSION_MINOR,
        0,          # thiszone (GMT)
        0,          # sigfigs
        PCAP_SNAPLEN,
        PCAP_LINK_TYPE,
    )


def pcap_packet_header(ts: float, pkt_len: int) -> bytes:
    """Write a PCAP packet record header."""
    ts_sec = int(ts)
    ts_usec = int((ts - ts_sec) * 1_000_000)
    return struct.pack("<IIII", ts_sec, ts_usec, pkt_len, pkt_len)


def ip_to_bytes(ip_str: str) -> bytes:
    parts = [int(x) for x in ip_str.split(".")]
    return bytes(parts)


def checksum(data: bytes) -> int:
    """Compute the 16-bit one's-complement checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def modbus_read_request(unit_id: int = 1, fc: int = 4, start_addr: int = 0, count: int = 7) -> bytes:
    """Build a Modbus TCP request PDU."""
    transaction_id = 1
    protocol_id = 0
    length = 6
    pdu = struct.pack(">HHHBBHH",
                      transaction_id, protocol_id, length,
                      unit_id, fc, start_addr, count)
    return pdu


def build_tcp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    """
    Build a minimal Ethernet + IP + TCP frame.
    Uses hardcoded MACs and minimal TCP (no options, seq/ack=0).
    """
    # Ethernet header (src_mac → dst_mac, type=IP)
    src_mac = b"\x02\x42\xac\x14\x00\x28"  # 02:42:ac:14:00:28 (172.20.0.40 style)
    dst_mac = b"\x02\x42\xac\x14\x00\x0b"  # 02:42:ac:14:00:11
    eth_type = b"\x08\x00"                  # IPv4
    eth_header = src_mac + dst_mac + eth_type

    # IP header
    src_bytes = ip_to_bytes(src_ip)
    dst_bytes = ip_to_bytes(dst_ip)
    total_length = IP_HEADER_LEN + TCP_HEADER_LEN + len(payload)
    ip_header = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,           # version + IHL
        0,              # DSCP
        total_length,
        1,              # identification
        0x4000,         # flags + fragment offset (DF set)
        64,             # TTL
        6,              # protocol TCP
        0,              # checksum placeholder
        src_bytes,
        dst_bytes,
    )
    ip_checksum = checksum(ip_header)
    ip_header = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, total_length, 1, 0x4000, 64, 6,
        ip_checksum,
        src_bytes,
        dst_bytes,
    )

    # TCP header (minimal, data offset = 5 * 4 = 20 bytes, flags = PSH+ACK)
    tcp_header = struct.pack(
        ">HHIIBBHHH",
        src_port,
        dst_port,
        0,      # seq
        0,      # ack
        0x50,   # data offset (5 << 4)
        0x18,   # flags: PSH + ACK
        65535,  # window
        0,      # checksum placeholder
        0,      # urgent pointer
    )
    pseudo_header = (
        src_bytes
        + dst_bytes
        + b"\x00\x06"
        + struct.pack("!H", TCP_HEADER_LEN + len(payload))
    )
    tcp_checksum = checksum(pseudo_header + tcp_header + payload)
    tcp_header = struct.pack(
        ">HHIIBBHHH",
        src_port,
        dst_port,
        0,
        0,
        0x50,
        0x18,
        65535,
        tcp_checksum,
        0,
    )

    return eth_header + ip_header + tcp_header + payload


def write_pcap(path: str, packets: list) -> None:
    """Write packets list [(ts_float, bytes)] to PCAP file."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "wb") as f:
        f.write(pcap_global_header())
        for ts, pkt in packets:
            hdr = pcap_packet_header(ts, len(pkt))
            f.write(hdr + pkt)


def generate_baseline_pcap(output_path: str, n_packets: int = 100) -> None:
    """
    Generate synthetic normal SCADA polling PCAP.
    FUXA HMI (172.20.0.40) polls each inverter (172.20.0.11-13) and PLC (172.20.0.20).
    """
    packets = []
    hmi_ip = "172.20.0.40"
    targets = [
        ("172.20.0.11", "inverter1"),
        ("172.20.0.12", "inverter2"),
        ("172.20.0.13", "inverter3"),
        ("172.20.0.20", "openplc"),
    ]

    base_ts = time.time() - 300   # 5 minutes ago
    ts = base_ts
    src_port_base = 50000

    for i in range(n_packets):
        target_ip, target_name = targets[i % len(targets)]
        fc = 4 if "inverter" in target_name else 3
        start_addr = 0
        count = 7 if fc == 4 else 3

        payload = modbus_read_request(unit_id=1, fc=fc, start_addr=start_addr, count=count)
        pkt = build_tcp_packet(
            src_ip=hmi_ip,
            dst_ip=target_ip,
            src_port=src_port_base + (i % 100),
            dst_port=502,
            payload=payload,
        )
        packets.append((ts, pkt))
        ts += 2.5   # poll every ~2.5 seconds

    write_pcap(output_path, packets)
    print(f"[generate_test_pcap] Wrote {len(packets)} packets to {output_path}")


if __name__ == "__main__":
    output = sys.argv[1] if len(sys.argv) > 1 else "/pcaps/normal_baseline.pcap"
    generate_baseline_pcap(output)
    sys.exit(0)
