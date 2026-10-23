"""
Unit tests — synthetic PCAP generator
Ensures replay traffic has valid IP/TCP checksums and a readable PCAP header.
"""

import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../services/sensor"))

from generate_test_pcap import (  # noqa: E402
    ETH_HEADER_LEN,
    IP_HEADER_LEN,
    TCP_HEADER_LEN,
    build_tcp_packet,
    checksum,
    generate_baseline_pcap,
    modbus_read_request,
)


def test_ip_and_tcp_checksums_are_valid():
    payload = modbus_read_request(unit_id=1, fc=4, start_addr=0, count=7)
    packet = build_tcp_packet(
        src_ip="172.20.0.40",
        dst_ip="172.20.0.11",
        src_port=50000,
        dst_port=502,
        payload=payload,
    )

    ip_header = packet[ETH_HEADER_LEN:ETH_HEADER_LEN + IP_HEADER_LEN]
    assert checksum(ip_header) == 0

    tcp_header = packet[
        ETH_HEADER_LEN + IP_HEADER_LEN:
        ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN
    ]
    src_ip = ip_header[12:16]
    dst_ip = ip_header[16:20]
    pseudo = src_ip + dst_ip + b"\x00\x06" + struct.pack("!H", len(tcp_header) + len(payload))
    assert checksum(pseudo + tcp_header + payload) == 0


def test_generated_pcap_has_global_header_and_packets():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "baseline.pcap")
        generate_baseline_pcap(path, n_packets=4)
        data = open(path, "rb").read()

    assert len(data) > 24
    magic, major, minor = struct.unpack("<IHH", data[:8])
    assert magic == 0xA1B2C3D4
    assert (major, minor) == (2, 4)
