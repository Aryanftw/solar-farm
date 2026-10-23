"""
Unit tests — Zeek Modbus log forwarder
Validates parsing of Zeek's built-in modbus.log and ICSNPP modbus_detailed.log.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../services/sensor"))

from log_forwarder import (  # noqa: E402
    ZeekModbusParser,
    merge_and_dedupe,
    normalise_record,
)


BASIC_HEADER = (
    "#separator \\x09\n"
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\t"
    "tid\tunit\tfunc\tpdu_type\texception\n"
)
BASIC_WRITE = (
    "1700000000.000000\tC1\t172.20.0.40\t50001\t172.20.0.11\t502\t"
    "7\t1\tWRITE_SINGLE_REGISTER\tREQ\t-\n"
)
BASIC_RESPONSE = (
    "1700000000.010000\tC1\t172.20.0.40\t50001\t172.20.0.11\t502\t"
    "7\t1\tWRITE_SINGLE_REGISTER\tRESP\t-\n"
)

DETAILED_HEADER = (
    "#separator \\x09\n"
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\t"
    "tid\tunit\tfunc\taddress\tquantity\trequest_values\tresponse_values\n"
)
DETAILED_WRITE = (
    "1700000000.000000\tC1\t172.20.0.40\t50001\t172.20.0.11\t502\t"
    "7\t1\tWRITE_SINGLE_REGISTER\t0\t1\t1000\t-\n"
)


def parse_all(text: str) -> list:
    parser = ZeekModbusParser()
    events = []
    for line in text.splitlines():
        event = parser.parse_line(line)
        if event:
            events.append(event)
    return events


def test_basic_modbus_log_uses_header_field_order():
    """Regression: func is column 8 in Zeek's modbus.log, not column 6."""
    events = parse_all(BASIC_HEADER + BASIC_WRITE)
    assert len(events) == 1
    event = events[0]
    assert event["id_orig_h"] == "172.20.0.40"
    assert event["id_resp_h"] == "172.20.0.11"
    assert event["id_resp_p"] == 502
    assert event["function_code"] == 6
    assert event["func"] == "WRITE_SINGLE_REGISTER"


def test_basic_modbus_log_filters_responses():
    events = parse_all(BASIC_HEADER + BASIC_RESPONSE)
    assert events == []


def test_detailed_log_extracts_address_and_value():
    events = parse_all(DETAILED_HEADER + DETAILED_WRITE)
    assert len(events) == 1
    event = events[0]
    assert event["register"] == 0
    assert event["value"] == 1000
    assert event["function_code"] == 6


def test_merge_basic_and_detailed_records():
    basic = parse_all(BASIC_HEADER + BASIC_WRITE)
    detailed = parse_all(DETAILED_HEADER + DETAILED_WRITE)
    merged = merge_and_dedupe(basic + detailed)
    assert len(merged) == 1
    assert merged[0]["function_code"] == 6
    assert merged[0]["register"] == 0
    assert merged[0]["value"] == 1000


def test_track_address_is_used_when_present():
    header = (
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\t"
        "tid\tunit\tfunc\tpdu_type\texception\ttrack_address\n"
    )
    line = (
        "1700000000.000000\tC1\t172.20.0.40\t50001\t172.20.0.11\t502\t"
        "8\t1\tREAD_HOLDING_REGISTERS\tREQ\t-\t1\n"
    )
    events = parse_all(header + line)
    assert len(events) == 1
    assert events[0]["function_code"] == 3
    assert events[0]["register"] == 1


def test_vector_request_values():
    record = {
        "ts": "1700000000.0",
        "uid": "C2",
        "id.orig_h": "172.20.0.99",
        "id.orig_p": "40000",
        "id.resp_h": "172.20.0.12",
        "id.resp_p": "502",
        "tid": "9",
        "func": "WRITE_MULTIPLE_REGISTERS",
        "address": "2",
        "request_values": "100,200,300",
    }
    event = normalise_record(record)
    assert event is not None
    assert event["function_code"] == 16
    assert event["register"] == 2
    assert event["value"] == 100


def test_numeric_and_hex_function_codes():
    for raw, expected in (("6", 6), ("0x06", 6), ("0x10", 16), ("16", 16)):
        record = {
            "ts": "1700000000.0",
            "uid": "C3",
            "id.orig_h": "172.20.0.40",
            "id.orig_p": "50000",
            "id.resp_h": "172.20.0.11",
            "id.resp_p": "502",
            "tid": "1",
            "func": raw,
        }
        event = normalise_record(record)
        assert event is not None
        assert event["function_code"] == expected


def test_true_source_destination_fields():
    record = {
        "ts": "1700000000.0",
        "uid": "C4",
        "id.orig_h": "172.20.0.11",
        "id.orig_p": "502",
        "id.resp_h": "172.20.0.40",
        "id.resp_p": "50001",
        "is_orig": "T",
        "source_h": "172.20.0.40",
        "source_p": "50001",
        "destination_h": "172.20.0.11",
        "destination_p": "502",
        "tid": "2",
        "func": "READ_INPUT_REGISTERS",
    }
    event = normalise_record(record)
    assert event is not None
    assert event["id_orig_h"] == "172.20.0.40"
    assert event["id_resp_h"] == "172.20.0.11"


def test_response_direction_via_is_orig_false():
    record = {
        "ts": "1700000000.0",
        "uid": "C5",
        "id.orig_h": "172.20.0.40",
        "id.orig_p": "50001",
        "id.resp_h": "172.20.0.11",
        "id.resp_p": "502",
        "is_orig": "F",
        "source_h": "172.20.0.11",
        "source_p": "502",
        "destination_h": "172.20.0.40",
        "destination_p": "50001",
        "tid": "3",
        "func": "READ_INPUT_REGISTERS",
    }
    assert normalise_record(record) is None


def test_unknown_function_is_ignored():
    record = {
        "ts": "1700000000.0",
        "uid": "C6",
        "id.orig_h": "172.20.0.40",
        "id.orig_p": "50000",
        "id.resp_h": "172.20.0.11",
        "id.resp_p": "502",
        "tid": "1",
        "func": "NOT_A_MODBUS_FUNCTION",
    }
    assert normalise_record(record) is None


def test_missing_timestamp_is_ignored():
    record = {
        "uid": "C7",
        "id.orig_h": "172.20.0.40",
        "id.orig_p": "50000",
        "id.resp_h": "172.20.0.11",
        "id.resp_p": "502",
        "func": "READ_INPUT_REGISTERS",
    }
    assert normalise_record(record) is None
