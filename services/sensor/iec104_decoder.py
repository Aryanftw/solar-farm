"""
IEC 60870-5-104 APDU & ASDU Protocol Decoder.
Provides offline and streaming byte-level decoding for IEC-104 telemetry and commands.

Handles:
- APCI Transport framing: I-Format (Information), S-Format (Supervisory), U-Format (Control).
- ASDU Application units:
  * Control commands: C_SC_NA_1 (45), C_DC_NA_1 (46), C_RC_NA_1 (47),
                      C_SE_NA_1 (48), C_SE_NB_1 (49), C_SE_NC_1 (50), C_BO_NA_1 (51)
  * Interrogation:    C_IC_NA_1 (100)
  * Measurements:     M_SP_NA_1 (1), M_DP_NA_1 (3), M_ME_NA_1 (9),
                      M_ME_NB_1 (11), M_ME_NC_1 (13)
- Safe error handling for truncated, malformed, or invalid APDUs.
"""

import struct
from typing import Optional, Dict, Any, Tuple

# Start byte for IEC 60870-5-104
START_BYTE = 0x68

# ASDU Type Identification mappings
ASDU_TYPES: Dict[int, str] = {
    1: "M_SP_NA_1",    # Single-point information
    3: "M_DP_NA_1",    # Double-point information
    9: "M_ME_NA_1",    # Measured value, normalized
    11: "M_ME_NB_1",   # Measured value, scaled
    13: "M_ME_NC_1",   # Measured value, short floating point
    45: "C_SC_NA_1",   # Single command
    46: "C_DC_NA_1",   # Double command
    47: "C_RC_NA_1",   # Regulating step command
    48: "C_SE_NA_1",   # Set-point command, normalized value
    49: "C_SE_NB_1",   # Set-point command, scaled value
    50: "C_SE_NC_1",   # Set-point command, short floating point
    51: "C_BO_NA_1",   # Bitstring of 32 bit command
    100: "C_IC_NA_1",  # Interrogation command
}

# Reverse mapping for fixture building
TYPE_BY_NAME = {v: k for k, v in ASDU_TYPES.items()}

# Set of control ASDU types
CONTROL_TYPES = {
    "C_SC_NA_1", "C_DC_NA_1", "C_RC_NA_1",
    "C_SE_NA_1", "C_SE_NB_1", "C_SE_NC_1", "C_BO_NA_1",
}


class IEC104DecodeError(Exception):
    """Raised when an IEC-104 frame cannot be decoded."""
    pass


def decode_iec104_apdu(data: bytes) -> Dict[str, Any]:
    """
    Decode a raw IEC 60870-5-104 APDU byte sequence into a structured dictionary.

    Args:
        data: Raw bytes starting at the 0x68 start byte.

    Returns:
        Dictionary containing frame format, sequence numbers, and decoded ASDU if present.

    Raises:
        IEC104DecodeError: If data is too short, start byte is invalid, or length mismatch.
    """
    if len(data) < 6:
        raise IEC104DecodeError(f"Frame too short ({len(data)} bytes, min 6)")

    start, length = data[0], data[1]
    if start != START_BYTE:
        raise IEC104DecodeError(f"Invalid start byte: 0x{start:02X} (expected 0x68)")

    if len(data) < 2 + length:
        raise IEC104DecodeError(f"Truncated frame: declared {length} APDU bytes, got {len(data)-2}")

    apci = data[2:6]
    first_byte = apci[0]

    # Format classification:
    # Bit 0 == 0 -> I-format
    # Bit 0 == 1 and Bit 1 == 0 -> S-format
    # Bit 0 == 1 and Bit 1 == 1 -> U-format
    if (first_byte & 0x01) == 0:
        apci_format = "I"
        tx_seq = ((apci[1] << 8) | (first_byte & 0xFE)) >> 1
        rx_seq = ((apci[3] << 8) | (apci[2] & 0xFE)) >> 1
        result: Dict[str, Any] = {
            "apci_format": "I",
            "tx_seq": tx_seq,
            "rx_seq": rx_seq,
            "length": length,
        }

        # If length > 4, there is an ASDU payload
        asdu_data = data[6 : 2 + length]
        if asdu_data:
            asdu_info = decode_asdu(asdu_data)
            result.update(asdu_info)

        return result

    elif (first_byte & 0x03) == 0x01:
        rx_seq = ((apci[3] << 8) | (apci[2] & 0xFE)) >> 1
        return {
            "apci_format": "S",
            "rx_seq": rx_seq,
            "length": length,
        }

    else:  # U-format
        u_types = {
            0x07: "STARTDT_ACT",
            0x0B: "STARTDT_CON",
            0x13: "STOPDT_ACT",
            0x23: "STOPDT_CON",
            0x43: "TESTFR_ACT",
            0x83: "TESTFR_CON",
        }
        u_func = u_types.get(first_byte, f"U_UNKNOWN_0x{first_byte:02X}")
        return {
            "apci_format": "U",
            "u_type": u_func,
            "length": length,
        }


def decode_asdu(data: bytes) -> Dict[str, Any]:
    """
    Decode an ASDU payload (header + information objects).
    """
    if len(data) < 6:
        raise IEC104DecodeError(f"ASDU payload too short ({len(data)} bytes, min 6)")

    type_id = data[0]
    type_name = ASDU_TYPES.get(type_id, f"UNKNOWN_TYPE_{type_id}")
    vsq = data[1]
    num_objects = vsq & 0x7F
    is_sequence = bool(vsq & 0x80)

    # Cause of transmission (2 bytes: COT + Originator address)
    cot = data[2]
    orig_addr = data[3]

    # Common Address of ASDU (2 bytes, little-endian)
    common_address = struct.unpack("<H", data[4:6])[0]

    result: Dict[str, Any] = {
        "asdu_type": type_name,
        "asdu_type_id": type_id,
        "is_control_command": type_name in CONTROL_TYPES,
        "num_objects": num_objects,
        "is_sequence": is_sequence,
        "cot": cot,
        "originator_address": orig_addr,
        "common_address": common_address,
    }

    # Extract first information object if present (min 3 bytes for IOA)
    io_data = data[6:]
    if len(io_data) >= 3:
        # IOA is 3 bytes, little-endian
        ioa = io_data[0] | (io_data[1] << 8) | (io_data[2] << 16)
        result["ioa"] = ioa
        val_bytes = io_data[3:]

        # Decode value depending on ASDU type
        if type_name == "C_SC_NA_1" and len(val_bytes) >= 1:
            # Single command: bit 0 is state (0/1), bit 7 is select/execute
            sco = val_bytes[0]
            result["command_state"] = sco & 0x01
            result["select_execute"] = "select" if (sco & 0x80) else "execute"
            result["value"] = str(sco & 0x01)

        elif type_name == "C_SE_NC_1" and len(val_bytes) >= 4:
            # Short float value
            val = struct.unpack("<f", val_bytes[0:4])[0]
            result["value"] = round(val, 4)

        elif type_name == "M_ME_NC_1" and len(val_bytes) >= 4:
            # Measured short float
            val = struct.unpack("<f", val_bytes[0:4])[0]
            result["value"] = round(val, 4)

        elif type_name == "C_IC_NA_1" and len(val_bytes) >= 1:
            # Qualifier of interrogation (QOI): 20 = Station interrogation
            result["qoi"] = val_bytes[0]
            result["value"] = f"QOI={val_bytes[0]}"

    return result


def build_c_sc_na_1(common_address: int, ioa: int, state: int, tx_seq: int = 0, rx_seq: int = 0) -> bytes:
    """Helper to build a valid IEC-104 Single Command (C_SC_NA_1, Type 45) APDU."""
    apci = bytearray(4)
    apci[0] = (tx_seq << 1) & 0xFE
    apci[1] = (tx_seq >> 7) & 0xFF
    apci[2] = (rx_seq << 1) & 0xFE
    apci[3] = (rx_seq >> 7) & 0xFF

    asdu = bytearray()
    asdu.append(45)                # Type 45 C_SC_NA_1
    asdu.append(1)                 # VSQ: 1 object
    asdu.append(6)                 # COT: 6 (Activation)
    asdu.append(0)                 # Originator address: 0
    asdu.extend(struct.pack("<H", common_address))  # Common Address (2 bytes)

    # Information Object (IOA 3 bytes + SCO 1 byte)
    asdu.append(ioa & 0xFF)
    asdu.append((ioa >> 8) & 0xFF)
    asdu.append((ioa >> 16) & 0xFF)
    asdu.append(state & 0x01)      # Single Command: ON (1) or OFF (0)

    apdu_len = len(apci) + len(asdu)
    header = bytes([START_BYTE, apdu_len])
    return header + bytes(apci) + bytes(asdu)


def build_c_se_nc_1(common_address: int, ioa: int, float_val: float, tx_seq: int = 0, rx_seq: int = 0) -> bytes:
    """Helper to build a valid IEC-104 Float Setpoint Command (C_SE_NC_1, Type 50) APDU."""
    apci = bytearray(4)
    apci[0] = (tx_seq << 1) & 0xFE
    apci[1] = (tx_seq >> 7) & 0xFF
    apci[2] = (rx_seq << 1) & 0xFE
    apci[3] = (rx_seq >> 7) & 0xFF

    asdu = bytearray()
    asdu.append(50)                # Type 50 C_SE_NC_1
    asdu.append(1)                 # VSQ: 1 object
    asdu.append(6)                 # COT: 6 (Activation)
    asdu.append(0)                 # Originator
    asdu.extend(struct.pack("<H", common_address))

    # IOA (3 bytes) + Float (4 bytes) + QOS (1 byte)
    asdu.append(ioa & 0xFF)
    asdu.append((ioa >> 8) & 0xFF)
    asdu.append((ioa >> 16) & 0xFF)
    asdu.extend(struct.pack("<f", float_val))
    asdu.append(0)                 # QOS

    apdu_len = len(apci) + len(asdu)
    header = bytes([START_BYTE, apdu_len])
    return header + bytes(apci) + bytes(asdu)


def build_m_me_nc_1(common_address: int, ioa: int, float_val: float, tx_seq: int = 0, rx_seq: int = 0) -> bytes:
    """Helper to build an IEC-104 Float Measurement (M_ME_NC_1, Type 13) APDU."""
    apci = bytearray(4)
    apci[0] = (tx_seq << 1) & 0xFE
    apci[1] = (tx_seq >> 7) & 0xFF
    apci[2] = (rx_seq << 1) & 0xFE
    apci[3] = (rx_seq >> 7) & 0xFF

    asdu = bytearray()
    asdu.append(13)                # Type 13 M_ME_NC_1
    asdu.append(1)                 # VSQ: 1 object
    asdu.append(3)                 # COT: 3 (Spontaneous)
    asdu.append(0)                 # Originator
    asdu.extend(struct.pack("<H", common_address))

    # IOA (3 bytes) + Float (4 bytes) + QDS (1 byte)
    asdu.append(ioa & 0xFF)
    asdu.append((ioa >> 8) & 0xFF)
    asdu.append((ioa >> 16) & 0xFF)
    asdu.extend(struct.pack("<f", float_val))
    asdu.append(0)                 # Quality Descriptor: valid (0)

    apdu_len = len(apci) + len(asdu)
    header = bytes([START_BYTE, apdu_len])
    return header + bytes(apci) + bytes(asdu)
