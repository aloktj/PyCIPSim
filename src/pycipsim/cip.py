"""Common Industrial Protocol metadata and helper utilities."""
from __future__ import annotations

from typing import Dict, List, Tuple, Union

__all__ = [
    "SEGMENT_TYPES",
    "KNOWN_CLASSES",
    "SERVICE_CODES",
    "ERROR_CODES",
    "decode_path",
    "format_path",
    "describe_service",
    "describe_error",
    "resolve_service_code",
]


# Logical segment types extracted from publicly documented CIP dissectors.
SEGMENT_TYPES: Dict[int, str] = {
    0: "class",
    1: "instance",
    2: "element",
    3: "connection_point",
    4: "attribute",
}


# Frequently encountered object class identifiers.
KNOWN_CLASSES: Dict[int, str] = {
    0x01: "Identity",
    0x02: "Message Router",
    0x04: "Assembly",
    0x06: "Connection Manager",
    0x6B: "Symbol",
    0x6C: "Template",
}


# CIP service codes mapped to their canonical names.
SERVICE_CODES: Dict[int, str] = {
    0x01: "Get_Attribute_All",
    0x02: "Set_Attribute_All",
    0x03: "Get_Attribute_List",
    0x04: "Set_Attribute_List",
    0x05: "Reset",
    0x06: "Start",
    0x07: "Stop",
    0x08: "Create",
    0x09: "Delete",
    0x0A: "Multiple_Service_Packet",
    0x0D: "Apply_Attributes",
    0x0E: "Get_Attribute_Single",
    0x10: "Set_Attribute_Single",
    0x4B: "Execute_PCCC_Service",
    0x4C: "Read_Tag_Service",
    0x4D: "Write_Tag_Service",
    0x4E: "Read_Modify_Write_Tag_Service",
    0x4F: "Read_Other_Tag_Service",
    0x52: "Read_Tag_Fragmented_Service",
    0x53: "Write_Tag_Fragmented_Service",
    0x54: "Forward_Open",
}


# CIP general status codes to human readable messages.
ERROR_CODES: Dict[int, str] = {
    0x00: "Success",
    0x01: "Connection failure",
    0x02: "Resource unavailable",
    0x03: "Invalid parameter value",
    0x04: "Path segment error",
    0x05: "Path destination unknown",
    0x06: "Partial transfer",
    0x07: "Connection lost",
    0x08: "Service not supported",
    0x09: "Invalid attribute value",
    0x0A: "Attribute list error",
    0x0B: "Already in requested mode/state",
    0x0C: "Object state conflict",
    0x0D: "Object already exists",
    0x0E: "Attribute not settable",
    0x0F: "Privilege violation",
    0x10: "Device state conflict",
    0x11: "Reply data too large",
    0x12: "Fragmentation of a primitive value",
    0x13: "Not enough data",
    0x14: "Attribute not supported",
    0x15: "Too much data",
    0x16: "Object does not exist",
    0x17: "Service fragmentation sequence not in progress",
    0x18: "No stored attribute data",
    0x19: "Store operation failure",
    0x1A: "Routing failure, request packet too large",
    0x1B: "Routing failure, response packet too large",
    0x1C: "Missing attribute list entry data",
    0x1D: "Invalid attribute value list",
    0x1E: "Embedded service error",
    0x1F: "Vendor specific error",
    0x20: "Invalid parameter",
    0x21: "Write-once value or medium already written",
    0x22: "Invalid reply received",
    0x23: "Buffer overflow",
    0x24: "Invalid message format",
    0x25: "Key failure in path",
    0x26: "Path size invalid",
    0x27: "Unexpected attribute in list",
    0x28: "Invalid Member ID",
    0x29: "Member not settable",
    0x2A: "Group 2 only server general failure",
    0x2B: "Unknown Modbus error",
    0x2C: "Attribute not gettable",
}


_SERVICE_NAME_INDEX: Dict[str, int] = {
    name.lower(): code for code, name in SERVICE_CODES.items()
}


def decode_path(path: bytes) -> List[Tuple[str, Union[int, str]]]:
    """Decode a raw CIP path into logical segment tuples."""

    result: List[Tuple[str, Union[int, str]]] = []
    data = memoryview(path)
    index = 0
    length = len(data)
    while index < length:
        header = data[index]
        index += 1

        if header == 0x91:  # ANSI extended symbolic segment
            if index >= length:
                break
            string_len = data[index]
            index += 1
            raw = bytes(data[index : index + string_len])
            index += string_len
            if string_len % 2:
                index += 1  # padding to word boundary
            try:
                text = raw.decode("ascii", errors="ignore")
            except Exception:  # pragma: no cover - defensive
                text = raw.decode("latin1", errors="ignore")
            result.append(("symbolic", text.rstrip("\x00")))
            continue

        segment_type = (header >> 2) & 0x07
        segment_name = SEGMENT_TYPES.get(segment_type, f"segment_{segment_type}")
        segment_format = header & 0x03

        if segment_format == 0:
            if index >= length:
                break
            value = int(data[index])
            index += 1
        elif segment_format == 1:
            if index + 2 > length:
                break
            # 16-bit segments include a padding byte for alignment.
            padding = data[index]
            index += 1
            value = int.from_bytes(data[index : index + 2], "little")
            index += 2
            if padding not in (0x00, 0x01):  # pragma: no cover - defensive
                index += padding
        elif segment_format == 2:
            # 32-bit logical segments are rare; align to the next 32-bit boundary.
            alignment = index % 4
            if alignment:
                index += 4 - alignment
            if index + 4 > length:
                break
            value = int.from_bytes(data[index : index + 4], "little")
            index += 4
        else:  # pragma: no cover - reserved formats
            break

        result.append((segment_name, value))

    return result


def format_path(path: bytes) -> str:
    """Return a human readable description of a CIP path."""

    parts: List[str] = []
    for segment_type, value in decode_path(path):
        if segment_type == "symbolic":
            parts.append(f"symbolic({value})")
            continue
        if isinstance(value, int):
            label = KNOWN_CLASSES.get(value) if segment_type == "class" else None
            if label:
                parts.append(f"{segment_type} 0x{value:02X} ({label})")
            else:
                parts.append(f"{segment_type} 0x{value:02X}")
        else:
            parts.append(f"{segment_type} {value}")
    return ", ".join(parts)


def describe_service(code: int) -> str:
    """Return the canonical name for a CIP service code."""

    return SERVICE_CODES.get(code & 0xFF, f"0x{code & 0xFF:02X}")


def describe_error(code: int) -> str:
    """Return the friendly description for a CIP general status code."""

    return ERROR_CODES.get(code & 0xFF, f"0x{code & 0xFF:02X}")


def resolve_service_code(value: Union[int, str]) -> int:
    """Resolve a service identifier to its numeric code."""

    if isinstance(value, int):
        return value & 0xFF

    text = str(value).strip()
    if not text:
        raise ValueError("CIP service code cannot be empty.")

    try:
        return int(text, 0) & 0xFF
    except ValueError:
        normalized = text.lower().replace(" ", "_").replace("-", "_")
        if normalized in _SERVICE_NAME_INDEX:
            return _SERVICE_NAME_INDEX[normalized]
        raise ValueError(f"Unknown CIP service code '{value}'.")

