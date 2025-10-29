"""Lightweight UDP protocol helpers for PyCIPSim target role."""
from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import ClassVar

PROTOCOL_VERSION: int = 1

MSG_HELLO: int = 0x01
MSG_HELLO_ACK: int = 0x02
MSG_GET: int = 0x10
MSG_DATA: int = 0x11
MSG_SET: int = 0x12
MSG_ACK: int = 0x13
MSG_ERROR: int = 0x7F


@dataclass(slots=True)
class TargetMessage:
    """Representation of a decoded PyCIPSim target datagram."""

    message_type: int
    assembly_id: int
    payload: bytes

    _HEADER: ClassVar[struct.Struct] = struct.Struct("!BBHI")

    @classmethod
    def decode(cls, data: bytes) -> "TargetMessage":
        if len(data) < cls._HEADER.size:
            raise ValueError("Datagram too small for PyCIPSim header")
        version, message_type, payload_size, assembly_id = cls._HEADER.unpack_from(data)
        if version != PROTOCOL_VERSION:
            raise ValueError(f"Unsupported protocol version {version}")
        expected_end = cls._HEADER.size + payload_size
        if len(data) < expected_end:
            raise ValueError("Datagram payload truncated")
        payload = data[cls._HEADER.size : expected_end]
        return cls(message_type=message_type, assembly_id=assembly_id, payload=payload)

    @classmethod
    def encode(cls, message_type: int, *, assembly_id: int = 0, payload: bytes | None = None) -> bytes:
        body = payload or b""
        if len(body) > 0xFFFF:
            raise ValueError("Payload too large for PyCIPSim datagram")
        header = cls._HEADER.pack(PROTOCOL_VERSION, message_type, len(body), assembly_id)
        return header + body


__all__ = [
    "MSG_ACK",
    "MSG_DATA",
    "MSG_ERROR",
    "MSG_GET",
    "MSG_HELLO",
    "MSG_HELLO_ACK",
    "MSG_SET",
    "PROTOCOL_VERSION",
    "TargetMessage",
]
