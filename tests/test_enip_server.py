from __future__ import annotations

import socket
import struct
import time
from typing import Tuple

import pytest

from pycipsim.runtime.enip_server import ConnectionManager, ENIPServer

_ENCAP = struct.Struct("<HHII8sI")


@pytest.fixture
def enip_server() -> ENIPServer:
    server = ENIPServer(
        host="127.0.0.1",
        tcp_port=0,
        udp_port=0,
        connection_manager=ConnectionManager(default_timeout=1.0),
        reaper_interval=0.05,
    )
    server.start()
    try:
        yield server
    finally:
        server.stop()


def _send_enip(sock: socket.socket, command: int, session: int, payload: bytes = b"") -> None:
    context = b"CTXMSG00"
    header = _ENCAP.pack(command, len(payload), session, 0, context, 0)
    sock.sendall(header + payload)


def _recv_enip(sock: socket.socket) -> Tuple[int, int, int, bytes]:
    header = _recv_exact(sock, _ENCAP.size)
    command, length, session, status, _context, _options = _ENCAP.unpack(header)
    payload = _recv_exact(sock, length)
    return command, session, status, payload


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise RuntimeError("socket closed before receiving expected data")
        data.extend(chunk)
    return bytes(data)


def _make_forward_open_request(*, timeout_multiplier: int = 0) -> bytes:
    service = 0x54
    path = b"\x20\x06\x24\x01"
    path_words = len(path) // 2
    priority = 0x0A
    timeout_ticks = 0x0A
    o_to_t_conn = 0
    t_to_o_conn = 0
    connection_serial = 0x4321
    vendor_id = 0x1337
    originator_serial = 0x12345678
    timeout_multiplier = timeout_multiplier
    o_to_t_rpi = 100_000
    o_to_t_network = struct.pack("<H", 0x2208)
    t_to_o_rpi = 100_000
    t_to_o_network = struct.pack("<H", 0x2208)
    transport_trigger = 0x01
    connection_path = b""
    connection_path_size = len(connection_path) // 2
    request = bytearray()
    request.append(service)
    request.append(path_words)
    request.extend(path)
    request.append(priority)
    request.append(timeout_ticks)
    request.extend(struct.pack("<I", o_to_t_conn))
    request.extend(struct.pack("<I", t_to_o_conn))
    request.extend(struct.pack("<H", connection_serial))
    request.extend(struct.pack("<H", vendor_id))
    request.extend(struct.pack("<I", originator_serial))
    request.append(timeout_multiplier)
    request.extend(b"\x00\x00\x00")
    request.extend(struct.pack("<I", o_to_t_rpi))
    request.extend(o_to_t_network)
    request.extend(struct.pack("<I", t_to_o_rpi))
    request.extend(t_to_o_network)
    request.append(transport_trigger)
    request.append(connection_path_size)
    request.extend(connection_path)
    interface_handle = 0
    timeout = 0
    item_count = 2
    envelope = bytearray(struct.pack("<IHH", interface_handle, timeout, item_count))
    envelope.extend(struct.pack("<HH", 0x0000, 0))
    envelope.extend(struct.pack("<HH", 0x00B2, len(request)))
    envelope.extend(request)
    return bytes(envelope)


def test_enip_server_accepts_forward_open(enip_server: ENIPServer) -> None:
    sock = socket.create_connection(("127.0.0.1", enip_server.tcp_port))
    sock.settimeout(1.0)
    with sock:
        _send_enip(sock, 0x0065, 0, struct.pack("<HH", 1, 0))
        command, session, status, payload = _recv_enip(sock)
        assert command == 0x0065
        assert session != 0
        assert status == 0
        assert payload == struct.pack("<HH", 1, 0)

        list_identity_payload = b""
        _send_enip(sock, 0x0063, session, list_identity_payload)
        command, _, status, payload = _recv_enip(sock)
        assert command == 0x0063
        assert status == 0
        assert payload.endswith(b"PyCIPSim\x03")

        forward_open = _make_forward_open_request()
        _send_enip(sock, 0x006F, session, forward_open)
        command, _, status, payload = _recv_enip(sock)
        assert command == 0x006F
        assert status == 0
        _, _, item_count = struct.unpack_from("<IHH", payload, 0)
        assert item_count == 2
        item_type, item_len = struct.unpack_from("<HH", payload, 8)
        assert item_type == 0x0000
        assert item_len == 0
        item_type, item_len = struct.unpack_from("<HH", payload, 12)
        assert item_type == 0x00B2
        cip = payload[16 : 16 + item_len]
        assert cip[0] == 0xD4
        assert cip[1] == 0x00
        assert cip[2] == 0x00
        o_to_t_conn = struct.unpack_from("<I", cip, 3)[0]
        t_to_o_conn = struct.unpack_from("<I", cip, 7)[0]
        assert o_to_t_conn != 0
        assert t_to_o_conn != 0
    connections = enip_server.connection_manager.active_connections()
    assert len(connections) == 1
    assert connections[0].connection_serial == 0x4321


def test_enip_server_connection_timeout() -> None:
    manager = ConnectionManager(default_timeout=0.2)
    server = ENIPServer(
        host="127.0.0.1",
        tcp_port=0,
        udp_port=0,
        connection_manager=manager,
        reaper_interval=0.05,
    )
    server.start()
    try:
        sock = socket.create_connection(("127.0.0.1", server.tcp_port))
        sock.settimeout(1.0)
        with sock:
            _send_enip(sock, 0x0065, 0, struct.pack("<HH", 1, 0))
            _, session, _, _ = _recv_enip(sock)
            _send_enip(sock, 0x006F, session, _make_forward_open_request(timeout_multiplier=0))
            _recv_enip(sock)
        time.sleep(0.6)
        for _ in range(10):
            if not manager.active_connections():
                break
            time.sleep(0.05)
        assert not manager.active_connections()
    finally:
        server.stop()
