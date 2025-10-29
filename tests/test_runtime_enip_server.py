import copy
import socket
import struct
import time

import pytest

from pycipsim.configuration import AssemblyDefinition, SignalDefinition, build_assembly_payload
from pycipsim.runtime import AssemblyHost, ConnectionManager, ENIPServer

_ENCAP = struct.Struct("<HHII8sI")
_ADDRESS_ITEM_CONNECTED = 0x00A1
_DATA_ITEM_CONNECTED = 0x00B1
_SEND_RR_DATA = 0x006F
_SEND_UNIT_DATA = 0x0070


@pytest.fixture
def runtime_setup() -> tuple[AssemblyHost, ENIPServer]:
    input_signal = SignalDefinition(name="InValue", offset=0, signal_type="UINT", value="42")
    output_signal = SignalDefinition(name="OutValue", offset=0, signal_type="UINT")
    input_assembly = AssemblyDefinition(
        assembly_id=0x64,
        name="Inputs",
        direction="input",
        size_bits=16,
        signals=[input_signal],
    )
    output_assembly = AssemblyDefinition(
        assembly_id=0x65,
        name="Outputs",
        direction="output",
        size_bits=16,
        signals=[output_signal],
    )
    host = AssemblyHost([input_assembly, output_assembly], cycle_interval=0.05)
    server = ENIPServer(
        host="127.0.0.1",
        tcp_port=0,
        udp_port=0,
        connection_manager=ConnectionManager(default_timeout=1.0),
        reaper_interval=0.05,
        assembly_host=host,
    )
    server.start()
    try:
        yield host, server
    finally:
        server.stop()


def _send_enip(sock: socket.socket, command: int, session: int, payload: bytes = b"") -> None:
    context = b"CTXIO000"
    header = _ENCAP.pack(command, len(payload), session, 0, context, 0)
    sock.sendall(header + payload)


def _recv_enip(sock: socket.socket) -> tuple[int, int, int, bytes]:
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


def _make_forward_open(connection_points: list[int]) -> bytes:
    service = 0x54
    path = bytearray([0x20, 0x04, 0x24, 0x01])
    for point in connection_points:
        if point <= 0xFF:
            path.extend([0x2C, point & 0xFF])
        else:
            path.extend([0x2D, point & 0xFF, (point >> 8) & 0xFF])
    if len(path) % 2:
        path.append(0x00)
    path_words = len(path) // 2
    priority = 0x0A
    timeout_ticks = 0x0A
    o_to_t_conn = 0
    t_to_o_conn = 0
    connection_serial = 0x1234
    vendor_id = 0x1337
    originator_serial = 0x12345678
    timeout_multiplier = 0
    o_to_t_rpi = 100_000
    o_to_t_network = struct.pack("<H", 0x2208)
    t_to_o_rpi = 100_000
    t_to_o_network = struct.pack("<H", 0x2208)
    transport_trigger = 0x01
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
    request.append(path_words)
    request.extend(path)
    envelope = bytearray(struct.pack("<IHH", 0, 0, 2))
    envelope.extend(struct.pack("<HH", 0x0000, 0))
    envelope.extend(struct.pack("<HH", 0x00B2, len(request)))
    envelope.extend(request)
    return bytes(envelope)


def _parse_connected_response(payload: bytes) -> bytes:
    _, _, item_count = struct.unpack_from("<IHH", payload, 0)
    offset = 8
    for _ in range(item_count):
        type_id, length = struct.unpack_from("<HH", payload, offset)
        offset += 4
        data = payload[offset : offset + length]
        offset += length
        if type_id == _DATA_ITEM_CONNECTED:
            return data[2:]
    raise AssertionError("Connected response did not include data item")


def _build_o_to_t_payload(assembly: AssemblyDefinition, value: str) -> bytes:
    updated = copy.deepcopy(assembly)
    updated.signals[0].value = value
    return build_assembly_payload(updated)


def test_server_cycles_io_between_originator_and_host(runtime_setup: tuple[AssemblyHost, ENIPServer]) -> None:
    host, server = runtime_setup
    sock = socket.create_connection(("127.0.0.1", server.tcp_port))
    sock.settimeout(1.0)
    with sock:
        _send_enip(sock, 0x0065, 0, struct.pack("<HH", 1, 0))
        _, session, _, payload = _recv_enip(sock)
        assert session != 0
        assert payload == struct.pack("<HH", 1, 0)

        forward_open = _make_forward_open([0x64, 0x65])
        _send_enip(sock, _SEND_RR_DATA, session, forward_open)
        command, _, status, payload = _recv_enip(sock)
        assert command == _SEND_RR_DATA
        assert status == 0
        _, _, item_count = struct.unpack_from("<IHH", payload, 0)
        assert item_count == 2
        offset = 8
        # Skip null address item
        _type_id, length = struct.unpack_from("<HH", payload, offset)
        offset += 4 + length
        type_id, length = struct.unpack_from("<HH", payload, offset)
        assert type_id == 0x00B2
        offset += 4
        cip = payload[offset : offset + length]
        assert cip[0] == 0xD4
        o_to_t_conn = struct.unpack_from("<I", cip, 3)[0]
        t_to_o_conn = struct.unpack_from("<I", cip, 7)[0]
        assert o_to_t_conn != 0
        assert t_to_o_conn != 0

        output_template = AssemblyDefinition(
            assembly_id=0x65,
            name="Outputs",
            direction="output",
            size_bits=16,
            signals=[SignalDefinition(name="OutValue", offset=0, signal_type="UINT")],
        )

        def _send_cyclic(sequence: int, value: str) -> bytes:
            payload_bytes = _build_o_to_t_payload(output_template, value)
            message = bytearray(struct.pack("<IHH", 0, 0, 2))
            message.extend(struct.pack("<HH", _ADDRESS_ITEM_CONNECTED, 4))
            message.extend(struct.pack("<I", o_to_t_conn))
            data_item = struct.pack("<H", sequence & 0xFFFF) + payload_bytes
            message.extend(struct.pack("<HH", _DATA_ITEM_CONNECTED, len(data_item)))
            message.extend(data_item)
            _send_enip(sock, _SEND_UNIT_DATA, session, bytes(message))
            command, _, status, response_payload = _recv_enip(sock)
            assert command == _SEND_UNIT_DATA
            assert status == 0
            return _parse_connected_response(response_payload)

        time.sleep(0.1)
        response = _send_cyclic(1, "77")
        assert response == build_assembly_payload(
            AssemblyDefinition(
                assembly_id=0x64,
                name="Inputs",
                direction="input",
                size_bits=16,
                signals=[SignalDefinition(name="InValue", offset=0, signal_type="UINT", value="42")],
            )
        )

        snapshot = host.snapshot(0x65)
        assert snapshot["OutValue"] == "77"

        host.update_assembly_values(0x64, {"InValue": "99"})
        time.sleep(0.1)
        response = _send_cyclic(2, "5")
        expected = build_assembly_payload(
            AssemblyDefinition(
                assembly_id=0x64,
                name="Inputs",
                direction="input",
                size_bits=16,
                signals=[SignalDefinition(name="InValue", offset=0, signal_type="UINT", value="99")],
            )
        )
        assert response == expected
        snapshot = host.snapshot(0x65)
        assert snapshot["OutValue"] == "5"
