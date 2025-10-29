"""Lightweight ENIP server with connection management for simulators."""
from __future__ import annotations

import contextlib
import ipaddress
import logging
import select
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

_LOGGER = logging.getLogger(__name__)

_ENCAP_HEADER = struct.Struct("<HHII8sI")

_REGISTER_SESSION = 0x0065
_UNREGISTER_SESSION = 0x0066
_LIST_IDENTITY = 0x0063
_SEND_RR_DATA = 0x006F
_SEND_UNIT_DATA = 0x0070

_ADDRESS_ITEM_NULL = 0x0000
_ADDRESS_ITEM_CONNECTED = 0x00A1
_DATA_ITEM_UNCONNECTED = 0x00B2

_FORWARD_OPEN = 0x54
_LARGE_FORWARD_OPEN = 0x5B
_FORWARD_CLOSE = 0x4E

_DEFAULT_IDENTITY = {
    "vendor_id": 0x1337,
    "device_type": 0x0022,
    "product_code": 0x0001,
    "revision_major": 1,
    "revision_minor": 0,
    "status": 0x0000,
    "serial_number": 0xABCDEF01,
    "product_name": "PyCIPSim",  # pragma: allowlist secret
    "state": 0x03,
}


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ConnectionError("Socket closed while receiving data")
        data.extend(chunk)
    return bytes(data)


@dataclass(slots=True)
class ForwardOpenRequest:
    """Parsed representation of a forward-open request."""

    service: int
    o_to_t_connection_id: int
    t_to_o_connection_id: int
    connection_serial: int
    vendor_id: int
    originator_serial: int
    timeout_multiplier: int
    transport_type_trigger: int
    connection_path_size: int
    connection_path: bytes
    o_to_t_rpi: int
    o_to_t_network: bytes
    t_to_o_rpi: int
    t_to_o_network: bytes

    priority_ticks: int
    timeout_ticks: int


@dataclass(slots=True)
class CIPConnection:
    """Active CIP connection metadata."""

    session_handle: int
    o_to_t_connection_id: int
    t_to_o_connection_id: int
    connection_serial: int
    vendor_id: int
    originator_serial: int
    timeout_multiplier: int
    timeout_seconds: float
    o_to_t_rpi: int
    t_to_o_rpi: int
    created_at: float = field(default_factory=time.monotonic)
    last_activity: float = field(default_factory=time.monotonic)

    def refresh(self) -> None:
        self.last_activity = time.monotonic()

    def expired(self, now: float) -> bool:
        return (now - self.last_activity) >= self.timeout_seconds

    def identifiers(self) -> Iterable[int]:
        yield self.o_to_t_connection_id
        yield self.t_to_o_connection_id


@dataclass(slots=True)
class ENIPSession:
    """Tracks encapsulation session state."""

    handle: int
    origin: Tuple[str, int]
    protocol_version: int
    options: int


class ConnectionManager:
    """Tracks the lifecycle of CIP connections established via ENIP."""

    def __init__(self, *, default_timeout: float = 5.0) -> None:
        self._default_timeout = max(default_timeout, 0.1)
        self._connections: Dict[Tuple[int, int, int, int], CIPConnection] = {}
        self._by_id: Dict[int, Tuple[int, int, int, int]] = {}
        self._lock = threading.Lock()
        self._next_connection_id = 0x1000_0000

    def _allocate_connection_id(self) -> int:
        with self._lock:
            value = self._next_connection_id
            self._next_connection_id += 1
        return value

    def _register(self, key: Tuple[int, int, int, int], connection: CIPConnection) -> None:
        self._connections[key] = connection
        for identifier in connection.identifiers():
            if identifier:
                self._by_id[identifier] = key

    def forward_open(self, session: ENIPSession, request: ForwardOpenRequest) -> CIPConnection:
        """Create or replace a CIP connection for the given session."""

        o_to_t = request.o_to_t_connection_id or self._allocate_connection_id()
        t_to_o = request.t_to_o_connection_id or self._allocate_connection_id()
        timeout = max(self._default_timeout, (request.timeout_multiplier + 1) * 0.5)
        connection = CIPConnection(
            session_handle=session.handle,
            o_to_t_connection_id=o_to_t,
            t_to_o_connection_id=t_to_o,
            connection_serial=request.connection_serial,
            vendor_id=request.vendor_id,
            originator_serial=request.originator_serial,
            timeout_multiplier=request.timeout_multiplier,
            timeout_seconds=timeout,
            o_to_t_rpi=request.o_to_t_rpi,
            t_to_o_rpi=request.t_to_o_rpi,
        )
        key = (session.handle, request.connection_serial, request.vendor_id, request.originator_serial)
        with self._lock:
            self._register(key, connection)
        return connection

    def forward_close(self, session: ENIPSession, connection_serial: int) -> None:
        key_to_remove: Optional[Tuple[int, int, int, int]] = None
        with self._lock:
            for key, connection in list(self._connections.items()):
                if connection.session_handle != session.handle:
                    continue
                if connection.connection_serial == connection_serial:
                    key_to_remove = key
                    break
            if key_to_remove is None:
                return
            connection = self._connections.pop(key_to_remove)
            for identifier in connection.identifiers():
                self._by_id.pop(identifier, None)

    def refresh(self, connection_id: int) -> None:
        key = self._by_id.get(connection_id)
        if key is None:
            return
        connection = self._connections.get(key)
        if connection is None:
            return
        connection.refresh()

    def drop_session(self, session_handle: int) -> None:
        with self._lock:
            for key, connection in list(self._connections.items()):
                if connection.session_handle != session_handle:
                    continue
                self._connections.pop(key, None)
                for identifier in connection.identifiers():
                    self._by_id.pop(identifier, None)

    def cleanup(self) -> List[CIPConnection]:
        now = time.monotonic()
        expired: List[CIPConnection] = []
        with self._lock:
            for key, connection in list(self._connections.items()):
                if connection.expired(now):
                    expired.append(connection)
                    self._connections.pop(key, None)
                    for identifier in connection.identifiers():
                        self._by_id.pop(identifier, None)
        return expired

    def active_connections(self) -> List[CIPConnection]:
        with self._lock:
            return list({id(conn): conn for conn in self._connections.values()}.values())

    def clear(self) -> None:
        with self._lock:
            self._connections.clear()
            self._by_id.clear()


class ENIPServer:
    """Minimal ENIP server that accepts originator connections."""

    def __init__(
        self,
        *,
        host: str = "0.0.0.0",
        tcp_port: int = 44818,
        udp_port: Optional[int] = None,
        identity: Optional[Dict[str, int]] = None,
        connection_manager: Optional[ConnectionManager] = None,
        reaper_interval: float = 0.5,
    ) -> None:
        self._host = host
        self._tcp_port = tcp_port
        self._udp_port = udp_port if udp_port is not None else tcp_port
        self._identity = {**_DEFAULT_IDENTITY, **(identity or {})}
        self.connection_manager = connection_manager or ConnectionManager()
        self._reaper_interval = max(reaper_interval, 0.1)
        self._sessions: Dict[int, ENIPSession] = {}
        self._session_lock = threading.Lock()
        self._next_session_handle = 1
        self._running = threading.Event()
        self._tcp_socket: Optional[socket.socket] = None
        self._udp_socket: Optional[socket.socket] = None
        self._threads: List[threading.Thread] = []
        self._client_threads: List[threading.Thread] = []

    @property
    def tcp_port(self) -> int:
        if self._tcp_socket is None:
            return self._tcp_port
        return self._tcp_socket.getsockname()[1]

    @property
    def udp_port(self) -> int:
        if self._udp_socket is None:
            return self._udp_port
        return self._udp_socket.getsockname()[1]

    def start(self) -> None:
        if self._running.is_set():
            return
        self._running.set()
        self._tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._tcp_socket.bind((self._host, self._tcp_port))
        self._tcp_socket.listen(5)
        self._tcp_socket.setblocking(False)
        self._udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._udp_socket.bind((self._host, self._udp_port))
        tcp_thread = threading.Thread(target=self._run_tcp_loop, name="enip-tcp", daemon=True)
        tcp_thread.start()
        self._threads.append(tcp_thread)
        udp_thread = threading.Thread(target=self._run_udp_loop, name="enip-udp", daemon=True)
        udp_thread.start()
        self._threads.append(udp_thread)
        reaper = threading.Thread(target=self._run_reaper_loop, name="enip-reaper", daemon=True)
        reaper.start()
        self._threads.append(reaper)

    def stop(self) -> None:
        if not self._running.is_set():
            return
        self._running.clear()
        sockets = [sock for sock in (self._tcp_socket, self._udp_socket) if sock is not None]
        for sock in sockets:
            with contextlib.suppress(Exception):  # type: ignore[name-defined]
                sock.shutdown(socket.SHUT_RDWR)
            sock.close()
        self._tcp_socket = None
        self._udp_socket = None
        for thread in list(self._client_threads):
            thread.join(timeout=1.0)
        self._client_threads.clear()
        for thread in list(self._threads):
            thread.join(timeout=1.0)
        self._threads.clear()
        self.connection_manager.clear()
        with self._session_lock:
            self._sessions.clear()

    def _run_tcp_loop(self) -> None:
        sock = self._tcp_socket
        if sock is None:
            return
        while self._running.is_set():
            try:
                ready, _, _ = select.select([sock], [], [], 0.2)
            except (OSError, ValueError):  # pragma: no cover - socket closed
                break
            if not ready:
                continue
            try:
                conn, addr = sock.accept()
            except OSError:
                if not self._running.is_set():
                    break
                continue
            conn.settimeout(5.0)
            thread = threading.Thread(
                target=self._handle_client,
                args=(conn, addr),
                name=f"enip-client-{addr[0]}:{addr[1]}",
                daemon=True,
            )
            thread.start()
            self._client_threads.append(thread)

    def _run_udp_loop(self) -> None:
        assert self._udp_socket is not None
        self._udp_socket.settimeout(0.5)
        while self._running.is_set():
            try:
                data, addr = self._udp_socket.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:  # pragma: no cover - socket closed
                break
            if not data:
                continue
            try:
                response = self._handle_message(data, addr, is_udp=True)
            except Exception as exc:  # pragma: no cover - defensive
                _LOGGER.error("UDP handler error: %s", exc)
                continue
            if response is not None:
                self._udp_socket.sendto(response, addr)

    def _run_reaper_loop(self) -> None:
        while self._running.is_set():
            expired = self.connection_manager.cleanup()
            for connection in expired:
                _LOGGER.info(
                    "Connection %s for session %s expired after %.2fs",
                    connection.t_to_o_connection_id,
                    connection.session_handle,
                    connection.timeout_seconds,
                )
            time.sleep(self._reaper_interval)

    def _handle_client(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        with conn:
            while self._running.is_set():
                try:
                    header = conn.recv(_ENCAP_HEADER.size)
                except socket.timeout:
                    continue
                except OSError:  # pragma: no cover - socket closed
                    break
                if not header:
                    break
                if len(header) < _ENCAP_HEADER.size:
                    try:
                        header += _recv_exact(conn, _ENCAP_HEADER.size - len(header))
                    except ConnectionError:
                        break
                try:
                    response = self._handle_stream_message(conn, header, addr)
                except Exception as exc:  # pragma: no cover - defensive
                    _LOGGER.error("Client handler error from %s: %s", addr, exc)
                    break
                if response is not None:
                    try:
                        conn.sendall(response)
                    except OSError:  # pragma: no cover - socket closed
                        break

    def _handle_stream_message(
        self,
        conn: socket.socket,
        header: bytes,
        addr: Tuple[str, int],
    ) -> Optional[bytes]:
        command, length, session_handle, _status, context, options = _ENCAP_HEADER.unpack(header)
        payload = b""
        if length:
            payload = _recv_exact(conn, length)
        message = header + payload
        return self._handle_message(message, addr)

    def _handle_message(
        self,
        message: bytes,
        addr: Tuple[str, int],
        *,
        is_udp: bool = False,
    ) -> Optional[bytes]:
        command, length, session_handle, status, context, options = _ENCAP_HEADER.unpack(
            message[: _ENCAP_HEADER.size]
        )
        payload = message[_ENCAP_HEADER.size : _ENCAP_HEADER.size + length]
        if command == _REGISTER_SESSION:
            handle, response_payload = self._handle_register_session(payload, addr)
            return _ENCAP_HEADER.pack(
                command,
                len(response_payload),
                handle,
                0,
                context,
                0,
            ) + response_payload
        if command == _UNREGISTER_SESSION:
            self._handle_unregister_session(session_handle)
            return _ENCAP_HEADER.pack(command, 0, session_handle, 0, context, 0)
        if command == _LIST_IDENTITY:
            response_payload = self._build_list_identity_response(addr)
            return _ENCAP_HEADER.pack(
                command,
                len(response_payload),
                session_handle,
                0,
                context,
                0,
            ) + response_payload
        if command in (_SEND_RR_DATA, _SEND_UNIT_DATA):
            response_payload = self._handle_data_message(command, session_handle, payload)
            return _ENCAP_HEADER.pack(
                command,
                len(response_payload),
                session_handle,
                status,
                context,
                options,
            ) + response_payload
        return None

    def _handle_register_session(self, payload: bytes, addr: Tuple[str, int]) -> Tuple[int, bytes]:
        if len(payload) < 4:
            raise ValueError("RegisterSession payload too short")
        protocol_version, options = struct.unpack_from("<HH", payload, 0)
        with self._session_lock:
            handle = self._next_session_handle
            self._next_session_handle += 1
            session = ENIPSession(handle=handle, origin=addr, protocol_version=protocol_version, options=options)
            self._sessions[handle] = session
        _LOGGER.info("Registered ENIP session %s from %s", handle, addr)
        return handle, struct.pack("<HH", protocol_version, options)

    def _handle_unregister_session(self, session_handle: int) -> None:
        with self._session_lock:
            session = self._sessions.pop(session_handle, None)
        if session is None:
            return
        self.connection_manager.drop_session(session_handle)
        _LOGGER.info("Session %s unregistered", session_handle)

    def _handle_data_message(self, command: int, session_handle: int, payload: bytes) -> bytes:
        session = self._sessions.get(session_handle)
        if session is None:
            raise ValueError(f"Unknown session handle {session_handle}")
        if len(payload) < 6:
            raise ValueError("SendRRData payload too short")
        interface_handle, timeout, item_count = struct.unpack_from("<IHH", payload, 0)
        offset = 8
        items: List[Tuple[int, bytes]] = []
        for _ in range(item_count):
            if len(payload) < offset + 4:
                raise ValueError("Item header truncated in SendRRData")
            type_id, length = struct.unpack_from("<HH", payload, offset)
            offset += 4
            if len(payload) < offset + length:
                raise ValueError("Item data truncated in SendRRData")
            items.append((type_id, payload[offset : offset + length]))
            offset += length
        cip_response = b""
        for type_id, data in items:
            if type_id == _DATA_ITEM_UNCONNECTED:
                cip_response = self._handle_unconnected_data(session, data)
            elif type_id == _ADDRESS_ITEM_CONNECTED and command == _SEND_UNIT_DATA:
                if len(data) >= 4:
                    connection_id = struct.unpack_from("<I", data, 0)[0]
                    self.connection_manager.refresh(connection_id)
        response_items: List[Tuple[int, bytes]] = []
        for type_id, data in items:
            if type_id == _DATA_ITEM_UNCONNECTED:
                response_items.append((type_id, cip_response))
            else:
                response_items.append((type_id, data))
        response = bytearray(struct.pack("<IHH", interface_handle, timeout, len(response_items)))
        for type_id, data in response_items:
            response.extend(struct.pack("<HH", type_id, len(data)))
            response.extend(data)
        return bytes(response)

    def _handle_unconnected_data(self, session: ENIPSession, payload: bytes) -> bytes:
        if len(payload) < 2:
            raise ValueError("CIP payload truncated")
        service = payload[0]
        path_size_words = payload[1]
        path_bytes = path_size_words * 2
        if len(payload) < 2 + path_bytes:
            raise ValueError("CIP path truncated")
        request_path = payload[2 : 2 + path_bytes]
        request_data = payload[2 + path_bytes :]
        if service in (_FORWARD_OPEN, _LARGE_FORWARD_OPEN):
            forward_request = self._parse_forward_open(service, request_data)
            connection = self.connection_manager.forward_open(session, forward_request)
            return self._build_forward_open_response(service, forward_request, connection)
        if service == _FORWARD_CLOSE:
            if len(request_data) < 10:
                raise ValueError("Forward close payload truncated")
            connection_serial = struct.unpack_from("<H", request_data, 0)[0]
            self.connection_manager.forward_close(session, connection_serial)
            return bytes([service | 0x80, 0x00, 0x00])
        _LOGGER.debug("Unhandled CIP service 0x%02X for path %s", service, request_path.hex())
        return bytes([service | 0x80, 0x00, 0x00])

    def _parse_forward_open(self, service: int, payload: bytes) -> ForwardOpenRequest:
        minimum = 32 if service == _FORWARD_OPEN else 36
        if len(payload) < minimum:
            raise ValueError("ForwardOpen payload too short")
        offset = 0
        priority_ticks = payload[offset]
        timeout_ticks = payload[offset + 1]
        offset += 2
        o_to_t_connection_id = struct.unpack_from("<I", payload, offset)[0]
        offset += 4
        t_to_o_connection_id = struct.unpack_from("<I", payload, offset)[0]
        offset += 4
        connection_serial = struct.unpack_from("<H", payload, offset)[0]
        offset += 2
        vendor_id = struct.unpack_from("<H", payload, offset)[0]
        offset += 2
        originator_serial = struct.unpack_from("<I", payload, offset)[0]
        offset += 4
        timeout_multiplier = payload[offset]
        offset += 1
        offset += 3  # reserved
        o_to_t_rpi = struct.unpack_from("<I", payload, offset)[0]
        offset += 4
        if service == _LARGE_FORWARD_OPEN:
            o_to_t_network = payload[offset : offset + 4]
            offset += 4
        else:
            o_to_t_network = payload[offset : offset + 2]
            offset += 2
        t_to_o_rpi = struct.unpack_from("<I", payload, offset)[0]
        offset += 4
        if service == _LARGE_FORWARD_OPEN:
            t_to_o_network = payload[offset : offset + 4]
            offset += 4
        else:
            t_to_o_network = payload[offset : offset + 2]
            offset += 2
        transport_type_trigger = payload[offset]
        offset += 1
        connection_path_size = payload[offset]
        offset += 1
        expected_bytes = connection_path_size * 2
        if len(payload) < offset + expected_bytes:
            raise ValueError("ForwardOpen connection path truncated")
        connection_path = payload[offset : offset + expected_bytes]
        return ForwardOpenRequest(
            service=service,
            o_to_t_connection_id=o_to_t_connection_id,
            t_to_o_connection_id=t_to_o_connection_id,
            connection_serial=connection_serial,
            vendor_id=vendor_id,
            originator_serial=originator_serial,
            timeout_multiplier=timeout_multiplier,
            transport_type_trigger=transport_type_trigger,
            connection_path_size=connection_path_size,
            connection_path=connection_path,
            o_to_t_rpi=o_to_t_rpi,
            o_to_t_network=o_to_t_network,
            t_to_o_rpi=t_to_o_rpi,
            t_to_o_network=t_to_o_network,
            priority_ticks=priority_ticks,
            timeout_ticks=timeout_ticks,
        )

    def _build_forward_open_response(
        self,
        service: int,
        request: ForwardOpenRequest,
        connection: CIPConnection,
    ) -> bytes:
        response = bytearray()
        response.append(service | 0x80)
        response.append(0x00)  # general status success
        response.append(0x00)  # additional status size
        response.extend(struct.pack("<I", connection.o_to_t_connection_id))
        response.extend(struct.pack("<I", connection.t_to_o_connection_id))
        response.extend(struct.pack("<H", connection.connection_serial))
        response.extend(struct.pack("<H", connection.vendor_id))
        response.extend(struct.pack("<I", connection.originator_serial))
        response.append(connection.timeout_multiplier & 0xFF)
        response.extend(b"\x00\x00\x00")
        response.extend(struct.pack("<I", request.o_to_t_rpi))
        response.extend(request.o_to_t_network)
        response.extend(struct.pack("<I", request.t_to_o_rpi))
        response.extend(request.t_to_o_network)
        response.append(0x00)  # application reply size
        response.append(0x00)  # reserved
        return bytes(response)

    def _build_list_identity_response(self, addr: Tuple[str, int]) -> bytes:
        identity = bytearray()
        identity.extend(struct.pack("<H", 1))  # protocol version
        ip_obj = ipaddress.ip_address(addr[0])
        if isinstance(ip_obj, ipaddress.IPv6Address):  # pragma: no cover - unlikely in tests
            ip_obj = ipaddress.IPv4Address("0.0.0.0")
        identity.extend(struct.pack(
            ">HHI8s",
            socket.AF_INET,
            socket.htons(self.tcp_port),
            int(ipaddress.IPv4Address(ip_obj)),
            b"\x00" * 8,
        ))
        identity.extend(struct.pack("<HHH", self._identity["vendor_id"], self._identity["device_type"], self._identity["product_code"]))
        identity.append(self._identity["revision_major"] & 0xFF)
        identity.append(self._identity["revision_minor"] & 0xFF)
        identity.extend(struct.pack("<H", self._identity["status"]))
        identity.extend(struct.pack("<I", self._identity["serial_number"]))
        name_bytes = self._identity["product_name"].encode("utf-8")
        identity.append(len(name_bytes) & 0xFF)
        identity.extend(name_bytes)
        identity.append(self._identity["state"] & 0xFF)
        response = bytearray(struct.pack("<H", 1))
        response.extend(struct.pack("<HH", 0x000C, len(identity)))
        response.extend(identity)
        return bytes(response)

    def active_sessions(self) -> List[ENIPSession]:
        with self._session_lock:
            return list(self._sessions.values())


__all__ = [
    "CIPConnection",
    "ConnectionManager",
    "ENIPServer",
    "ForwardOpenRequest",
]
