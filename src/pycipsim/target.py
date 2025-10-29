"""Runtime implementation for PyCIPSim target role."""
from __future__ import annotations

import contextlib
import logging
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from .config_store import ConfigurationStore, ConfigurationNotFoundError
from .configuration import (
    AssemblyDefinition,
    ConfigurationError,
    SimulatorConfiguration,
    build_assembly_payload,
    parse_assembly_payload,
)
from .target_protocol import (
    MSG_ACK,
    MSG_DATA,
    MSG_ERROR,
    MSG_GET,
    MSG_HELLO,
    MSG_HELLO_ACK,
    MSG_SET,
    TargetMessage,
)

_LOGGER = logging.getLogger(__name__)


def _find_interface_ipv4(interface: str) -> Optional[str]:
    """Attempt to resolve the IPv4 address associated with an interface."""

    try:  # pragma: no cover - optional dependency
        import psutil  # type: ignore[import-untyped]
    except Exception:  # pragma: no cover - fallback when psutil is missing
        psutil = None  # type: ignore[assignment]

    if psutil is None:
        return None

    try:
        addrs = psutil.net_if_addrs().get(interface, [])
    except Exception:  # pragma: no cover - defensive
        return None

    for addr in addrs:
        if addr.family == socket.AF_INET and addr.address:
            return addr.address
    return None


@dataclass(slots=True)
class _TargetClient:
    host: str
    command_port: int
    data_port: int
    last_seen: float

    def address(self) -> Tuple[str, int]:
        return (self.host, self.command_port)

    def data_address(self) -> Tuple[str, int]:
        return (self.host, self.data_port)


class CIPTargetRuntime:
    """Expose configuration assemblies over the lightweight PyCIPSim UDP protocol."""

    def __init__(
        self,
        configuration: SimulatorConfiguration,
        store: ConfigurationStore,
        *,
        cycle_interval: float = 0.1,
    ) -> None:
        self._configuration = configuration
        self._config_name = configuration.name
        self._store = store
        self._cycle_interval = max(cycle_interval, 0.05)
        self._stop_event = threading.Event()
        self._output_event = threading.Event()
        self._threads: List[threading.Thread] = []
        self._sock: Optional[socket.socket] = None
        self._clients: Dict[Tuple[str, int], _TargetClient] = {}
        self._lock = threading.RLock()
        self._multicast_target: Optional[Tuple[str, int]] = None
        self._multicast_membership: Optional[bytes] = None

    # ------------------------------------------------------------------
    # Multicast helpers
    # ------------------------------------------------------------------
    def _resolve_multicast_interface(self) -> str:
        """Determine the IPv4 address to use for multicast traffic."""

        interface = (self._configuration.listener_interface or "").strip()
        if interface:
            resolved = _find_interface_ipv4(interface)
            if resolved:
                return resolved
            _LOGGER.warning(
                "Listener interface '%s' has no IPv4 address; defaulting to INADDR_ANY.",
                interface,
            )
        host = (self._configuration.target_ip or "").strip()
        if host and host not in {"0.0.0.0", ""}:
            try:
                socket.inet_aton(host)
                return host
            except OSError:
                _LOGGER.debug("Target host '%s' is not a valid IPv4 address for multicast.", host)
        return "0.0.0.0"

    def _configure_multicast(self, sock: socket.socket) -> None:
        """Join the configured multicast group when enabled."""

        self._multicast_target = None
        self._multicast_membership = None

        if not self._configuration.multicast:
            return
        group = (self._configuration.receive_address or "").strip()
        if not group:
            return
        try:
            group_bytes = socket.inet_aton(group)
        except OSError:
            _LOGGER.warning("Invalid multicast receive address '%s'; skipping multicast setup.", group)
            return

        interface_ip = self._resolve_multicast_interface()
        try:
            interface_bytes = socket.inet_aton(interface_ip)
        except OSError:
            _LOGGER.debug(
                "Interface IP '%s' is invalid; falling back to INADDR_ANY for multicast membership.",
                interface_ip,
            )
            interface_bytes = socket.inet_aton("0.0.0.0")

        membership = group_bytes + interface_bytes
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
        except OSError as exc:
            _LOGGER.warning(
                "Unable to join multicast group %s on %s: %s", group, interface_ip, exc
            )
            return
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack("B", 1))
        except OSError:
            _LOGGER.debug("Failed to set multicast TTL; continuing with default value.")
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, interface_bytes)
        except OSError:
            _LOGGER.debug("Failed to set multicast interface; continuing with default routing.")

        self._multicast_target = (group, int(self._configuration.target_port))
        self._multicast_membership = membership

    # ------------------------------------------------------------------
    # Lifecycle management
    # ------------------------------------------------------------------
    def start(self) -> None:
        host = self._configuration.target_ip or "0.0.0.0"
        try:
            port = int(self._configuration.target_port)
        except Exception as exc:  # pragma: no cover - defensive
            raise RuntimeError("Configuration target port is invalid for target runtime") from exc
        _LOGGER.info(
            "Starting PyCIPSim target runtime '%s' on %s:%s",
            self._config_name,
            host,
            port,
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.settimeout(0.5)
        self._configure_multicast(sock)
        self._sock = sock
        self._stop_event.clear()
        self._output_event.set()
        request_thread = threading.Thread(
            target=self._request_loop,
            name=f"pycipsim-target-requests-{self._config_name}",
            daemon=True,
        )
        request_thread.start()
        self._threads.append(request_thread)
        broadcast_thread = threading.Thread(
            target=self._broadcast_loop,
            name=f"pycipsim-target-broadcast-{self._config_name}",
            daemon=True,
        )
        broadcast_thread.start()
        self._threads.append(broadcast_thread)

    def stop(self) -> None:
        self._stop_event.set()
        self._output_event.set()
        for thread in self._threads:
            thread.join(timeout=2.0)
        self._threads.clear()
        if self._sock is not None:
            try:
                if self._multicast_membership:
                    with contextlib.suppress(OSError):
                        self._sock.setsockopt(
                            socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, self._multicast_membership
                        )
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        self._multicast_target = None
        self._multicast_membership = None
        with self._lock:
            self._clients.clear()
        _LOGGER.info("Target runtime for '%s' stopped.", self._config_name)

    def notify_output_update(self) -> None:
        self._output_event.set()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _configuration_snapshot(self) -> SimulatorConfiguration:
        """Return the latest configuration instance from the backing store."""

        try:
            configuration = self._store.get(self._config_name)
        except ConfigurationNotFoundError:
            return self._configuration
        else:
            self._configuration = configuration
            return configuration

    def _input_assemblies(self) -> Iterable[AssemblyDefinition]:
        configuration = self._configuration_snapshot()
        for assembly in configuration.assemblies:
            direction = (assembly.direction or "").lower()
            if direction in {"input", "in"}:
                yield assembly

    def _output_assemblies(self) -> Iterable[AssemblyDefinition]:
        configuration = self._configuration_snapshot()
        for assembly in configuration.assemblies:
            direction = (assembly.direction or "").lower()
            if direction in {"output", "out"}:
                yield assembly

    def _register_client(self, addr: Tuple[str, int], data_port: int) -> None:
        with self._lock:
            self._clients[addr] = _TargetClient(
                host=addr[0],
                command_port=addr[1],
                data_port=data_port,
                last_seen=time.monotonic(),
            )
        _LOGGER.debug(
            "Registered PyCIPSim client %s:%s (data port %s)",
            addr[0],
            addr[1],
            data_port,
        )

    def _update_client_seen(self, addr: Tuple[str, int]) -> None:
        with self._lock:
            client = self._clients.get(addr)
            if client:
                client.last_seen = time.monotonic()

    def _remove_stale_clients(self, *, ttl: float = 10.0) -> None:
        now = time.monotonic()
        with self._lock:
            stale = [key for key, client in self._clients.items() if now - client.last_seen > ttl]
            for key in stale:
                _LOGGER.debug("Removing stale PyCIPSim client %s:%s", key[0], key[1])
                self._clients.pop(key, None)

    def _clients_snapshot(self) -> List[_TargetClient]:
        with self._lock:
            return list(self._clients.values())

    def _send_datagram(self, payload: bytes, target: Tuple[str, int]) -> None:
        if self._sock is None:
            return
        try:
            self._sock.sendto(payload, target)
        except OSError as exc:
            _LOGGER.debug("Failed to send datagram to %s:%s: %s", target[0], target[1], exc)

    def _handle_get(self, assembly_id: int, addr: Tuple[str, int]) -> None:
        try:
            assembly = self._configuration_snapshot().find_assembly(assembly_id)
            payload = build_assembly_payload(assembly)
        except ConfigurationError as exc:
            _LOGGER.warning("GET for unknown assembly %s on '%s': %s", assembly_id, self._config_name, exc)
            error = TargetMessage.encode(
                MSG_ERROR,
                assembly_id=assembly_id,
                payload=str(exc).encode("utf-8"),
            )
            self._send_datagram(error, addr)
            return
        response = TargetMessage.encode(MSG_DATA, assembly_id=assembly_id, payload=payload)
        self._send_datagram(response, addr)

    def _handle_set(self, assembly_id: int, data: bytes, addr: Tuple[str, int]) -> None:
        try:
            assembly = self._configuration_snapshot().find_assembly(assembly_id)
        except ConfigurationError as exc:
            _LOGGER.warning("SET for unknown assembly %s on '%s': %s", assembly_id, self._config_name, exc)
            error = TargetMessage.encode(
                MSG_ERROR,
                assembly_id=assembly_id,
                payload=str(exc).encode("utf-8"),
            )
            self._send_datagram(error, addr)
            return
        try:
            decoded = parse_assembly_payload(assembly, data)
        except ConfigurationError as exc:
            _LOGGER.error(
                "Failed to decode payload for assembly %s on '%s': %s",
                assembly_id,
                self._config_name,
                exc,
            )
            error = TargetMessage.encode(
                MSG_ERROR,
                assembly_id=assembly_id,
                payload=str(exc).encode("utf-8"),
            )
            self._send_datagram(error, addr)
            return
        if decoded:
            self._store.update_assembly_values(self._config_name, assembly_id, decoded)
            self._output_event.set()
        ack = TargetMessage.encode(MSG_ACK, assembly_id=assembly_id)
        self._send_datagram(ack, addr)

    def _request_loop(self) -> None:
        assert self._sock is not None
        while not self._stop_event.is_set():
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                self._remove_stale_clients()
                continue
            except OSError:
                break
            try:
                message = TargetMessage.decode(data)
            except Exception as exc:
                _LOGGER.debug("Invalid datagram from %s:%s: %s", addr[0], addr[1], exc)
                continue
            self._update_client_seen(addr)
            if message.message_type == MSG_HELLO:
                if len(message.payload) < 2:
                    _LOGGER.debug("HELLO missing data port from %s:%s", addr[0], addr[1])
                    continue
                data_port = struct.unpack("!H", message.payload[:2])[0]
                self._register_client(addr, data_port)
                ack = TargetMessage.encode(MSG_HELLO_ACK)
                self._send_datagram(ack, addr)
                continue
            if message.message_type == MSG_GET:
                self._handle_get(message.assembly_id, addr)
                continue
            if message.message_type == MSG_SET:
                self._handle_set(message.assembly_id, message.payload, addr)
                continue
            _LOGGER.debug(
                "Unsupported message type 0x%02X from %s:%s",
                message.message_type,
                addr[0],
                addr[1],
            )

    def _broadcast_loop(self) -> None:
        while not self._stop_event.is_set():
            triggered = self._output_event.wait(self._cycle_interval)
            self._output_event.clear()
            if self._stop_event.is_set():
                break
            clients = self._clients_snapshot()
            if not clients and not self._multicast_target:
                continue
            for assembly in self._input_assemblies():
                try:
                    payload = build_assembly_payload(assembly)
                except ConfigurationError as exc:
                    _LOGGER.error(
                        "Unable to build payload for assembly %s on '%s': %s",
                        assembly.assembly_id,
                        self._config_name,
                        exc,
                    )
                    continue
                datagram = TargetMessage.encode(
                    MSG_DATA,
                    assembly_id=assembly.assembly_id,
                    payload=payload,
                )
                targets: List[Tuple[str, int]] = [client.data_address() for client in clients]
                if self._multicast_target:
                    targets.append(self._multicast_target)
                for destination in targets:
                    self._send_datagram(datagram, destination)


__all__ = ["CIPTargetRuntime"]
