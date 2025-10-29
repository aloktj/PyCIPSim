"""Session abstractions for CIP simulations."""
from __future__ import annotations

import contextlib
import copy
import logging
import os
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Protocol, Sequence, Tuple

from .cip import describe_error, resolve_service_code
from .device import DeviceProfile, ServiceRequest, ServiceResponse
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
    """Attempt to resolve the primary IPv4 address for a network interface."""

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


class TransportError(RuntimeError):
    """Raised when transport operations fail."""


class Transport(Protocol):
    """Protocol describing CIP transport behavior."""

    def connect(self) -> None:  # pragma: no cover - interface
        """Establish the underlying connection."""

    def disconnect(self) -> None:  # pragma: no cover - interface
        """Tear down the underlying connection."""

    def send(self, request: ServiceRequest) -> ServiceResponse:  # pragma: no cover - interface
        """Send a service request and return the response."""


def _summarize_cip_error(error: Any) -> str:
    """Render CIP response errors using known status descriptions when possible."""

    if isinstance(error, str):
        return error

    general_status = getattr(error, "status", None)
    if general_status is None:
        general_status = getattr(error, "general_status", None)

    if isinstance(general_status, int):
        description = describe_error(general_status)
    else:
        description = str(error)

    extended = getattr(error, "extended_status", None)
    if extended is None:
        extended = getattr(error, "extended_statuses", None)
    if isinstance(extended, (list, tuple)):
        hex_values = [f"0x{int(code) & 0xFFFF:04X}" for code in extended if isinstance(code, int)]
        if hex_values:
            description = f"{description} (extended {', '.join(hex_values)})"

    return description


@dataclass(slots=True)
class SessionConfig:
    """Configuration options for establishing a CIP session."""

    ip_address: str = "127.0.0.1"
    port: int = 44818
    timeout: float = 2.5
    retries: int = 3
    slot: Optional[int] = None
    network_interface: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    allowed_hosts: Sequence[str] = field(
        default_factory=lambda: ("127.0.0.1", "localhost")
    )
    allow_external: bool = False
    username_env_var: Optional[str] = None
    password_env_var: Optional[str] = None
    transport: str = "pycomm3"

    def resolve_credentials(self) -> Dict[str, Optional[str]]:
        """Load credentials from environment variables when configured."""

        username = (
            os.getenv(self.username_env_var) if self.username_env_var else None
        )
        password = (
            os.getenv(self.password_env_var) if self.password_env_var else None
        )
        return {"username": username, "password": password}

    def resolve_source_address(self) -> Optional[Tuple[str, int]]:
        """Return a socket source address derived from the configured interface."""

        if not self.network_interface:
            return None
        address = _find_interface_ipv4(self.network_interface)
        if not address:
            _LOGGER.warning(
                "Network interface '%s' has no IPv4 address; falling back to default routing.",
                self.network_interface,
            )
            return None
        return (address, 0)


class SimulatedTransport:
    """In-memory transport for exercising simulations without hardware."""

    def __init__(self, profile: DeviceProfile) -> None:
        self._profile = profile
        self._connected = False

    def connect(self) -> None:
        if self._connected:
            _LOGGER.debug("Simulated transport already connected; ignoring duplicate connect.")
            return
        _LOGGER.info("Connecting to simulated device profile '%s'", self._profile.name)
        self._connected = True

    def disconnect(self) -> None:
        if not self._connected:
            return
        _LOGGER.info("Disconnecting from simulated device profile '%s'", self._profile.name)
        self._connected = False

    def send(self, request: ServiceRequest) -> ServiceResponse:
        if not self._connected:
            raise TransportError("Cannot send message when transport is not connected.")
        _LOGGER.debug("Simulated transport dispatching request %s", request)
        return self._profile.respond(request)


class PyCipSimClientTransport:
    """UDP-based transport for PyCIPSim target interoperability."""

    def __init__(self, config: SessionConfig):
        self._config = config
        self._command_sock: Optional[socket.socket] = None
        self._data_sock: Optional[socket.socket] = None
        self._listener: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._server = (config.ip_address, config.port)
        self._update_callback: Optional[Callable[[int, bytes], None]] = None
        self._multicast_memberships: List[bytes] = []

    def register_update_listener(self, callback: Callable[[int, bytes], None]) -> None:
        self._update_callback = callback

    def _resolve_multicast_groups(self) -> List[str]:
        metadata = self._config.metadata or {}
        groups = metadata.get("multicast_groups")
        resolved: List[str] = []
        if isinstance(groups, str):
            resolved = [grp.strip() for grp in groups.split(",") if grp.strip()]
        elif isinstance(groups, (list, tuple, set)):
            resolved = [str(grp).strip() for grp in groups if str(grp).strip()]
        elif metadata.get("receive_address"):
            address = str(metadata.get("receive_address") or "").strip()
            if address:
                resolved = [address]
        return [grp for grp in resolved if grp]

    def _resolve_multicast_port(self) -> int:
        metadata = self._config.metadata or {}
        port_value = metadata.get("multicast_port")
        if isinstance(port_value, (int, float)):
            try:
                port = int(port_value)
            except (TypeError, ValueError):
                port = 0
        elif isinstance(port_value, str) and port_value.strip():
            try:
                port = int(port_value.strip(), 0)
            except ValueError:
                port = 0
        else:
            port = 0
        if port <= 0 or port >= 65536:
            port = int(self._config.port)
        return port

    def _join_multicast_groups(self, sock: socket.socket) -> None:
        self._multicast_memberships = []
        groups = self._resolve_multicast_groups()
        if not groups:
            return

        metadata = self._config.metadata or {}
        interface_name = str(metadata.get("multicast_interface") or "").strip()
        interface_ip: Optional[str] = None
        if interface_name:
            interface_ip = _find_interface_ipv4(interface_name)
            if interface_ip is None:
                _LOGGER.warning(
                    "Multicast interface '%s' has no IPv4 address; falling back to session interface.",
                    interface_name,
                )
        if interface_ip is None:
            source = self._config.resolve_source_address()
            if source:
                interface_ip = source[0]
        if interface_ip is None and self._config.network_interface:
            interface_ip = _find_interface_ipv4(self._config.network_interface)
        if not interface_ip:
            interface_ip = "0.0.0.0"

        try:
            interface_bytes = socket.inet_aton(interface_ip)
        except OSError:
            interface_bytes = socket.inet_aton("0.0.0.0")
            interface_ip = "0.0.0.0"

        for group in groups:
            try:
                group_bytes = socket.inet_aton(group)
            except OSError:
                _LOGGER.warning("Invalid multicast group '%s'; skipping subscription.", group)
                continue
            membership = group_bytes + interface_bytes
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
            except OSError as exc:
                _LOGGER.warning(
                    "Unable to join multicast group %s on %s: %s", group, interface_ip, exc
                )
                continue
            self._multicast_memberships.append(membership)

    def _leave_multicast_groups(self, sock: socket.socket) -> None:
        for membership in self._multicast_memberships:
            with contextlib.suppress(OSError):
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, membership)
        self._multicast_memberships = []

    # ------------------------------------------------------------------
    # Transport lifecycle
    # ------------------------------------------------------------------
    def connect(self) -> None:
        if self._command_sock is not None:
            return
        timeout = max(self._config.timeout, 0.1)
        command_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        command_sock.settimeout(timeout)
        source = self._config.resolve_source_address()
        if source:
            command_sock.bind(source)
        multicast_groups = self._resolve_multicast_groups()
        data_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        data_sock.settimeout(0.5)
        if multicast_groups:
            data_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bind_host = source[0] if source else ""
        bind_port = self._resolve_multicast_port() if multicast_groups else 0
        data_sock.bind((bind_host, bind_port))
        if multicast_groups:
            self._join_multicast_groups(data_sock)
        self._command_sock = command_sock
        self._data_sock = data_sock
        data_port = data_sock.getsockname()[1]
        hello = TargetMessage.encode(MSG_HELLO, payload=struct.pack("!H", data_port))
        try:
            command_sock.sendto(hello, self._server)
            response = self._receive(expected={MSG_HELLO_ACK})
            if response.message_type != MSG_HELLO_ACK:
                raise TransportError("Unexpected response during PyCIPSim handshake")
        except Exception:
            self.disconnect()
            raise
        self._stop_event.clear()
        listener = threading.Thread(
            target=self._listen_loop,
            name="pycipsim-transport-listener",
            daemon=True,
        )
        listener.start()
        self._listener = listener

    def disconnect(self) -> None:
        self._stop_event.set()
        if self._listener is not None:
            self._listener.join(timeout=1.0)
        self._listener = None
        if self._command_sock is not None:
            with contextlib.suppress(OSError):
                self._command_sock.close()
        if self._data_sock is not None:
            with contextlib.suppress(OSError):
                self._leave_multicast_groups(self._data_sock)
            with contextlib.suppress(OSError):
                self._data_sock.close()
        self._command_sock = None
        self._data_sock = None

    # ------------------------------------------------------------------
    # Request/response handling
    # ------------------------------------------------------------------
    def _resolve_assembly_id(self, request: ServiceRequest) -> int:
        metadata = request.metadata or {}
        instance = metadata.get("instance") or request.tag_path
        try:
            return int(str(instance), 0)
        except (TypeError, ValueError) as exc:
            raise TransportError(f"Assembly instance identifier '{instance}' is not valid.") from exc

    def _receive(self, expected: set[int]) -> TargetMessage:
        if self._command_sock is None:
            raise TransportError("PyCIPSim transport is not connected")
        deadline = time.monotonic() + max(self._config.timeout, 0.1)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TransportError("Timed out waiting for PyCIPSim response")
            self._command_sock.settimeout(remaining)
            try:
                data, addr = self._command_sock.recvfrom(4096)
            except socket.timeout:
                raise TransportError("Timed out waiting for PyCIPSim response")
            except OSError as exc:
                raise TransportError(str(exc)) from exc
            if addr[:2] != self._server:
                continue
            try:
                message = TargetMessage.decode(data)
            except Exception as exc:
                _LOGGER.debug("Discarding invalid datagram from %s:%s: %s", addr[0], addr[1], exc)
                continue
            if message.message_type in expected or message.message_type == MSG_ERROR:
                return message

    def _exchange(self, payload: bytes, expected: set[int]) -> TargetMessage:
        if self._command_sock is None:
            raise TransportError("PyCIPSim transport is not connected")
        try:
            self._command_sock.sendto(payload, self._server)
        except OSError as exc:
            raise TransportError(str(exc)) from exc
        return self._receive(expected)

    def _dispatch_update(self, assembly_id: int, payload: bytes) -> None:
        callback = self._update_callback
        if callback is None:
            return
        try:
            callback(assembly_id, payload)
        except Exception:  # pragma: no cover - defensive
            _LOGGER.exception("PyCIPSim update listener failed")

    def _listen_loop(self) -> None:
        if self._data_sock is None:
            return
        while not self._stop_event.is_set():
            try:
                data, addr = self._data_sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                message = TargetMessage.decode(data)
            except Exception as exc:
                _LOGGER.debug("Discarding invalid broadcast from %s:%s: %s", addr[0], addr[1], exc)
                continue
            if message.message_type == MSG_DATA:
                self._dispatch_update(message.assembly_id, message.payload)

    def send(self, request: ServiceRequest) -> ServiceResponse:
        assembly_id = self._resolve_assembly_id(request)
        if request.service_code == "GET_ASSEMBLY":
            message = TargetMessage.encode(MSG_GET, assembly_id=assembly_id)
            response = self._exchange(message, expected={MSG_DATA, MSG_ERROR})
            if response.message_type == MSG_DATA:
                payload = response.payload if response.payload else b""
                return ServiceResponse(
                    service=request.service_code,
                    status="SUCCESS",
                    payload=payload,
                )
            status = response.payload.decode("utf-8", errors="ignore") or "ERROR"
            return ServiceResponse(service=request.service_code, status=status, payload=None)
        if request.service_code == "SET_ASSEMBLY":
            payload = request.payload or b""
            message = TargetMessage.encode(MSG_SET, assembly_id=assembly_id, payload=payload)
            response = self._exchange(message, expected={MSG_ACK, MSG_ERROR})
            if response.message_type == MSG_ACK:
                return ServiceResponse(
                    service=request.service_code,
                    status="SUCCESS",
                    payload=payload if payload else None,
                )
            status = response.payload.decode("utf-8", errors="ignore") or "ERROR"
            return ServiceResponse(service=request.service_code, status=status, payload=None)
        raise TransportError("PyCIPSim transport only supports GET_ASSEMBLY and SET_ASSEMBLY services")


class PyComm3Transport:
    """Adapter around pycomm3 client APIs."""

    def __init__(self, config: SessionConfig):
        try:  # pragma: no cover - optional dependency
            from pycomm3 import CIPDriver, socket_
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise TransportError(
                "pycomm3 is not installed. Install pycipsim[pycomm3] to enable live connections."
            ) from exc

        self._config = config
        address = config.ip_address
        if config.slot is not None:
            address = f"{address}/{config.slot}"
        self._driver = CIPDriver(address)
        self._configure_driver(socket_)

    def _configure_driver(self, socket_module: Any) -> None:
        cfg = self._driver._cfg  # type: ignore[attr-defined]
        cfg["port"] = self._config.port
        cfg["socket_timeout"] = max(self._config.timeout, 0.1)
        cfg["timeout"] = max(self._config.timeout, 0.1)

        metadata = self._config.metadata or {}
        max_size = metadata.get("max_connection_size_bytes")
        if isinstance(max_size, int) and max_size > 0:
            cfg["connection_size"] = min(max_size, 4000)

        source = self._config.resolve_source_address()
        if source:
            source_ip, _ = source

            class _BoundSocket(socket_module.Socket):  # type: ignore[misc]
                def __init__(self, timeout: float, ip: str) -> None:
                    super().__init__(timeout)
                    self._source_ip = ip

                def connect(self, host: str, port: int) -> None:  # type: ignore[override]
                    try:
                        self.sock.bind((self._source_ip, 0))
                    except OSError as exc:  # pragma: no cover - depends on network
                        raise TransportError(
                            f"Failed to bind to source interface {self._source_ip}: {exc}"
                        ) from exc
                    super().connect(host, port)

            self._driver._sock = _BoundSocket(cfg["socket_timeout"], source_ip)

    def connect(self) -> None:  # pragma: no cover - requires hardware
        if not self._driver.open():
            raise TransportError("Failed to open ENIP session")

    def disconnect(self) -> None:  # pragma: no cover - requires hardware
        with contextlib.suppress(Exception):
            self._driver.close()

    def _unwrap_unconnected_response(self, data: bytes) -> bytes:
        if len(data) < 2:
            return data
        length = struct.unpack_from("<H", data, 0)[0]
        nested_end = 2 + length
        if length <= 0 or nested_end > len(data):
            return data
        nested = data[2:nested_end]
        if not nested:
            return b""
        if nested[0] & 0x80:
            return nested[4:]
        return data

    def _assembly_service(self, request: ServiceRequest, service_code: int) -> ServiceResponse:
        metadata = request.metadata or {}
        instance = metadata.get("instance") or request.tag_path
        try:
            instance_id = int(str(instance), 0)
        except (TypeError, ValueError) as exc:
            raise TransportError(f"Assembly instance identifier '{instance}' is not valid.") from exc

        payload = request.payload or b""
        preferred_connected = metadata.get("connected")
        attempts: Iterable[bool]
        if preferred_connected is None:
            attempts = (False, True)
        else:
            attempts = (bool(preferred_connected),)

        last_response: Optional[ServiceResponse] = None
        for connected in attempts:
            start = time.perf_counter()
            try:
                tag = self._driver.generic_message(
                    service=service_code,
                    class_code=0x04,
                    instance=instance_id,
                    attribute=3,
                    request_data=payload,
                    connected=connected,
                    unconnected_send=not connected,
                    name=request.service_code.lower(),
                )
            except Exception as exc:  # pragma: no cover - depends on network
                raise TransportError(str(exc)) from exc
            duration = (time.perf_counter() - start) * 1000
            if tag.error:
                status = str(tag.error)
            else:
                status = "SUCCESS"
            response_payload: Optional[bytes]
            if request.service_code == "GET_ASSEMBLY":
                value = tag.value
                if isinstance(value, bytes):
                    response_payload = self._unwrap_unconnected_response(value)
                elif isinstance(value, bytearray):
                    response_payload = self._unwrap_unconnected_response(bytes(value))
                elif value is None:
                    response_payload = b""
                else:
                    response_payload = bytes(value)
            else:
                response_payload = payload if payload else None

            response = ServiceResponse(
                service=request.service_code,
                status=status,
                payload=response_payload,
                round_trip_ms=duration,
            )
            if status == "SUCCESS":
                return response

            last_response = response
            if preferred_connected is not None or connected:
                return response

            normalized_status = status.strip().lower()
            if normalized_status not in {"too much data"}:
                return response

        return last_response or ServiceResponse(
            service=request.service_code,
            status="UNKNOWN_ERROR",
            payload=None,
        )

    def send(self, request: ServiceRequest) -> ServiceResponse:  # pragma: no cover - requires hardware
        if request.service_code == "GET_ASSEMBLY":
            return self._assembly_service(request, 0x0E)
        if request.service_code == "SET_ASSEMBLY":
            return self._assembly_service(request, 0x10)

        metadata = request.metadata or {}
        class_code = metadata.get("class")
        instance = metadata.get("instance")
        attribute = metadata.get("attribute", 0)
        if class_code is None or instance is None:
            raise TransportError(
                "Generic service requests must provide 'class' and 'instance' metadata."
            )
        try:
            class_code_int = int(str(class_code), 0)
            instance_int = int(str(instance), 0)
            attribute_int = int(str(attribute), 0)
        except (TypeError, ValueError) as exc:
            raise TransportError("Invalid class/instance/attribute metadata for generic request") from exc

        start = time.perf_counter()
        try:
            tag = self._driver.generic_message(
                service=request.service_code,
                class_code=class_code_int,
                instance=instance_int,
                attribute=attribute_int,
                request_data=request.payload or b"",
                connected=False,
                name=request.tag_path or request.service_code,
            )
        except Exception as exc:  # pragma: no cover - depends on network
            raise TransportError(str(exc)) from exc
        duration = (time.perf_counter() - start) * 1000
        status = "SUCCESS" if not tag.error else str(tag.error)
        value = tag.value
        if isinstance(value, bytearray):
            payload = bytes(value)
        elif isinstance(value, bytes):
            payload = value
        elif value is None:
            payload = None
        else:
            payload = bytes(value)
        return ServiceResponse(
            service=request.service_code,
            status=status,
            payload=payload,
            round_trip_ms=duration,
        )


class CIPSession:
    """Lifecycle management for CIP transport sessions."""

    def __init__(
        self,
        config: SessionConfig,
        transport: Optional[Transport] = None,
        profile: Optional[DeviceProfile] = None,
    ) -> None:
        self.config = config
        self._transport = transport
        self._profile = profile
        self._last_response: Optional[ServiceResponse] = None
        self._history: List[Tuple[ServiceRequest, ServiceResponse]] = []

    @property
    def last_response(self) -> Optional[ServiceResponse]:
        """Return the most recent response."""

        return self._last_response

    def history(self) -> List[Tuple[ServiceRequest, ServiceResponse]]:
        """Return a copy of the request/response history."""

        return list(self._history)

    def _ensure_transport(self) -> Transport:
        if self._transport is not None:
            return self._transport
        if self._profile is not None:
            self._transport = SimulatedTransport(self._profile)
        else:
            transport_mode = (self.config.transport or "pycomm3").lower()
            if transport_mode == "pycipsim":
                self._transport = PyCipSimClientTransport(self.config)
            else:
                self._transport = PyComm3Transport(self.config)
        return self._transport

    def _resolve_allowed_hosts(self) -> Iterable[str]:
        hosts: List[str] = list(self.config.allowed_hosts)
        env_hosts = os.getenv("PYCIPSIM_ALLOWED_HOSTS")
        if env_hosts:
            hosts.extend(h.strip() for h in env_hosts.split(",") if h.strip())
        return hosts

    def _validate_target(self) -> None:
        if self._profile is not None:
            return
        if self.config.allow_external or os.getenv("PYCIPSIM_ALLOW_EXTERNAL") == "1":
            _LOGGER.warning(
                "External connections enabled for %s; ensure compliance with safety policies.",
                self.config.ip_address,
            )
            return
        allowed_hosts = set(self._resolve_allowed_hosts())
        if self.config.ip_address not in allowed_hosts:
            raise TransportError(
                "Target host '%s' is not in the allowed hosts list. Set allow_external to True "
                "or update allowed_hosts to proceed."
                % self.config.ip_address
            )

    @contextlib.contextmanager
    def lifecycle(self) -> "CIPSession":
        """Context manager that opens and closes the session."""

        self._validate_target()
        transport = self._ensure_transport()
        start = time.perf_counter()
        transport.connect()
        elapsed = (time.perf_counter() - start) * 1000
        _LOGGER.info(
            "Session established to %s:%s in %.2fms",
            self.config.ip_address,
            self.config.port,
            elapsed,
        )
        try:
            yield self
        finally:
            transport.disconnect()

    def connect(self) -> None:
        """Open the session without a context manager."""

        self._validate_target()
        transport = self._ensure_transport()
        transport.connect()

    def disconnect(self) -> None:
        """Close the session."""

        if self._transport is None:
            return
        self._transport.disconnect()

    def send(self, request: ServiceRequest) -> ServiceResponse:
        """Send a request and return the response, applying retry semantics."""

        transport = self._ensure_transport()
        last_error: Optional[Exception] = None
        for attempt in range(1, self.config.retries + 1):
            try:
                start = time.perf_counter()
                response = transport.send(request)
                duration = (time.perf_counter() - start) * 1000
                response.round_trip_ms = duration
                _LOGGER.debug(
                    "Attempt %d successful for service %s in %.2fms",
                    attempt,
                    request.service_code,
                    duration,
                )
                self._last_response = response
                self._history.append((copy.deepcopy(request), copy.deepcopy(response)))
                return response
            except Exception as exc:  # pragma: no cover - exceptional flow
                last_error = exc
                _LOGGER.warning(
                    "Attempt %d failed for service %s: %s",
                    attempt,
                    request.service_code,
                    exc,
                )
                time.sleep(min(0.25 * attempt, self.config.timeout))
        raise TransportError(f"Failed to send request after {self.config.retries} retries") from last_error

    def register_update_listener(self, callback: Callable[[int, bytes], None]) -> None:
        """Register a callback for asynchronous assembly updates when supported."""

        transport = self._ensure_transport()
        handler = getattr(transport, "register_update_listener", None)
        if callable(handler):
            handler(callback)
