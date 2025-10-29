"""Session abstractions for CIP simulations."""
from __future__ import annotations

import contextlib
import copy
import logging
import os
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Protocol, Sequence, Tuple

from .cip import describe_error, resolve_service_code
from .device import DeviceProfile, ServiceRequest, ServiceResponse

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
                    response_payload = value
                elif isinstance(value, bytearray):
                    response_payload = bytes(value)
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
