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
            from pycomm3 import LogixDriver
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise TransportError(
                "pycomm3 is not installed. Install pycipsim[pycomm3] to enable live connections."
            ) from exc

        self._config = config
        address = config.ip_address
        if config.slot is not None:
            address = f"{address}/{config.slot}"
        credentials = config.resolve_credentials()
        driver_kwargs = {
            "port": config.port,
            "timeout": config.timeout,
        }
        if credentials.get("username"):
            driver_kwargs["username"] = credentials["username"]
        if credentials.get("password"):
            driver_kwargs["password"] = credentials["password"]
        self._driver = LogixDriver(address, **driver_kwargs)

    def connect(self) -> None:  # pragma: no cover - requires hardware
        self._driver.open()

    def disconnect(self) -> None:  # pragma: no cover - requires hardware
        self._driver.close()

    def send(self, request: ServiceRequest) -> ServiceResponse:  # pragma: no cover - requires hardware
        metadata = request.metadata or {}
        if request.service_code in {"GET_ASSEMBLY", "SET_ASSEMBLY"}:
            instance = metadata.get("instance") or request.tag_path
            try:
                instance_id = int(str(instance), 0)
            except (TypeError, ValueError) as exc:
                raise TransportError(
                    f"Assembly instance identifier '{instance}' is not valid."
                ) from exc
            service_code = 0x0E if request.service_code == "GET_ASSEMBLY" else 0x10
            try:
                result = self._driver.generic_message(
                    service=service_code,
                    class_code=0x04,
                    instance=instance_id,
                    attribute=3,
                    request_data=request.payload,
                    response_data=True,
                )
            except Exception as exc:
                raise TransportError(str(exc)) from exc
            payload = result.get("value")
            if isinstance(payload, bytearray):
                payload = bytes(payload)
            elif isinstance(payload, list):
                payload = bytes(payload)
            return ServiceResponse(
                service=request.service_code,
                status=result.get("status", "SUCCESS"),
                payload=payload,
                round_trip_ms=result.get("duration", 0.0) * 1000,
            )
        result = self._driver.generic_message(
            service=request.service_code,
            request_data=request.payload,
            response_data=True,
            address=request.tag_path,
        )
        return ServiceResponse(
            service=request.service_code,
            status=result.get("status", "SUCCESS"),
            payload=result.get("value"),
            round_trip_ms=result.get("duration", 0.0) * 1000,
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
