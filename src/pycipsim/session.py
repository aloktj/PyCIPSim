"""Session abstractions for CIP simulations."""
from __future__ import annotations

import contextlib
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Protocol

from .device import DeviceProfile, ServiceRequest, ServiceResponse

_LOGGER = logging.getLogger(__name__)


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
    metadata: Dict[str, Any] = field(default_factory=dict)


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
        self._driver = LogixDriver(address, port=config.port, timeout=config.timeout)

    def connect(self) -> None:  # pragma: no cover - requires hardware
        self._driver.open()

    def disconnect(self) -> None:  # pragma: no cover - requires hardware
        self._driver.close()

    def send(self, request: ServiceRequest) -> ServiceResponse:  # pragma: no cover - requires hardware
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

    @property
    def last_response(self) -> Optional[ServiceResponse]:
        """Return the most recent response."""

        return self._last_response

    def _ensure_transport(self) -> Transport:
        if self._transport is not None:
            return self._transport
        if self._profile is not None:
            self._transport = SimulatedTransport(self._profile)
        else:
            self._transport = PyComm3Transport(self.config)
        return self._transport

    @contextlib.contextmanager
    def lifecycle(self) -> "CIPSession":
        """Context manager that opens and closes the session."""

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

        self._ensure_transport().connect()

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
