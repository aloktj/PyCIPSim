"""Device profiles and request/response data structures."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Callable, Dict, Iterable, List, Optional

_LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class ServiceRequest:
    """Represents a CIP service invocation."""

    service_code: str
    tag_path: str
    payload: Optional[bytes] = None
    metadata: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "service_code": self.service_code,
            "tag_path": self.tag_path,
            "payload": self.payload.decode("latin1") if self.payload else None,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class ServiceResponse:
    """Represents a CIP response."""

    service: str
    status: str
    payload: Optional[bytes] = None
    round_trip_ms: float = 0.0
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> Dict[str, object]:
        return {
            "service": self.service,
            "status": self.status,
            "payload": self.payload.decode("latin1") if self.payload else None,
            "round_trip_ms": self.round_trip_ms,
            "generated_at": self.generated_at.isoformat(),
        }


@dataclass(slots=True)
class FaultInjection:
    """Describes a fault scenario the device profile can trigger."""

    name: str
    description: str
    apply: Callable[[ServiceRequest], Optional[ServiceResponse]]


@dataclass
class DeviceProfile:
    """Encapsulates expected device behavior and available services."""

    name: str
    services: Dict[str, Callable[[ServiceRequest], ServiceResponse]]
    faults: Iterable[FaultInjection] = ()
    default_status: str = "SUCCESS"

    def respond(self, request: ServiceRequest) -> ServiceResponse:
        """Handle a request according to the profile's service map."""

        _LOGGER.info("Profile '%s' handling service %s", self.name, request.service_code)
        for fault in self.faults:
            maybe_response = fault.apply(request)
            if maybe_response is not None:
                _LOGGER.warning(
                    "Fault '%s' triggered for request %s", fault.name, request.service_code
                )
                return maybe_response

        handler = self.services.get(request.service_code)
        if handler is None:
            _LOGGER.error(
                "Service %s not supported by profile '%s'", request.service_code, self.name
            )
            return ServiceResponse(
                service=request.service_code,
                status="UNSUPPORTED_SERVICE",
                payload=None,
            )
        return handler(request)

    def to_json(self) -> str:
        """Serialize profile summary for reporting purposes."""

        data = {
            "name": self.name,
            "services": list(self.services.keys()),
            "faults": [fault.name for fault in self.faults],
            "default_status": self.default_status,
        }
        return json.dumps(data, indent=2)

    @staticmethod
    def echo_profile(name: str = "EchoDevice") -> "DeviceProfile":
        """Create a simple profile that echoes payload data."""

        def handler(request: ServiceRequest) -> ServiceResponse:
            payload = request.payload or b""
            return ServiceResponse(
                service=request.service_code,
                status="SUCCESS",
                payload=payload,
            )

        return DeviceProfile(name=name, services={"ECHO": handler})

    @staticmethod
    def counter_profile(name: str = "CounterDevice") -> "DeviceProfile":
        """Profile that returns incrementing counts per tag."""

        counters: Dict[str, int] = {}

        def handler(request: ServiceRequest) -> ServiceResponse:
            counters[request.tag_path] = counters.get(request.tag_path, 0) + 1
            value = counters[request.tag_path]
            return ServiceResponse(
                service=request.service_code,
                status="SUCCESS",
                payload=str(value).encode(),
            )

        return DeviceProfile(name=name, services={"READ": handler})


def drop_request_fault(name: str, target_service: str) -> FaultInjection:
    """Return a fault that drops matching requests."""

    def apply(request: ServiceRequest) -> Optional[ServiceResponse]:
        if request.service_code != target_service:
            return None
        return ServiceResponse(
            service=request.service_code,
            status="TIMEOUT",
            payload=None,
        )

    return FaultInjection(name=name, description=f"Drop {target_service} requests", apply=apply)


def delay_response_fault(name: str, delay_ms: float) -> FaultInjection:
    """Fault that delays the response without altering payload."""

    def apply(request: ServiceRequest) -> Optional[ServiceResponse]:
        _LOGGER.info("Applying delay of %.2fms to service %s", delay_ms, request.service_code)
        from time import sleep

        sleep(delay_ms / 1000.0)
        return None

    return FaultInjection(name=name, description=f"Delay responses by {delay_ms}ms", apply=apply)


def make_default_profiles() -> List[DeviceProfile]:
    """Return a list of built-in device profiles."""

    return [
        DeviceProfile.echo_profile(),
        DeviceProfile.counter_profile(),
    ]
