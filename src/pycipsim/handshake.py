"""Explicit handshake helpers for CIP originator connections."""
from __future__ import annotations

import contextlib
import secrets
import socket
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Protocol, Tuple

from .session import SessionConfig


class HandshakePhase(str, Enum):
    """Phases required to establish an originator connection."""

    TCP_CONNECT = "tcp_connect"
    ENIP_SESSION = "enip_session"
    CIP_FORWARD_OPEN = "cip_forward_open"


@dataclass(slots=True)
class HandshakeStep:
    """Outcome of an individual handshake phase."""

    phase: HandshakePhase
    success: bool
    detail: str


@dataclass(slots=True)
class HandshakeResult:
    """Summary of the handshake attempt."""

    success: bool
    steps: List[HandshakeStep] = field(default_factory=list)
    error: Optional[str] = None
    duration_ms: float = 0.0


class HandshakeDriver(Protocol):  # pragma: no cover - interface definition
    """Minimal interface for performing ENIP/CIP steps."""

    def open(self) -> None:
        """Open an ENIP session."""

    def forward_open(self) -> None:
        """Issue a CIP forward-open."""

    def close(self) -> None:
        """Close the ENIP session."""


def _resolve_driver(config: SessionConfig) -> HandshakeDriver:
    try:  # pragma: no cover - optional dependency resolution
        from pycomm3 import CIPDriver, socket_
        from pycomm3.cip.data_types import LogicalSegment, PADDED_EPATH
        from pycomm3.cip_driver import (
            ClassCode,
            ConnectionManagerInstances,
            ConnectionManagerServices,
            MSG_ROUTER_PATH,
            PADDED_EPATH as DRIVER_PADDED_EPATH,
            PRIORITY,
            TIMEOUT_MULTIPLIER,
            TIMEOUT_TICKS,
            UDINT,
            UINT,
        )
    except ImportError as exc:  # pragma: no cover - optional dependency resolution
        raise RuntimeError(
            "pycomm3 is required to perform a live handshake. Install pycipsim[pycomm3]."
        ) from exc

    _CONNECTION_TYPE_BASE = {
        # Bits 13-14 encode the connection type while the low 10 bits capture the
        # size. The high nibble in the expected parameters (0x4892/0x2894) maps to
        # these base masks.
        "point_to_point": 0x4800,
        "multicast": 0x2800,
    }

    def _normalize_int(value: Any, *, field: str, default: Optional[int] = None, minimum: Optional[int] = None, maximum: Optional[int] = None) -> int:
        if value is None:
            if default is None:
                raise RuntimeError(f"Forward-open metadata missing '{field}'.")
            value = default
        try:
            number = int(str(value), 0)
        except Exception as exc:  # pragma: no cover - defensive
            raise RuntimeError(f"Forward-open metadata field '{field}' is not numeric: {value!r}") from exc
        if minimum is not None and number < minimum:
            raise RuntimeError(
                f"Forward-open metadata field '{field}' must be at least {minimum}."
            )
        if maximum is not None and number > maximum:
            number = maximum
        return number

    def _normalize_connection_type(value: Any, default: str) -> str:
        mapping = {
            "point_to_point": "point_to_point",
            "point-to-point": "point_to_point",
            "p2p": "point_to_point",
            "unicast": "point_to_point",
            "multicast": "multicast",
            "multi": "multicast",
        }
        if value is None:
            return default
        text = str(value).strip().lower()
        return mapping.get(text, default)

    def _encode_network_parameter(size: int, connection_type: str, *, extended: bool) -> bytes:
        base = _CONNECTION_TYPE_BASE.get(connection_type, _CONNECTION_TYPE_BASE["point_to_point"])
        if extended:
            return UDINT.encode((size & 0xFFFF) | (base << 16))
        return UINT.encode((size & 0x01FF) | base)

    def _build_forward_open_request(metadata: Dict[str, Any]) -> Tuple[bytes, Any, Dict[str, int]]:
        if not metadata:
            raise RuntimeError("Forward-open metadata is required for live handshakes.")

        application_class = _normalize_int(
            metadata.get("application_class", 0x04), field="application_class", minimum=0, maximum=0xFF
        )
        application_instance = _normalize_int(
            metadata.get("application_instance"), field="application_instance", minimum=0, maximum=0xFFFF_FFFF
        )
        o_to_t_instance = _normalize_int(
            metadata.get("o_to_t_instance"), field="o_to_t_instance", minimum=0, maximum=0xFFFF_FFFF
        )
        t_to_o_instance = _normalize_int(
            metadata.get("t_to_o_instance"), field="t_to_o_instance", minimum=0, maximum=0xFFFF_FFFF
        )
        o_to_t_size = _normalize_int(
            metadata.get("o_to_t_size"), field="o_to_t_size", minimum=1, maximum=0xFFFF
        )
        t_to_o_size = _normalize_int(
            metadata.get("t_to_o_size"), field="t_to_o_size", minimum=1, maximum=0xFFFF
        )
        o_to_t_type = _normalize_connection_type(
            metadata.get("o_to_t_connection_type"), "point_to_point"
        )
        t_to_o_type = _normalize_connection_type(
            metadata.get("t_to_o_connection_type"), "point_to_point"
        )
        o_to_t_rpi = _normalize_int(
            metadata.get("o_to_t_rpi_us", 200_000), field="o_to_t_rpi_us", minimum=1, maximum=0xFFFF_FFFF
        )
        t_to_o_rpi = _normalize_int(
            metadata.get("t_to_o_rpi_us", 200_000), field="t_to_o_rpi_us", minimum=1, maximum=0xFFFF_FFFF
        )
        timeout_multiplier = _normalize_int(
            metadata.get("timeout_multiplier", 0),
            field="timeout_multiplier",
            minimum=0,
            maximum=0xFF,
        )
        transport_trigger = _normalize_int(
            metadata.get("transport_type_trigger", 0x01),
            field="transport_type_trigger",
            minimum=0,
            maximum=0xFF,
        )

        o_to_t_conn_id = _normalize_int(
            metadata.get("o_to_t_connection_id", 0),
            field="o_to_t_connection_id",
            minimum=0,
            maximum=0xFFFF_FFFF,
        )
        t_to_o_conn_id = _normalize_int(
            metadata.get("t_to_o_connection_id", 0),
            field="t_to_o_connection_id",
            minimum=0,
            maximum=0xFFFF_FFFF,
        )
        connection_serial = _normalize_int(
            metadata.get("connection_serial", secrets.randbits(16) or 1),
            field="connection_serial",
            minimum=1,
            maximum=0xFFFF,
        )
        vendor_id = _normalize_int(
            metadata.get("vendor_id", 0x1337), field="vendor_id", minimum=0, maximum=0xFFFF
        )
        originator_serial = _normalize_int(
            metadata.get("originator_serial", secrets.randbits(32) or 1),
            field="originator_serial",
            minimum=1,
            maximum=0xFFFF_FFFF,
        )

        extended = bool(metadata.get("use_large_forward_open")) or o_to_t_size > 0x01FF or t_to_o_size > 0x01FF
        o_to_t_param = _encode_network_parameter(o_to_t_size, o_to_t_type, extended=extended)
        t_to_o_param = _encode_network_parameter(t_to_o_size, t_to_o_type, extended=extended)
        service = (
            ConnectionManagerServices.large_forward_open
            if extended
            else ConnectionManagerServices.forward_open
        )

        connection_points_raw = metadata.get("connection_points")
        config_point = metadata.get("configuration_point")
        if config_point is not None:
            config_point = _normalize_int(
                config_point, field="configuration_point", minimum=0, maximum=0xFFFF_FFFF
            )

        if connection_points_raw is not None:
            try:
                iterable = list(connection_points_raw)
            except TypeError as exc:  # pragma: no cover - defensive
                raise RuntimeError(
                    "Forward-open metadata field 'connection_points' must be an iterable."
                ) from exc
            connection_points: List[int] = [
                _normalize_int(value, field=f"connection_points[{index}]", minimum=0, maximum=0xFFFF_FFFF)
                for index, value in enumerate(iterable)
            ]
        else:
            connection_points = [t_to_o_instance, o_to_t_instance]
            if config_point is not None and config_point not in connection_points:
                connection_points.append(config_point)

        if not connection_points:
            raise RuntimeError("Forward-open metadata did not specify any connection points.")

        path_segments = [
            LogicalSegment(application_class, "class_id"),
            LogicalSegment(application_instance, "instance_id"),
        ]
        for point in connection_points:
            path_segments.append(LogicalSegment(point, "connection_point"))

        path_bytes = PADDED_EPATH.encode(path_segments, length=False)
        if len(path_bytes) % 2:
            path_bytes += b"\x00"
        path_words = len(path_bytes) // 2
        if path_words <= 0:
            raise RuntimeError("Forward-open connection path is empty.")

        message = b"".join(
            [
                PRIORITY,
                TIMEOUT_TICKS,
                UDINT.encode(o_to_t_conn_id),
                UDINT.encode(t_to_o_conn_id),
                UINT.encode(connection_serial),
                UINT.encode(vendor_id),
                UDINT.encode(originator_serial),
                bytes([timeout_multiplier & 0xFF]),
                b"\x00\x00\x00",
                UDINT.encode(o_to_t_rpi),
                o_to_t_param,
                UDINT.encode(t_to_o_rpi),
                t_to_o_param,
                bytes([transport_trigger & 0xFF]),
                bytes([path_words & 0xFF]),
                path_bytes,
            ]
        )
        return (
            message,
            service,
            {
                "connection_serial": connection_serial,
                "vendor_id": vendor_id,
                "originator_serial": originator_serial,
                "t_to_o_conn_id": t_to_o_conn_id,
            },
        )

    address = config.ip_address
    if config.slot is not None:
        address = f"{address}/{config.slot}"

    class _DriverAdapter:
        def __init__(self) -> None:
            self._driver = CIPDriver(address)
            cfg = self._driver._cfg  # type: ignore[attr-defined]
            cfg["port"] = config.port
            cfg["socket_timeout"] = max(config.timeout, 0.1)
            cfg["timeout"] = max(config.timeout, 0.1)
            metadata = config.metadata or {}
            max_size = metadata.get("max_connection_size_bytes")
            if isinstance(max_size, int) and max_size > 0:
                cfg["connection_size"] = min(max_size, 4000)
            forward_open_meta = metadata.get("forward_open") if isinstance(metadata, dict) else None
            self._forward_open_meta = forward_open_meta if isinstance(forward_open_meta, dict) else None
            source = config.resolve_source_address()
            if source:
                source_ip, _ = source

                class _BoundSocket(socket_.Socket):  # type: ignore[misc]
                    def __init__(self, timeout: float, ip: str) -> None:
                        super().__init__(timeout)
                        self._source_ip = ip

                    def connect(self, host: str, port: int) -> None:  # type: ignore[override]
                        try:
                            self.sock.bind((self._source_ip, 0))
                        except OSError as exc:  # pragma: no cover - depends on network
                            raise RuntimeError(
                                f"Failed to bind to source interface {self._source_ip}: {exc}"
                            ) from exc
                        super().connect(host, port)

                self._driver._sock = _BoundSocket(cfg["socket_timeout"], source_ip)

        def open(self) -> None:
            if not self._driver.open():
                raise RuntimeError("Failed to register ENIP session")

        def forward_open(self) -> None:
            if not self._forward_open_meta:
                if not self._driver._forward_open():  # type: ignore[attr-defined]
                    raise RuntimeError("Failed to perform CIP forward open")
                return

            request_data, service, state = _build_forward_open_request(self._forward_open_meta)
            cfg = self._driver._cfg  # type: ignore[attr-defined]
            cfg["csn"] = UINT.encode(state["connection_serial"])
            cfg["vid"] = UINT.encode(state["vendor_id"])
            cfg["vsn"] = UDINT.encode(state["originator_serial"])
            cfg["cid"] = UDINT.encode(state["t_to_o_conn_id"])
            route_path = DRIVER_PADDED_EPATH.encode(
                self._driver._cfg["cip_path"] + MSG_ROUTER_PATH, length=True
            )
            try:
                response = self._driver.generic_message(
                    service=service,
                    class_code=ClassCode.connection_manager,
                    instance=ConnectionManagerInstances.open_request,
                    request_data=request_data,
                    route_path=route_path,
                    connected=False,
                    name="forward_open",
                )
            except Exception as exc:  # pragma: no cover - depends on network
                raise RuntimeError(str(exc)) from exc
            if not response or response.error:
                error = getattr(response, "error", None) if response else None
                raise RuntimeError(str(error) if error else "Forward open returned no response")
            setattr(self._driver, "_connection_opened", True)
            setattr(self._driver, "_target_is_connected", True)
            value = getattr(response, "value", None)
            if isinstance(value, (bytes, bytearray)) and len(value) >= 4:
                setattr(self._driver, "_target_cid", bytes(value[:4]))

        def forward_close(self) -> None:
            with contextlib.suppress(Exception):
                forward_close = getattr(self._driver, "_forward_close", None)
                if callable(forward_close):
                    forward_close()

        def close(self) -> None:
            with contextlib.suppress(Exception):
                self.forward_close()
            with contextlib.suppress(Exception):
                self._driver.close()

    return _DriverAdapter()


def perform_handshake(
    config: SessionConfig,
    *,
    simulate: bool = False,
    driver_factory: Optional[Callable[[SessionConfig], HandshakeDriver]] = None,
    tcp_connector: Optional[Callable[[SessionConfig], None]] = None,
) -> HandshakeResult:
    """Execute the TCP → ENIP → CIP handshake for an originator session."""

    start = time.perf_counter()
    steps: List[HandshakeStep] = []

    if simulate:
        steps.extend(
            [
                HandshakeStep(HandshakePhase.TCP_CONNECT, True, "Simulated TCP connection"),
                HandshakeStep(HandshakePhase.ENIP_SESSION, True, "Simulated ENIP register session"),
                HandshakeStep(
                    HandshakePhase.CIP_FORWARD_OPEN,
                    True,
                    "Simulated CIP forward open established",
                ),
            ]
        )
        return HandshakeResult(True, steps, duration_ms=(time.perf_counter() - start) * 1000)

    connector = tcp_connector or _default_tcp_connector
    driver_builder = driver_factory or _resolve_driver

    try:
        connector(config)
        steps.append(HandshakeStep(HandshakePhase.TCP_CONNECT, True, "TCP socket established"))
    except Exception as exc:
        steps.append(HandshakeStep(HandshakePhase.TCP_CONNECT, False, str(exc)))
        return HandshakeResult(False, steps, error=str(exc), duration_ms=_elapsed_ms(start))

    driver: Optional[HandshakeDriver] = None
    try:
        try:
            driver = driver_builder(config)
        except Exception as exc:
            detail = str(exc)
            steps.append(HandshakeStep(HandshakePhase.ENIP_SESSION, False, detail))
            return HandshakeResult(False, steps, error=detail, duration_ms=_elapsed_ms(start))

        try:
            driver.open()
        except Exception as exc:  # pragma: no cover - depends on live hardware failures
            detail = str(exc)
            steps.append(HandshakeStep(HandshakePhase.ENIP_SESSION, False, detail))
            return HandshakeResult(False, steps, error=detail, duration_ms=_elapsed_ms(start))

        steps.append(
            HandshakeStep(
                HandshakePhase.ENIP_SESSION,
                True,
                "ENIP session registered with target",
            )
        )
        try:
            driver.forward_open()
            steps.append(
                HandshakeStep(
                    HandshakePhase.CIP_FORWARD_OPEN,
                    True,
                    "CIP forward-open successful",
                )
            )
        except Exception as exc:  # pragma: no cover - requires hardware to fully exercise
            detail = str(exc)
            steps.append(HandshakeStep(HandshakePhase.CIP_FORWARD_OPEN, False, detail))
            return HandshakeResult(False, steps, error=detail, duration_ms=_elapsed_ms(start))
    finally:
        if driver is not None:
            with contextlib.suppress(Exception):
                forward_close = getattr(driver, "forward_close", None)
                if callable(forward_close):
                    forward_close()
            with contextlib.suppress(Exception):
                driver.close()

    return HandshakeResult(True, steps, duration_ms=_elapsed_ms(start))


def _default_tcp_connector(config: SessionConfig) -> None:
    source_address = config.resolve_source_address()
    with contextlib.closing(
        socket.create_connection(
            (config.ip_address, config.port), config.timeout, source_address
        )
    ):
        return


def _elapsed_ms(start: float) -> float:
    return (time.perf_counter() - start) * 1000


__all__ = [
    "HandshakePhase",
    "HandshakeResult",
    "HandshakeStep",
    "perform_handshake",
]

