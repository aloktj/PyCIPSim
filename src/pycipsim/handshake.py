"""Explicit handshake helpers for CIP originator connections."""
from __future__ import annotations

import contextlib
import secrets
import socket
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Protocol, Tuple

from .cip import format_path
from .session import PyCipSimClientTransport, SessionConfig


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
    except ImportError as exc:  # pragma: no cover - optional dependency resolution
        raise RuntimeError(
            "pycomm3 is required to perform a live handshake. Install pycipsim[pycomm3]."
        ) from exc

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
            if not self._driver._forward_open():  # type: ignore[attr-defined]
                raise RuntimeError("Failed to perform CIP forward open")

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


def _perform_pycipsim_handshake(
    config: SessionConfig,
    *,
    simulate: bool = False,
) -> HandshakeResult:
    """Perform the lightweight UDP HELLO handshake against a PyCIPSim target."""

    start = time.perf_counter()
    steps: List[HandshakeStep] = []

    if simulate:
        steps.append(
            HandshakeStep(
                HandshakePhase.TCP_CONNECT,
                True,
                "Simulated UDP HELLO",
            )
        )
        return HandshakeResult(True, steps, duration_ms=_elapsed_ms(start))

    transport = PyCipSimClientTransport(config)
    try:
        transport.connect()
    except Exception as exc:
        detail = f"UDP HELLO failed: {exc}"
        steps.append(HandshakeStep(HandshakePhase.TCP_CONNECT, False, detail))
        return HandshakeResult(False, steps, error=detail, duration_ms=_elapsed_ms(start))
    else:
        steps.append(
            HandshakeStep(
                HandshakePhase.TCP_CONNECT,
                True,
                "UDP HELLO acknowledged by target",
            )
        )
        return HandshakeResult(True, steps, duration_ms=_elapsed_ms(start))
    finally:
        with contextlib.suppress(Exception):
            transport.disconnect()


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

    transport_mode = (config.transport or "pycomm3").lower()
    if transport_mode == "pycipsim":
        return _perform_pycipsim_handshake(config, simulate=simulate)

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

