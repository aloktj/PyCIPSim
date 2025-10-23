"""Explicit handshake helpers for CIP originator connections."""
from __future__ import annotations

import contextlib
import socket
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Iterable, List, Optional, Protocol

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
        import pycomm3
    except ImportError as exc:  # pragma: no cover - optional dependency resolution
        raise RuntimeError(
            "pycomm3 is required to perform a live handshake. Install pycipsim[pycomm3]."
        ) from exc

    driver_cls = getattr(pycomm3, "LogixDriver", None)
    if driver_cls is None:  # pragma: no cover - defensive
        raise RuntimeError("pycomm3.LogixDriver is unavailable; cannot perform handshake")

    class _DriverAdapter:
        def __init__(self) -> None:
            port = config.port
            timeout = config.timeout
            params = {}
            credentials = config.resolve_credentials()
            if credentials.get("username"):
                params["username"] = credentials["username"]
            if credentials.get("password"):
                params["password"] = credentials["password"]
            address = config.ip_address
            if config.slot is not None:
                address = f"{address}/{config.slot}"
            self._driver = driver_cls(address, port=port, timeout=timeout, **params)

        def open(self) -> None:
            self._driver.open()

        def forward_open(self) -> None:
            if hasattr(self._driver, "forward_open"):
                self._driver.forward_open()
            else:  # pragma: no cover - dependent on pycomm3 version
                raise RuntimeError("forward_open not supported by this pycomm3 driver")

        def close(self) -> None:
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
        driver = driver_builder(config)
        driver.open()
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
            steps.append(HandshakeStep(HandshakePhase.CIP_FORWARD_OPEN, False, str(exc)))
            return HandshakeResult(False, steps, error=str(exc), duration_ms=_elapsed_ms(start))
    finally:
        if driver is not None:
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

