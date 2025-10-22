from __future__ import annotations

from typing import List

from pycipsim.handshake import HandshakePhase, perform_handshake
from pycipsim.session import SessionConfig


def test_simulated_handshake_produces_all_phases() -> None:
    config = SessionConfig()
    result = perform_handshake(config, simulate=True)

    assert result.success
    phases = [step.phase for step in result.steps]
    assert phases == [
        HandshakePhase.TCP_CONNECT,
        HandshakePhase.ENIP_SESSION,
        HandshakePhase.CIP_FORWARD_OPEN,
    ]


def test_tcp_failure_short_circuits_handshake() -> None:
    config = SessionConfig()
    driver_calls: List[str] = []

    def connector(_: SessionConfig) -> None:
        raise RuntimeError("tcp failure")

    def driver_factory(_: SessionConfig):  # pragma: no cover - should not be invoked
        driver_calls.append("called")
        raise AssertionError("driver should not be created when TCP fails")

    result = perform_handshake(
        config,
        simulate=False,
        tcp_connector=connector,
        driver_factory=driver_factory,
    )

    assert not result.success
    assert driver_calls == []
    assert result.steps[0].phase == HandshakePhase.TCP_CONNECT
    assert not result.steps[0].success


def test_custom_driver_handles_forward_open() -> None:
    config = SessionConfig()
    events: List[str] = []

    class DummyDriver:
        def open(self) -> None:
            events.append("open")

        def forward_open(self) -> None:
            events.append("forward_open")

        def close(self) -> None:
            events.append("close")

    def driver_factory(_: SessionConfig) -> DummyDriver:
        return DummyDriver()

    def connector(_: SessionConfig) -> None:
        events.append("tcp")

    result = perform_handshake(
        config,
        simulate=False,
        driver_factory=driver_factory,
        tcp_connector=connector,
    )

    assert result.success
    assert events == ["tcp", "open", "forward_open", "close"]
