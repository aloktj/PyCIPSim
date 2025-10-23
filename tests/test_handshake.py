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


def test_driver_forward_close_invoked_when_available() -> None:
    config = SessionConfig()
    events: List[str] = []

    class DummyDriver:
        def open(self) -> None:
            events.append("open")

        def forward_open(self) -> None:
            events.append("forward_open")

        def forward_close(self) -> None:
            events.append("forward_close")

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
    assert events == ["tcp", "open", "forward_open", "forward_close", "close"]


def test_driver_factory_failure_records_enip_step() -> None:
    config = SessionConfig()

    def connector(_: SessionConfig) -> None:
        return None

    def driver_factory(_: SessionConfig):
        raise RuntimeError("driver unavailable")

    result = perform_handshake(
        config,
        simulate=False,
        tcp_connector=connector,
        driver_factory=driver_factory,
    )

    assert not result.success
    assert result.error == "driver unavailable"
    assert result.steps[-1].phase == HandshakePhase.ENIP_SESSION
    assert not result.steps[-1].success
    assert result.steps[-1].detail == "driver unavailable"


def test_open_failure_marks_enip_step_failed() -> None:
    config = SessionConfig()
    events: List[str] = []

    class DummyDriver:
        def open(self) -> None:
            events.append("open")
            raise RuntimeError("open failure")

        def forward_open(self) -> None:  # pragma: no cover - should not be called
            raise AssertionError("forward_open should not run when open fails")

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

    assert not result.success
    assert result.error == "open failure"
    assert [step.phase for step in result.steps] == [
        HandshakePhase.TCP_CONNECT,
        HandshakePhase.ENIP_SESSION,
    ]
    assert not result.steps[-1].success
    assert result.steps[-1].detail == "open failure"
    assert events == ["tcp", "open", "close"]
