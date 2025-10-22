from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pycipsim.device import DeviceProfile, ServiceRequest, ServiceResponse
from pycipsim.engine import SimulationScenario, SimulationStep
from pycipsim.session import CIPSession, SessionConfig, TransportError


def test_scenario_with_echo_profile():
    profile = DeviceProfile.echo_profile()
    session = CIPSession(config=SessionConfig(), profile=profile)
    steps = [
        SimulationStep(
            request=ServiceRequest(service_code="ECHO", tag_path="TagA", payload=b"Hello"),
            expected_status="SUCCESS",
            description="Echo hello",
        )
    ]

    with session.lifecycle():
        result = SimulationScenario(session=session, steps=steps).execute()

    assert result.success
    assert result.responses[0].payload == b"Hello"
    assert result.metrics.success_count == 1
    assert result.metrics.failure_count == 0
    assert result.metrics.status_counts["SUCCESS"] == 1
    history = session.history()
    assert len(history) == 1
    recorded_request, recorded_response = history[0]
    assert recorded_request.payload == b"Hello"
    assert recorded_response.status == "SUCCESS"


def test_scenario_detects_failure():
    profile = DeviceProfile.echo_profile()
    session = CIPSession(config=SessionConfig(), profile=profile)
    steps = [
        SimulationStep(
            request=ServiceRequest(service_code="ECHO", tag_path="TagA", payload=b"Hello"),
            expected_status="BAD_STATUS",
        )
    ]

    with session.lifecycle():
        result = SimulationScenario(session=session, steps=steps).execute()

    assert not result.success
    assert result.metrics.failure_count == 1
    assert result.metrics.completed_steps == 1


def test_session_blocks_non_whitelisted_host():
    config = SessionConfig(ip_address="10.0.0.25")
    session = CIPSession(config=config)

    with pytest.raises(TransportError):
        session.connect()


class _DummyTransport:
    def __init__(self) -> None:
        self.connected = False

    def connect(self) -> None:
        self.connected = True

    def disconnect(self) -> None:
        self.connected = False

    def send(self, request: ServiceRequest) -> ServiceResponse:
        return ServiceResponse(service=request.service_code, status="SUCCESS", payload=request.payload)


def test_allow_external_flag_permits_connections():
    transport = _DummyTransport()
    config = SessionConfig(ip_address="10.0.0.25", allow_external=True)
    session = CIPSession(config=config, transport=transport)

    session.connect()
    response = session.send(ServiceRequest(service_code="PING", tag_path="Tag", payload=b"hi"))
    assert response.status == "SUCCESS"
    session.disconnect()
