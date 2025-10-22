from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pycipsim.device import DeviceProfile, ServiceRequest
from pycipsim.engine import SimulationScenario, SimulationStep
from pycipsim.session import CIPSession, SessionConfig


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
