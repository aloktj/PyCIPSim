from __future__ import annotations

import copy

from pycipsim.configuration import (
    AssemblyDefinition,
    SignalDefinition,
    SimulatorConfiguration,
    build_assembly_payload,
)
from pycipsim.device import ServiceResponse
from pycipsim.runtime import CIPIORuntime


class DummySession:
    def __init__(self) -> None:
        self.connected = False
        self.sent_requests = []
        self.next_responses: list[ServiceResponse] = []

    def connect(self) -> None:
        self.connected = True

    def disconnect(self) -> None:
        self.connected = False

    def send(self, request):
        self.sent_requests.append(request)
        if not self.next_responses:
            raise AssertionError("No response queued for request")
        return self.next_responses.pop(0)


class DummyStore:
    def __init__(self) -> None:
        self.calls = []

    def update_input_values(self, name, assembly_id, values, *, persist):
        self.calls.append((name, assembly_id, values, persist))


def _make_config(*assemblies: AssemblyDefinition) -> SimulatorConfiguration:
    return SimulatorConfiguration(
        name="DemoConfig",
        target_ip="127.0.0.1",
        assemblies=list(assemblies),
    )


def test_runtime_pushes_updated_outputs() -> None:
    output_assembly = AssemblyDefinition(
        assembly_id=0x64,
        name="Outputs",
        direction="output",
        size_bits=16,
        signals=[
            SignalDefinition(
                name="OutValue",
                offset=0,
                signal_type="INT",
                value="5",
            )
        ],
    )

    config = _make_config(output_assembly)
    session = DummySession()
    store = DummyStore()
    runtime = CIPIORuntime(config, store, session)

    session.next_responses.append(ServiceResponse(service="SET_ASSEMBLY", status="SUCCESS"))
    runtime._push_outputs()

    assert len(session.sent_requests) == 1
    request = session.sent_requests[0]
    assert request.service_code == "SET_ASSEMBLY"
    assert request.tag_path == "assembly/100"
    assert request.payload == build_assembly_payload(output_assembly)

    # Without changing any values the runtime should not retransmit the payload.
    runtime._push_outputs()
    assert len(session.sent_requests) == 1


def test_runtime_updates_store_with_received_inputs() -> None:
    input_signal = SignalDefinition(
        name="InValue",
        offset=0,
        signal_type="UINT",
    )
    input_assembly = AssemblyDefinition(
        assembly_id=0xC8,
        name="Inputs",
        direction="input",
        size_bits=16,
        signals=[input_signal],
    )

    config = _make_config(input_assembly)
    session = DummySession()
    store = DummyStore()
    runtime = CIPIORuntime(config, store, session)

    payload_assembly = copy.deepcopy(input_assembly)
    payload_assembly.signals[0].value = "321"
    payload = build_assembly_payload(payload_assembly)

    session.next_responses.append(
        ServiceResponse(service="GET_ASSEMBLY", status="SUCCESS", payload=payload)
    )
    runtime._pull_inputs()

    assert len(session.sent_requests) == 1
    request = session.sent_requests[0]
    assert request.service_code == "GET_ASSEMBLY"
    assert request.tag_path == "assembly/200"

    assert store.calls == [("DemoConfig", 0xC8, {"InValue": "321"}, False)]
