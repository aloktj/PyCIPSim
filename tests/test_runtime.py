from __future__ import annotations

import contextlib
import copy
import socket

from pycipsim.config_store import ConfigurationStore
from pycipsim.configuration import (
    AssemblyDefinition,
    SignalDefinition,
    SimulatorConfiguration,
    build_assembly_payload,
    parse_assembly_payload,
)
from pycipsim.device import ServiceResponse
from pycipsim.runtime.cip_io import CIPIORuntime
from pycipsim.target import CIPTargetRuntime
from pycipsim.target_protocol import MSG_DATA, TargetMessage


class DummySession:
    def __init__(self) -> None:
        self.connected = False
        self.sent_requests = []
        self.next_responses: list[ServiceResponse] = []
        self.listener = None

    def connect(self) -> None:
        self.connected = True

    def disconnect(self) -> None:
        self.connected = False

    def send(self, request):
        self.sent_requests.append(request)
        if not self.next_responses:
            raise AssertionError("No response queued for request")
        return self.next_responses.pop(0)

    def register_update_listener(self, callback):
        self.listener = callback


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


def _reserve_udp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


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


def test_runtime_handles_async_input_updates() -> None:
    input_signal = SignalDefinition(
        name="InValue",
        offset=0,
        signal_type="UINT",
    )
    input_assembly = AssemblyDefinition(
        assembly_id=0xD2,
        name="Inputs",
        direction="input",
        size_bits=16,
        signals=[input_signal],
    )

    config = _make_config(input_assembly)
    session = DummySession()
    store = DummyStore()
    runtime = CIPIORuntime(config, store, session)
    runtime._output_ids = []
    runtime._input_ids = []

    runtime.start()
    try:
        assert session.listener is not None

        payload_assembly = copy.deepcopy(input_assembly)
        payload_assembly.signals[0].value = "654"
        payload = build_assembly_payload(payload_assembly)

        session.listener(input_assembly.assembly_id, payload)

        assert store.calls == [("DemoConfig", 0xD2, {"InValue": "654"}, False)]
    finally:
        runtime.stop()


def test_target_runtime_multicast_broadcast(tmp_path) -> None:
    group = "239.255.0.1"
    port = _reserve_udp_port()

    input_signal = SignalDefinition(
        name="InValue",
        offset=0,
        signal_type="UINT",
        value="123",
        size_bits=16,
    )
    input_assembly = AssemblyDefinition(
        assembly_id=0xC9,
        name="Inputs",
        direction="input",
        size_bits=16,
        signals=[input_signal],
    )
    input_assembly.rebuild_padding()

    store = ConfigurationStore(storage_path=tmp_path / "config.json")
    config = SimulatorConfiguration(
        name="MulticastDemo",
        target_ip="127.0.0.1",
        target_port=port,
        receive_address=group,
        multicast=True,
        assemblies=[input_assembly],
    )
    store.upsert(config)

    runtime = CIPTargetRuntime(config, store, cycle_interval=0.05)
    runtime.start()
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("", port))
        membership = socket.inet_aton(group) + socket.inet_aton("127.0.0.1")
        listener.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
        listener.settimeout(2.0)

        # Drain the initial broadcast payload to ensure the runtime is active.
        initial_payload, _ = listener.recvfrom(4096)
        initial_message = TargetMessage.decode(initial_payload)
        assert initial_message.message_type == MSG_DATA

        store.update_assembly_values("MulticastDemo", input_assembly.assembly_id, {"InValue": "999"})
        runtime.notify_output_update()

        payload, _ = listener.recvfrom(4096)
        message = TargetMessage.decode(payload)
        assert message.message_type == MSG_DATA
        assert message.assembly_id == input_assembly.assembly_id
        decoded = parse_assembly_payload(config.find_assembly(input_assembly.assembly_id), message.payload)
        assert decoded["InValue"] == "999"
    finally:
        with contextlib.suppress(OSError):
            listener.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, membership)
        listener.close()
        runtime.stop()
