from __future__ import annotations

import copy
import time

import pytest

from pycipsim.config_store import ConfigurationStore
from pycipsim.configuration import (
    AssemblyDefinition,
    SimulatorConfiguration,
    SignalDefinition,
    build_assembly_payload,
    parse_assembly_payload,
)
from pycipsim.device import ServiceRequest
from pycipsim.runtime import CIPIORuntime
from pycipsim.session import CIPSession, SessionConfig


def _value_snapshot(store: ConfigurationStore, config_name: str, assembly_id: int) -> dict[str, str | None]:
    configuration = store.get(config_name)
    assembly = configuration.find_assembly(assembly_id)
    values: dict[str, str | None] = {}
    for signal in assembly.signals:
        if signal.is_padding:
            continue
        values[signal.name] = signal.value
    return values


def _originator_configuration(name: str, target_ip: str, target_port: int) -> SimulatorConfiguration:
    assemblies = [
        AssemblyDefinition(
            name="O_T",
            assembly_id=0x64,
            direction="output",
            size_bits=16,
            signals=[
                SignalDefinition(
                    name="Value",
                    offset=0,
                    signal_type="INT",
                    value="515",
                    size_bits=16,
                )
            ],
        ),
        AssemblyDefinition(
            name="T_O",
            assembly_id=0x65,
            direction="input",
            size_bits=16,
            signals=[
                SignalDefinition(
                    name="Value",
                    offset=0,
                    signal_type="INT",
                    value="0",
                    size_bits=16,
                )
            ],
        ),
    ]
    for assembly in assemblies:
        assembly.rebuild_padding()
    return SimulatorConfiguration(
        name=name,
        target_ip=target_ip,
        target_port=target_port,
        runtime_mode="live",
        role="originator",
        transport="pycomm3",
        assemblies=assemblies,
    )


@pytest.mark.integration
def test_pycomm3_originator_cycles_io(enip_target_runtime, tmp_path):
    pytest.importorskip("pycomm3")

    runtime, target_store = enip_target_runtime
    target_config = target_store.get("enip-target")

    originator_store = ConfigurationStore(storage_path=tmp_path / "originator.json")
    originator_config = _originator_configuration(
        name="originator",
        target_ip="127.0.0.1",
        target_port=runtime.tcp_port,
    )
    originator_store.upsert(originator_config)

    session_config = SessionConfig(
        ip_address="127.0.0.1",
        port=runtime.tcp_port,
        timeout=2.0,
        retries=1,
        allowed_hosts=("127.0.0.1",),
        transport="pycomm3",
    )
    session = CIPSession(session_config)
    originator_runtime = CIPIORuntime(
        configuration=originator_config,
        store=originator_store,
        session=session,
        cycle_interval=0.05,
    )
    originator_runtime.start()
    try:
        # Allow the runtime to establish connections and perform initial cycles.
        time.sleep(0.5)

        target_values = _value_snapshot(target_store, "enip-target", 0x64)
        assert target_values["Value"] == "515"

        target_store.update_assembly_values("enip-target", 0x65, {"Value": "902"})
        runtime.notify_output_update()

        deadline = time.time() + 3.0
        originator_values: dict[str, str | None] = {}
        while time.time() < deadline:
            originator_values = _value_snapshot(originator_store, "originator", 0x65)
            if originator_values.get("Value") == "902":
                break
            time.sleep(0.05)
        assert originator_values.get("Value") == "902"
    finally:
        originator_runtime.stop()

    # Connected GET requests should return the latest payload.
    verification_session = CIPSession(
        SessionConfig(
            ip_address="127.0.0.1",
            port=runtime.tcp_port,
            timeout=2.0,
            retries=1,
            allowed_hosts=("127.0.0.1",),
            transport="pycomm3",
        )
    )
    with verification_session.lifecycle():
        response = verification_session.send(
            ServiceRequest(
                service_code="GET_ASSEMBLY",
                tag_path="assembly/0x65",
                metadata={"instance": "0x65", "connected": True},
            )
        )
        assert response.status == "SUCCESS"
        payload = response.payload or b""
        parsed = parse_assembly_payload(target_config.find_assembly(0x65), payload)
        assert parsed["Value"] == "902"

        output_template = copy.deepcopy(target_config.find_assembly(0x64))
        for signal in output_template.signals:
            if signal.is_padding:
                continue
            signal.value = "777"
        payload_bytes = build_assembly_payload(output_template)
        response = verification_session.send(
            ServiceRequest(
                service_code="SET_ASSEMBLY",
                tag_path="assembly/0x64",
                payload=payload_bytes,
                metadata={"instance": "0x64", "connected": True},
            )
        )
        assert response.status == "SUCCESS"

    updated_values = _value_snapshot(target_store, "enip-target", 0x64)
    assert updated_values["Value"] == "777"
