import copy
import threading

from pycipsim.config_store import ConfigurationStore
from pycipsim.configuration import (
    AssemblyDefinition,
    SimulatorConfiguration,
    SignalDefinition,
    build_assembly_payload,
    parse_assembly_payload,
)
from pycipsim.session import CIPSession, SessionConfig
from pycipsim.target import CIPTargetRuntime
from pycipsim.device import ServiceRequest


def _make_assembly(name: str, assembly_id: int, direction: str, value: str) -> AssemblyDefinition:
    assembly = AssemblyDefinition(
        name=name,
        assembly_id=assembly_id,
        direction=direction,
        size_bits=16,
        signals=[
            SignalDefinition(name="Value", offset=0, signal_type="INT", value=value, size_bits=16)
        ],
    )
    assembly.rebuild_padding()
    return assembly


def test_originator_transport_exchanges_with_target(tmp_path) -> None:
    store_path = tmp_path / "config.json"
    store = ConfigurationStore(storage_path=store_path)
    config = SimulatorConfiguration(
        name="target",
        target_ip="127.0.0.1",
        target_port=51234,
        runtime_mode="live",
        role="target",
        transport="pycipsim",
        assemblies=[
            _make_assembly("OriginatorToTarget", 100, "output", "0"),
            _make_assembly("TargetToOriginator", 200, "input", "123"),
        ],
    )
    store.upsert(config)

    target_runtime = CIPTargetRuntime(config, store, cycle_interval=0.05)
    target_runtime.start()
    try:
        session_config = SessionConfig(
            ip_address="127.0.0.1",
            port=config.target_port,
            timeout=1.0,
            retries=1,
            allowed_hosts=("127.0.0.1",),
            transport="pycipsim",
        )
        session = CIPSession(session_config)
        with session.lifecycle():
            updates: dict[int, bytes] = {}
            event = threading.Event()

            def _listener(assembly_id: int, payload: bytes) -> None:
                updates[assembly_id] = payload
                event.set()

            session.register_update_listener(_listener)

            response = session.send(
                ServiceRequest(
                    service_code="GET_ASSEMBLY",
                    tag_path="assembly/200",
                    metadata={"instance": 200},
                )
            )
            assert response.status == "SUCCESS"
            decoded = parse_assembly_payload(
                store.get("target").find_assembly(200), response.payload or b""
            )
            assert decoded["Value"] == "123"

            target_config = store.get("target")
            output_assembly = target_config.find_assembly(100)
            original_signals = copy.deepcopy(output_assembly.signals)
            try:
                for signal in output_assembly.signals:
                    if signal.is_padding:
                        continue
                    signal.value = "321"
                payload = build_assembly_payload(output_assembly)
            finally:
                output_assembly.signals = original_signals
            response = session.send(
                ServiceRequest(
                    service_code="SET_ASSEMBLY",
                    tag_path="assembly/100",
                    payload=payload,
                    metadata={"instance": 100},
                )
            )
            assert response.status == "SUCCESS"
            refreshed = store.get("target").find_assembly(100)
            refreshed_values = {sig.name: sig.value for sig in refreshed.signals if not sig.is_padding}
            assert refreshed_values["Value"] == "321"

            store.update_assembly_values("target", 200, {"Value": "456"})
            event.clear()
            target_runtime.notify_output_update()
            assert event.wait(2.0)
            pushed = updates[200]
            broadcast = parse_assembly_payload(store.get("target").find_assembly(200), pushed)
            assert broadcast["Value"] == "456"
    finally:
        target_runtime.stop()
