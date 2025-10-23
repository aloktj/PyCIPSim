from __future__ import annotations

import json
import time
from pathlib import Path
from typing import List

import pytest
from fastapi.testclient import TestClient

from pycipsim.config_store import ConfigurationStore, SimulatorConfiguration
from pycipsim.device import ServiceResponse
from pycipsim.session import CIPSession, SessionConfig
from pycipsim.web.app import SimulatorManager, get_app


class _StubTransport:
    def __init__(self, configuration: SimulatorConfiguration) -> None:
        self._configuration = configuration
        self.connected = False
        self.output_payloads: dict[int, bytes] = {}
        self.input_payloads: dict[int, bytes] = {}
        self.requests: List[str] = []

    def connect(self) -> None:
        self.connected = True

    def disconnect(self) -> None:
        self.connected = False

    def send(self, request):  # type: ignore[override]
        metadata = request.metadata or {}
        instance_raw = metadata.get("instance")
        instance_id = int(str(instance_raw), 0) if instance_raw is not None else 0
        self.requests.append(request.service_code)
        if request.service_code == "SET_ASSEMBLY":
            self.output_payloads[instance_id] = request.payload or b""
            return ServiceResponse(service=request.service_code, status="SUCCESS")
        if request.service_code == "GET_ASSEMBLY":
            payload = self.input_payloads.get(instance_id)
            if payload is None:
                assembly = self._configuration.find_assembly(instance_id)
                payload = bytes((assembly.size_bits + 7) // 8)
            return ServiceResponse(service=request.service_code, status="SUCCESS", payload=payload)
        return ServiceResponse(service=request.service_code, status="SUCCESS")


@pytest.fixture(autouse=True)
def fake_interfaces(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "pycipsim.web.app._detect_network_interfaces",
        lambda: [{"name": "eth0", "label": "eth0"}],
    )


@pytest.fixture()
def store(tmp_path: Path) -> ConfigurationStore:
    return ConfigurationStore(storage_path=tmp_path / "configs.json")


@pytest.fixture()
def manager(store: ConfigurationStore):
    transports: List[_StubTransport] = []

    def factory(session_config: SessionConfig, sim_config: SimulatorConfiguration) -> CIPSession:
        transport = _StubTransport(sim_config)
        transports.append(transport)
        session = CIPSession(session_config, transport=transport)
        session.config.allow_external = True
        session.config.allowed_hosts = tuple(list(session.config.allowed_hosts) + [session_config.ip_address])
        return session

    manager = SimulatorManager(
        session_factory=factory,
        cycle_interval=0.01,
        simulate_handshake=True,
    )
    setattr(manager, "_test_transports", transports)
    yield manager
    manager.stop()


def _scenario_payload(name: str = "WebConfig") -> dict:
    return {
        "name": name,
        "target": {
            "ip": "10.10.10.10",
            "port": 44818,
            "interface": "eth0",
            "mode": "live",
        },
        "assemblies": [
            {
                "id": 200,
                "name": "Outputs",
                "direction": "output",
                "size_bits": 8,
                "signals": [
                    {"name": "SigA", "offset": 0, "type": "BOOL", "value": "0"},
                ],
            }
        ],
    }


def test_upload_and_start_flow(
    store: ConfigurationStore, manager: SimulatorManager
) -> None:
    app = get_app(store=store, manager=manager)
    client = TestClient(app)

    payload = json.dumps(_scenario_payload()).encode("utf-8")
    response = client.post(
        "/configs/upload",
        files={"file": ("config.json", payload, "application/json")},
        follow_redirects=False,
    )
    assert response.status_code == 303
    first = list(store.list())[0]
    assert first.name == "WebConfig"
    assert first.network_interface == "eth0"

    start_response = client.post("/configs/WebConfig/start", follow_redirects=False)
    assert start_response.status_code == 303
    assert manager.active() is not None
    assert manager.active().runtime is not None

    value_response = client.post(
        "/configs/WebConfig/assemblies/200/signals/SigA/value",
        data={"value": "1", "action": "set"},
        follow_redirects=False,
    )
    assert value_response.status_code == 303
    config = store.get("WebConfig")
    assert config.find_signal(200, "SigA").value == "1"

    transports = getattr(manager, "_test_transports")
    assert transports
    transport = transports[0]
    for _ in range(50):
        if transport.output_payloads.get(200) == b"\x01":
            break
        time.sleep(0.02)
    assert transport.output_payloads.get(200) == b"\x01"


def test_update_target_via_web(
    store: ConfigurationStore, manager: SimulatorManager
) -> None:
    config = SimulatorConfiguration.from_dict(_scenario_payload())
    store.upsert(config)
    app = get_app(store=store, manager=manager)
    client = TestClient(app)

    response = client.post(
        "/configs/WebConfig/target",
        data={
            "target_ip": "10.0.0.20",
            "target_port": "44818",
            "receive_address": "",
            "multicast": "",
            "network_interface": "eth0",
            "runtime_mode": "simulated",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    refreshed = store.get("WebConfig")
    assert refreshed.target_ip == "10.0.0.20"
    assert refreshed.network_interface == "eth0"
    assert refreshed.runtime_mode == "simulated"


def test_start_simulated_mode_skips_runtime(
    store: ConfigurationStore, manager: SimulatorManager
) -> None:
    payload = _scenario_payload()
    payload["target"]["mode"] = "simulated"
    config = SimulatorConfiguration.from_dict(payload)
    store.upsert(config)
    app = get_app(store=store, manager=manager)
    client = TestClient(app)

    response = client.post("/configs/WebConfig/start", follow_redirects=False)
    assert response.status_code == 303
    active = manager.active()
    assert active is not None
    assert active.runtime is None


def test_type_update_blocked_when_running(
    store: ConfigurationStore, manager: SimulatorManager
) -> None:
    config = SimulatorConfiguration.from_dict(_scenario_payload())
    store.upsert(config)
    manager.start(config, store)
    app = get_app(store=store, manager=manager)
    client = TestClient(app)

    response = client.post(
        "/configs/WebConfig/assemblies/200/signals/SigA/details",
        data={"new_name": "SigA", "offset": "0", "signal_type": "INT"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "error=" in response.headers["location"]
    config_after = store.get("WebConfig")
    assert config_after.find_signal(200, "SigA").signal_type == "BOOL"


def test_invalid_signal_type_rejected(
    store: ConfigurationStore, manager: SimulatorManager
) -> None:
    config = SimulatorConfiguration.from_dict(_scenario_payload())
    store.upsert(config)
    app = get_app(store=store, manager=manager)
    client = TestClient(app)

    response = client.post(
        "/configs/WebConfig/assemblies/200/signals/SigA/details",
        data={"new_name": "SigA", "offset": "0", "signal_type": "Invalid"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=" in response.headers["location"]
    assert store.get("WebConfig").find_signal(200, "SigA").signal_type == "BOOL"


def test_value_update_rejected_for_input_assembly(
    store: ConfigurationStore, manager: SimulatorManager
) -> None:
    payload = _scenario_payload()
    payload["assemblies"][0]["direction"] = "input"
    config = SimulatorConfiguration.from_dict(payload)
    store.upsert(config)
    app = get_app(store=store, manager=manager)
    client = TestClient(app)

    response = client.post(
        "/configs/WebConfig/assemblies/200/signals/SigA/value",
        data={"value": "1", "action": "set"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "error=" in response.headers["location"]
    config_after = store.get("WebConfig")
    assert config_after.find_signal(200, "SigA").value == "0"


def test_remove_signal_from_web(
    store: ConfigurationStore, manager: SimulatorManager
) -> None:
    config = SimulatorConfiguration.from_dict(_scenario_payload())
    store.upsert(config)
    app = get_app(store=store, manager=manager)
    client = TestClient(app)

    response = client.post(
        "/configs/WebConfig/assemblies/200/signals/SigA/delete",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assembly = store.get("WebConfig").find_assembly(200)
    assert assembly.signals == []


def test_update_assembly_metadata_via_web(
    store: ConfigurationStore, manager: SimulatorManager
) -> None:
    payload = _scenario_payload()
    payload["assemblies"].append(
        {
            "id": 201,
            "name": "Inputs",
            "direction": "output",
            "signals": [],
        }
    )
    config = SimulatorConfiguration.from_dict(payload)
    store.upsert(config)
    app = get_app(store=store, manager=manager)
    client = TestClient(app)

    response = client.post(
        "/configs/WebConfig/assemblies/200/metadata",
        data={"new_id": "300", "direction": "input", "size_bits": "8"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    refreshed = store.get("WebConfig")
    assert refreshed.find_assembly(300).direction == "input"


def test_assembly_metadata_update_blocked_when_running(
    store: ConfigurationStore, manager: SimulatorManager
) -> None:
    config = SimulatorConfiguration.from_dict(_scenario_payload())
    store.upsert(config)
    manager.start(config, store)
    app = get_app(store=store, manager=manager)
    client = TestClient(app)

    response = client.post(
        "/configs/WebConfig/assemblies/200/metadata",
        data={"new_id": "250", "direction": "output", "size_bits": "8"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=" in response.headers["location"]
    assert store.get("WebConfig").find_assembly(200).assembly_id == 200


def test_index_groups_assemblies_by_direction(
    store: ConfigurationStore, manager: SimulatorManager
) -> None:
    payload = _scenario_payload()
    payload["assemblies"].append(
        {
            "id": 210,
            "name": "SecondOutput",
            "direction": "output",
            "signals": [],
        }
    )
    payload["assemblies"].append(
        {
            "id": 310,
            "name": "InputOne",
            "direction": "input",
            "signals": [],
        }
    )
    config = SimulatorConfiguration.from_dict(payload)
    store.upsert(config)
    app = get_app(store=store, manager=manager)
    client = TestClient(app)

    response = client.get("/")
    assert response.status_code == 200
    html = response.text
    assert "Output Assemblies" in html
    assert "Input Assemblies" in html
    output_section = html.split("Output Assemblies", 1)[1].split("Input Assemblies", 1)[0]
    assert "Assembly Outputs (#200" in output_section
    assert "Assembly SecondOutput (#210)" in output_section
    input_section = html.split("Input Assemblies", 1)[1]
    assert "Assembly InputOne (#310)" in input_section


def test_add_and_remove_assembly_via_web(
    store: ConfigurationStore, manager: SimulatorManager
) -> None:
    config = SimulatorConfiguration.from_dict(_scenario_payload())
    store.upsert(config)
    app = get_app(store=store, manager=manager)
    client = TestClient(app)

    response = client.post(
        "/configs/WebConfig/assemblies/add",
        data={
            "assembly_id": "300",
            "assembly_name": "Extra",
            "direction": "input",
            "size_bits": "8",
            "position": "after",
            "relative_assembly": "200",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303

    added = store.get("WebConfig").find_assembly(300)
    assert added.direction == "input"

    remove_response = client.post(
        "/configs/WebConfig/assemblies/300/delete",
        follow_redirects=False,
    )
    assert remove_response.status_code == 303

    refreshed = store.get("WebConfig")
    assert all(assembly.assembly_id != 300 for assembly in refreshed.assemblies)


def test_add_assembly_blocked_when_running(
    store: ConfigurationStore, manager: SimulatorManager
) -> None:
    config = SimulatorConfiguration.from_dict(_scenario_payload())
    store.upsert(config)
    manager.start(config, store)
    app = get_app(store=store, manager=manager)
    client = TestClient(app)

    response = client.post(
        "/configs/WebConfig/assemblies/add",
        data={
            "assembly_id": "300",
            "assembly_name": "Blocked",
            "direction": "output",
            "size_bits": "8",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=" in response.headers["location"]
    refreshed = store.get("WebConfig")
    assert all(assembly.assembly_id != 300 for assembly in refreshed.assemblies)


def test_input_poll_updates_store(store: ConfigurationStore, manager: SimulatorManager) -> None:
    payload = _scenario_payload()
    payload["assemblies"][0]["direction"] = "input"
    payload["assemblies"][0]["signals"][0]["value"] = "0"
    config = SimulatorConfiguration.from_dict(payload)
    store.upsert(config)

    manager.start(config, store)
    transports = getattr(manager, "_test_transports")
    transport = transports[0]
    transport.input_payloads[200] = b"\x01"

    for _ in range(50):
        if store.get("WebConfig").find_signal(200, "SigA").value == "1":
            break
        time.sleep(0.02)

    assert store.get("WebConfig").find_signal(200, "SigA").value == "1"
    manager.stop()
