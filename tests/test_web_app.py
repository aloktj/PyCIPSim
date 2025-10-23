from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from pycipsim.config_store import ConfigurationStore, SimulatorConfiguration
from pycipsim.web.app import SimulatorManager, get_app


@pytest.fixture()
def store(tmp_path: Path) -> ConfigurationStore:
    return ConfigurationStore(storage_path=tmp_path / "configs.json")


def _scenario_payload(name: str = "WebConfig") -> dict:
    return {
        "name": name,
        "target": {"ip": "10.10.10.10", "port": 44818},
        "assemblies": [
            {
                "id": 200,
                "name": "Outputs",
                "direction": "output",
                "signals": [
                    {"name": "SigA", "offset": 0, "type": "BOOL", "value": "0"},
                ],
            }
        ],
    }


def test_upload_and_start_flow(store: ConfigurationStore) -> None:
    manager = SimulatorManager()
    app = get_app(store=store, manager=manager)
    client = TestClient(app)

    payload = json.dumps(_scenario_payload()).encode("utf-8")
    response = client.post(
        "/configs/upload",
        files={"file": ("config.json", payload, "application/json")},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert list(store.list())[0].name == "WebConfig"

    start_response = client.post("/configs/WebConfig/start", follow_redirects=False)
    assert start_response.status_code == 303
    assert manager.active() is not None

    value_response = client.post(
        "/configs/WebConfig/assemblies/200/signals/SigA/value",
        data={"value": "1", "action": "set"},
        follow_redirects=False,
    )
    assert value_response.status_code == 303
    config = store.get("WebConfig")
    assert config.find_signal(200, "SigA").value == "1"


def test_type_update_blocked_when_running(store: ConfigurationStore) -> None:
    manager = SimulatorManager()
    config = SimulatorConfiguration.from_dict(_scenario_payload())
    store.upsert(config)
    manager.start(config)
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


def test_value_update_rejected_for_input_assembly(store: ConfigurationStore) -> None:
    manager = SimulatorManager()
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


def test_remove_signal_from_web(store: ConfigurationStore) -> None:
    manager = SimulatorManager()
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


def test_update_assembly_metadata_via_web(store: ConfigurationStore) -> None:
    manager = SimulatorManager()
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
        data={"new_id": "300", "direction": "input"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    refreshed = store.get("WebConfig")
    assert refreshed.find_assembly(300).direction == "input"


def test_assembly_metadata_update_blocked_when_running(store: ConfigurationStore) -> None:
    manager = SimulatorManager()
    config = SimulatorConfiguration.from_dict(_scenario_payload())
    store.upsert(config)
    manager.start(config)
    app = get_app(store=store, manager=manager)
    client = TestClient(app)

    response = client.post(
        "/configs/WebConfig/assemblies/200/metadata",
        data={"new_id": "250", "direction": "output"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=" in response.headers["location"]
    assert store.get("WebConfig").find_assembly(200).assembly_id == 200


def test_index_groups_assemblies_by_direction(store: ConfigurationStore) -> None:
    manager = SimulatorManager()
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
    assert "Assembly Outputs (#200)" in output_section
    assert "Assembly SecondOutput (#210)" in output_section
    input_section = html.split("Input Assemblies", 1)[1]
    assert "Assembly InputOne (#310)" in input_section


def test_add_and_remove_assembly_via_web(store: ConfigurationStore) -> None:
    manager = SimulatorManager()
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


def test_add_assembly_blocked_when_running(store: ConfigurationStore) -> None:
    manager = SimulatorManager()
    config = SimulatorConfiguration.from_dict(_scenario_payload())
    store.upsert(config)
    manager.start(config)
    app = get_app(store=store, manager=manager)
    client = TestClient(app)

    response = client.post(
        "/configs/WebConfig/assemblies/add",
        data={
            "assembly_id": "300",
            "assembly_name": "Blocked",
            "direction": "output",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=" in response.headers["location"]
    refreshed = store.get("WebConfig")
    assert all(assembly.assembly_id != 300 for assembly in refreshed.assemblies)
