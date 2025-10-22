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
