from __future__ import annotations

from pathlib import Path

from pycipsim.config_store import ConfigurationStore, SimulatorConfiguration


def _sample_configuration() -> SimulatorConfiguration:
    data = {
        "name": "DemoConfig",
        "target": {
            "ip": "192.168.1.10",
            "port": 44818,
            "receive_address": "239.1.1.1",
            "multicast": True,
        },
        "assemblies": [
            {
                "id": 100,
                "name": "Input",
                "direction": "input",
                "signals": [
                    {"name": "SignalA", "offset": 0, "type": "BOOL", "value": "0"},
                    {"name": "SignalB", "offset": 1, "type": "INT", "value": "5"},
                ],
            }
        ],
    }
    return SimulatorConfiguration.from_dict(data)


def test_upsert_and_reload(tmp_path: Path) -> None:
    storage = tmp_path / "configs.json"
    store = ConfigurationStore(storage_path=storage)
    config = _sample_configuration()
    store.upsert(config)

    reloaded = ConfigurationStore(storage_path=storage)
    configs = list(reloaded.list())
    assert len(configs) == 1
    assert configs[0].name == "DemoConfig"
    assert configs[0].target_ip == "192.168.1.10"


def test_signal_updates_persist(tmp_path: Path) -> None:
    storage = tmp_path / "configs.json"
    store = ConfigurationStore(storage_path=storage)
    config = _sample_configuration()
    store.upsert(config)

    store.update_signal_value("DemoConfig", 100, "SignalA", "1")
    store.update_signal_type("DemoConfig", 100, "SignalB", "DINT")

    reloaded = ConfigurationStore(storage_path=storage)
    updated = reloaded.get("DemoConfig")
    signal_a = updated.find_signal(100, "SignalA")
    assert signal_a.value == "1"
    signal_b = updated.find_signal(100, "SignalB")
    assert signal_b.signal_type == "DINT"
    assert signal_b.value is None
