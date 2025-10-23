from __future__ import annotations

from pathlib import Path

import pytest

from pycipsim.config_store import (
    ConfigurationError,
    ConfigurationStore,
    SimulatorConfiguration,
)
from pycipsim.configuration import AssemblyDefinition


def _sample_configuration(*, direction: str = "input") -> SimulatorConfiguration:
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
                "direction": direction,
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
    config = _sample_configuration(direction="output")
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


def test_signal_type_validation(tmp_path: Path) -> None:
    storage = tmp_path / "configs.json"
    store = ConfigurationStore(storage_path=storage)
    config = _sample_configuration(direction="output")
    store.upsert(config)

    with pytest.raises(ConfigurationError):
        store.update_signal_type("DemoConfig", 100, "SignalA", "NotAType")

    store.add_signal(
        "DemoConfig",
        100,
        new_name="SignalC",
        offset="2",
        signal_type="bool",
        position="after",
        relative_signal="SignalB",
    )

    refreshed = store.get("DemoConfig")
    signal_c = refreshed.find_signal(100, "SignalC")
    assert signal_c.signal_type == "BOOL"


def test_signal_value_update_blocked_for_input(tmp_path: Path) -> None:
    storage = tmp_path / "configs.json"
    store = ConfigurationStore(storage_path=storage)
    config = _sample_configuration(direction="input")
    store.upsert(config)

    with pytest.raises(ConfigurationError):
        store.update_signal_value("DemoConfig", 100, "SignalA", "1")


def test_remove_signal_persists(tmp_path: Path) -> None:
    storage = tmp_path / "configs.json"
    store = ConfigurationStore(storage_path=storage)
    config = _sample_configuration(direction="output")
    store.upsert(config)

    store.remove_signal("DemoConfig", 100, "SignalA")

    reloaded = ConfigurationStore(storage_path=storage)
    updated = reloaded.get("DemoConfig")
    remaining = [signal.name for signal in updated.find_assembly(100).signals]
    assert remaining == ["SignalB"]


def test_update_assembly_metadata(tmp_path: Path) -> None:
    storage = tmp_path / "configs.json"
    store = ConfigurationStore(storage_path=storage)
    config = _sample_configuration(direction="output")
    config.assemblies.append(
        AssemblyDefinition(
            assembly_id=200,
            name="Second",
            direction="input",
            signals=[],
        )
    )
    store.upsert(config)

    updated = store.update_assembly(
        "DemoConfig",
        100,
        new_id="300",
        direction="input",
    )

    assert updated.assembly_id == 300
    assert updated.direction == "input"

    reloaded = ConfigurationStore(storage_path=storage)
    refreshed = reloaded.get("DemoConfig")
    assert refreshed.find_assembly(300).direction == "input"
    assert refreshed.find_assembly(200).direction == "input"


def test_update_assembly_rejects_duplicate_id(tmp_path: Path) -> None:
    storage = tmp_path / "configs.json"
    store = ConfigurationStore(storage_path=storage)
    config = _sample_configuration(direction="output")
    config.assemblies.append(
        AssemblyDefinition(
            assembly_id=150,
            name="Other",
            direction="output",
            signals=[],
        )
    )
    store.upsert(config)

    with pytest.raises(ConfigurationError):
        store.update_assembly("DemoConfig", 100, new_id="150", direction="output")


def test_add_assembly_with_relative_position(tmp_path: Path) -> None:
    storage = tmp_path / "configs.json"
    store = ConfigurationStore(storage_path=storage)
    config = _sample_configuration(direction="output")
    config.assemblies.append(
        AssemblyDefinition(
            assembly_id=200,
            name="Second",
            direction="output",
            signals=[],
        )
    )
    store.upsert(config)

    store.add_assembly(
        "DemoConfig",
        assembly_id="0x201",
        assembly_name="Inserted",
        direction="In",
        position="before",
        relative_assembly="200",
    )

    updated = store.get("DemoConfig")
    ids = [assembly.assembly_id for assembly in updated.assemblies]
    assert ids == [100, 0x201, 200]
    inserted = updated.find_assembly(0x201)
    assert inserted.direction == "input"


def test_add_and_remove_assembly_validations(tmp_path: Path) -> None:
    storage = tmp_path / "configs.json"
    store = ConfigurationStore(storage_path=storage)
    config = _sample_configuration(direction="output")
    store.upsert(config)

    with pytest.raises(ConfigurationError):
        store.add_assembly(
            "DemoConfig",
            assembly_id="100",
            assembly_name="DuplicateId",
            direction="output",
        )

    with pytest.raises(ConfigurationError):
        store.add_assembly(
            "DemoConfig",
            assembly_id="300",
            assembly_name="Input",
            direction="output",
        )

    store.add_assembly(
        "DemoConfig",
        assembly_id="300",
        assembly_name="NewAssembly",
        direction="output",
        position="start",
    )

    updated = store.get("DemoConfig")
    ids = [assembly.assembly_id for assembly in updated.assemblies]
    assert ids[0] == 300

    store.remove_assembly("DemoConfig", 300)
    refreshed = store.get("DemoConfig")
    assert all(assembly.assembly_id != 300 for assembly in refreshed.assemblies)
