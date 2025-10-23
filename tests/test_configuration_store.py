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
            "interface": "eth0",
        },
        "assemblies": [
            {
                "id": 100,
                "name": "Input",
                "direction": direction,
                "size_bits": 64,
                "signals": [
                    {"name": "SignalA", "offset": 0, "type": "BOOL", "value": "0"},
                    {"name": "SignalB", "offset": 1, "type": "INT", "value": "5"},
                ],
            }
        ],
    }
    return SimulatorConfiguration.from_dict(data)


def test_forward_open_metadata_generation() -> None:
    config = SimulatorConfiguration.from_dict(
        {
            "name": "Runtime",
            "target": {
                "ip": "10.0.0.10",
                "port": 44818,
                "multicast": True,
            },
            "assemblies": [
                {"id": 1, "name": "Config", "direction": "config", "size_bits": 16},
                {"id": 100, "name": "Inputs", "direction": "input", "size_bits": 32},
                {"id": 200, "name": "Outputs", "direction": "output", "size_bits": 8},
            ],
        }
    )

    metadata = config.build_forward_open_metadata()
    assert metadata is not None
    assert metadata["application_instance"] == 1
    assert metadata["t_to_o_instance"] == 100
    assert metadata["o_to_t_instance"] == 200
    assert metadata["configuration_point"] == 1
    assert metadata["t_to_o_connection_type"] == "multicast"
    assert metadata["o_to_t_connection_type"] == "point_to_point"
    assert metadata["t_to_o_size"] == 4
    assert metadata["o_to_t_size"] == 1
    assert metadata["connection_points"] == [100, 200, 1]


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
    assert configs[0].network_interface == "eth0"
    assert configs[0].runtime_mode == "simulated"


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


def test_update_target_records_interface(tmp_path: Path) -> None:
    storage = tmp_path / "configs.json"
    store = ConfigurationStore(storage_path=storage)
    config = _sample_configuration(direction="output")
    store.upsert(config)

    store.update_target(
        "DemoConfig",
        target_ip="10.0.0.5",
        target_port="44818",
        receive_address="",
        multicast=False,
        network_interface="eth1",
        runtime_mode="live",
        allowed_hosts="10.0.0.1, 10.0.0.2",
        allow_external=True,
    )

    refreshed = store.get("DemoConfig")
    assert refreshed.target_ip == "10.0.0.5"
    assert refreshed.network_interface == "eth1"
    assert refreshed.runtime_mode == "live"
    assert refreshed.allowed_hosts == ("10.0.0.1", "10.0.0.2")
    assert refreshed.allow_external is True


def test_update_target_rejects_invalid_runtime_mode(tmp_path: Path) -> None:
    storage = tmp_path / "configs.json"
    store = ConfigurationStore(storage_path=storage)
    config = _sample_configuration(direction="output")
    store.upsert(config)

    with pytest.raises(ConfigurationError):
        store.update_target(
            "DemoConfig",
            target_ip="10.0.0.5",
            target_port="44818",
            receive_address="",
            multicast=False,
            network_interface="eth0",
            runtime_mode="invalid",
        )


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
        offset="17",
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
    assert [name for name in remaining if not name.startswith("padding_")] == ["SignalB"]


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
        size_bits="64",
    )

    assert updated.assembly_id == 300
    assert updated.direction == "input"

    reloaded = ConfigurationStore(storage_path=storage)
    refreshed = reloaded.get("DemoConfig")
    assert refreshed.find_assembly(300).direction == "input"
    assert refreshed.find_assembly(200).direction == "input"


def test_update_assembly_metadata_without_size(tmp_path: Path) -> None:
    storage = tmp_path / "configs.json"
    store = ConfigurationStore(storage_path=storage)
    config = _sample_configuration(direction="output")
    config.assemblies[0].size_bits = 96
    store.upsert(config)

    updated = store.update_assembly(
        "DemoConfig",
        100,
        new_id="321",
        direction="input",
    )

    assert updated.size_bits == 96

    reloaded = ConfigurationStore(storage_path=storage)
    refreshed = reloaded.get("DemoConfig")
    assert refreshed.find_assembly(321).size_bits == 96


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
        store.update_assembly(
            "DemoConfig", 100, new_id="150", direction="output", size_bits="64"
        )


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
        size_bits="64",
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
            size_bits="16",
        )

    with pytest.raises(ConfigurationError):
        store.add_assembly(
            "DemoConfig",
            assembly_id="300",
            assembly_name="Input",
            direction="output",
            size_bits="16",
        )

    store.add_assembly(
        "DemoConfig",
        assembly_id="300",
        assembly_name="NewAssembly",
        direction="output",
        size_bits="16",
        position="start",
    )

    updated = store.get("DemoConfig")
    ids = [assembly.assembly_id for assembly in updated.assemblies]
    assert ids[0] == 300

    store.remove_assembly("DemoConfig", 300)
    refreshed = store.get("DemoConfig")
    assert all(assembly.assembly_id != 300 for assembly in refreshed.assemblies)


def test_padding_generated_to_fill_assembly(tmp_path: Path) -> None:
    storage = tmp_path / "configs.json"
    store = ConfigurationStore(storage_path=storage)
    config = SimulatorConfiguration.from_dict(
        {
            "name": "PadConfig",
            "target": {"ip": "10.0.0.1", "port": 44818},
            "assemblies": [
                {
                    "id": 1,
                    "name": "Packed",
                    "direction": "output",
                    "size_bits": 8,
                    "signals": [
                        {"name": "BitFive", "offset": 5, "type": "BOOL"},
                    ],
                }
            ],
        }
    )
    store.upsert(config)

    assembly = store.get("PadConfig").find_assembly(1)
    padding_offsets = sorted(
        sig.offset for sig in assembly.signals if sig.is_padding and sig.signal_type == "BOOL"
    )
    assert padding_offsets == [0, 1, 2, 3, 4, 6, 7]
    assert any(sig.name == "BitFive" for sig in assembly.signals if not sig.is_padding)


def test_padding_prefers_wider_types(tmp_path: Path) -> None:
    storage = tmp_path / "configs.json"
    store = ConfigurationStore(storage_path=storage)
    config = SimulatorConfiguration.from_dict(
        {
            "name": "WidePadding",
            "target": {"ip": "10.0.0.3", "port": 44818},
            "assemblies": [
                {
                    "id": 5,
                    "name": "Offsets",
                    "direction": "output",
                    "size_bits": 32,
                    "signals": [
                        {"name": "FirstBit", "offset": 0, "type": "BOOL"},
                    ],
                },
                {
                    "id": 6,
                    "name": "ByteGap",
                    "direction": "output",
                    "size_bits": 16,
                    "signals": [
                        {"name": "Byte", "offset": 8, "type": "USINT"},
                    ],
                },
            ],
        }
    )
    store.upsert(config)

    offsets = store.get("WidePadding")
    first = offsets.find_assembly(5)
    bool_padding = [sig.offset for sig in first.signals if sig.is_padding and sig.signal_type == "BOOL"]
    assert bool_padding == [1, 2, 3, 4, 5, 6, 7]
    assert any(sig.signal_type == "UINT" and sig.offset == 8 for sig in first.signals if sig.is_padding)
    assert any(sig.signal_type == "USINT" and sig.offset == 24 for sig in first.signals if sig.is_padding)

    second = offsets.find_assembly(6)
    padding_types = [sig.signal_type for sig in second.signals if sig.is_padding]
    assert padding_types == ["USINT"]
    assert second.signals[0].offset == 0


def test_signal_cannot_exceed_assembly_size(tmp_path: Path) -> None:
    storage = tmp_path / "configs.json"
    store = ConfigurationStore(storage_path=storage)
    config = SimulatorConfiguration.from_dict(
        {
            "name": "OverflowConfig",
            "target": {"ip": "10.0.0.2", "port": 44818},
            "assemblies": [
                {
                    "id": 1,
                    "name": "Limited",
                    "direction": "output",
                    "size_bits": 8,
                    "signals": [],
                }
            ],
        }
    )
    store.upsert(config)

    with pytest.raises(ConfigurationError):
        store.add_signal(
            "OverflowConfig",
            1,
            new_name="TooLarge",
            offset="0",
            signal_type="INT",
            position="after",
            relative_signal=None,
        )

    assembly = store.get("OverflowConfig").find_assembly(1)
    assert not assembly.signals
