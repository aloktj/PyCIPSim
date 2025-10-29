from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from pycipsim.config_store import ConfigurationStore
from pycipsim.configuration import (
    AssemblyDefinition,
    SimulatorConfiguration,
    SignalDefinition,
)
from pycipsim.runtime.enip_target import ENIPTargetRuntime


def _make_assembly(
    name: str,
    assembly_id: int,
    direction: str,
    *,
    initial_value: str,
) -> AssemblyDefinition:
    assembly = AssemblyDefinition(
        name=name,
        assembly_id=assembly_id,
        direction=direction,
        size_bits=16,
        signals=[
            SignalDefinition(
                name="Value",
                offset=0,
                signal_type="INT",
                value=initial_value,
                size_bits=16,
            )
        ],
    )
    assembly.rebuild_padding()
    return assembly


@pytest.fixture
def enip_target_runtime(tmp_path):
    pytest.importorskip("pycomm3")

    store_path = tmp_path / "target.json"
    store = ConfigurationStore(storage_path=store_path)
    assemblies = [
        _make_assembly("O_T", 0x64, "output", initial_value="0"),
        _make_assembly("T_O", 0x65, "input", initial_value="100"),
    ]
    config = SimulatorConfiguration(
        name="enip-target",
        target_ip="127.0.0.1",
        target_port=0,
        runtime_mode="live",
        role="target",
        transport="enip",
        assemblies=assemblies,
    )
    store.upsert(config)
    # Ensure the initial target-to-originator payload reflects stored values.
    store.update_assembly_values("enip-target", 0x65, {"Value": "321"})

    runtime = ENIPTargetRuntime(config, store, cycle_interval=0.05)
    runtime.start()
    try:
        yield runtime, store
    finally:
        runtime.stop()
