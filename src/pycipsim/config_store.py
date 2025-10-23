"""Persistence helpers for simulator configurations."""
from __future__ import annotations

import copy
import json
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from .configuration import (
    AssemblyDefinition,
    ConfigurationError,
    SimulatorConfiguration,
    SignalDefinition,
    validate_signal_type,
)


class ConfigurationNotFoundError(KeyError):
    """Raised when a requested configuration is unavailable."""


class ConfigurationStore:
    """Thread-safe JSON-backed configuration store."""

    def __init__(self, storage_path: Optional[Path] = None) -> None:
        self._storage_path = storage_path or Path.home() / ".pycipsim" / "configurations.json"
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._configs: Dict[str, SimulatorConfiguration] = {}
        self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def list(self) -> Iterable[SimulatorConfiguration]:
        """Return the available configurations."""

        with self._lock:
            return list(self._configs.values())

    def get(self, name: str) -> SimulatorConfiguration:
        with self._lock:
            if name not in self._configs:
                raise ConfigurationNotFoundError(name)
            return self._configs[name]

    def upsert(self, config: SimulatorConfiguration) -> None:
        with self._lock:
            self._configs[config.name] = config
            self._persist()

    def delete(self, name: str) -> None:
        with self._lock:
            if name in self._configs:
                del self._configs[name]
                self._persist()

    def update_signal_value(
        self,
        name: str,
        assembly_id: int,
        signal_name: str,
        value: Optional[str],
    ) -> SignalDefinition:
        with self._lock:
            configuration = self.get(name)
            assembly = configuration.find_assembly(assembly_id)
            direction = (assembly.direction or "").lower()
            if direction in {"input", "in"}:
                raise ConfigurationError(
                    f"Cannot modify values for input assembly '{assembly.name}'."
                )
            signal = configuration.find_signal(assembly_id, signal_name)
            if signal.is_padding:
                raise ConfigurationError("Cannot modify padding signal values.")
            signal.value = value
            self._persist()
            return signal

    def update_input_values(
        self,
        name: str,
        assembly_id: int,
        values: Dict[str, Any],
        *,
        persist: bool = False,
    ) -> None:
        """Update input-direction assembly values, typically from runtime data."""

        with self._lock:
            configuration = self.get(name)
            assembly = configuration.find_assembly(assembly_id)
            direction = (assembly.direction or "").lower()
            if direction not in {"input", "in"}:
                raise ConfigurationError(
                    f"Assembly '{assembly.name}' is not input-direction; refusing to update values."
                )
            for signal in assembly.signals:
                if signal.is_padding:
                    continue
                if signal.name not in values:
                    continue
                signal.value = values[signal.name]
            if persist:
                self._persist()

    def update_signal_type(
        self, name: str, assembly_id: int, signal_name: str, new_type: str
    ) -> SignalDefinition:
        with self._lock:
            configuration = self.get(name)
            assembly = configuration.find_assembly(assembly_id)
            original_signals = copy.deepcopy(assembly.signals)
            try:
                assembly.remove_padding()
                signal = configuration.find_signal(assembly_id, signal_name)
                if signal.is_padding:
                    raise ConfigurationError("Cannot update padding signal types.")
                normalized_type = validate_signal_type(new_type)
                if signal.signal_type != normalized_type:
                    signal.signal_type = normalized_type
                    signal.value = None
                    signal.size_bits = None
                assembly.rebuild_padding()
            except Exception:
                assembly.signals = original_signals
                raise
            self._persist()
            return configuration.find_signal(assembly_id, signal.name)

    def update_target(
        self,
        name: str,
        *,
        target_ip: str,
        target_port: str,
        receive_address: Optional[str],
        multicast: bool,
        network_interface: Optional[str],
    ) -> SimulatorConfiguration:
        with self._lock:
            configuration = self.get(name)
            if not target_ip:
                raise ConfigurationError("Target IP cannot be empty.")
            try:
                port_value = int(target_port)
            except (TypeError, ValueError) as exc:
                raise ConfigurationError("Target port must be an integer.") from exc
            if not (0 < port_value < 65536):
                raise ConfigurationError("Target port must be between 1 and 65535.")
            configuration.target_ip = target_ip
            configuration.target_port = port_value
            configuration.receive_address = receive_address or None
            configuration.multicast = multicast
            configuration.network_interface = (network_interface or None)
            self._persist()
            return configuration

    def update_signal_details(
        self,
        name: str,
        assembly_id: int,
        signal_name: str,
        *,
        new_name: str,
        offset: str,
        signal_type: str,
    ) -> SignalDefinition:
        with self._lock:
            configuration = self.get(name)
            assembly = configuration.find_assembly(assembly_id)
            original_signals = copy.deepcopy(assembly.signals)
            try:
                assembly.remove_padding()
                signal = configuration.find_signal(assembly_id, signal_name)
                if signal.is_padding:
                    raise ConfigurationError("Cannot modify padding signals.")
                if not new_name:
                    raise ConfigurationError("Signal name cannot be empty.")
                try:
                    offset_value = int(offset)
                except (TypeError, ValueError) as exc:
                    raise ConfigurationError("Signal offset must be an integer.") from exc
                if offset_value < 0:
                    raise ConfigurationError("Signal offset cannot be negative.")
                if signal_name != new_name:
                    if any(existing.name == new_name for existing in assembly.signals):
                        raise ConfigurationError(
                            f"Signal name '{new_name}' already exists in assembly {assembly_id}."
                        )
                normalized_type = validate_signal_type(signal_type)
                signal.name = new_name
                signal.offset = offset_value
                if signal.signal_type != normalized_type:
                    signal.signal_type = normalized_type
                    signal.value = None
                    signal.size_bits = None
                assembly.rebuild_padding()
            except Exception:
                assembly.signals = original_signals
                raise
            self._persist()
            return configuration.find_signal(assembly_id, new_name)

    def update_assembly(
        self,
        name: str,
        assembly_id: int,
        *,
        new_id: str,
        direction: str,
        size_bits: Optional[str] = None,
    ) -> AssemblyDefinition:
        with self._lock:
            configuration = self.get(name)
            assembly = configuration.find_assembly(assembly_id)
            original_signals = copy.deepcopy(assembly.signals)
            original_id = assembly.assembly_id
            original_direction = assembly.direction
            original_size = assembly.size_bits
            try:
                try:
                    parsed_id = int(str(new_id), 0)
                except (TypeError, ValueError) as exc:
                    raise ConfigurationError("Assembly ID must be an integer.") from exc
                if parsed_id < 0:
                    raise ConfigurationError("Assembly ID cannot be negative.")
                if parsed_id != assembly.assembly_id:
                    if any(item.assembly_id == parsed_id for item in configuration.assemblies):
                        raise ConfigurationError(
                            f"Assembly ID '{parsed_id}' already exists in configuration '{name}'."
                        )
                normalized_direction = (direction or "").strip().lower()
                if normalized_direction in {"input", "in"}:
                    canonical_direction = "input"
                elif normalized_direction in {"output", "out"}:
                    canonical_direction = "output"
                else:
                    raise ConfigurationError(
                        "Assembly direction must be either 'input' or 'output'."
                    )
                if size_bits is None:
                    parsed_size = assembly.size_bits
                else:
                    try:
                        parsed_size = int(size_bits)
                    except (TypeError, ValueError) as exc:
                        raise ConfigurationError(
                            "Assembly size (bits) must be an integer."
                        ) from exc
                    if parsed_size < 0:
                        raise ConfigurationError(
                            "Assembly size (bits) cannot be negative."
                        )
                assembly.assembly_id = parsed_id
                assembly.direction = canonical_direction
                assembly.size_bits = parsed_size
                assembly.rebuild_padding()
            except Exception:
                assembly.signals = original_signals
                assembly.assembly_id = original_id
                assembly.direction = original_direction
                assembly.size_bits = original_size
                raise
            self._persist()
            return assembly

    def add_assembly(
        self,
        name: str,
        *,
        assembly_id: str,
        assembly_name: str,
        direction: str,
        size_bits: str,
        position: str = "end",
        relative_assembly: Optional[str] = None,
    ) -> AssemblyDefinition:
        """Insert a new assembly into the configuration."""

        with self._lock:
            configuration = self.get(name)
            if not assembly_name:
                raise ConfigurationError("Assembly name cannot be empty.")
            try:
                parsed_id = int(str(assembly_id), 0)
            except (TypeError, ValueError) as exc:
                raise ConfigurationError("Assembly ID must be an integer.") from exc
            if parsed_id < 0:
                raise ConfigurationError("Assembly ID cannot be negative.")
            if any(item.assembly_id == parsed_id for item in configuration.assemblies):
                raise ConfigurationError(
                    f"Assembly ID '{parsed_id}' already exists in configuration '{name}'."
                )
            if any(item.name == assembly_name for item in configuration.assemblies):
                raise ConfigurationError(
                    f"Assembly name '{assembly_name}' already exists in configuration '{name}'."
                )
            normalized_direction = (direction or "").strip().lower()
            if normalized_direction in {"input", "in"}:
                canonical_direction = "input"
            elif normalized_direction in {"output", "out"}:
                canonical_direction = "output"
            else:
                raise ConfigurationError("Assembly direction must be either 'input' or 'output'.")

            try:
                parsed_size = int(size_bits)
            except (TypeError, ValueError) as exc:
                raise ConfigurationError("Assembly size (bits) must be an integer.") from exc
            if parsed_size < 0:
                raise ConfigurationError("Assembly size (bits) cannot be negative.")

            new_assembly = AssemblyDefinition(
                assembly_id=parsed_id,
                name=assembly_name,
                direction=canonical_direction,
                size_bits=parsed_size,
                signals=[],
            )

            insert_index = len(configuration.assemblies)
            normalized_position = (position or "end").strip().lower()
            if normalized_position in {"before", "after"} and relative_assembly:
                try:
                    relative_id = int(str(relative_assembly), 0)
                except (TypeError, ValueError) as exc:
                    raise ConfigurationError("Relative assembly ID must be an integer.") from exc
                relative_index = configuration.find_assembly_index(relative_id)
                insert_index = relative_index
                if normalized_position == "after":
                    insert_index += 1
            elif normalized_position == "start":
                insert_index = 0

            configuration.assemblies.insert(insert_index, new_assembly)
            self._persist()
            return new_assembly

    def remove_assembly(self, name: str, assembly_id: int) -> None:
        """Remove an assembly from the configuration."""

        with self._lock:
            configuration = self.get(name)
            index = configuration.find_assembly_index(assembly_id)
            configuration.assemblies.pop(index)
            self._persist()

    def add_signal(
        self,
        name: str,
        assembly_id: int,
        *,
        new_name: str,
        offset: str,
        signal_type: str,
        position: str,
        relative_signal: Optional[str],
    ) -> SignalDefinition:
        with self._lock:
            configuration = self.get(name)
            assembly = configuration.find_assembly(assembly_id)
            original_signals = copy.deepcopy(assembly.signals)
            try:
                assembly.remove_padding()
                if not new_name:
                    raise ConfigurationError("Signal name cannot be empty.")
                if any(existing.name == new_name for existing in assembly.signals):
                    raise ConfigurationError(
                        f"Signal name '{new_name}' already exists in assembly {assembly_id}."
                    )
                try:
                    offset_value = int(offset)
                except (TypeError, ValueError) as exc:
                    raise ConfigurationError("Signal offset must be an integer.") from exc
                if offset_value < 0:
                    raise ConfigurationError("Signal offset cannot be negative.")
                normalized_type = validate_signal_type(signal_type)
                new_signal = SignalDefinition(
                    name=new_name,
                    offset=offset_value,
                    signal_type=normalized_type,
                )
                insert_index = len(assembly.signals)
                if relative_signal:
                    relative_index = assembly.find_signal_index(relative_signal)
                    if position == "before":
                        insert_index = relative_index
                    else:
                        insert_index = relative_index + 1
                assembly.signals.insert(insert_index, new_signal)
                assembly.rebuild_padding()
            except Exception:
                assembly.signals = original_signals
                raise
            self._persist()
            return configuration.find_signal(assembly_id, new_name)

    def remove_signal(self, name: str, assembly_id: int, signal_name: str) -> None:
        """Remove a signal from the given assembly."""

        with self._lock:
            configuration = self.get(name)
            assembly = configuration.find_assembly(assembly_id)
            original_signals = copy.deepcopy(assembly.signals)
            try:
                assembly.remove_padding()
                index = assembly.find_signal_index(signal_name)
                candidate = assembly.signals[index]
                if candidate.is_padding:
                    raise ConfigurationError("Cannot remove padding signals explicitly.")
                assembly.signals.pop(index)
                assembly.rebuild_padding()
            except Exception:
                assembly.signals = original_signals
                raise
            self._persist()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _load(self) -> None:
        if not self._storage_path.exists():
            return
        with self._storage_path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
        configs = {}
        for item in raw:
            configs[item["name"]] = SimulatorConfiguration.from_dict(item)
        self._configs = configs

    def _persist(self) -> None:
        payload = [config.to_dict() for config in self._configs.values()]
        with self._storage_path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)


__all__ = [
    "AssemblyDefinition",
    "ConfigurationError",
    "ConfigurationNotFoundError",
    "ConfigurationStore",
    "SimulatorConfiguration",
    "SignalDefinition",
]

