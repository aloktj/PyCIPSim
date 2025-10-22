"""Persistence helpers for simulator configurations."""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Dict, Iterable, Optional

from .configuration import (
    AssemblyDefinition,
    ConfigurationError,
    SimulatorConfiguration,
    SignalDefinition,
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
            signal.value = value
            self._persist()
            return signal

    def update_signal_type(
        self, name: str, assembly_id: int, signal_name: str, new_type: str
    ) -> SignalDefinition:
        with self._lock:
            configuration = self.get(name)
            signal = configuration.find_signal(assembly_id, signal_name)
            if not new_type:
                raise ConfigurationError("Signal type cannot be empty.")
            if signal.signal_type != new_type:
                signal.signal_type = new_type
                signal.value = None
            self._persist()
            return signal

    def update_target(
        self,
        name: str,
        *,
        target_ip: str,
        target_port: str,
        receive_address: Optional[str],
        multicast: bool,
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
            signal = configuration.find_signal(assembly_id, signal_name)
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
            if not signal_type:
                raise ConfigurationError("Signal type cannot be empty.")
            signal.name = new_name
            signal.offset = offset_value
            if signal.signal_type != signal_type:
                signal.signal_type = signal_type
                signal.value = None
            self._persist()
            return signal

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
            if not signal_type:
                raise ConfigurationError("Signal type cannot be empty.")
            new_signal = SignalDefinition(
                name=new_name,
                offset=offset_value,
                signal_type=signal_type,
            )
            insert_index = len(assembly.signals)
            if relative_signal:
                relative_index = assembly.find_signal_index(relative_signal)
                if position == "before":
                    insert_index = relative_index
                else:
                    insert_index = relative_index + 1
            assembly.signals.insert(insert_index, new_signal)
            self._persist()
            return new_signal

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

