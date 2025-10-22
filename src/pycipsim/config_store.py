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

    def update_signal_type(
        self, name: str, assembly_id: int, signal_name: str, new_type: str
    ) -> SignalDefinition:
        with self._lock:
            configuration = self.get(name)
            signal = configuration.find_signal(assembly_id, signal_name)
            signal.signal_type = new_type
            signal.value = None
            self._persist()
            return signal

    def update_signal_value(
        self,
        name: str,
        assembly_id: int,
        signal_name: str,
        value: Optional[str],
    ) -> SignalDefinition:
        with self._lock:
            configuration = self.get(name)
            signal = configuration.find_signal(assembly_id, signal_name)
            signal.value = value
            self._persist()
            return signal

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

