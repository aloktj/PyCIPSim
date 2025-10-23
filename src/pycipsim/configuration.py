"""Configuration models for the web-based simulator workflow."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional


# Common CIP atomic and composite data types supported by the simulator UI.
CIP_SIGNAL_TYPES: List[str] = [
    "BOOL",
    "SINT",
    "INT",
    "DINT",
    "LINT",
    "USINT",
    "UINT",
    "UDINT",
    "ULINT",
    "BYTE",
    "WORD",
    "DWORD",
    "LWORD",
    "REAL",
    "LREAL",
    "TIME",
    "DATE",
    "TIME_OF_DAY",
    "DATE_AND_TIME",
    "STRING",
    "SHORT_STRING",
    "BITSTRING",
    "ARRAY",
    "STRUCT",
]

_SIGNAL_TYPE_LOOKUP = {item.lower(): item for item in CIP_SIGNAL_TYPES}


def canonicalize_signal_type(value: str) -> str:
    """Return the canonical representation for a signal type if known."""

    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    return _SIGNAL_TYPE_LOOKUP.get(text.lower(), text)


def validate_signal_type(value: str) -> str:
    """Validate a submitted signal type against the supported CIP types."""

    try:
        text = str(value).strip()
    except Exception as exc:  # pragma: no cover - defensive
        raise ConfigurationError("Signal type must be a string.") from exc
    if not text:
        raise ConfigurationError("Signal type cannot be empty.")
    normalized = _SIGNAL_TYPE_LOOKUP.get(text.lower())
    if not normalized:
        raise ConfigurationError(f"Unsupported signal type '{value}'.")
    return normalized


class ConfigurationError(ValueError):
    """Raised when configuration data is invalid."""


@dataclass(slots=True)
class SignalDefinition:
    """Representation of an individual CIP assembly signal."""

    name: str
    offset: int
    signal_type: str
    value: Optional[Any] = None

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "SignalDefinition":
        try:
            name = raw["name"]
            offset = int(raw["offset"])
            signal_type_raw = raw["type"]
        except KeyError as exc:  # pragma: no cover - defensive
            raise ConfigurationError(f"Missing signal field: {exc.args[0]}") from exc
        canonical_type = canonicalize_signal_type(signal_type_raw)
        signal_type = canonical_type or str(signal_type_raw)
        return cls(name=name, offset=offset, signal_type=signal_type, value=raw.get("value"))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "offset": self.offset,
            "type": self.signal_type,
            "value": self.value,
        }


@dataclass(slots=True)
class AssemblyDefinition:
    """CIP assembly containing a collection of signals."""

    assembly_id: int
    name: str
    direction: str
    signals: List[SignalDefinition] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "AssemblyDefinition":
        try:
            assembly_id = int(raw["id"])
            name = raw["name"]
            direction = raw.get("direction", "output")
        except KeyError as exc:  # pragma: no cover - defensive
            raise ConfigurationError(f"Missing assembly field: {exc.args[0]}") from exc
        signals = [SignalDefinition.from_dict(sig) for sig in raw.get("signals", [])]
        return cls(
            assembly_id=assembly_id,
            name=name,
            direction=str(direction),
            signals=signals,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.assembly_id,
            "name": self.name,
            "direction": self.direction,
            "signals": [signal.to_dict() for signal in self.signals],
        }

    def iter_signals(self) -> Iterable[SignalDefinition]:
        """Iterate over contained signals."""

        return list(self.signals)

    def find_signal_index(self, signal_name: str) -> int:
        for index, signal in enumerate(self.signals):
            if signal.name == signal_name:
                return index
        raise ConfigurationError(
            f"Signal '{signal_name}' not found in assembly '{self.name}' ({self.assembly_id})."
        )


@dataclass(slots=True)
class SimulatorConfiguration:
    """Top-level configuration for a CIP simulator instance."""

    name: str
    target_ip: str
    target_port: int = 44818
    receive_address: Optional[str] = None
    multicast: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    assemblies: List[AssemblyDefinition] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "SimulatorConfiguration":
        try:
            name = raw["name"]
            target = raw["target"]
        except KeyError as exc:  # pragma: no cover - defensive
            raise ConfigurationError(f"Missing configuration field: {exc.args[0]}") from exc

        target_ip = target.get("ip", "127.0.0.1")
        target_port = int(target.get("port", 44818))
        receive_address = target.get("receive_address")
        multicast = bool(target.get("multicast", False))
        assemblies = [AssemblyDefinition.from_dict(item) for item in raw.get("assemblies", [])]
        metadata = raw.get("metadata", {})
        if not isinstance(metadata, dict):  # pragma: no cover - defensive
            raise ConfigurationError("Configuration metadata must be a mapping")
        return cls(
            name=str(name),
            target_ip=str(target_ip),
            target_port=target_port,
            receive_address=str(receive_address) if receive_address else None,
            multicast=multicast,
            metadata=metadata,
            assemblies=assemblies,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "target": {
                "ip": self.target_ip,
                "port": self.target_port,
                "receive_address": self.receive_address,
                "multicast": self.multicast,
            },
            "metadata": self.metadata,
            "assemblies": [assembly.to_dict() for assembly in self.assemblies],
        }

    def find_assembly(self, assembly_id: int) -> AssemblyDefinition:
        for assembly in self.assemblies:
            if assembly.assembly_id == assembly_id:
                return assembly
        raise ConfigurationError(
            f"Assembly '{assembly_id}' not found for configuration '{self.name}'."
        )

    def find_assembly_index(self, assembly_id: int) -> int:
        """Return the position of an assembly within the configuration."""

        for index, assembly in enumerate(self.assemblies):
            if assembly.assembly_id == assembly_id:
                return index
        raise ConfigurationError(
            f"Assembly '{assembly_id}' not found for configuration '{self.name}'."
        )

    def find_signal(self, assembly_id: int, signal_name: str) -> SignalDefinition:
        """Locate a signal by assembly and name."""

        assembly = self.find_assembly(assembly_id)
        for signal in assembly.signals:
            if signal.name == signal_name:
                return signal
        raise ConfigurationError(
            f"Signal '{signal_name}' not found in assembly {assembly_id} for configuration '{self.name}'."
        )

