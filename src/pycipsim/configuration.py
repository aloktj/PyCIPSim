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


# Nominal bit widths for well-known CIP signal types.
_CIP_SIGNAL_TYPE_BITS: Dict[str, int] = {
    "BOOL": 1,
    "SINT": 8,
    "INT": 16,
    "DINT": 32,
    "LINT": 64,
    "USINT": 8,
    "UINT": 16,
    "UDINT": 32,
    "ULINT": 64,
    "BYTE": 8,
    "WORD": 16,
    "DWORD": 32,
    "LWORD": 64,
    "REAL": 32,
    "LREAL": 64,
    "TIME": 32,
    "DATE": 16,
    "TIME_OF_DAY": 32,
    "DATE_AND_TIME": 64,
}


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
    size_bits: Optional[int] = None
    is_padding: bool = False

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
        size_bits = raw.get("size_bits")
        if size_bits is None and "bits" in raw:
            size_bits = raw["bits"]
        parsed_size: Optional[int]
        if size_bits is None:
            parsed_size = None
        else:
            try:
                parsed_size = int(size_bits)
            except (TypeError, ValueError) as exc:  # pragma: no cover - defensive
                raise ConfigurationError(
                    f"Signal '{name}' has invalid size_bits '{size_bits}'."
                ) from exc
            if parsed_size < 0:
                raise ConfigurationError(
                    f"Signal '{name}' cannot have a negative size in bits."
                )
        is_padding = bool(raw.get("padding"))
        if not is_padding and isinstance(name, str):
            is_padding = name.lower().startswith("padding_")
        return cls(
            name=name,
            offset=offset,
            signal_type=signal_type,
            value=raw.get("value"),
            size_bits=parsed_size,
            is_padding=is_padding,
        )

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "name": self.name,
            "offset": self.offset,
            "type": self.signal_type,
            "value": self.value,
        }
        if self.size_bits is not None:
            payload["size_bits"] = self.size_bits
        if self.is_padding:
            payload["padding"] = True
        return payload

    def bit_length(self) -> int:
        """Return the effective width of the signal in bits."""

        if self.size_bits is not None:
            return self.size_bits
        signal_type = (self.signal_type or "").upper()
        if signal_type in _CIP_SIGNAL_TYPE_BITS:
            return _CIP_SIGNAL_TYPE_BITS[signal_type]
        raise ConfigurationError(
            f"Signal '{self.name}' has type '{self.signal_type}' without a defined bit width."
        )


@dataclass(slots=True)
class AssemblyDefinition:
    """CIP assembly containing a collection of signals."""

    assembly_id: int
    name: str
    direction: str
    size_bits: int = 0
    signals: List[SignalDefinition] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "AssemblyDefinition":
        try:
            assembly_id = int(raw["id"])
            name = raw["name"]
            direction = raw.get("direction", "output")
        except KeyError as exc:  # pragma: no cover - defensive
            raise ConfigurationError(f"Missing assembly field: {exc.args[0]}") from exc
        size_bits_raw = raw.get("size_bits")
        if size_bits_raw is None and "size" in raw:
            size_bits_raw = raw["size"]
        if size_bits_raw is None:
            size_bits = 0
        else:
            try:
                size_bits = int(size_bits_raw)
            except (TypeError, ValueError) as exc:  # pragma: no cover - defensive
                raise ConfigurationError(
                    f"Assembly '{name}' has invalid size '{size_bits_raw}'."
                ) from exc
            if size_bits < 0:
                raise ConfigurationError(f"Assembly '{name}' cannot have a negative size.")
        signals = [SignalDefinition.from_dict(sig) for sig in raw.get("signals", [])]
        return cls(
            assembly_id=assembly_id,
            name=name,
            direction=str(direction),
            size_bits=size_bits,
            signals=signals,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.assembly_id,
            "name": self.name,
            "direction": self.direction,
            "size_bits": self.size_bits,
            "signals": [signal.to_dict() for signal in self.signals],
        }

    def iter_signals(self) -> Iterable[SignalDefinition]:
        """Iterate over contained signals."""

        return list(self.signals)

    def remove_padding(self) -> None:
        """Strip auto-generated padding signals from the assembly."""

        self.signals = [signal for signal in self.signals if not signal.is_padding]

    def rebuild_padding(self) -> None:
        """Ensure the assembly is fully covered with padding signals."""

        base_signals = [signal for signal in self.signals if not signal.is_padding]
        base_signals.sort(key=lambda sig: (sig.offset, sig.name))
        if not base_signals:
            self.signals = base_signals
            return
        if self.size_bits <= 0:
            self.signals = base_signals
            return
        coverage = [False] * self.size_bits
        for signal in base_signals:
            length = signal.bit_length()
            if length <= 0:
                raise ConfigurationError(
                    f"Signal '{signal.name}' must occupy at least one bit."
                )
            end = signal.offset + length
            if end > self.size_bits:
                raise ConfigurationError(
                    f"Signal '{signal.name}' exceeds assembly size ({self.size_bits} bits)."
                )
            for bit in range(signal.offset, end):
                if coverage[bit]:
                    raise ConfigurationError(
                        f"Signal '{signal.name}' overlaps another signal at bit {bit}."
                    )
                coverage[bit] = True
        padding_signals: List[SignalDefinition] = []
        for bit, covered in enumerate(coverage):
            if not covered:
                padding_signals.append(
                    SignalDefinition(
                        name=f"padding_BOOL_{bit}",
                        offset=bit,
                        signal_type="BOOL",
                        value="0",
                        size_bits=1,
                        is_padding=True,
                    )
                )
        combined = base_signals + padding_signals
        combined.sort(key=lambda sig: (sig.offset, sig.is_padding, sig.name))
        self.signals = combined

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
        for assembly in assemblies:
            assembly.rebuild_padding()
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

