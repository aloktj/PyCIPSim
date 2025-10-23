"""Configuration models for the web-based simulator workflow."""
from __future__ import annotations

from dataclasses import dataclass, field
import math
import struct
from typing import Any, Dict, Iterable, List, Optional, Tuple


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

# Runtime operating modes supported by the simulator. "simulated" keeps the
# legacy behaviour (no live transport), while "live" enables network sessions.
RUNTIME_MODES: tuple[str, ...] = ("simulated", "live")


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

# Preferred padding types by size so gaps can be filled with the fewest
# auto-generated signals possible while maintaining byte-aligned packing.
_PADDING_TYPE_CANDIDATES: List[tuple[int, str]] = [
    (64, "ULINT"),
    (32, "UDINT"),
    (16, "UINT"),
    (8, "USINT"),
]

_SIGNED_SIGNAL_TYPES = {"SINT", "INT", "DINT", "LINT"}
_UNSIGNED_SIGNAL_TYPES = {
    "USINT",
    "UINT",
    "UDINT",
    "ULINT",
    "BYTE",
    "WORD",
    "DWORD",
    "LWORD",
}
_FLOAT_SIGNAL_TYPES = {"REAL", "LREAL"}


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


def normalize_runtime_mode(value: Optional[str]) -> str:
    """Validate and canonicalize the configured runtime mode."""

    text = "" if value is None else str(value).strip().lower()
    if not text:
        return "simulated"
    if text not in RUNTIME_MODES:
        raise ConfigurationError(f"Unsupported runtime mode '{value}'.")
    return text


def parse_allowed_hosts(raw: Any) -> Tuple[str, ...]:
    """Convert arbitrary data into a normalized tuple of allowed hosts."""

    if raw is None:
        return tuple()
    hosts: List[str] = []
    source: Iterable[Any]
    if isinstance(raw, (list, tuple, set)):
        source = raw
    else:
        text = str(raw).replace("\n", ",")
        source = text.split(",")
    for item in source:
        try:
            candidate = str(item).strip()
        except Exception:  # pragma: no cover - defensive
            continue
        if not candidate:
            continue
        hosts.append(candidate)
    seen = set()
    normalized: List[str] = []
    for host in hosts:
        if host in seen:
            continue
        seen.add(host)
        normalized.append(host)
    return tuple(normalized)


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
        bit_index = 0
        while bit_index < self.size_bits:
            if coverage[bit_index]:
                bit_index += 1
                continue
            start = bit_index
            while bit_index < self.size_bits and not coverage[bit_index]:
                bit_index += 1
            length = bit_index - start
            padding_signals.extend(_build_padding_for_gap(start, length))
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
    network_interface: Optional[str] = None
    runtime_mode: str = "simulated"
    metadata: Dict[str, Any] = field(default_factory=dict)
    allowed_hosts: Tuple[str, ...] = field(default_factory=tuple)
    allow_external: bool = False
    assemblies: List[AssemblyDefinition] = field(default_factory=list)

    def max_connection_size_bytes(self) -> int:
        """Return the maximum assembly size in bytes for forward-open sizing."""

        if not self.assemblies:
            return 0
        return max(_total_bytes(assembly.size_bits) for assembly in self.assemblies)

    def build_forward_open_metadata(self) -> Optional[Dict[str, Any]]:
        """Compose metadata required for a Class-1 forward open."""

        if not self.assemblies:
            return None

        def _direction(value: Optional[str]) -> str:
            return (value or "").strip().lower()

        inputs = [
            assembly
            for assembly in self.assemblies
            if _direction(assembly.direction) in {"input", "in"}
        ]
        outputs = [
            assembly
            for assembly in self.assemblies
            if _direction(assembly.direction) in {"output", "out"}
        ]

        if not inputs or not outputs:
            return None

        input_assembly = inputs[0]
        output_assembly = outputs[0]

        config_candidates = [
            assembly
            for assembly in self.assemblies
            if _direction(assembly.direction) in {"config", "configuration"}
        ]
        if not config_candidates:
            config_candidates = [
                assembly
                for assembly in self.assemblies
                if "config" in assembly.name.lower()
            ]
        configuration = config_candidates[0] if config_candidates else None

        overrides_raw = self.metadata.get("forward_open") if isinstance(self.metadata, dict) else None
        overrides: Dict[str, Any] = {}
        if isinstance(overrides_raw, dict):
            overrides = dict(overrides_raw)

        application_instance = overrides.get("application_instance")
        if application_instance is None:
            if configuration is not None:
                application_instance = configuration.assembly_id
            else:
                application_instance = output_assembly.assembly_id

        metadata: Dict[str, Any] = {
            "application_class": overrides.get("application_class", 0x04),
            "application_instance": application_instance,
            "o_to_t_instance": overrides.get(
                "o_to_t_instance", output_assembly.assembly_id
            ),
            "t_to_o_instance": overrides.get(
                "t_to_o_instance", input_assembly.assembly_id
            ),
            "o_to_t_size": overrides.get(
                "o_to_t_size", max(1, _total_bytes(output_assembly.size_bits))
            ),
            "t_to_o_size": overrides.get(
                "t_to_o_size", max(1, _total_bytes(input_assembly.size_bits))
            ),
            "o_to_t_connection_type": overrides.get(
                "o_to_t_connection_type", "point_to_point"
            ),
            "t_to_o_connection_type": overrides.get(
                "t_to_o_connection_type",
                "multicast" if self.multicast else "point_to_point",
            ),
            "o_to_t_rpi_us": overrides.get("o_to_t_rpi_us", 200_000),
            "t_to_o_rpi_us": overrides.get("t_to_o_rpi_us", 200_000),
            "transport_type_trigger": overrides.get("transport_type_trigger", 0x01),
        }

        configuration_point = overrides.get("configuration_point")
        if configuration_point is None and configuration is not None:
            configuration_point = configuration.assembly_id
        if configuration_point is not None:
            metadata["configuration_point"] = configuration_point

        optional_keys = (
            "o_to_t_connection_id",
            "t_to_o_connection_id",
            "connection_serial",
            "vendor_id",
            "originator_serial",
            "timeout_multiplier",
            "connection_points",
            "use_large_forward_open",
        )
        for key in optional_keys:
            if key in overrides:
                metadata[key] = overrides[key]

        return metadata

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
        network_interface = target.get("interface") or target.get("network_interface")
        assemblies = [AssemblyDefinition.from_dict(item) for item in raw.get("assemblies", [])]
        metadata = raw.get("metadata", {})
        if not isinstance(metadata, dict):  # pragma: no cover - defensive
            raise ConfigurationError("Configuration metadata must be a mapping")
        for assembly in assemblies:
            assembly.rebuild_padding()
        runtime_mode = normalize_runtime_mode(
            target.get("mode") if isinstance(target, dict) else None
        )
        if runtime_mode == "simulated" and "runtime_mode" in raw:
            runtime_mode = normalize_runtime_mode(raw.get("runtime_mode"))
        allowed_hosts_raw: Any = None
        allow_external = False
        if isinstance(target, dict):
            allowed_hosts_raw = target.get("allowed_hosts")
            allow_external = bool(target.get("allow_external", False))
        if allowed_hosts_raw is None:
            allowed_hosts_raw = raw.get("allowed_hosts")
        if not allow_external and "allow_external" in raw:
            allow_external = bool(raw.get("allow_external", False))
        return cls(
            name=str(name),
            target_ip=str(target_ip),
            target_port=target_port,
            receive_address=str(receive_address) if receive_address else None,
            multicast=multicast,
            network_interface=str(network_interface) if network_interface else None,
            runtime_mode=runtime_mode,
            metadata=metadata,
            assemblies=assemblies,
            allowed_hosts=parse_allowed_hosts(allowed_hosts_raw),
            allow_external=allow_external,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "target": {
                "ip": self.target_ip,
                "port": self.target_port,
                "receive_address": self.receive_address,
                "multicast": self.multicast,
                "interface": self.network_interface,
                "mode": self.runtime_mode,
                "allowed_hosts": list(self.allowed_hosts),
                "allow_external": self.allow_external,
            },
            "metadata": self.metadata,
            "assemblies": [assembly.to_dict() for assembly in self.assemblies],
        }

    @property
    def allowed_hosts_text(self) -> str:
        """Return a comma-separated representation of configured allowed hosts."""

        if not self.allowed_hosts:
            return ""
        return ", ".join(self.allowed_hosts)

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


def _build_padding_for_gap(start: int, length: int) -> List[SignalDefinition]:
    """Generate padding signals to cover an uncovered region."""

    padding: List[SignalDefinition] = []
    current = start
    remaining = length

    # Use single-bit padding until the region is byte-aligned.
    misalignment = current % 8
    if misalignment:
        align_bits = min(remaining, 8 - misalignment)
        for offset in range(current, current + align_bits):
            padding.append(
                SignalDefinition(
                    name=f"padding_BOOL_{offset}",
                    offset=offset,
                    signal_type="BOOL",
                    value=0,
                    size_bits=1,
                    is_padding=True,
                )
            )
        current += align_bits
        remaining -= align_bits

    if remaining <= 0:
        return padding

    full_bytes, trailing_bits = divmod(remaining, 8)

    for size_bits, signal_type in _PADDING_TYPE_CANDIDATES:
        chunk_bytes = size_bits // 8
        if chunk_bytes == 0:
            continue
        while full_bytes >= chunk_bytes:
            padding.append(
                SignalDefinition(
                    name=f"padding_{signal_type}_{current}",
                    offset=current,
                    signal_type=signal_type,
                    value=0,
                    size_bits=size_bits,
                    is_padding=True,
                )
            )
            current += size_bits
            full_bytes -= chunk_bytes

    # Cover any remaining bytes with 8-bit padding.
    while full_bytes > 0:
        padding.append(
            SignalDefinition(
                name=f"padding_USINT_{current}",
                offset=current,
                signal_type="USINT",
                value=0,
                size_bits=8,
                is_padding=True,
            )
        )
        current += 8
        full_bytes -= 1

    if trailing_bits:
        for offset in range(current, current + trailing_bits):
            padding.append(
                SignalDefinition(
                    name=f"padding_BOOL_{offset}",
                    offset=offset,
                    signal_type="BOOL",
                    value=0,
                    size_bits=1,
                    is_padding=True,
                )
            )

    return padding


def _total_bytes(bit_length: int) -> int:
    return (bit_length + 7) // 8


def _parse_int_value(value: Optional[Any]) -> int:
    if value is None:
        return 0
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    try:
        text = str(value).strip()
    except Exception as exc:  # pragma: no cover - defensive
        raise ConfigurationError(f"Unsupported numeric value '{value}'.") from exc
    if not text:
        return 0
    try:
        return int(text, 0)
    except ValueError as exc:
        raise ConfigurationError(f"Value '{value}' is not a valid integer.") from exc


def _clamp_integer(value: int, bits: int, signed: bool) -> int:
    if bits <= 0:
        raise ConfigurationError("Signal must occupy at least one bit.")
    if signed:
        min_value = -(1 << (bits - 1))
        max_value = (1 << (bits - 1)) - 1
    else:
        min_value = 0
        max_value = (1 << bits) - 1
    if value < min_value or value > max_value:
        raise ConfigurationError(
            f"Value {value} exceeds bounds for a {'signed' if signed else 'unsigned'} {bits}-bit field."
        )
    if value < 0:
        value = (1 << bits) + value
    return value


def _encode_signal_value(signal: SignalDefinition) -> int:
    bits = signal.bit_length()
    signal_type = (signal.signal_type or "").upper()
    raw_value = signal.value

    if signal_type == "BOOL":
        truthy = str(raw_value).lower() in {"1", "true", "on", "yes"}
        return 1 if truthy else 0
    if signal_type in _SIGNED_SIGNAL_TYPES:
        numeric = _parse_int_value(raw_value)
        return _clamp_integer(numeric, bits, signed=True)
    if signal_type in _UNSIGNED_SIGNAL_TYPES or signal_type in {
        "TIME",
        "DATE",
        "TIME_OF_DAY",
        "DATE_AND_TIME",
        "BITSTRING",
    }:
        numeric = _parse_int_value(raw_value)
        return _clamp_integer(numeric, bits, signed=False)
    if signal_type in _FLOAT_SIGNAL_TYPES:
        if raw_value is None:
            value = 0.0
        else:
            try:
                value = float(raw_value)
            except (TypeError, ValueError) as exc:
                raise ConfigurationError(
                    f"Value '{raw_value}' is not a valid floating point number."
                ) from exc
        if signal_type == "REAL":
            packed = struct.pack("<f", value)
        else:
            packed = struct.pack("<d", value)
        return int.from_bytes(packed, "little")
    if signal_type in {"STRING", "SHORT_STRING", "ARRAY", "STRUCT"}:
        length_bytes = _total_bytes(bits)
        text = "" if raw_value is None else str(raw_value)
        data = text.encode("utf-8")
        if len(data) > length_bytes:
            data = data[:length_bytes]
        else:
            data = data.ljust(length_bytes, b"\x00")
        return int.from_bytes(data, "little")

    # Fallback for unknown types when a size is specified: treat as unsigned integer.
    numeric = _parse_int_value(raw_value)
    return _clamp_integer(numeric, bits, signed=False)


def _write_bits(buffer: bytearray, offset: int, width: int, value: int) -> None:
    for bit in range(width):
        target_bit = offset + bit
        byte_index = target_bit // 8
        bit_index = target_bit % 8
        bit_value = (value >> bit) & 1
        if byte_index >= len(buffer):
            raise ConfigurationError("Encoded payload exceeds assembly size.")
        if bit_value:
            buffer[byte_index] |= 1 << bit_index
        else:
            buffer[byte_index] &= ~(1 << bit_index)


def build_assembly_payload(assembly: AssemblyDefinition) -> bytes:
    """Construct a byte payload representing the assembly's current values."""

    if assembly.size_bits <= 0:
        return b""
    payload = bytearray(math.ceil(assembly.size_bits / 8))
    for signal in assembly.signals:
        try:
            encoded = _encode_signal_value(signal)
        except ConfigurationError as exc:
            raise ConfigurationError(
                f"Signal '{signal.name}' in assembly '{assembly.name}' cannot be encoded: {exc}"
            ) from exc
        _write_bits(payload, signal.offset, signal.bit_length(), encoded)
    return bytes(payload)


def _read_bits(data: bytes, offset: int, width: int) -> int:
    value = 0
    for bit in range(width):
        target_bit = offset + bit
        byte_index = target_bit // 8
        bit_index = target_bit % 8
        if byte_index >= len(data):
            continue
        bit_value = (data[byte_index] >> bit_index) & 1
        value |= bit_value << bit
    return value


def _decode_integer(value: int, bits: int, signed: bool) -> int:
    if not signed:
        return value
    boundary = 1 << (bits - 1)
    if value >= boundary:
        return value - (1 << bits)
    return value


def parse_assembly_payload(
    assembly: AssemblyDefinition, payload: bytes
) -> Dict[str, Any]:
    """Decode a payload into per-signal values."""

    results: Dict[str, Any] = {}
    for signal in assembly.signals:
        bits = signal.bit_length()
        raw = _read_bits(payload, signal.offset, bits)
        signal_type = (signal.signal_type or "").upper()
        if signal_type == "BOOL":
            results[signal.name] = "1" if raw & 1 else "0"
            continue
        if signal_type in _SIGNED_SIGNAL_TYPES:
            decoded = _decode_integer(raw, bits, signed=True)
            results[signal.name] = str(decoded)
            continue
        if signal_type in _UNSIGNED_SIGNAL_TYPES or signal_type in {
            "TIME",
            "DATE",
            "TIME_OF_DAY",
            "DATE_AND_TIME",
            "BITSTRING",
        }:
            results[signal.name] = str(raw)
            continue
        if signal_type in _FLOAT_SIGNAL_TYPES:
            byte_length = _total_bytes(bits)
            data = raw.to_bytes(byte_length, "little", signed=False)
            if signal_type == "REAL":
                decoded = struct.unpack("<f", data)[0]
            else:
                decoded = struct.unpack("<d", data)[0]
            results[signal.name] = f"{decoded:g}"
            continue
        if signal_type in {"STRING", "SHORT_STRING", "ARRAY", "STRUCT"}:
            byte_length = _total_bytes(bits)
            data = raw.to_bytes(byte_length, "little", signed=False)
            results[signal.name] = data.rstrip(b"\x00").decode("utf-8", errors="ignore")
            continue
        results[signal.name] = str(raw)
    return results

