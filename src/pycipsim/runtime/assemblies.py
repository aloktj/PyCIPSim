"""Runtime assembly host for ENIP connections."""

from __future__ import annotations

import copy
import logging
import threading
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional

from ..configuration import AssemblyDefinition, build_assembly_payload, parse_assembly_payload

_LOGGER = logging.getLogger(__name__)


Producer = Callable[[AssemblyDefinition], Optional[Dict[str, object]]]


def _normalize_direction(direction: Optional[str]) -> str:
    text = (direction or "").strip().lower()
    mapping = {
        "in": "input",
        "input": "input",
        "t->o": "input",
        "t_to_o": "input",
        "t2o": "input",
        "to": "input",
        "target_to_originator": "input",
        "out": "output",
        "output": "output",
        "o->t": "output",
        "o_to_t": "output",
        "o2t": "output",
        "ot": "output",
        "originator_to_target": "output",
    }
    return mapping.get(text, text)


@dataclass(slots=True)
class _ConnectionContext:
    """Tracks runtime state for an active assembly connection."""

    key: int
    connection_ids: tuple[int, ...]
    t_to_o_assembly: Optional[int]
    o_to_t_assembly: Optional[int]
    interval: float
    last_payload: bytes = b""
    wake_event: threading.Event = field(default_factory=threading.Event)
    stop_event: threading.Event = field(default_factory=threading.Event)
    thread: Optional[threading.Thread] = None


class AssemblyHost:
    """Maintain assembly values and manage cyclic payload production."""

    def __init__(
        self,
        configuration: Iterable[AssemblyDefinition],
        *,
        cycle_interval: float = 0.1,
        input_callback: Optional[Callable[[int, Dict[str, object]], None]] = None,
    ) -> None:
        self._cycle_interval = max(cycle_interval, 0.01)
        self._assemblies: Dict[int, AssemblyDefinition] = {
            assembly.assembly_id: copy.deepcopy(assembly)
            for assembly in configuration
        }
        self._producers: Dict[int, List[Producer]] = {}
        self._contexts: Dict[int, _ConnectionContext] = {}
        self._by_connection_id: Dict[int, _ConnectionContext] = {}
        self._lock = threading.RLock()
        self._input_callback = input_callback

    # ------------------------------------------------------------------
    # Producer registration
    # ------------------------------------------------------------------
    def register_producer(self, assembly_id: int, producer: Producer) -> None:
        """Associate a callable that can mutate outgoing values."""

        with self._lock:
            if assembly_id not in self._assemblies:
                raise KeyError(f"Unknown assembly {assembly_id}")
            self._producers.setdefault(assembly_id, []).append(producer)

    def set_input_callback(
        self, callback: Optional[Callable[[int, Dict[str, object]], None]]
    ) -> None:
        """Register a callback invoked when O→T payloads are decoded."""

        with self._lock:
            self._input_callback = callback

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------
    def activate_connection(
        self,
        key: int,
        connection_ids: Iterable[int],
        connection_points: Iterable[int],
        *,
        t_to_o_rpi_us: int,
    ) -> None:
        """Start tracking a new ENIP Class-1 connection."""

        connection_ids_tuple = tuple(sorted({cid for cid in connection_ids if cid}))
        if key in self._contexts:
            return

        t_to_o_assembly: Optional[int] = None
        o_to_t_assembly: Optional[int] = None
        for point in connection_points:
            assembly = self._assemblies.get(point)
            if assembly is None:
                continue
            direction = _normalize_direction(assembly.direction)
            if direction == "input" and t_to_o_assembly is None:
                t_to_o_assembly = point
                continue
            if direction == "output" and o_to_t_assembly is None:
                o_to_t_assembly = point

        interval = max(self._cycle_interval, (t_to_o_rpi_us or 0) / 1_000_000.0)
        if interval <= 0:
            interval = self._cycle_interval

        context = _ConnectionContext(
            key=key,
            connection_ids=connection_ids_tuple,
            t_to_o_assembly=t_to_o_assembly,
            o_to_t_assembly=o_to_t_assembly,
            interval=interval,
        )
        self._refresh_context(context)
        thread = threading.Thread(
            target=self._run_context,
            args=(context,),
            name=f"assembly-ctx-{key}",
            daemon=True,
        )
        context.thread = thread
        with self._lock:
            self._contexts[key] = context
            for connection_id in connection_ids_tuple:
                self._by_connection_id[connection_id] = context
        thread.start()

    def deactivate_connection(self, key: int) -> None:
        """Stop tracking a connection and tear down workers."""

        with self._lock:
            context = self._contexts.pop(key, None)
        if context is None:
            return
        context.stop_event.set()
        context.wake_event.set()
        with self._lock:
            for connection_id in context.connection_ids:
                self._by_connection_id.pop(connection_id, None)
        if context.thread is not None:
            context.thread.join(timeout=0.5)

    # ------------------------------------------------------------------
    # Payload exchange helpers
    # ------------------------------------------------------------------
    def process_o_to_t(self, connection_id: int, payload: bytes) -> None:
        """Ingest originator-to-target payloads and store decoded values."""

        context = self._by_connection_id.get(connection_id)
        if context is None or context.o_to_t_assembly is None:
            return
        assembly = self._assemblies.get(context.o_to_t_assembly)
        if assembly is None:
            return
        try:
            decoded = parse_assembly_payload(assembly, payload)
        except Exception as exc:  # pragma: no cover - defensive
            _LOGGER.error(
                "Failed to decode O→T payload for assembly %s: %s",
                context.o_to_t_assembly,
                exc,
            )
            return
        if not decoded:
            return
        with self._lock:
            for signal in assembly.signals:
                if signal.name in decoded:
                    signal.value = decoded[signal.name]
        callback = self._input_callback
        if callback is not None:
            try:
                callback(context.o_to_t_assembly, dict(decoded))
            except Exception as exc:  # pragma: no cover - defensive
                _LOGGER.error(
                    "Input callback for assembly %s failed: %s",
                    context.o_to_t_assembly,
                    exc,
                )

    def build_t_to_o_payload(self, connection_id: int) -> bytes:
        """Return the last generated target-to-originator payload."""

        context = self._by_connection_id.get(connection_id)
        if context is None:
            return b""
        if context.t_to_o_assembly is None:
            return b""
        # Ensure payload is current when fetched outside the periodic loop.
        self._refresh_context(context)
        return context.last_payload

    def update_assembly_values(self, assembly_id: int, values: Dict[str, object]) -> None:
        """Manually update stored values for a given assembly."""

        assembly = self._assemblies.get(assembly_id)
        if assembly is None:
            raise KeyError(f"Unknown assembly {assembly_id}")
        with self._lock:
            for signal in assembly.signals:
                if signal.name in values:
                    signal.value = str(values[signal.name])
        for context in list(self._contexts.values()):
            if context.t_to_o_assembly == assembly_id:
                context.wake_event.set()

    def snapshot(self, assembly_id: int) -> Dict[str, Optional[str]]:
        """Return the current cached values for an assembly."""

        assembly = self._assemblies.get(assembly_id)
        if assembly is None:
            raise KeyError(f"Unknown assembly {assembly_id}")
        with self._lock:
            return {signal.name: signal.value for signal in assembly.signals}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _run_context(self, context: _ConnectionContext) -> None:
        try:
            while not context.stop_event.is_set():
                context.wake_event.wait(context.interval)
                context.wake_event.clear()
                if context.stop_event.is_set():
                    break
                self._refresh_context(context)
        except Exception as exc:  # pragma: no cover - defensive
            _LOGGER.error("Assembly context loop error: %s", exc)

    def _refresh_context(self, context: _ConnectionContext) -> None:
        if context.t_to_o_assembly is None:
            context.last_payload = b""
            return
        assembly = self._assemblies.get(context.t_to_o_assembly)
        if assembly is None:
            context.last_payload = b""
            return
        with self._lock:
            working = copy.deepcopy(assembly)
        for producer in self._producers.get(context.t_to_o_assembly, []):
            try:
                produced = producer(copy.deepcopy(working))
            except Exception as exc:  # pragma: no cover - defensive
                _LOGGER.error(
                    "Assembly producer for %s failed: %s",
                    context.t_to_o_assembly,
                    exc,
                )
                continue
            if not produced:
                continue
            for signal in working.signals:
                if signal.name in produced:
                    signal.value = str(produced[signal.name])
        try:
            context.last_payload = build_assembly_payload(working)
        except Exception as exc:  # pragma: no cover - defensive
            _LOGGER.error(
                "Failed to encode T→O payload for assembly %s: %s",
                context.t_to_o_assembly,
                exc,
            )
            context.last_payload = b""


__all__ = ["AssemblyHost"]

