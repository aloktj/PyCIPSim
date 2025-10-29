"""Runtime management for live CIP I/O exchange."""
from __future__ import annotations

import contextlib
import logging
import threading
import time
from typing import Dict, Iterable, List

from ..config_store import ConfigurationError, ConfigurationStore
from ..configuration import (
    AssemblyDefinition,
    SimulatorConfiguration,
    build_assembly_payload,
    parse_assembly_payload,
)
from ..device import ServiceRequest
from ..session import CIPSession

_LOGGER = logging.getLogger(__name__)


class CIPIORuntime:
    """Coordinate cyclic I/O producers and consumers for a simulator."""

    def __init__(
        self,
        configuration: SimulatorConfiguration,
        store: ConfigurationStore,
        session: CIPSession,
        *,
        cycle_interval: float = 0.1,
    ) -> None:
        self._configuration = configuration
        self._config_name = configuration.name
        self._store = store
        self._session = session
        self._cycle_interval = max(cycle_interval, 0.01)
        self._stop_event = threading.Event()
        self._output_event = threading.Event()
        self._threads: List[threading.Thread] = []
        self._last_output_payloads: Dict[int, bytes] = {}
        self._output_ids = self._collect_ids("output")
        self._input_ids = self._collect_ids("input")

    def _collect_ids(self, direction: str) -> List[int]:
        matches: List[int] = []
        for assembly in self._configuration.assemblies:
            if (assembly.direction or "").lower() == direction:
                matches.append(assembly.assembly_id)
        return matches

    def start(self) -> None:
        """Connect the session and spawn cyclic workers."""

        _LOGGER.info(
            "Starting CIP I/O runtime for '%s' with %d outputs and %d inputs.",
            self._config_name,
            len(self._output_ids),
            len(self._input_ids),
        )
        self._session.connect()
        self._session.register_update_listener(self._handle_async_input)
        if self._output_ids:
            thread = threading.Thread(
                target=self._run_output_loop,
                name=f"pycipsim-output-{self._config_name}",
                daemon=True,
            )
            thread.start()
            self._threads.append(thread)
            self._output_event.set()
        if self._input_ids:
            thread = threading.Thread(
                target=self._run_input_loop,
                name=f"pycipsim-input-{self._config_name}",
                daemon=True,
            )
            thread.start()
            self._threads.append(thread)

    def stop(self) -> None:
        """Signal workers to terminate and close the session."""

        self._stop_event.set()
        self._output_event.set()
        for thread in self._threads:
            thread.join(timeout=2.0)
        self._threads.clear()
        with contextlib.suppress(Exception):
            self._session.disconnect()
        _LOGGER.info("CIP I/O runtime for '%s' stopped.", self._config_name)

    def notify_output_update(self) -> None:
        """Wake the producer loop so fresh values are transmitted promptly."""

        self._output_event.set()

    def _assemblies(self, ids: Iterable[int]) -> Iterable[AssemblyDefinition]:
        for assembly_id in ids:
            yield self._configuration.find_assembly(assembly_id)

    def _run_output_loop(self) -> None:
        while not self._stop_event.is_set():
            triggered = self._output_event.wait(self._cycle_interval)
            self._output_event.clear()
            if self._stop_event.is_set():
                break
            try:
                self._push_outputs()
            except Exception as exc:  # pragma: no cover - defensive
                _LOGGER.error("Output loop failure for '%s': %s", self._config_name, exc)
        _LOGGER.debug("Output loop for '%s' terminated.", self._config_name)

    def _push_outputs(self) -> None:
        for assembly in self._assemblies(self._output_ids):
            try:
                payload = build_assembly_payload(assembly)
            except ConfigurationError as exc:
                _LOGGER.error(
                    "Skipping output assembly %s (%s): %s",
                    assembly.assembly_id,
                    assembly.name,
                    exc,
                )
                continue
            if payload == self._last_output_payloads.get(assembly.assembly_id):
                continue
            request = ServiceRequest(
                service_code="SET_ASSEMBLY",
                tag_path=f"assembly/{assembly.assembly_id}",
                payload=payload,
                metadata={"instance": str(assembly.assembly_id)},
            )
            response = self._session.send(request)
            if response.status != "SUCCESS":
                _LOGGER.warning(
                    "Failed to push output assembly %s (%s): %s",
                    assembly.assembly_id,
                    assembly.name,
                    response.status,
                )
                continue
            self._last_output_payloads[assembly.assembly_id] = payload

    def _run_input_loop(self) -> None:
        while not self._stop_event.is_set():
            start = time.perf_counter()
            try:
                self._pull_inputs()
            except Exception as exc:  # pragma: no cover - defensive
                _LOGGER.error("Input loop failure for '%s': %s", self._config_name, exc)
            elapsed = time.perf_counter() - start
            wait_time = max(self._cycle_interval - elapsed, 0.01)
            self._stop_event.wait(wait_time)
        _LOGGER.debug("Input loop for '%s' terminated.", self._config_name)

    def _pull_inputs(self) -> None:
        for assembly in self._assemblies(self._input_ids):
            request = ServiceRequest(
                service_code="GET_ASSEMBLY",
                tag_path=f"assembly/{assembly.assembly_id}",
                metadata={"instance": str(assembly.assembly_id)},
            )
            response = self._session.send(request)
            if response.status != "SUCCESS":
                _LOGGER.warning(
                    "Failed to pull input assembly %s (%s): %s",
                    assembly.assembly_id,
                    assembly.name,
                    response.status,
                )
                continue
            payload = response.payload or b""
            try:
                decoded = parse_assembly_payload(assembly, payload)
            except ConfigurationError as exc:
                _LOGGER.error(
                    "Unable to decode input assembly %s (%s): %s",
                    assembly.assembly_id,
                    assembly.name,
                    exc,
                )
                continue
            if not decoded:
                continue
            self._store.update_input_values(
                self._config_name, assembly.assembly_id, decoded, persist=False
            )

    # ------------------------------------------------------------------
    # Async update handling
    # ------------------------------------------------------------------
    def _handle_async_input(self, assembly_id: int, payload: bytes) -> None:
        try:
            assembly = self._configuration.find_assembly(assembly_id)
        except ConfigurationError:
            _LOGGER.debug(
                "Async update for unknown assembly %s on '%s' ignored.",
                assembly_id,
                self._config_name,
            )
            return
        try:
            decoded = parse_assembly_payload(assembly, payload)
        except ConfigurationError as exc:
            _LOGGER.error(
                "Failed to decode async payload for assembly %s on '%s': %s",
                assembly_id,
                self._config_name,
                exc,
            )
            return
        if not decoded:
            return
        self._store.update_input_values(
            self._config_name, assembly_id, decoded, persist=False
        )


__all__ = ["CIPIORuntime"]

