"""Runtime wrapper exposing simulator assemblies over real ENIP/CIP sessions."""
from __future__ import annotations

import logging
import threading
from typing import Dict, Iterable, Optional

from ..config_store import ConfigurationNotFoundError, ConfigurationStore
from ..configuration import AssemblyDefinition, SimulatorConfiguration
from .assemblies import AssemblyHost
from .enip_server import ConnectionManager, ENIPServer

_LOGGER = logging.getLogger(__name__)


def _normalize_direction(direction: Optional[str]) -> str:
    return (direction or "").strip().lower()


class ENIPTargetRuntime:
    """Expose simulator assemblies to ENIP originators."""

    def __init__(
        self,
        configuration: SimulatorConfiguration,
        store: ConfigurationStore,
        *,
        cycle_interval: float = 0.1,
    ) -> None:
        self._configuration = configuration
        self._config_name = configuration.name
        self._store = store
        self._cycle_interval = max(cycle_interval, 0.05)
        self._host = AssemblyHost(
            configuration.assemblies, cycle_interval=self._cycle_interval
        )
        self._host.set_input_callback(self._handle_o_to_t_payload)
        self._register_producers()
        self._lock = threading.RLock()
        self._server: Optional[ENIPServer] = None
        self._connection_manager = ConnectionManager(default_timeout=2.0)

    # ------------------------------------------------------------------
    # Lifecycle management
    # ------------------------------------------------------------------
    def start(self) -> None:
        with self._lock:
            if self._server is not None:
                return
            host = self._configuration.target_ip or "0.0.0.0"
            try:
                port = int(self._configuration.target_port)
            except Exception as exc:  # pragma: no cover - defensive
                raise RuntimeError("Configured target port is invalid for ENIP target runtime") from exc
            _LOGGER.info(
                "Starting ENIP target runtime '%s' on %s:%s",
                self._config_name,
                host,
                port,
            )
            server = ENIPServer(
                host=host,
                tcp_port=port,
                udp_port=port,
                connection_manager=self._connection_manager,
                reaper_interval=max(self._cycle_interval, 0.5),
                assembly_host=self._host,
            )
            try:
                server.start()
            except Exception:
                _LOGGER.exception("Failed to start ENIP target runtime '%s'", self._config_name)
                raise
            self._server = server
            self._configuration.target_port = server.tcp_port
        self._sync_host_outputs()
        _LOGGER.info(
            "ENIP target runtime '%s' listening on %s:%s",
            self._config_name,
            host,
            self.tcp_port,
        )

    def stop(self) -> None:
        with self._lock:
            server = self._server
            self._server = None
        if server is None:
            return
        server.stop()
        _LOGGER.info("ENIP target runtime for '%s' stopped.", self._config_name)

    # ------------------------------------------------------------------
    # Runtime helpers
    # ------------------------------------------------------------------
    def notify_output_update(self) -> None:
        """Synchronize cached assembly values with the configuration store."""

        self._sync_host_outputs()

    @property
    def tcp_port(self) -> int:
        server = self._server
        if server is None:
            return int(self._configuration.target_port)
        return server.tcp_port

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _register_producers(self) -> None:
        for assembly in self._input_assemblies():
            try:
                self._host.register_producer(assembly.assembly_id, self._build_store_producer(assembly.assembly_id))
            except Exception as exc:  # pragma: no cover - defensive
                _LOGGER.error(
                    "Failed to register producer for assembly %s on '%s': %s",
                    assembly.assembly_id,
                    self._config_name,
                    exc,
                )

    def _input_assemblies(self) -> Iterable[AssemblyDefinition]:
        for assembly in self._configuration.assemblies:
            if _normalize_direction(assembly.direction) == "input":
                yield assembly

    def _build_store_producer(self, assembly_id: int):
        def producer(_: AssemblyDefinition) -> Optional[Dict[str, object]]:
            try:
                configuration = self._store.get(self._config_name)
            except ConfigurationNotFoundError:
                return None
            try:
                assembly = configuration.find_assembly(assembly_id)
            except Exception:
                return None
            values: Dict[str, object] = {}
            for signal in assembly.signals:
                if signal.is_padding or signal.value is None:
                    continue
                values[signal.name] = str(signal.value)
            return values if values else None

        return producer

    def _handle_o_to_t_payload(self, assembly_id: int, values: Dict[str, object]) -> None:
        if not values:
            return
        try:
            normalized = {name: None if value is None else str(value) for name, value in values.items()}
            self._store.update_assembly_values(self._config_name, assembly_id, normalized)
        except Exception as exc:  # pragma: no cover - defensive
            _LOGGER.error(
                "Failed to process O→T payload for assembly %s on '%s': %s",
                assembly_id,
                self._config_name,
                exc,
            )

    def _sync_host_outputs(self) -> None:
        for assembly in self._input_assemblies():
            values = self._snapshot_store_values(assembly.assembly_id)
            if not values:
                continue
            try:
                self._host.update_assembly_values(assembly.assembly_id, values)
            except KeyError:
                _LOGGER.debug(
                    "Assembly %s missing from ENIP target host for '%s'", assembly.assembly_id, self._config_name
                )

    def _snapshot_store_values(self, assembly_id: int) -> Dict[str, object]:
        try:
            configuration = self._store.get(self._config_name)
        except ConfigurationNotFoundError:
            return {}
        try:
            assembly = configuration.find_assembly(assembly_id)
        except Exception:
            return {}
        values: Dict[str, object] = {}
        for signal in assembly.signals:
            if signal.is_padding or signal.value is None:
                continue
            values[signal.name] = str(signal.value)
        return values


__all__ = ["ENIPTargetRuntime"]
