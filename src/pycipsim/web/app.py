"""FastAPI application exposing the web configuration UI."""
from __future__ import annotations

import contextlib
import json
import socket
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlencode

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from ..config_store import (
    ConfigurationError,
    ConfigurationNotFoundError,
    ConfigurationStore,
    SimulatorConfiguration,
)
from ..configuration import CIP_SIGNAL_TYPES
from ..handshake import HandshakePhase, HandshakeResult, HandshakeStep, perform_handshake
from ..runtime import CIPIORuntime
from ..runtime.enip_target import ENIPTargetRuntime
from ..target import CIPTargetRuntime
from ..session import CIPSession, SessionConfig


@dataclass
class ActiveSimulation:
    """Runtime metadata for a started simulator."""

    configuration_name: str
    handshake: HandshakeResult
    started_at: datetime
    runtime: Optional[Any]


class SimulatorManager:
    """Coordinate start/stop operations for configurations."""

    def __init__(
        self,
        *,
        session_factory: Optional[
            Callable[[SessionConfig, SimulatorConfiguration], CIPSession]
        ] = None,
        cycle_interval: float = 0.1,
        simulate_handshake: bool = False,
    ) -> None:
        self._lock = threading.RLock()
        self._active: Optional[ActiveSimulation] = None
        self._session_factory = session_factory or (lambda cfg, _config: CIPSession(cfg))
        self._cycle_interval = cycle_interval
        self._simulate_handshake = simulate_handshake
        self._last_handshake: Optional[tuple[str, HandshakeResult]] = None

    def start(
        self,
        config: SimulatorConfiguration,
        store: ConfigurationStore,
        *,
        simulate_handshake: Optional[bool] = None,
    ) -> HandshakeResult:
        with self._lock:
            if self._active is not None:
                raise RuntimeError("A simulation is already running. Stop it before starting a new one.")
            session_metadata = dict(config.metadata)
            max_connection_size = config.max_connection_size_bytes()
            if max_connection_size > 0:
                session_metadata["max_connection_size_bytes"] = max_connection_size
            forward_open = config.build_forward_open_metadata()
            if forward_open:
                session_metadata["forward_open"] = forward_open
            role = (config.role or "originator").lower()
            allowed_hosts = list(SessionConfig().allowed_hosts)
            allowed_hosts.extend(config.allowed_hosts)
            allowed_hosts.append(config.target_ip)
            deduped_hosts: list[str] = []
            seen_hosts: set[str] = set()
            for host in allowed_hosts:
                if not host or host in seen_hosts:
                    continue
                deduped_hosts.append(host)
                seen_hosts.add(host)
            mode = (config.runtime_mode or "simulated").lower()
            should_run_runtime = mode == "live"
            if role == "target":
                steps: List[HandshakeStep] = [
                    HandshakeStep(
                        phase=HandshakePhase.TCP_CONNECT,
                        success=True,
                        detail="Target listener initialized",
                    )
                ]
                handshake = HandshakeResult(success=True, steps=steps, duration_ms=0.0)
                runtime: Optional[Any] = None
                if should_run_runtime:
                    transport_mode = (config.transport or "pycipsim").lower()
                    if transport_mode == "enip":
                        runtime = ENIPTargetRuntime(
                            configuration=config,
                            store=store,
                            cycle_interval=self._cycle_interval,
                        )
                    else:
                        runtime = CIPTargetRuntime(
                            configuration=config,
                            store=store,
                            cycle_interval=self._cycle_interval,
                        )
                    runtime.start()
                self._last_handshake = (config.name, handshake)
                self._active = ActiveSimulation(
                    configuration_name=config.name,
                    handshake=handshake,
                    started_at=datetime.now(timezone.utc),
                    runtime=runtime,
                )
                return handshake
            session_config = SessionConfig(
                ip_address=config.target_ip,
                port=config.target_port,
                network_interface=config.network_interface,
                metadata=session_metadata,
                allowed_hosts=tuple(deduped_hosts),
                allow_external=config.allow_external,
                transport=config.transport,
            )
            if simulate_handshake is not None:
                handshake_simulated = simulate_handshake
            else:
                handshake_simulated = self._simulate_handshake or not should_run_runtime
            handshake = perform_handshake(session_config, simulate=handshake_simulated)
            self._last_handshake = (config.name, handshake)
            if not handshake.success:
                return handshake
            runtime: Optional[CIPIORuntime] = None
            if should_run_runtime:
                session = self._session_factory(session_config, config)
                runtime = CIPIORuntime(
                    configuration=config,
                    store=store,
                    session=session,
                    cycle_interval=self._cycle_interval,
                )
                try:
                    runtime.start()
                except Exception:
                    runtime.stop()
                    raise
            self._active = ActiveSimulation(
                configuration_name=config.name,
                handshake=handshake,
                started_at=datetime.now(timezone.utc),
                runtime=runtime,
            )
            return handshake

    def stop(self) -> None:
        runtime: Optional[CIPIORuntime] = None
        with self._lock:
            if self._active is not None:
                runtime = self._active.runtime
            self._active = None
        if runtime is not None:
            runtime.stop()

    def active(self) -> Optional[ActiveSimulation]:
        with self._lock:
            return self._active

    def last_handshake(self) -> Optional[tuple[str, HandshakeResult]]:
        with self._lock:
            return self._last_handshake

    def ensure_config_mutable(self, config_name: str) -> None:
        """Ensure the configuration is not active before mutating metadata."""

        active = self.active()
        if active and active.configuration_name == config_name:
            raise RuntimeError("Configuration is locked while the simulator is running.")

    def ensure_type_mutable(self, config_name: str) -> None:
        self.ensure_config_mutable(config_name)

    def notify_output_update(self, config_name: str) -> None:
        active = self.active()
        if active and active.configuration_name == config_name:
            if active.runtime is not None:
                active.runtime.notify_output_update()


def _templates() -> Jinja2Templates:
    root = Path(__file__).resolve().parent / "templates"
    return Jinja2Templates(directory=str(root))


def _detect_network_interfaces() -> List[Dict[str, str]]:
    """Return host network interfaces suitable for selection in the UI."""

    try:  # pragma: no cover - optional dependency
        import psutil  # type: ignore[import-untyped]
    except Exception:  # pragma: no cover - fallback path
        psutil = None  # type: ignore[assignment]

    interfaces: List[Dict[str, str]] = []

    if psutil:
        try:
            data = psutil.net_if_addrs()
        except Exception:  # pragma: no cover - defensive
            data = {}
        for name, addrs in data.items():
            labels: List[str] = []
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address:
                    labels.append(addr.address)
            label = name if not labels else f"{name} ({', '.join(labels)})"
            interfaces.append({"name": name, "label": label})
    else:
        try:
            for _, name in socket.if_nameindex():
                interfaces.append({"name": name, "label": name})
        except Exception:  # pragma: no cover - defensive
            pass

    interfaces.sort(key=lambda item: item["name"])
    return interfaces


_HANDSHAKE_LABELS = {
    HandshakePhase.TCP_CONNECT: "TCP handshake",
    HandshakePhase.ENIP_SESSION: "ENIP session",
    HandshakePhase.CIP_FORWARD_OPEN: "CIP forward open",
}


def _format_handshake_failure(handshake: HandshakeResult) -> str:
    failure = next((step for step in handshake.steps if not step.success), None)
    detail = handshake.error or (failure.detail if failure else "Unknown error")
    if failure is None:
        return f"Handshake failed: {detail}"
    label = _HANDSHAKE_LABELS.get(failure.phase, failure.phase.value)
    return f"{label} failed: {detail}"


def get_app(
    store: Optional[ConfigurationStore] = None,
    manager: Optional[SimulatorManager] = None,
) -> FastAPI:
    store = store or ConfigurationStore()
    manager = manager or SimulatorManager()
    templates = _templates()
    app = FastAPI(title="PyCIPSim Web")

    def redirect(path: str, message: Optional[str] = None, error: Optional[str] = None) -> RedirectResponse:
        query = {}
        if message:
            query["message"] = message
        if error:
            query["error"] = error
        url = path
        if query:
            url = f"{path}?{urlencode(query)}"
        return RedirectResponse(url=url, status_code=303)

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request, selected: Optional[str] = None, message: Optional[str] = None, error: Optional[str] = None) -> HTMLResponse:
        configs = list(store.list())
        active = manager.active()
        current = None
        if selected:
            try:
                current = store.get(selected)
            except ConfigurationNotFoundError:
                current = None
        if current is None and configs:
            current = configs[0]
        assembly_groups = {"output": [], "input": []}
        handshake_result: Optional[HandshakeResult] = None
        if current:
            for assembly in current.assemblies:
                direction = (assembly.direction or "").lower()
                key = "input" if direction in {"input", "in"} else "output"
                assembly_groups[key].append(assembly)
            if active and active.configuration_name == current.name:
                handshake_result = active.handshake
            else:
                last_handshake = manager.last_handshake()
                if last_handshake and last_handshake[0] == current.name:
                    handshake_result = last_handshake[1]
        return templates.TemplateResponse(
            request,
            "index.html",
            {
                "configs": configs,
                "current": current,
                "active": active,
                "handshake_result": handshake_result,
                "assembly_groups": assembly_groups,
                "signal_types": CIP_SIGNAL_TYPES,
                "network_interfaces": _detect_network_interfaces(),
                "handshake_labels": {phase.value: label for phase, label in _HANDSHAKE_LABELS.items()},
                "message": message,
                "error": error,
            },
        )

    @app.post("/configs/upload")
    async def upload_config(file: UploadFile = File(...)) -> RedirectResponse:
        try:
            payload = await file.read()
            data = json.loads(payload.decode("utf-8"))
            config = SimulatorConfiguration.from_dict(data)
        except ConfigurationError as exc:
            return redirect("/", error=f"Invalid configuration: {exc}")
        except json.JSONDecodeError as exc:
            return redirect("/", error=f"Configuration is not valid JSON: {exc}")
        store.upsert(config)
        return redirect("/", message=f"Configuration '{config.name}' uploaded.")

    @app.post("/configs/{name}/start")
    async def start_simulator(name: str) -> RedirectResponse:
        try:
            config = store.get(name)
        except ConfigurationNotFoundError:
            raise HTTPException(status_code=404, detail="Configuration not found")
        try:
            handshake = manager.start(config, store)
        except RuntimeError as exc:
            return redirect("/", error=str(exc))
        if not handshake.success:
            return redirect("/", error=_format_handshake_failure(handshake))
        return redirect(
            "/",
            message=f"Simulator started for {name}. Handshake duration {handshake.duration_ms:.2f}ms.",
        )

    @app.post("/stop")
    async def stop_simulator() -> RedirectResponse:
        manager.stop()
        return redirect("/", message="Simulator stopped.")

    @app.post("/configs/{name}/select")
    async def select_configuration(name: str) -> RedirectResponse:
        try:
            store.get(name)
        except ConfigurationNotFoundError:
            return redirect("/", error="Configuration not found")
        return redirect(f"/?selected={name}")

    @app.post("/configs/{name}/assemblies/{assembly_id}/signals/{signal_name}/value")
    async def update_signal_value(
        name: str,
        assembly_id: int,
        signal_name: str,
        action: str = Form("set"),
        value: Optional[str] = Form(None),
    ) -> RedirectResponse:
        try:
            payload = None if action == "clear" else value
            store.update_signal_value(name, assembly_id, signal_name, payload)
            manager.notify_output_update(name)
        except ConfigurationNotFoundError:
            return redirect("/", error="Configuration not found")
        except ConfigurationError as exc:
            return redirect("/", error=str(exc))
        message = "Signal value cleared." if action == "clear" else f"Signal '{signal_name}' value updated."
        return redirect("/", message=message)

    @app.post("/configs/{name}/target")
    async def update_target(
        name: str,
        target_ip: str = Form(...),
        target_port: str = Form(...),
        receive_address: Optional[str] = Form(None),
        multicast: Optional[str] = Form(None),
        network_interface: Optional[str] = Form(None),
        runtime_mode: Optional[str] = Form(None),
        role: Optional[str] = Form(None),
        transport: Optional[str] = Form(None),
        allowed_hosts: Optional[str] = Form(None),
        allow_external: Optional[str] = Form(None),
    ) -> RedirectResponse:
        try:
            manager.ensure_config_mutable(name)
            allow_external_flag = allow_external is not None
            store.update_target(
                name,
                target_ip=target_ip,
                target_port=target_port,
                receive_address=receive_address,
                multicast=bool(multicast),
                network_interface=network_interface,
                runtime_mode=runtime_mode,
                role=role,
                transport=transport,
                allowed_hosts=allowed_hosts,
                allow_external=allow_external_flag,
            )
        except RuntimeError as exc:
            return redirect("/", error=str(exc))
        except ConfigurationNotFoundError:
            return redirect("/", error="Configuration not found")
        except ConfigurationError as exc:
            return redirect("/", error=str(exc))
        return redirect("/", message=f"Target for '{name}' updated.")

    @app.post("/configs/{name}/assemblies/{assembly_id}/signals/{signal_name}/details")
    async def update_signal_details(
        name: str,
        assembly_id: int,
        signal_name: str,
        new_name: str = Form(...),
        offset: str = Form(...),
        signal_type: str = Form(...),
    ) -> RedirectResponse:
        try:
            manager.ensure_config_mutable(name)
            store.update_signal_details(
                name,
                assembly_id,
                signal_name,
                new_name=new_name,
                offset=offset,
                signal_type=signal_type,
            )
        except RuntimeError as exc:
            return redirect("/", error=str(exc))
        except ConfigurationNotFoundError:
            return redirect("/", error="Configuration not found")
        except ConfigurationError as exc:
            return redirect("/", error=str(exc))
        return redirect("/", message=f"Signal '{signal_name}' updated.")

    @app.post("/configs/{name}/assemblies/{assembly_id}/metadata")
    async def update_assembly_metadata(
        name: str,
        assembly_id: int,
        new_id: str = Form(...),
        direction: str = Form(...),
        size_bits: str = Form(...),
    ) -> RedirectResponse:
        try:
            manager.ensure_config_mutable(name)
            assembly = store.update_assembly(
                name,
                assembly_id,
                new_id=new_id,
                direction=direction,
                size_bits=size_bits,
            )
        except RuntimeError as exc:
            return redirect("/", error=str(exc))
        except ConfigurationNotFoundError:
            return redirect("/", error="Configuration not found")
        except ConfigurationError as exc:
            return redirect("/", error=str(exc))
        message = f"Assembly '{assembly.name}' updated."
        return redirect("/", message=message)

    @app.post("/configs/{name}/assemblies/add")
    async def add_assembly(
        name: str,
        assembly_id: str = Form(...),
        assembly_name: str = Form(...),
        direction: str = Form(...),
        size_bits: str = Form(...),
        position: str = Form("end"),
        relative_assembly: Optional[str] = Form(None),
    ) -> RedirectResponse:
        try:
            manager.ensure_config_mutable(name)
            store.add_assembly(
                name,
                assembly_id=assembly_id,
                assembly_name=assembly_name,
                direction=direction,
                size_bits=size_bits,
                position=position,
                relative_assembly=relative_assembly or None,
            )
        except RuntimeError as exc:
            return redirect("/", error=str(exc))
        except ConfigurationNotFoundError:
            return redirect("/", error="Configuration not found")
        except ConfigurationError as exc:
            return redirect("/", error=str(exc))
        return redirect("/", message=f"Assembly '{assembly_name}' added.")

    @app.post("/configs/{name}/assemblies/{assembly_id}/delete")
    async def remove_assembly(name: str, assembly_id: int) -> RedirectResponse:
        try:
            manager.ensure_config_mutable(name)
            store.remove_assembly(name, assembly_id)
        except RuntimeError as exc:
            return redirect("/", error=str(exc))
        except ConfigurationNotFoundError:
            return redirect("/", error="Configuration not found")
        except ConfigurationError as exc:
            return redirect("/", error=str(exc))
        return redirect("/", message=f"Assembly '{assembly_id}' removed.")

    @app.post("/configs/{name}/assemblies/{assembly_id}/signals/add")
    async def add_signal(
        name: str,
        assembly_id: int,
        new_name: str = Form(...),
        offset: str = Form(...),
        signal_type: str = Form(...),
        position: str = Form("after"),
        relative_signal: Optional[str] = Form(None),
    ) -> RedirectResponse:
        try:
            manager.ensure_config_mutable(name)
            store.add_signal(
                name,
                assembly_id,
                new_name=new_name,
                offset=offset,
                signal_type=signal_type,
                position=position,
                relative_signal=relative_signal or None,
            )
        except RuntimeError as exc:
            return redirect("/", error=str(exc))
        except ConfigurationNotFoundError:
            return redirect("/", error="Configuration not found")
        except ConfigurationError as exc:
            return redirect("/", error=str(exc))
        return redirect("/", message=f"Signal '{new_name}' added.")

    @app.post("/configs/{name}/assemblies/{assembly_id}/signals/{signal_name}/delete")
    async def remove_signal(name: str, assembly_id: int, signal_name: str) -> RedirectResponse:
        try:
            manager.ensure_config_mutable(name)
            store.remove_signal(name, assembly_id, signal_name)
        except RuntimeError as exc:
            return redirect("/", error=str(exc))
        except ConfigurationNotFoundError:
            return redirect("/", error="Configuration not found")
        except ConfigurationError as exc:
            return redirect("/", error=str(exc))
        return redirect("/", message=f"Signal '{signal_name}' removed.")

    @app.get("/configs/{name}/export")
    async def export_configuration(name: str) -> Response:
        try:
            config = store.get(name)
        except ConfigurationNotFoundError:
            raise HTTPException(status_code=404, detail="Configuration not found")
        payload = json.dumps(config.to_dict(), indent=2)
        headers = {
            "Content-Disposition": f"attachment; filename={name}.json",
        }
        return Response(content=payload, media_type="application/json", headers=headers)

    return app


__all__ = ["get_app", "SimulatorManager", "ActiveSimulation"]

