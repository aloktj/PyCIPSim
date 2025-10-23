"""FastAPI application exposing the web configuration UI."""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
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
from ..handshake import HandshakeResult, perform_handshake
from ..session import SessionConfig


@dataclass
class ActiveSimulation:
    """Runtime metadata for a started simulator."""

    configuration_name: str
    handshake: HandshakeResult
    started_at: datetime


class SimulatorManager:
    """Coordinate start/stop operations for configurations."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._active: Optional[ActiveSimulation] = None

    def start(self, config: SimulatorConfiguration, simulate_handshake: bool = True) -> HandshakeResult:
        with self._lock:
            if self._active is not None:
                raise RuntimeError("A simulation is already running. Stop it before starting a new one.")
            session_config = SessionConfig(
                ip_address=config.target_ip,
                port=config.target_port,
                metadata=config.metadata,
            )
            handshake = perform_handshake(session_config, simulate=simulate_handshake)
            if not handshake.success:
                raise RuntimeError(handshake.error or "Handshake failed")
            self._active = ActiveSimulation(
                configuration_name=config.name,
                handshake=handshake,
                started_at=datetime.now(timezone.utc),
            )
            return handshake

    def stop(self) -> None:
        with self._lock:
            self._active = None

    def active(self) -> Optional[ActiveSimulation]:
        with self._lock:
            return self._active

    def ensure_config_mutable(self, config_name: str) -> None:
        """Ensure the configuration is not active before mutating metadata."""

        active = self.active()
        if active and active.configuration_name == config_name:
            raise RuntimeError("Configuration is locked while the simulator is running.")

    def ensure_type_mutable(self, config_name: str) -> None:
        self.ensure_config_mutable(config_name)


def _templates() -> Jinja2Templates:
    root = Path(__file__).resolve().parent / "templates"
    return Jinja2Templates(directory=str(root))


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
        if current:
            for assembly in current.assemblies:
                direction = (assembly.direction or "").lower()
                key = "input" if direction in {"input", "in"} else "output"
                assembly_groups[key].append(assembly)
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "configs": configs,
                "current": current,
                "active": active,
                "assembly_groups": assembly_groups,
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
            handshake = manager.start(config)
        except RuntimeError as exc:
            return redirect("/", error=str(exc))
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
    ) -> RedirectResponse:
        try:
            manager.ensure_config_mutable(name)
            store.update_target(
                name,
                target_ip=target_ip,
                target_port=target_port,
                receive_address=receive_address,
                multicast=bool(multicast),
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
    ) -> RedirectResponse:
        try:
            manager.ensure_config_mutable(name)
            assembly = store.update_assembly(
                name,
                assembly_id,
                new_id=new_id,
                direction=direction,
            )
        except RuntimeError as exc:
            return redirect("/", error=str(exc))
        except ConfigurationNotFoundError:
            return redirect("/", error="Configuration not found")
        except ConfigurationError as exc:
            return redirect("/", error=str(exc))
        message = f"Assembly '{assembly.name}' updated."
        return redirect("/", message=message)

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
                relative_signal=relative_signal,
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

