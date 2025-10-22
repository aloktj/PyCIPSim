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
from fastapi.responses import HTMLResponse, RedirectResponse
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

    def ensure_type_mutable(self, config_name: str) -> None:
        active = self.active()
        if active and active.configuration_name == config_name:
            raise RuntimeError("Signal types are locked while the simulator is running.")


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
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "configs": configs,
                "current": current,
                "active": active,
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

    @app.post("/configs/{name}/assemblies/{assembly_id}/signals/{signal_name}/type")
    async def update_signal_type(
        name: str,
        assembly_id: int,
        signal_name: str,
        signal_type: str = Form(...),
    ) -> RedirectResponse:
        try:
            manager.ensure_type_mutable(name)
            store.update_signal_type(name, assembly_id, signal_name, signal_type)
        except RuntimeError as exc:
            return redirect("/", error=str(exc))
        except ConfigurationNotFoundError:
            return redirect("/", error="Configuration not found")
        except ConfigurationError as exc:
            return redirect("/", error=str(exc))
        return redirect("/", message=f"Signal '{signal_name}' type updated to {signal_type}.")

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

    return app


__all__ = ["get_app", "SimulatorManager", "ActiveSimulation"]

