"""Command line interface for PyCIPSim."""
from __future__ import annotations

import contextlib
import json
import logging
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import click
from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from .config_store import ConfigurationNotFoundError, ConfigurationStore
from .configuration import (
    ConfigurationError,
    RUNTIME_MODES,
    SimulatorConfiguration,
    normalize_role,
    normalize_transport_mode,
)
from .device import DeviceProfile, ServiceRequest, ServiceResponse, make_default_profiles
from .engine import (
    BenchmarkResult,
    ScenarioExecutionError,
    SimulationResult,
    SimulationScenario,
    SimulationStep,
    run_benchmark,
    run_scenarios_parallel,
)
from .logging_config import configure_logging
from .runtime import AssemblyHost, ConnectionManager
from .runtime.cip_io import CIPIORuntime
from .runtime.enip_server import ENIPServer
from .session import CIPSession, SessionConfig, TransportError
from .target import CIPTargetRuntime
from .runtime.enip_target import ENIPTargetRuntime

console = Console()


@click.group()
@click.option("--verbose", is_flag=True, help="Enable verbose logging output.")
def cli(verbose: bool) -> None:
    """Entry point for the PyCIPSim toolkit."""

    configure_logging(verbose=verbose)


@cli.command()
@click.option("--profile", type=click.Choice([p.name for p in make_default_profiles()]), help="Device profile to use.")
@click.option("--profile-file", type=click.Path(exists=True, dir_okay=False), help="Path to custom profile JSON file.")
@click.option(
    "--scenario",
    "scenario_files",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    multiple=True,
    help="JSON file describing simulation steps. Repeat for multiple scenarios.",
)
@click.option("--ip", default="127.0.0.1", help="Target IP address for live sessions.")
@click.option("--port", default=44818, show_default=True, type=int, help="Target port.")
@click.option("--retries", default=3, show_default=True, type=int, help="Retry attempts.")
@click.option("--timeout", default=2.5, show_default=True, type=float, help="Request timeout in seconds.")
@click.option("--report", type=click.Path(dir_okay=False), help="Where to write the JSON report.")
@click.option("--halt/--no-halt", default=True, show_default=True, help="Stop on first failure.")
@click.option(
    "--workers",
    default=1,
    show_default=True,
    type=int,
    help="Number of scenarios to execute in parallel.",
)
@click.option("--slot", type=int, help="Slot identifier when targeting chassis-based PLCs.")
@click.option(
    "--allowed-host",
    "allowed_hosts",
    multiple=True,
    help="Additional hostnames or IPs to whitelist for live sessions.",
)
@click.option(
    "--allow-external",
    is_flag=True,
    help="Bypass the safety whitelist and allow external connections.",
)
@click.option(
    "--username-env",
    type=str,
    help="Environment variable containing a CIP username for pycomm3 sessions.",
)
@click.option(
    "--password-env",
    type=str,
    help="Environment variable containing a CIP password for pycomm3 sessions.",
)
def run(
    profile: Optional[str],
    profile_file: Optional[str],
    scenario_files: tuple[str, ...],
    ip: str,
    port: int,
    retries: int,
    timeout: float,
    report: Optional[str],
    halt: bool,
    slot: Optional[int],
    allowed_hosts: tuple[str, ...],
    allow_external: bool,
    username_env: Optional[str],
    password_env: Optional[str],
    workers: int,
) -> None:
    """Execute a simulation scenario."""

    if workers < 1:
        raise click.BadParameter("workers must be greater than or equal to 1", param_hint="workers")

    profile_obj = _load_profile(profile, profile_file)
    allowed = list(SessionConfig().allowed_hosts)
    if allowed_hosts:
        allowed.extend(list(allowed_hosts))
    allowed = list(dict.fromkeys(allowed))
    config = SessionConfig(
        ip_address=ip,
        port=port,
        retries=retries,
        timeout=timeout,
        slot=slot,
        allowed_hosts=tuple(allowed),
        allow_external=allow_external,
        username_env_var=username_env,
        password_env_var=password_env,
    )
    if allow_external:
        console.print(
            "[yellow]External connections explicitly enabled. Confirm the target network is approved before proceeding.[/yellow]"
        )

    scenario_map: dict[str, SimulationScenario] = {}
    for scenario_path in scenario_files:
        steps = _load_scenario(Path(scenario_path))
        scenario_session = CIPSession(config=config, profile=profile_obj)
        scenario_map[scenario_path] = SimulationScenario(
            session=scenario_session,
            steps=steps,
            halt_on_failure=halt,
        )

    if report and len(scenario_map) > 1:
        raise click.UsageError("--report is only supported when running a single scenario")

    if len(scenario_map) == 1 and workers == 1:
        _, scenario_runner = next(iter(scenario_map.items()))
        with scenario_runner.session.lifecycle():
            result = scenario_runner.execute()
        _render_single_result(result)
        if report:
            output_path = Path(report)
            result.write_json(output_path)
            console.print(f"Report written to {output_path}")
        return

    try:
        results = run_scenarios_parallel(scenario_map, max_workers=workers)
    except ScenarioExecutionError as exc:
        for name, error in exc.failures.items():
            console.print(f"[red]Scenario '{name}' failed: {error}[/red]")
        raise click.Abort()

    _render_multi_results(results)


@cli.command()
@click.option(
    "--config-file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Simulator configuration JSON file.",
)
@click.option(
    "--cycle-interval",
    default=0.1,
    show_default=True,
    type=float,
    help="Loop interval for cyclic updates (seconds).",
)
@click.option(
    "--role",
    type=click.Choice(["originator", "target"]),
    help="Override the role defined in the configuration file.",
)
@click.option(
    "--transport",
    type=click.Choice(["pycomm3", "pycipsim"]),
    help="Override the transport mode for originator sessions.",
)
def runtime(
    config_file: Path,
    cycle_interval: float,
    role: Optional[str],
    transport: Optional[str],
) -> None:
    """Start a live runtime based on a saved simulator configuration."""

    config = _load_simulator_config(config_file)
    if role:
        config.role = normalize_role(role)
    if transport:
        config.transport = normalize_transport_mode(transport)
    tmp_store_path = Path(tempfile.mkdtemp(prefix="pycipsim-cli-")) / "config.json"
    store = ConfigurationStore(storage_path=tmp_store_path)
    store.upsert(config)
    if config.role == "target":
        transport_mode = (config.transport or "pycipsim").lower()
        if transport_mode == "enip":
            runtime = ENIPTargetRuntime(config, store, cycle_interval=cycle_interval)
            runtime.start()
            listen_port = runtime.tcp_port
            console.print(
                f"[green]ENIP target runtime listening on {config.target_ip}:{listen_port}. Press CTRL+C to stop.[/green]"
            )
        else:
            runtime = CIPTargetRuntime(config, store, cycle_interval=cycle_interval)
            runtime.start()
            console.print(
                f"[green]Target runtime listening on {config.target_ip}:{config.target_port}. Press CTRL+C to stop.[/green]"
            )
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            console.print("Stopping target runtime...")
        finally:
            runtime.stop()
        return

    session_metadata = dict(config.metadata)
    max_connection_size = config.max_connection_size_bytes()
    if max_connection_size > 0:
        session_metadata["max_connection_size_bytes"] = max_connection_size
    forward_open = config.build_forward_open_metadata()
    if forward_open:
        session_metadata["forward_open"] = forward_open
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
    session_config = SessionConfig(
        ip_address=config.target_ip,
        port=config.target_port,
        network_interface=config.network_interface,
        metadata=session_metadata,
        allowed_hosts=tuple(deduped_hosts),
        allow_external=config.allow_external,
        transport=config.transport,
    )
    session = CIPSession(session_config)
    runtime = CIPIORuntime(
        configuration=config,
        store=store,
        session=session,
        cycle_interval=cycle_interval,
    )
    runtime.start()
    console.print(
        f"[green]Originator runtime connected to {config.target_ip}:{config.target_port}. Press CTRL+C to stop.[/green]"
    )
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        console.print("Stopping originator runtime...")
    finally:
        runtime.stop()


@cli.command()
@click.option(
    "--config-file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Simulator configuration JSON or YAML file.",
)
def inspect(config_file: Path) -> None:
    """Display a rich summary of a simulator configuration."""

    config = _load_simulator_config(config_file)
    _render_configuration_overview(config)


@cli.command()
@click.option("--profile", type=click.Choice([p.name for p in make_default_profiles()]), help="Device profile to use.")
@click.option("--profile-file", type=click.Path(exists=True, dir_okay=False), help="Path to custom profile JSON file.")
@click.option("--ip", default="127.0.0.1", show_default=True, help="Target IP address for live sessions.")
@click.option("--port", default=44818, show_default=True, type=int, help="Target port.")
@click.option("--retries", default=3, show_default=True, type=int, help="Retry attempts.")
@click.option("--timeout", default=2.5, show_default=True, type=float, help="Request timeout in seconds.")
@click.option("--messages", default=200, show_default=True, type=int, help="Number of benchmark requests to send.")
@click.option("--warmup", default=10, show_default=True, type=int, help="Warmup requests to issue before measuring throughput.")
@click.option(
    "--target-throughput",
    default=100.0,
    show_default=True,
    type=float,
    help="Required throughput in messages per second.",
)
@click.option("--service", default="ECHO", show_default=True, help="CIP service code to exercise.")
@click.option("--tag", default="BenchmarkTag", show_default=True, help="Tag path used for the benchmark request.")
@click.option("--payload", default="Hello CIP", show_default=True, help="Payload to send with each request.")
@click.option("--slot", type=int, help="Slot identifier when targeting chassis-based PLCs.")
@click.option(
    "--allowed-host",
    "allowed_hosts",
    multiple=True,
    help="Additional hostnames or IPs to whitelist for live sessions.",
)
@click.option("--allow-external", is_flag=True, help="Bypass the safety whitelist and allow external connections.")
@click.option("--username-env", type=str, help="Environment variable containing a CIP username for pycomm3 sessions.")
@click.option("--password-env", type=str, help="Environment variable containing a CIP password for pycomm3 sessions.")
def benchmark(
    profile: Optional[str],
    profile_file: Optional[str],
    ip: str,
    port: int,
    retries: int,
    timeout: float,
    messages: int,
    warmup: int,
    target_throughput: float,
    service: str,
    tag: str,
    payload: str,
    slot: Optional[int],
    allowed_hosts: tuple[str, ...],
    allow_external: bool,
    username_env: Optional[str],
    password_env: Optional[str],
) -> None:
    """Validate simulator throughput against performance targets."""

    if messages < 1:
        raise click.BadParameter("messages must be at least 1", param_hint="messages")
    if warmup < 0:
        raise click.BadParameter("warmup must be zero or greater", param_hint="warmup")
    if target_throughput <= 0:
        raise click.BadParameter(
            "target-throughput must be greater than zero", param_hint="target-throughput"
        )

    profile_obj = _load_profile(profile, profile_file)
    allowed = list(SessionConfig().allowed_hosts)
    if allowed_hosts:
        allowed.extend(list(allowed_hosts))
    allowed = list(dict.fromkeys(allowed))
    config = SessionConfig(
        ip_address=ip,
        port=port,
        retries=retries,
        timeout=timeout,
        slot=slot,
        allowed_hosts=tuple(allowed),
        allow_external=allow_external,
        username_env_var=username_env,
        password_env_var=password_env,
    )

    if allow_external:
        console.print(
            "[yellow]External connections explicitly enabled. Confirm the target network is approved before proceeding.[/yellow]"
        )

    session = CIPSession(config=config, profile=profile_obj)
    request = ServiceRequest(
        service_code=service,
        tag_path=tag,
        payload=payload.encode("latin1") if payload else None,
    )

    try:
        with session.lifecycle():
            result = run_benchmark(session, request, message_count=messages, warmup=warmup)
    except TransportError as exc:
        raise click.ClickException(str(exc)) from exc

    _render_benchmark(result, target_throughput)
    if result.throughput_per_second < target_throughput:
        raise click.ClickException(
            f"Throughput {result.throughput_per_second:.2f} msg/s did not meet the target of {target_throughput:.2f} msg/s"
        )


@cli.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="Host interface to bind the web UI.")
@click.option("--port", default=8000, show_default=True, type=int, help="Port for the web UI.")
@click.option(
    "--reload/--no-reload",
    default=False,
    show_default=True,
    help="Enable auto-reload (development only).",
)
def web(host: str, port: int, reload: bool) -> None:
    """Launch the web-based configuration interface."""

    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise click.UsageError(
            "uvicorn is required to launch the web UI. Reinstall PyCIPSim with its default dependencies or install uvicorn."
        ) from exc

    from .web import get_app

    app = get_app()
    uvicorn.run(app, host=host, port=port, reload=reload)


@cli.command()
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False),
    help="Simulator configuration JSON or YAML file.",
)
@click.option(
    "--assembly-file",
    type=click.Path(exists=True, dir_okay=False),
    help="Assembly definitions in JSON or YAML.",
)
@click.option("--name", default="TargetServer", show_default=True, help="Configuration name when using --assembly-file.")
@click.option("--listener-host", type=str, help="Override the listener host binding.")
@click.option(
    "--listener-port",
    type=int,
    help="Override the listener TCP/UDP port (0 selects a random free port).",
)
@click.option("--listener-interface", type=str, help="Override the listener network interface identifier.")
@click.option(
    "--duration",
    type=float,
    help="Seconds to run before exiting. Runs until interrupted when omitted.",
)
def serve(
    config_path: Optional[str],
    assembly_file: Optional[str],
    name: str,
    listener_host: Optional[str],
    listener_port: Optional[int],
    listener_interface: Optional[str],
    duration: Optional[float],
) -> None:
    """Start the simulator in target mode and expose assemblies to originators."""

    if not config_path and not assembly_file:
        raise click.UsageError("Provide either --config or --assembly-file.")
    if config_path and assembly_file:
        raise click.UsageError("Use --config or --assembly-file, not both.")
    if duration is not None and duration < 0:
        raise click.BadParameter("duration must be zero or positive", param_hint="duration")

    if config_path:
        structure = _load_structure(Path(config_path))
        if not isinstance(structure, dict):
            raise click.ClickException("Configuration file must contain an object at the top level.")
        data = structure
    else:
        structure = _load_structure(Path(assembly_file))
        assemblies = _load_assemblies_payload(structure)
        data = {
            "name": name,
            "role": "target",
            "listener": {},
            "target": {"ip": "127.0.0.1", "port": 44818},
            "assemblies": assemblies,
        }

    try:
        config = SimulatorConfiguration.from_dict(data)
    except ConfigurationError as exc:
        raise click.ClickException(f"Invalid configuration: {exc}") from exc

    if config.role != "target":
        console.print("[yellow]Overriding simulator role to 'target' for the serve command.[/yellow]")
        config.role = "target"

    if listener_host:
        config.listener_host = listener_host
    elif not config.listener_host:
        config.listener_host = "0.0.0.0"
    if listener_port is not None:
        config.listener_port = listener_port
    if listener_interface is not None:
        config.listener_interface = listener_interface or None
    if not config.listener_host:
        config.listener_host = "0.0.0.0"

    cycle_interval = max(0.05, config.default_production_interval_seconds())

    with tempfile.TemporaryDirectory(prefix="pycipsim-serve-") as tmpdir:
        store = ConfigurationStore(storage_path=Path(tmpdir) / "config.json")
        store.upsert(config)

        host = AssemblyHost(config.assemblies, cycle_interval=cycle_interval)

        def _input_callback(assembly_id: int, values: Dict[str, object]) -> None:
            for signal_name, signal_value in values.items():
                if signal_value is None:
                    continue
                with contextlib.suppress(Exception):
                    store.update_signal_value(
                        config.name, assembly_id, signal_name, str(signal_value)
                    )

        host.set_input_callback(_input_callback)
        for assembly in config.assemblies:
            if (assembly.direction or "").lower() not in {"output", "out"}:
                continue
            host.register_producer(
                assembly.assembly_id,
                _build_store_producer_cli(store, config.name, assembly.assembly_id),
            )
        _sync_host_outputs_cli(host, config)

        server = ENIPServer(
            host=config.listener_host or "0.0.0.0",
            tcp_port=config.listener_port,
            udp_port=config.listener_port,
            connection_manager=ConnectionManager(),
            reaper_interval=max(cycle_interval, 0.5),
            assembly_host=host,
        )
        try:
            server.start()
        except Exception as exc:  # pragma: no cover - server startup failure
            raise click.ClickException(f"Failed to start ENIP server: {exc}") from exc

        actual_port = server.tcp_port
        outputs = [a for a in config.assemblies if (a.direction or "").lower() in {"output", "out"}]
        inputs = [a for a in config.assemblies if (a.direction or "").lower() in {"input", "in"}]
        console.print(
            f"Target simulator listening on {config.listener_host}:{actual_port} "
            f"with {len(outputs)} outputs and {len(inputs)} inputs. Press Ctrl+C to stop."
        )

        stop_at = time.monotonic() + duration if duration is not None else None
        try:
            while True:
                if stop_at is not None and time.monotonic() >= stop_at:
                    break
                time.sleep(0.1)
        except KeyboardInterrupt:
            console.print("\nStopping target server...")
        finally:
            server.stop()
        console.print("Target server stopped.")

@cli.command("list-profiles")
def list_profiles() -> None:
    """Display bundled device profiles."""

    profiles = make_default_profiles()
    table = Table(title="Available Device Profiles")
    table.add_column("Name")
    table.add_column("Services")
    for profile in profiles:
        table.add_row(profile.name, ", ".join(profile.services.keys()))
    console.print(table)


@cli.command()
@click.argument("output", type=click.Path(dir_okay=False))
def scaffold(output: str) -> None:
    """Generate a template scenario JSON file."""

    steps = [
        {
            "request": {
                "service_code": "ECHO",
                "tag_path": "SimulatedTag",
                "payload": "Hello CIP",
                "metadata": {"comment": "Example"},
            },
            "expected_status": "SUCCESS",
            "description": "Verify echo service",
        }
    ]
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(steps, indent=2), encoding="utf-8")
    console.print(f"Scenario template written to {output_path}")


def _render_configuration_overview(config: SimulatorConfiguration) -> None:
    role_label = Text((config.role or "originator").replace("_", " ").title(), style="bold magenta")
    overview = Table.grid(expand=True)
    overview.add_column(justify="left")
    overview.add_column(justify="right")
    overview.add_row(Text(config.name, style="bold cyan"), role_label)
    transport_mode = (config.transport or "pycomm3").replace("_", " ")
    runtime_mode = (config.runtime_mode or "simulated").replace("_", " ")
    assembly_summary = f"{len(config.assemblies)} assemblies" if config.assemblies else "No assemblies"
    overview.add_row(
        Text(f"{transport_mode} transport • {runtime_mode}", style="dim"),
        Text(assembly_summary, style="dim"),
    )
    console.print(Panel(overview, title="Simulator Overview", border_style="bright_cyan"))

    connection_table = Table(box=box.ROUNDED, expand=True)
    connection_table.add_column("Field", style="cyan", no_wrap=True)
    connection_table.add_column("Value", style="white", overflow="fold")
    connection_table.add_row("Target", f"{config.target_ip}:{config.target_port}")
    if config.network_interface:
        connection_table.add_row("Network interface", config.network_interface)
    if config.receive_address:
        connection_table.add_row("Receive address", config.receive_address)
    connection_table.add_row("Transport", transport_mode.title())
    connection_table.add_row("Runtime mode", runtime_mode.title())
    connection_table.add_row("Multicast", "Yes" if getattr(config, "multicast", False) else "No")
    allowed_hosts = "\n".join(config.allowed_hosts) if config.allowed_hosts else "—"
    connection_table.add_row("Allowed hosts", allowed_hosts)
    connection_table.add_row("Allow external", "Yes" if config.allow_external else "No")
    listener_host = getattr(config, "listener_host", None)
    listener_port = getattr(config, "listener_port", None)
    if listener_host or listener_port is not None:
        host_text = listener_host or "0.0.0.0"
        if listener_port is not None:
            host_text = f"{host_text}:{listener_port}"
        connection_table.add_row("Listener", host_text)
    listener_interface = getattr(config, "listener_interface", None)
    if listener_interface:
        connection_table.add_row("Listener iface", listener_interface)

    metadata_table = Table(box=box.ROUNDED, expand=True)
    metadata_table.add_column("Key", style="magenta", no_wrap=True)
    metadata_table.add_column("Value", style="white", overflow="fold")
    if config.metadata:
        for key, value in sorted(config.metadata.items()):
            metadata_table.add_row(str(key), _format_metadata_value(value))
    else:
        metadata_table.add_row("—", "No metadata entries")

    console.print(
        Columns(
            [
                Panel(connection_table, title="Connection", border_style="bright_blue"),
                Panel(metadata_table, title="Metadata", border_style="bright_magenta"),
            ],
            equal=True,
            expand=True,
        )
    )

    assembly_tree = Tree("[bold]Assemblies[/bold]")
    if config.assemblies:
        for assembly in config.assemblies:
            direction = (assembly.direction or "").replace("_", " ").strip() or "Unspecified"
            direction_label = direction.title()
            summary_bits = f"{assembly.size_bits} bits"
            branch_label = f"[cyan]#{assembly.assembly_id}[/cyan] {assembly.name or 'Assembly'} • {direction_label} • {summary_bits}"
            if assembly.production_interval_ms:
                branch_label += f" • {assembly.production_interval_ms} ms"
            branch = assembly_tree.add(branch_label)
            if assembly.signals:
                for signal in assembly.signals:
                    branch.add(_render_signal_line(signal))
            else:
                branch.add("[dim]No signals defined[/dim]")
    else:
        assembly_tree.add("[dim]No assemblies defined[/dim]")

    console.print(Panel(assembly_tree, title="Assemblies", border_style="yellow"))


def _render_signal_line(signal: Any) -> str:
    bits = signal.bit_length()
    pieces = [f"@{signal.offset}", signal.name, f"[{signal.signal_type}]"]
    if bits:
        pieces.append(f"{bits}b")
    if signal.value not in (None, ""):
        pieces.append(f"= {signal.value}")
    line = " • ".join(pieces)
    if getattr(signal, "is_padding", False):
        return f"[dim]{line} (padding)[/dim]"
    return line


def _format_metadata_value(value: Any) -> str:
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value, indent=2, sort_keys=True)
        except TypeError:
            return str(value)
    return str(value)


def _load_structure(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        try:  # pragma: no cover - optional dependency
            import yaml  # type: ignore[import-untyped]
        except ImportError as exc:
            raise click.ClickException(
                "Configuration file is not valid JSON and PyYAML is not installed."
            ) from exc
        try:
            return yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise click.ClickException(f"Failed to parse configuration file: {exc}") from exc


def _load_assemblies_payload(structure: Any) -> List[Dict[str, Any]]:
    if isinstance(structure, dict):
        assemblies = structure.get("assemblies")
    else:
        assemblies = structure
    if assemblies is None:
        raise click.ClickException("Assembly definition file does not contain assemblies data.")
    if not isinstance(assemblies, list):
        raise click.ClickException("Assemblies payload must be a list of definitions.")
    return assemblies


def _build_store_producer_cli(
    store: ConfigurationStore, config_name: str, assembly_id: int
):
    def producer(_: Any) -> Optional[Dict[str, object]]:
        try:
            configuration = store.get(config_name)
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
            values[signal.name] = signal.value
        return values or None

    return producer


def _sync_host_outputs_cli(host: AssemblyHost, config: SimulatorConfiguration) -> None:
    for assembly in config.assemblies:
        direction = (assembly.direction or "").lower()
        if direction not in {"input", "in"}:
            continue
        values: Dict[str, object] = {}
        for signal in assembly.signals:
            if signal.is_padding or signal.value is None:
                continue
            values[signal.name] = signal.value
        if not values:
            continue
        with contextlib.suppress(KeyError):
            host.update_assembly_values(assembly.assembly_id, values)


def _render_benchmark(result: BenchmarkResult, target: float) -> None:
    table = Table(title="Benchmark Summary")
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("Total messages", str(result.total_messages))
    table.add_row("Duration (s)", f"{result.duration_seconds:.4f}")
    table.add_row("Throughput (msg/s)", f"{result.throughput_per_second:.2f}")
    table.add_row("Successes", str(result.success_count))
    table.add_row("Failures", str(result.failure_count))
    table.add_row("Target throughput (msg/s)", f"{target:.2f}")
    table.add_row(
        "Requirement met",
        "Yes" if result.throughput_per_second >= target else "No",
    )
    console.print(table)


def _render_single_result(result: SimulationResult) -> None:
    console.print(f"Simulation success: {result.success}")
    metrics_table = Table(title="Simulation Metrics")
    metrics_table.add_column("Metric")
    metrics_table.add_column("Value")
    metrics = result.metrics
    metrics_table.add_row("Total steps", str(metrics.total_steps))
    metrics_table.add_row("Completed steps", str(metrics.completed_steps))
    metrics_table.add_row("Successes", str(metrics.success_count))
    metrics_table.add_row("Failures", str(metrics.failure_count))
    metrics_table.add_row("Average round trip (ms)", f"{metrics.average_round_trip_ms:.2f}")
    metrics_table.add_row("Max round trip (ms)", f"{metrics.max_round_trip_ms:.2f}")
    console.print(metrics_table)
    if metrics.status_counts:
        status_table = Table(title="Response Status Counts")
        status_table.add_column("Status")
        status_table.add_column("Count")
        for status, count in metrics.status_counts.items():
            status_table.add_row(status, str(count))
        console.print(status_table)
    table = Table(title="Simulation Responses")
    table.add_column("Service")
    table.add_column("Status")
    table.add_column("Round Trip (ms)")
    table.add_column("Payload")

    for response in result.responses:
        table.add_row(
            response.service,
            response.status,
            f"{response.round_trip_ms:.2f}",
            (response.payload or b"").decode("latin1") if response.payload else "",
        )
    console.print(table)


def _render_multi_results(results: Dict[str, SimulationResult]) -> None:
    summary_table = Table(title="Batch Simulation Summary")
    summary_table.add_column("Scenario")
    summary_table.add_column("Success")
    summary_table.add_column("Completed")
    summary_table.add_column("Failures")
    summary_table.add_column("Avg RT (ms)")
    summary_table.add_column("Max RT (ms)")

    aggregate_success = 0
    total_completed = 0
    total_steps = 0
    total_failures = 0
    weighted_rt = 0.0
    max_rt = 0.0
    status_counts: Dict[str, int] = {}

    for name, result in sorted(results.items()):
        metrics = result.metrics
        summary_table.add_row(
            str(name),
            "Yes" if result.success else "No",
            f"{metrics.completed_steps}/{metrics.total_steps}",
            str(metrics.failure_count),
            f"{metrics.average_round_trip_ms:.2f}",
            f"{metrics.max_round_trip_ms:.2f}",
        )
        if result.success:
            aggregate_success += 1
        total_completed += metrics.completed_steps
        total_steps += metrics.total_steps
        total_failures += metrics.failure_count
        weighted_rt += metrics.average_round_trip_ms * metrics.completed_steps
        max_rt = max(max_rt, metrics.max_round_trip_ms)
        for status, count in metrics.status_counts.items():
            status_counts[status] = status_counts.get(status, 0) + count

    console.print(summary_table)

    aggregate_table = Table(title="Aggregate Metrics")
    aggregate_table.add_column("Metric")
    aggregate_table.add_column("Value")
    aggregate_table.add_row("Scenarios", str(len(results)))
    aggregate_table.add_row("Successful scenarios", str(aggregate_success))
    aggregate_table.add_row("Total steps", str(total_steps))
    aggregate_table.add_row("Completed steps", str(total_completed))
    aggregate_table.add_row("Failures", str(total_failures))
    average_rt = weighted_rt / total_completed if total_completed else 0.0
    aggregate_table.add_row("Average round trip (ms)", f"{average_rt:.2f}")
    aggregate_table.add_row("Max round trip (ms)", f"{max_rt:.2f}")
    console.print(aggregate_table)

    if status_counts:
        status_table = Table(title="Aggregate Response Status Counts")
        status_table.add_column("Status")
        status_table.add_column("Count")
        for status, count in sorted(status_counts.items()):
            status_table.add_row(status, str(count))
        console.print(status_table)


def _load_simulator_config(path: Path) -> SimulatorConfiguration:
    try:
        payload = _load_structure(path)
    except click.ClickException:
        raise
    except Exception as exc:  # pragma: no cover - defensive fallback
        raise click.ClickException(f"Failed to load configuration file: {exc}") from exc

    if not isinstance(payload, dict):
        raise click.ClickException("Configuration file must contain an object at the top level.")

    try:
        return SimulatorConfiguration.from_dict(payload)
    except ConfigurationError as exc:
        raise click.ClickException(f"Invalid configuration: {exc}") from exc


def _load_profile(name: Optional[str], profile_file: Optional[str]) -> DeviceProfile:
    if profile_file:
        data = json.loads(Path(profile_file).read_text(encoding="utf-8"))
        services = {}
        for service_name, response_data in data.get("services", {}).items():
            payload_bytes = (response_data.get("payload") or "").encode("latin1") or None

            def handler(request: ServiceRequest, status=response_data.get("status", "SUCCESS"), payload=payload_bytes) -> ServiceResponse:
                return ServiceResponse(service=request.service_code, status=status, payload=payload)

            services[service_name] = handler
        return DeviceProfile(name=data.get("name", "CustomProfile"), services=services)

    profiles = {profile.name: profile for profile in make_default_profiles()}
    if name and name in profiles:
        return profiles[name]
    if profiles:
        return next(iter(profiles.values()))
    raise click.UsageError("No device profiles available")


def _load_scenario(path: Path) -> Iterable[SimulationStep]:
    data = json.loads(path.read_text(encoding="utf-8"))
    steps = []
    for entry in data:
        request = ServiceRequest(
            service_code=entry["request"]["service_code"],
            tag_path=entry["request"]["tag_path"],
            payload=(entry["request"].get("payload") or "").encode("latin1") or None,
            metadata=entry["request"].get("metadata", {}),
        )
        steps.append(
            SimulationStep(
                request=request,
                expected_status=entry.get("expected_status"),
                description=entry.get("description"),
            )
        )
    return steps


if __name__ == "__main__":  # pragma: no cover
    cli()
