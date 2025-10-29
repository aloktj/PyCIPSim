# PyCIPSim

> **Authoritative requirements live in [`SRS.md`](./SRS.md).** This README explains how the current codebase implements those
> directives, how to get started locally, and what work remains.

## Overview

PyCIPSim is a Python toolkit for simulating Common Industrial Protocol (CIP) traffic so that PLC integrations can be exercised
without dedicated hardware. The implementation mirrors the major capabilities defined in the SRS:

- **Session Management (`pycipsim.session`)** — wraps the lifecycle of CIP connections, enforces SRS §5.2 safety whitelists,
  loads credentials from environment variables per §5.3, and exposes retry-aware transports for both simulated devices and live
  PLCs (via `pycomm3`).
- **Device Profiles (`pycipsim.device`)** — captures reusable PLC behaviours, fault injections, and request/response data
  structures.
- **Scenario Execution (`pycipsim.engine`)** — orchestrates scripted message exchanges, validates expectations, and generates
  machine-readable reports.
- **Automation Surface (`pycipsim.cli`)** — Click-powered CLI that runs scenarios, lists bundled profiles, scaffolds new
  scenario definitions, exposes a throughput benchmark, and launches the web dashboard.
- **Web Application (`pycipsim.web`)** — FastAPI/Jinja interface for uploading CIP configurations, editing assemblies, and
  supervising simulator state with explicit handshake visibility.

All modules log through `pycipsim.logging_config` to honour the observability requirements in the SRS.

## Current Status

- ✅ Editable install exposes the `pycipsim` console script so CLI commands are available immediately after setup.
- ✅ Optional `[pycomm3]` extra now resolves against the published `pycomm3==1.2.14` release, so hardware connectivity installs succeed on fresh environments.
- ✅ `pycipsim scaffold` creates intermediate directories before writing scenario templates, unblocking first-run usage.
- ✅ `pycipsim benchmark` validates the ≥100 msg/s performance requirement called out in SRS §5.1 when run against bundled profiles.
- ✅ The FastAPI web dashboard persists uploaded CIP configurations, enforces signal-type locking while simulations run, and now drives a live CIP runtime that streams output edits and decodes inbound payloads in real time.
- ✅ `perform_handshake` renders explicit TCP → ENIP → CIP forward-open progress so operators can confirm originator behaviour before exchanging cyclic I/O.

## Next Steps

1. Deliver the live CIP I/O runtime outlined in SRS §3.7 by opening real sessions, running cyclic producer/consumer loops, bridging output edits to the wire, and decoding inbound payloads back into the UI.
2. Add integration coverage that exercises real `pycomm3` sessions when hardware or emulators are available.
3. Expand the web UI with live log streaming, UDP transport configuration, and richer assembly visualisations.
4. Implement UDP transport adapters to satisfy the communications interface expectations in SRS §4.5.
5. Extend CLI and web regression suites to cover failure messaging, report downloads, and session teardown scenarios.

## Repository Layout

```
pyproject.toml
src/
  pycipsim/
    __init__.py
    cli.py
    device.py
    engine.py
    logging_config.py
    session.py
tests/
  test_scenario.py
```

The `src/` layout keeps runtime packages separate from tests and documentation, simplifying packaging and tooling integration.

## Getting Started

### Prerequisites

- Python 3.10 or newer (per SRS §2.4).
- `pip` or `uv` for dependency installation.
- Optional: `pycomm3` when connecting to real PLC hardware.

### Installation

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
pip install -e .[dev]
# Optional hardware support
pip install -e .[pycomm3]
```

### Running the CLI

1. Generate a scenario template:
   ```bash
   pycipsim scaffold scenarios/echo.json
   ```
2. Execute the scenario against the default simulated Echo profile:
   ```bash
   pycipsim run --scenario scenarios/echo.json --report reports/echo.json
   ```
3. Inspect the bundled device profiles:
   ```bash
   pycipsim list-profiles
   ```

4. Validate throughput requirements using the benchmark harness:
   ```bash
   pycipsim benchmark --messages 500 --target-throughput 100
   ```

Repeat `--scenario` to execute several definitions in one run. Provide `--workers` to fan them out across threads for faster
feedback while iterating on multiple behaviours.

When `pycomm3` is available you can point the same command at live hardware with `--ip`, `--port`, and `--slot` overrides. Use
`--allowed-host` to extend the default whitelist or `--allow-external` (with caution) to bypass it, and provide credential
variable names via `--username-env` / `--password-env` so secrets stay out of config files. The CLI emits structured JSON
reports and rich tables that include latency metrics and status tallies to satisfy SRS §3.4 and §3.5.

### Launching the Web UI

With the default installation dependencies in place you can launch the FastAPI dashboard directly:

```bash
pycipsim web --host 0.0.0.0 --port 8000
```

Navigate to `http://localhost:8000` to upload CIP configuration files, select a saved configuration to inspect assemblies,
change signal types before starting the simulator, and toggle payload values while the simulator is running. The page displays
TCP, ENIP, and CIP forward-open handshake steps so you can confirm originator progress prior to cyclic I/O traffic.

### Authoring Scenarios

Scenarios are JSON arrays with each element describing a single request/expectation pair:

```json
[
  {
    "request": {
      "service_code": "ECHO",
      "tag_path": "TagA",
      "payload": "Hello CIP",
      "metadata": {"comment": "Sample"}
    },
    "expected_status": "SUCCESS",
    "description": "Validate echo behaviour"
  }
]
```

The CLI loader mirrors this structure and converts payload strings to bytes internally. Scenario execution halts on the first
failure by default, but `--no-halt` enables full-run auditing.

### Web Configuration Files

The web interface accepts JSON objects describing originator connection details and CIP assemblies. A minimal example looks like
this:

```json
{
  "name": "Demo Cell",
  "target": {
    "ip": "192.168.0.10",
    "port": 44818,
    "receive_address": "239.1.1.1",
    "multicast": true,
    "interface": "eth0",
    "mode": "live"
  },
  "assemblies": [
    {
      "id": 100,
      "name": "Outputs",
      "direction": "output",
      "signals": [
        {"name": "ValveA", "offset": 0, "type": "BOOL", "value": "0"},
        {"name": "PumpSpeed", "offset": 2, "type": "INT", "value": "1200"}
      ]
    }
  ]
}
```

Signals can be edited directly in the UI prior to starting the simulator. Once running, signal types and offsets are locked, but
operators can use the provided set/clear controls to adjust payload values on the fly.

Use the configuration panel to select the host network interface that should source CIP traffic. The choice is saved with the
configuration and reused whenever the simulator starts, ensuring connections originate from the expected adapter. The same
panel exposes a **Connection Mode** selector: choose *Simulated* to exercise the UI without opening sockets, or switch to *Live*
to attempt real TCP/ENIP/CIP exchanges with the target device.

For environments with strict egress policies, populate the **Allowed Hosts** field with any additional IPs or hostnames the
simulator is permitted to contact. The active target IP is automatically whitelisted at runtime, and you can tick **Allow
external targets** to bypass the whitelist entirely when connecting to lab hardware outside the default loopback range.

### Batch & Parallel Execution

PyCIPSim now supports multi-scenario runs so that development and regression testing can happen in parallel:

```bash
pycipsim run \
  --scenario scenarios/echo.json \
  --scenario scenarios/counter.json \
  --workers 2
```

Each scenario spins up an isolated `CIPSession` and the CLI renders a summary table along with aggregate latency and status
metrics. Failures across any worker surface as a non-zero exit status, keeping CI pipelines honest.

### Device Profiles

`pycipsim.device` includes two sample profiles to speed up local testing:

- **EchoDevice** — returns the request payload unchanged (`ECHO` service), supporting connectivity checks.
- **CounterDevice** — increments a per-tag counter (`READ` service), useful for exercising stateful scenarios.

Fault injection helpers such as `drop_request_fault` and `delay_response_fault` can be composed into custom profiles to satisfy
robustness testing requirements in SRS §3.3.

## Safety & Security Controls

- **Connection Whitelists:** `SessionConfig.allowed_hosts` defaults to loopback-only communication. Provide additional hosts via
  the CLI (`--allowed-host`) or environment variable `PYCIPSIM_ALLOWED_HOSTS`. Entries may be hostnames, literal IP addresses, or
  CIDR blocks (IPv4/IPv6); the session resolver normalizes these forms using forward and reverse DNS so equivalent addresses match
  automatically. Attempts to connect elsewhere raise a `TransportError` unless `allow_external` is explicitly set or
  `PYCIPSIM_ALLOW_EXTERNAL=1` is exported (SRS §5.2).
- **Credential Management:** Instead of embedding usernames and passwords in scenario files, reference environment variables via
  `SessionConfig.username_env_var` / `password_env_var` or the CLI flags noted above so sensitive data never appears in plaintext
  configs (SRS §5.3).
- **Auditable History:** Each `CIPSession` records timestamped request/response pairs accessible through `session.history()` so
  operators can review what occurred during a run in alignment with the traceability goals in §3.2 and §3.4.

## Testing & Quality

Automated testing covers scenario execution with simulated devices and safety guardrails. Run the suite with:

```bash
pytest
```

To mirror the CLI's batch behaviour inside Python code, call `pycipsim.run_scenarios_parallel(...)` with a mapping of scenario
names to `SimulationScenario` instances. This helper manages session lifecycles and aggregates exceptions, making it easy to
smoke-test multiple device behaviours while feature development is underway.

Future milestones will layer in additional checks to match the SRS quality targets:

- Static analysis (`mypy`, `ruff`) and formatting hooks via `pre-commit`.
- Integration tests targeting containerised PLC simulators once transport adapters are extended.
- Expanded reporting for benchmark runs (percentiles, histograms) so long-term throughput trends remain visible alongside the pass/fail gate enforced by `pycipsim benchmark`.

## Roadmap Highlights

Short-term work should focus on:

1. **Transport Extensibility** — introduce additional adapters (e.g., asynchronous, UDP) while maintaining compatibility with
   the `Transport` protocol in `session.py`.
2. **Scenario DSL Enhancements** — expand beyond JSON arrays to support branching, timing constraints, and assertions mapped to
   explicit SRS requirement IDs.
3. **Reporting Improvements** — emit structured metrics (counts, latency histograms) to satisfy monitoring goals in SRS §3.4.
4. **Documentation & Traceability** — link code artifacts back to SRS sections and maintain an ADR log under `docs/`.

Refer back to [`SRS.md`](./SRS.md) after each milestone review to ensure the README and implementation remain aligned.
