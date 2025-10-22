# PyCIPSim

> **Authoritative requirements live in [`SRS.md`](./SRS.md).** This README explains how the current codebase implements those
> directives, how to get started locally, and what work remains.

## Overview

PyCIPSim is a Python toolkit for simulating Common Industrial Protocol (CIP) traffic so that PLC integrations can be exercised
without dedicated hardware. The implementation mirrors the major capabilities defined in the SRS:

- **Session Management (`pycipsim.session`)** — wraps the lifecycle of CIP connections, provides retry semantics, and exposes
  a unified interface for both simulated devices and live PLCs (via `pycomm3`).
- **Device Profiles (`pycipsim.device`)** — captures reusable PLC behaviours, fault injections, and request/response data
  structures.
- **Scenario Execution (`pycipsim.engine`)** — orchestrates scripted message exchanges, validates expectations, and generates
  machine-readable reports.
- **Automation Surface (`pycipsim.cli`)** — Click-powered CLI that runs scenarios, lists bundled profiles, and scaffolds new
  scenario definitions while emitting rich console output.

All modules log through `pycipsim.logging_config` to honour the observability requirements in the SRS.

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
pip install pycomm3
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

When `pycomm3` is available you can point the same command at live hardware with `--ip`, `--port`, and `--slot` overrides. The
CLI emits structured JSON reports suitable for CI consumption as required in SRS §3.5.

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

### Device Profiles

`pycipsim.device` includes two sample profiles to speed up local testing:

- **EchoDevice** — returns the request payload unchanged (`ECHO` service), supporting connectivity checks.
- **CounterDevice** — increments a per-tag counter (`READ` service), useful for exercising stateful scenarios.

Fault injection helpers such as `drop_request_fault` and `delay_response_fault` can be composed into custom profiles to satisfy
robustness testing requirements in SRS §3.3.

## Testing & Quality

Automated testing currently covers scenario execution with simulated devices. Run the suite with:

```bash
pytest
```

Future milestones will layer in additional checks to match the SRS quality targets:

- Static analysis (`mypy`, `ruff`) and formatting hooks via `pre-commit`.
- Integration tests targeting containerised PLC simulators once transport adapters are extended.
- Performance harnesses to validate the ≥100 message-per-second throughput in SRS §5.1.

## Roadmap Highlights

Short-term work should focus on:

1. **Transport Extensibility** — introduce additional adapters (e.g., asynchronous, UDP) while maintaining compatibility with
   the `Transport` protocol in `session.py`.
2. **Scenario DSL Enhancements** — expand beyond JSON arrays to support branching, timing constraints, and assertions mapped to
   explicit SRS requirement IDs.
3. **Reporting Improvements** — emit structured metrics (counts, latency histograms) to satisfy monitoring goals in SRS §3.4.
4. **Documentation & Traceability** — link code artifacts back to SRS sections and maintain an ADR log under `docs/`.

Refer back to [`SRS.md`](./SRS.md) after each milestone review to ensure the README and implementation remain aligned.
