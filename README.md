# PyCIPSim Roadmap

> **Authoritative requirements live in [`SRS.md`](./SRS.md).** This README distills the near-term delivery plan for getting from the approved specification to a working prototype.

## Architecture Direction

The initial implementation will focus on a modular Python package that mirrors the major capability areas in the SRS:

1. **Core Simulation Engine**
   - Manage CIP session lifecycles (connect, sustain, tear down) and delegate protocol details to `pycomm3`.
   - Provide synchronous helpers first, leaving room to introduce `asyncio`-powered flows in a later milestone.
   - Persist request/response transcripts to structured log objects for later analysis.
2. **Device Profile Library**
   - Represent reusable PLC behavior models as Python classes with overridable hooks for fault injection.
   - Support YAML/JSON-backed configuration so complex scenarios can be expressed without modifying code.
3. **Scenario Orchestrator**
   - Allow users to compose sequences of message exchanges, including branching on CIP status codes.
   - Produce machine-readable execution reports (JSON/CSV) aligned with CI tooling expectations.
4. **CLI and Automation Surface**
   - Ship an ergonomic command group (e.g., `pycipsim run`, `pycipsim devices`, `pycipsim report`).
   - Integrate with Python logging for configurable verbosity and export debug information suitable for pipelines.

Future architecture refinements (e.g., asynchronous drivers, GUI authoring tools) should be scheduled only after the baseline above is validated against the SRS.

## Environment & Setup

1. **Prerequisites**
   - Python 3.10 or newer (per SRS operating environment constraints).
   - `pip` and `virtualenv` (or Poetry) for isolated dependency management.
   - Network access to any target PLC endpoints used in integration testing.
2. **Project Bootstrap**
   ```bash
   git clone <repo-url>
   cd PyCIPSim
   python -m venv .venv
   source .venv/bin/activate  # On Windows use: .venv\Scripts\activate
   pip install --upgrade pip
   pip install -r requirements.txt  # placeholder until the dependency list is finalized
   ```
3. **Configuration**
   - Place scenario definitions under `scenarios/` using the JSON/YAML schema documented in the SRS feature sections.
   - Use environment variables for sensitive connection details (e.g., `PYCIPSIM_TARGET_IP`).
   - Default logging writes to `logs/`; override via CLI flags once available.

## Testing Strategy

Automated confidence will be built iteratively:

1. **Unit Tests**
   - Cover session lifecycle helpers, device profile behaviors, and scenario orchestration utilities with `pytest`.
   - Employ fixtures that stub `pycomm3` clients to avoid requiring live PLC hardware during CI.
2. **Integration Tests**
   - Spin up loopback or containerized CIP endpoints to validate end-to-end message flows.
   - Ensure transcripts and generated reports conform to the formats promised in the SRS.
3. **Performance & Reliability Checks**
   - Stress-test scenario batches to confirm the 100 messages/second throughput expectation from the SRS.
   - Run extended soak tests (≥24 hours) before tagging releases to validate stability objectives.
4. **Continuous Integration**
   - Configure workflows to lint (e.g., `ruff`/`black`), type-check (`mypy`), and execute the test suites on every push.
   - Publish coverage and report artifacts so stakeholders can trace verification back to the requirements in `SRS.md`.

## Next Steps

- Finalize dependency manifests and scaffolding scripts.
- Scaffold the package structure (`pycipsim/`) with placeholders for engine, profiles, and CLI modules.
- Establish CI pipelines mirroring the testing strategy above.
- Iteratively implement and validate features, updating this roadmap when the SRS evolves.

For any clarifications or requirement changes, always defer to [`SRS.md`](./SRS.md) as the single source of truth.
