# HMI smoke test log

This repository includes a helper script for setting up a local environment, running the test suite, and launching the web-based HMI. The steps below capture a full smoke test run performed in this workspace.

## Setup and test execution

- Ran `bash scripts/setup_wsl.sh` from the repo root on Linux.  
  - Created `.venv`, installed editable `.[dev]` extras, and executed the bundled CLI smoke checks.  
  - Completed `pytest` with 80 passing tests and one skipped integration test due to the optional `pycomm3` dependency not being installed.

## Starting the HMI

After setup completes, start the FastAPI HMI with:

```bash
source .venv/bin/activate
pycipsim web --host 0.0.0.0 --port 8000
```

The server logs indicate the application is listening at `http://0.0.0.0:8000`. Navigate to `http://127.0.0.1:8000` in a browser to interact with the dashboard.

## Screenshot

A fresh screenshot of the HMI landing page was captured during this run using the browser automation tooling (see `artifacts/hmi.png` in the automation output).
