"""CLI integration tests for the rich inspector."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from pycipsim.cli import cli


def _sample_configuration() -> dict:
    return {
        "name": "Inspectable",
        "target": {
            "ip": "192.168.1.5",
            "port": 44818,
            "interface": "eth0",
            "mode": "live",
            "allowed_hosts": ["127.0.0.1", "192.168.1.5"],
        },
        "metadata": {"purpose": "demo", "labels": ["alpha", "beta"]},
        "assemblies": [
            {
                "id": 101,
                "name": "Outputs",
                "direction": "output",
                "size_bits": 8,
                "signals": [
                    {"name": "SigA", "offset": 0, "type": "BOOL", "value": "1"},
                    {
                        "name": "Padding_0",
                        "offset": 1,
                        "type": "PADDING",
                        "padding": True,
                    },
                ],
            },
            {
                "id": 201,
                "name": "Inputs",
                "direction": "input",
                "size_bits": 16,
                "production_interval_ms": 100,
                "signals": [
                    {"name": "SigB", "offset": 0, "type": "INT", "value": "12"},
                ],
            },
        ],
    }


def test_inspect_renders_configuration(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(_sample_configuration()), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["inspect", "--config-file", str(config_path)])

    assert result.exit_code == 0
    output = result.output
    assert "Inspectable" in output
    assert "192.168.1.5:44818" in output
    assert "Allowed hosts" in output
    assert "Outputs" in output and "Inputs" in output
    assert "SigA" in output and "SigB" in output
    assert "padding" in output.lower()


def test_scaffold_creates_nested_directories(tmp_path: Path) -> None:
    output_path = tmp_path / "nested" / "echo.json"
    runner = CliRunner()

    result = runner.invoke(cli, ["scaffold", str(output_path)])

    assert result.exit_code == 0
    assert output_path.exists()

    payload = json.loads(output_path.read_text())
    assert isinstance(payload, list)
    assert payload
    first_step = payload[0]
    assert first_step["request"]["service_code"] == "ECHO"


def test_benchmark_meets_target(tmp_path: Path) -> None:
    runner = CliRunner()

    result = runner.invoke(
        cli,
        [
            "benchmark",
            "--messages",
            "10",
            "--warmup",
            "0",
            "--target-throughput",
            "5",
        ],
    )

    assert result.exit_code == 0
    assert "Benchmark Summary" in result.output


def test_serve_command_with_assembly_file(tmp_path: Path) -> None:
    assemblies = [
        {
            "id": 100,
            "name": "Outputs",
            "direction": "output",
            "size_bits": 16,
            "production_interval_ms": 50,
            "signals": [
                {"name": "Value", "offset": 0, "type": "UINT", "value": "123"},
            ],
        }
    ]
    assembly_file = tmp_path / "assemblies.json"
    assembly_file.write_text(json.dumps(assemblies), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "serve",
            "--assembly-file",
            str(assembly_file),
            "--name",
            "TargetServe",
            "--duration",
            "0",
        ],
    )

    assert result.exit_code == 0
    assert "Target simulator listening on" in result.output
    assert "Target server stopped." in result.output
