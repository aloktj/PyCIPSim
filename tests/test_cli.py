import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from click.testing import CliRunner

from pycipsim.cli import cli


def test_scaffold_creates_nested_directories(tmp_path):
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


def test_benchmark_meets_target(tmp_path):
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


def test_serve_command_with_assembly_file(tmp_path):
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
