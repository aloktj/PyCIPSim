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
