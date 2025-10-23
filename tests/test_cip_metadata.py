import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pycipsim.cip import (
    describe_error,
    describe_service,
    format_path,
    resolve_service_code,
)


def test_resolve_service_code_accepts_names_and_hex():
    assert resolve_service_code("0x4c") == 0x4C
    assert resolve_service_code("Get_Attribute_Single") == 0x0E
    assert resolve_service_code(0x54) == 0x54


def test_describe_helpers_use_known_tables():
    assert describe_service(0x54) == "Forward_Open"
    assert describe_error(0x15) == "Too much data"


def test_format_path_decodes_segments():
    path_bytes = bytes([0x20, 0x04, 0x24, 0x01, 0x2C, 0x65, 0x2C, 0x64])
    description = format_path(path_bytes)
    assert "class 0x04 (Assembly)" in description
    assert "instance 0x01" in description
    assert "connection_point 0x65" in description
