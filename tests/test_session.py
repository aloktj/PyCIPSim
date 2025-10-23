from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pycipsim.device import ServiceRequest
from pycipsim.session import PyComm3Transport, SessionConfig


class _StubTag:
    def __init__(self, *, value=None, error=None):
        self.value = value
        self.error = error


def test_pycomm3_transport_retries_with_connected(monkeypatch):
    responses = [
        _StubTag(error="Too much data"),
        _StubTag(value=b"\x01\x02"),
    ]
    calls = []

    class _StubDriver:
        def __init__(self, address):
            self._cfg = {"cip_path": []}

        def generic_message(self, **kwargs):
            calls.append((kwargs.get("connected"), kwargs.get("unconnected_send")))
            return responses.pop(0)

        def open(self):  # pragma: no cover - not used in this test
            return True

        def close(self):  # pragma: no cover - not used in this test
            return None

    class _StubSocket:
        def __init__(self, timeout):
            self.sock = self

        def bind(self, addr):  # pragma: no cover - not used
            pass

        def connect(self, host, port):
            return None

    stub_module = type(
        "_StubPycomm3",
        (),
        {"CIPDriver": _StubDriver, "socket_": type("_S", (), {"Socket": _StubSocket})},
    )()

    import sys

    monkeypatch.setitem(sys.modules, "pycomm3", stub_module)

    transport = PyComm3Transport(SessionConfig(ip_address="1.2.3.4"))
    request = ServiceRequest(
        service_code="GET_ASSEMBLY",
        tag_path="assembly/100",
        metadata={"instance": "100"},
    )

    response = transport.send(request)

    assert response.status == "SUCCESS"
    assert response.payload == b"\x01\x02"
    assert calls == [(False, True), (True, False)]
