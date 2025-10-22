from pycipsim.device import DeviceProfile, ServiceRequest
from pycipsim.engine import run_benchmark
from pycipsim.session import CIPSession, SessionConfig


def test_run_benchmark_collects_metrics():
    session = CIPSession(SessionConfig(), profile=DeviceProfile.echo_profile())
    request = ServiceRequest(service_code="ECHO", tag_path="BenchTag", payload=b"data")

    with session.lifecycle():
        result = run_benchmark(session, request, message_count=5, warmup=1)

    assert result.total_messages == 5
    assert result.success_count == 5
    assert result.failure_count == 0
    assert result.throughput_per_second > 0
    assert result.duration_seconds > 0
