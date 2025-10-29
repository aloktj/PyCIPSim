"""Tests for allowed host normalization and validation."""

import pytest

from pycipsim.session import CIPSession, SessionConfig, TransportError


def make_session(ip_address: str, allowed_hosts: tuple[str, ...]) -> CIPSession:
    config = SessionConfig(ip_address=ip_address, allowed_hosts=allowed_hosts)
    return CIPSession(config=config)


def test_allowed_hostname_matches_resolved_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PYCIPSIM_ALLOWED_HOSTS", raising=False)
    session = make_session("127.0.0.1", ("LOCALHOST",))
    session._validate_target()


def test_allowed_ip_matches_hostname_target(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PYCIPSIM_ALLOWED_HOSTS", raising=False)
    session = make_session("localhost", ("127.0.0.1",))
    session._validate_target()


def test_cidr_range_allows_member_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PYCIPSIM_ALLOWED_HOSTS", raising=False)
    session = make_session("127.0.0.1", ("127.0.0.0/8",))
    session._validate_target()


def test_rejects_ip_outside_allowed_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PYCIPSIM_ALLOWED_HOSTS", raising=False)
    session = make_session("10.0.0.5", ("127.0.0.0/8",))
    with pytest.raises(TransportError):
        session._validate_target()
