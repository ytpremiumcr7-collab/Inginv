from __future__ import annotations

import socket

import pytest


@pytest.fixture(autouse=True)
def block_network_during_tests(monkeypatch: pytest.MonkeyPatch):
    """Fail closed on DNS and socket connections during the Inginv test suite."""

    def blocked(*args, **kwargs):
        raise AssertionError("network access is disabled during Inginv tests")

    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(socket.socket, "sendto", blocked)
    if hasattr(socket.socket, "sendmsg"):
        monkeypatch.setattr(socket.socket, "sendmsg", blocked)
