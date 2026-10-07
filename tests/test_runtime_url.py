import builtins
import socket
import subprocess

from ordin._runtime_url import has_unsafe_authority_characters


def test_raw_authority_check_covers_every_ascii_control_space_and_del():
    for number in range(128):
        expected = number <= 32 or number == 127
        assert has_unsafe_authority_characters("https://api.example.com/" + chr(number)) is expected
    assert not has_unsafe_authority_characters("https://api.example.com/a%20b")


def test_raw_authority_check_performs_no_io_or_normalization(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("authority validation performed I/O")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    raw = " https://api.example.com/a"
    assert has_unsafe_authority_characters(raw)
    assert raw.startswith(" ")
