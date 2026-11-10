import socket

import pytest

from wp_maintenance.security import UnsafeTarget, redact_secrets, validate_public_url


def test_blocks_local_and_private_destinations():
    for url in ["http://127.0.0.1/", "http://10.0.0.4/", "http://169.254.169.254/latest/meta-data/", "http://localhost/"]:
        with pytest.raises(UnsafeTarget):
            validate_public_url(url, resolve_dns=False)


def test_blocks_private_dns_resolution(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.10", 443))])
    with pytest.raises(UnsafeTarget, match="non-public"):
        validate_public_url("https://attacker.example")


def test_approved_host_and_disallowed_host():
    assert validate_public_url("https://example.com/path", resolve_dns=False) == "https://example.com/path"
    with pytest.raises(UnsafeTarget, match="approved"):
        validate_public_url("https://other.example", allowed_hosts={"example.com"}, resolve_dns=False)


def test_invalid_port_and_scheme_are_rejected():
    for url in ["file:///etc/passwd", "https://example.com:0", "https://example.com:70000", "https://example.com:8443"]:
        with pytest.raises(UnsafeTarget):
            validate_public_url(url, resolve_dns=False)


def test_secret_redaction():
    text = "Authorization: Bearer abc123 password=secret https://user:pass@example.com"
    safe = redact_secrets(text)
    assert "abc123" not in safe and "secret" not in safe and "user:pass" not in safe
