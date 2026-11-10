"""Strict URL validation for all remotely supplied destinations."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit


class UnsafeTarget(ValueError):
    """Raised when a URL is unsafe for network access."""


def _public_address(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    return ip.is_global


def validate_public_url(
    url: str,
    *,
    allowed_hosts: set[str] | None = None,
    resolve_dns: bool = True,
    allow_http: bool = True,
) -> str:
    """Normalize a URL and reject unsafe schemes, hosts, IPs, and unapproved origins."""
    parsed = urlsplit(url)
    if parsed.scheme not in ({"https", "http"} if allow_http else {"https"}):
        raise UnsafeTarget("only HTTP and HTTPS URLs are allowed")
    if not parsed.hostname or parsed.username or parsed.password:
        raise UnsafeTarget("URL must have a hostname and must not contain credentials")
    try:
        port = parsed.port
    except ValueError as exc:
        raise UnsafeTarget("invalid URL port") from exc
    if port is not None and not (1 <= port <= 65535):
        raise UnsafeTarget("invalid URL port")
    expected_port = 443 if parsed.scheme == "https" else 80
    if port is not None and port != expected_port:
        raise UnsafeTarget("only standard HTTP/HTTPS ports are allowed")
    host = parsed.hostname.rstrip(".").lower()
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".localhost") or host.endswith(".local"):
        raise UnsafeTarget("local hostnames are not allowed")
    try:
        _public_address(host)
        addresses = [host]
    except ValueError:
        if resolve_dns:
            try:
                addresses = sorted({entry[4][0] for entry in socket.getaddrinfo(host, port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)})
            except OSError as exc:
                raise UnsafeTarget("DNS resolution failed") from exc
        else:
            addresses = []
    for address in addresses:
        if not _public_address(address):
            raise UnsafeTarget("destination resolves to a non-public IP address")
    if allowed_hosts is not None and host not in {item.rstrip(".").lower() for item in allowed_hosts}:
        raise UnsafeTarget("destination host is outside the approved host list")
    netloc = host
    if port is not None:
        netloc = f"{host}:{port}"
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))


def redact_secrets(value: str) -> str:
    """Redact common bearer tokens, application passwords and URL credentials."""
    import re

    value = re.sub(r"(?i)(authorization\s*[:=]\s*(?:bearer|basic)\s+)[^\s,;]+", r"\1[REDACTED]", value)
    value = re.sub(r"(?i)(password|token|secret|api[_-]?key)(\s*[:=]\s*)[^\s,;]+", r"\1\2[REDACTED]", value)
    value = re.sub(r"(https?://)[^/@\s]+@", r"\1[REDACTED]@", value)
    return value
