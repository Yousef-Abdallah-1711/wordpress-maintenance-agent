"""Bounded HTTP access with explicit redirect validation and no credential forwarding."""

from __future__ import annotations

import asyncio
import ipaddress
import posixpath
import socket
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import unquote, urljoin, urlsplit

import httpx
import httpcore

from .security import UnsafeTarget, validate_public_url

USER_AGENT = "WordPressMaintenanceAgent/0.1 (+https://github.com/Yousef-Abdallah-1711/wordpress-maintenance-agent)"


def _canonical_path(path: str) -> str:
    value = path or "/"
    for _ in range(4):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    value = value.replace("\\", "/").casefold()
    normalized = posixpath.normpath("/" + value.lstrip("/"))
    if value.endswith("/") and normalized != "/":
        normalized += "/"
    return normalized


def _path_is_blocked(path: str, blocked_paths: tuple[str, ...]) -> bool:
    canonical = _canonical_path(path)
    for blocked in blocked_paths:
        prefix = _canonical_path(blocked).rstrip("/") or "/"
        if canonical == prefix or prefix == "/" or canonical.startswith(prefix + "/"):
            return True
    return False


class PublicOnlyNetworkBackend:
    """Resolve once per socket connection and connect to that validated address."""

    def __init__(self, delegate: object | None = None):
        self._delegate = delegate or httpcore.AnyIOBackend()

    async def connect_tcp(self, host: str, port: int, timeout: float | None = None,
                          local_address: str | None = None, socket_options: object = None) -> object:
        loop = asyncio.get_running_loop()
        try:
            records = await asyncio.wait_for(loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), timeout=timeout)
        except asyncio.TimeoutError as exc:
            raise httpcore.ConnectTimeout("DNS resolution timed out") from exc
        addresses = list(dict.fromkeys(record[4][0].split("%", 1)[0] for record in records))
        if not addresses:
            raise httpcore.ConnectError("host resolved to no addresses")
        for address in addresses:
            try:
                if not ipaddress.ip_address(address).is_global:
                    raise httpcore.ConnectError("host resolved to a non-public address")
            except ValueError as exc:
                raise httpcore.ConnectError("host resolved to an invalid address") from exc
        # HTTP Core retains the original hostname for Host and TLS SNI while the
        # network stream is opened to one exact, already-validated IP address.
        deadline = time.monotonic() + timeout if timeout is not None else None
        last_error: Exception | None = None
        for address in addresses:
            remaining = max(0.0, deadline - time.monotonic()) if deadline is not None else None
            if remaining == 0:
                break
            try:
                return await self._delegate.connect_tcp(address, port, timeout=remaining,
                    local_address=local_address, socket_options=socket_options)
            except (httpcore.ConnectError, httpcore.ConnectTimeout, OSError) as exc:
                last_error = exc
        if last_error:
            raise httpcore.ConnectError(f"all validated public addresses failed: {last_error}") from last_error
        raise httpcore.ConnectError("connection timeout expired before trying a validated address")

    async def connect_unix_socket(self, path: str, timeout: float | None = None,
                                  socket_options: object = None) -> object:
        return await self._delegate.connect_unix_socket(path, timeout=timeout, socket_options=socket_options)

    async def sleep(self, seconds: float) -> None:
        await self._delegate.sleep(seconds)


class PinnedHTTPTransport(httpx.AsyncHTTPTransport):
    """HTTPX transport whose TCP connections use validated, pinned DNS results."""

    def __init__(self):
        super().__init__(verify=True, trust_env=False)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl.create_default_context(), network_backend=PublicOnlyNetworkBackend(),
            max_connections=20, max_keepalive_connections=10, keepalive_expiry=5.0,
            retries=0, http1=True, http2=False,
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        # Audits do not need browser sessions; never send response-set cookies.
        request.headers.pop("cookie", None)
        return await super().handle_async_request(request)


@dataclass
class FetchResult:
    requested_url: str
    final_url: str
    status_code: int | None
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    redirect_chain: list[str] = field(default_factory=list)
    elapsed_ms: float = 0
    error: str | None = None
    retries: int = 0


class SafeHttp:
    def __init__(self, *, timeout: float = 15, max_bytes: int = 2_000_000, max_redirects: int = 8,
                 retries: int = 2, allowed_hosts: set[str] | None = None, delay: float = 0.25):
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.max_redirects = max_redirects
        self.retries = retries
        self.allowed_hosts = allowed_hosts
        self.delay = delay
        self._last_request: dict[str, float] = {}
        self._host_locks: dict[str, asyncio.Lock] = {}
        self._clients: dict[tuple[str, str | None, int | None], httpx.AsyncClient] = {}

    def _client_for(self, origin: tuple[str, str | None, int | None]) -> httpx.AsyncClient:
        # Separate cookie jars by origin so a parent-domain Set-Cookie cannot cross a host boundary.
        client = self._clients.get(origin)
        if client is None:
            client = httpx.AsyncClient(transport=PinnedHTTPTransport(), timeout=httpx.Timeout(self.timeout),
                verify=True, follow_redirects=False, trust_env=False, headers={"User-Agent": USER_AGENT,
                "Accept": "text/html,application/xml,application/json,*/*;q=0.5"})
            self._clients[origin] = client
        return client

    async def __aenter__(self) -> "SafeHttp":
        return self

    async def __aexit__(self, *args: object) -> None:
        for client in self._clients.values():
            await client.aclose()

    async def get(self, url: str, *, headers: dict[str, str] | None = None,
                  auth: httpx.Auth | tuple[str, str] | None = None,
                  max_bytes: int | None = None, blocked_paths: tuple[str, ...] = ()) -> FetchResult:
        start = time.monotonic()
        try:
            current = validate_public_url(url, allowed_hosts=self.allowed_hosts)
            initial = urlsplit(current)
            if auth is not None and initial.scheme != "https":
                raise UnsafeTarget("authenticated requests require HTTPS")
            original_origin = (initial.scheme, initial.hostname, initial.port or (443 if initial.scheme == "https" else 80))
            chain: list[str] = []
            for redirect_count in range(self.max_redirects + 1):
                current_parts = urlsplit(current)
                if _path_is_blocked(httpx.URL(current).path, blocked_paths):
                    raise UnsafeTarget("request path is excluded by site policy")
                host = current_parts.hostname or ""
                current_origin = (current_parts.scheme, current_parts.hostname,
                                  current_parts.port or (443 if current_parts.scheme == "https" else 80))
                host_lock = self._host_locks.setdefault(host, asyncio.Lock())
                async with host_lock:
                    elapsed = time.monotonic() - self._last_request.get(host, 0)
                    if elapsed < self.delay:
                        await asyncio.sleep(self.delay - elapsed)
                    self._last_request[host] = time.monotonic()
                req_headers = dict(headers or {})
                req_auth = auth if current_origin == original_origin else None
                if current_origin != original_origin:
                    req_headers = {name: value for name, value in req_headers.items()
                                   if name.lower() not in {"authorization", "proxy-authorization", "cookie"}}
                if initial.scheme == "https" and current_parts.scheme != "https":
                    raise UnsafeTarget("HTTPS downgrade redirects are not allowed")
                status_code: int | None = None
                response_headers: dict[str, str] = {}
                body = bytearray()
                retry_count = 0
                for attempt in range(self.retries + 1):
                    retry_count = max(retry_count, attempt)
                    try:
                        async with self._client_for(current_origin).stream("GET", current, headers=req_headers, auth=req_auth,
                                                       follow_redirects=False) as response:
                            status_code = response.status_code
                            response_headers = dict(response.headers)
                            if response.status_code == 429 or response.status_code >= 500:
                                if attempt < self.retries:
                                    retry_after = response.headers.get("retry-after", "")
                                    try:
                                        backoff = min(max(float(retry_after), 0), 10)
                                    except ValueError:
                                        backoff = min(0.25 * (2 ** attempt), 3)
                                    await asyncio.sleep(backoff)
                                    continue
                            body.clear()
                            if response.status_code not in {301, 302, 303, 307, 308}:
                                async for chunk in response.aiter_bytes():
                                    body.extend(chunk)
                                    if len(body) > (max_bytes or self.max_bytes):
                                        return FetchResult(url, current, response.status_code, response_headers,
                                                           redirect_chain=chain, elapsed_ms=(time.monotonic()-start)*1000,
                                                           error="response exceeded configured size limit")
                        break
                    except (httpx.TimeoutException, httpx.NetworkError) as exc:
                        if attempt >= self.retries:
                            raise exc
                        await asyncio.sleep(min(0.25 * (2 ** attempt), 3))
                assert status_code is not None
                if status_code in {301, 302, 303, 307, 308}:
                    location = response_headers.get("location")
                    if not location:
                        return FetchResult(url, current, status_code, response_headers,
                                           redirect_chain=chain, elapsed_ms=(time.monotonic()-start)*1000,
                                           error="redirect missing Location header")
                    if redirect_count >= self.max_redirects:
                        return FetchResult(url, current, status_code, response_headers,
                                           redirect_chain=chain, elapsed_ms=(time.monotonic()-start)*1000,
                                           error="maximum redirects exceeded")
                    if current in chain:
                        return FetchResult(url, current, status_code, response_headers,
                                           redirect_chain=chain, elapsed_ms=(time.monotonic()-start)*1000,
                                           error="redirect loop detected")
                    chain.append(current)
                    target = validate_public_url(urljoin(current, location), allowed_hosts=self.allowed_hosts)
                    if urlsplit(current).scheme == "https" and urlsplit(target).scheme != "https":
                        raise UnsafeTarget("HTTPS downgrade redirects are not allowed")
                    current = target
                    continue
                return FetchResult(url, current, status_code, response_headers, bytes(body),
                                   chain, (time.monotonic()-start)*1000, retries=retry_count)
        except (UnsafeTarget, httpx.HTTPError, OSError) as exc:
            return FetchResult(url, url, None, elapsed_ms=(time.monotonic()-start)*1000,
                               error=f"{type(exc).__name__}: {exc}")
        return FetchResult(url, current, None, redirect_chain=chain,
                           elapsed_ms=(time.monotonic()-start)*1000, error="unexpected redirect state")
