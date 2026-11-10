"""Bounded HTTP access with explicit redirect validation and no credential forwarding."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

from .security import UnsafeTarget, validate_public_url

USER_AGENT = "WordPressMaintenanceAgent/0.1 (+https://github.com/Yousef-Abdallah-1711/wordpress-maintenance-agent)"


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
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(timeout), verify=True,
                                         follow_redirects=False, headers={"User-Agent": USER_AGENT,
                                         "Accept": "text/html,application/xml,application/json,*/*;q=0.5"})

    async def __aenter__(self) -> "SafeHttp":
        return self

    async def __aexit__(self, *args: object) -> None:
        await self._client.aclose()

    async def get(self, url: str, *, headers: dict[str, str] | None = None,
                  auth: httpx.Auth | tuple[str, str] | None = None,
                  max_bytes: int | None = None) -> FetchResult:
        start = time.monotonic()
        try:
            current = validate_public_url(url, allowed_hosts=self.allowed_hosts)
            initial = urlsplit(current)
            original_origin = (initial.scheme, initial.hostname, initial.port or (443 if initial.scheme == "https" else 80))
            chain: list[str] = []
            for redirect_count in range(self.max_redirects + 1):
                current_parts = urlsplit(current)
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
                retry_response = False
                retry_count = 0
                for attempt in range(self.retries + 1):
                    retry_count = max(retry_count, attempt)
                    try:
                        async with self._client.stream("GET", current, headers=req_headers, auth=req_auth,
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
                                    retry_response = True
                                    continue
                            body.clear()
                            if response.status_code not in {301, 302, 303, 307, 308}:
                                async for chunk in response.aiter_bytes():
                                    body.extend(chunk)
                                    if len(body) > (max_bytes or self.max_bytes):
                                        return FetchResult(url, current, response.status_code, response_headers,
                                                           redirect_chain=chain, elapsed_ms=(time.monotonic()-start)*1000,
                                                           error="response exceeded configured size limit")
                        if retry_response:
                            retry_response = False
                            continue
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
