import asyncio
import socket

import httpx
import pytest
import respx

from wp_maintenance.crawler import check_pages
from wp_maintenance.http import SafeHttp


@pytest.fixture(autouse=True)
def public_dns(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))])


@pytest.mark.asyncio
@respx.mock
async def test_page_status_and_redirect_classification():
    respx.get("https://example.com/").mock(return_value=httpx.Response(200, text="ok"))
    respx.get("https://example.com/moved").mock(return_value=httpx.Response(301, headers={"location": "/new"}))
    respx.get("https://example.com/new").mock(return_value=httpx.Response(200, text="new"))
    respx.get("https://example.com/missing").mock(return_value=httpx.Response(404))
    respx.get("https://example.com/error").mock(return_value=httpx.Response(503))
    async with SafeHttp(delay=0, retries=0, allowed_hosts={"example.com"}) as client:
        results = await check_pages(["https://example.com/", "https://example.com/moved", "https://example.com/missing", "https://example.com/error"], client)
    assert [item["classification"] for item in results] == ["available", "redirect", "missing", "server_error"]
    assert results[1]["final_url"] == "https://example.com/new"


@pytest.mark.asyncio
@respx.mock
async def test_redirect_to_private_address_is_blocked():
    respx.get("https://example.com/").mock(return_value=httpx.Response(302, headers={"location": "http://127.0.0.1/admin"}))
    async with SafeHttp(delay=0, retries=0, allowed_hosts={"example.com"}) as client:
        result = await client.get("https://example.com/")
    assert result.status_code is None
    assert "non-public" in (result.error or "")


@pytest.mark.asyncio
@respx.mock
async def test_authorization_is_not_forwarded_across_origins():
    first = respx.get("https://example.com/").mock(return_value=httpx.Response(302, headers={"location": "https://cdn.example.org/asset"}))
    second = respx.get("https://cdn.example.org/asset").mock(return_value=httpx.Response(200, text="ok"))
    async with SafeHttp(delay=0, retries=0, allowed_hosts={"example.com", "cdn.example.org"}) as client:
        result = await client.get("https://example.com/", headers={"Authorization": "Bearer secret"}, auth=("user", "app-password"))
    assert result.status_code == 200
    assert first.calls[0].request.headers.get("authorization") is not None
    assert second.calls[0].request.headers.get("authorization") is None


@pytest.mark.asyncio
@respx.mock
async def test_cookies_are_not_shared_across_origins(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))])
    first = respx.get("https://example.com/").mock(return_value=httpx.Response(
        302, headers={"Location": "https://cdn.example.com/file", "Set-Cookie": "session=secret; Domain=.example.com"}))
    second = respx.get("https://cdn.example.com/file").mock(return_value=httpx.Response(200))
    async with SafeHttp(delay=0, retries=0, allowed_hosts={"example.com", "cdn.example.com"}) as client:
        await client.get("https://example.com/")
    assert first.call_count == 1
    assert second.calls[0].request.headers.get("cookie") is None


@pytest.mark.asyncio
@respx.mock
async def test_authenticated_http_endpoint_is_rejected(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))])
    route = respx.get("http://example.com/private").mock(return_value=httpx.Response(200))
    async with SafeHttp(delay=0, retries=0) as client:
        result = await client.get("http://example.com/private", auth=("user", "password"))
    assert result.status_code is None
    assert "HTTPS" in (result.error or "")
    assert route.call_count == 0


@pytest.mark.asyncio
@respx.mock
async def test_excluded_path_is_enforced_after_dot_segment_normalization(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))])
    route = respx.get("https://example.com/private").mock(return_value=httpx.Response(200))
    async with SafeHttp(delay=0, retries=0) as client:
        result = await client.get("https://example.com/public/../private", blocked_paths=("/private",))
    assert result.status_code is None
    assert "excluded" in (result.error or "")
    assert route.call_count == 0


@pytest.mark.asyncio
@respx.mock
async def test_excluded_path_is_enforced_after_percent_encoded_dot_normalization(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))])
    route = respx.get("https://example.com/%2e%2e/private").mock(return_value=httpx.Response(200))
    route2 = respx.get("https://example.com/private").mock(return_value=httpx.Response(200))
    async with SafeHttp(delay=0, retries=0) as client:
        result = await client.get("https://example.com/%2e%2e/private", blocked_paths=("/private",))
    assert result.status_code is None
    assert "excluded" in (result.error or "")
    assert route.call_count == 0
    assert route2.call_count == 0


@pytest.mark.asyncio
@respx.mock
async def test_redirect_cannot_enter_an_excluded_path(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))])
    start = respx.get("https://example.com/public").mock(return_value=httpx.Response(302, headers={"Location": "/private"}))
    excluded = respx.get("https://example.com/private").mock(return_value=httpx.Response(200))
    async with SafeHttp(delay=0, retries=0) as client:
        result = await client.get("https://example.com/public", blocked_paths=("/private",))
    assert result.status_code is None
    assert "excluded" in (result.error or "")
    assert start.call_count == 1
    assert excluded.call_count == 0


@pytest.mark.asyncio
@respx.mock
async def test_retry_after_response_does_not_discard_success(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))])
    route = respx.get("https://example.com/").mock(side_effect=[
        httpx.Response(429), httpx.Response(200, text="ok"), httpx.Response(500)])
    async with SafeHttp(delay=0, retries=2) as client:
        result = await client.get("https://example.com/")
    assert result.status_code == 200
    assert result.body == b"ok"
    assert route.call_count == 2


@pytest.mark.asyncio
async def test_connection_uses_the_validated_public_dns_address(monkeypatch):
    from wp_maintenance.http import PublicOnlyNetworkBackend

    class Delegate:
        called = None
        async def connect_tcp(self, host, port, **kwargs):
            self.called = (host, port)
            return object()

    async def getaddrinfo(host, port, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "getaddrinfo", getaddrinfo)
    delegate = Delegate()
    await PublicOnlyNetworkBackend(delegate).connect_tcp("example.com", 443)
    assert delegate.called == ("93.184.216.34", 443)


@pytest.mark.asyncio
async def test_connection_falls_back_to_next_validated_public_address(monkeypatch):
    from wp_maintenance.http import PublicOnlyNetworkBackend

    class Delegate:
        def __init__(self):
            self.called = []
        async def connect_tcp(self, host, port, **kwargs):
            self.called.append(host)
            if host == "2606:4700:4700::1111":
                import httpcore
                raise httpcore.ConnectTimeout("unreachable IPv6")
            return object()

    async def getaddrinfo(host, port, **kwargs):
        return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700:4700::1111", port, 0, 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "getaddrinfo", getaddrinfo)
    delegate = Delegate()
    await PublicOnlyNetworkBackend(delegate).connect_tcp("dual-stack.example", 443, timeout=5)
    assert delegate.called == ["2606:4700:4700::1111", "93.184.216.34"]


@pytest.mark.asyncio
async def test_connection_refuses_private_dns_results(monkeypatch):
    import httpcore
    from wp_maintenance.http import PublicOnlyNetworkBackend

    class Delegate:
        async def connect_tcp(self, host, port, **kwargs):
            raise AssertionError("must not connect")

    async def getaddrinfo(host, port, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "getaddrinfo", getaddrinfo)
    with pytest.raises(httpcore.ConnectError, match="non-public"):
        await PublicOnlyNetworkBackend(Delegate()).connect_tcp("rebound.example", 443)


@pytest.mark.asyncio
@respx.mock
async def test_https_downgrade_redirect_is_blocked():
    respx.get("https://example.com/").mock(return_value=httpx.Response(302, headers={"location": "http://example.com/plain"}))
    async with SafeHttp(delay=0, retries=0, allowed_hosts={"example.com"}) as client:
        result = await client.get("https://example.com/")
    assert "downgrade" in (result.error or "")


@pytest.mark.asyncio
@respx.mock
async def test_response_size_is_bounded_while_streaming():
    respx.get("https://example.com/large").mock(return_value=httpx.Response(200, content=b"123456789"))
    async with SafeHttp(delay=0, retries=0, max_bytes=5, allowed_hosts={"example.com"}) as client:
        result = await client.get("https://example.com/large")
    assert "size limit" in (result.error or "")


@pytest.mark.asyncio
@respx.mock
async def test_429_retries_then_reports_success():
    route = respx.get("https://example.com/").mock(side_effect=[
        httpx.Response(429, headers={"retry-after": "0"}), httpx.Response(200, text="ok")
    ])
    async with SafeHttp(delay=0, retries=1, allowed_hosts={"example.com"}) as client:
        result = await client.get("https://example.com/")
    assert result.status_code == 200
    assert route.call_count == 2


@pytest.mark.asyncio
@respx.mock
async def test_redirect_loop_is_distinguished():
    respx.get("https://example.com/a").mock(return_value=httpx.Response(302, headers={"location": "/b"}))
    respx.get("https://example.com/b").mock(return_value=httpx.Response(302, headers={"location": "/a"}))
    async with SafeHttp(delay=0, retries=0, allowed_hosts={"example.com"}) as client:
        result = await client.get("https://example.com/a")
    assert "redirect loop" in (result.error or "")
