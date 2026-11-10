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
