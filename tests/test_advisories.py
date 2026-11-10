import json
import socket

import httpx
import pytest
import respx

from wp_maintenance.advisories import FEED_URL, check_wordfence_feed
from wp_maintenance.http import SafeHttp


@pytest.fixture(autouse=True)
def public_dns(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))])


@pytest.mark.asyncio
@respx.mock
async def test_exact_slug_and_version_range_match(monkeypatch):
    monkeypatch.setenv("TEST_WORDfence_KEY", "secret-token")
    feed = {"123": {"id": "uuid-123", "title": "Example XSS", "software": [{"type": "plugin", "slug": "sample-plugin",
        "affected_versions": {"1.0.0 - 1.2.0": {"from_version": "1.0.0", "from_inclusive": True, "to_version": "1.2.0", "to_inclusive": True}},
        "patched": True, "patched_versions": ["1.2.1"], "remediation": "Update to 1.2.1"}], "references": ["https://example.org/advisory"], "cve": "CVE-2026-1234"}}
    route = respx.get(FEED_URL).mock(return_value=httpx.Response(200, json=feed))
    async with SafeHttp(delay=0, retries=0, allowed_hosts={"www.wordfence.com"}) as client:
        matched = await check_wordfence_feed([{"slug": "sample-plugin", "installed_version": "1.1.0"}], client, api_key_env="TEST_WORDfence_KEY")
    assert route.calls[0].request.headers["authorization"] == "Bearer secret-token"
    assert len(matched) == 1
    assert matched[0]["id"] == "uuid-123"
    assert matched[0]["patched_versions"] == ["1.2.1"]


@pytest.mark.asyncio
@respx.mock
async def test_nonmatching_version_and_slug_do_not_report(monkeypatch):
    monkeypatch.setenv("TEST_WF_KEY", "key")
    feed = {"id": {"id": "id", "title": "Issue", "software": [{"type": "plugin", "slug": "same-name-but-different-slug",
        "affected_versions": {"1.x": {"from_version": "1.0", "from_inclusive": True, "to_version": "1.5", "to_inclusive": True}}}]}}
    respx.get(FEED_URL).mock(return_value=httpx.Response(200, json=feed))
    async with SafeHttp(delay=0, retries=0, allowed_hosts={"www.wordfence.com"}) as client:
        matched = await check_wordfence_feed([{"slug": "another-plugin", "installed_version": "1.2"}], client, api_key_env="TEST_WF_KEY")
    assert matched == []


@pytest.mark.asyncio
async def test_missing_api_key_means_unconfigured_not_clean(monkeypatch):
    monkeypatch.delenv("TEST_WF_MISSING", raising=False)
    async with SafeHttp(delay=0, retries=0, allowed_hosts={"www.wordfence.com"}) as client:
        matched = await check_wordfence_feed([], client, api_key_env="TEST_WF_MISSING")
    assert matched is None


@pytest.mark.asyncio
@respx.mock
async def test_concurrent_site_checks_reuse_advisory_feed(monkeypatch):
    monkeypatch.setenv("TEST_WF_CACHE_KEY", "cache-key-for-this-test")
    route = respx.get(FEED_URL).mock(return_value=httpx.Response(200, json={}))
    async with SafeHttp(delay=0, retries=0, allowed_hosts={"www.wordfence.com"}) as client:
        first, second = await __import__("asyncio").gather(
            check_wordfence_feed([], client, api_key_env="TEST_WF_CACHE_KEY"),
            check_wordfence_feed([], client, api_key_env="TEST_WF_CACHE_KEY"),
        )
    assert first == second == []
    assert route.call_count == 1
