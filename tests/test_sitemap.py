import gzip
import socket

import pytest

from wp_maintenance.sitemap import parse_sitemap_xml
from wp_maintenance.sitemap import discover_sitemaps
from wp_maintenance.http import SafeHttp
import httpx
import respx
import pytest


def test_parse_valid_namespaced_sitemap_and_compressed_content():
    xml = b'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://example.com/</loc></url></urlset>'
    assert parse_sitemap_xml(xml) == ("urlset", ["https://example.com/"])
    assert parse_sitemap_xml(gzip.compress(xml))[0] == "urlset"


def test_empty_sitemap():
    assert parse_sitemap_xml(b'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"/>') == ("urlset", [])


def test_reject_malformed_oversized_and_entity_xml():
    with pytest.raises(ValueError, match="malformed"):
        parse_sitemap_xml(b"<urlset>")
    with pytest.raises(ValueError, match="size"):
        parse_sitemap_xml(b"<urlset/>", max_bytes=2)
    with pytest.raises(ValueError, match="unsafe"):
        parse_sitemap_xml(b'<!DOCTYPE a [<!ENTITY x "boom">]><urlset><url><loc>&x;</loc></url></urlset>')


def test_reject_unknown_root():
    with pytest.raises(ValueError, match="unexpected"):
        parse_sitemap_xml(b"<root/>")


@pytest.mark.asyncio
@respx.mock
async def test_nested_cyclic_index_duplicates_and_cross_origin_rejection(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))])
    respx.get("https://example.com/robots.txt").mock(return_value=httpx.Response(200, text="Sitemap: https://example.com/index.xml\n"))
    index = '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><sitemap><loc>https://example.com/index.xml</loc></sitemap><sitemap><loc>https://example.com/pages.xml</loc></sitemap></sitemapindex>'
    respx.get("https://example.com/index.xml").mock(return_value=httpx.Response(200, text=index))
    urls = '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://example.com/a</loc></url><url><loc>https://example.com/a</loc></url><url><loc>https://evil.example/</loc></url></urlset>'
    respx.get("https://example.com/pages.xml").mock(return_value=httpx.Response(200, text=urls))
    for path in ("/wp-sitemap.xml", "/sitemap_index.xml", "/sitemap.xml"):
        respx.get(f"https://example.com{path}").mock(return_value=httpx.Response(404))
    async with SafeHttp(delay=0, retries=0, allowed_hosts={"example.com"}) as client:
        result = await discover_sitemaps("https://example.com", client, max_pages=20)
    assert result.urls == ["https://example.com/a"]
    assert result.duplicates == ["https://example.com/a"]
    assert any("approved" in item["reason"] for item in result.invalid)
    assert result.checked_sitemaps.count("https://example.com/index.xml") == 1
    assert not any("HTTP 404" in item["reason"] for item in result.invalid)


@pytest.mark.asyncio
@respx.mock
async def test_advertised_fallback_sitemap_404_is_not_silently_suppressed(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))])
    respx.get("https://example.com/robots.txt").mock(return_value=httpx.Response(200, text="Sitemap: https://example.com/wp-sitemap.xml\n"))
    for path in ("/wp-sitemap.xml", "/sitemap_index.xml", "/sitemap.xml"):
        respx.get(f"https://example.com{path}").mock(return_value=httpx.Response(404))
    async with SafeHttp(delay=0, retries=0, allowed_hosts={"example.com"}) as client:
        result = await discover_sitemaps("https://example.com", client)
    assert any(item["url"] == "https://example.com/wp-sitemap.xml" and item["reason"] == "HTTP 404" for item in result.invalid)


@pytest.mark.asyncio
@respx.mock
async def test_nested_index_makes_conventional_child_sitemap_required(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))])
    respx.get("https://example.com/robots.txt").mock(return_value=httpx.Response(200, text="Sitemap: https://example.com/wp-sitemap.xml\n"))
    index = b'<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><sitemap><loc>https://example.com/sitemap.xml</loc></sitemap></sitemapindex>'
    respx.get("https://example.com/wp-sitemap.xml").mock(return_value=httpx.Response(200, content=index))
    respx.get("https://example.com/sitemap.xml").mock(return_value=httpx.Response(404))
    respx.get("https://example.com/sitemap_index.xml").mock(return_value=httpx.Response(404))
    async with SafeHttp(delay=0, retries=0, allowed_hosts={"example.com"}) as client:
        result = await discover_sitemaps("https://example.com", client)
    assert any(item["url"] == "https://example.com/sitemap.xml" and item["reason"] == "HTTP 404" for item in result.invalid)


@pytest.mark.asyncio
@respx.mock
async def test_configured_fallback_path_is_required_after_normalization(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))])
    respx.get("https://example.com/robots.txt").mock(return_value=httpx.Response(404))
    for path in ("/wp-sitemap.xml", "/sitemap_index.xml", "/sitemap.xml"):
        respx.get(f"https://example.com{path}").mock(return_value=httpx.Response(404))
    async with SafeHttp(delay=0, retries=0, allowed_hosts={"example.com"}) as client:
        result = await discover_sitemaps("https://example.com", client,
            configured=["HTTPS://EXAMPLE.COM/wp-sitemap.xml"])
    assert any(item["url"] == "https://example.com/wp-sitemap.xml" and item["reason"] == "HTTP 404" for item in result.invalid)


def test_reject_decompression_bomb_with_bounded_read():
    compressed = gzip.compress(b"x" * 100_000)
    with pytest.raises(ValueError, match="decompressed.*size"):
        parse_sitemap_xml(compressed, max_bytes=500)
