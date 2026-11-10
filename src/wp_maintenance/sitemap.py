"""Safe sitemap discovery and bounded XML parsing."""

from __future__ import annotations

import gzip
from io import BytesIO
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from defusedxml import ElementTree

from .http import SafeHttp
from .security import UnsafeTarget, validate_public_url

SITEMAP_NS = "http://www.sitemaps.org/schemas/sitemap/0.9"
LOC_TAGS = {"loc", f"{{{SITEMAP_NS}}}loc"}


@dataclass
class SitemapResult:
    discovered: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    duplicates: list[str] = field(default_factory=list)
    invalid: list[dict[str, str]] = field(default_factory=list)
    checked_sitemaps: list[str] = field(default_factory=list)


def parse_sitemap_xml(content: bytes, *, max_bytes: int = 5_000_000) -> tuple[str, list[str]]:
    """Return sitemap type and loc values; reject oversized or malformed documents."""
    if len(content) > max_bytes:
        raise ValueError("sitemap exceeded configured size limit")
    if content[:2] == b"\x1f\x8b":
        try:
            with gzip.GzipFile(fileobj=BytesIO(content)) as compressed:
                content = compressed.read(max_bytes + 1)
        except (OSError, EOFError) as exc:
            raise ValueError("invalid gzip sitemap") from exc
        if len(content) > max_bytes:
            raise ValueError("decompressed sitemap exceeded configured size limit")
    try:
        root = ElementTree.fromstring(content)
    except Exception as exc:
        raise ValueError("malformed or unsafe XML sitemap") from exc
    kind = root.tag.rsplit("}", 1)[-1].lower()
    if kind not in {"urlset", "sitemapindex"}:
        raise ValueError("unexpected XML root; expected urlset or sitemapindex")
    locs = []
    for node in root.iter():
        if node.tag in LOC_TAGS and node.text:
            locs.append(node.text.strip())
    return kind, [item for item in locs if item]


async def discover_sitemaps(site_url: str, client: SafeHttp, *, configured: list[str] | None = None,
                           approved_hosts: set[str] | None = None, max_pages: int = 500,
                           max_depth: int = 8, max_bytes: int = 5_000_000) -> SitemapResult:
    base = urlsplit(site_url)
    origin_host = base.hostname or ""
    allowed = {origin_host, *(approved_hosts or set())}
    result = SitemapResult()
    required_candidates = list(configured or [])
    robots = await client.get(f"{base.scheme}://{base.netloc}/robots.txt")
    if robots.status_code == 200:
        for line in robots.body.decode("utf-8", "replace").splitlines():
            key, sep, value = line.partition(":")
            if sep and key.strip().lower() == "sitemap":
                advertised = value.strip()
                required_candidates.append(advertised)
    elif robots.status_code is None or robots.status_code == 429 or (robots.status_code is not None and robots.status_code >= 500):
        result.invalid.append({"url": f"{base.scheme}://{base.netloc}/robots.txt",
                               "reason": robots.error or f"HTTP {robots.status_code}"})
    raw_fallback_candidates = {
        f"{base.scheme}://{base.netloc}/wp-sitemap.xml",
        f"{base.scheme}://{base.netloc}/sitemap_index.xml",
        f"{base.scheme}://{base.netloc}/sitemap.xml",
    }
    fallback_candidates = {validate_public_url(item, allowed_hosts=allowed) for item in raw_fallback_candidates}
    required_queue: list[tuple[str, int]] = []
    optional_queue: list[tuple[str, int]] = []
    candidate_pairs = [(item, True) for item in required_candidates] + [(item, False) for item in sorted(raw_fallback_candidates)]
    for candidate, required in candidate_pairs:
        try:
            normalized = validate_public_url(candidate, allowed_hosts=allowed)
            target = required_queue if required else optional_queue
            if all(item != normalized for item, _ in target):
                target.append((normalized, 0))
        except UnsafeTarget as exc:
            result.invalid.append({"url": candidate, "reason": str(exc)})
    seen_maps: set[str] = set()
    seen_urls: set[str] = set()
    max_sitemaps = max(16, min(max_pages, 1000))
    while (required_queue or optional_queue) and len(result.urls) < max_pages:
        is_required = bool(required_queue)
        queue = required_queue if is_required else optional_queue
        sitemap_url, depth = queue.pop(0)
        if sitemap_url in seen_maps:
            continue
        if len(seen_maps) >= max_sitemaps:
            result.invalid.append({"url": sitemap_url, "reason": "maximum sitemap count reached"})
            break
        seen_maps.add(sitemap_url)
        if depth > max_depth:
            result.invalid.append({"url": sitemap_url, "reason": "maximum sitemap depth exceeded"})
            continue
        fetched = await client.get(sitemap_url, max_bytes=max_bytes)
        result.checked_sitemaps.append(sitemap_url)
        if fetched.status_code != 200:
            if not is_required and sitemap_url in fallback_candidates and fetched.status_code in {404, 410}:
                seen_maps.discard(sitemap_url)
                continue
            result.invalid.append({"url": sitemap_url, "reason": fetched.error or f"HTTP {fetched.status_code}"})
            continue
        result.discovered.append(sitemap_url)
        try:
            kind, locs = parse_sitemap_xml(fetched.body, max_bytes=max_bytes)
        except ValueError as exc:
            result.invalid.append({"url": sitemap_url, "reason": str(exc)})
            continue
        for loc in locs:
            try:
                normalized = validate_public_url(loc, allowed_hosts=allowed)
                if kind == "sitemapindex":
                    if normalized not in seen_maps and all(item != normalized for item, _ in required_queue):
                        required_queue.append((normalized, depth + 1))
                elif normalized in seen_urls:
                    result.duplicates.append(normalized)
                elif len(result.urls) < max_pages:
                    seen_urls.add(normalized)
                    result.urls.append(normalized)
            except UnsafeTarget as exc:
                result.invalid.append({"url": loc, "reason": str(exc)})
    remaining = required_queue or optional_queue
    if remaining:
        result.invalid.append({"url": remaining[0][0], "reason": "URL limit reached; sitemap entries left unchecked"})
    result.discovered = list(dict.fromkeys(result.discovered))
    return result
