"""Optional Wordfence Intelligence V3 vulnerability feed integration."""

from __future__ import annotations

import json
import os
import asyncio
import hashlib
import threading
import time

from packaging.version import InvalidVersion, Version

from .http import SafeHttp

FEED_URL = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production"
_CACHE: dict[str, tuple[float, dict]] = {}
_INFLIGHT: dict[str, asyncio.Task] = {}
_CACHE_LOCK = threading.RLock()


def _affected(installed: str, rule: dict) -> bool:
    try:
        current = Version(installed)
        lower, upper = rule.get("from_version", "*"), rule.get("to_version", "*")
        if lower != "*":
            bound = Version(lower)
            if current < bound or (current == bound and not rule.get("from_inclusive", True)):
                return False
        if upper != "*":
            bound = Version(upper)
            if current > bound or (current == bound and not rule.get("to_inclusive", True)):
                return False
        return True
    except (InvalidVersion, TypeError):
        return False


async def check_wordfence_feed(
    plugins: list[dict[str, object]],
    client: SafeHttp,
    *,
    api_key_env: str = "WORDFENCE_API_KEY",
) -> list[dict[str, object]] | None:
    """Return verified plugin advisory matches, or None when the integration is unconfigured."""
    key = os.environ.get(api_key_env)
    if not key:
        return None
    cache_key = hashlib.sha256(key.encode()).hexdigest()
    with _CACHE_LOCK:
        cached = _CACHE.get(cache_key)
        if cached and time.monotonic() - cached[0] < 900:
            feed = cached[1]
            task = None
        else:
            task = _INFLIGHT.get(cache_key)
            if task is None:
                task = asyncio.create_task(_fetch_feed(client, key))
                _INFLIGHT[cache_key] = task
            feed = None
    if task is not None:
        try:
            feed = await task
        except Exception:
            with _CACHE_LOCK:
                if _INFLIGHT.get(cache_key) is task:
                    _INFLIGHT.pop(cache_key, None)
            raise
        with _CACHE_LOCK:
            _CACHE[cache_key] = (time.monotonic(), feed)
            if _INFLIGHT.get(cache_key) is task:
                _INFLIGHT.pop(cache_key, None)
    assert isinstance(feed, dict)

    by_slug = {str(plugin.get("slug")): plugin for plugin in plugins if plugin.get("slug") and plugin.get("installed_version")}
    findings: list[dict[str, object]] = []
    for advisory_id, advisory in feed.items():
        if not isinstance(advisory, dict):
            continue
        for software in advisory.get("software", []):
            if not isinstance(software, dict) or software.get("type") != "plugin":
                continue
            slug = str(software.get("slug") or "")
            plugin = by_slug.get(slug)
            if not plugin:
                continue
            version = str(plugin["installed_version"])
            ranges = software.get("affected_versions") or {}
            if not isinstance(ranges, dict):
                continue
            matched = [label for label, rule in ranges.items() if isinstance(rule, dict) and _affected(version, rule)]
            if matched:
                findings.append({
                    "id": str(advisory.get("id") or advisory_id),
                    "title": str(advisory.get("title") or "WordPress plugin vulnerability"),
                    "slug": slug,
                    "installed_version": version,
                    "affected_versions": matched,
                    "patched_versions": software.get("patched_versions", []),
                    "patched": bool(software.get("patched")),
                    "remediation": software.get("remediation") or "Review the advisory and update to a verified patched version.",
                    "references": advisory.get("references", []),
                    "cve": advisory.get("cve"),
                    "cvss": advisory.get("cvss"),
                    "informational": bool(advisory.get("informational")),
                    "published": advisory.get("published"),
                    "copyrights": advisory.get("copyrights"),
                    "source": FEED_URL,
                })
    return findings


async def _fetch_feed(client: SafeHttp, key: str) -> dict:
    response = await client.get(FEED_URL, headers={"Authorization": f"Bearer {key}", "Accept": "application/json"}, max_bytes=20_000_000)
    if response.status_code != 200:
        raise RuntimeError(response.error or f"Wordfence Intelligence returned HTTP {response.status_code}")
    try:
        feed = json.loads(response.body)
    except ValueError as exc:
        raise RuntimeError("Wordfence Intelligence returned invalid JSON") from exc
    if not isinstance(feed, dict):
        raise RuntimeError("Wordfence Intelligence feed had an unsupported shape")
    return feed
