"""Authoritative WordPress.org plugin metadata lookups."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from urllib.parse import urlencode

from .http import SafeHttp
from packaging.version import InvalidVersion, Version


async def lookup_plugin(slug: str, installed_version: str, client: SafeHttp, *, version_verified: bool = False) -> dict[str, object]:
    source = "https://api.wordpress.org/plugins/info/1.2/?" + urlencode({"action": "plugin_information", "request[slug]": slug})
    response = await client.get(source)
    base: dict[str, object] = {"slug": slug, "installed_version": installed_version if version_verified else None,
                               "asset_version_hint": None if version_verified else installed_version,
                               "installed_version_confidence": "verified" if version_verified else "unknown",
                               "latest_version": None, "source_type": "wordpress.org", "source": source, "status": "UNKNOWN"}
    if response.status_code != 200:
        base["metadata_error"] = response.error or f"HTTP {response.status_code}"
        base["metadata_error_kind"] = "transport" if response.status_code is None else "rate_limit" if response.status_code == 429 else "server" if response.status_code >= 500 else "not_found" if response.status_code == 404 else "http"
        return base
    try:
        data = json.loads(response.body)
    except ValueError:
        base["metadata_error"] = "invalid JSON from WordPress.org plugin API"
        base["metadata_error_kind"] = "malformed"
        return base
    if not isinstance(data, dict) or not data.get("version"):
        base["source_type"] = "unverified"
        base["metadata_error"] = "plugin slug not found in WordPress.org"
        base["metadata_error_kind"] = "not_found"
        return base
    latest = str(data["version"])
    status = "UNKNOWN"
    if version_verified:
        try:
            installed_v, latest_v = Version(installed_version), Version(latest)
            status = "OUTDATED" if installed_v < latest_v else "CURRENT"
        except InvalidVersion:
            pass
    last_updated = data.get("last_updated")
    abandoned = False
    if isinstance(last_updated, str):
        try:
            updated = datetime.strptime(last_updated[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - updated).days
            abandoned = age_days > 730
        except ValueError:
            pass
    base.update({"name": data.get("name"), "latest_version": latest,
                 "last_updated": data.get("last_updated"), "tested_up_to": data.get("tested"),
                 "requires_php": data.get("requires_php"), "requires_wordpress": data.get("requires"),
                 "status": status, "abandoned_candidate": abandoned,
                 "support_status": "potentially_abandoned" if abandoned else "metadata_available"})
    return base


async def audit_discovered_plugins(discovered: dict[str, str], client: SafeHttp) -> list[dict[str, object]]:
    """Only query slugs discovered in exact plugin asset URLs, with inventory limits explicit."""
    output = []
    for slug, version in sorted(discovered.items()):
        output.append(await lookup_plugin(slug, version, client, version_verified=False))
    return output


def classify_plugin(plugin: dict[str, object], *, verified: bool, metadata_error_kind: object = None) -> dict[str, object]:
    """Assign an evidence-based classification. Asset ?ver= hints never count as a verified install."""
    status = plugin.get("status")
    if metadata_error_kind in {"transport", "rate_limit", "server", "malformed"}:
        label, action = "NOT_VERIFIABLE", "Retry later; release metadata could not be retrieved."
    elif metadata_error_kind in {"not_found"} or plugin.get("source_type") == "unverified":
        label = "UPDATE_SOURCE_UNKNOWN"
        action = "Commercial or custom plugin: check the vendor for updates using an authenticated inventory."
    elif verified and status == "OUTDATED":
        label, action = "VERIFIED_OUTDATED", "Review release notes and update in staging before production."
    elif verified and status == "CURRENT":
        label, action = "VERIFIED_CURRENT", "No action."
    elif plugin.get("latest_version"):
        label, action = "VERSION_UNKNOWN", "Installed version is not publicly verifiable; confirm it in wp-admin or with the connector."
    else:
        label, action = "NOT_VERIFIABLE", "Insufficient public evidence."
    notes = []
    if plugin.get("tested_up_to"):
        notes.append(f"latest release tested up to WordPress {plugin['tested_up_to']}")
    if plugin.get("requires_php"):
        notes.append(f"latest release requires PHP {plugin['requires_php']}")
    plugin["classification"] = label
    plugin["confidence"] = "high" if verified else "slug exact; version unverified"
    plugin["recommended_action"] = action
    plugin["compatibility_notes"] = "; ".join(notes) or "not available"
    plugin.setdefault("advisory_references", [])
    return plugin
