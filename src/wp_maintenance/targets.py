"""Deterministic audit-target resolution (inventory, WP_MAINTENANCE_URLS, manual inputs)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .inventory import ID_PATTERN, Inventory, InventoryError, load_inventory, origin_key
from .reporting import site_slug
from .urlmode import InvalidSiteUrl, normalize_site_url

SCOPES = ("all", "single", "custom_url")
REPORT_MODES = ("standard", "detailed")
MAX_URLS_CEILING = 50000


class TargetError(ValueError):
    """Raised when the requested audit selection is invalid or ambiguous."""


@dataclass
class Target:
    id: str
    name: str
    url: str
    tags: list[str] = field(default_factory=list)
    max_urls: int = 500
    concurrency: int = 4
    timeout_seconds: float = 20
    respect_robots_txt: bool = True
    exclude_paths: list[str] = field(default_factory=list)
    audit: dict[str, Any] = field(default_factory=dict)
    github_issues: bool | None = None
    source: str = "inventory"


@dataclass
class Resolution:
    targets: list[Target]
    source: str
    notes: list[str] = field(default_factory=list)


def parse_url_list(text: str | None) -> list[str]:
    """WP_MAINTENANCE_URLS format: one URL per line (whitespace also separates); '#' starts a comment."""
    urls: list[str] = []
    for line in (text or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            urls.extend(line.split())
    return urls


def _from_urls(urls: list[str], *, resolve_dns: bool) -> list[Target]:
    seen: dict[str, str] = {}
    targets = []
    for raw in urls:
        try:
            origin = normalize_site_url(raw, resolve_dns=resolve_dns)
        except InvalidSiteUrl as exc:
            raise TargetError(f"WP_MAINTENANCE_URLS entry rejected ({raw!r}): {exc}") from exc
        key = origin_key(origin)
        if key in seen:
            raise TargetError(f"WP_MAINTENANCE_URLS lists {origin} twice (duplicates are never merged silently)")
        seen[key] = origin
        sid = site_slug(origin)
        targets.append(Target(id=sid, name=sid, url=origin, source="WP_MAINTENANCE_URLS"))
    return targets


def _from_inventory(inv: Inventory, entry) -> Target:
    d = inv.defaults
    return Target(id=entry.id, name=entry.name, url=entry.url, tags=list(entry.tags),
        max_urls=entry.max_urls or d.max_urls, concurrency=entry.concurrency or d.concurrency,
        timeout_seconds=entry.timeout_seconds or d.timeout_seconds,
        respect_robots_txt=d.respect_robots_txt if entry.respect_robots_txt is None else entry.respect_robots_txt,
        exclude_paths=list(entry.exclude_paths), audit=dict(entry.audit),
        github_issues=entry.notifications.github_issues, source="inventory")


def validate_selection(scope: str, site_id: str | None, custom_url: str | None, max_urls: str | int | None,
                       report_mode: str = "standard") -> tuple[str, str | None, str | None, int | None, str]:
    scope = (scope or "all").strip()
    site_id = (site_id or "").strip() or None
    custom_url = (custom_url or "").strip() or None
    if scope not in SCOPES:
        raise TargetError(f"audit_scope must be one of {', '.join(SCOPES)}")
    if report_mode not in REPORT_MODES:
        raise TargetError(f"report_mode must be one of {', '.join(REPORT_MODES)}")
    if scope == "all" and (site_id or custom_url):
        raise TargetError("audit_scope 'all' cannot be combined with site_id or custom_url")
    if scope == "single":
        if not site_id:
            raise TargetError("audit_scope 'single' requires site_id")
        if custom_url:
            raise TargetError("audit_scope 'single' cannot be combined with custom_url")
        if not re.fullmatch(ID_PATTERN, site_id):
            raise TargetError("site_id contains invalid characters")
    if scope == "custom_url":
        if not custom_url:
            raise TargetError("audit_scope 'custom_url' requires custom_url")
        if site_id:
            raise TargetError("audit_scope 'custom_url' cannot be combined with site_id")
    limit = None
    if max_urls not in (None, ""):
        try:
            limit = int(str(max_urls).strip())
        except ValueError as exc:
            raise TargetError("max_urls must be a whole number") from exc
        if not 1 <= limit <= MAX_URLS_CEILING:
            raise TargetError(f"max_urls must be between 1 and {MAX_URLS_CEILING}")
    return scope, site_id, custom_url, limit, report_mode


def resolve_targets(*, inventory_path: Path | None, urls_text: str | None = None, scope: str = "all",
                    site_id: str | None = None, custom_url: str | None = None, max_urls: str | int | None = None,
                    resolve_dns: bool = True) -> Resolution:
    """Precedence: custom_url (this run only) > inventory file with sites > WP_MAINTENANCE_URLS. Never merged."""
    scope, site_id, custom_url, limit, _ = validate_selection(scope, site_id, custom_url, max_urls)
    notes: list[str] = []
    if scope == "custom_url":
        try:
            origin = normalize_site_url(custom_url, resolve_dns=resolve_dns)
        except InvalidSiteUrl as exc:
            raise TargetError(f"custom_url rejected: {exc}") from exc
        sid = site_slug(origin)
        targets = [Target(id=sid, name=sid, url=origin, source="custom_url")]
        notes.append("custom_url audit: one-time, not added to the inventory")
        return Resolution(_apply_limit(targets, limit), "custom_url", notes)

    inventory: Inventory | None = None
    if inventory_path is not None and Path(inventory_path).is_file():
        try:
            inventory = load_inventory(inventory_path)
        except InventoryError as exc:
            raise TargetError(f"inventory invalid: {exc}") from exc
    url_list = parse_url_list(urls_text)

    if inventory is not None and inventory.sites:
        source = f"inventory ({inventory_path})"
        if url_list:
            notes.append("WP_MAINTENANCE_URLS is set but ignored because the inventory file lists sites")
        if scope == "single":
            entry = inventory.get(site_id) if any(s.id == site_id for s in inventory.sites) else None
            if entry is None:
                raise TargetError(f"site_id '{site_id}' is not in the inventory")
            if not entry.enabled:
                raise TargetError(f"site '{site_id}' is disabled; enable it or use custom_url for a one-time audit")
            targets = [_from_inventory(inventory, entry)]
        else:
            targets = [_from_inventory(inventory, s) for s in inventory.sites if s.enabled]
            disabled = [s.id for s in inventory.sites if not s.enabled]
            if disabled:
                notes.append(f"skipped disabled sites: {', '.join(disabled)}")
            if not targets:
                raise TargetError("the inventory has sites but none are enabled")
        return Resolution(_apply_limit(targets, limit), source, notes)

    if url_list:
        targets = _from_urls(url_list, resolve_dns=resolve_dns)
        if scope == "single":
            targets = [t for t in targets if t.id == site_id]
            if not targets:
                raise TargetError(f"site_id '{site_id}' is not in WP_MAINTENANCE_URLS")
        return Resolution(_apply_limit(targets, limit), "WP_MAINTENANCE_URLS", notes)

    raise TargetError("no websites configured: add sites to config/websites.yaml (wp-maintenance site add <url>), "
                      "set the WP_MAINTENANCE_URLS repository variable, or run with audit_scope=custom_url")


def _apply_limit(targets: list[Target], limit: int | None) -> list[Target]:
    if limit is not None:
        for target in targets:
            target.max_urls = limit
    return targets
