"""Persistent website inventory (config/websites.yaml): strict schema, safe edits, atomic writes."""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from ruamel.yaml import YAML

from .models import AuditOptions
from .reporting import site_slug
from .urlmode import InvalidSiteUrl, normalize_site_url

DEFAULT_INVENTORY = Path("config/websites.yaml")
ID_PATTERN = r"^[a-z0-9][a-z0-9_-]{0,63}$"
SECRET_KEY_RE = re.compile(r"(?i)(pass(word)?|token|secret|api[_-]?key|credential|authorization)")


class InventoryError(ValueError):
    """Raised for invalid inventory content or an unsafe inventory operation."""


class SiteNotifications(BaseModel):
    model_config = ConfigDict(extra="forbid")
    github_issues: bool | None = None


class Defaults(BaseModel):
    model_config = ConfigDict(extra="forbid")
    audit_mode: Literal["public"] = "public"
    max_urls: int = Field(default=500, ge=1, le=50000)
    concurrency: int = Field(default=4, ge=1, le=32)
    timeout_seconds: float = Field(default=20, gt=0, le=120)
    respect_robots_txt: bool = True


class SiteEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=ID_PATTERN)
    name: str = Field(min_length=1, max_length=120)
    url: str
    enabled: bool = True
    tags: list[str] = Field(default_factory=list)
    max_urls: int | None = Field(default=None, ge=1, le=50000)
    concurrency: int | None = Field(default=None, ge=1, le=32)
    timeout_seconds: float | None = Field(default=None, gt=0, le=120)
    respect_robots_txt: bool | None = None
    exclude_paths: list[str] = Field(default_factory=list)
    audit: dict[str, Any] = Field(default_factory=dict)
    notifications: SiteNotifications = Field(default_factory=SiteNotifications)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        if re.search(r"[\x00-\x1f]", value):
            raise ValueError("name must not contain control characters")
        return value.strip()

    @field_validator("tags")
    @classmethod
    def clean_tags(cls, value: list[str]) -> list[str]:
        for tag in value:
            if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,40}", tag):
                raise ValueError(f"invalid tag: {tag!r}")
        return value

    @field_validator("exclude_paths")
    @classmethod
    def clean_exclusions(cls, value: list[str]) -> list[str]:
        for path in value:
            if not path.startswith("/") or re.search(r"[\s\x00-\x1f]", path):
                raise ValueError(f"exclude_paths entries must start with '/': {path!r}")
        return value

    @field_validator("audit")
    @classmethod
    def valid_audit_overrides(cls, value: dict[str, Any]) -> dict[str, Any]:
        if value:
            AuditOptions.model_validate(value)  # unknown keys / bad values are rejected
        return value

    @field_validator("url")
    @classmethod
    def safe_url(cls, value: str) -> str:
        try:
            return normalize_site_url(value, resolve_dns=False)
        except InvalidSiteUrl as exc:
            raise ValueError(str(exc)) from exc


def origin_key(url: str) -> str:
    """Duplicate-detection key: host without a leading www (scheme and path are irrelevant)."""
    host = (urlsplit(url).hostname or url).lower()
    return host[4:] if host.startswith("www.") else host


class Inventory(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Literal[1] = 1
    defaults: Defaults = Field(default_factory=Defaults)
    sites: list[SiteEntry] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique(self) -> "Inventory":
        ids, origins = set(), {}
        for site in self.sites:
            if site.id in ids:
                raise ValueError(f"duplicate site id: {site.id}")
            ids.add(site.id)
            key = origin_key(site.url)
            if key in origins:
                raise ValueError(f"duplicate website {site.url} (already listed as '{origins[key]}')")
            origins[key] = site.id
        return self

    def get(self, site_id: str) -> SiteEntry:
        for site in self.sites:
            if site.id == site_id:
                return site
        raise InventoryError(f"no site with id '{site_id}' in the inventory")


def _reject_secret_keys(node: Any, path: str = "") -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if SECRET_KEY_RE.search(str(key)):
                raise InventoryError(f"inventory must not contain credentials (key '{path}{key}')")
            _reject_secret_keys(value, f"{path}{key}.")
    elif isinstance(node, list):
        for item in node:
            _reject_secret_keys(item, path)


def _yaml() -> YAML:
    y = YAML(typ="rt")
    y.preserve_quotes = True
    y.indent(mapping=2, sequence=4, offset=2)
    y.width = 100
    return y


def _plain(node: Any) -> Any:
    if isinstance(node, dict):
        return {str(k): _plain(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_plain(v) for v in node]
    return node


def _read_raw(path: Path) -> Any:
    try:
        raw = _yaml().load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise InventoryError(f"inventory not found: {path}") from exc
    except Exception as exc:  # ruamel raises several parser error types
        raise InventoryError(f"inventory is not valid YAML: {exc}") from exc
    if raw is None:
        from ruamel.yaml.comments import CommentedMap
        raw = CommentedMap({"version": 1, "sites": []})
    if not isinstance(raw, dict):
        raise InventoryError("inventory root must be a YAML mapping")
    return raw


def parse_inventory(raw: Any) -> Inventory:
    plain = _plain(raw)
    _reject_secret_keys(plain)
    try:
        return Inventory.model_validate(plain)
    except Exception as exc:
        raise InventoryError(_format_validation(exc)) from exc


def _format_validation(exc: Exception) -> str:
    errors = getattr(exc, "errors", None)
    if not callable(errors):
        return str(exc)
    lines = []
    for item in errors():
        where = ".".join(str(part) for part in item.get("loc", ()))
        lines.append(f"{where}: {item.get('msg', 'invalid')}")
    return "; ".join(lines)


def load_inventory(path: str | Path) -> Inventory:
    return parse_inventory(_read_raw(Path(path)))


def _atomic_write(path: Path, raw: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".websites-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            _yaml().dump(raw, handle)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _mutate(path: Path, change) -> Inventory:
    """Load (round-trip, keeping comments), apply `change`, validate the result, then write atomically."""
    raw = _read_raw(path)
    change(raw)
    inventory = parse_inventory(raw)  # validate BEFORE touching the file
    _atomic_write(path, raw)
    return inventory


def new_inventory(path: Path) -> None:
    if path.exists():
        raise InventoryError(f"refusing to overwrite existing inventory: {path}")
    from ruamel.yaml.comments import CommentedMap
    raw = CommentedMap()
    raw["version"] = 1
    raw["sites"] = []
    _atomic_write(path, raw)


def add_site(path: Path, url: str, *, name: str | None = None, site_id: str | None = None,
             tags: list[str] | None = None, enabled: bool = True, resolve_dns: bool = True) -> SiteEntry:
    try:
        origin = normalize_site_url(url, resolve_dns=resolve_dns)
    except InvalidSiteUrl as exc:
        raise InventoryError(f"rejected URL: {exc}") from exc
    host = urlsplit(origin).hostname or origin
    sid = (site_id or site_slug(origin)).lower()
    entry: dict[str, Any] = {"id": sid, "name": name or host, "url": origin, "enabled": enabled}
    if tags:
        entry["tags"] = list(tags)
    if not path.exists():
        new_inventory(path)

    def change(raw: Any) -> None:
        raw.setdefault("version", 1)
        sites = raw.get("sites")
        if sites is None:
            raw["sites"] = sites = []
        sites.append(entry)

    inventory = _mutate(path, change)
    return inventory.get(sid)


def _find_index(raw: Any, site_id: str) -> int:
    for index, item in enumerate(raw.get("sites") or []):
        if item.get("id") == site_id:
            return index
    raise InventoryError(f"no site with id '{site_id}' in the inventory")


def remove_site(path: Path, site_id: str) -> SiteEntry:
    removed = load_inventory(path).get(site_id)

    def change(raw: Any) -> None:
        del raw["sites"][_find_index(raw, site_id)]

    _mutate(path, change)
    return removed


def set_enabled(path: Path, site_id: str, enabled: bool) -> tuple[SiteEntry, bool]:
    """Returns (entry, changed). Setting the current state is a no-op."""
    entry = load_inventory(path).get(site_id)
    if entry.enabled == enabled:
        return entry, False

    def change(raw: Any) -> None:
        raw["sites"][_find_index(raw, site_id)]["enabled"] = enabled

    inventory = _mutate(path, change)
    return inventory.get(site_id), True


def validate_inventory(path: Path, *, resolve_dns: bool = True) -> tuple[Inventory, list[str]]:
    """Strict validation; with DNS resolution every enabled site must resolve to public addresses."""
    inventory = load_inventory(path)
    problems: list[str] = []
    if resolve_dns:
        for site in inventory.sites:
            try:
                normalize_site_url(site.url, resolve_dns=True)
            except InvalidSiteUrl as exc:
                problems.append(f"{site.id}: {exc}")
    return inventory, problems
