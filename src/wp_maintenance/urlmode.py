"""Zero-configuration URL handling: normalization, scope and ephemeral configuration."""

from __future__ import annotations

import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from .models import AppConfig, Site
from .reporting import site_slug
from .security import UnsafeTarget, validate_public_url


class InvalidSiteUrl(ValueError):
    """Raised when a user-supplied website address cannot be audited safely."""


def normalize_site_url(raw: str, *, resolve_dns: bool = True) -> str:
    """Return the audit origin (scheme://host) for a user-supplied address, or raise InvalidSiteUrl."""
    value = (raw or "").strip()
    if not value or re.search(r"[\s\x00-\x1f]", value):
        raise InvalidSiteUrl("URL is empty or contains whitespace/control characters")
    if "://" not in value:
        value = "https://" + value
    parts = urlsplit(value)
    if parts.scheme.lower() not in {"http", "https"}:
        raise InvalidSiteUrl("only http:// and https:// URLs can be audited")
    if parts.username or parts.password:
        raise InvalidSiteUrl("URL must not contain credentials")
    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise InvalidSiteUrl("URL has no hostname")
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise InvalidSiteUrl("hostname is not a valid domain name") from exc
    if "." not in host and ":" not in host:
        raise InvalidSiteUrl("hostname must be a fully qualified domain name")
    if not re.fullmatch(r"[a-z0-9.-]+|[0-9a-f:.]+", host):
        raise InvalidSiteUrl("hostname contains invalid characters")
    try:
        port = parts.port
    except ValueError as exc:
        raise InvalidSiteUrl("invalid port") from exc
    candidate = f"{parts.scheme.lower()}://{host}" + (f":{port}" if port else "") + "/"
    try:
        validate_public_url(candidate, resolve_dns=resolve_dns)
    except UnsafeTarget as exc:
        raise InvalidSiteUrl(str(exc)) from exc
    return candidate.rstrip("/")


def counterpart_host(host: str) -> str | None:
    if re.fullmatch(r"[0-9.]+", host) or ":" in host or host.count(".") < 1:
        return None
    return host[4:] if host.startswith("www.") else f"www.{host}"


def build_site(url: str, *, name: str | None = None, site_id: str | None = None) -> Site:
    origin = normalize_site_url(url)
    host = urlsplit(origin).hostname or ""
    other = counterpart_host(host)
    return Site(id=site_id or site_slug(origin), name=name or host, url=origin,
                approved_hosts=[other] if other else [])


def default_reports_dir() -> Path:
    return Path(os.environ.get("WP_MAINTENANCE_REPORTS_DIR") or Path.home() / "wp-maintenance-reports")


def default_config_path() -> Path:
    env = os.environ.get("WP_MAINTENANCE_CONFIG")
    if env:
        return Path(env)
    local = Path("wp-maintenance.yaml")
    return local if local.exists() else Path.home() / ".wp-maintenance" / "config.yaml"


def build_url_config(url: str, *, reports_dir: Path | None = None, max_pages: int | None = None,
                     concurrency: int | None = None, formats: list[str] | None = None) -> AppConfig:
    site = build_site(url)
    audit: dict[str, object] = {}
    if max_pages is not None:
        audit["max_pages"] = max_pages
    if concurrency is not None:
        audit["concurrency"] = concurrency
    return AppConfig.model_validate({"sites": [site.model_dump(mode="json")], "audit": audit,
        "reports": {"directory": str(reports_dir or default_reports_dir()), "format": formats or ["markdown", "json"]}})
