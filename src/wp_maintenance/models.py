"""Validated configuration and audit result models."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator, model_validator


class AccessMode(StrEnum):
    PUBLIC = "public"
    AUTHENTICATED = "authenticated"


class Site(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")
    name: str = Field(min_length=1, max_length=120)
    url: HttpUrl
    environment: str = Field(default="production", pattern=r"^(production|staging|development)$")
    access_mode: AccessMode = AccessMode.PUBLIC
    enabled: bool = True
    credentials_ref: str | None = None
    approved_hosts: list[str] = Field(default_factory=list)
    exclude_paths: list[str] = Field(default_factory=list)
    sitemap_urls: list[HttpUrl] = Field(default_factory=list)

    @field_validator("url")
    @classmethod
    def root_url_only(cls, value: HttpUrl) -> HttpUrl:
        if value.username or value.password:
            raise ValueError("site URL must not contain credentials")
        if value.scheme not in {"http", "https"}:
            raise ValueError("site URL must use HTTP or HTTPS")
        return value

    @model_validator(mode="after")
    def authenticated_requires_ref(self) -> "Site":
        if self.access_mode == AccessMode.AUTHENTICATED and not self.credentials_ref:
            raise ValueError("authenticated sites require credentials_ref")
        return self


class AuditOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")
    wordpress_core: bool = True
    plugins: bool = True
    php: bool = True
    sitemaps: bool = True
    pages: bool = True
    security_advisories: bool = True
    max_pages: int = Field(default=500, ge=1, le=50000)
    max_sitemap_bytes: int = Field(default=5_000_000, ge=1024, le=50_000_000)
    max_sitemap_depth: int = Field(default=8, ge=1, le=20)
    max_redirects: int = Field(default=8, ge=0, le=20)
    concurrency: int = Field(default=5, ge=1, le=32)
    per_host_delay_seconds: float = Field(default=0.25, ge=0, le=30)
    timeout_seconds: float = Field(default=15, gt=0, le=120)
    retries: int = Field(default=2, ge=0, le=5)
    max_response_bytes: int = Field(default=2_000_000, ge=1024, le=20_000_000)
    ssl: bool = True
    respect_robots_txt: bool = True
    security_headers: bool = True
    seo: bool = True
    ssl_warning_days: int = Field(default=30, ge=1, le=365)
    ssl_high_days: int = Field(default=14, ge=1, le=365)
    ssl_critical_days: int = Field(default=6, ge=0, le=365)
    max_crawl_seconds: float = Field(default=900, ge=10, le=86400)

    @model_validator(mode="after")
    def ordered_ssl_thresholds(self) -> "AuditOptions":
        if not (self.ssl_critical_days < self.ssl_high_days < self.ssl_warning_days):
            raise ValueError("ssl thresholds must satisfy critical < high < warning")
        return self


class Schedule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    timezone: str = "UTC"
    day: str = Field(default="sunday", pattern=r"^(saturday|sunday)$")
    time: str = Field(default="03:00", pattern=r"^(?:[01]\d|2[0-3]):[0-5]\d$")

    @field_validator("timezone")
    @classmethod
    def valid_timezone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError("timezone must be a valid IANA timezone") from exc
        return value


class ReportOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")
    format: list[str] = Field(default_factory=lambda: ["markdown", "json"])
    directory: Path = Path("./reports")
    retention_days: int = Field(default=365, ge=1, le=3650)

    @field_validator("format")
    @classmethod
    def supported_formats(cls, value: list[str]) -> list[str]:
        if not value or any(item not in {"markdown", "json"} for item in value):
            raise ValueError("report format must contain markdown and/or json")
        return value


class NotificationOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    email_to: list[str] = Field(default_factory=list)
    webhook_url_ref: str | None = None
    on_status: list[str] = Field(default_factory=lambda: ["ACTION_REQUIRED", "INCOMPLETE"])

    @field_validator("on_status")
    @classmethod
    def valid_statuses(cls, value: list[str]) -> list[str]:
        allowed = {"PASS", "PASS_WITH_WARNINGS", "ACTION_REQUIRED", "INCOMPLETE"}
        if any(item not in allowed for item in value):
            raise ValueError(f"notification status must be one of: {', '.join(sorted(allowed))}")
        return value


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sites: list[Site]
    schedule: Schedule = Field(default_factory=Schedule)
    audit: AuditOptions = Field(default_factory=AuditOptions)
    reports: ReportOptions = Field(default_factory=ReportOptions)
    notifications: NotificationOptions = Field(default_factory=NotificationOptions)
    safety: dict[str, Any] = Field(default_factory=lambda: {"read_only": True, "automatic_updates": False})

    @model_validator(mode="after")
    def unique_site_ids(self) -> "AppConfig":
        ids = [site.id for site in self.sites]
        if len(ids) != len(set(ids)):
            raise ValueError("site identifiers must be unique")
        if self.safety.get("read_only") is not True or self.safety.get("automatic_updates") is not False:
            raise ValueError("safety.read_only must be true and automatic_updates must be false")
        return self


class Finding(BaseModel):
    id: str
    severity: str
    component: str
    title: str
    detail: str
    evidence: list[str] = Field(default_factory=list)
    recommendation: str = ""


class AuditResult(BaseModel):
    site_id: str
    site_name: str
    url: str
    environment: str
    access_mode: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    status: str = "INCOMPLETE"
    coverage: list[str] = Field(default_factory=list)
    wordpress: dict[str, Any] = Field(default_factory=dict)
    php: dict[str, Any] = Field(default_factory=dict)
    plugins: list[dict[str, Any]] = Field(default_factory=list)
    ssl: dict[str, Any] = Field(default_factory=dict)
    http: dict[str, Any] = Field(default_factory=dict)
    sitemaps: dict[str, Any] = Field(default_factory=dict)
    pages: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    crawl: dict[str, Any] = Field(default_factory=dict)
