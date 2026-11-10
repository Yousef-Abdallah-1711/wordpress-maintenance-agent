"""Per-site audit orchestration."""

from __future__ import annotations

import asyncio
import json
import os
import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urlsplit

import httpx
from packaging.version import InvalidVersion, Version

from .core_audit import audit_core
from .crawler import check_pages
from .advisories import check_wordfence_feed
from .http import SafeHttp
from .models import AccessMode, AppConfig, AuditResult, Finding, Site
from .php_audit import evaluate_php
from .plugin_audit import audit_discovered_plugins
from .security import redact_secrets
from .sitemap import discover_sitemaps


class PublicEvidenceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.generator: str | None = None
        self.plugin_assets: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = dict(attrs)
        if tag.lower() == "meta" and (data.get("name") or "").lower() == "generator":
            self.generator = data.get("content")
        for key in ("src", "href"):
            asset = data.get(key) or ""
            match = re.search(r"/wp-content/plugins/([a-zA-Z0-9_-]+)/[^?#]*", asset)
            if match:
                slug = match.group(1)
                query_ver = re.search(r"[?&]ver=([0-9]+(?:\.[0-9A-Za-z_-]+)+)", asset)
                if query_ver:
                    self.plugin_assets[slug] = query_ver.group(1)
                else:
                    self.plugin_assets.setdefault(slug, "UNKNOWN")


async def _authenticated_inventory(site: Site, client: SafeHttp) -> dict[str, object] | None:
    if site.access_mode != AccessMode.AUTHENTICATED or not site.credentials_ref:
        return None
    raw = os.environ.get(site.credentials_ref)
    if not raw:
        raise PermissionError(f"credential environment variable {site.credentials_ref} is not set")
    parts = raw.split(":", 1)
    if len(parts) != 2:
        raise PermissionError(f"{site.credentials_ref} must contain WORDPRESS_USERNAME:APPLICATION_PASSWORD")
    endpoint = str(site.url).rstrip("/") + "/wp-json/wp-maintenance/v1/inventory"
    # Secrets are only sent to this same-origin endpoint and SafeHttp never forwards
    # authorization on cross-origin redirects.
    result = await client.get(endpoint, auth=(parts[0], parts[1]))
    if result.status_code == 401 or result.status_code == 403:
        raise PermissionError("WordPress connector denied inventory access; verify application password and capability")
    if result.status_code != 200:
        raise RuntimeError(result.error or f"connector returned HTTP {result.status_code}")
    try:
        data = json.loads(result.body)
    except ValueError as exc:
        raise RuntimeError("connector returned invalid JSON") from exc
    return data if isinstance(data, dict) else None


def _priority(severity: str) -> str:
    return {"critical": "P0", "high": "P1", "medium": "P2", "low": "P3"}.get(severity, "P2")


async def audit_site(site: Site, config: AppConfig) -> AuditResult:
    opts = config.audit
    allowed = {site.url.host.lower(), *(host.lower() for host in site.approved_hosts)}
    # Official public metadata hosts are allowed only for their read-only API checks.
    allowed.update({"api.wordpress.org"})
    allowed.add("www.wordfence.com")
    result = AuditResult(site_id=site.id, site_name=site.name, url=str(site.url).rstrip("/"),
                         environment=site.environment, access_mode=site.access_mode.value)
    async with SafeHttp(timeout=opts.timeout_seconds, max_bytes=opts.max_response_bytes,
                        max_redirects=opts.max_redirects, retries=opts.retries,
                        allowed_hosts=allowed, delay=opts.per_host_delay_seconds) as client:
        home = await client.get(result.url)
        if home.status_code != 200 or home.error:
            result.errors.append(f"Homepage request: {home.error or 'HTTP ' + str(home.status_code)}")
        html = home.body.decode("utf-8", "replace")
        parser = PublicEvidenceParser()
        parser.feed(html)
        generator_html = parser.generator or ""
        result.coverage.append("homepage_http")

        if opts.wordpress_core:
            core = await audit_core(result.url, generator_html, client)
            result.wordpress = core
            result.coverage.append("wordpress_core_metadata")
            if core.get("installed_version") and (core.get("update_available") or core.get("security_relevance")):
                security_issue = bool(core.get("security_relevance"))
                severity = "high" if security_issue else "medium"
                result.findings.append(Finding(id="WP-CORE-SECURITY" if security_issue else "WP-CORE-UPDATE", severity=severity, component="WordPress core",
                    title="WordPress core security release indicated" if security_issue else "WordPress core update available",
                    detail=f"Installed {core['installed_version']}; official offer {core.get('latest_official') or 'not returned'}.",
                    evidence=[str(core.get("source")), str(core.get("stability_source") or core.get("evidence"))],
                    recommendation="Review compatibility and backup readiness, then plan the core maintenance update."))
            if not core.get("installed_version"):
                result.limitations.append("Exact WordPress core version is NOT_VERIFIABLE_WITH_PUBLIC_ACCESS.")

        inventory: dict[str, object] | None = None
        if site.access_mode == AccessMode.AUTHENTICATED:
            try:
                inventory = await _authenticated_inventory(site, client)
            except PermissionError as exc:
                result.errors.append(redact_secrets(f"AUTHENTICATION FAILURE: {exc}"))
            except Exception as exc:
                result.errors.append(redact_secrets(f"Authenticated inventory: {type(exc).__name__}: {exc}"))

        if inventory:
            result.findings = [finding for finding in result.findings if finding.component != "WordPress core"]
            if inventory.get("wordpress_version"):
                result.wordpress = await audit_core(result.url, f"WordPress {inventory['wordpress_version']}", client)
                result.coverage.append("authenticated_wordpress_core_update_check")
            if inventory.get("wordpress_update_version"):
                result.wordpress["latest_official"] = inventory.get("wordpress_update_version")
                result.wordpress["update_available"] = str(inventory.get("wordpress_version")) != str(inventory.get("wordpress_update_version"))
            if result.wordpress.get("installed_version") and (result.wordpress.get("update_available") or result.wordpress.get("security_relevance")):
                security_issue = bool(result.wordpress.get("security_relevance"))
                result.findings.append(Finding(id="WP-CORE-SECURITY" if security_issue else "WP-CORE-UPDATE",
                    severity="high" if security_issue else "medium", component="WordPress core",
                    title="WordPress core security release indicated" if security_issue else "WordPress core update available",
                    detail=f"Installed {result.wordpress.get('installed_version')}; official offer {result.wordpress.get('latest_official') or 'not returned'}.",
                    evidence=[str(result.wordpress.get("source")), str(result.wordpress.get("stability_source") or "authenticated update transient")],
                    recommendation="Review compatibility and backup readiness, then plan the core maintenance update."))
            result.php = evaluate_php(str(inventory.get("php_version") or "") or None)
            result.plugins = list(inventory.get("plugins") or [])
            result.coverage.extend(["authenticated_wordpress_inventory", "authenticated_php_version", "authenticated_plugin_inventory"])
            for plugin in result.plugins:
                plugin["installed_version"] = plugin.get("version")
                if plugin.get("update_available"):
                    plugin["status"] = "OUTDATED"
                    result.findings.append(Finding(id=f"PLUGIN-UPDATE-{plugin.get('slug', 'unknown')}", severity="medium",
                        component="plugin", title=f"Update available: {plugin.get('name') or plugin.get('slug')}",
                        detail=f"Installed {plugin.get('version')}; available {plugin.get('update_version') or 'unknown'}.",
                        evidence=["Authenticated WordPress connector update transient"], recommendation="Review release notes and compatibility, then update in staging."))
                else:
                    plugin["status"] = "UNKNOWN"
                php_required = plugin.get("requires_php")
                php_installed = result.php.get("installed_version")
                if php_required and php_installed:
                    try:
                        if Version(str(php_installed)) < Version(str(php_required)):
                            result.findings.append(Finding(id=f"PLUGIN-PHP-{plugin.get('slug', 'unknown')}", severity="high", component="plugin compatibility",
                                title=f"PHP requirement not met: {plugin.get('name') or plugin.get('slug')}",
                                detail=f"Plugin requires PHP {php_required}; site reports PHP {php_installed}.",
                                evidence=["Authenticated plugin headers", "Authenticated PHP runtime"], recommendation="Check available plugin updates and prepare a staging compatibility plan."))
                    except InvalidVersion:
                        result.limitations.append(f"Could not compare PHP compatibility metadata for plugin {plugin.get('slug', 'unknown')}.")
        else:
            result.php = evaluate_php(None)
            if opts.plugins:
                discovered = {slug: version for slug, version in parser.plugin_assets.items() if version != "UNKNOWN"}
                result.plugins = await audit_discovered_plugins(discovered, client)
                result.coverage.append("public_plugin_asset_hints")
                for plugin in result.plugins:
                    if plugin.get("abandoned_candidate"):
                        result.findings.append(Finding(id=f"PLUGIN-ABANDONED-{plugin.get('slug')}", severity="medium", component="plugin support",
                            title=f"Potentially abandoned plugin: {plugin.get('name') or plugin.get('slug')}",
                            detail=f"WordPress.org reports the plugin was last updated {plugin.get('last_updated')}; this is a review signal, not a verified support-status finding.",
                            evidence=[str(plugin.get("source")), str(plugin.get("last_updated"))],
                            recommendation="Confirm vendor support and consider a maintained alternative if compatibility or security fixes are unavailable."))
                result.limitations.append("Public HTML plugin asset hints are incomplete and may not reveal inactive, must-use, premium, or non-enqueued plugins.")
                result.limitations.append("PHP version and exact runtime support are NOT_VERIFIABLE_WITH_PUBLIC_ACCESS.")
            else:
                result.limitations.append("Plugin inventory is NOT_VERIFIABLE_WITH_PUBLIC_ACCESS.")

        if result.php.get("support_status") == "END_OF_LIFE":
            result.findings.append(Finding(id="PHP-END-OF-LIFE", severity="high", component="PHP",
                title="PHP branch is end-of-life", detail=f"PHP {result.php.get('installed_version')} no longer receives security fixes.",
                evidence=[str(result.php.get("source")), str(result.php.get("security_support_until"))],
                recommendation="Prepare a staged compatibility review and a tested PHP upgrade/rollback plan."))
        elif result.php.get("support_status") == "SECURITY_FIXES_ONLY":
            result.findings.append(Finding(id="PHP-SECURITY-SUPPORT", severity="medium", component="PHP",
                title="PHP branch receives security fixes only", detail=f"PHP {result.php.get('installed_version')} is outside active support.",
                evidence=[str(result.php.get("source")), str(result.php.get("active_support_until"))],
                recommendation="Review a staged upgrade path and verify all plugin and theme compatibility."))

        if opts.security_advisories:
            try:
                advisories = await check_wordfence_feed(result.plugins, client)
                if advisories is None:
                    result.limitations.append("Vulnerability advisory integration is not configured; set WORDFENCE_API_KEY to enable Wordfence Intelligence V3 checks.")
                else:
                    result.coverage.append("wordfence_intelligence_v3")
                    result.wordpress["security_advisories_checked"] = True
                    result.wordpress["security_advisory_count"] = len(advisories)
                    for advisory in advisories:
                        cvss = advisory.get("cvss") or {}
                        score = cvss.get("score") if isinstance(cvss, dict) else None
                        severity = "low" if advisory.get("informational") else "critical" if isinstance(score, (int, float)) and score >= 9 else "high" if isinstance(score, (int, float)) and score >= 7 else "low" if isinstance(score, (int, float)) and score < 4 else "medium"
                        result.findings.append(Finding(id=str(advisory["id"]), severity=severity, component="security",
                            title=str(advisory["title"]), detail=f"Plugin {advisory['slug']} {advisory['installed_version']} is in affected range(s): {', '.join(advisory['affected_versions'])}.",
                            evidence=[str(advisory.get("source")), *(str(x) for x in advisory.get("references", []))],
                            recommendation=str(advisory.get("remediation"))))
                        plugin = next((item for item in result.plugins if item.get("slug") == advisory["slug"]), None)
                        if plugin is not None:
                            plugin["status"] = "VULNERABLE"
                            plugin.setdefault("advisories", []).append(advisory)
            except Exception as exc:
                result.errors.append(redact_secrets(f"Security advisory lookup failed: {type(exc).__name__}: {exc}"))

        if opts.sitemaps:
            sitemaps = await discover_sitemaps(result.url, client, configured=[str(x) for x in site.sitemap_urls],
                approved_hosts=set(site.approved_hosts), max_pages=opts.max_pages,
                max_depth=opts.max_sitemap_depth, max_bytes=opts.max_sitemap_bytes)
            result.sitemaps = {"discovered": sitemaps.discovered, "checked": sitemaps.checked_sitemaps,
                "urls_discovered": len(sitemaps.urls), "duplicates": sitemaps.duplicates,
                "invalid": sitemaps.invalid}
            result.coverage.append("sitemap_discovery")
            if sitemaps.invalid:
                result.findings.append(Finding(id="SITEMAP-INVALID", severity="medium", component="sitemap",
                    title="Sitemap contains invalid or unchecked entries",
                    detail=f"{len(sitemaps.invalid)} sitemap candidates or entries could not be verified.",
                    evidence=[f"{item.get('url')}: {item.get('reason')}" for item in sitemaps.invalid[:20]],
                    recommendation="Review the listed sitemap URLs, origin approvals, size and format, then run the audit again."))
            if opts.pages and sitemaps.urls:
                page_results = await check_pages(sitemaps.urls, client, concurrency=opts.concurrency)
                excluded = [path for path in site.exclude_paths if path]
                result.pages = [item for item in page_results if not any(urlsplit(str(item["url"])).path.startswith(path) for path in excluded)]
                result.coverage.append("sitemap_page_http_checks")
                for page in result.pages:
                    classification = page.get("classification")
                    if classification in {"missing", "server_error", "client_error", "network_failure", "network_or_policy_error", "timeout", "redirect_loop", "redirect_limit", "tls_error", "rate_limited", "access_restricted"}:
                        severity = "high" if classification in {"server_error", "redirect_loop", "redirect_limit", "tls_error"} else "medium" if classification in {"missing", "client_error", "network_failure", "network_or_policy_error", "timeout"} else "low"
                        result.findings.append(Finding(id=f"PAGE-{len(result.findings)+1}", severity=severity, component="page",
                            title=f"Page health issue: {classification}", detail=f"{page['url']} returned {page.get('status')}.",
                            evidence=[str(page.get("url")), str(page.get("status")), str(page.get("classification"))],
                            recommendation="Investigate the route or server response and recheck after remediation."))
        else:
            result.limitations.append("Sitemap and page checks were disabled by configuration.")

    result.finished_at = datetime.now(timezone.utc)
    if result.errors or not result.coverage:
        result.status = "INCOMPLETE"
    elif result.findings:
        result.status = "ACTION_REQUIRED"
    elif result.limitations:
        result.status = "PASS_WITH_WARNINGS"
    else:
        result.status = "PASS"
    return result


async def run_audit(config: AppConfig, site_ids: set[str] | None = None) -> list[AuditResult]:
    sites = [site for site in config.sites if site.enabled and (site_ids is None or site.id in site_ids)]
    if site_ids is not None and not site_ids.issubset({site.id for site in config.sites}):
        raise ValueError("unknown site identifier requested")
    return await asyncio.gather(*(audit_site(site, config) for site in sites))
