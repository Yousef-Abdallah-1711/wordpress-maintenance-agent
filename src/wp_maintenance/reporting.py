"""Evidence-focused Markdown and JSON reports."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .history import compare_results, previous_result
from .models import AuditResult
from .security import redact_secrets

SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]
BROKEN = {"missing", "server_error", "client_error", "network_failure", "network_or_policy_error", "timeout",
          "redirect_loop", "redirect_limit", "tls_error", "rate_limited", "access_restricted"}
MAX_LISTED = 200


def _safe_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]+", "-", value).strip("-") or "site"


def site_slug(url_or_host: str) -> str:
    """Deterministic identifier for a site, e.g. https://www.juhayna.com -> juhayna-com."""
    host = (urlsplit(url_or_host if "//" in url_or_host else f"//{url_or_host}").hostname or url_or_host).lower()
    if host.startswith("www."):
        host = host[4:]
    return _safe_id(host.replace(".", "-"))


def _cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _md(result: AuditResult, delta: dict[str, list[str]]) -> str:
    duration = (result.finished_at - result.started_at).total_seconds() if result.finished_at else 0.0
    counts = {name: sum(f.severity == name for f in result.findings) for name in SEVERITY_ORDER}
    wp, php, ssl_info, http = result.wordpress, result.php, result.ssl, result.http
    seo = http.get("seo", {}) if isinstance(http, dict) else {}
    lines = ["# WordPress Maintenance Audit Report", "", "## 1. Website Information", "",
        f"- Website name: {result.site_name}", f"- Website URL: {result.url}",
        f"- Final URL after redirects: {http.get('final_url', 'UNKNOWN')}", f"- Environment: {result.environment}",
        f"- Access mode: {result.access_mode}", f"- Audit date: {result.started_at.isoformat()}",
        f"- Audit duration: {duration:.2f} seconds", f"- Audit coverage: {', '.join(result.coverage) or 'none'}", "",
        "## 2. Overall Health", "", f"- Overall status: **{result.status}**",
        *[f"- {name.capitalize()} findings: {counts[name]}" for name in SEVERITY_ORDER],
        f"- Unknown/unverified items: {len(result.limitations)}", f"- Collector errors: {len(result.errors)}", ""]
    lines += ["## 3. SSL Certificate", ""]
    if ssl_info:
        redirect = ssl_info.get("https_redirect") or {}
        trust = "TRUSTED" if ssl_info.get("trusted") else "NOT TRUSTED"
        lines += [f"- Certificate status: **{ssl_info.get('status', 'UNKNOWN')}** ({trust})",
            f"- TLS handshake: {'succeeded' if ssl_info.get('handshake_ok') else 'failed'}"
            + (f" — {ssl_info.get('error_kind')}: {ssl_info.get('error')}" if ssl_info.get("error_kind") else ""),
            f"- Negotiated protocol: {ssl_info.get('tls_version') or 'UNKNOWN'}",
            f"- Subject: {ssl_info.get('subject') or 'UNKNOWN'}", f"- Issuer: {ssl_info.get('issuer') or 'UNKNOWN'}",
            f"- Valid until: {ssl_info.get('not_after') or 'UNKNOWN'}",
            f"- Days remaining: {ssl_info.get('days_remaining') if ssl_info.get('days_remaining') is not None else 'UNKNOWN'}",
            f"- Subject Alternative Names: {', '.join(ssl_info.get('san') or []) or 'UNKNOWN'}",
            f"- Hostname valid: {ssl_info.get('hostname_valid') if ssl_info.get('hostname_valid') is not None else 'UNKNOWN'}",
            f"- HTTP to HTTPS: {redirect.get('state', 'NOT_CHECKED')} ({redirect.get('detail', 'n/a')})"]
        if ssl_info.get("diagnostic_only"):
            lines.append("- Note: certificate metadata was collected by a diagnostic connection after verification failed; the connection is NOT trusted.")
    else:
        lines.append("- SSL inspection was not performed or did not complete.")
    lines += ["", "## 4. WordPress Core", "",
        f"- Detection: **{wp.get('detection', 'NOT_CHECKED')}**",
        f"- Detection signals: {'; '.join(wp.get('detection_signals') or []) or 'none'}",
        f"- Installed version: {wp.get('installed_version') or 'UNKNOWN'} ({wp.get('version_status', 'UNKNOWN')})",
        f"- Latest official version: {wp.get('latest_official') or 'UNKNOWN'}",
        f"- Update available: {wp.get('update_available') if wp.get('update_available') is not None else 'UNKNOWN'}",
        f"- Security relevance: {wp.get('security_relevance') if wp.get('security_relevance') is not None else 'UNKNOWN'}",
        f"- Evidence: {wp.get('evidence', 'not checked')}", f"- Official source: {wp.get('source', 'n/a')}",
        f"- Retrieved at: {wp.get('retrieved_at', 'n/a')}", "",
        "## 5. Plugin Inventory and Updates", "",
        "| Plugin | Installed | Latest | Classification | Confidence | Evidence | Action |", "|---|---:|---:|---|---|---|---|"]
    if result.plugins:
        for plugin in result.plugins:
            installed = plugin.get("installed_version") or plugin.get("version") or "UNKNOWN"
            if plugin.get("asset_version_hint") and not plugin.get("installed_version"):
                installed = f"UNKNOWN (asset hint: {plugin['asset_version_hint']})"
            name = plugin.get("name") or plugin.get("slug") or "Unidentified plugin"
            latest = plugin.get("latest_version") or plugin.get("update_version") or "UNKNOWN"
            label = "VULNERABLE" if plugin.get("status") == "VULNERABLE" else plugin.get("classification") or plugin.get("status", "UNKNOWN")
            lines.append(f"| {_cell(name)} ({_cell(plugin.get('slug', ''))}) | {_cell(installed)} | {_cell(latest)} | {label} | "
                f"{_cell(plugin.get('confidence', 'n/a'))} | {_cell(plugin.get('evidence_url') or 'n/a')} | {_cell(plugin.get('recommended_action', 'Review'))} |")
    else:
        lines.append("| No plugin references found | UNKNOWN | UNKNOWN | NOT_VERIFIABLE | — | — | Authenticated inventory required for completeness |")
    lines += ["", "The public plugin list is incomplete by nature: inactive, must-use, premium or non-enqueued plugins are not visible.", ""]
    lines += ["## 6. PHP Runtime", "",
        f"- Installed version: {php.get('installed_version') or php.get('message') or 'PHP VERSION: UNKNOWN — AUTHENTICATED VERIFICATION REQUIRED'}",
        f"- Support status: {php.get('support_status', 'UNKNOWN')}",
        f"- Evidence: {php.get('evidence', 'no public version disclosure')}", f"- Lifecycle source: {php.get('source', 'not checked')}",
        "- Upgrade readiness: not evaluated; compatibility must be validated in staging.", ""]
    sm = result.sitemaps
    crawl = result.crawl
    lines += ["## 7. Sitemap Discovery", "", f"- Sitemaps discovered: {len(sm.get('discovered', []))}"]
    lines += [f"  - {u}" for u in sm.get("discovered", [])[:20]]
    lines += [f"- URLs discovered: {sm.get('urls_discovered', 0)} (listed in sitemaps: {sm.get('urls_listed', 0)}{'+' if sm.get('truncated') else ''})",
        f"- Duplicate URLs: {len(sm.get('duplicates', []))}", f"- Invalid sitemap entries: {len(sm.get('invalid', []))}", ""]
    pages = result.pages
    times = sorted(p.get("elapsed_ms") or 0 for p in pages)
    p95 = times[max(int(len(times) * 0.95) - 1, 0)] if times else 0
    lines += ["## 8. Page Health", "",
        f"- Coverage: **{crawl.get('urls_checked', len(pages))}/{crawl.get('sitemap_urls_listed', len(pages))}"
        f"{'+' if crawl.get('sitemap_truncated') else ''}** sitemap URLs checked"
        + (f" (stopped: {crawl['halted_reason']})" if crawl.get("halted_reason") else ""),
        f"- Successful (2xx): {sum(p.get('classification') == 'available' for p in pages)}",
        f"- Redirects (3xx): {sum(p.get('classification') == 'redirect' for p in pages)}",
        f"- Client errors (4xx): {sum(p.get('classification') in {'missing', 'client_error', 'access_restricted', 'rate_limited'} for p in pages)}",
        f"- Server errors (5xx): {sum(p.get('classification') == 'server_error' for p in pages)}",
        f"- Network/TLS/timeouts/loops: {sum(p.get('classification') in {'network_failure', 'network_or_policy_error', 'timeout', 'tls_error', 'redirect_loop', 'redirect_limit'} for p in pages)}",
        f"- Response time: median {times[len(times)//2] if times else 0:.0f} ms, p95 {p95:.0f} ms, max {times[-1] if times else 0:.0f} ms", "",
        "## 9. Broken Page URLs", ""]
    issues = [p for p in pages if p.get("classification") in BROKEN]
    lines += [f"- `{p.get('url')}` — HTTP {p.get('status') or 'unavailable'} ({p.get('classification')}); final: {p.get('final_url')}" for p in issues[:MAX_LISTED]]
    if len(issues) > MAX_LISTED:
        lines.append(f"- ... {len(issues) - MAX_LISTED} more; see the JSON report for the complete list.")
    if not issues:
        lines.append("No broken URL findings among the pages that were checked." if pages else "No pages were checked.")
    sec = [f for f in result.findings if f.component in {"security", "security headers"}]
    lines += ["", "## 10. Security Configuration", "", "Missing headers are ranked by context and are hardening items, not vulnerabilities.", ""]
    headers = http.get("security_headers", {}) if isinstance(http, dict) else {}
    if headers:
        lines += [f"- {name}: {value if value else 'MISSING'}" for name, value in headers.items()]
    lines += [f"- **{f.severity.upper()} {f.title}:** {f.detail}" for f in sec if f.component == "security"]
    if not any(f.component == "security" for f in result.findings):
        lines.append("- No verified vulnerability advisory findings were returned (advisory checks require exact plugin identity and version).")
    for plugin in result.plugins:
        if plugin.get("status") == "VULNERABLE":
            for advisory in plugin.get("advisories", []):
                if advisory.get("cve"):
                    lines.append(f"- CVE: {advisory['cve']}")
                for ref in advisory.get("references") or []:
                    lines.append(f"- Advisory reference: {ref}")
                copyrights = advisory.get("copyrights") or {}
                if isinstance(copyrights, dict):
                    for owner, notice in copyrights.items():
                        if isinstance(notice, dict) and notice.get("notice"):
                            lines.append(f"- Attribution ({owner}): {notice['notice']}; {notice.get('license_url', '')}")
    lines += ["", "## 11. Technical SEO and Performance", "",
        f"- robots.txt: HTTP {seo.get('robots_txt_status', 'NOT_CHECKED')}", f"- Canonical: {seo.get('canonical') or 'none found'}",
        f"- Meta robots: {seo.get('meta_robots') or 'none'}; X-Robots-Tag: {seo.get('x_robots_tag') or 'none'}",
        f"- Sitemap available: {'yes' if sm.get('discovered') else 'no'}",
        f"- Homepage response time: {http.get('homepage_response_ms', 'UNKNOWN')} ms (server response only; no Lighthouse or Core Web Vitals measured)", ""]
    lines += ["## 12. Previous Audit Comparison", "", f"- New issues: {', '.join(delta['new'][:30]) or 'none'}",
        f"- Resolved issues: {', '.join(delta['resolved'][:30]) or 'none'}", f"- Persistent issues: {len(delta['persistent'])}", ""]
    lines += ["## 13. Prioritized Maintenance Actions", ""]
    ordered = sorted(result.findings, key=lambda f: SEVERITY_ORDER.index(f.severity) if f.severity in SEVERITY_ORDER else 9)
    page_findings = [f for f in ordered if f.component == "page"]
    shown = [f for f in ordered if f.component != "page"] + page_findings[:25]
    for severity in SEVERITY_ORDER:
        group = [f for f in shown if f.severity == severity]
        if group:
            lines += [f"### {severity.upper()}", ""]
            for f in group:
                lines += [f"- [ ] **{f.title}** (`{f.id}`, {f.component}) — {f.detail}",
                          f"  - Action: {f.recommendation or 'Investigate.'}",
                          f"  - Evidence: {'; '.join(f.evidence) or 'none recorded'}"]
            lines.append("")
    if len(page_findings) > 25:
        lines += [f"- {len(page_findings) - 25} further page-health findings omitted here; see Section 9 and the JSON report.", ""]
    if not result.findings:
        lines += ["No remediation actions were supported by the collected evidence.", ""]
    lines += ["Safe change sequence for any production change: verified backup, staging, compatibility review, test, scheduled deployment, validation, tested rollback.", "",
        "## 14. Evidence and Sources", "",
        "- WordPress core: https://api.wordpress.org/core/version-check/1.7/ and stable-check API",
        "- Plugins: https://api.wordpress.org/plugins/info/1.2/", "- PHP lifecycle: https://www.php.net/supported-versions.php",
        "- TLS: direct handshake to the host on port 443 (see Section 3 timestamp)",
        "- Page checks: HTTP GET requests recorded per URL in the JSON report (status, redirect chain, timing, timestamp)", "",
        "## 15. Unknown or Unverified Information", ""]
    lines += [f"- {item}" for item in result.limitations] or ["- No known limitations were recorded."]
    lines += [f"- Collector error: {redact_secrets(error)}" for error in result.errors]
    lines += ["", "A successful HTTP status checks availability only; it does not prove browser or application behavior.",
              "", "## 16. Final Audit Status", "", f"**{result.status}**", ""]
    return "\n".join(lines)


def write_reports(results: list[AuditResult], reports_dir: Path, *, formats: list[str] | None = None,
                  retention_days: int = 365) -> Path:
    now = datetime.now(timezone.utc)
    formats = formats or ["markdown", "json"]
    run_dir = reports_dir / now.astimezone().strftime("%Y-%m-%d") / now.strftime("%Y-%m-%dT%H%M%S.%fZ")
    run_dir.mkdir(parents=True, exist_ok=True)
    marker = run_dir / ".wp-maintenance-agent-report"
    marker.write_text("Generated by WordPress Maintenance Agent.\n", encoding="utf-8")
    try:
        os.chmod(run_dir, 0o700)
    except OSError:
        pass
    output = []
    for result in results:
        payload = result.model_dump(mode="json")
        prior = previous_result(reports_dir, result.site_id, current_run=run_dir / "results.json")
        delta = compare_results(payload, prior)
        output.append({**payload, "previous_audit": delta})
        if "markdown" in formats:
            target = run_dir / f"{_safe_id(result.site_id)}.md"
            target.write_text(_md(result, delta), encoding="utf-8")
            try:
                os.chmod(target, 0o600)
            except OSError:
                pass
    data = {"generated_at": now.isoformat(), "sites": output}
    if "json" in formats:
        (run_dir / "results.json").write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if "markdown" in formats:
        summary = ["# WordPress Maintenance Audit Summary", "", f"Generated: {now.isoformat()}", "", "| Site | Status | Findings |", "|---|---|---:|"]
        summary.extend(f"| {r.site_name} | {r.status} | {len(r.findings)} |" for r in results)
        (run_dir / "summary.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    cutoff = now.date() - timedelta(days=retention_days)
    if reports_dir.exists():
        for marker in reports_dir.rglob(".wp-maintenance-agent-report"):
            old_dir = marker.parent
            if old_dir == run_dir or not old_dir.is_dir():
                continue
            try:
                if datetime.fromtimestamp(marker.stat().st_mtime, timezone.utc).date() < cutoff:
                    for child in old_dir.iterdir():
                        if child.is_file() and (child.name.endswith(".md") or child.name == "results.json" or child.name == ".wp-maintenance-agent-report"):
                            child.unlink()
                    if not any(old_dir.iterdir()):
                        old_dir.rmdir()
            except (ValueError, OSError):
                continue
    return run_dir


def write_site_layout(results: list[AuditResult], reports_dir: Path, *, formats: list[str] | None = None,
                      retention_days: int = 365) -> dict[str, dict[str, Path]]:
    """reports/<site>/latest.{md,json} plus history/<timestamp>.{md,json}; history is never overwritten."""
    formats = formats or ["markdown", "json"]
    now = datetime.now().astimezone()
    stamp = now.strftime("%Y-%m-%d-%H%M%S")
    written: dict[str, dict[str, Path]] = {}
    for result in results:
        site_dir = reports_dir / _safe_id(result.site_id)
        history = site_dir / "history"
        history.mkdir(parents=True, exist_ok=True)
        prior = None
        latest_json = site_dir / "latest.json"
        if latest_json.is_file():
            try:
                prior = json.loads(latest_json.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                prior = None
        payload = result.model_dump(mode="json")
        delta = compare_results(payload, prior)
        payload["previous_audit"] = delta
        name = stamp
        counter = 1
        while (history / f"{name}.md").exists() or (history / f"{name}.json").exists():
            counter += 1
            name = f"{stamp}-{counter}"
        paths: dict[str, Path] = {}
        if "markdown" in formats:
            text = _md(result, delta)
            (history / f"{name}.md").write_text(text, encoding="utf-8")
            (site_dir / "latest.md").write_text(text, encoding="utf-8")
            paths["markdown"] = (site_dir / "latest.md").resolve()
        if "json" in formats:
            text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
            (history / f"{name}.json").write_text(text, encoding="utf-8")
            latest_json.write_text(text, encoding="utf-8")
            paths["json"] = latest_json.resolve()
        paths["history"] = history.resolve()
        written[result.site_id] = paths
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        for old in history.iterdir():
            try:
                if old.is_file() and datetime.fromtimestamp(old.stat().st_mtime, timezone.utc) < cutoff:
                    old.unlink()
            except OSError:
                continue
    if "markdown" in formats and results:
        summary = ["# WordPress Maintenance Audit Summary", "", f"Generated: {now.isoformat()}", "",
                   "| Site | Status | Critical | High | Medium | Low | New issues | Report |", "|---|---|---:|---:|---:|---:|---:|---|"]
        for r in results:
            sev = {n: sum(f.severity == n for f in r.findings) for n in ("critical", "high", "medium", "low")}
            new = 0
            try:
                new = len(json.loads((reports_dir / _safe_id(r.site_id) / "latest.json").read_text(encoding="utf-8"))["previous_audit"]["new"])
            except (OSError, ValueError, KeyError):
                pass
            summary.append(f"| {r.site_name} | {r.status} | {sev['critical']} | {sev['high']} | {sev['medium']} | {sev['low']} | {new} | {_safe_id(r.site_id)}/latest.md |")
        text = "\n".join(summary) + "\n"
        (reports_dir / "summaries").mkdir(parents=True, exist_ok=True)
        (reports_dir / "summaries" / f"{stamp}.md").write_text(text, encoding="utf-8")
        (reports_dir / "latest-summary.md").write_text(text, encoding="utf-8")
        written["_summary"] = {"markdown": (reports_dir / "latest-summary.md").resolve()}
    return written
