"""Evidence-focused Markdown and JSON reports."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .history import compare_results, previous_result
from .models import AuditResult
from .security import redact_secrets


def _safe_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]+", "-", value).strip("-") or "site"


def _md(result: AuditResult, delta: dict[str, list[str]]) -> str:
    duration = 0.0
    if result.finished_at:
        duration = (result.finished_at - result.started_at).total_seconds()
    severities = {name: sum(f.severity == name for f in result.findings) for name in ("critical", "high", "medium", "low")}
    lines = ["# WordPress Maintenance Audit Report", "", "## 1. Website Information", "",
        f"- Website name: {result.site_name}", f"- Website URL: {result.url}",
        f"- Environment: {result.environment}", f"- Audit date: {result.started_at.isoformat()}",
        f"- Audit duration: {duration:.2f} seconds", f"- Access mode: {result.access_mode}",
        f"- Audit coverage: {', '.join(result.coverage) or 'none'}", "", "## 2. Executive Summary", "",
        f"- Overall status: **{result.status}**", f"- Critical issues: {severities['critical']}",
        f"- High-priority issues: {severities['high']}", f"- Medium-priority issues: {severities['medium']}",
        f"- Low-priority issues: {severities['low']}", f"- Unknown/unverified findings: {len(result.limitations)}", "",
        "## 3. WordPress Core", "", f"- Installed version: {result.wordpress.get('installed_version') or 'UNKNOWN'}",
        f"- Latest official version: {result.wordpress.get('latest_official') or 'UNKNOWN'}",
        f"- Update available: {result.wordpress.get('update_available') if result.wordpress else 'UNKNOWN'}",
        f"- Security relevance: {result.wordpress.get('security_relevance') if result.wordpress else 'UNKNOWN'}",
        f"- Evidence: {result.wordpress.get('evidence', 'not checked')}", "",
        "## 4. PHP Runtime", "", f"- Installed version: {result.php.get('installed_version') or result.php.get('support_status', 'UNKNOWN')}",
        f"- Support status: {result.php.get('support_status', 'UNKNOWN')}",
        f"- Source: {result.php.get('source', 'not checked')}",
        "- Upgrade readiness: not evaluated; compatibility must be validated in staging.", "", "## 5. Plugin Inventory", "",
        "| Plugin | Installed | Latest | Status | Priority | Action |", "|---|---:|---:|---|---|---|"]
    if result.plugins:
        for plugin in result.plugins:
            status = plugin.get("status", "UNKNOWN")
            priority = "P1" if status == "VULNERABLE" else "P2" if status == "OUTDATED" else "P3"
            action = "Review update" if status == "OUTDATED" else "Verify source/inventory" if status == "UNKNOWN" else "No action"
            name = plugin.get("name") or plugin.get("slug") or "Unidentified plugin"
            installed = plugin.get("installed_version") or plugin.get("version") or "UNKNOWN"
            if plugin.get("asset_version_hint"):
                installed = f"UNKNOWN (asset hint: {plugin['asset_version_hint']})"
            safe_name = str(name).replace("|", "\\|").replace("\r", " ").replace("\n", " ")
            lines.append(f"| {safe_name} | {installed} | {plugin.get('latest_version') or plugin.get('update_version') or 'UNKNOWN'} | {status} | {priority} | {action} |")
    else:
        lines.append("| Inventory unavailable | UNKNOWN | UNKNOWN | NOT_VERIFIABLE_WITH_PUBLIC_ACCESS | — | Enable authenticated access for a complete inventory |")
    lines.extend(["", "## 6. Security Findings", ""])
    security = [f for f in result.findings if f.component == "security"]
    lines.extend([f"- **{f.severity.upper()} {f.title}:** {f.detail}" for f in security] or ["No verified vulnerability advisory findings were returned."])
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
    lines.extend(["", "## 7. Sitemap Audit", "", f"- Sitemaps discovered: {len(result.sitemaps.get('discovered', []))}",
        f"- URLs discovered: {result.sitemaps.get('urls_discovered', 0)}", f"- URLs checked: {len(result.pages)}",
        f"- Duplicate URLs: {len(result.sitemaps.get('duplicates', []))}",
        f"- Invalid sitemap entries: {len(result.sitemaps.get('invalid', []))}", "",
        "## 8. Page Health", "", f"- Successful URLs: {sum(p.get('classification') == 'available' for p in result.pages)}",
        f"- Redirects: {sum(p.get('classification') == 'redirect' for p in result.pages)}",
        f"- Client errors: {sum(p.get('classification') in {'missing', 'client_error', 'access_restricted'} for p in result.pages)}",
        f"- Server errors: {sum(p.get('classification') == 'server_error' for p in result.pages)}",
        f"- Network/policy failures: {sum(p.get('classification') in {'network_failure', 'network_or_policy_error', 'timeout', 'tls_error'} for p in result.pages)}", "",
        "## 9. Broken URLs", ""])
    issues = [p for p in result.pages if p.get("classification") in {"missing", "server_error", "client_error", "network_failure", "network_or_policy_error", "timeout", "redirect_loop", "redirect_limit", "tls_error", "rate_limited", "access_restricted"}]
    lines.extend([f"- `{p.get('url')}` — HTTP {p.get('status') or 'unavailable'} ({p.get('classification')}); investigate the route or host response." for p in issues] or ["No broken URL findings."])
    lines.extend(["", "## 10. Required Maintenance Actions", ""])
    for finding in result.findings:
        lines.append(f"- [ ] {finding.recommendation or finding.title}")
    if not result.findings:
        lines.append("No remediation actions were supported by the collected evidence.")
    lines.extend(["", "## 11. Prioritized Remediation Plan", ""])
    for idx, finding in enumerate(sorted(result.findings, key=lambda x: (0 if x.severity == 'critical' else 1 if x.severity == 'high' else 2)), 1):
        lines.extend([f"### {finding.id or f'ACT-{idx}'} — {finding.title}", "", f"- Severity: {finding.severity.upper()}",
            f"- Affected component: {finding.component}", f"- Current state: {finding.detail}",
            f"- Required change: {finding.recommendation}", "- Dependencies: validate compatibility and ownership.",
            "- Backup requirement: verify a restorable backup before production changes.",
            "- Testing requirement: validate on staging and re-run the affected checks.",
            "- Rollback consideration: document a tested rollback before deployment.",
            f"- Evidence: {', '.join(finding.evidence) or 'none recorded'}", ""])
    lines.extend(["## 12. Previous Audit Comparison", "", f"- Newly detected issues: {', '.join(delta['new']) or 'none'}",
        f"- Resolved issues: {', '.join(delta['resolved']) or 'none'}", f"- Persistent issues: {', '.join(delta['persistent']) or 'none'}",
        "", "## 13. Evidence and Limitations", "", "Findings are based only on listed response evidence and official metadata sources. HTTP availability does not verify browser functionality."])
    lines.extend([f"- {item}" for item in result.limitations] or ["- No known limitations were recorded."])
    lines.extend([f"- Audit errors: {redact_secrets(error)}" for error in result.errors])
    lines.extend(["", "## 14. Final Status", "", f"**{result.status}**", ""])
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
