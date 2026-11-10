"""Multi-site batch execution, per-site isolation, aggregate reports and CI summaries."""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .audit import audit_site
from .delta import compute_delta
from .history_store import load_previous, prune, save_snapshot
from .models import AppConfig, AuditOptions, AuditResult
from .reporting import BROKEN, SEVERITY_ORDER, _cell, _md, _safe_id
from .security import redact_secrets
from .targets import Target
from .urlmode import build_site

EXIT_OK, EXIT_FINDINGS, EXIT_INCOMPLETE, EXIT_CRITICAL, EXIT_CANCELLED = 0, 2, 5, 7, 130
RANK = {"CRITICAL": 4, "INCOMPLETE": 3, "ACTION_REQUIRED": 2, "PASS_WITH_WARNINGS": 1, "PASS": 0}


@dataclass
class BatchOutcome:
    results: list[AuditResult]
    summary: dict[str, Any]
    run_dir: Path
    deltas: dict[str, dict]
    cancelled: bool = False
    paths: dict[str, Path] = field(default_factory=dict)


def _failed(target: Target, message: str) -> AuditResult:
    return AuditResult(site_id=target.id, site_name=target.name, url=target.url, environment="production",
                       access_mode="public", status="INCOMPLETE", finished_at=datetime.now(timezone.utc),
                       errors=[redact_secrets(message)])


def _config_for(target: Target, site_timeout: float) -> tuple[Any, AppConfig]:
    site = build_site(target.url, name=target.name, site_id=target.id)
    site = site.model_copy(update={"exclude_paths": list(target.exclude_paths)})
    audit = {"max_pages": target.max_urls, "concurrency": target.concurrency, "timeout_seconds": target.timeout_seconds,
             "respect_robots_txt": target.respect_robots_txt, "max_crawl_seconds": max(10.0, site_timeout * 0.75),
             "security_advisories": True, **target.audit}
    config = AppConfig(sites=[site], audit=AuditOptions.model_validate(audit))
    return site, config


async def run_targets(targets: list[Target], *, site_concurrency: int = 2, site_timeout: float = 1800,
                      log=print) -> tuple[list[AuditResult], bool]:
    """Audit every target with bounded parallelism. A failing or timed-out site never affects the others."""
    semaphore = asyncio.Semaphore(max(1, site_concurrency))
    done: dict[str, AuditResult] = {}

    async def one(target: Target) -> None:
        async with semaphore:
            log(f"[{target.id}] starting audit of {target.url}")
            try:
                site, config = _config_for(target, site_timeout)
                done[target.id] = await asyncio.wait_for(audit_site(site, config), timeout=site_timeout)
            except asyncio.TimeoutError:
                done[target.id] = _failed(target, f"Site audit exceeded the {site_timeout:.0f}s limit and was stopped.")
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # isolation: report, continue with the other sites
                done[target.id] = _failed(target, f"Site audit failed: {type(exc).__name__}: {exc}")
            log(f"[{target.id}] finished: {done[target.id].status}")

    cancelled = False
    tasks = [asyncio.ensure_future(one(t)) for t in targets]
    try:
        await asyncio.gather(*tasks)
    except (asyncio.CancelledError, KeyboardInterrupt):
        cancelled = True
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    results = []
    for target in targets:
        results.append(done.get(target.id) or _failed(target, "Audit cancelled before this site completed."))
    return results, cancelled


# ------------------------------------------------------------------ summary


def _site_metrics(result: AuditResult, delta: dict) -> dict[str, Any]:
    sev = {name: sum(f.severity == name for f in result.findings) for name in SEVERITY_ORDER}
    pages = result.pages
    ssl = result.ssl or {}
    wp = result.wordpress or {}
    ssl_cell = "UNKNOWN"
    if ssl:
        ssl_cell = (f"{ssl.get('status', 'UNKNOWN')} ({ssl['days_remaining']}d)" if ssl.get("days_remaining") is not None
                    else str(ssl.get("error_kind") or ssl.get("status", "UNKNOWN")))
        if not ssl.get("trusted"):
            ssl_cell += " NOT TRUSTED"
    version = wp.get("installed_version")
    wp_cell = f"{wp.get('detection', 'NOT_CHECKED')}" + (f" {version}" if version else " (version unknown)")
    plugins = result.plugins
    outdated = sum(1 for p in plugins if p.get("classification") == "VERIFIED_OUTDATED")
    vulnerable = sum(1 for p in plugins if p.get("status") == "VULNERABLE")
    return {"id": result.site_id, "name": result.site_name, "url": result.url, "status": result.status,
            "findings": sev, "ssl": ssl_cell, "ssl_status": ssl.get("status"), "ssl_days_remaining": ssl.get("days_remaining"),
            "wordpress": wp_cell, "wordpress_detection": wp.get("detection"), "wordpress_version": version,
            "plugins_detected": len(plugins), "plugins_verified_outdated": outdated, "plugins_vulnerable": vulnerable,
            "pages_checked": len(pages), "broken_urls": sum(p.get("classification") in BROKEN for p in pages),
            "server_errors": sum(p.get("classification") == "server_error" for p in pages),
            "coverage": result.crawl or {}, "errors": [redact_secrets(e) for e in result.errors][:10],
            "php": (result.php or {}).get("installed_version") or "UNKNOWN",
            "delta": {"available": delta.get("available", False), "reason": delta.get("reason"),
                      "new": len(delta.get("new", [])), "resolved": len(delta.get("resolved", [])),
                      "persistent": len(delta.get("persistent", [])), "unverified": len(delta.get("unverified", []))}}


def build_summary(results: list[AuditResult], deltas: dict[str, dict], *, run_id: str, scope: str, source: str,
                  generated_at: datetime, report_mode: str, history: dict[str, Any], notes: list[str]) -> dict[str, Any]:
    sites = [_site_metrics(r, deltas.get(r.site_id, {})) for r in results]
    critical = [s["id"] for s in sites if s["findings"]["critical"]]
    high = [s["id"] for s in sites if s["findings"]["high"]]
    incomplete = [s["id"] for s in sites if s["status"] == "INCOMPLETE"]
    if critical:
        overall = "CRITICAL"
    else:
        overall = max((s["status"] for s in sites), key=lambda x: RANK.get(x, 0), default="PASS")
    ssl_warn = [{"site": s["id"], "status": s["ssl_status"], "days": s["ssl_days_remaining"]}
                for s in sites if s["ssl_status"] in {"WARNING", "HIGH", "CRITICAL"}]
    return {"schema_version": 2, "report_version": __version__, "run_id": run_id, "generated_at": generated_at.isoformat(),
            "scope": scope, "source": source, "report_mode": report_mode, "overall_status": overall,
            "total_sites": len(sites), "sites_audited": len(sites) - len(incomplete),
            "sites_with_critical": critical, "sites_with_high": high, "sites_incomplete": incomplete,
            "total_broken_urls": sum(s["broken_urls"] for s in sites), "total_server_errors": sum(s["server_errors"] for s in sites),
            "ssl_expiring": ssl_warn, "new_issues": sum(s["delta"]["new"] for s in sites),
            "resolved_issues": sum(s["delta"]["resolved"] for s in sites), "history": history, "notes": notes, "sites": sites}


def render_summary_md(summary: dict[str, Any]) -> str:
    lines = ["# WordPress Maintenance Weekly Summary", "", f"- Generated: {summary['generated_at']}",
        f"- Run: {summary['run_id']} (scope: {summary['scope']}; targets from: {summary['source']})",
        f"- Overall status: **{summary['overall_status']}**", f"- Total sites: {summary['total_sites']}",
        f"- Sites audited (completed): {summary['sites_audited']}",
        f"- Sites with critical findings: {len(summary['sites_with_critical'])}",
        f"- Sites with high-priority findings: {len(summary['sites_with_high'])}",
        f"- Sites with incomplete audits: {len(summary['sites_incomplete'])}",
        f"- Total broken URLs: {summary['total_broken_urls']}", f"- Total server errors (5xx): {summary['total_server_errors']}",
        f"- SSL certificates approaching expiration: {len(summary['ssl_expiring'])}",
        f"- New issues this run: {summary['new_issues']}", f"- Resolved issues this run: {summary['resolved_issues']}",
        f"- Historical comparison: {summary['history'].get('comparison', 'unavailable')}", "",
        "| Website | SSL | WordPress | Plugins | Broken URLs | Status |", "|---|---|---|---|---|---|"]
    for s in summary["sites"]:
        plugins = f"{s['plugins_detected']} detected" + (f", {s['plugins_verified_outdated']} outdated" if s["plugins_verified_outdated"] else "")
        lines.append(f"| {_cell(s['name'])} | {_cell(s['ssl'])} | {_cell(s['wordpress'])} | {_cell(plugins)} | "
                     f"{s['broken_urls']} | **{s['status']}** |")
    if summary["ssl_expiring"]:
        lines += ["", "## SSL certificates approaching expiration", ""]
        lines += [f"- {e['site']}: {e['status']} ({e['days']} days)" for e in summary["ssl_expiring"]]
    failed = [s for s in summary["sites"] if s["status"] == "INCOMPLETE"]
    if failed:
        lines += ["", "## Incomplete or failed audits", ""]
        for s in failed:
            lines.append(f"- **{_cell(s['name'])}**: " + ("; ".join(_cell(e) for e in s["errors"]) or "required checks did not complete"))
    for note in summary["notes"]:
        lines += ["", f"> {_cell(note)}"]
    lines.append("")
    return "\n".join(lines)


def render_delta_md(summary: dict[str, Any], results: list[AuditResult], deltas: dict[str, dict]) -> str:
    lines = ["# Weekly Delta", "", f"Run {summary['run_id']} at {summary['generated_at']}.", ""]
    for result in results:
        delta = deltas.get(result.site_id, {})
        lines += [f"## {_cell(result.site_name)} ({result.site_id})", ""]
        if not delta.get("available"):
            lines += [f"Historical comparison UNAVAILABLE: {delta.get('reason', 'no previous evidence')}", ""]
            continue
        prev = delta.get("previous") or {}
        lines.append(f"Compared with run {prev.get('run_id', '?')} ({prev.get('audit_date', '?')}, {prev.get('status', '?')}).")
        details = delta.get("details", {})

        def listing(title: str, ids: list[str]) -> None:
            lines.extend(["", f"### {title} ({len(ids)})", ""])
            lines.extend([f"- `{i}` [{(details.get(i) or {}).get('severity', '?')}] {_cell((details.get(i) or {}).get('title', ''))}" for i in ids[:100]]
                         or ["- none"])
        listing("New findings", delta["new"])
        listing("Resolved findings (verified)", delta["resolved"])
        listing("Persistent findings", delta["persistent"])
        lines += ["", f"### Unverified changes ({len(delta['unverified'])})", ""]
        lines += [f"- `{u['id']}`: {_cell(u['reason'])}" for u in delta["unverified"][:100]] or ["- none"]
        lines += ["", f"### Detected changes ({len(delta['changes'])})", ""]
        lines += [f"- ({c['type']}) {_cell(c['detail'])}" for c in delta["changes"][:100]] or ["- none"]
        lines.append("")
    return "\n".join(lines)


def _escape_command(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A").replace(":", "%3A").replace(",", "%2C")


def annotations(summary: dict[str, Any]) -> list[str]:
    """GitHub workflow commands. Every dynamic value is escaped to prevent command injection."""
    out = []
    for s in summary["sites"]:
        label = _escape_command(s["id"])
        if s["findings"]["critical"]:
            out.append(f"::error title=Critical finding::{label}: {s['findings']['critical']} critical finding(s)")
        if s["status"] == "INCOMPLETE":
            out.append(f"::warning title=Audit incomplete::{label}: audit did not complete")
        if s["ssl_status"] in {"WARNING", "HIGH", "CRITICAL"}:
            out.append(f"::warning title=SSL expiring::{label}: certificate expires in {s['ssl_days_remaining']} days")
    return out


def render_github_summary(summary: dict[str, Any], *, run_url: str | None = None) -> str:
    lines = ["# Weekly WordPress Maintenance", "",
        f"- **Run date:** {summary['generated_at'][:10]}", f"- **Sites audited:** {summary['sites_audited']} of {summary['total_sites']}",
        f"- **Overall status:** **{summary['overall_status']}**", f"- **Critical findings (sites):** {len(summary['sites_with_critical'])}",
        f"- **High-priority findings (sites):** {len(summary['sites_with_high'])}", f"- **SSL warnings:** {len(summary['ssl_expiring'])}",
        f"- **Broken pages:** {summary['total_broken_urls']} (server errors: {summary['total_server_errors']})",
        f"- **Failed or incomplete audits:** {len(summary['sites_incomplete'])}",
        f"- **New / resolved issues:** {summary['new_issues']} / {summary['resolved_issues']}",
        f"- **Historical comparison:** {summary['history'].get('comparison', 'unavailable')}", "",
        "| Website | SSL | WordPress | Plugins | Broken URLs | Status |", "|---|---|---|---|---|---|"]
    for s in summary["sites"]:
        lines.append(f"| {_cell(s['name'])} | {_cell(s['ssl'])} | {_cell(s['wordpress'])} | {s['plugins_detected']} | {s['broken_urls']} | {s['status']} |")
    for note in summary["notes"]:
        lines += ["", f"> {_cell(note)}"]
    if run_url:
        lines += ["", f"Reports are attached to the [workflow run]({run_url}) as artifacts (when enabled for this repository)."]
    lines.append("")
    return "\n".join(lines)


def exit_code(summary: dict[str, Any], *, cancelled: bool = False) -> int:
    if cancelled:
        return EXIT_CANCELLED
    if summary["sites_with_critical"]:
        return EXIT_CRITICAL
    if summary["sites_incomplete"]:
        return EXIT_INCOMPLETE
    if summary["overall_status"] == "ACTION_REQUIRED":
        return EXIT_FINDINGS
    return EXIT_OK


def apply_fail_policy(code: int, summary: dict[str, Any], fail_on: set[str]) -> int:
    """With --fail-on, only the listed conditions produce a non-zero exit code."""
    if "never" in fail_on:
        return 0 if code != EXIT_CANCELLED else code
    if code == EXIT_CANCELLED:
        return code
    triggered = (("critical" in fail_on and summary["sites_with_critical"]) or
                 ("high" in fail_on and (summary["sites_with_high"] or summary["sites_with_critical"])) or
                 ("incomplete" in fail_on and summary["sites_incomplete"]))
    return code if triggered else 0


# ------------------------------------------------------------------ orchestration


def _run_dir(reports_dir: Path, run_id: str, now: datetime) -> Path:
    base = reports_dir / now.strftime("%Y-%m-%d")
    if (base / "summary.json").exists():
        base = reports_dir / f"{now.strftime('%Y-%m-%d')}-{_safe_id(run_id)}"
        counter = 1
        while (base / "summary.json").exists():
            counter += 1
            base = reports_dir / f"{now.strftime('%Y-%m-%d')}-{_safe_id(run_id)}-{counter}"
    return base


def write_batch(results: list[AuditResult], *, reports_dir: Path, history_dir: Path | None, run_id: str, scope: str,
                source: str, report_mode: str, notes: list[str], retention_days: int = 365,
                save_history: bool = True, now: datetime | None = None, cancelled: bool = False) -> BatchOutcome:
    now = now or datetime.now(timezone.utc)
    run_dir = _run_dir(reports_dir, run_id, now)
    (run_dir / "sites").mkdir(parents=True, exist_ok=True)
    deltas: dict[str, dict] = {}
    loaded = 0
    for result in results:
        payload = result.model_dump(mode="json")
        if history_dir is not None:
            snap, reason = load_previous(history_dir, result.site_id, exclude_run_id=run_id)
        else:
            snap, reason = None, "no history storage is configured for this run"
        if snap is not None:
            loaded += 1
            meta = {"run_id": snap.run_id, "audit_date": snap.saved_at.isoformat(), "status": snap.result.get("status")}
            deltas[result.site_id] = compute_delta(payload, snap.result, previous_meta=meta)
        else:
            deltas[result.site_id] = compute_delta(payload, None, unavailable_reason=reason)
    if history_dir is None:
        comparison = "unavailable (no history storage configured)"
    elif loaded == 0:
        comparison = "unavailable (no previous evidence found; this run becomes the baseline)"
    else:
        comparison = f"loaded previous evidence for {loaded} of {len(results)} sites"
    history = {"enabled": history_dir is not None, "comparison": comparison, "sites_with_previous": loaded}
    summary = build_summary(results, deltas, run_id=run_id, scope=scope, source=source, generated_at=now,
                            report_mode=report_mode, history=history, notes=notes)
    for result in results:
        site_dir = run_dir / "sites" / _safe_id(result.site_id)
        site_dir.mkdir(parents=True, exist_ok=True)
        payload = result.model_dump(mode="json")
        payload["previous_audit"] = deltas[result.site_id]
        (site_dir / "report.md").write_text(_md(result, deltas[result.site_id], detailed=report_mode == "detailed"), encoding="utf-8")
        (site_dir / "report.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    paths = {"summary_md": run_dir / "summary.md", "summary_json": run_dir / "summary.json", "delta_md": run_dir / "weekly-delta.md"}
    paths["summary_md"].write_text(render_summary_md(summary), encoding="utf-8")
    paths["summary_json"].write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    paths["delta_md"].write_text(render_delta_md(summary, results, deltas), encoding="utf-8")
    if history_dir is not None and save_history and not cancelled:
        for result in results:
            if result.status == "INCOMPLETE" and not result.coverage:
                continue  # nothing observed; keep the last valid baseline instead
            save_snapshot(history_dir, result.model_dump(mode="json"), run_id=run_id, now=now)
        prune(history_dir, retention_days=retention_days, now=now)
    return BatchOutcome(results, summary, run_dir, deltas, cancelled, paths)


def emit_github(outcome: BatchOutcome, *, env: dict[str, str] | None = None) -> None:
    """Append the job summary and step outputs when running on GitHub Actions."""
    env = env if env is not None else dict(os.environ)
    server, repo, run_id = env.get("GITHUB_SERVER_URL"), env.get("GITHUB_REPOSITORY"), env.get("GITHUB_RUN_ID")
    run_url = f"{server}/{repo}/actions/runs/{run_id}" if server and repo and run_id else None
    if env.get("GITHUB_STEP_SUMMARY"):
        with open(env["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as handle:
            handle.write(render_github_summary(outcome.summary, run_url=run_url))
    if env.get("GITHUB_OUTPUT"):
        s = outcome.summary
        with open(env["GITHUB_OUTPUT"], "a", encoding="utf-8") as handle:
            handle.write(f"overall_status={s['overall_status']}\nsites_audited={s['sites_audited']}\n"
                         f"critical_sites={len(s['sites_with_critical'])}\nincomplete_sites={len(s['sites_incomplete'])}\n"
                         f"report_dir={outcome.run_dir}\n")
    for line in annotations(outcome.summary):
        print(line)
