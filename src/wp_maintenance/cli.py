"""Command line interface."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml
from pydantic import ValidationError

from . import __version__
from .audit import run_audit
from .config import load_config
from .integrations import doctor_global, install_global, uninstall_global
from .locking import audit_lock
from .models import AppConfig, Schedule
from .reporting import _safe_id, site_slug, write_reports, write_site_layout
from .scheduler import install_schedule, remove_schedule, schedule_status
from .batch import apply_fail_policy, emit_github, exit_code as batch_exit_code, run_targets, write_batch
from .inventory import (DEFAULT_INVENTORY, InventoryError, add_site, load_inventory, remove_site, set_enabled,
                        validate_inventory)
from .notifications import NOTIFIERS
from .targets import REPORT_MODES, SCOPES, TargetError, resolve_targets, validate_selection
from .urlmode import (InvalidSiteUrl, build_site, build_url_config, default_config_path, default_reports_dir)

EXIT_OK = 0
EXIT_FINDINGS = 2
EXIT_CONFIGURATION = 3
EXIT_AUTHENTICATION = 4
EXIT_INCOMPLETE = 5
EXIT_INTERNAL = 6
EXIT_CANCELLED = 130


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wp-maintenance", description="Read-only WordPress maintenance audits")
    parser.add_argument("--version", action="version", version=f"wp-maintenance {__version__}")
    subs = parser.add_subparsers(dest="command", required=True)
    init = subs.add_parser("init", help="Create an example configuration")
    init.add_argument("--config", default=None)
    sites = subs.add_parser("site", help="Manage registered websites (add <url>, list, remove <id|url>)")
    sites.add_argument("action", choices=["add", "list", "remove", "enable", "disable", "show", "validate"])
    sites.add_argument("target", nargs="?", help="Website URL (add) or site id/URL (remove)")
    sites.add_argument("--config", default=None, help="Legacy per-user registry (used when no inventory is selected)")
    sites.add_argument("--inventory", default=None, help="Inventory file (default: config/websites.yaml when it exists)")
    sites.add_argument("--tag", action="append", default=None, help="Tag for `site add` (repeatable)")
    sites.add_argument("--offline", action="store_true", help="Skip DNS resolution while validating")
    sites.add_argument("--id")
    sites.add_argument("--name")
    sites.add_argument("--url")
    sites.add_argument("--environment", choices=["production", "staging", "development"], default="production")
    sites.add_argument("--access-mode", choices=["public", "authenticated"], default="public")
    sites.add_argument("--credentials-ref")
    audit = subs.add_parser("audit", help="Run a read-only audit: `audit <url>` needs no configuration")
    audit.add_argument("target", nargs="?", help="Website URL to audit without any configuration")
    audit.add_argument("--url", dest="url", help="Website URL to audit without any configuration")
    audit.add_argument("--all", action="store_true", help="Audit every registered site")
    audit.add_argument("--site", help="Audit one registered site id")
    audit.add_argument("--config", default=None)
    audit.add_argument("--output", "--reports-dir", dest="output", default=None,
                       help="Report directory (default: ~/wp-maintenance-reports or $WP_MAINTENANCE_REPORTS_DIR)")
    audit.add_argument("--max-pages", type=int, default=None, help="Maximum sitemap URLs to check")
    audit.add_argument("--concurrency", type=int, default=None, help="Concurrent page checks (default 5)")
    audit.add_argument("--mode", choices=["read-only"], default="read-only")
    batch = subs.add_parser("audit-batch", help="Audit the inventory (or one site / one URL) with per-site isolation")
    batch.add_argument("--inventory", default=str(DEFAULT_INVENTORY))
    batch.add_argument("--scope", choices=list(SCOPES), default="all")
    batch.add_argument("--site", default=None, help="Site id (scope single)")
    batch.add_argument("--url", default=None, help="One-time URL (scope custom_url); not added to the inventory")
    batch.add_argument("--max-urls", default=None, help="Override the per-site sitemap URL limit for this run")
    batch.add_argument("--report-mode", choices=list(REPORT_MODES), default="standard")
    batch.add_argument("--output", default="reports", help="Directory for reports/YYYY-MM-DD/")
    batch.add_argument("--history-dir", default=os.environ.get("WP_MAINTENANCE_HISTORY_DIR") or None)
    batch.add_argument("--retention-days", type=int, default=365)
    batch.add_argument("--site-concurrency", type=int, default=2, help="Sites audited in parallel")
    batch.add_argument("--site-timeout", type=float, default=1800, help="Wall-clock seconds allowed per site")
    batch.add_argument("--run-id", default=None)
    batch.add_argument("--fail-on", default=None, help="Comma list of: critical, high, incomplete, never")
    batch.add_argument("--notify", choices=["github-issues"], default=None)
    batch.add_argument("--allow-public-issues", action="store_true")
    batch.add_argument("--dry-run", action="store_true", help="Resolve and validate targets, then exit")
    hist = subs.add_parser("history", help="List or show stored audit snapshots (a local clone of the history repository)")
    hist.add_argument("action", choices=["list", "show"])
    hist.add_argument("--history-dir", required=True, help="history directory, e.g. history-repo/history")
    hist.add_argument("--site", default=None)
    hist.add_argument("--run-id", default=None, help="for `show`: a run id (default: latest)")
    report = subs.add_parser("report", help="Display the latest report")
    report.add_argument("--latest", action="store_true")
    report.add_argument("--site")
    report.add_argument("--url")
    report.add_argument("--output", "--reports-dir", dest="output", default=None)
    report.add_argument("--config", default=None)
    doctor = subs.add_parser("doctor", help="Check runtime, configuration, and agent integration")
    doctor.add_argument("--config", default=None)
    install = subs.add_parser("install", help="Install supported agent integrations")
    install.add_argument("--global", dest="global_install", action="store_true")
    uninstall = subs.add_parser("uninstall", help="Remove managed global agent integrations")
    uninstall.add_argument("--global", dest="global_install", action="store_true")
    schedule = subs.add_parser("schedule", help="Manage weekend automation")
    schedule.add_argument("action", choices=["install", "status", "remove"])
    schedule.add_argument("--config", default=None)
    schedule.add_argument("--weekly", action="store_true", help="Weekly schedule (the only supported cadence)")
    schedule.add_argument("--day", choices=["saturday", "sunday"], default=None)
    schedule.add_argument("--time", default=None, help="HH:MM, 24-hour")
    schedule.add_argument("--timezone", default=None, help="IANA timezone (default: machine local time)")
    schedule.add_argument("--method", choices=["auto", "cron", "systemd", "task-scheduler"], default="auto")
    return parser


def _config_path(value: str | None) -> Path:
    return Path(value) if value else default_config_path()


def _cmd_init(config_path: Path) -> int:
    if config_path.exists():
        print(f"Refusing to overwrite existing configuration: {config_path}", file=sys.stderr)
        return EXIT_CONFIGURATION
    config_path.parent.mkdir(parents=True, exist_ok=True)
    sample = {"sites": [], "schedule": {"timezone": "UTC", "day": "sunday", "time": "03:00"},
              "audit": {}, "reports": {"format": ["markdown", "json"], "directory": "./reports"},
              "safety": {"read_only": True, "automatic_updates": False}}
    config_path.write_text(yaml.safe_dump(sample, sort_keys=False), encoding="utf-8")
    print(f"Created {config_path}. Add sites with `wp-maintenance site add <url>`.")
    return EXIT_OK


def _inventory_for_site(args: argparse.Namespace) -> Path | None:
    """Inventory mode when --inventory/WP_MAINTENANCE_INVENTORY is given or config/websites.yaml exists,
    unless the legacy --config registry was chosen explicitly."""
    explicit = getattr(args, "inventory", None) or os.environ.get("WP_MAINTENANCE_INVENTORY")
    if explicit:
        return Path(explicit)
    if getattr(args, "config", None):
        return None
    if DEFAULT_INVENTORY.is_file() or args.action in {"enable", "disable", "show", "validate"}:
        return DEFAULT_INVENTORY
    return None


def _cmd_site_inventory(args: argparse.Namespace, path: Path) -> int:
    try:
        if args.action == "list":
            inv = load_inventory(path)
            for site in inv.sites:
                print(f"{site.id}\t{'enabled' if site.enabled else 'disabled'}\t{site.url}\t{site.name}\t{','.join(site.tags)}")
            if not inv.sites:
                print(f"No sites in {path}.")
            return EXIT_OK
        if args.action == "show":
            site = load_inventory(path).get(args.target or args.id or "")
            print(yaml.safe_dump(site.model_dump(mode="json"), sort_keys=False).rstrip())
            return EXIT_OK
        if args.action == "validate":
            inv, problems = validate_inventory(path, resolve_dns=not args.offline)
            enabled = sum(s.enabled for s in inv.sites)
            for problem in problems:
                print(f"PROBLEM {problem}", file=sys.stderr)
            print(f"{path}: {len(inv.sites)} sites ({enabled} enabled, {len(inv.sites) - enabled} disabled); "
                  f"{'valid' if not problems else str(len(problems)) + ' problem(s)'}")
            return EXIT_OK if not problems else EXIT_CONFIGURATION
        if args.action == "add":
            url = args.url or args.target
            if not url:
                print("site add requires a website URL", file=sys.stderr)
                return EXIT_CONFIGURATION
            entry = add_site(path, url, name=args.name, site_id=args.id, tags=args.tag, resolve_dns=not args.offline)
            print(f"Added '{entry.id}' ({entry.url}) to {path}.")
            return EXIT_OK
        key = args.target or args.id
        if not key:
            print(f"site {args.action} requires a site id", file=sys.stderr)
            return EXIT_CONFIGURATION
        if args.action == "remove":
            removed = remove_site(path, key)
            print(f"Removed '{removed.id}' ({removed.url}) from {path}. Past reports are untouched.")
        else:
            entry, changed = set_enabled(path, key, args.action == "enable")
            print(f"Site '{entry.id}' {'is now' if changed else 'was already'} {args.action}d.")
        return EXIT_OK
    except InventoryError as exc:
        print(f"Inventory error: {exc}", file=sys.stderr)
        return EXIT_CONFIGURATION


def _cmd_site(args: argparse.Namespace) -> int:
    inventory = _inventory_for_site(args)
    if inventory is not None:
        return _cmd_site_inventory(args, inventory)
    if args.action in {"enable", "disable", "show", "validate"}:
        print(f"site {args.action} requires an inventory file (--inventory)", file=sys.stderr)
        return EXIT_CONFIGURATION
    path = _config_path(args.config)
    if args.action == "list":
        try:
            config = load_config(path)
        except FileNotFoundError:
            print(f"No registered websites yet ({path} does not exist). Add one with `wp-maintenance site add <url>`.")
            return EXIT_OK
        except Exception as exc:
            print(f"Configuration error: {exc}", file=sys.stderr)
            return EXIT_CONFIGURATION
        for site in config.sites:
            print(f"{site.id}\t{site.environment}\t{site.access_mode}\t{site.url}\t{'enabled' if site.enabled else 'disabled'}")
        return EXIT_OK
    if args.action == "remove":
        key = args.target or args.id
        if not key or not path.exists():
            print("site remove requires a registered site id or URL", file=sys.stderr)
            return EXIT_CONFIGURATION
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            slug = site_slug(key)
            kept = [s for s in raw.get("sites", []) if s.get("id") not in {key, slug}]
            if len(kept) == len(raw.get("sites", [])):
                print(f"No registered site matches {key}", file=sys.stderr)
                return EXIT_CONFIGURATION
            raw["sites"] = kept
            path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
            print(f"Removed {key} from {path}. Existing reports were left untouched.")
            return EXIT_OK
        except Exception as exc:
            print(f"Could not remove site: {exc}", file=sys.stderr)
            return EXIT_CONFIGURATION
    url = args.url or args.target
    if not url:
        print("site add requires a website URL, e.g. `wp-maintenance site add https://www.example.com`", file=sys.stderr)
        return EXIT_CONFIGURATION
    try:
        if args.access_mode == "authenticated":
            if not (args.id and args.credentials_ref):
                print("authenticated sites require --id and --credentials-ref", file=sys.stderr)
                return EXIT_CONFIGURATION
        site = build_site(url, name=args.name, site_id=args.id)
        if path.exists():
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {"sites": []}
        else:
            raw = {"sites": [], "reports": {"directory": str(default_reports_dir())}}
        raw.setdefault("sites", [])
        for existing in raw["sites"]:
            if existing.get("id") == site.id or str(existing.get("url", "")).rstrip("/") == str(site.url).rstrip("/"):
                print(f"{site.url} is already registered as {existing.get('id')} in {path}.")
                return EXIT_OK
        entry = site.model_dump(mode="json", exclude_defaults=True)
        entry.update(id=site.id, name=site.name, url=str(site.url).rstrip("/"), environment=args.environment,
                     access_mode=args.access_mode, enabled=True)
        if args.credentials_ref:
            entry["credentials_ref"] = args.credentials_ref
        raw["sites"].append(entry)
        validated = AppConfig.model_validate(raw)
        data = validated.model_dump(mode="json", exclude_defaults=True)
        data["reports"] = {**data.get("reports", {}), "directory": raw.get("reports", {}).get("directory", str(default_reports_dir()))}
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        print(f"Registered {site.url} as '{site.id}' in {path}.")
        if args.access_mode == "authenticated":
            print(f"Set {args.credentials_ref}=WORDPRESS_USERNAME:APPLICATION_PASSWORD in the environment; do not put secrets in YAML.")
        return EXIT_OK
    except (InvalidSiteUrl, ValidationError, ValueError) as exc:
        print(f"Could not add site: {exc}", file=sys.stderr)
        return EXIT_CONFIGURATION
    except Exception as exc:
        print(f"Could not add site: {exc}", file=sys.stderr)
        return EXIT_CONFIGURATION


def _exit_code(results: list) -> int:
    if any(any(error.startswith("AUTHENTICATION FAILURE:") for error in item.errors) for item in results):
        return EXIT_AUTHENTICATION
    if any(item.status == "INCOMPLETE" for item in results):
        return EXIT_INCOMPLETE
    if any(item.status == "ACTION_REQUIRED" for item in results):
        return EXIT_FINDINGS
    return EXIT_OK


def _run(config: AppConfig, site_ids: set[str] | None, *, run_dirs: bool) -> int:
    base = Path(config.reports.directory)
    try:
        with audit_lock(base / ".wp-maintenance.lock"):
            results = asyncio.run(run_audit(config, site_ids))
            run_dir = (write_reports(results, base, formats=config.reports.format,
                                     retention_days=config.reports.retention_days) if run_dirs else None)
            layout = write_site_layout(results, base, formats=config.reports.format,
                                       retention_days=config.reports.retention_days)
    except KeyboardInterrupt:
        print("Audit cancelled by user; no report was written for the interrupted audit.", file=sys.stderr)
        return EXIT_CANCELLED
    except RuntimeError as exc:
        print(f"Audit lock: {exc}", file=sys.stderr)
        return EXIT_INCOMPLETE
    except PermissionError as exc:
        print(f"Authentication failure: {exc}", file=sys.stderr)
        return EXIT_AUTHENTICATION
    except Exception as exc:
        print(f"Audit failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_INTERNAL
    for result in results:
        print(f"{result.site_id}: {result.status} ({len(result.findings)} findings, {len(result.errors)} errors)")
        paths = layout.get(result.site_id, {})
        if paths.get("markdown"):
            print(f"  Markdown: {paths['markdown']}")
        if paths.get("json"):
            print(f"  JSON:     {paths['json']}")
        if paths.get("history"):
            print(f"  History:  {paths['history']}")
    if "_summary" in layout:
        print(f"Summary: {layout['_summary']['markdown']}")
    if run_dir is not None:
        print(f"Reports: {run_dir.resolve()}")
    return _exit_code(results)


def _cmd_audit(args: argparse.Namespace) -> int:
    target = getattr(args, "url", None) or getattr(args, "target", None)
    if getattr(args, "url", None) and getattr(args, "target", None) and args.url != args.target:
        print("Provide the URL either positionally or with --url, not two different values", file=sys.stderr)
        return EXIT_CONFIGURATION
    if target:
        if args.all or args.site:
            print("Specify a URL or --all/--site, not both", file=sys.stderr)
            return EXIT_CONFIGURATION
        try:
            config = build_url_config(target, reports_dir=Path(args.output) if getattr(args, "output", None) else None,
                                      max_pages=getattr(args, "max_pages", None),
                                      concurrency=getattr(args, "concurrency", None))
        except (InvalidSiteUrl, ValidationError, ValueError) as exc:
            print(f"Invalid URL: {exc}", file=sys.stderr)
            return EXIT_CONFIGURATION
        site = config.sites[0]
        print(f"Auditing {site.url} (read-only, public evidence only)...")
        return _run(config, {site.id}, run_dirs=False)
    path = _config_path(args.config)
    try:
        config = load_config(path)
    except FileNotFoundError:
        print(f"Configuration error: {path} not found. Audit a URL directly (`wp-maintenance audit <url>`) "
              "or register one with `wp-maintenance site add <url>`.", file=sys.stderr)
        return EXIT_CONFIGURATION
    except (OSError, ValueError, ValidationError) as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIGURATION
    if getattr(args, "output", None):
        config.reports.directory = Path(args.output).resolve()
    if bool(args.all) == bool(args.site):
        print("Specify a URL, or exactly one of --all or --site ID", file=sys.stderr)
        return EXIT_CONFIGURATION
    enabled_ids = {site.id for site in config.sites if site.enabled}
    if args.all and not enabled_ids:
        print("Configuration error: no enabled websites are configured", file=sys.stderr)
        return EXIT_CONFIGURATION
    if args.site and args.site not in enabled_ids:
        print(f"Configuration error: site is missing or disabled: {args.site}", file=sys.stderr)
        return EXIT_CONFIGURATION
    if getattr(args, "max_pages", None) is not None:
        config.audit.max_pages = args.max_pages
    return _run(config, None if args.all else {args.site}, run_dirs=True)


def _cmd_batch(args: argparse.Namespace) -> int:
    try:
        scope, site, url, limit, mode = validate_selection(args.scope, args.site, args.url, args.max_urls, args.report_mode)
        resolution = resolve_targets(inventory_path=Path(args.inventory), urls_text=os.environ.get("WP_MAINTENANCE_URLS"),
                                     scope=scope, site_id=site, custom_url=url, max_urls=limit)
    except TargetError as exc:
        print(f"Target error: {exc}", file=sys.stderr)
        return EXIT_CONFIGURATION
    print(f"Targets from {resolution.source}: " + ", ".join(t.id for t in resolution.targets))
    for note in resolution.notes:
        print(f"Note: {note}")
    if args.dry_run:
        return EXIT_OK
    run_id = args.run_id or os.environ.get("GITHUB_RUN_ID") or datetime.now(timezone.utc).strftime("local%Y%m%d%H%M%S")
    history_dir = Path(args.history_dir) if args.history_dir else None
    try:
        results, cancelled = asyncio.run(run_targets(resolution.targets, site_concurrency=args.site_concurrency,
                                                     site_timeout=args.site_timeout, log=lambda m: print(m, flush=True)))
    except KeyboardInterrupt:
        print("Cancelled before any site completed.", file=sys.stderr)
        return EXIT_CANCELLED
    outcome = write_batch(results, reports_dir=Path(args.output), history_dir=history_dir, run_id=run_id, scope=scope,
                          source=resolution.source, report_mode=mode, notes=list(resolution.notes),
                          retention_days=args.retention_days, cancelled=cancelled,
                          save_history=scope != "custom_url")
    print(f"Overall: {outcome.summary['overall_status']} | audited {outcome.summary['sites_audited']}/{outcome.summary['total_sites']}")
    print(f"Reports: {outcome.run_dir.resolve()}")
    print(f"Summary: {outcome.paths['summary_md'].resolve()}")
    emit_github(outcome)
    if args.notify:
        repo = os.environ.get("GITHUB_REPOSITORY")
        if not repo:
            print("Notification skipped: GITHUB_REPOSITORY is not set.", file=sys.stderr)
        else:
            try:
                server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
                run_url = f"{server}/{repo}/actions/runs/{os.environ['GITHUB_RUN_ID']}" if os.environ.get("GITHUB_RUN_ID") else None
                notifier = NOTIFIERS[args.notify](repo, allow_public=args.allow_public_issues, run_url=run_url)
                for line in notifier.notify(outcome.summary, [r.model_dump(mode="json") for r in results], outcome.deltas):
                    print(line)
            except Exception as exc:  # notification problems never change audit evidence
                print(f"Notification failed: {type(exc).__name__}: {exc}", file=sys.stderr)
    code = batch_exit_code(outcome.summary, cancelled=cancelled)
    if args.fail_on:
        code = apply_fail_policy(code, outcome.summary, {p.strip() for p in args.fail_on.split(",") if p.strip()})
    return code


def _cmd_history(args: argparse.Namespace) -> int:
    from .history_store import list_snapshots
    from .models import AuditResult
    from .reporting import _md
    base = Path(args.history_dir)
    if not base.is_dir():
        print(f"History directory not found: {base}", file=sys.stderr)
        return EXIT_CONFIGURATION
    sites = [args.site] if args.site else sorted(p.name for p in base.iterdir() if p.is_dir())
    if args.action == "list":
        for site in sites:
            for snap in list_snapshots(base, site):
                print(f"{site}\t{snap.saved_at.isoformat()}\trun {snap.run_id}\t{snap.result.get('status')}\t{snap.path.name}")
        return EXIT_OK
    if not args.site:
        print("history show requires --site", file=sys.stderr)
        return EXIT_CONFIGURATION
    snaps = list_snapshots(base, args.site)
    if args.run_id:
        snaps = [x for x in snaps if x.run_id == args.run_id]
    if not snaps:
        print("No matching snapshot found.", file=sys.stderr)
        return EXIT_CONFIGURATION
    snap = snaps[-1]
    print(_md(AuditResult.model_validate(snap.result), {"available": False, "reason": f"stored snapshot from run {snap.run_id}"}))
    return EXIT_OK


def _cmd_report(args: argparse.Namespace) -> int:
    try:
        if getattr(args, "output", None):
            base = Path(args.output)
        else:
            path = _config_path(getattr(args, "config", None))
            base = Path(load_config(path).reports.directory) if path.exists() else default_reports_dir()
    except Exception as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIGURATION
    key = getattr(args, "site", None) or (site_slug(args.url) if getattr(args, "url", None) else None)
    if key:
        latest = base / _safe_id(key) / "latest.md"
        if latest.is_file():
            print(latest.read_text(encoding="utf-8"))
            return EXIT_OK
    candidates = sorted((item for item in base.rglob("*.md")
                         if (item.parent / ".wp-maintenance-agent-report").is_file()),
                        key=lambda item: item.stat().st_mtime, reverse=True)
    if key:
        candidates = [p for p in candidates if p.name == f"{key}.md"]
    if not candidates:
        json_candidates = sorted((item for item in base.rglob("results.json")
                                  if (item.parent / ".wp-maintenance-agent-report").is_file()),
                                 key=lambda item: item.stat().st_mtime, reverse=True)
        for json_file in json_candidates:
            try:
                payload = json.loads(json_file.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not key:
                print(json.dumps(payload, indent=2, ensure_ascii=False))
                return EXIT_OK
            match = next((item for item in payload.get("sites", []) if item.get("site_id") == key), None)
            if match is not None:
                print(json.dumps(match, indent=2, ensure_ascii=False))
                return EXIT_OK
        print("No matching report found.", file=sys.stderr)
        return EXIT_CONFIGURATION
    print(candidates[0].read_text(encoding="utf-8"))
    return EXIT_OK


def _cmd_doctor(config_path: Path) -> int:
    print(f"Python: {sys.version.split()[0]} (requires >=3.12)")
    print(f"Executable: {sys.executable}")
    print(f"wp-maintenance CLI: {shutil.which('wp-maintenance') or 'current Python invocation'}")
    print(f"GitHub CLI: {shutil.which('gh') or 'not found'}")
    for line in doctor_global():
        print(line)
    print(f"Default reports directory: {default_reports_dir()}")
    if config_path.exists():
        try:
            config = load_config(config_path)
            print(f"Configuration: valid ({len(config.sites)} sites) at {config_path}")
        except Exception as exc:
            print(f"Configuration: invalid — {exc}")
            return EXIT_CONFIGURATION
    else:
        print(f"Configuration: not found ({config_path}); not required for `wp-maintenance audit <url>`")
    return EXIT_OK


def _cmd_schedule(args: argparse.Namespace) -> int:
    path = _config_path(args.config)
    if args.action == "status":
        print(schedule_status(config=path, method=args.method))
        return EXIT_OK
    if args.action == "remove":
        print(remove_schedule(config=path, method=args.method))
        return EXIT_OK
    config = load_config(path)
    if not any(site.enabled for site in config.sites):
        print("No registered websites. Add one first: wp-maintenance site add <url>", file=sys.stderr)
        return EXIT_CONFIGURATION
    explicit_zone = args.timezone or (config.schedule.timezone if config.schedule.timezone != "UTC" else None)
    schedule = Schedule(timezone=explicit_zone or "UTC", day=args.day or config.schedule.day,
                        time=args.time or config.schedule.time)
    print(install_schedule(schedule, config=path, method=args.method, local_time=explicit_zone is None))
    return EXIT_OK


def main() -> None:
    args = _parser().parse_args()
    try:
        if args.command == "init":
            code = _cmd_init(_config_path(args.config))
        elif args.command == "site":
            code = _cmd_site(args)
        elif args.command == "audit":
            code = _cmd_audit(args)
        elif args.command == "history":
            code = _cmd_history(args)
        elif args.command == "audit-batch":
            code = _cmd_batch(args)
        elif args.command == "report":
            code = _cmd_report(args)
        elif args.command == "doctor":
            code = _cmd_doctor(_config_path(args.config))
        elif args.command == "install":
            if not args.global_install:
                print("Specify --global", file=sys.stderr)
                code = EXIT_CONFIGURATION
            else:
                for line in install_global(): print(line)
                code = EXIT_OK
        elif args.command == "uninstall":
            if not args.global_install:
                print("Specify --global", file=sys.stderr)
                code = EXIT_CONFIGURATION
            else:
                for line in uninstall_global(): print(line)
                code = EXIT_OK
        elif args.command == "schedule":
            code = _cmd_schedule(args)
        else:
            code = EXIT_CONFIGURATION
    except KeyboardInterrupt:
        print("Cancelled.", file=sys.stderr)
        code = EXIT_CANCELLED
    except Exception as exc:
        print(f"Error: {type(exc).__name__}: {exc}", file=sys.stderr)
        code = EXIT_INTERNAL
    raise SystemExit(code)


if __name__ == "__main__":
    main()
