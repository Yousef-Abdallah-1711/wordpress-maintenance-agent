"""Command line interface."""

from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import sys
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
from .urlmode import (InvalidSiteUrl, build_site, build_url_config, default_config_path, default_reports_dir,
                      normalize_site_url)

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
    sites.add_argument("action", choices=["add", "list", "remove"])
    sites.add_argument("target", nargs="?", help="Website URL (add) or site id/URL (remove)")
    sites.add_argument("--config", default=None)
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


def _cmd_site(args: argparse.Namespace) -> int:
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
