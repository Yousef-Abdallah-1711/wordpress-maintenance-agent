"""Command line interface."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
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
from .models import AppConfig
from .reporting import write_reports
from .scheduler import install_schedule, schedule_status

EXIT_OK = 0
EXIT_FINDINGS = 2
EXIT_CONFIGURATION = 3
EXIT_AUTHENTICATION = 4
EXIT_INCOMPLETE = 5
EXIT_INTERNAL = 6


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wp-maintenance", description="Read-only WordPress maintenance audits")
    parser.add_argument("--version", action="version", version=f"wp-maintenance {__version__}")
    subs = parser.add_subparsers(dest="command", required=True)
    init = subs.add_parser("init", help="Create an example configuration")
    init.add_argument("--config", default="wp-maintenance.yaml")
    sites = subs.add_parser("site", help="Manage configured websites")
    sites.add_argument("action", choices=["add", "list"])
    sites.add_argument("--config", default="wp-maintenance.yaml")
    sites.add_argument("--id")
    sites.add_argument("--name")
    sites.add_argument("--url")
    sites.add_argument("--environment", choices=["production", "staging", "development"], default="production")
    sites.add_argument("--access-mode", choices=["public", "authenticated"], default="public")
    sites.add_argument("--credentials-ref")
    audit = subs.add_parser("audit", help="Run a read-only audit")
    audit.add_argument("--all", action="store_true")
    audit.add_argument("--site")
    audit.add_argument("--config", default="wp-maintenance.yaml")
    audit.add_argument("--mode", choices=["read-only"], default="read-only")
    report = subs.add_parser("report", help="Display the latest report")
    report.add_argument("--latest", action="store_true")
    report.add_argument("--site")
    report.add_argument("--config", default="wp-maintenance.yaml")
    doctor = subs.add_parser("doctor", help="Check runtime, configuration, and agent integration")
    doctor.add_argument("--config", default="wp-maintenance.yaml")
    install = subs.add_parser("install", help="Install supported agent integrations")
    install.add_argument("--global", dest="global_install", action="store_true")
    uninstall = subs.add_parser("uninstall", help="Remove managed global agent integrations")
    uninstall.add_argument("--global", dest="global_install", action="store_true")
    schedule = subs.add_parser("schedule", help="Manage weekend automation")
    schedule.add_argument("action", choices=["install", "status"])
    schedule.add_argument("--config", default="wp-maintenance.yaml")
    schedule.add_argument("--method", choices=["auto", "cron", "systemd", "task-scheduler"], default="auto")
    return parser


def _cmd_init(config_path: Path) -> int:
    if config_path.exists():
        print(f"Refusing to overwrite existing configuration: {config_path}", file=sys.stderr)
        return EXIT_CONFIGURATION
    config_path.parent.mkdir(parents=True, exist_ok=True)
    sample = {"sites": [], "schedule": {"timezone": "UTC", "day": "sunday", "time": "03:00"},
              "audit": {}, "reports": {"format": ["markdown", "json"], "directory": "./reports"},
              "safety": {"read_only": True, "automatic_updates": False}}
    config_path.write_text(yaml.safe_dump(sample, sort_keys=False), encoding="utf-8")
    print(f"Created {config_path}. Add sites with `wp-maintenance site add`.")
    return EXIT_OK


def _cmd_site(args: argparse.Namespace) -> int:
    path = Path(args.config)
    if args.action == "list":
        try:
            config = load_config(path)
        except Exception as exc:
            print(f"Configuration error: {exc}", file=sys.stderr)
            return EXIT_CONFIGURATION
        for site in config.sites:
            print(f"{site.id}\t{site.environment}\t{site.access_mode}\t{site.url}\t{'enabled' if site.enabled else 'disabled'}")
        return EXIT_OK
    if not (args.id and args.name and args.url):
        print("site add requires --id, --name, and --url", file=sys.stderr)
        return EXIT_CONFIGURATION
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else {"sites": []}
        raw.setdefault("sites", []).append({"id": args.id, "name": args.name, "url": args.url,
            "environment": args.environment, "access_mode": args.access_mode, "enabled": True,
            **({"credentials_ref": args.credentials_ref} if args.credentials_ref else {})})
        validated = AppConfig.model_validate(raw)
        data = validated.model_dump(mode="json", exclude_defaults=True)
        path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        print(f"Added site {args.id} to {path}.")
        if args.access_mode == "authenticated":
            print(f"Set {args.credentials_ref}=WORDPRESS_USERNAME:APPLICATION_PASSWORD in the environment; do not put secrets in YAML.")
        return EXIT_OK
    except Exception as exc:
        print(f"Could not add site: {exc}", file=sys.stderr)
        return EXIT_CONFIGURATION


def _cmd_audit(args: argparse.Namespace) -> int:
    path = Path(args.config)
    try:
        config = load_config(path)
    except (OSError, ValueError, ValidationError) as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIGURATION
    if bool(args.all) == bool(args.site):
        print("Specify exactly one of --all or --site ID", file=sys.stderr)
        return EXIT_CONFIGURATION
    enabled_ids = {site.id for site in config.sites if site.enabled}
    if args.all and not enabled_ids:
        print("Configuration error: no enabled websites are configured", file=sys.stderr)
        return EXIT_CONFIGURATION
    if args.site and args.site not in enabled_ids:
        print(f"Configuration error: site is missing or disabled: {args.site}", file=sys.stderr)
        return EXIT_CONFIGURATION
    try:
        with audit_lock(Path(config.reports.directory) / ".wp-maintenance.lock"):
            results = asyncio.run(run_audit(config, None if args.all else {args.site}))
            run_dir = write_reports(results, Path(config.reports.directory), formats=config.reports.format,
                                    retention_days=config.reports.retention_days)
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
        print(f"{result.site_id}: {result.status} ({len(result.findings)} findings)")
    print(f"Reports: {run_dir.resolve()}")
    if any(any(error.startswith("AUTHENTICATION FAILURE:") for error in item.errors) for item in results):
        return EXIT_AUTHENTICATION
    if any(item.status == "INCOMPLETE" for item in results):
        return EXIT_INCOMPLETE
    if any(item.status == "ACTION_REQUIRED" for item in results):
        return EXIT_FINDINGS
    return EXIT_OK


def _cmd_report(args: argparse.Namespace) -> int:
    try:
        config = load_config(args.config)
        base = Path(config.reports.directory)
    except Exception as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIGURATION
    candidates = sorted(base.glob("*/*.md"), key=lambda item: item.stat().st_mtime, reverse=True)
    if args.site:
        candidates = [p for p in candidates if p.name == f"{args.site}.md"]
    if not candidates:
        json_candidates = sorted(base.glob("*/results.json"), key=lambda item: item.stat().st_mtime, reverse=True)
        for json_file in json_candidates:
            try:
                payload = json.loads(json_file.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not args.site:
                print(json.dumps(payload, indent=2, ensure_ascii=False))
                return EXIT_OK
            match = next((item for item in payload.get("sites", []) if item.get("site_id") == args.site), None)
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
    if config_path.exists():
        try:
            config = load_config(config_path)
            print(f"Configuration: valid ({len(config.sites)} sites)")
        except Exception as exc:
            print(f"Configuration: invalid — {exc}")
            return EXIT_CONFIGURATION
    else:
        print(f"Configuration: not found ({config_path})")
    return EXIT_OK


def main() -> None:
    args = _parser().parse_args()
    try:
        if args.command == "init":
            code = _cmd_init(Path(args.config))
        elif args.command == "site":
            code = _cmd_site(args)
        elif args.command == "audit":
            code = _cmd_audit(args)
        elif args.command == "report":
            code = _cmd_report(args)
        elif args.command == "doctor":
            code = _cmd_doctor(Path(args.config))
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
            config = load_config(args.config)
            if args.action == "status":
                print(schedule_status(config=Path(args.config), method=args.method))
            else:
                print(install_schedule(config.schedule, config=Path(args.config), method=args.method))
            code = EXIT_OK
        else:
            code = EXIT_CONFIGURATION
    except Exception as exc:
        print(f"Error: {type(exc).__name__}: {exc}", file=sys.stderr)
        code = EXIT_INTERNAL
    raise SystemExit(code)


if __name__ == "__main__":
    main()
