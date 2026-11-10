"""Weekend scheduler helpers for cron, systemd user timers, and Windows Task Scheduler."""

from __future__ import annotations

import hashlib
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from .models import Schedule

def _task_name(config: Path) -> str:
    digest = hashlib.sha1(str(config.resolve()).encode()).hexdigest()[:8]
    return f"WordPressMaintenanceAgent-{digest}"


def _ps_quote(value: str | Path) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _systemd_quote(value: str | Path) -> str:
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$")
    return f'"{escaped}"'


def _timezone_matches_local(name: str) -> bool:
    zone = ZoneInfo(name)
    for year in (datetime.now().year, datetime.now().year + 1):
        for month in range(1, 13):
            wall_time = datetime(year, month, 15, 12, 0)
            if abs(time.mktime(wall_time.timetuple()) - wall_time.replace(tzinfo=zone).timestamp()) > 1:
                return False
    return True


def _system_timezone_name() -> str:
    configured = os.environ.get("TZ", "").lstrip(":")
    if configured:
        try:
            ZoneInfo(configured)
            return configured
        except Exception:
            pass
    try:
        system_file = Path("/etc/timezone")
        if system_file.is_file():
            candidate = system_file.read_text(encoding="utf-8").strip()
            ZoneInfo(candidate)
            return candidate
        localtime = Path("/etc/localtime").resolve()
        parts = localtime.parts
        if "zoneinfo" in parts:
            candidate = "/".join(parts[parts.index("zoneinfo") + 1:])
            ZoneInfo(candidate)
            return candidate
    except (OSError, ValueError):
        pass
    if datetime.now().astimezone().utcoffset().total_seconds() == 0:
        return "UTC"
    raise RuntimeError("cannot determine the machine's IANA timezone; set TZ before installing a cron schedule")


def install_schedule(schedule: Schedule, *, config: Path, method: str = "auto", local_time: bool = False) -> str:
    system = platform.system()
    if method == "auto":
        method = "task-scheduler" if system == "Windows" else "cron"
    if method == "task-scheduler":
        if system != "Windows":
            raise RuntimeError("Task Scheduler installation is available only on Windows")
        if not local_time and not _timezone_matches_local(schedule.timezone):
            raise RuntimeError("Windows Task Scheduler uses local time; set schedule.timezone to the machine's local timezone")
        day = "SUN" if schedule.day == "sunday" else "SAT"
        executable = shutil.which("wp-maintenance")
        runner = f'"{executable}"' if executable else f'"{sys.executable}" -m wp_maintenance.cli'
        # schtasks /TR is limited to 261 characters and mangles nested quotes, so the task runs a short launcher.
        launcher_dir = Path.home() / ".wp-maintenance"
        launcher_dir.mkdir(parents=True, exist_ok=True)
        launcher = launcher_dir / f"{_task_name(config)}.cmd"
        log = launcher_dir / "scheduled-audit.log"
        launcher.write_text("@echo off\r\n"
                            f'cd /d "{Path.cwd()}"\r\n'
                            f'{runner} audit --all --config "{config.resolve()}" >> "{log}" 2>&1\r\n', encoding="utf-8")
        result = subprocess.run(["schtasks.exe", "/Create", "/SC", "WEEKLY", "/D", day, "/ST", schedule.time,
                                 "/TN", _task_name(config), "/TR", f'"{launcher}"', "/F"], capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"schtasks failed ({result.returncode}): {(result.stderr or result.stdout).strip()}")
        return f"Installed Windows Task Scheduler task {_task_name(config)} for {schedule.day} {schedule.time} local system time."
    if method == "cron":
        executable = shutil.which("wp-maintenance")
        runner = shlex.quote(executable) if executable else f"{shlex.quote(sys.executable)} -m wp_maintenance.cli"
        marker = f"# BEGIN wp-maintenance-agent managed schedule {_task_name(config)}"
        end_marker = f"# END wp-maintenance-agent managed schedule {_task_name(config)}"
        command = f"{schedule.time.split(':')[1]} {schedule.time.split(':')[0]} * * {0 if schedule.day == 'sunday' else 6} cd {shlex.quote(str(Path.cwd()))} && {runner} audit --all --config {shlex.quote(str(config.resolve()))}"
        existing = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        text = existing.stdout if existing.returncode == 0 else ""
        if marker in text and end_marker in text:
            start, end = text.index(marker), text.index(end_marker) + len(end_marker)
            text = text[:start] + text[end:]
        assignments = re.findall(r"^CRON_TZ=([^\r\n]+)", text, flags=re.MULTILINE)
        restore_timezone = None if local_time else (assignments[-1] if assignments else _system_timezone_name())
        command = command.replace("%", "\\%")
        block = (f"{marker}\n{command}\n{end_marker}\n" if local_time else
                 f"{marker}\nCRON_TZ={schedule.timezone}\n{command}\nCRON_TZ={restore_timezone}\n{end_marker}\n")
        subprocess.run(["crontab", "-"], input=(text.rstrip() + "\n\n" + block), check=True, text=True)
        return f"Installed user cron schedule for {schedule.day} {schedule.time} in {'local system time' if local_time else schedule.timezone}."
    if method == "systemd":
        if system != "Linux":
            raise RuntimeError("systemd user timer installation is available only on Linux")
        unit_dir = Path.home() / ".config/systemd/user"
        unit_dir.mkdir(parents=True, exist_ok=True)
        stem = _task_name(config)
        executable = shutil.which("wp-maintenance") or sys.executable
        day = "Sun" if schedule.day == "sunday" else "Sat"
        module_args = "" if shutil.which("wp-maintenance") else " -m wp_maintenance.cli"
        (unit_dir / f"{stem}.service").write_text(f"[Unit]\nDescription=WordPress Maintenance Agent audit\n\n[Service]\nType=oneshot\nWorkingDirectory={_systemd_quote(Path.cwd())}\nExecStart={_systemd_quote(executable)}{module_args} audit --all --config {_systemd_quote(config.resolve())}\n", encoding="utf-8")
        (unit_dir / f"{stem}.timer").write_text(f"[Unit]\nDescription=Weekly WordPress Maintenance Agent audit\n\n[Timer]\nOnCalendar={day} *-*-* {schedule.time}:00{'' if local_time else ' ' + schedule.timezone}\nPersistent=true\nUnit={stem}.service\n\n[Install]\nWantedBy=timers.target\n", encoding="utf-8")
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=True, capture_output=True, text=True)
        subprocess.run(["systemctl", "--user", "enable", "--now", f"{stem}.timer"], check=True, capture_output=True, text=True)
        return f"Installed and enabled systemd user timer {stem}.timer for {day} {schedule.time} in local time."
    raise ValueError("method must be auto, cron, systemd, or task-scheduler")


def schedule_status(*, config: Path, method: str = "auto") -> str:
    system = platform.system()
    if method == "auto":
        method = "task-scheduler" if system == "Windows" else "cron"
    if method == "task-scheduler":
        result = subprocess.run(["schtasks.exe", "/Query", "/TN", _task_name(config), "/FO", "LIST"], capture_output=True, text=True)
        return result.stdout.strip() if result.returncode == 0 else "No installed Task Scheduler task found."
    if method == "cron":
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        return "\n".join(line for line in result.stdout.splitlines() if _task_name(config) in line) or "No managed cron schedule found."
    if method == "systemd":
        result = subprocess.run(["systemctl", "--user", "status", f"{_task_name(config)}.timer"], capture_output=True, text=True)
        return result.stdout.strip() or "No systemd user timer found."
    raise ValueError("method must be auto, cron, systemd, or task-scheduler")


def remove_schedule(*, config: Path, method: str = "auto") -> str:
    system = platform.system()
    if method == "auto":
        method = "task-scheduler" if system == "Windows" else "cron"
    if method == "task-scheduler":
        result = subprocess.run(["schtasks.exe", "/Delete", "/TN", _task_name(config), "/F"], capture_output=True, text=True)
        return "Removed Task Scheduler task." if result.returncode == 0 else "No installed Task Scheduler task found."
    if method == "cron":
        existing = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        text = existing.stdout if existing.returncode == 0 else ""
        marker = f"# BEGIN wp-maintenance-agent managed schedule {_task_name(config)}"
        end_marker = f"# END wp-maintenance-agent managed schedule {_task_name(config)}"
        if marker not in text or end_marker not in text:
            return "No managed cron schedule found."
        start, end = text.index(marker), text.index(end_marker) + len(end_marker)
        subprocess.run(["crontab", "-"], input=(text[:start] + text[end:]).strip() + "\n", check=True, text=True)
        return "Removed managed cron schedule."
    if method == "systemd":
        stem = _task_name(config)
        subprocess.run(["systemctl", "--user", "disable", "--now", f"{stem}.timer"], capture_output=True, text=True)
        for suffix in ("service", "timer"):
            (Path.home() / ".config/systemd/user" / f"{stem}.{suffix}").unlink(missing_ok=True)
        return "Removed systemd user timer."
    raise ValueError("method must be auto, cron, systemd, or task-scheduler")
