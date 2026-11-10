"""Weekend scheduler helpers for cron, systemd user timers, and Windows Task Scheduler."""

from __future__ import annotations

import hashlib
import os
import platform
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from .models import Schedule

def _task_name(config: Path) -> str:
    digest = hashlib.sha1(str(config.resolve()).encode()).hexdigest()[:8]
    return f"WordPressMaintenanceAgent-{digest}"


def _ps_quote(value: str | Path) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def install_schedule(schedule: Schedule, *, config: Path, method: str = "auto") -> str:
    system = platform.system()
    if method == "auto":
        method = "task-scheduler" if system == "Windows" else "cron"
    if method == "task-scheduler":
        if system != "Windows":
            raise RuntimeError("Task Scheduler installation is available only on Windows")
        day = "SUN" if schedule.day == "sunday" else "SAT"
        executable = shutil.which("wp-maintenance")
        runner = f"& {_ps_quote(executable)}" if executable else f"& {_ps_quote(sys.executable)} -m wp_maintenance.cli"
        command = f'powershell.exe -NoProfile -NonInteractive -Command "Set-Location -LiteralPath {_ps_quote(Path.cwd())}; {runner} audit --all --config {_ps_quote(config.resolve())}"'
        subprocess.run(["schtasks.exe", "/Create", "/SC", "WEEKLY", "/D", day, "/ST", schedule.time,
                        "/TN", _task_name(config), "/TR", command, "/F"], check=True, capture_output=True, text=True)
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
        block = f"{marker}\n{command}\n{end_marker}\n"
        subprocess.run(["crontab", "-"], input=(text.rstrip() + "\n\n" + block), check=True, text=True)
        return f"Installed user cron schedule for {schedule.day} {schedule.time} in the machine timezone."
    if method == "systemd":
        if system != "Linux":
            raise RuntimeError("systemd user timer installation is available only on Linux")
        unit_dir = Path.home() / ".config/systemd/user"
        unit_dir.mkdir(parents=True, exist_ok=True)
        stem = _task_name(config)
        executable = shutil.which("wp-maintenance") or sys.executable
        day = "Sun" if schedule.day == "sunday" else "Sat"
        module_args = "" if shutil.which("wp-maintenance") else " -m wp_maintenance.cli"
        (unit_dir / f"{stem}.service").write_text(f"[Unit]\nDescription=WordPress Maintenance Agent audit\n\n[Service]\nType=oneshot\nWorkingDirectory={Path.cwd()}\nExecStart={executable}{module_args} audit --all --config {config.resolve()}\n", encoding="utf-8")
        (unit_dir / f"{stem}.timer").write_text(f"[Unit]\nDescription=Weekly WordPress Maintenance Agent audit\n\n[Timer]\nOnCalendar={day} *-*-* {schedule.time}:00\nPersistent=true\nUnit={stem}.service\n\n[Install]\nWantedBy=timers.target\n", encoding="utf-8")
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
