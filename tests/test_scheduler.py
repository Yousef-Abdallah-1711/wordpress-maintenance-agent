from pathlib import Path
from types import SimpleNamespace

from wp_maintenance.models import Schedule
from wp_maintenance import scheduler


def test_cron_install_is_idempotent_and_preserves_other_jobs(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler.platform, "system", lambda: "Linux")
    monkeypatch.setenv("TZ", "UTC")
    monkeypatch.setattr(scheduler.shutil, "which", lambda name: "/usr/local/bin/wp-maintenance")
    config = tmp_path / "sites.yaml"
    current = "# user's unrelated backup job\n30 2 * * * backup-job\n"
    saved = []

    def fake_run(args, **kwargs):
        nonlocal current
        if args == ["crontab", "-l"]:
            return SimpleNamespace(returncode=0, stdout=current)
        assert args == ["crontab", "-"]
        current = kwargs["input"]
        saved.append(current)
        return SimpleNamespace(returncode=0, stdout="")

    monkeypatch.setattr(scheduler.subprocess, "run", fake_run)
    schedule = Schedule(timezone="Africa/Cairo", day="sunday", time="03:00")
    scheduler.install_schedule(schedule, config=config, method="cron")
    scheduler.install_schedule(schedule, config=config, method="cron")
    assert len(saved) == 2
    assert current.count("# user's unrelated backup job") == 1
    assert current.count("BEGIN wp-maintenance-agent") == 1
    assert current.count("audit --all") == 1
    assert "CRON_TZ=Africa/Cairo" in current
    assert "CRON_TZ=UTC" in current


def test_schedule_rejects_unknown_iana_timezone():
    import pytest
    with pytest.raises(ValueError, match="IANA timezone"):
        Schedule(timezone="Mars/Olympus", day="sunday", time="03:00")


def test_cron_uses_python_module_when_console_command_is_not_on_path(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler.platform, "system", lambda: "Linux")
    monkeypatch.setenv("TZ", "UTC")
    monkeypatch.setattr(scheduler.shutil, "which", lambda name: None)
    monkeypatch.setattr(scheduler.sys, "executable", "/opt/wp maintenance/bin/python")
    config = tmp_path / "sites.yaml"
    saved = []
    def fake_run(args, **kwargs):
        if args == ["crontab", "-l"]:
            return SimpleNamespace(returncode=1, stdout="")
        saved.append(kwargs["input"])
        return SimpleNamespace(returncode=0, stdout="")
    monkeypatch.setattr(scheduler.subprocess, "run", fake_run)
    scheduler.install_schedule(Schedule(), config=config, method="cron")
    assert "'/opt/wp maintenance/bin/python'" in saved[0]
    assert "-m wp_maintenance.cli audit --all" in saved[0]


def test_systemd_quotes_paths_with_spaces(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler.platform, "system", lambda: "Linux")
    monkeypatch.setattr(scheduler.shutil, "which", lambda name: None)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(Path, "cwd", classmethod(lambda cls: tmp_path / "working directory"))
    config = tmp_path / "client sites.yaml"
    calls = []
    monkeypatch.setattr(scheduler.subprocess, "run", lambda args, **kwargs: calls.append(args) or SimpleNamespace(returncode=0, stdout=""))
    scheduler.install_schedule(Schedule(timezone="Africa/Cairo"), config=config, method="systemd")
    unit = next((tmp_path / ".config/systemd/user").glob("*.service")).read_text(encoding="utf-8")
    assert f"WorkingDirectory={scheduler._systemd_quote(tmp_path / 'working directory')}" in unit
    assert f"ExecStart={scheduler._systemd_quote(scheduler.sys.executable)} -m wp_maintenance.cli audit --all --config {scheduler._systemd_quote(config.resolve())}" in unit


def test_cron_restores_existing_timezone_and_escapes_percent_in_command(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler.platform, "system", lambda: "Linux")
    monkeypatch.setattr(scheduler.shutil, "which", lambda name: "/opt/maint%enance/wp-maintenance")
    current = "CRON_TZ=Europe/Paris\n15 1 * * * unrelated\n"
    saved = []
    def fake_run(args, **kwargs):
        nonlocal current
        if args == ["crontab", "-l"]:
            return SimpleNamespace(returncode=0, stdout=current)
        current = kwargs["input"]
        saved.append(current)
        return SimpleNamespace(returncode=0, stdout="")
    monkeypatch.setattr(scheduler.subprocess, "run", fake_run)
    scheduler.install_schedule(Schedule(timezone="Africa/Cairo"), config=tmp_path / "config.yaml", method="cron")
    assert "CRON_TZ=Europe/Paris" in saved[0]
    assert "/opt/maint\\%enance/wp-maintenance" in saved[0]
