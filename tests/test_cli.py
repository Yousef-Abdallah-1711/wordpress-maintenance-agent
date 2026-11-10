import json
from pathlib import Path
from types import SimpleNamespace

from wp_maintenance.cli import EXIT_CONFIGURATION, _cmd_audit, _cmd_report


def test_audit_all_without_enabled_sites_is_configuration_error(tmp_path):
    config = tmp_path / "sites.yaml"
    config.write_text("sites: []\n", encoding="utf-8")
    args = SimpleNamespace(config=str(config), all=True, site=None, mode="read-only")
    assert _cmd_audit(args) == EXIT_CONFIGURATION


def test_report_site_can_read_json_only_output(tmp_path, capsys):
    reports_dir = tmp_path / "reports"
    run_dir = reports_dir / "2026-11-10"
    run_dir.mkdir(parents=True)
    (run_dir / "results.json").write_text(json.dumps({"sites": [{"site_id": "site-a", "status": "PASS_WITH_WARNINGS"}]}), encoding="utf-8")
    config = tmp_path / "sites.yaml"
    config.write_text(f"sites: []\nreports:\n  directory: {reports_dir.as_posix()}\n  format: [json]\n", encoding="utf-8")
    args = SimpleNamespace(config=str(config), latest=False, site="site-a")
    assert _cmd_report(args) == 0
    assert '"site_id": "site-a"' in capsys.readouterr().out
