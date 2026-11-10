import json
from datetime import datetime, timezone

from wp_maintenance.history import compare_results
from wp_maintenance.models import AuditResult, Finding
from wp_maintenance.reporting import write_reports


def test_report_generation_and_status_evidence(tmp_path):
    result = AuditResult(site_id="sample-site", site_name="Sample Data Site", url="https://example.test",
        environment="staging", access_mode="public", status="ACTION_REQUIRED",
        wordpress={"installed_version": None, "latest_official": "7.1.4", "update_available": None},
        php={"support_status": "NOT_VERIFIABLE_WITH_PUBLIC_ACCESS"},
        findings=[Finding(id="SAMPLE-404", severity="medium", component="page", title="Sample 404", detail="Fixture route returned HTTP 404.", evidence=["fixture only"])]
    )
    out = write_reports([result], tmp_path)
    markdown = (out / "sample-site.md").read_text(encoding="utf-8")
    payload = json.loads((out / "results.json").read_text(encoding="utf-8"))
    assert "WordPress Maintenance Audit Report" in markdown
    assert "ACTION_REQUIRED" in markdown
    assert "UNKNOWN" in markdown
    assert payload["sites"][0]["findings"][0]["id"] == "SAMPLE-404"


def test_history_delta():
    old = {"findings": [{"id": "a"}, {"id": "b"}]}
    new = {"findings": [{"id": "b"}, {"id": "c"}]}
    assert compare_results(new, old) == {"new": ["c"], "resolved": ["a"], "persistent": ["b"]}


def test_multiple_same_day_runs_keep_history_and_previous_evidence(tmp_path):
    finding = Finding(id="PLUGIN-UPDATE-sample", severity="medium", component="plugin",
        title="Update available", detail="An update is offered.")
    result = AuditResult(site_id="sample", site_name="Sample", url="https://example.test",
        environment="production", access_mode="public", status="ACTION_REQUIRED", findings=[finding])
    first = write_reports([result], tmp_path)
    second = write_reports([result], tmp_path)
    assert first != second
    payload = json.loads((second / "results.json").read_text(encoding="utf-8"))
    assert payload["sites"][0]["previous_audit"]["persistent"] == ["PLUGIN-UPDATE-sample"]


def test_notification_preferences_validate_without_exposing_secrets():
    from wp_maintenance.models import AppConfig
    config = AppConfig.model_validate({"sites": [], "notifications": {"enabled": True, "webhook_url_ref": "AUDIT_HOOK", "on_status": ["ACTION_REQUIRED"]}})
    assert config.notifications.webhook_url_ref == "AUDIT_HOOK"
