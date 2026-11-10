import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from wp_maintenance import batch as batchmod
from wp_maintenance.batch import (annotations, apply_fail_policy, build_summary, emit_github, exit_code,
                                  render_github_summary, run_targets, write_batch)
from wp_maintenance.delta import compute_delta
from wp_maintenance.history_store import list_snapshots, load_previous, prune, save_snapshot
from wp_maintenance.models import AuditResult, Finding
from wp_maintenance.notifications import GitHubIssueNotifier
from wp_maintenance.targets import Target

NOW = datetime(2026, 11, 15, 1, 0, tzinfo=timezone.utc)


def F(fid, sev="medium", comp="page", url=None, title=None):
    return Finding(id=fid, severity=sev, component=comp, title=title or fid, detail=fid,
                   evidence=[url] if url else [])


def page(url, status=200, cls="available"):
    return {"url": url, "status": status, "classification": cls, "elapsed_ms": 10.0, "final_url": url}


def R(site="s1", status="ACTION_REQUIRED", findings=(), pages=(), **kw):
    base = dict(site_id=site, site_name=site.upper(), url=f"https://{site}.example.com", environment="production",
                access_mode="public", status=status, started_at=NOW, finished_at=NOW,
                coverage=["homepage_http", "ssl_tls_inspection", "sitemap_discovery", "sitemap_page_http_checks",
                          "security_headers", "technical_seo", "wordpress_core_metadata", "public_plugin_asset_hints"],
                findings=list(findings), pages=list(pages),
                crawl={"urls_checked": len(pages), "sitemap_urls_listed": len(pages), "sitemap_truncated": False})
    base.update(kw)
    return AuditResult(**base)


def dump(r):
    return r.model_dump(mode="json")


# ---------- delta ----------

def test_new_resolved_persistent_with_verified_page_recheck():
    prev = R(findings=[F("PAGE-a", url="https://x/a"), F("PAGE-b", url="https://x/b")],
             pages=[page("https://x/a", 404, "missing"), page("https://x/b", 404, "missing")])
    cur = R(findings=[F("PAGE-b", url="https://x/b"), F("PAGE-c", url="https://x/c")],
            pages=[page("https://x/a"), page("https://x/b", 404, "missing"), page("https://x/c", 500, "server_error")])
    d = compute_delta(dump(cur), dump(prev))
    assert d["available"] and d["new"] == ["PAGE-c"] and d["resolved"] == ["PAGE-a"] and d["persistent"] == ["PAGE-b"]
    kinds = {c["type"] for c in d["changes"]}
    assert {"resolved_404", "new_5xx"} <= kinds


def test_unchecked_page_is_not_marked_resolved():
    prev = R(findings=[F("PAGE-a", url="https://x/a")], pages=[page("https://x/a", 404, "missing")])
    cur = R(pages=[page("https://x/other")])
    d = compute_delta(dump(cur), dump(prev))
    assert d["resolved"] == [] and d["unverified"][0]["id"] == "PAGE-a"
    assert "not checked" in d["unverified"][0]["reason"]


def test_incomplete_current_audit_resolves_nothing():
    prev = R(findings=[F("SSL-EXPIRING", comp="ssl")])
    cur = R(status="INCOMPLETE")
    d = compute_delta(dump(cur), dump(prev))
    assert d["resolved"] == [] and "INCOMPLETE" in d["unverified"][0]["reason"]


def test_check_that_did_not_run_is_unverified_not_resolved():
    prev = R(findings=[F("SSL-EXPIRING", comp="ssl")])
    cur = R(coverage=["homepage_http"])
    d = compute_delta(dump(cur), dump(prev))
    assert d["resolved"] == [] and d["unverified"][0]["id"] == "SSL-EXPIRING"
    ran = compute_delta(dump(R()), dump(prev))
    assert ran["resolved"] == ["SSL-EXPIRING"]


def test_core_and_php_resolution_requires_visible_version():
    prev = R(findings=[F("WP-CORE-UPDATE", comp="WordPress core"), F("PHP-END-OF-LIFE", comp="PHP")],
             wordpress={"installed_version": "6.4"}, php={"installed_version": "7.4"})
    cur = R(wordpress={"installed_version": None}, php={"installed_version": None})
    d = compute_delta(dump(cur), dump(prev))
    assert d["resolved"] == [] and {u["id"] for u in d["unverified"]} >= {"WP-CORE-UPDATE", "PHP-END-OF-LIFE"}


def test_ssl_renewal_and_version_changes_detected():
    prev = R(ssl={"not_after": "2026-11-20T00:00:00+00:00", "issuer": "CN=A", "status": "HIGH", "days_remaining": 5},
             wordpress={"installed_version": "6.4.1", "version_status": "PUBLICLY_INDICATED_UNVERIFIED"},
             php={"installed_version": "8.1.2"}, plugins=[{"slug": "p", "installed_version": "1.0"}])
    cur = R(ssl={"not_after": "2027-02-18T00:00:00+00:00", "issuer": "CN=B", "status": "HEALTHY", "days_remaining": 95},
            wordpress={"installed_version": "6.5.0", "version_status": "PUBLICLY_INDICATED_UNVERIFIED"},
            php={"installed_version": "8.3.0"}, plugins=[{"slug": "p", "installed_version": "1.1"}, {"slug": "q"}])
    kinds = {c["type"] for c in compute_delta(dump(cur), dump(prev))["changes"]}
    assert {"ssl_renewed", "ssl_issuer_changed", "ssl_status_changed", "wordpress_version_changed",
            "php_version_changed", "plugin_version_changed", "plugin_reference_new"} <= kinds


def test_unknown_versions_do_not_produce_change_events():
    cur, prev = R(wordpress={"installed_version": None}), R(wordpress={"installed_version": None})
    assert not [c for c in compute_delta(dump(cur), dump(prev))["changes"] if "version" in c["type"]]


def test_vulnerability_new_and_resolved_are_explicit():
    prev = R(findings=[F("WF-1", "high", "security", title="old vuln")], coverage=["wordfence_intelligence_v3", "homepage_http"])
    cur = R(findings=[F("WF-2", "critical", "security", title="new vuln")], coverage=["wordfence_intelligence_v3", "homepage_http"])
    kinds = {c["type"] for c in compute_delta(dump(cur), dump(prev))["changes"]}
    assert {"new_vulnerable_plugin", "resolved_vulnerability"} <= kinds


def test_sitemap_url_changes_only_when_coverage_is_complete():
    prev = R(pages=[page("https://x/a"), page("https://x/b")])
    cur = R(pages=[page("https://x/a"), page("https://x/c")])
    kinds = [c["type"] for c in compute_delta(dump(cur), dump(prev))["changes"]]
    assert "sitemap_url_added" in kinds and "sitemap_url_removed" in kinds
    partial = R(pages=[page("https://x/a"), page("https://x/c")], crawl={"urls_checked": 2, "sitemap_urls_listed": 50, "sitemap_truncated": True})
    d = compute_delta(dump(partial), dump(prev))
    assert "sitemap_url_added" not in [c["type"] for c in d["changes"]]
    assert any(u["id"] == "sitemap-url-set" for u in d["unverified"])


def test_missing_previous_evidence_is_reported_as_unavailable():
    d = compute_delta(dump(R()), None, unavailable_reason="no previous snapshot exists")
    assert d["available"] is False and "no previous" in d["reason"] and d["new"] == [] and d["resolved"] == []


# ---------- history store ----------

def test_snapshots_never_overwrite_and_are_ordered(tmp_path):
    a = save_snapshot(tmp_path, dump(R()), run_id="100", now=NOW)
    b = save_snapshot(tmp_path, dump(R()), run_id="100", now=NOW)
    c = save_snapshot(tmp_path, dump(R()), run_id="101", now=NOW + timedelta(days=7))
    assert len({a, b, c}) == 3 and all(p.exists() for p in (a, b, c))
    data = json.loads(a.read_text(encoding="utf-8"))
    assert data["schema_version"] == 2 and data["run_id"] == "100" and data["report_version"]
    assert [s.run_id for s in list_snapshots(tmp_path, "s1")][-1] == "101"


def test_previous_valid_skips_incomplete_runs_and_corrupt_files(tmp_path):
    save_snapshot(tmp_path, dump(R(findings=[F("OLD")])), run_id="1", now=NOW - timedelta(days=14))
    save_snapshot(tmp_path, dump(R(status="INCOMPLETE")), run_id="2", now=NOW - timedelta(days=7))
    (tmp_path / "s1" / "garbage.json").write_text("{not json", encoding="utf-8")
    snap, reason = load_previous(tmp_path, "s1")
    assert snap is not None and snap.run_id == "1" and reason == "ok"
    snap, reason = load_previous(tmp_path, "s1", exclude_run_id="1")
    assert snap is None and "none is a valid" in reason
    assert load_previous(tmp_path, "unknown")[0] is None


def test_retention_prunes_old_snapshots_but_keeps_the_latest(tmp_path):
    for i, days in enumerate((400, 380, 10)):
        save_snapshot(tmp_path, dump(R()), run_id=str(i), now=NOW - timedelta(days=days))
    assert prune(tmp_path, retention_days=365, now=NOW, keep_latest=1) == 2
    assert [s.run_id for s in list_snapshots(tmp_path, "s1")] == ["2"]


# ---------- batch execution ----------

def target(i, url=None):
    return Target(id=f"site{i}", name=f"Site {i}", url=url or f"https://site{i}.example.com")


@pytest.mark.asyncio
async def test_one_failing_and_one_hanging_site_never_block_the_others(monkeypatch):
    async def fake_audit(site, config):
        if site.id == "site2":
            raise RuntimeError("boom with password=hunter2")
        if site.id == "site3":
            await asyncio.sleep(10)
        return R(site=site.id, status="PASS")
    monkeypatch.setattr(batchmod, "audit_site", fake_audit)
    monkeypatch.setattr(batchmod, "build_site", lambda url, name, site_id: _site(site_id, url, name))
    results, cancelled = await run_targets([target(i) for i in range(1, 6)], site_concurrency=3, site_timeout=0.5, log=lambda m: None)
    by = {r.site_id: r for r in results}
    assert not cancelled and [r.site_id for r in results] == [f"site{i}" for i in range(1, 6)]
    assert by["site1"].status == by["site4"].status == by["site5"].status == "PASS"
    assert by["site2"].status == "INCOMPLETE" and "hunter2" not in " ".join(by["site2"].errors)
    assert by["site3"].status == "INCOMPLETE" and "exceeded" in by["site3"].errors[0]


def _site(site_id, url, name):
    from wp_maintenance.models import Site
    return Site(id=site_id, name=name or site_id, url=url)


@pytest.mark.asyncio
async def test_site_concurrency_is_bounded(monkeypatch):
    running = {"now": 0, "max": 0}

    async def fake_audit(site, config):
        running["now"] += 1
        running["max"] = max(running["max"], running["now"])
        await asyncio.sleep(0.05)
        running["now"] -= 1
        return R(site=site.id, status="PASS")
    monkeypatch.setattr(batchmod, "audit_site", fake_audit)
    monkeypatch.setattr(batchmod, "build_site", lambda url, name, site_id: _site(site_id, url, name))
    await run_targets([target(i) for i in range(8)], site_concurrency=2, site_timeout=5, log=lambda m: None)
    assert running["max"] == 2


@pytest.mark.asyncio
async def test_twenty_sites_three_failures_seventeen_reports(monkeypatch, tmp_path):
    async def fake_audit(site, config):
        if site.id in {"site3", "site9", "site15"}:
            raise ConnectionError("down")
        return R(site=site.id, status="PASS")
    monkeypatch.setattr(batchmod, "audit_site", fake_audit)
    monkeypatch.setattr(batchmod, "build_site", lambda url, name, site_id: _site(site_id, url, name))
    results, _ = await run_targets([target(i) for i in range(1, 21)], site_concurrency=4, site_timeout=5, log=lambda m: None)
    out = write_batch(results, reports_dir=tmp_path / "reports", history_dir=None, run_id="1", scope="all", source="inventory", report_mode="standard", notes=[], now=NOW)
    assert len(list((out.run_dir / "sites").glob("*/report.md"))) == 20
    assert out.summary["sites_audited"] == 17 and sorted(out.summary["sites_incomplete"]) == ["site15", "site3", "site9"]
    assert out.summary["overall_status"] == "INCOMPLETE" and exit_code(out.summary) == 5
    text = (out.run_dir / "summary.md").read_text(encoding="utf-8")
    assert "Incomplete or failed audits" in text and "down" in text


@pytest.mark.asyncio
async def test_cancellation_still_returns_results_for_finished_sites(monkeypatch):
    async def fake_audit(site, config):
        if site.id == "site1":
            return R(site="site1", status="PASS")
        await asyncio.sleep(30)
    monkeypatch.setattr(batchmod, "audit_site", fake_audit)
    monkeypatch.setattr(batchmod, "build_site", lambda url, name, site_id: _site(site_id, url, name))
    task = asyncio.ensure_future(run_targets([target(1), target(2)], site_concurrency=2, site_timeout=60, log=lambda m: None))
    await asyncio.sleep(0.2)
    task.cancel()
    results, cancelled = await task
    assert cancelled and results[0].status == "PASS" and results[1].status == "INCOMPLETE" and "cancelled" in results[1].errors[0]


# ---------- summary / outputs ----------

def test_summary_metrics_are_derived_from_collected_data(tmp_path):
    a = R(site="a", findings=[F("PAGE-1", url="u1"), F("SSL-EXPIRED", "critical", "ssl")],
          pages=[page("u1", 404, "missing"), page("u2", 500, "server_error"), page("u3")],
          ssl={"status": "CRITICAL", "days_remaining": 3, "trusted": True},
          wordpress={"detection": "CONFIRMED_WORDPRESS", "installed_version": "6.5"},
          plugins=[{"slug": "p", "classification": "VERIFIED_OUTDATED"}])
    b = R(site="b", status="PASS", ssl={"status": "HEALTHY", "days_remaining": 90, "trusted": True})
    out = write_batch([a, b], reports_dir=tmp_path, history_dir=None, run_id="9", scope="all", source="inventory",
                      report_mode="standard", notes=["n"], now=NOW)
    s = out.summary
    assert s["total_sites"] == 2 and s["sites_with_critical"] == ["a"] and s["overall_status"] == "CRITICAL"
    assert s["total_broken_urls"] == 2 and s["total_server_errors"] == 1
    assert s["ssl_expiring"] == [{"site": "a", "status": "CRITICAL", "days": 3}]
    assert exit_code(s) == 7
    md = (out.run_dir / "summary.md").read_text(encoding="utf-8")
    assert "| Website | SSL | WordPress | Plugins | Broken URLs | Status |" in md and "CRITICAL (3d)" in md
    assert json.loads((out.run_dir / "summary.json").read_text(encoding="utf-8"))["total_sites"] == 2
    assert (out.run_dir / "weekly-delta.md").is_file() and (out.run_dir / "sites" / "a" / "report.json").is_file()


def test_fail_policy():
    s = {"sites_with_critical": [], "sites_with_high": ["x"], "sites_incomplete": ["y"], "overall_status": "INCOMPLETE"}
    assert apply_fail_policy(5, s, {"critical"}) == 0
    assert apply_fail_policy(5, s, {"critical", "incomplete"}) == 5
    assert apply_fail_policy(2, s, {"high"}) == 2
    assert apply_fail_policy(5, s, {"never"}) == 0


def test_two_weeks_of_history_produce_real_comparison_and_no_silent_claims(tmp_path):
    hist, reports = tmp_path / "h", tmp_path / "r"
    week1 = write_batch([R(findings=[F("PAGE-a", url="https://x/a")], pages=[page("https://x/a", 404, "missing")])], reports_dir=reports,
                        history_dir=hist, run_id="1", scope="all", source="inventory", report_mode="standard", notes=[], now=NOW)
    assert week1.deltas["s1"]["available"] is False
    assert "baseline" in week1.summary["history"]["comparison"]
    week2 = write_batch([R(status="PASS", pages=[page("https://x/a")])], reports_dir=reports, history_dir=hist, run_id="2",
                        scope="all", source="inventory", report_mode="standard", notes=[], now=NOW + timedelta(days=7))
    assert week2.deltas["s1"]["resolved"] == ["PAGE-a"] and week2.summary["resolved_issues"] == 1
    assert "loaded previous evidence for 1 of 1" in week2.summary["history"]["comparison"]
    assert "Resolved findings (verified) (1)" in (week2.run_dir / "weekly-delta.md").read_text(encoding="utf-8")
    assert len(list_snapshots(hist, "s1")) == 2
    assert week1.run_dir != week2.run_dir


def test_same_day_runs_never_overwrite_reports(tmp_path):
    kw = dict(reports_dir=tmp_path, history_dir=None, scope="all", source="inventory", report_mode="standard", notes=[], now=NOW)
    one = write_batch([R()], run_id="1", **kw)
    two = write_batch([R()], run_id="2", **kw)
    assert one.run_dir != two.run_dir and (one.run_dir / "summary.json").exists() and (two.run_dir / "summary.json").exists()


def test_detailed_mode_lists_every_checked_url(tmp_path):
    r = R(pages=[page(f"https://x/p{i}") for i in range(5)])
    out = write_batch([r], reports_dir=tmp_path, history_dir=None, run_id="1", scope="all", source="s", report_mode="detailed", notes=[], now=NOW)
    text = (out.run_dir / "sites" / "s1" / "report.md").read_text(encoding="utf-8")
    assert "All Checked URLs" in text and "https://x/p4" in text
    std = write_batch([r], reports_dir=tmp_path / "o", history_dir=None, run_id="1", scope="all", source="s", report_mode="standard", notes=[], now=NOW)
    assert "All Checked URLs" not in (std.run_dir / "sites" / "s1" / "report.md").read_text(encoding="utf-8")


def test_github_summary_outputs_and_annotation_escaping(tmp_path):
    evil = R(site="evil", status="INCOMPLETE", findings=[F("X", "critical", "ssl")], errors=["Authorization: Bearer abc123secret"])
    evil.site_name = "Evil | name\n## injected"
    out = write_batch([evil, R(site="ok", status="PASS")], reports_dir=tmp_path, history_dir=None, run_id="5", scope="all",
                      source="inventory", report_mode="standard", notes=[], now=NOW)
    step, gh_out = tmp_path / "step.md", tmp_path / "out.txt"
    emit_github(out, env={"GITHUB_STEP_SUMMARY": str(step), "GITHUB_OUTPUT": str(gh_out), "GITHUB_SERVER_URL": "https://github.com",
                          "GITHUB_REPOSITORY": "o/r", "GITHUB_RUN_ID": "5"})
    text = step.read_text(encoding="utf-8")
    assert "# Weekly WordPress Maintenance" in text and "actions/runs/5" in text and "| Website | SSL |" in text
    assert "\n## injected" not in text and "abc123secret" not in text
    assert "overall_status=CRITICAL" in gh_out.read_text(encoding="utf-8")
    for line in annotations(out.summary):
        assert "\n" not in line and line.startswith("::")


# ---------- GitHub issue notifications ----------

class FakeGh:
    def __init__(self, private=True, issues=None):
        self.calls, self.private, self.issues = [], private, issues or []

    def __call__(self, args):
        self.calls.append(args)
        if args[0] == "api":
            return 0, json.dumps({"private": self.private})
        if args[:2] == ["issue", "list"]:
            return 0, json.dumps(self.issues)
        return 0, ""


def _notif_inputs(critical=True, resolved=False):
    result = dump(R(findings=[F("SSL-EXPIRED", "critical", "ssl")] if critical else []))
    delta = {"resolved": ["SSL-EXPIRED"] if resolved else [], "details": {"SSL-EXPIRED": {"severity": "critical"}}}
    return {"run_id": "7"}, [result], {"s1": delta}


def test_issues_are_skipped_for_public_repositories_unless_allowed():
    gh = FakeGh(private=False)
    log = GitHubIssueNotifier("o/r", runner=gh).notify(*_notif_inputs())
    assert "skipped" in log[0] and not [c for c in gh.calls if c[:2] == ["issue", "create"]]


def test_issue_created_once_updated_when_persistent_and_closed_only_when_verified():
    gh = FakeGh()
    n = GitHubIssueNotifier("o/r", runner=gh, run_url="https://github.com/o/r/actions/runs/7")
    n.notify(*_notif_inputs())
    assert any(c[:2] == ["issue", "create"] for c in gh.calls)
    title = "[WP Maintenance] s1: SSL-EXPIRED"
    gh2 = FakeGh(issues=[{"number": 4, "title": title, "state": "OPEN"}])
    GitHubIssueNotifier("o/r", runner=gh2).notify(*_notif_inputs())
    assert any(c[:2] == ["issue", "comment"] for c in gh2.calls) and not any(c[:2] == ["issue", "create"] for c in gh2.calls)
    gh3 = FakeGh(issues=[{"number": 4, "title": title, "state": "OPEN"}])
    GitHubIssueNotifier("o/r", runner=gh3).notify(*_notif_inputs(critical=False, resolved=True))
    assert any(c[:2] == ["issue", "close"] for c in gh3.calls)
    gh4 = FakeGh(issues=[{"number": 4, "title": title, "state": "OPEN"}])
    GitHubIssueNotifier("o/r", runner=gh4).notify(*_notif_inputs(critical=False, resolved=False))
    assert not any(c[:2] == ["issue", "close"] for c in gh4.calls)  # unverified absence never closes


def test_all_notifier_calls_use_argument_lists_without_a_shell():
    gh = FakeGh()
    GitHubIssueNotifier("o/r", runner=gh).notify(*_notif_inputs())
    assert all(isinstance(c, list) and all(isinstance(a, str) for a in c) for c in gh.calls)
