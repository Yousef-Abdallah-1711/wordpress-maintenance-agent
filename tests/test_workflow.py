import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github/workflows/weekly-audit.yml"
SCRIPTS = sorted((ROOT / "scripts/ci").glob("*.sh"))


@pytest.fixture(scope="module")
def wf():
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    data["on"] = data.pop(True) if True in data else data["on"]  # YAML 1.1 parses the key `on` as True
    return data


def test_triggers_schedule_in_cairo_time_and_manual_dispatch(wf):
    entry = wf["on"]["schedule"][0]
    assert entry["cron"] == "0 3 * * 0" and entry["timezone"] == "Africa/Cairo"
    inputs = wf["on"]["workflow_dispatch"]["inputs"]
    assert set(inputs) == {"audit_scope", "site_id", "custom_url", "max_urls", "report_mode"}
    assert inputs["audit_scope"]["options"] == ["all", "single", "custom_url"] and inputs["audit_scope"]["default"] == "all"
    assert inputs["report_mode"]["options"] == ["standard", "detailed"]


def test_no_privileged_pull_request_triggers(wf):
    assert not {"pull_request", "pull_request_target", "workflow_run", "issue_comment"} & set(wf["on"])
    assert "pull_request_target" not in WORKFLOW.read_text(encoding="utf-8")


def test_least_privilege_permissions_and_limits(wf):
    assert wf["permissions"] == {}
    job = wf["jobs"]["audit"]
    assert job["permissions"] == {"contents": "read", "actions": "read", "issues": "write"}
    assert isinstance(job["timeout-minutes"], int) and job["timeout-minutes"] <= 360
    assert wf["concurrency"]["cancel-in-progress"] is False


def test_every_action_is_pinned_to_a_full_commit_sha(wf):
    uses = [s["uses"] for s in wf["jobs"]["audit"]["steps"] if "uses" in s]
    assert uses
    for ref in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", ref), ref


def test_untrusted_inputs_never_appear_in_shell_source(wf):
    for step in wf["jobs"]["audit"]["steps"]:
        script = step.get("run", "")
        assert "${{" not in script.replace("${{ github.run_id }}", ""), f"expression interpolated in run block: {step.get('name')}"
        assert "github.event.inputs" not in script and "inputs." not in script


def test_inputs_flow_only_through_environment(wf):
    env = wf["jobs"]["audit"]["env"]
    for name, expr in (("INPUT_SITE_ID", "inputs.site_id"), ("INPUT_CUSTOM_URL", "inputs.custom_url"),
                       ("INPUT_MAX_URLS", "inputs.max_urls"), ("INPUT_SCOPE", "inputs.audit_scope")):
        assert expr in env[name]


def test_secrets_are_scoped_to_the_steps_that_need_them(wf):
    assert "secrets." not in str(wf["jobs"]["audit"]["env"])
    holders = [s["name"] for s in wf["jobs"]["audit"]["steps"] if "secrets." in str(s.get("env", {}))]
    assert set(holders) == {"Decide report storage policy", "Load audit history (private repository)",
                            "Save audit history (private repository)"}
    assert "secrets." not in WORKFLOW.read_text(encoding="utf-8").replace("secrets.WP_MAINTENANCE_HISTORY_DEPLOY_KEY", "")


def test_schedule_is_gated_by_a_repository_variable(wf):
    assert "WP_MAINTENANCE_SCHEDULE_ENABLED" in wf["jobs"]["audit"]["if"]
    assert "schedule" in wf["jobs"]["audit"]["if"]


def test_artifacts_use_safe_names_and_configurable_retention(wf):
    uploads = [s for s in wf["jobs"]["audit"]["steps"] if str(s.get("uses", "")).startswith("actions/upload-artifact")]
    names = {u["with"]["name"] for u in uploads}
    assert names == {"wp-maintenance-reports-${{ github.run_id }}", "wp-maintenance-history"}
    assert all("retention-days" in u["with"] for u in uploads)


def test_report_upload_is_blocked_for_public_repositories_by_default():
    policy = (ROOT / "scripts/ci/policy.sh").read_text(encoding="utf-8")
    assert '"$private" = "true" ] || [ "${PUBLIC_ARTIFACTS:-}" = "true"' in policy
    assert "public" in policy and "not** stored" in policy


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_ci_scripts_are_strict_and_free_of_eval(script):
    text = script.read_text(encoding="utf-8")
    assert "eval " not in text and "bash -c" not in text and "sh -c" not in text
    assert re.search(r"set -[eu]*o pipefail|set -uo pipefail", text)
    assert "\r" not in text


def _bash_works() -> bool:
    exe = shutil.which("bash")
    if exe is None:
        return False
    try:  # on Windows `bash` may be a WSL launcher without a distribution
        return subprocess.run([exe, "-c", "exit 0"], capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


@pytest.mark.skipif(not _bash_works(), reason="a working bash is not available")
@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_ci_scripts_have_valid_bash_syntax(script):
    assert subprocess.run([shutil.which("bash"), "-n", str(script).replace("\\", "/")], capture_output=True).returncode == 0


def test_run_audit_script_quotes_every_user_value_and_exposes_exit_code():
    text = (ROOT / "scripts/ci/run-audit.sh").read_text(encoding="utf-8")
    for var in ("INPUT_SITE_ID", "INPUT_CUSTOM_URL", "INPUT_MAX_URLS"):
        assert re.search(rf'"\${{{var}}}"', text), var
    assert 'args=(' in text and '"${args[@]}"' in text and "exit_code=" in text


def test_history_repo_name_is_validated_before_use():
    for name in ("policy.sh", "history-repo-load.sh"):
        assert "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$" in (ROOT / "scripts/ci" / name).read_text(encoding="utf-8")


def test_deploy_key_is_never_echoed_and_is_removed():
    for name in ("history-repo-load.sh", "history-repo-save.sh"):
        text = (ROOT / "scripts/ci" / name).read_text(encoding="utf-8")
        assert "echo ${HISTORY_KEY" not in text and 'echo "${HISTORY_KEY' not in text and "rm -f" in text
        assert "StrictHostKeyChecking=yes" in text


def test_secret_redaction_in_reports_and_logs():
    from wp_maintenance.security import redact_secrets
    out = redact_secrets("Authorization: Bearer abc.def.ghi password=hunter2 https://user:pw@example.com/x token: tkn123")
    assert "abc.def.ghi" not in out and "hunter2" not in out and "pw@" not in out and "tkn123" not in out


def test_ssl_alert_thresholds_default_to_30_14_and_under_7_days():
    from wp_maintenance.models import AuditOptions
    from wp_maintenance.ssl_audit import classify_days
    o = AuditOptions()
    assert (o.ssl_warning_days, o.ssl_high_days, o.ssl_critical_days) == (30, 14, 6)
    assert [classify_days(d) for d in (31, 30, 14, 7, 6, 0, -1)] == ["HEALTHY", "WARNING", "HIGH", "HIGH", "CRITICAL", "CRITICAL", "CRITICAL"]


def test_example_inventory_is_valid_and_contains_no_placeholder_targets():
    from wp_maintenance.inventory import load_inventory
    inv = load_inventory(ROOT / "config/websites.yaml")
    assert [s.id for s in inv.sites if s.enabled] == ["juhayna"]
    assert not any("example" in s.url for s in inv.sites)


# ---------- private history save script against a real (local) git remote ----------

def _git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True).stdout.strip()


@pytest.mark.skipif(not _bash_works() or shutil.which("git") is None, reason="bash/git not available")
def test_history_save_script_is_append_only_conflict_safe_and_prunes(tmp_path):
    import os
    remote = tmp_path / "remote.git"
    _git(tmp_path, "init", "--bare", "-b", "main", str(remote))
    seed = tmp_path / "seed"
    _git(tmp_path, "clone", str(remote), str(seed))
    (seed / "README.md").write_text("history\n", encoding="utf-8")
    old_dir = seed / "archive" / "2000-01-01" / "1"
    old_dir.mkdir(parents=True)
    (old_dir / "summary.md").write_text("ancient\n", encoding="utf-8")
    for cmd in (["config", "user.email", "t@example.com"], ["config", "user.name", "t"], ["add", "-A"], ["commit", "-m", "seed"], ["push", "origin", "HEAD:main"]):
        _git(seed, *cmd)

    work = tmp_path / "work"
    work.mkdir()
    _git(work, "clone", str(remote), "history-repo")
    reports = work / "reports" / "2026-11-15"
    (reports / "sites" / "juhayna").mkdir(parents=True)
    (reports / "summary.md").write_text("week one\n", encoding="utf-8")
    snap_dir = work / "history-repo" / "history" / "juhayna"
    snap_dir.mkdir(parents=True)
    (snap_dir / "20261115T010000Z-100.json").write_text("{}", encoding="utf-8")

    # A concurrent writer pushes first: the script must rebase instead of failing or overwriting.
    other = tmp_path / "other"
    _git(tmp_path, "clone", str(remote), str(other))
    (other / "note.txt").write_text("concurrent\n", encoding="utf-8")
    for cmd in (["config", "user.email", "t@example.com"], ["config", "user.name", "t"], ["add", "-A"], ["commit", "-m", "concurrent"], ["push", "origin", "HEAD:main"]):
        _git(other, *cmd)

    env = {**os.environ, "HISTORY_KEY": "not-a-real-key", "REPORT_DIR": "reports/2026-11-15", "RETENTION_DAYS": "365",
           "RUNNER_TEMP": str(tmp_path), "GITHUB_RUN_ID": "100", "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md")}
    script = str(ROOT / "scripts/ci/history-repo-save.sh").replace("\\", "/")
    result = subprocess.run([shutil.which("bash"), script], cwd=work, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "verified on the remote" in result.stdout
    assert not (tmp_path / "wpm_history_key").exists()  # deploy key file removed

    check = tmp_path / "check"
    _git(tmp_path, "clone", str(remote), str(check))
    assert (check / "note.txt").exists()  # concurrent change preserved
    assert (check / "history/juhayna/20261115T010000Z-100.json").exists()
    assert (check / "archive/2026-11-15/100/summary.md").read_text(encoding="utf-8") == "week one\n"
    assert not (check / "archive/2000-01-01").exists()  # retention pruned the ancient archive

    # A second run appends a new archive folder and never rewrites the first one.
    (reports / "summary.md").write_text("week two\n", encoding="utf-8")
    (snap_dir / "20261122T010000Z-101.json").write_text("{}", encoding="utf-8")
    env["GITHUB_RUN_ID"] = "101"
    assert subprocess.run([shutil.which("bash"), script], cwd=work, env=env, capture_output=True, text=True).returncode == 0
    _git(check, "pull", "-q")
    assert (check / "archive/2026-11-15/100/summary.md").read_text(encoding="utf-8") == "week one\n"
    assert (check / "archive/2026-11-15/101/summary.md").read_text(encoding="utf-8") == "week two\n"


def test_setup_scripts_refuse_non_private_history_and_never_print_keys():
    for name in ("setup-private-history.sh", "setup-private-history.ps1"):
        text = (ROOT / "scripts" / name).read_text(encoding="utf-8")
        assert "NOT private" in text and "--allow-write" in text and "WP_MAINTENANCE_HISTORY_DEPLOY_KEY" in text
        assert "cat \"${tmp}/key\"" not in text and "Write-Host $key" not in text
    assert "eval " not in (ROOT / "scripts/setup-private-history.sh").read_text(encoding="utf-8")
