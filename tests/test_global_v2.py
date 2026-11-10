from pathlib import Path

from wp_maintenance import integrations


def _setup(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / ".codex"))
    monkeypatch.setattr(integrations.shutil, "which", lambda name: "C:/fake/" + name if name in {"codex", "claude"} else None)
    monkeypatch.setattr(integrations, "_skill_source", lambda: Path(__file__).parents[1] / "skills/wordpress-maintenance")


def test_outdated_managed_block_and_skill_are_updated_in_place(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    (tmp_path / ".claude").mkdir()
    old = f"# Mine\nkeep me\n\n{integrations.BEGIN}\nold v0.1 guidance\n{integrations.END}\n\n# After\nkeep too\n"
    (tmp_path / ".claude/CLAUDE.md").write_text(old, encoding="utf-8")
    out = integrations.install_global()
    text = (tmp_path / ".claude/CLAUDE.md").read_text(encoding="utf-8")
    assert any("updated global CLAUDE.md" in line for line in out)
    assert "keep me" in text and "keep too" in text and "old v0.1" not in text
    assert text.count(integrations.BEGIN) == 1 and "wp-maintenance audit <url>" in text
    assert list((tmp_path / ".claude").glob("CLAUDE.md.backup.*"))


def test_installed_skill_contains_the_url_workflow_and_doctor_reports_current(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    integrations.install_global()
    skill = (tmp_path / ".claude/skills/wordpress-maintenance/SKILL.md").read_text(encoding="utf-8")
    assert "wp-maintenance audit <url>" in skill and "Audit https://www.juhayna.com" in skill
    assert (tmp_path / ".agents/skills/wordpress-maintenance/SKILL.md").read_text(encoding="utf-8") == skill
    report = "\n".join(integrations.doctor_global())
    assert "Codex skill: installed and current" in report and "Claude Code skill: installed and current" in report


def test_packaged_skill_copy_matches_the_repository_skill():
    root = Path(__file__).parents[1]
    packaged = (root / "src/wp_maintenance/resources/wordpress-maintenance/SKILL.md").read_bytes()
    assert packaged == (root / "skills/wordpress-maintenance/SKILL.md").read_bytes()


def test_skill_backups_never_live_inside_skills_folders(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    integrations.install_global()
    skill = tmp_path / ".claude/skills/wordpress-maintenance/SKILL.md"
    skill.write_text("stale", encoding="utf-8")
    integrations.install_global()
    assert [p.name for p in (tmp_path / ".claude/skills").iterdir()] == ["wordpress-maintenance"]
    assert [p.name for p in (tmp_path / ".agents/skills").iterdir()] == ["wordpress-maintenance"]
    assert list((tmp_path / ".wp-maintenance/backups").glob("*wordpress-maintenance.backup.*"))
