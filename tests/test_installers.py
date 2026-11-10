from pathlib import Path

import pytest

from wp_maintenance import integrations


def test_global_install_preserves_existing_files_and_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / ".codex"))
    monkeypatch.setattr(integrations.shutil, "which", lambda name: "C:/fake/" + name if name in {"codex", "claude"} else None)
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex/AGENTS.md").write_text("# Existing Codex rules\nKeep this text.\n", encoding="utf-8")
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude/CLAUDE.md").write_text("# Existing Claude rules\nKeep this too.\n", encoding="utf-8")
    monkeypatch.setattr(integrations, "_skill_source", lambda: Path(__file__).parents[1] / "skills/wordpress-maintenance")
    first = integrations.install_global()
    second = integrations.install_global()
    assert len(first) == 2
    assert all("already installed" in line for line in second)
    assert "Keep this text." in (tmp_path / ".codex/AGENTS.md").read_text(encoding="utf-8")
    assert list((tmp_path / ".codex").glob("AGENTS.md.backup.*"))
    removed = integrations.uninstall_global()
    assert len(removed) == 4
    assert "Keep this text." in (tmp_path / ".codex/AGENTS.md").read_text(encoding="utf-8")
    assert not (tmp_path / ".agents/skills/wordpress-maintenance").exists()


def test_global_install_refuses_unmarked_same_name_skill(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / ".codex"))
    monkeypatch.setattr(integrations.shutil, "which", lambda name: "fake" if name == "codex" else None)
    (tmp_path / ".agents/skills/wordpress-maintenance").mkdir(parents=True)
    (tmp_path / ".agents/skills/wordpress-maintenance/SKILL.md").write_text("User skill", encoding="utf-8")
    monkeypatch.setattr(integrations, "_skill_source", lambda: Path(__file__).parents[1] / "skills/wordpress-maintenance")
    with pytest.raises(FileExistsError, match="unrelated"):
        integrations.install_global()


def test_codex_active_override_is_extended_instead_of_inactive_agents_file(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / ".codex"))
    monkeypatch.setattr(integrations.shutil, "which", lambda name: "fake" if name == "codex" else None)
    home = tmp_path / ".codex"
    home.mkdir()
    (home / "AGENTS.md").write_text("Inactive base file\n", encoding="utf-8")
    (home / "AGENTS.override.md").write_text("Active override\n", encoding="utf-8")
    monkeypatch.setattr(integrations, "_skill_source", lambda: Path(__file__).parents[1] / "skills/wordpress-maintenance")
    integrations.install_global()
    assert "BEGIN WordPress Maintenance Agent" in (home / "AGENTS.override.md").read_text(encoding="utf-8")
    assert "BEGIN WordPress Maintenance Agent" not in (home / "AGENTS.md").read_text(encoding="utf-8")


def test_uninstall_restores_original_trailing_whitespace_exactly(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / ".codex"))
    monkeypatch.setattr(integrations.shutil, "which", lambda name: "fake" if name == "codex" else None)
    home = tmp_path / ".codex"
    home.mkdir()
    target = home / "AGENTS.md"
    original = b"Existing rules with trailing spaces  \r\n\r\n"
    target.write_bytes(original)
    monkeypatch.setattr(integrations, "_skill_source", lambda: Path(__file__).parents[1] / "skills/wordpress-maintenance")
    integrations.install_global()
    integrations.uninstall_global()
    assert target.read_bytes() == original
