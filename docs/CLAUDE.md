# Claude Code integration

Claude Code loads user instructions from `~/.claude/CLAUDE.md` and user skills from `~/.claude/skills/<name>/SKILL.md`. Project Claude instructions can import `AGENTS.md`; this repository's `CLAUDE.md` does so and adds a short Claude-specific note. A project skill is also provided in `.claude/skills/`.

Run `wp-maintenance install --global`, then start a new Claude Code session and confirm `/wordpress-maintenance` appears. Claude Code requires separate native paths; the Codex skill directory is not reused.

## URL workflow (v0.2)

The installed skill (`~/.claude/skills/wordpress-maintenance/SKILL.md`) and the managed block in `~/.claude/CLAUDE.md` route `Audit https://www.example.com` to `wp-maintenance audit <url>` from any directory. Re-run `wp-maintenance install --global` after upgrading to refresh them, then start a new Claude Code session.
