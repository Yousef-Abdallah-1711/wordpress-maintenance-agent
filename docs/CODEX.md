# Codex integration

Codex discovers global guidance from `AGENTS.md` in its home directory, which defaults to `~/.codex` and can be changed with `CODEX_HOME`. Local skills are discovered in `~/.agents/skills/`. This repository ships its project instruction in `AGENTS.md` and a native project skill at `.agents/skills/wordpress-maintenance/SKILL.md`.

Run `wp-maintenance install --global`, then start a new Codex session and confirm the instruction/skill is discoverable. Codex's global guidance and skill directories are different locations; the installer handles both.
