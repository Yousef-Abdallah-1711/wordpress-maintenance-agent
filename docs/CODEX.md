# Codex integration

Codex discovers global guidance from `AGENTS.md` in its home directory, which defaults to `~/.codex` and can be changed with `CODEX_HOME`. Local skills are discovered in `~/.agents/skills/`. This repository ships its project instruction in `AGENTS.md` and a native project skill at `.agents/skills/wordpress-maintenance/SKILL.md`.

Run `wp-maintenance install --global`, then start a new Codex session and confirm the instruction/skill is discoverable. Codex's global guidance and skill directories are different locations; the installer handles both.

## URL workflow (v0.2)

The installed skill and the managed `AGENTS.md` block tell Codex to run `wp-maintenance audit <url>` for requests like `Audit https://www.example.com`, from any directory. Verify installation with `wp-maintenance doctor`; start a fresh Codex session after installing so the skill list is reloaded.
