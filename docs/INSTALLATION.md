# Installation

Install Python 3.12+, then run `python -m pip install .` from a release or checkout. `wp-maintenance --help` verifies command registration when Python's Scripts/bin directory is on `PATH`; otherwise use `python -m wp_maintenance.cli --help`.

On Windows, use the same pip command from PowerShell. On Linux/macOS, use a virtual environment or user install. The global agent installer never requires administrator rights.

`wp-maintenance install --global` detects `codex` and `claude` executables. Codex guidance is installed in its active global instruction file: `$CODEX_HOME/AGENTS.override.md` when non-empty, otherwise `$CODEX_HOME/AGENTS.md` (default `~/.codex`). Its skill goes in `~/.agents/skills/wordpress-maintenance/`. Claude guidance is installed at `~/.claude/CLAUDE.md` and its skill at `~/.claude/skills/wordpress-maintenance/`. The installer creates timestamped backups, appends a tagged guidance block, and refuses to replace an unmarked same-name skill. `wp-maintenance doctor` checks the integration. `wp-maintenance uninstall --global` removes only marked content.

The PowerShell and shell helpers in `scripts/` wrap these commands; they do not download and execute remote code. Schedulers fall back to the installed Python module when the console command is not on `PATH`.

## Verifying a global install (v0.2)

1. `wp-maintenance doctor` reports the CLI path, global guidance and whether each skill is `installed and current`. Re-running `wp-maintenance install --global` updates an outdated managed block or skill in place (file backups sit next to them; skill backups go to `~/.wp-maintenance/backups/` so they are never registered as a duplicate skill).
2. Make sure Python's `Scripts` directory is on `PATH` (pip prints a warning if it is not), then open a **new** terminal in any directory and run `wp-maintenance --version`.
3. Start a new Codex or Claude Code session and say `Audit https://www.example.com`. `doctor` verifies *installation*; whether the agent chooses to invoke the skill is the agent's behaviour and can only be confirmed by trying it.
