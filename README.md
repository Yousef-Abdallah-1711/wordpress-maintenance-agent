# WordPress Maintenance Agent

A read-only Python CLI that collects public and explicitly authenticated WordPress maintenance evidence, checks sitemap URLs, and writes one Markdown report per site plus a machine-readable JSON summary. It does not depend on an AI model to determine versions or HTTP outcomes.

## URL-only quick start (v0.2)

```sh
python -m pip install .
wp-maintenance install --global        # optional: Codex / Claude Code integration
wp-maintenance audit https://www.example.com
```

That is all: no YAML, WordPress login, SSH, FTP, hosting credentials or plugin. The audit checks SSL/TLS, WordPress detection and version evidence, publicly exposed plugins, PHP disclosure, sitemaps and every sitemap URL, security headers, technical SEO and response time, then writes `latest.md`, `latest.json` and a preserved `history/` entry under `~/wp-maintenance-reports/<site>/`. In Codex or Claude Code, from any directory, just say `Audit https://www.example.com`. See [docs/CLI.md](docs/CLI.md).

Weekly monitoring of several sites:

```sh
wp-maintenance site add https://www.example.com
wp-maintenance site add https://shop.example.org
wp-maintenance schedule install --weekly --day sunday --time 03:00
```

## What it does

- Audits multiple configured WordPress sites.
- Reads exact WordPress generator metadata when a site exposes it and compares it with the official WordPress version-check API.
- Uses WordPress.org's plugin information API for exact slugs observed in public page assets. Asset version query values remain hints and never prove an installed plugin version.
- Uses the optional authenticated connector to inventory active/inactive/must-use plugins, core/PHP versions, and core/plugin update transients.
- Discovers sitemaps through `robots.txt` and common WordPress paths, parses nested indexes safely, and checks in-scope URLs.
- Produces dated Markdown and JSON reports with evidence, limitations, status and historical issue deltas.
- Audits any public URL with zero configuration, including TLS certificate expiry/trust/hostname checks, security headers, technical SEO and partial-coverage reporting (`checked/listed`).
- Supports user-level Codex and Claude Code skills, GitHub Actions, cron, systemd user timers and Windows Task Scheduler.

## What it does not do

- It does not update software, alter files or databases, deactivate plugins, or change PHP.
- Public access cannot prove the complete plugin inventory, exact PHP version or hidden WordPress core version.
- An HTTP 200 does not prove browser functionality. Bot protection and access restrictions are reported, never bypassed.
- Optional Wordfence Intelligence V3 advisory checks match exact plugin slugs and affected version ranges; configure `WORDFENCE_API_KEY`. No vulnerability is inferred from age or update status.

## Requirements

- Python 3.12 or later.
- Windows, Linux or macOS for manual CLI use. The CLI is portable; schedule integration depends on the host scheduler.

## Install

```powershell
python -m pip install .
wp-maintenance --help
```

For contributors:

```powershell
python -m pip install -e ".[dev]"
python -m pytest
```

To install the agent globally for tools detected on the current user account:

```powershell
wp-maintenance install --global
wp-maintenance doctor
```

Codex uses `AGENTS.md` under `$CODEX_HOME` (default `~/.codex`) and discovers user skills under `~/.agents/skills/wordpress-maintenance/`. Claude Code uses `~/.claude/CLAUDE.md` plus `~/.claude/skills/wordpress-maintenance/SKILL.md`. Those are distinct native paths and formats. Existing instructions are backed up and preserved around a managed block. If a same-named skill already exists without this project's marker, installation stops rather than overwriting it. Use `wp-maintenance uninstall --global` to remove only managed blocks and marked skill folders.

## Quick start

```sh
wp-maintenance init
wp-maintenance site add --id example --name "Example site" --url https://example.com
wp-maintenance site list
wp-maintenance audit --site example
wp-maintenance report --latest
```

Use `examples/sites.example.yaml` as a reference for multiple sites and weekend preferences. The CLI never overwrites an existing file on `init`. Site credentials are referenced by environment variable name, not stored in YAML.

Authenticated access uses a WordPress Application Password whose user has the connector's `view_wp_maintenance_inventory` capability and the optional connector at `wordpress-connector/wp-maintenance-connector.php`. Store `username:application-password` in the referenced environment variable, e.g. `WORDPRESS_STAGING`. Do not paste secrets into the config or commit them.

## Audit behavior

All website requests use TLS verification, timeouts, retry limits, bounded response sizes and explicit redirect checks. Crawls stay within the site's hostname unless `approved_hosts` is configured. Private, loopback, link-local and reserved IPs are rejected, and only standard web ports are allowed. The connector's inventory route requires WordPress authentication and its dedicated `view_wp_maintenance_inventory` capability; application passwords do not bypass that capability check.

Reports are written to `<reports>/<site>/latest.md|json` plus a never-overwritten `history/` (default `~/wp-maintenance-reports`; config-mode runs also keep `YYYY-MM-DD/` run folders). Status values are `PASS`, `PASS_WITH_WARNINGS`, `ACTION_REQUIRED` or `INCOMPLETE`; only medium-or-higher findings make a run `ACTION_REQUIRED`, and partial coverage can never be `PASS`. Exit codes: 0 success/warnings, 2 actionable findings, 3 config/usage failure, 4 authentication failure, 5 incomplete audit, 6 internal failure, 130 cancelled.

## Weekend automation

Register URLs with `wp-maintenance site add <url>` and run `wp-maintenance schedule install --weekly --day sunday --time 03:00` (add `--timezone Africa/Cairo` for an explicit IANA zone; without it the machine's local time is used). `schedule status` / `schedule remove` manage it. It runs without Codex or Claude Code open, but only while the machine is on (Windows Task Scheduler: while the user is logged on). See [docs/AUTOMATION.md](docs/AUTOMATION.md).

GitHub Actions runs weekly Sunday at 00:00 UTC and supports manual dispatch. GitHub cron uses UTC, not `schedule.timezone`. Add a `WP_MAINTENANCE_CONFIG_B64` repository secret containing base64-encoded YAML and environment secrets for credentials. Reports are uploaded as workflow artifacts, not committed. Do not put private site details in a public repository; artifacts in public repositories may be visible to repository readers.

## Global uninstall

```sh
wp-maintenance uninstall --global
```

Only agent-owned guidance blocks and skill directories marked by the installer are removed. Backups remain alongside modified user files for recovery.

## Security and limitations

See [CLI reference](docs/CLI.md), [Security](SECURITY.md), [Installation](docs/INSTALLATION.md), [Configuration](docs/CONFIGURATION.md), [Authentication](docs/AUTHENTICATION.md), [Automation](docs/AUTOMATION.md), and [Report format](docs/REPORT_FORMAT.md). Each socket connection pins a validated public DNS address while preserving the hostname for TLS. Keep network egress controls enabled as a defense in depth.

## Development

```sh
python -m pip install -e ".[dev]"
python -m pytest
python -m wp_maintenance.cli --help
```

Contributions and security reports are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
