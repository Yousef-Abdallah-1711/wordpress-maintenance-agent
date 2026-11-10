# Automation

The preferred schedule is Sunday 03:00 in the configured IANA timezone. No scheduler is activated by `init` or `install --global`; run `wp-maintenance schedule install` explicitly.

- Windows: Task Scheduler weekly, using machine-local time; installation refuses a configured timezone that does not match the machine's timezone rules.
- Linux: user cron (`--method cron`, with `CRON_TZ`) or a systemd user timer (`--method systemd`, with the timezone in `OnCalendar`).
- macOS: user cron. A LaunchAgent is not installed automatically.
- GitHub Actions: Sunday 00:00 UTC and manual dispatch. GitHub Actions cron does not use the YAML timezone; DST may shift the local execution time.

Set the `WP_MAINTENANCE_CONFIG_B64` repository secret to the base64 content of a configuration file and add site credentials as repository or environment secrets. Reports are artifacts with bounded retention and are never committed. Confirm repository visibility before uploading sensitive audit output.

## URL-only weekly monitoring (v0.2)

```sh
wp-maintenance site add https://www.example.com
wp-maintenance site add https://shop.example.org
wp-maintenance schedule install --weekly --day sunday --time 03:00 [--timezone Africa/Cairo]
wp-maintenance schedule status
wp-maintenance schedule remove
```

Each run executes `wp-maintenance audit --all` against the registry (`~/.wp-maintenance/config.yaml` by default): SSL expiry, WordPress/plugin/PHP status where verifiable, sitemap rechecks, per-site `latest.md`/`history/` reports with a *new/resolved/persistent issues* comparison against the previous audit, and a consolidated `latest-summary.md`.

**Time zones.** Without `--timezone` the schedule uses the machine's local time (Task Scheduler, cron, systemd). With `--timezone` cron/systemd honour the zone; Windows Task Scheduler requires it to equal the machine's zone. GitHub Actions cron is always UTC.

**Limitations.** A local schedule only runs while the machine is on (Windows: while the user is logged on; missed runs are not replayed by Task Scheduler as installed, systemd uses `Persistent=true`). Codex and Claude Code do not need to be open. For always-on monitoring use the GitHub Actions workflow: set a repository **variable** `WP_MAINTENANCE_URLS` (space or newline separated) and the reports are uploaded as artifacts.

## GitHub Actions is the primary platform (v0.3)

Hosted weekly monitoring replaces local schedulers for most users: see [GITHUB_ACTIONS.md](GITHUB_ACTIONS.md). The local Task Scheduler / cron / systemd options above remain available for machines that should audit locally.
