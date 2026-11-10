# Automation

The preferred schedule is Sunday 03:00 in the configured timezone. No scheduler is activated by `init` or `install --global`; run `wp-maintenance schedule install` explicitly.

- Windows: Task Scheduler weekly, using machine-local time.
- Linux: user cron (`--method cron`) or a systemd user timer (`--method systemd`).
- macOS: user cron. A LaunchAgent is not installed automatically.
- GitHub Actions: Sunday 00:00 UTC and manual dispatch. GitHub Actions cron does not use the YAML timezone; DST may shift the local execution time.

Set the `WP_MAINTENANCE_CONFIG_B64` repository secret to the base64 content of a configuration file and add site credentials as repository or environment secrets. Reports are artifacts with bounded retention and are never committed. Confirm repository visibility before uploading sensitive audit output.
