# GitHub Actions automation (v0.3)

A hosted, read-only audit that runs **every Sunday at 03:00 Africa/Cairo** and on demand, without your computer being online. It audits the sites in `config/websites.yaml`, writes per-site Markdown + JSON reports and a consolidated summary, compares with the previous run, and publishes a job summary.

## 1. Set it up (fork or use as a template)

1. Fork the repository (use a **private** fork/copy if the sites you monitor should not be public: `config/websites.yaml` and, by default, reports are visible in a public repository).
2. **Actions** tab → enable workflows.
3. Add your sites (locally or by editing the file on GitHub):
   ```sh
   pip install .
   wp-maintenance site add https://www.example.com --name "Example"
   git add config/websites.yaml && git commit -m "Add example site" && git push
   ```
4. **Actions → WordPress Maintenance Audit → Run workflow** and pick `all`.
5. Enable the weekly schedule: **Settings → Secrets and variables → Actions → Variables → New repository variable** `WP_MAINTENANCE_SCHEDULE_ENABLED` = `true`.

No WordPress credentials are needed; audits use public evidence only and never modify the sites.

## 2. Website inventory (`config/websites.yaml`)

```yaml
version: 1
defaults: {audit_mode: public, max_urls: 500, concurrency: 4, timeout_seconds: 20, respect_robots_txt: true}
sites:
  - id: juhayna            # unique, [a-z0-9_-]
    name: Juhayna
    url: https://www.juhayna.com
    enabled: true
    tags: [wordpress, corporate]
    # optional per-site: max_urls, concurrency, timeout_seconds, respect_robots_txt,
    #                    exclude_paths: ["/private/"], audit: {plugins: false}, notifications: {github_issues: true}
```

| Task | Command |
|---|---|
| Add | `wp-maintenance site add https://example.com --name "Example"` |
| Disable / enable | `wp-maintenance site disable example` / `site enable example` |
| Remove | `wp-maintenance site remove example` (reports/history stay) |
| Inspect | `wp-maintenance site list` / `site show example` |
| Validate (DNS + schema) | `wp-maintenance site validate` (`--offline` skips DNS) |

The schema rejects credentials, unknown keys, duplicate ids, duplicate websites (`www.` and apex count as the same site), non-HTTP(S) schemes, non-standard ports, localhost, private/link-local/metadata addresses. Edits keep your comments and are written atomically (a failed validation never changes the file). On a machine where `config/websites.yaml` does not exist, `site add` keeps using the legacy per-user registry unless you pass `--inventory`.

### `WP_MAINTENANCE_URLS` (optional, compatibility)

For deployments without an inventory file, set the repository **variable** `WP_MAINTENANCE_URLS`: one URL per line (blank lines and `# comments` allowed; whitespace-separated also works).

**Precedence (deterministic, never merged):**
1. `audit_scope = custom_url` → only that URL, for this run only.
2. `config/websites.yaml` if it exists **and lists at least one site** → used exclusively; disabled sites stay disabled; `WP_MAINTENANCE_URLS` is ignored (the run says so).
3. Otherwise `WP_MAINTENANCE_URLS`. Duplicate or unsafe entries fail the run instead of being merged silently.

## 3. Running manually

**Actions → WordPress Maintenance Audit → Run workflow**

| Input | Values |
|---|---|
| `audit_scope` | `all` (every enabled site), `single` (needs `site_id`, must be enabled), `custom_url` (needs `custom_url`; not saved; no history written) |
| `site_id` / `custom_url` | only with the matching scope; combinations are validated and ambiguous ones rejected |
| `max_urls` | optional sitemap-URL limit, 1-50000 |
| `report_mode` | `standard`, or `detailed` (lists every checked URL) |

Inputs reach the scripts only as environment variables and are validated again by `wp-maintenance`.

## 4. Reports, summary and artifacts

```text
reports/YYYY-MM-DD/summary.md | summary.json | weekly-delta.md
reports/YYYY-MM-DD/sites/<id>/report.md | report.json
```
The run's **job summary** shows status, critical/high counts, SSL warnings, broken pages, failed audits, history availability and a per-site table. Download the files from the run page → **Artifacts** → `wp-maintenance-reports-<run id>` (retention: variable `WP_MAINTENANCE_ARTIFACT_RETENTION_DAYS`, default 30).

Status values: `PASS`, `PASS_WITH_WARNINGS`, `ACTION_REQUIRED`, `INCOMPLETE`, and `CRITICAL` for the overall run when any site has a critical finding. By default the job **fails** for critical findings or incomplete audits (`WP_MAINTENANCE_FAIL_ON`, comma list of `critical`, `high`, `incomplete`, `never`; default `critical,incomplete`). Reports are always saved first.

## 5. History and week-over-week comparison

Runners are ephemeral, so history is stored outside them. The workflow chooses a backend (shown in the job summary):

| Backend | When | Notes |
|---|---|---|
| **Private history repository** (recommended) | `WP_MAINTENANCE_HISTORY_REPO` variable (`owner/name`) + `WP_MAINTENANCE_HISTORY_DEPLOY_KEY` secret (set by the setup script below) | Per-site snapshots plus a report archive; append-only; pruned by `WP_MAINTENANCE_RETENTION_DAYS`. Works when this repository is public and is the only backend that keeps reports private there. |
| **Artifact** | repository is private, or `WP_MAINTENANCE_PUBLIC_ARTIFACTS=true` | Each run restores the newest `wp-maintenance-history` artifact and uploads an updated one (retention `WP_MAINTENANCE_HISTORY_RETENTION_DAYS`, default 90, GitHub max). A gap longer than the retention loses the baseline. |
| **None** | public repository without the above | The audit still runs; reports are **not** uploaded; the summary states that comparison is unavailable. |

### Private history setup (one time, run by a repository admin)

Granting credentials is deliberately a human step. From a machine where `gh` is logged in as an admin of the source repository:

```sh
bash scripts/setup-private-history.sh OWNER          # Linux/macOS/Git Bash
powershell -File scripts\setup-private-history.ps1 -Owner OWNER   # Windows
```

The script (1) creates the **private** `OWNER/wordpress-maintenance-history` repository if missing and refuses to continue if it is not private, (2) generates a throw-away ed25519 key, (3) registers only the public half as a *write deploy key on that single repository*, (4) stores the private half as the Actions secret `WP_MAINTENANCE_HISTORY_DEPLOY_KEY` and sets the variable `WP_MAINTENANCE_HISTORY_REPO`, (5) deletes the local key files. Re-running rotates the key. A deploy key can touch only that one repository; no personal access token is stored. (A fine-grained token or GitHub App installation token limited to the history repository with `Contents: read & write` is an acceptable alternative if your organisation forbids deploy keys.)

### Storage guarantees

- Every run appends `history/<site>/<UTC time>-<run id>.json` and `archive/<report date>/<run id>/...` (all reports, summary and weekly delta) in one commit; existing files are never rewritten. A concurrent writer is handled by `pull --rebase` and retry, and the push is verified against the remote head.
- Retention: archive folders and snapshots older than `WP_MAINTENANCE_RETENTION_DAYS` (default 365) are pruned; the newest two snapshots per site are always kept.
- The public source repository never receives reports, and report artifacts are not uploaded from public repositories (see below).

### Retrieving reports (authenticated)

```sh
gh repo clone OWNER/wordpress-maintenance-history && cd wordpress-maintenance-history
ls archive/                                   # YYYY-MM-DD folders, one subfolder per workflow run id
cat archive/2026-11-15/<run id>/summary.md    # weekly summary; also weekly-delta.md and sites/<id>/report.md|json
wp-maintenance history list --history-dir history
wp-maintenance history show --history-dir history --site juhayna   # re-render the latest stored report
```
Only people with access to the private repository can read these files. You can also browse them in the GitHub web UI.

**Comparison rules.** The previous *valid* snapshot (complete evidence, not `INCOMPLETE`) is loaded per site. Findings are matched by stable ids. A finding is reported **resolved** only if the relevant check ran again and was clean (a page is re-fetched; a coverage tag is present; a version is visible). Otherwise it is listed under *unverified changes* (page not checked, partial coverage, version no longer disclosed, incomplete audit). `weekly-delta.md` lists new, resolved, persistent and unverified findings plus detected changes (new/resolved 404 and 5xx, redirect problems, certificate renewal/issuer change, WordPress/PHP/plugin version changes where both runs had evidence, new/removed sitemap URLs when coverage was complete, coverage changes).

## 6. Optional GitHub Issues for critical findings

Off by default. Set `WP_MAINTENANCE_ISSUES=true` to open one issue per **critical** finding (title `[WP Maintenance] <site>: <finding id>`, label `wp-maintenance`), comment while it persists, and close it only when a re-check verifies the resolution. In a **public** repository it refuses to run unless `WP_MAINTENANCE_ISSUES_ALLOW_PUBLIC=true`, because issues would be public. Notifiers implement `wp_maintenance.notifications.Notifier`, so email/Slack/Discord/webhook senders can be added later.

## 7. Schedule

`on.schedule` uses GitHub's native `timezone: "Africa/Cairo"` with `cron: "0 3 * * 0"`, so Egypt's daylight-saving changes are handled by GitHub. GitHub may start scheduled runs minutes late, only runs workflows from the default branch, and disables schedules in public repositories after 60 days without repository activity (re-enable in the Actions tab). To change it, edit the `cron`/`timezone` lines in `.github/workflows/weekly-audit.yml`. The workflow only runs on schedule when `WP_MAINTENANCE_SCHEDULE_ENABLED` is `true`; remove the variable to pause weekly runs.

## 8. Security and privacy

- Token permissions are empty at workflow level; the job gets `contents: read`, `actions: read`, `issues: write` (used only if issues are enabled). No `pull_request_target`, no forks' code with secrets.
- Actions are pinned to full commit SHAs; the job has a timeout and a concurrency group.
- Workflow inputs are only passed through environment variables, never interpolated into shell code; site names/URLs are validated and escaped in summaries and annotations; secrets are redacted from reports.
- The deploy key is scoped to one repository, written to a temporary file, never printed, and deleted; SSH host keys come from GitHub's metadata API.
- Audits are read-only GET requests with SSRF protections (public addresses only, validated redirects, pinned DNS), bounded concurrency/rate/response sizes, TLS verification, and they never bypass WAFs or CAPTCHAs.
- **Public repositories expose the inventory, logs, the job summary and (if enabled) artifacts.** Reports are withheld by default; use a private fork or the private history repository for anything sensitive.

## 9. Troubleshooting

| Symptom | Fix |
|---|---|
| Run skipped on schedule | set `WP_MAINTENANCE_SCHEDULE_ENABLED=true` |
| "no websites configured" | add a site / set `WP_MAINTENANCE_URLS` / use `custom_url` |
| "site '...' is disabled" | `site enable <id>` or use `custom_url` |
| "History repository unavailable" | check the deploy key has **write** access and the repo name |
| Job red but reports exist | the fail policy triggered (critical/incomplete); see the summary or set `WP_MAINTENANCE_FAIL_ON` |
| Audit `INCOMPLETE`, blocked | the site rate-limited or blocked automation; the audit stops instead of bypassing it; lower `max_urls`/`concurrency` or allow-list the runner |
| Slow site | raise nothing: each site is capped (30 min) and the crawl is capped at 75% of that |
