# CLI reference

```text
wp-maintenance audit <url>                 zero-config public audit
wp-maintenance audit --url <url>           same, option form
wp-maintenance audit --all | --site <id>   audit registered sites
wp-maintenance site add <url> | list | remove <id|url>
wp-maintenance schedule install --weekly --day sunday --time 03:00 [--timezone Africa/Cairo]
wp-maintenance schedule status | remove
wp-maintenance report --url <url> | --site <id>
wp-maintenance install --global | uninstall --global | doctor | init
```

## Zero-config audit

`wp-maintenance audit https://www.example.com` needs no YAML, login, SSH, FTP, hosting access or plugin. The URL is normalized to its origin (scheme + host; paths, queries and fragments are dropped), validated (HTTP/HTTPS, standard ports, no credentials, no private/loopback/link-local/reserved addresses) and the crawl scope is that host plus its `www`/apex counterpart.

Options: `--output <dir>` (reports directory), `--max-pages <n>` (sitemap URLs to check, default 500), `--concurrency <n>` (default 5). Requests are additionally limited to one per 0.25 s per host with retry/backoff.

### What is checked

| Area | Evidence | Never inferred |
|---|---|---|
| SSL/TLS | Verified handshake to port 443: subject, issuer, SAN, expiry, days left, protocol, hostname match, HTTP→HTTPS redirect | Trust after a failed verification |
| WordPress | Generator meta, `/wp-json/` namespaces, `/wp-content/`/`/wp-includes/` references, RSS feed generator → `CONFIRMED_WORDPRESS`, `LIKELY_WORDPRESS`, `NOT_DETECTED`, `UNKNOWN`; version compared with the official API only when exposed | An outdated state for an unknown version |
| Plugins | Exact `/wp-content/plugins/<slug>/` references in HTML/CSS/JS URLs; WordPress.org metadata | Installed versions from `?ver=`; inventory completeness; vulnerabilities from a path |
| PHP | Explicit `X-Powered-By: PHP/x.y` or `X-PHP-Version`, compared with the official lifecycle | Anything else → `PHP VERSION: UNKNOWN — AUTHENTICATED VERIFICATION REQUIRED` |
| Sitemaps/pages | `robots.txt`, `wp-sitemap.xml`, `sitemap.xml`, `sitemap_index.xml`, nested indexes; status, redirect chain, timing, error class per URL | Coverage beyond what was checked (`checked/listed` is reported) |
| Headers/SEO/perf | HSTS, CSP, nosniff, referrer, permissions, frame protection; robots.txt, canonical, noindex; homepage response time | Lighthouse or Core Web Vitals |

Plugin classifications: `VERIFIED_OUTDATED`, `VERIFIED_CURRENT` (authenticated inventory only), `VERSION_UNKNOWN`, `UPDATE_SOURCE_UNKNOWN`, `NOT_VERIFIABLE`.

SSL expiry classes (configurable via `audit.ssl_warning_days/ssl_high_days/ssl_critical_days`): more than 30 days `HEALTHY`; 15–30 `WARNING`; 7–14 `HIGH`; 0–6 or expired `CRITICAL`.

### Exit codes

0 success or warnings only · 2 actionable findings · 3 invalid URL/configuration · 4 authentication failure · 5 incomplete audit (collector failure, blocked automation, partial crawl stopped early) · 6 internal error · 130 cancelled.

## Reports

```text
<reports>/<site-slug>/latest.md
<reports>/<site-slug>/latest.json
<reports>/<site-slug>/history/2026-11-10-140000.md|json   (never overwritten)
<reports>/latest-summary.md, <reports>/summaries/<timestamp>.md
```

The default directory is `~/wp-maintenance-reports` (override with `--output` or `WP_MAINTENANCE_REPORTS_DIR`), so reports do not land in whatever directory an agent happens to be in. Config-mode audits (`--all`, `--site`) additionally keep the original `YYYY-MM-DD/<run>/` run folders.

## Registry and configuration location

`site add <url>` stores sites in `$WP_MAINTENANCE_CONFIG`, else `./wp-maintenance.yaml` if present, else `~/.wp-maintenance/config.yaml`. Authenticated mode (`--access-mode authenticated --id ... --credentials-ref ...`) is unchanged.

## Inventory and batch commands (v0.3)

```text
wp-maintenance site list|show <id>|add <url> [--name N] [--id I] [--tag T]|remove <id>|enable <id>|disable <id>|validate [--offline]
wp-maintenance audit-batch [--inventory config/websites.yaml] [--scope all|single|custom_url] [--site ID] [--url URL]
                           [--max-urls N] [--report-mode standard|detailed] [--output reports] [--history-dir DIR]
                           [--retention-days N] [--site-concurrency 2] [--site-timeout 1800] [--fail-on critical,incomplete]
                           [--notify github-issues] [--allow-public-issues] [--dry-run]
```

`site` commands use the inventory when `--inventory` / `WP_MAINTENANCE_INVENTORY` is given or `config/websites.yaml` exists, unless the legacy `--config` registry is chosen explicitly. `audit-batch` resolves targets with the precedence described in [GITHUB_ACTIONS.md](GITHUB_ACTIONS.md), audits each site in isolation (bounded parallelism, per-site wall-clock limit, graceful cancellation), writes `reports/YYYY-MM-DD/{summary.md,summary.json,weekly-delta.md,sites/<id>/report.{md,json}}`, loads/saves per-site history in `--history-dir`, and on GitHub Actions appends the job summary and step outputs.

Batch exit codes: 0 pass/warnings, 2 findings need action, 3 invalid selection or inventory, 5 any incomplete audit, 7 any critical finding, 130 cancelled. `--fail-on` limits which conditions produce a non-zero code (`never` always returns 0 except for cancellation).
