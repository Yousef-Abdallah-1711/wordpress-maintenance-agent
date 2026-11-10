# Changelog

## 0.3.0 - 2026-11-10

- GitHub Actions is now the primary automation platform: `WordPress Maintenance Audit` workflow with a native `Africa/Cairo` Sunday 03:00 schedule, manual inputs (`audit_scope` all/single/custom_url, `site_id`, `custom_url`, `max_urls`, `report_mode`), job summary, annotations, fail policy, pinned actions and least-privilege permissions.
- Persistent website inventory `config/websites.yaml` with strict schema, duplicate/SSRF/credential rejection, comment-preserving atomic edits; `site add|remove|enable|disable|show|validate`; `WP_MAINTENANCE_URLS` compatibility with documented precedence.
- `audit-batch`: bounded multi-site execution with per-site isolation, timeouts, cancellation; `summary.md|json`, `weekly-delta.md`, per-site reports.
- Persistent history (private history repository via deploy key, or artifact backend), retention, evidence-aware week-over-week comparison (resolved only when re-verified).
- Optional GitHub Issues notifier for critical findings and an extensible notifier interface; robots.txt-respecting crawl (`respect_robots_txt`).
- `scripts/setup-private-history.sh|ps1` (private history repository + single-repo deploy key), `wp-maintenance history list|show`, verified conflict-safe append-only history save, step-summary confirmation of the saved snapshot.
- Replaces the 0.2 workflow and its `WP_MAINTENANCE_CONFIG_B64` secret flow.

## 0.2.0 — 2026-11-10

- Zero-config `wp-maintenance audit <url>` / `--url`; URL normalization with SSRF validation; `site add <url>`, `site remove`, `schedule install --weekly --day --time --timezone`, `schedule remove`.
- New SSL/TLS module (expiry classes, hostname/trust/chain/handshake failures, HTTP to HTTPS redirect) with configurable thresholds and diagnostic-only metadata after failed verification.
- WordPress detection states (REST, feed, generator, asset signals), richer public plugin discovery with evidence URLs and classifications, PHP header disclosure, security-header, technical-SEO and response-time checks.
- Crawl coverage reporting (`checked/listed`), runtime cap, WAF/rate-limit halt, cancellation.
- 16-section report, `<site>/latest.*` plus immutable `history/`, consolidated summary, previous-audit deltas.
- Installer updates outdated managed blocks/skills in place; skill backups no longer land inside skills folders.
- Status: only medium-or-higher findings yield `ACTION_REQUIRED`; the informational severity was added.

## 0.1.0 — 2026-11-10

- Initial read-only CLI, public evidence collection, sitemap crawling, authenticated connector, reports, native agent skills, installers and scheduling integrations.
- Optional Wordfence Intelligence V3 integration matches exact slugs and version ranges when an API key is configured.
