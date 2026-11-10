# Changelog

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
