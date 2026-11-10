# Report format

URL-mode and config-mode runs write `<reports>/<site>/latest.md|json` and an immutable `history/<timestamp>.md|json`; config-mode also writes `reports/YYYY-MM-DD/<site-id>.md`, `summary.md`, and `results.json`. Markdown includes site details, status, core/PHP evidence, plugin table, security findings, sitemap/page health, actions, history deltas and limitations. JSON contains typed site results and machine-readable findings.

Sections: 1 Website information, 2 Overall health, 3 SSL certificate, 4 WordPress core, 5 Plugin inventory and updates, 6 PHP runtime, 7 Sitemap discovery, 8 Page health (with `checked/listed` coverage), 9 Broken page URLs, 10 Security configuration, 11 Technical SEO and performance, 12 Previous audit comparison, 13 Prioritized maintenance actions (CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL checklist), 14 Evidence and sources, 15 Unknown or unverified information, 16 Final audit status.

`PASS` means all configured checks completed without findings; `PASS_WITH_WARNINGS` means there are material public-access or coverage limitations; `ACTION_REQUIRED` means evidence-backed findings exist; `INCOMPLETE` means one or more required checks failed. Unknown versions remain unknown and do not trigger an outdated finding. WordPress stable-check status comes from the official stable-check API and distinguishes `insecure` from a routine update.

## Batch reports (v0.3)

`reports/YYYY-MM-DD/summary.md|json` (totals, per-site table, SSL warnings, new/resolved counts, history availability), `weekly-delta.md` (new, resolved, persistent, unverified findings and detected changes per site) and `sites/<id>/report.md|json` (the 16-section report; `detailed` mode adds every checked URL). Resolution is reported only when the relevant check ran again; otherwise the change is *unverified*. JSON schema version 2 carries `report_version`, `run_id` and the delta.
