# Report format

Each run writes `reports/YYYY-MM-DD/<site-id>.md`, `summary.md`, and `results.json`. Markdown includes site details, status, core/PHP evidence, plugin table, security findings, sitemap/page health, actions, history deltas and limitations. JSON contains typed site results and machine-readable findings.

`PASS` means all configured checks completed without findings; `PASS_WITH_WARNINGS` means there are material public-access or coverage limitations; `ACTION_REQUIRED` means evidence-backed findings exist; `INCOMPLETE` means one or more required checks failed. Unknown versions remain unknown and do not trigger an outdated finding. WordPress stable-check status comes from the official stable-check API and distinguishes `insecure` from a routine update.
