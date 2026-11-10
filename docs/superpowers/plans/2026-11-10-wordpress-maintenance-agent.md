# WordPress Maintenance Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a reusable read-only WordPress maintenance CLI with evidence-backed public and authenticated checks, reports, agent integrations, installation, and weekend automation.

**Architecture:** A typed Python CLI validates YAML configuration and runs deterministic checks through a bounded HTTP client. Public checks record only observable evidence; private inventory uses a bearer-authenticated companion plugin. Codex and Claude integrations install platform-native instruction and skill files without overwriting existing content.

**Tech Stack:** Python 3.12+, httpx, Pydantic, PyYAML, defusedxml, pytest, PHP connector, GitHub Actions, PowerShell/Bash installers.

**Spec:** User-provided MASTER PROMPT — BUILD A GLOBAL WORDPRESS MAINTENANCE AGENT.

## Global Constraints

- Audit-only defaults; never remotely modify a production WordPress site.
- Unknown data remains `UNKNOWN` or `NOT_VERIFIABLE_WITH_PUBLIC_ACCESS`.
- Reject private, loopback, link-local, reserved, and metadata IP destinations.
- Restrict crawls to the configured website origin unless a hostname is explicitly approved.
- Validate every redirect destination; do not forward credentials across origins.
- Preserve existing global agent configuration and back it up before additive changes.
- Never commit credentials, live reports, or real site inventories.

## Review Focus

- DNS rebinding between validation and connection: DNS/IP pinning test and document residual limits.
- Large or malicious sitemap XML: size, depth, recursion, decompression, and entity tests.
- Redirects to a private host: validation before each followed request.
- Partial audit failures: status must remain `INCOMPLETE`, never `PASS`.
- Installer reruns and pre-existing user instructions: additive idempotent behavior and exact removal only for owned blocks.

---

### Task 1: Typed project foundation and safe URL policy

**Files:** `pyproject.toml`, `src/wp_maintenance/{__init__,models,config,security}.py`, `tests/test_config.py`, `tests/test_security.py`, examples and `.env.example`.

**Interfaces:** `load_config(path) -> AppConfig`; `validate_public_url(url, allowed_hosts=()) -> str`; strict Pydantic models for sites, audit, schedule, reports and safety.

- [ ] Add failing tests for multi-site config, missing IDs, invalid URL, localhost/private IP, approved additional host, and secret redaction.
- [ ] Implement configuration and URL policy.
- [ ] Run the focused tests.

### Task 2: Evidence collectors and HTTP safeguards

**Files:** `core_audit.py`, `plugin_audit.py`, `php_audit.py`, `sitemap.py`, `crawler.py`, `advisories.py`, `tests/test_audit.py`, `tests/test_sitemap.py`, `tests/test_crawler.py`.

**Interfaces:** asynchronous collectors return typed evidence records; public access reports unknown inventories without guessing. Use authoritative WordPress.org plugin/core APIs and PHP lifecycle data.

- [ ] Add mocked tests for core/plugin versions, unknown data, bounded XML parsing, redirects, HTTP status classes, timeout and retry behavior.
- [ ] Implement bounded collectors, same-origin redirect checks, rate/concurrency limits and optional vulnerability integrations.
- [ ] Run the focused tests.

### Task 3: Authenticated connector and reporting

**Files:** `wordpress-connector/wp-maintenance-connector.php`, `history.py`, `reporting.py`, `cli.py`, `tests/test_reporting.py`, sample report.

**Interfaces:** connector `GET /wp-json/wp-maintenance/v1/inventory` requires `manage_options` initially and application-password authentication; report generation emits per-site Markdown and aggregate JSON with findings, evidence, status and history deltas.

- [ ] Test report states and historical comparison with deterministic fixtures.
- [ ] Implement connector with explicit `permission_callback`, reports and CLI `init/site/audit/report/doctor` commands.
- [ ] Run unit tests and local CLI checks.

### Task 4: Agent integrations, packaging, installation and schedules

**Files:** `AGENTS.md`, `CLAUDE.md`, `agents/`, `skills/`, `scripts/`, `scheduler.py`, `.github/workflows/`, docs and repository metadata.

**Interfaces:** global install writes Codex `AGENTS.md` under active Codex home and skill under `~/.agents/skills`; Claude gets `~/.claude/CLAUDE.md` additive guidance and `~/.claude/skills`. Installer is additive and reversible. Schedule install/status provide Task Scheduler, cron and systemd instructions or setup.

- [ ] Test additive block ownership, idempotence, backups and uninstall.
- [ ] Implement installers, schedule commands, CI, docs, license and security policy.
- [ ] Run all available tests, CLI doctor, package build and workflow/config checks.

### Task 5: Publish and verify

**Files:** remote GitHub repository `Yousef-Abdallah-1711/wordpress-maintenance-agent`.

- [ ] Create the public repository if absent, commit the implementation, push the default branch and verify remote SHA and workflow state.
- [ ] Report implementation, tests, unverified platform behavior, active schedule status, installation results and blockers.
