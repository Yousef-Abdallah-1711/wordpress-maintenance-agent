"""Optional notifications. Disabled by default; GitHub Issues only when explicitly enabled and safe."""

from __future__ import annotations

import json
import subprocess
from typing import Callable, Protocol

Runner = Callable[[list[str]], tuple[int, str]]
LABEL = "wp-maintenance"


def gh_runner(args: list[str]) -> tuple[int, str]:
    """Run the GitHub CLI without a shell; arguments are always a list."""
    proc = subprocess.run(["gh", *args], capture_output=True, text=True, timeout=60)
    return proc.returncode, proc.stdout


class Notifier(Protocol):
    """Extension point: future Email/Slack/Discord/Webhook notifiers implement this interface."""
    name: str

    def notify(self, summary: dict, site_results: list[dict], deltas: dict[str, dict]) -> list[str]: ...


def _title(site_id: str, finding_id: str) -> str:
    return f"[WP Maintenance] {site_id}: {finding_id}"


class GitHubIssueNotifier:
    """One issue per critical finding: no duplicates, updated while it persists, closed only when verified resolved."""
    name = "github-issues"

    def __init__(self, repo: str, *, runner: Runner = gh_runner, allow_public: bool = False, run_url: str | None = None):
        self.repo, self.runner, self.allow_public, self.run_url = repo, runner, allow_public, run_url

    def _json(self, args: list[str]):
        code, out = self.runner(args)
        if code != 0:
            raise RuntimeError(f"gh {' '.join(args[:2])} failed")
        return json.loads(out or "null")

    def _find(self, title: str) -> dict | None:
        items = self._json(["issue", "list", "--repo", self.repo, "--state", "all", "--label", LABEL, "--search",
                            f'"{title}" in:title', "--json", "number,title,state", "--limit", "20"]) or []
        for item in items:
            if item.get("title") == title:
                return item
        return None

    def notify(self, summary: dict, site_results: list[dict], deltas: dict[str, dict]) -> list[str]:
        log: list[str] = []
        private = self._json(["api", f"repos/{self.repo}", "--jq", "{private: .private}"])
        if not (private or {}).get("private") and not self.allow_public:
            return ["GitHub Issues skipped: the repository is public. Pass --allow-public-issues only if reports may be public."]
        self.runner(["label", "create", LABEL, "--repo", self.repo, "--force", "--color", "B60205",
                     "--description", "Automated WordPress maintenance finding"])
        for result in site_results:
            sid = result["site_id"]
            critical = [f for f in result.get("findings", []) if f.get("severity") == "critical"]
            for finding in critical:
                title = _title(sid, finding["id"])
                body = (f"**Site:** {result.get('site_name')} ({result.get('url')})\n**Severity:** CRITICAL\n"
                        f"**Finding:** {finding.get('title')}\n\n{finding.get('detail')}\n\n"
                        f"**Action:** {finding.get('recommendation') or 'Investigate.'}\n"
                        + (f"\nLatest run: {self.run_url}\n" if self.run_url else ""))
                existing = self._find(title)
                if existing is None:
                    self.runner(["issue", "create", "--repo", self.repo, "--title", title, "--label", LABEL, "--body", body])
                    log.append(f"created issue: {title}")
                elif existing["state"].upper() == "OPEN":
                    self.runner(["issue", "comment", str(existing["number"]), "--repo", self.repo, "--body",
                                 f"Still present in run {summary.get('run_id')}.\n{self.run_url or ''}"])
                    log.append(f"updated issue #{existing['number']}: {title}")
                else:
                    self.runner(["issue", "reopen", str(existing["number"]), "--repo", self.repo, "--comment",
                                 f"Finding detected again in run {summary.get('run_id')}."])
                    log.append(f"reopened issue #{existing['number']}: {title}")
            delta = deltas.get(sid, {})
            for fid in delta.get("resolved", []):  # verified resolutions only
                if (delta.get("details", {}).get(fid) or {}).get("severity") != "critical":
                    continue
                existing = self._find(_title(sid, fid))
                if existing and existing["state"].upper() == "OPEN":
                    self.runner(["issue", "close", str(existing["number"]), "--repo", self.repo, "--comment",
                                 f"Resolution verified by a re-check in run {summary.get('run_id')}."])
                    log.append(f"closed issue #{existing['number']} (resolution verified)")
        return log


NOTIFIERS: dict[str, type] = {GitHubIssueNotifier.name: GitHubIssueNotifier}
