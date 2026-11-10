"""Previous audit selection and issue deltas."""

from __future__ import annotations

import json
from pathlib import Path


def previous_result(reports_dir: Path, site_id: str, current_run: Path | None = None) -> dict | None:
    candidates = sorted(reports_dir.rglob("results.json"), reverse=True)
    for path in candidates:
        if current_run and path.resolve() == current_run.resolve():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for item in data.get("sites", []):
            if item.get("site_id") == site_id:
                return item
    return None


def compare_results(current: dict, previous: dict | None) -> dict[str, list[str]]:
    if not previous:
        return {"new": [], "resolved": [], "persistent": []}
    now = {finding.get("id", "") for finding in current.get("findings", [])}
    before = {finding.get("id", "") for finding in previous.get("findings", [])}
    return {"new": sorted(now - before), "resolved": sorted(before - now), "persistent": sorted(now & before)}
