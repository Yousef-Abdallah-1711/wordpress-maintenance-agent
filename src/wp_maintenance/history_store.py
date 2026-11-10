"""Append-only per-site audit snapshots used for week-over-week comparison."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import __version__

SCHEMA_VERSION = 2
SAFE_COMPONENT = re.compile(r"[^A-Za-z0-9_.-]+")


@dataclass
class Snapshot:
    path: Path
    run_id: str
    saved_at: datetime
    result: dict


def _safe(value: str) -> str:
    return SAFE_COMPONENT.sub("-", value).strip("-.") or "x"


def save_snapshot(history_dir: Path, result: dict, *, run_id: str, now: datetime | None = None) -> Path:
    """Write history/<site>/<UTC timestamp>-<run>.json. Never overwrites an existing snapshot."""
    now = now or datetime.now(timezone.utc)
    site_dir = history_dir / _safe(str(result["site_id"]))
    site_dir.mkdir(parents=True, exist_ok=True)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    payload = {"schema_version": SCHEMA_VERSION, "report_version": __version__, "run_id": str(run_id),
               "site_id": result["site_id"], "saved_at": now.isoformat(), "result": result}
    counter = 0
    while True:
        suffix = "" if counter == 0 else f"-{counter}"
        target = site_dir / f"{stamp}-{_safe(str(run_id))}{suffix}.json"
        try:
            with target.open("x", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False)
            return target
        except FileExistsError:
            counter += 1


def _read(path: Path) -> Snapshot | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("schema_version") not in (1, SCHEMA_VERSION) or not isinstance(data.get("result"), dict):
            return None
        saved = datetime.fromisoformat(data["saved_at"])
        if saved.tzinfo is None:
            saved = saved.replace(tzinfo=timezone.utc)
        return Snapshot(path, str(data.get("run_id", "")), saved, data["result"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def list_snapshots(history_dir: Path, site_id: str) -> list[Snapshot]:
    site_dir = history_dir / _safe(site_id)
    if not site_dir.is_dir():
        return []
    items = [s for s in (_read(p) for p in sorted(site_dir.glob("*.json"))) if s is not None]
    return sorted(items, key=lambda s: s.saved_at)


def load_previous(history_dir: Path, site_id: str, *, exclude_run_id: str | None = None) -> tuple[Snapshot | None, str]:
    """Most recent previous *valid* snapshot (evidence present and not INCOMPLETE) and a reason string."""
    snaps = [s for s in list_snapshots(history_dir, site_id) if s.run_id != exclude_run_id]
    if not snaps:
        return None, "no previous snapshot exists for this site"
    for snap in reversed(snaps):
        result = snap.result
        if result.get("status") != "INCOMPLETE" and result.get("coverage"):
            return snap, "ok"
    return None, "previous snapshots exist but none is a valid (complete) audit"


def prune(history_dir: Path, *, retention_days: int, now: datetime | None = None, keep_latest: int = 2) -> int:
    """Delete snapshots older than retention_days, always keeping the newest `keep_latest` per site."""
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=retention_days)
    removed = 0
    if not history_dir.is_dir():
        return 0
    for site_dir in (d for d in history_dir.iterdir() if d.is_dir()):
        snaps = list_snapshots(history_dir, site_dir.name)
        for snap in snaps[:-keep_latest] if keep_latest else snaps:
            if snap.saved_at < cutoff:
                snap.path.unlink(missing_ok=True)
                removed += 1
    return removed
