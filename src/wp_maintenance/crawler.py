"""Read-only page availability checks."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .http import SafeHttp


async def check_pages(urls: list[str], client: SafeHttp, *, concurrency: int = 5,
                      excluded_paths: tuple[str, ...] = (), deadline_seconds: float | None = None,
                      stats: dict[str, object] | None = None) -> list[dict[str, object]]:
    """Check URLs politely. Stops (never bypasses) when the deadline passes or the site blocks automation."""
    semaphore = asyncio.Semaphore(concurrency)
    started = time.monotonic()
    state = {"blocked": 0, "done": 0, "halt": None}

    async def one(url: str) -> dict[str, object] | None:
        async with semaphore:
            if state["halt"]:
                return None
            if deadline_seconds is not None and time.monotonic() - started > deadline_seconds:
                state["halt"] = "time limit reached"
                return None
            response = await client.get(url, blocked_paths=excluded_paths)
            status = response.status_code
            if response.error and "excluded by site policy" in response.error:
                classification = "excluded"
            elif response.error:
                classification = "timeout" if "Timeout" in response.error else "redirect_loop" if "redirect loop" in response.error else "redirect_limit" if "maximum redirects" in response.error else "tls_error" if "CERTIFICATE_VERIFY_FAILED" in response.error else "network_or_policy_error"
            elif response.status_code is None:
                classification = "network_failure"
            elif status == 429:
                classification = "rate_limited"
            elif status in {401, 403, 451}:
                classification = "access_restricted"
            elif status in {404, 410}:
                classification = "missing"
            elif status >= 500:
                classification = "server_error"
            elif response.redirect_chain:
                classification = "redirect"
            elif 200 <= status < 300:
                classification = "available"
            else:
                classification = "client_error"
            state["done"] += 1
            if classification in {"rate_limited", "access_restricted"}:
                state["blocked"] += 1
            if state["blocked"] >= 10 and state["blocked"] / max(state["done"], 1) >= 0.5:
                state["halt"] = "site is rate limiting or blocking automated requests (not bypassed)"
            return {"url": url, "final_url": response.final_url, "status": status,
                    "redirect_chain": response.redirect_chain, "elapsed_ms": round(response.elapsed_ms, 2),
                    "content_type": response.headers.get("content-type"), "classification": classification,
                    "checked_at": datetime.now(timezone.utc).isoformat(), "retries": response.retries,
                    "error": response.error}

    try:
        results = [item for item in await asyncio.gather(*(one(url) for url in urls)) if item is not None]
    except asyncio.CancelledError:
        state["halt"] = "crawl cancelled"
        raise
    if stats is not None:
        stats.update(requested=len(urls), checked=len(results), halted_reason=state["halt"])
    return results
