"""Read-only page availability checks."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .http import SafeHttp


async def check_pages(urls: list[str], client: SafeHttp, *, concurrency: int = 5) -> list[dict[str, object]]:
    semaphore = asyncio.Semaphore(concurrency)

    async def one(url: str) -> dict[str, object]:
        async with semaphore:
            response = await client.get(url)
            status = response.status_code
            if response.error:
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
            return {"url": url, "final_url": response.final_url, "status": status,
                    "redirect_chain": response.redirect_chain, "elapsed_ms": round(response.elapsed_ms, 2),
                    "content_type": response.headers.get("content-type"), "classification": classification,
                    "checked_at": datetime.now(timezone.utc).isoformat(), "retries": response.retries,
                    "error": response.error}

    return await asyncio.gather(*(one(url) for url in urls))
