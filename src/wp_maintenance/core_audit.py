"""WordPress core version discovery and official update lookup."""

from __future__ import annotations

import json
import re
from urllib.parse import urlencode

from packaging.version import InvalidVersion, Version
from .http import SafeHttp

VERSION_RE = re.compile(r"WordPress\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I)


async def audit_core(site_url: str, html: str, client: SafeHttp) -> dict[str, object]:
    match = VERSION_RE.search(html)
    installed = match.group(1) if match else None
    evidence = "public HTML generator metadata" if installed else "no reliable public version marker"
    result: dict[str, object] = {"installed_version": installed, "latest_official": None,
                                 "update_available": None,
                                 "security_relevance": None,
                                 "source": "https://api.wordpress.org/core/version-check/1.7/",
                                 "evidence": evidence, "confidence": "medium" if installed else "unknown"}
    if not installed:
        result["lookup_error"] = "installed core version is not exposed; no update comparison was attempted"
        return result
    response = await client.get(result["source"] + "?" + urlencode({"version": installed}))
    if response.status_code == 200:
        try:
            payload = json.loads(response.body)
            offers = payload.get("offers", []) if isinstance(payload, dict) else []
            stable = [offer for offer in offers if isinstance(offer, dict) and offer.get("response") == "autoupdate"]
            versions = [str(offer.get("version")) for offer in stable if offer.get("version")]
            if versions:
                result["latest_official"] = versions[0]
                try:
                    result["update_available"] = Version(installed) < Version(versions[0])
                except InvalidVersion:
                    result["update_available"] = None
                result["retrieved_from"] = result["source"]
        except (ValueError, TypeError):
            result["lookup_error"] = "official version response was not valid JSON"
    else:
        result["lookup_error"] = response.error or f"official version API returned HTTP {response.status_code}"
    if installed:
        stable_url = "https://api.wordpress.org/core/stable-check/1.0/?" + urlencode({"version": installed})
        stable = await client.get(stable_url)
        if stable.status_code == 200:
            try:
                statuses = json.loads(stable.body)
                status = str(statuses.get(installed, "")).strip().lower() if isinstance(statuses, dict) else ""
            except (ValueError, TypeError):
                status = ""
            if status in {"latest", "outdated", "insecure"}:
                result["stability_status"] = status
                result["security_relevance"] = status == "insecure"
                result["stability_source"] = stable_url
                if status == "latest":
                    result["update_available"] = False
                elif status in {"outdated", "insecure"}:
                    result["update_available"] = True
            else:
                result["stability_error"] = "official stable-check response did not contain a recognized status for the installed version"
        else:
            result["stability_error"] = stable.error or f"official stable-check API returned HTTP {stable.status_code}"
    return result
