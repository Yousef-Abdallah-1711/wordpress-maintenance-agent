"""Evidence-aware week-over-week comparison. Missing evidence is never reported as a resolution."""

from __future__ import annotations

from typing import Any

BROKEN_4XX = {"missing"}
SERVER = {"server_error"}
REDIRECT_PROBLEMS = {"redirect_loop", "redirect_limit"}

# finding component -> coverage tags proving the relevant check ran this time
COMPONENT_COVERAGE = {
    "ssl": {"ssl_tls_inspection"}, "security headers": {"security_headers"}, "seo": {"technical_seo"},
    "http": {"homepage_http"}, "performance": {"homepage_http"}, "WordPress core": {"wordpress_core_metadata"},
    "plugin": {"public_plugin_asset_hints", "authenticated_plugin_inventory"},
    "plugin support": {"public_plugin_asset_hints", "authenticated_plugin_inventory"},
    "plugin compatibility": {"authenticated_plugin_inventory"},
    "PHP": {"php_header_disclosure", "authenticated_php_version"}, "security": {"wordfence_intelligence_v3"},
    "sitemap": {"sitemap_discovery"},
}


def _by_id(findings: list[dict]) -> dict[str, dict]:
    return {str(f.get("id")): f for f in findings}


def _pages(result: dict) -> dict[str, dict]:
    return {str(p.get("url")): p for p in result.get("pages", []) or []}


def _truncated(result: dict) -> bool:
    crawl = result.get("crawl") or {}
    return bool(crawl.get("sitemap_truncated") or crawl.get("halted_reason")
                or (crawl.get("urls_checked", 0) < crawl.get("sitemap_urls_listed", 0)))


def _check_resolution(finding: dict, current: dict, cur_pages: dict[str, dict], cur_plugins: set[str]) -> str | None:
    """None when the resolution is verified, otherwise the reason the evidence is missing."""
    if current.get("status") == "INCOMPLETE":
        return "the current audit is INCOMPLETE"
    component = finding.get("component")
    fid = str(finding.get("id"))
    coverage = set(current.get("coverage", []))
    if component == "page":
        url = (finding.get("evidence") or [""])[0]
        if url not in cur_pages:
            return "the page was not checked in the current run"
        return None
    required = COMPONENT_COVERAGE.get(str(component))
    if required is not None and not (required & coverage):
        return f"the {component} check did not run in the current audit"
    if component == "WordPress core" and not (current.get("wordpress") or {}).get("installed_version"):
        return "the WordPress version is no longer visible, so the update state cannot be re-evaluated"
    if component == "PHP" and not (current.get("php") or {}).get("installed_version"):
        return "the PHP version is no longer visible, so lifecycle state cannot be re-evaluated"
    if fid.startswith(("PLUGIN-UPDATE-", "PLUGIN-ABANDONED-")):
        slug = fid.split("-", 2)[2]
        if slug not in cur_plugins:
            return "the plugin is no longer observed in public evidence (public inventories are incomplete)"
    return None


def compute_delta(current: dict, previous: dict | None, *, previous_meta: dict | None = None,
                  unavailable_reason: str = "") -> dict[str, Any]:
    if previous is None:
        return {"available": False, "reason": unavailable_reason or "no previous audit evidence was loaded",
                "previous": None, "new": [], "resolved": [], "persistent": [], "unverified": [], "changes": [],
                "details": {}}
    cur, prev = _by_id(current.get("findings", [])), _by_id(previous.get("findings", []))
    cur_pages = _pages(current)
    prev_pages = _pages(previous)
    cur_plugins = {str(p.get("slug")) for p in current.get("plugins", []) or []}
    new = sorted(set(cur) - set(prev))
    persistent = sorted(set(cur) & set(prev))
    resolved, unverified = [], []
    for fid in sorted(set(prev) - set(cur)):
        reason = _check_resolution(prev[fid], current, cur_pages, cur_plugins)
        if reason is None:
            resolved.append(fid)
        else:
            unverified.append({"id": fid, "reason": reason})
    details = {fid: {"title": f.get("title"), "severity": f.get("severity"), "component": f.get("component")}
               for fid, f in {**prev, **cur}.items()}
    changes: list[dict[str, str]] = []

    def add(kind: str, detail: str) -> None:
        changes.append({"type": kind, "detail": detail})

    # --- pages / HTTP errors ---
    for url, page in sorted(cur_pages.items()):
        cls, before = page.get("classification"), prev_pages.get(url, {}).get("classification")
        if cls in BROKEN_4XX and before != cls:
            add("new_404", f"{url} now returns {page.get('status')}")
        if cls in SERVER and before != cls:
            add("new_5xx", f"{url} now returns {page.get('status')}")
        if cls in REDIRECT_PROBLEMS and before != cls:
            add("new_redirect_problem", f"{url}: {cls}")
        if url in prev_pages:
            if before in BROKEN_4XX and cls not in BROKEN_4XX:
                add("resolved_404", f"{url} now {page.get('status')} (verified by recheck)")
            if before in SERVER and cls not in SERVER:
                add("resolved_5xx", f"{url} now {page.get('status')} (verified by recheck)")
    both_complete = not _truncated(current) and not _truncated(previous)
    new_urls, gone_urls = sorted(set(cur_pages) - set(prev_pages)), sorted(set(prev_pages) - set(cur_pages))
    if both_complete:
        for url in new_urls[:50]:
            add("sitemap_url_added", url)
        for url in gone_urls[:50]:
            add("sitemap_url_removed", url)
    elif new_urls or gone_urls:
        unverified.append({"id": "sitemap-url-set", "reason":
            f"URL sets differ ({len(new_urls)} new, {len(gone_urls)} not checked) but coverage was partial in one of the runs"})
    # --- SSL ---
    cs, ps = current.get("ssl") or {}, previous.get("ssl") or {}
    if cs and ps:
        if cs.get("not_after") and ps.get("not_after") and cs["not_after"] != ps["not_after"]:
            kind = "ssl_renewed" if cs["not_after"] > ps["not_after"] else "ssl_changed"
            add(kind, f"certificate expiry {ps['not_after']} -> {cs['not_after']}")
        if cs.get("issuer") != ps.get("issuer") and cs.get("issuer") and ps.get("issuer"):
            add("ssl_issuer_changed", f"{ps['issuer']} -> {cs['issuer']}")
        if cs.get("error_kind") != ps.get("error_kind"):
            add("ssl_error_changed", f"{ps.get('error_kind') or 'none'} -> {cs.get('error_kind') or 'none'}")
        if cs.get("status") != ps.get("status"):
            add("ssl_status_changed", f"{ps.get('status')} -> {cs.get('status')} ({cs.get('days_remaining')} days left)")
    elif cs and not ps:
        unverified.append({"id": "ssl", "reason": "no previous TLS evidence to compare"})
    # --- WordPress / PHP / plugins ---
    cw, pw = current.get("wordpress") or {}, previous.get("wordpress") or {}
    if cw.get("installed_version") and pw.get("installed_version") and cw["installed_version"] != pw["installed_version"]:
        add("wordpress_version_changed", f"{pw['installed_version']} -> {cw['installed_version']} ({cw.get('version_status', 'unverified')})")
    elif bool(cw.get("installed_version")) != bool(pw.get("installed_version")):
        unverified.append({"id": "wordpress-version", "reason": "version evidence was available in only one of the two runs"})
    cp, pp = current.get("php") or {}, previous.get("php") or {}
    if cp.get("installed_version") and pp.get("installed_version") and cp["installed_version"] != pp["installed_version"]:
        add("php_version_changed", f"{pp['installed_version']} -> {cp['installed_version']}")
    cur_pl = {str(p.get("slug")): p for p in current.get("plugins", []) or []}
    prev_pl = {str(p.get("slug")): p for p in previous.get("plugins", []) or []}
    for slug, plugin in sorted(cur_pl.items()):
        old = prev_pl.get(slug)
        if old is None:
            add("plugin_reference_new", f"{slug} newly observed in public evidence")
        elif plugin.get("installed_version") and old.get("installed_version") and plugin["installed_version"] != old["installed_version"]:
            add("plugin_version_changed", f"{slug}: {old['installed_version']} -> {plugin['installed_version']}")
    for slug in sorted(set(prev_pl) - set(cur_pl)):
        unverified.append({"id": f"plugin-{slug}", "reason": "no longer observed; public inventories are incomplete, so removal is not proven"})
    for fid in new:
        if cur[fid].get("component") == "security":
            add("new_vulnerable_plugin", f"{fid}: {cur[fid].get('title')}")
    for fid in resolved:
        if prev[fid].get("component") == "security":
            add("resolved_vulnerability", f"{fid}: {prev[fid].get('title')}")
    # --- coverage ---
    cc, pc = set(current.get("coverage", [])), set(previous.get("coverage", []))
    if cc != pc:
        add("coverage_changed", f"added: {', '.join(sorted(cc - pc)) or 'none'}; removed: {', '.join(sorted(pc - cc)) or 'none'}")
    ccr, pcr = current.get("crawl") or {}, previous.get("crawl") or {}
    if ccr.get("urls_checked") != pcr.get("urls_checked"):
        add("page_coverage_changed", f"URLs checked {pcr.get('urls_checked', 0)} -> {ccr.get('urls_checked', 0)}")
    return {"available": True, "reason": "ok", "previous": previous_meta, "new": new, "resolved": resolved,
            "persistent": persistent, "unverified": unverified, "changes": changes, "details": details}
