"""Public, read-only website checks: WordPress detection, headers, redirects, SEO, performance."""

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from .http import FetchResult, SafeHttp
from .models import Finding

PLUGIN_PATH_RE = re.compile(r"/wp-content/(?:plugins|mu-plugins)/([A-Za-z0-9._-]+)/", re.I)
PLUGIN_ASSET_RE = re.compile(r"""[^\s"'<>()=]*?/wp-content/plugins/([A-Za-z0-9_-]+)/[^\s"'<>()]*""", re.I)
VER_RE = re.compile(r"[?&](?:amp;|#038;)?ver=([0-9]+(?:\.[0-9A-Za-z_-]+)+)")


def discover_plugin_references(html: str) -> dict[str, dict[str, str]]:
    """Every exact /wp-content/plugins/<slug>/ reference in markup, inline scripts and JSON (escaped slashes)."""
    text = html.replace("\\/", "/")
    found: dict[str, dict[str, str]] = {}
    for match in PLUGIN_ASSET_RE.finditer(text):
        slug, url = match.group(1), match.group(0)
        entry = found.setdefault(slug, {"evidence_url": url[:300], "version_hint": "UNKNOWN"})
        ver = VER_RE.search(url)
        if ver and entry["version_hint"] == "UNKNOWN":
            entry["version_hint"] = ver.group(1)
    return found


def detect_wordpress(html: str, generator: str | None, rest: FetchResult | None, feed: FetchResult | None,
                     *, homepage_ok: bool) -> dict[str, object]:
    """Classify WordPress presence from public evidence only."""
    signals: list[str] = []
    text = html.replace("\\/", "/")
    if generator and re.search(r"wordpress", generator, re.I):
        signals.append("generator meta tag names WordPress")
    if "/wp-content/" in text:
        signals.append("HTML references /wp-content/")
    if "/wp-includes/" in text:
        signals.append("HTML references /wp-includes/")
    if re.search(r"rel=[\"']https://api\.w\.org/[\"']", text):
        signals.append("HTML links the WordPress REST API (api.w.org)")
    rest_confirmed = False
    if rest and rest.status_code == 200:
        try:
            data = json.loads(rest.body)
            namespaces = data.get("namespaces", []) if isinstance(data, dict) else []
            if any(str(ns).startswith("wp/") for ns in namespaces):
                rest_confirmed = True
                signals.append("/wp-json/ lists the wp/v2 REST namespace")
        except ValueError:
            pass
    feed_version = None
    if feed and feed.status_code == 200:
        match = re.search(r"<generator>https?://wordpress\.org/\?v=([0-9]+\.[0-9]+(?:\.[0-9]+)?)</generator>",
                          feed.body.decode("utf-8", "replace"))
        if match:
            feed_version = match.group(1)
            signals.append("RSS feed generator names WordPress")
    strong = rest_confirmed or feed_version or (generator and re.search(r"wordpress", generator, re.I))
    if strong:
        state = "CONFIRMED_WORDPRESS"
    elif len(signals) >= 2:
        state = "LIKELY_WORDPRESS"
    elif signals:
        state = "LIKELY_WORDPRESS"
    elif not homepage_ok:
        state = "UNKNOWN"
    else:
        state = "NOT_DETECTED"
    return {"state": state, "signals": signals, "feed_version": feed_version,
            "rest_url": rest.final_url if rest else None}


def alt_host(host: str) -> str | None:
    if host.count(".") < 1 or re.fullmatch(r"[0-9.]+", host) or ":" in host:
        return None
    return host[4:] if host.startswith("www.") else f"www.{host}"


async def check_https_redirect(host: str, client: SafeHttp) -> dict[str, object]:
    url = f"http://{host}/"
    response = await client.get(url)
    base = {"requested": url, "final_url": response.final_url, "status": response.status_code,
            "chain": response.redirect_chain, "evidence": f"GET {url} -> {response.status_code} ({response.final_url})"}
    if response.error and response.status_code is None:
        return {**base, "state": "UNREACHABLE", "detail": response.error}
    if response.error and ("loop" in response.error or "maximum redirects" in response.error):
        return {**base, "state": "BROKEN", "detail": response.error}
    final = urlsplit(response.final_url)
    if final.scheme == "https" and response.status_code and response.status_code < 400:
        return {**base, "state": "REDIRECTS_TO_HTTPS", "detail": "HTTP redirects to HTTPS."}
    if final.scheme == "https":
        return {**base, "state": "BROKEN", "detail": f"redirect target returned HTTP {response.status_code}"}
    if response.status_code and response.status_code < 400:
        return {**base, "state": "NO_REDIRECT", "detail": "HTTP served without redirect."}
    return {**base, "state": "UNREACHABLE", "detail": f"HTTP {response.status_code}"}


def _header(headers: dict[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name:
            return value
    return None


def analyze_security_headers(headers: dict[str, str], *, https: bool) -> tuple[dict[str, object], list[Finding]]:
    present = {}
    findings: list[Finding] = []
    csp = _header(headers, "content-security-policy")
    spec = [
        ("strict-transport-security", "HSTS", "low", "Add Strict-Transport-Security (e.g. max-age=31536000) once HTTPS is stable."),
        ("content-security-policy", "CSP", "low", "Define a Content-Security-Policy, starting in report-only mode to avoid breaking the site."),
        ("x-content-type-options", "X-Content-Type-Options", "low", "Send X-Content-Type-Options: nosniff."),
        ("referrer-policy", "Referrer-Policy", "informational", "Send a Referrer-Policy such as strict-origin-when-cross-origin."),
        ("permissions-policy", "Permissions-Policy", "informational", "Send a Permissions-Policy restricting unused browser features."),
    ]
    for header, label, severity, advice in spec:
        value = _header(headers, header)
        present[header] = value
        if header == "strict-transport-security" and not https:
            continue
        if value is None:
            findings.append(Finding(id=f"HDR-{label.upper().replace('-', '_')}", severity=severity, component="security headers",
                title=f"Missing {label} header", detail=f"{header} was not present in the homepage response.",
                evidence=["Homepage response headers"], recommendation=advice))
    frame = _header(headers, "x-frame-options")
    present["x-frame-options"] = frame
    if frame is None and not (csp and "frame-ancestors" in csp.lower()):
        findings.append(Finding(id="HDR-FRAME", severity="low", component="security headers",
            title="No clickjacking protection header", detail="Neither X-Frame-Options nor CSP frame-ancestors was present.",
            evidence=["Homepage response headers"], recommendation="Send X-Frame-Options or a CSP frame-ancestors directive."))
    hsts = present["strict-transport-security"]
    if hsts:
        m = re.search(r"max-age=(\d+)", hsts, re.I)
        if m and int(m.group(1)) < 15_552_000:
            findings.append(Finding(id="HDR-HSTS-SHORT", severity="informational", component="security headers",
                title="HSTS max-age is short", detail=f"Strict-Transport-Security: {hsts}",
                evidence=["Homepage response headers"], recommendation="Raise max-age to at least six months once stable."))
    return present, findings


def php_from_headers(headers: dict[str, str]) -> tuple[str | None, str | None]:
    """Return an explicitly disclosed PHP version and the header that disclosed it."""
    for name in ("x-powered-by", "x-php-version"):
        value = _header(headers, name)
        if value:
            m = re.search(r"PHP/?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", value, re.I)
            if m:
                return m.group(1), f"{name}: {value}"
    return None, None


def robots_policy(body: str) -> dict[str, object]:
    blocks_all = False
    agent_all = False
    for raw in body.splitlines():
        line = raw.split("#", 1)[0].strip()
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key, value = key.strip().lower(), value.strip()
        if key == "user-agent":
            agent_all = value == "*"
        elif key == "disallow" and agent_all and value == "/":
            blocks_all = True
    return {"blocks_all": blocks_all}


def analyze_seo(*, robots: FetchResult | None, canonical: str | None, meta_robots: str | None,
                x_robots: str | None, final_url: str) -> tuple[dict[str, object], list[Finding]]:
    findings: list[Finding] = []
    info: dict[str, object] = {"canonical": canonical, "meta_robots": meta_robots, "x_robots_tag": x_robots}
    if robots is not None:
        info["robots_txt_status"] = robots.status_code
        if robots.status_code == 200:
            policy = robots_policy(robots.body.decode("utf-8", "replace"))
            info["robots_blocks_all"] = policy["blocks_all"]
            if policy["blocks_all"]:
                findings.append(Finding(id="SEO-ROBOTS-BLOCKS-ALL", severity="high", component="seo",
                    title="robots.txt blocks all crawlers", detail="User-agent: * has Disallow: /",
                    evidence=["robots.txt"], recommendation="Confirm this is intentional; production sites normally allow crawling."))
        elif robots.status_code in {404, 410}:
            findings.append(Finding(id="SEO-NO-ROBOTS", severity="low", component="seo", title="robots.txt not found",
                detail=f"/robots.txt returned HTTP {robots.status_code}.", evidence=["robots.txt"],
                recommendation="Publish a robots.txt that references the sitemap."))
    for source, value in (("meta robots", meta_robots), ("X-Robots-Tag", x_robots)):
        if value and "noindex" in value.lower():
            findings.append(Finding(id=f"SEO-NOINDEX-{source.split()[0].upper().replace('-', '')}", severity="high", component="seo",
                title=f"Homepage carries a noindex directive ({source})", detail=f"{source}: {value}",
                evidence=["Homepage response"], recommendation="Remove noindex from the production homepage unless intentional."))
    if canonical is None:
        findings.append(Finding(id="SEO-NO-CANONICAL", severity="low", component="seo", title="Homepage has no canonical link",
            detail="No <link rel=\"canonical\"> was found.", evidence=["Homepage HTML"],
            recommendation="Add a canonical URL to avoid duplicate-content ambiguity."))
    else:
        c_host = (urlsplit(canonical).hostname or "").lower()
        f_host = (urlsplit(final_url).hostname or "").lower()
        if c_host and c_host != f_host:
            findings.append(Finding(id="SEO-CANONICAL-HOST", severity="medium", component="seo",
                title="Canonical host differs from the served host",
                detail=f"Canonical {canonical} vs served host {f_host}.", evidence=["Homepage HTML", final_url],
                recommendation="Align the canonical host, redirects and WordPress Site URL."))
    return info, findings


def analyze_performance(elapsed_ms: float) -> tuple[dict[str, object], list[Finding]]:
    findings: list[Finding] = []
    info = {"homepage_response_ms": round(elapsed_ms, 1),
            "note": "Server response time for the HTML document only; not Lighthouse or Core Web Vitals."}
    if elapsed_ms > 5000:
        findings.append(Finding(id="PERF-SLOW-HOMEPAGE", severity="medium", component="performance",
            title="Very slow homepage response", detail=f"Homepage took {elapsed_ms:.0f} ms.",
            evidence=["Measured by this audit from one location"], recommendation="Review caching, hosting capacity and slow plugins."))
    elif elapsed_ms > 2000:
        findings.append(Finding(id="PERF-SLOW-HOMEPAGE", severity="low", component="performance",
            title="Slow homepage response", detail=f"Homepage took {elapsed_ms:.0f} ms.",
            evidence=["Measured by this audit from one location"], recommendation="Review caching and server response time."))
    return info, findings
