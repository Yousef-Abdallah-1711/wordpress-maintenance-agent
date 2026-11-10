import json
import socket
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
import respx
import yaml

from wp_maintenance import cli
from wp_maintenance.audit import audit_site
from wp_maintenance.http import SafeHttp
from wp_maintenance.models import AppConfig, AuditResult, Finding
from wp_maintenance.reporting import _md, site_slug, write_site_layout
from wp_maintenance.site_checks import (analyze_security_headers, analyze_seo, check_https_redirect, detect_wordpress,
                                        discover_plugin_references, php_from_headers, robots_policy)
from wp_maintenance.urlmode import InvalidSiteUrl, build_url_config, normalize_site_url

PUBLIC = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]


@pytest.fixture(autouse=True)
def public_dns(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **k: PUBLIC)


# ---------- URL normalization and SSRF ----------

@pytest.mark.parametrize("raw,expected", [
    ("https://www.juhayna.com", "https://www.juhayna.com"),
    ("juhayna.com", "https://juhayna.com"),
    ("  HTTPS://Example.COM/some/path?q=1#frag ", "https://example.com"),
    ("http://example.com/", "http://example.com"),
])
def test_url_normalization_reduces_to_the_audit_origin(raw, expected):
    assert normalize_site_url(raw) == expected


@pytest.mark.parametrize("raw", [
    "", "   ", "ftp://example.com", "file:///etc/passwd", "javascript:alert(1)", "https://user:pw@example.com",
    "https://localhost", "https://127.0.0.1", "http://169.254.169.254/latest/meta-data", "https://10.0.0.5",
    "https://[::1]/", "https://intranet", "https://example.com:8443", "https://exa mple.com", "https://",
    "http://service.local",
])
def test_invalid_and_ssrf_targets_are_rejected(raw):
    with pytest.raises(InvalidSiteUrl):
        normalize_site_url(raw)


def test_hostname_resolving_to_private_address_is_rejected(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.10", 443))])
    with pytest.raises(InvalidSiteUrl, match="non-public"):
        normalize_site_url("https://innocent.example.com")


def test_zero_config_builds_a_complete_configuration_without_yaml(tmp_path):
    config = build_url_config("https://www.juhayna.com", reports_dir=tmp_path, max_pages=50)
    site = config.sites[0]
    assert site.id == "juhayna-com" and str(site.url) == "https://www.juhayna.com/"
    assert site.approved_hosts == ["juhayna.com"]
    assert config.audit.max_pages == 50 and config.safety["read_only"] is True
    assert site_slug("https://www.juhayna.com/x") == "juhayna-com"


class _Captured:
    config = None


def _fake_run(monkeypatch):
    seen = {}

    async def run_audit(config, ids):
        seen["config"], seen["ids"] = config, ids
        site = config.sites[0]
        return [AuditResult(site_id=site.id, site_name=site.name, url=str(site.url).rstrip("/"), environment="production",
                            access_mode="public", status="PASS_WITH_WARNINGS", coverage=["homepage_http"])]
    monkeypatch.setattr(cli, "run_audit", run_audit)
    return seen


def _args(**kw):
    base = dict(target=None, url=None, all=False, site=None, config=None, output=None, max_pages=None,
                concurrency=None, mode="read-only")
    base.update(kw)
    return SimpleNamespace(**base)


def test_positional_url_audits_without_configuration(monkeypatch, tmp_path, capsys):
    seen = _fake_run(monkeypatch)
    code = cli._cmd_audit(_args(target="https://www.juhayna.com", output=str(tmp_path)))
    assert code == cli.EXIT_OK
    assert seen["ids"] == {"juhayna-com"}
    assert (tmp_path / "juhayna-com" / "latest.md").is_file()
    assert (tmp_path / "juhayna-com" / "latest.json").is_file()
    assert "latest.md" in capsys.readouterr().out


def test_url_flag_is_equivalent_to_positional(monkeypatch, tmp_path):
    seen = _fake_run(monkeypatch)
    assert cli._cmd_audit(_args(url="juhayna.com", output=str(tmp_path))) == cli.EXIT_OK
    assert seen["ids"] == {"juhayna-com"}


def test_cli_parser_accepts_both_url_forms():
    parser = cli._parser()
    assert parser.parse_args(["audit", "https://a.example.com"]).target == "https://a.example.com"
    assert parser.parse_args(["audit", "--url", "https://a.example.com"]).url == "https://a.example.com"


def test_invalid_url_is_a_configuration_error_and_makes_no_requests(monkeypatch, capsys):
    seen = _fake_run(monkeypatch)
    assert cli._cmd_audit(_args(target="http://169.254.169.254/")) == cli.EXIT_CONFIGURATION
    assert "config" not in seen
    assert "Invalid URL" in capsys.readouterr().err


def test_conflicting_url_arguments_are_rejected(monkeypatch):
    _fake_run(monkeypatch)
    assert cli._cmd_audit(_args(target="https://a.example.com", url="https://b.example.com")) == cli.EXIT_CONFIGURATION
    assert cli._cmd_audit(_args(target="https://a.example.com", all=True)) == cli.EXIT_CONFIGURATION


# ---------- WordPress detection, plugins, PHP ----------

def fetch(status=200, body=b"", url="https://example.com/x"):
    from wp_maintenance.http import FetchResult
    return FetchResult(url, url, status, {}, body)


def test_wordpress_detection_states():
    rest = fetch(body=json.dumps({"namespaces": ["oembed/1.0", "wp/v2"]}).encode())
    assert detect_wordpress("", None, rest, None, homepage_ok=True)["state"] == "CONFIRMED_WORDPRESS"
    assert detect_wordpress("", "WordPress 6.8.1", None, None, homepage_ok=True)["state"] == "CONFIRMED_WORDPRESS"
    likely = detect_wordpress('<link href="/wp-content/themes/x/style.css"><script src="/wp-includes/js/a.js">', None, None, None, homepage_ok=True)
    assert likely["state"] == "LIKELY_WORDPRESS"
    assert detect_wordpress("<html>static</html>", None, None, None, homepage_ok=True)["state"] == "NOT_DETECTED"
    assert detect_wordpress("", None, None, None, homepage_ok=False)["state"] == "UNKNOWN"
    feed = fetch(body=b"<rss><generator>https://wordpress.org/?v=6.7.2</generator></rss>")
    detected = detect_wordpress("", None, None, feed, homepage_ok=True)
    assert detected["state"] == "CONFIRMED_WORDPRESS" and detected["feed_version"] == "6.7.2"


def test_plugin_discovery_reads_css_js_json_and_escaped_paths_without_trusting_ver():
    html = ('<link href="https://x.com/wp-content/plugins/elementor/assets/css/a.css?ver=3.2.1">'
            '<script>var u="https:\\/\\/x.com\\/wp-content\\/plugins\\/woocommerce\\/assets\\/js\\/b.js";</script>'
            '<img src="/wp-content/uploads/2024/a.png?ver=9.9.9">')
    found = discover_plugin_references(html)
    assert set(found) == {"elementor", "woocommerce"}
    assert found["elementor"]["version_hint"] == "3.2.1"
    assert found["woocommerce"]["version_hint"] == "UNKNOWN"
    assert "wp-content/plugins/woocommerce" in found["woocommerce"]["evidence_url"]


def test_php_version_only_from_explicit_headers():
    assert php_from_headers({"X-Powered-By": "PHP/8.1.27"}) == ("8.1.27", "x-powered-by: PHP/8.1.27")
    assert php_from_headers({"Server": "Apache/2.4.58 (Ubuntu)", "X-Powered-By": "WP Engine"}) == (None, None)
    assert php_from_headers({"Server": "nginx"}) == (None, None)


def test_security_headers_are_risk_ranked_not_critical():
    present, findings = analyze_security_headers({}, https=True)
    assert findings and all(f.severity in {"low", "informational"} for f in findings)
    _, none_needed = analyze_security_headers({"Strict-Transport-Security": "max-age=31536000", "Content-Security-Policy": "frame-ancestors 'self'",
        "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=()"}, https=True)
    assert none_needed == []
    _, http_only = analyze_security_headers({}, https=False)
    assert "HDR-HSTS" not in {f.id for f in http_only}


def test_seo_findings_for_noindex_blocked_robots_and_canonical_host():
    robots = fetch(body=b"User-agent: *\nDisallow: /\n")
    assert robots_policy(robots.body.decode())["blocks_all"] is True
    info, findings = analyze_seo(robots=robots, canonical="https://other.example/", meta_robots="noindex, follow",
                                 x_robots=None, final_url="https://example.com/")
    ids = {f.id for f in findings}
    assert {"SEO-ROBOTS-BLOCKS-ALL", "SEO-NOINDEX-META", "SEO-CANONICAL-HOST"} <= ids


@pytest.mark.asyncio
@respx.mock
async def test_https_redirect_states():
    respx.get("http://example.com/").mock(return_value=httpx.Response(301, headers={"location": "https://example.com/"}))
    respx.get("https://example.com/").mock(return_value=httpx.Response(200, text="ok"))
    async with SafeHttp(delay=0, retries=0, allowed_hosts={"example.com"}) as client:
        assert (await check_https_redirect("example.com", client))["state"] == "REDIRECTS_TO_HTTPS"
    respx.get("http://plain.example.com/").mock(return_value=httpx.Response(200, text="served over http"))
    async with SafeHttp(delay=0, retries=0, allowed_hosts={"plain.example.com"}) as client:
        assert (await check_https_redirect("plain.example.com", client))["state"] == "NO_REDIRECT"
    respx.get("http://loop.example.com/").mock(return_value=httpx.Response(302, headers={"location": "http://loop.example.com/"}))
    async with SafeHttp(delay=0, retries=0, allowed_hosts={"loop.example.com"}) as client:
        assert (await check_https_redirect("loop.example.com", client))["state"] == "BROKEN"


@pytest.mark.asyncio
@respx.mock
async def test_redirect_to_private_or_unapproved_host_is_refused():
    respx.get("https://example.com/").mock(return_value=httpx.Response(302, headers={"location": "http://169.254.169.254/"}))
    async with SafeHttp(delay=0, retries=0, allowed_hosts={"example.com"}) as client:
        result = await client.get("https://example.com/")
    assert result.status_code is None and "UnsafeTarget" in result.error


# ---------- full URL-only audit ----------

def sitemap_xml(urls):
    body = "".join(f"<url><loc>{u}</loc></url>" for u in urls)
    return f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{body}</urlset>'.encode()


def mock_site(extra_pages=None, home_headers=None, sitemap_count=3, statuses=None):
    html = ('<html><head><meta name="generator" content="WordPress 6.8.1">'
            '<link rel="canonical" href="https://example.com/">'
            '<script src="/wp-content/plugins/contact-form-7/js/a.js?ver=5.9.1"></script></head></html>')
    respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=html, headers=home_headers or {"X-Powered-By": "PHP/7.4.33"}))
    respx.get("https://example.com/robots.txt").mock(return_value=httpx.Response(200, text="Sitemap: https://example.com/sitemap_index.xml\n"))
    index = ('<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
             '<sitemap><loc>https://example.com/post-sitemap.xml</loc></sitemap></sitemapindex>').encode()
    respx.get("https://example.com/sitemap_index.xml").mock(return_value=httpx.Response(200, content=index))
    urls = [f"https://example.com/p{i}" for i in range(sitemap_count)]
    respx.get("https://example.com/post-sitemap.xml").mock(return_value=httpx.Response(200, content=sitemap_xml(urls)))
    for path in ("/wp-sitemap.xml", "/sitemap.xml"):
        respx.get(f"https://example.com{path}").mock(return_value=httpx.Response(404))
    for i, url in enumerate(urls):
        code = (statuses or {}).get(i, 200)
        respx.get(url).mock(return_value=httpx.Response(code, text="x"))
    respx.get("https://example.com/wp-json/").mock(return_value=httpx.Response(200, json={"namespaces": ["wp/v2"]}))
    respx.get("http://example.com/").mock(return_value=httpx.Response(301, headers={"location": "https://example.com/"}))
    respx.get("https://www.example.com/").mock(return_value=httpx.Response(301, headers={"location": "https://example.com/"}))
    respx.get("https://api.wordpress.org/core/version-check/1.7/").mock(return_value=httpx.Response(200, json={"offers": [{"response": "autoupdate", "version": "6.8.3"}]}))
    respx.get("https://api.wordpress.org/core/stable-check/1.0/").mock(return_value=httpx.Response(200, json={"6.8.1": "outdated"}))
    respx.get("https://api.wordpress.org/plugins/info/1.2/").mock(return_value=httpx.Response(200, json={"name": "Contact Form 7", "version": "6.0", "last_updated": "2026-10-01 00:00:00"}))


def cfg(tmp_path, **audit):
    audit.setdefault("per_host_delay_seconds", 0)
    audit.setdefault("retries", 0)
    config = build_url_config("https://example.com", reports_dir=tmp_path)
    for key, value in audit.items():
        setattr(config.audit, key, value)
    return config


@pytest.mark.asyncio
@respx.mock
async def test_url_only_audit_collects_every_public_evidence_class(tmp_path, monkeypatch):
    monkeypatch.delenv("WORDFENCE_API_KEY", raising=False)
    mock_site(statuses={1: 404, 2: 500})
    config = cfg(tmp_path)
    result = await audit_site(config.sites[0], config)
    assert result.wordpress["detection"] == "CONFIRMED_WORDPRESS"
    assert result.wordpress["version_status"] == "PUBLICLY_INDICATED_UNVERIFIED"
    assert result.php["installed_version"] == "7.4.33" and result.php["support_status"] == "END_OF_LIFE"
    assert result.ssl["status"] == "HEALTHY" and result.ssl["https_redirect"]["state"] == "REDIRECTS_TO_HTTPS"
    plugin = result.plugins[0]
    assert plugin["slug"] == "contact-form-7" and plugin["classification"] == "VERSION_UNKNOWN"
    assert plugin["installed_version"] is None and plugin["asset_version_hint"] == "5.9.1"
    assert result.sitemaps["urls_discovered"] == 3 and len(result.pages) == 3
    classes = sorted(p["classification"] for p in result.pages)
    assert classes == ["available", "missing", "server_error"]
    ids = {f.id for f in result.findings}
    assert {"WP-CORE-UPDATE", "PHP-END-OF-LIFE", "PHP-VERSION-DISCLOSED"} <= ids
    assert result.status == "ACTION_REQUIRED"
    assert "Page coverage is partial" not in " ".join(result.limitations)
    assert result.crawl["urls_checked"] == 3


@pytest.mark.asyncio
@respx.mock
async def test_unknown_php_is_reported_as_unknown_not_guessed(tmp_path, monkeypatch):
    monkeypatch.delenv("WORDFENCE_API_KEY", raising=False)
    mock_site(home_headers={"Server": "nginx"})
    config = cfg(tmp_path)
    result = await audit_site(config.sites[0], config)
    assert result.php["installed_version"] is None
    assert "UNKNOWN — AUTHENTICATED VERIFICATION REQUIRED" in result.php["message"]
    assert not any(f.id.startswith("PHP-") for f in result.findings)


@pytest.mark.asyncio
@respx.mock
async def test_partial_crawl_reports_checked_over_listed(tmp_path, monkeypatch):
    monkeypatch.delenv("WORDFENCE_API_KEY", raising=False)
    mock_site(sitemap_count=8)
    config = cfg(tmp_path, max_pages=5)
    result = await audit_site(config.sites[0], config)
    assert result.crawl["urls_checked"] == 5 and result.sitemaps["truncated"] is True
    assert any("Page coverage is partial: 5/" in item for item in result.limitations)
    assert not any(f.id == "SITEMAP-INVALID" for f in result.findings)
    assert "**5/" in _md(result, {"new": [], "resolved": [], "persistent": []})


@pytest.mark.asyncio
@respx.mock
async def test_crawl_stops_instead_of_bypassing_a_blocking_waf(tmp_path, monkeypatch):
    monkeypatch.delenv("WORDFENCE_API_KEY", raising=False)
    mock_site(sitemap_count=40, statuses={i: 429 for i in range(40)})
    config = cfg(tmp_path, concurrency=1, max_pages=40)
    result = await audit_site(config.sites[0], config)
    assert result.crawl["halted_reason"] and "not bypassed" in result.crawl["halted_reason"]
    assert len(result.pages) < 40
    assert result.status == "INCOMPLETE" and any("stopped early" in e for e in result.errors)


@pytest.mark.asyncio
@respx.mock
async def test_blocked_homepage_marks_the_audit_incomplete(tmp_path, monkeypatch):
    monkeypatch.delenv("WORDFENCE_API_KEY", raising=False)
    respx.get("https://example.com/").mock(return_value=httpx.Response(403, text="blocked"))
    config = cfg(tmp_path, sitemaps=False)
    result = await audit_site(config.sites[0], config)
    assert result.status == "INCOMPLETE" and result.wordpress["detection"] in {"UNKNOWN", "NOT_DETECTED"}


# ---------- reports ----------

def test_markdown_contains_every_required_section(tmp_path):
    result = AuditResult(site_id="s", site_name="S", url="https://example.com", environment="production", access_mode="public",
                         status="ACTION_REQUIRED", findings=[Finding(id="X", severity="critical", component="ssl", title="t", detail="d")])
    text = _md(result, {"new": [], "resolved": [], "persistent": []})
    for heading in ["Website Information", "Overall Health", "SSL Certificate", "WordPress Core", "Plugin Inventory",
                    "PHP Runtime", "Sitemap Discovery", "Page Health", "Broken Page URLs", "Security Configuration",
                    "Technical SEO", "Previous Audit Comparison", "Prioritized Maintenance Actions", "Evidence and Sources",
                    "Unknown or Unverified", "Final Audit Status"]:
        assert heading in text
    assert "### CRITICAL" in text and "PHP VERSION: UNKNOWN — AUTHENTICATED VERIFICATION REQUIRED" in text


def test_layout_preserves_history_and_reports_deltas(tmp_path):
    def result(ids):
        return AuditResult(site_id="juhayna-com", site_name="x", url="https://x", environment="production", access_mode="public",
                           status="ACTION_REQUIRED", findings=[Finding(id=i, severity="medium", component="c", title=i, detail=i) for i in ids])
    first = write_site_layout([result(["A", "B"])], tmp_path)
    second = write_site_layout([result(["B", "C"])], tmp_path)
    site = tmp_path / "juhayna-com"
    assert len(list((site / "history").glob("*.md"))) == 2 and len(list((site / "history").glob("*.json"))) == 2
    latest = json.loads((site / "latest.json").read_text(encoding="utf-8"))
    assert latest["previous_audit"] == {"new": ["C"], "resolved": ["A"], "persistent": ["B"]}
    assert first["juhayna-com"]["markdown"] == second["juhayna-com"]["markdown"]
    assert (tmp_path / "latest-summary.md").is_file()


def test_json_report_round_trips_ssl_and_crawl_fields(tmp_path):
    r = AuditResult(site_id="s", site_name="S", url="https://e.com", environment="production", access_mode="public",
                    ssl={"status": "HEALTHY"}, crawl={"urls_checked": 3})
    write_site_layout([r], tmp_path)
    data = json.loads((tmp_path / "s" / "latest.json").read_text(encoding="utf-8"))
    assert data["ssl"]["status"] == "HEALTHY" and data["crawl"]["urls_checked"] == 3


# ---------- multi-site registry and scheduling ----------

def test_site_add_registers_multiple_urls_idempotently(tmp_path, capsys):
    path = tmp_path / "cfg" / "config.yaml"

    def add(url):
        return cli._cmd_site(SimpleNamespace(action="add", target=url, url=None, id=None, name=None, config=str(path),
                                             environment="production", access_mode="public", credentials_ref=None))
    assert add("https://www.juhayna.com") == 0
    assert add("https://example.org") == 0
    assert add("https://juhayna.com") == 0  # same id: already registered
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert [s["id"] for s in data["sites"]] == ["juhayna-com", "example-org"]
    assert Path(data["reports"]["directory"]).is_absolute()
    assert add("http://127.0.0.1") == cli.EXIT_CONFIGURATION
    assert "already registered" in capsys.readouterr().out
    assert cli._cmd_site(SimpleNamespace(action="remove", target="example-org", id=None, config=str(path))) == 0
    assert [s["id"] for s in yaml.safe_load(path.read_text(encoding="utf-8"))["sites"]] == ["juhayna-com"]


def test_schedule_install_uses_local_time_and_covers_all_registered_sites(tmp_path, monkeypatch):
    from wp_maintenance import scheduler
    path = tmp_path / "config.yaml"
    for url in ("https://a.example.com", "https://b.example.com"):
        cli._cmd_site(SimpleNamespace(action="add", target=url, url=None, id=None, name=None, config=str(path),
                                      environment="production", access_mode="public", credentials_ref=None))
    calls = []
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(scheduler.platform, "system", lambda: "Windows")
    monkeypatch.setattr(scheduler.shutil, "which", lambda name: "C:/bin/wp-maintenance.exe")
    monkeypatch.setattr(scheduler.subprocess, "run", lambda args, **kw: calls.append(args) or SimpleNamespace(returncode=0, stdout=""))
    code = cli._cmd_schedule(SimpleNamespace(action="install", config=str(path), weekly=True, day="sunday", time="03:00",
                                             timezone=None, method="auto"))
    assert code == 0
    args = calls[0]
    assert args[0] == "schtasks.exe" and "SUN" in args and "03:00" in args
    task_run = args[args.index("/TR") + 1]
    assert len(task_run) < 261 and task_run.endswith('.cmd"')
    launcher = (tmp_path / ".wp-maintenance").glob("WordPressMaintenanceAgent-*.cmd")
    assert "audit --all" in next(launcher).read_text(encoding="utf-8")


def test_schedule_requires_registered_sites(tmp_path, capsys):
    path = tmp_path / "config.yaml"
    path.write_text("sites: []\n", encoding="utf-8")
    code = cli._cmd_schedule(SimpleNamespace(action="install", config=str(path), weekly=True, day=None, time=None,
                                             timezone=None, method="cron"))
    assert code == cli.EXIT_CONFIGURATION


def test_cron_local_time_has_no_timezone_override(tmp_path, monkeypatch):
    from wp_maintenance import scheduler
    from wp_maintenance.models import Schedule
    saved = []
    monkeypatch.setattr(scheduler.platform, "system", lambda: "Linux")
    monkeypatch.setattr(scheduler.shutil, "which", lambda name: "/usr/bin/wp-maintenance")

    def fake_run(args, **kw):
        if args == ["crontab", "-l"]:
            return SimpleNamespace(returncode=0, stdout="")
        saved.append(kw["input"])
        return SimpleNamespace(returncode=0, stdout="")
    monkeypatch.setattr(scheduler.subprocess, "run", fake_run)
    scheduler.install_schedule(Schedule(day="sunday", time="03:00"), config=tmp_path / "c.yaml", method="cron", local_time=True)
    assert "CRON_TZ" not in saved[0] and "00 03 * * 0" in saved[0]
