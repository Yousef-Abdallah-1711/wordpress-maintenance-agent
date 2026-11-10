import socket
from pathlib import Path
from types import SimpleNamespace

import pytest

from wp_maintenance import cli
from wp_maintenance.inventory import (InventoryError, add_site, load_inventory, remove_site, set_enabled,
                                      validate_inventory)
from wp_maintenance.targets import TargetError, parse_url_list, resolve_targets, validate_selection

PUBLIC = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
SAMPLE = """# my comment
version: 1
defaults:
  max_urls: 100   # inline comment
sites:
  - id: alpha
    name: Alpha
    url: https://alpha.example.com
    enabled: true
    tags: [wordpress]
  - id: beta
    name: Beta
    url: https://beta.example.com
    enabled: false
"""


@pytest.fixture(autouse=True)
def dns(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: PUBLIC)


@pytest.fixture
def inv(tmp_path):
    path = tmp_path / "config" / "websites.yaml"
    path.parent.mkdir()
    path.write_text(SAMPLE, encoding="utf-8")
    return path


# ---------- inventory parsing and validation ----------

def test_inventory_parses_defaults_and_sites(inv):
    inventory = load_inventory(inv)
    assert inventory.defaults.max_urls == 100 and inventory.defaults.respect_robots_txt is True
    assert [s.id for s in inventory.sites] == ["alpha", "beta"]
    assert inventory.get("beta").enabled is False


@pytest.mark.parametrize("snippet,message", [
    ("sites:\n  - {id: a, name: A, url: 'https://a.example.com'}\n  - {id: a, name: B, url: 'https://b.example.com'}\n", "duplicate site id"),
    ("sites:\n  - {id: a, name: A, url: 'https://a.example.com'}\n  - {id: b, name: B, url: 'https://www.a.example.com/other'}\n", "duplicate website"),
    ("sites:\n  - {id: a, name: A, url: 'http://127.0.0.1'}\n", "non-public|local|private"),
    ("sites:\n  - {id: a, name: A, url: 'http://169.254.169.254/latest'}\n", "non-public|private"),
    ("sites:\n  - {id: a, name: A, url: 'ftp://a.example.com'}\n", "http"),
    ("sites:\n  - {id: a, name: A, url: 'https://u:p@a.example.com'}\n", "credentials"),
    ("sites:\n  - {id: 'Bad Id', name: A, url: 'https://a.example.com'}\n", "id"),
    ("sites:\n  - {id: a, name: A, url: 'https://a.example.com', password: x}\n", "credentials"),
    ("sites:\n  - {id: a, name: A, url: 'https://a.example.com', api_token: x}\n", "credentials"),
    ("sites:\n  - {id: a, name: A, url: 'https://a.example.com', surprise: 1}\n", "surprise|extra"),
    ("version: 2\nsites: []\n", "version"),
    ("sites:\n  - {id: a, name: A, url: 'https://a.example.com', exclude_paths: ['nope']}\n", "exclude_paths"),
])
def test_invalid_inventories_are_rejected(tmp_path, snippet, message):
    path = tmp_path / "w.yaml"
    path.write_text("version: 1\n" + snippet if not snippet.startswith("version") else snippet, encoding="utf-8")
    with pytest.raises(InventoryError, match=message):
        load_inventory(path)


def test_validate_inventory_checks_dns_for_every_site(inv, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.9", 443))])
    _, problems = validate_inventory(inv)
    assert len(problems) == 2 and all("non-public" in p for p in problems)
    assert validate_inventory(inv, resolve_dns=False)[1] == []


# ---------- add / enable / disable / remove ----------

def test_add_site_normalizes_preserves_comments_and_is_atomic(inv):
    entry = add_site(inv, "HTTPS://Gamma.Example.com/some/path?x=1", name="Gamma Site", tags=["corporate"])
    assert entry.id == "gamma-example-com" and entry.url == "https://gamma.example.com"
    text = inv.read_text(encoding="utf-8")
    assert "# my comment" in text and "# inline comment" in text and "Gamma Site" in text
    assert not list(inv.parent.glob(".websites-*.tmp"))
    assert [s.id for s in load_inventory(inv).sites] == ["alpha", "beta", "gamma-example-com"]


@pytest.mark.parametrize("url", ["http://localhost", "http://10.1.2.3", "http://169.254.169.254", "file:///etc/passwd",
                                 "https://user:pw@x.example.com", "https://x.example.com:8443"])
def test_add_rejects_unsafe_targets_and_leaves_file_untouched(inv, url):
    before = inv.read_bytes()
    with pytest.raises(InventoryError):
        add_site(inv, url)
    assert inv.read_bytes() == before


def test_add_rejects_duplicates_without_modifying_the_file(inv):
    before = inv.read_bytes()
    with pytest.raises(InventoryError, match="duplicate website"):
        add_site(inv, "https://www.alpha.example.com", site_id="alpha2")
    with pytest.raises(InventoryError, match="duplicate site id"):
        add_site(inv, "https://other.example.com", site_id="alpha")
    assert inv.read_bytes() == before


def test_enable_disable_and_remove(inv):
    entry, changed = set_enabled(inv, "beta", True)
    assert entry.enabled and changed
    assert set_enabled(inv, "beta", True)[1] is False
    set_enabled(inv, "alpha", False)
    assert [s.id for s in load_inventory(inv).sites if s.enabled] == ["beta"]
    removed = remove_site(inv, "alpha")
    assert removed.id == "alpha" and [s.id for s in load_inventory(inv).sites] == ["beta"]
    with pytest.raises(InventoryError, match="no site"):
        remove_site(inv, "ghost")
    with pytest.raises(InventoryError, match="no site"):
        set_enabled(inv, "ghost", True)
    assert "# my comment" in inv.read_text(encoding="utf-8")


def test_site_cli_inventory_commands(inv, capsys):
    def run(action, target=None, **kw):
        base = dict(action=action, target=target, url=None, id=None, name=None, config=None, inventory=str(inv), tag=None,
                    offline=True, environment="production", access_mode="public", credentials_ref=None)
        base.update(kw)
        return cli._cmd_site(SimpleNamespace(**base))
    assert run("add", "https://delta.example.com", name="Delta") == 0
    assert run("disable", "delta-example-com") == 0
    assert run("enable", "delta-example-com") == 0
    assert run("show", "delta-example-com") == 0
    assert run("list") == 0
    out = capsys.readouterr().out
    assert "Delta" in out and "enabled" in out
    assert run("remove", "delta-example-com") == 0
    assert run("remove", "delta-example-com") == cli.EXIT_CONFIGURATION
    assert run("add", "http://127.0.0.1") == cli.EXIT_CONFIGURATION
    assert run("validate") == 0


# ---------- target resolution, precedence, workflow-input validation ----------

def test_url_list_format_newlines_comments_whitespace():
    assert parse_url_list("https://a.example.com\n\n# note\nhttps://b.example.com  # trailing\n  https://c.example.com ") == [
        "https://a.example.com", "https://b.example.com", "https://c.example.com"]
    assert parse_url_list(None) == [] and parse_url_list("") == []


def test_inventory_wins_over_variable_and_never_merges(inv):
    res = resolve_targets(inventory_path=inv, urls_text="https://var.example.com", resolve_dns=False)
    assert [t.id for t in res.targets] == ["alpha"] and res.source.startswith("inventory")
    assert any("ignored" in n for n in res.notes)


def test_disabled_sites_are_never_reenabled_by_fallback(inv):
    set_enabled(inv, "alpha", False)
    with pytest.raises(TargetError, match="none are enabled"):
        resolve_targets(inventory_path=inv, urls_text="https://alpha.example.com", resolve_dns=False)


def test_variable_used_only_when_inventory_has_no_sites(tmp_path):
    missing = tmp_path / "nope.yaml"
    res = resolve_targets(inventory_path=missing, urls_text="https://a.example.com\nhttps://b.example.org", resolve_dns=False)
    assert [t.id for t in res.targets] == ["a-example-com", "b-example-org"] and res.source == "WP_MAINTENANCE_URLS"
    empty = tmp_path / "e.yaml"
    empty.write_text("version: 1\nsites: []\n", encoding="utf-8")
    assert resolve_targets(inventory_path=empty, urls_text="https://a.example.com", resolve_dns=False).source == "WP_MAINTENANCE_URLS"


def test_variable_duplicates_are_rejected_not_merged():
    with pytest.raises(TargetError, match="twice"):
        resolve_targets(inventory_path=None, urls_text="https://a.example.com\nhttps://www.a.example.com/x", resolve_dns=False)


def test_unsafe_variable_entries_are_rejected():
    with pytest.raises(TargetError, match="rejected"):
        resolve_targets(inventory_path=None, urls_text="https://ok.example.com\nhttp://169.254.169.254", resolve_dns=False)


def test_no_configuration_is_a_clear_error(tmp_path):
    with pytest.raises(TargetError, match="no websites configured"):
        resolve_targets(inventory_path=tmp_path / "x.yaml", urls_text="")


def test_single_scope_selects_exactly_one_and_rejects_disabled_or_unknown(inv):
    assert [t.id for t in resolve_targets(inventory_path=inv, scope="single", site_id="alpha", resolve_dns=False).targets] == ["alpha"]
    with pytest.raises(TargetError, match="disabled"):
        resolve_targets(inventory_path=inv, scope="single", site_id="beta", resolve_dns=False)
    with pytest.raises(TargetError, match="not in the inventory"):
        resolve_targets(inventory_path=inv, scope="single", site_id="ghost", resolve_dns=False)


def test_custom_url_is_one_time_and_does_not_touch_the_inventory(inv):
    before = inv.read_bytes()
    res = resolve_targets(inventory_path=inv, scope="custom_url", custom_url="https://temp.example.net/path", resolve_dns=False)
    assert [t.url for t in res.targets] == ["https://temp.example.net"] and res.source == "custom_url"
    assert inv.read_bytes() == before
    with pytest.raises(TargetError, match="custom_url rejected"):
        resolve_targets(inventory_path=inv, scope="custom_url", custom_url="http://localhost", resolve_dns=False)


@pytest.mark.parametrize("scope,site,url,msg", [
    ("bogus", None, None, "audit_scope must be"), ("all", "alpha", None, "cannot be combined"),
    ("all", None, "https://x.example.com", "cannot be combined"), ("single", None, None, "requires site_id"),
    ("single", "alpha", "https://x.example.com", "cannot be combined"), ("custom_url", None, None, "requires custom_url"),
    ("custom_url", "alpha", "https://x.example.com", "cannot be combined"), ("single", "a b; rm -rf /", None, "invalid characters"),
    ("single", "$(whoami)", None, "invalid characters"),
])
def test_ambiguous_or_malicious_workflow_inputs_are_rejected(scope, site, url, msg):
    with pytest.raises(TargetError, match=msg):
        validate_selection(scope, site, url, None)


@pytest.mark.parametrize("value", ["0", "-5", "abc", "99999999", "1e3", "5; id"])
def test_max_urls_validation(value):
    with pytest.raises(TargetError):
        validate_selection("all", None, None, value)
    assert validate_selection("all", "", "", "250")[3] == 250


def test_max_urls_and_site_overrides_apply(inv):
    inv.write_text(SAMPLE.replace("tags: [wordpress]", "tags: [wordpress]\n    max_urls: 40\n    exclude_paths: ['/x/']"), encoding="utf-8")
    t = resolve_targets(inventory_path=inv, resolve_dns=False).targets[0]
    assert t.max_urls == 40 and t.exclude_paths == ["/x/"] and t.concurrency == 4
    assert resolve_targets(inventory_path=inv, max_urls="7", resolve_dns=False).targets[0].max_urls == 7
