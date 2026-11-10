from pathlib import Path

import pytest
from pydantic import ValidationError

from wp_maintenance.config import load_config
from wp_maintenance.models import AppConfig


def test_multi_site_config_validates_and_keeps_secret_as_reference(tmp_path: Path):
    path = tmp_path / "sites.yaml"
    path.write_text("""
sites:
  - id: one
    name: One
    url: https://example.com
    access_mode: authenticated
    credentials_ref: WORDPRESS_ONE
  - id: two
    name: Two
    url: https://example.org
schedule: {timezone: Africa/Cairo, day: sunday, time: '03:00'}
""", encoding="utf-8")
    config = load_config(path)
    assert [site.id for site in config.sites] == ["one", "two"]
    assert config.sites[0].credentials_ref == "WORDPRESS_ONE"
    assert config.safety["read_only"] is True


def test_duplicate_site_ids_fail():
    with pytest.raises(ValidationError, match="unique"):
        AppConfig.model_validate({"sites": [
            {"id": "same", "name": "One", "url": "https://one.example"},
            {"id": "same", "name": "Two", "url": "https://two.example"},
        ]})


def test_authenticated_site_requires_credential_reference():
    with pytest.raises(ValidationError, match="credentials_ref"):
        AppConfig.model_validate({"sites": [{"id": "a", "name": "A", "url": "https://example.com", "access_mode": "authenticated"}]})
