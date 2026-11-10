"""YAML loading and environment variable expansion."""

from __future__ import annotations

import os
import re
from pathlib import Path

import yaml

from .models import AppConfig

ENV_PATTERN = re.compile(r"\$\{([A-Z0-9_]+)(?::-([^}]*))?\}")


def _expand_env(value: object) -> object:
    if isinstance(value, str):
        def replace(match: re.Match[str]) -> str:
            variable, default = match.groups()
            found = os.environ.get(variable)
            if found is None and default is None:
                raise ValueError(f"environment variable {variable} is not set")
            return found if found is not None else default or ""
        return ENV_PATTERN.sub(replace, value)
    if isinstance(value, list):
        return [_expand_env(item) for item in value]
    if isinstance(value, dict):
        return {key: _expand_env(item) for key, item in value.items()}
    return value


def load_config(path: str | Path) -> AppConfig:
    """Read and validate an application YAML configuration."""
    config_path = Path(path)
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("configuration root must be a YAML mapping")
    config = AppConfig.model_validate(_expand_env(raw))
    if not config.reports.directory.is_absolute():
        config.reports.directory = (config_path.parent / config.reports.directory).resolve()
    return config
