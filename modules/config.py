"""Reads config.yaml. Callers load it once and pass the values they need to each module."""
from os import PathLike
from typing import Any

import yaml

DEFAULT_CONFIG_PATH = "config.yaml"


class ConfigError(Exception):
    """config.yaml is missing, is not valid YAML, or has no `default` section."""


def load_config(path: str | PathLike[str] = DEFAULT_CONFIG_PATH) -> dict[str, Any]:
    try:
        with open(path, "r") as file:
            config = yaml.safe_load(file)
    except FileNotFoundError as e:
        raise ConfigError(f"{path} not found") from e
    except yaml.YAMLError as e:
        raise ConfigError(f"{path} is not valid YAML: {e}") from e
    if not isinstance(config, dict) or not isinstance(config.get("default"), dict):
        raise ConfigError(f"{path} has no 'default' section")
    return config
