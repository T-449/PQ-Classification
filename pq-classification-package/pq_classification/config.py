"""
The package keeps a single global configuration that maps each classifier
("kex" and "sig") to the file paths of its trained model and scaler. The
config can be loaded from a JSON file via :func:`add_config`, supplied as a
dict via :func:`set_config`, or left at the bundled defaults that ship with
the package.

Expected JSON schema::

    {
      "kex": {
        "model":  "/abs/or/relative/path/to/kex_model.joblib",
        "scaler": "/abs/or/relative/path/to/kex_scaler.pkl"
      },
      "sig": {
        "model":  "/abs/or/relative/path/to/model_sig.joblib",
        "scaler": "/abs/or/relative/path/to/scaler_sig.pkl"
      }
    }

Relative paths are resolved against the directory containing the JSON file
(or the current working directory when :func:`set_config` is used).
"""

from __future__ import annotations

import json
import os
from typing import Any


_PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
_ARTIFACTS_DIR = os.path.join(_PACKAGE_DIR, "artifacts")

DEFAULT_CONFIG: dict[str, dict[str, str]] = {
    "kex": {
        "model":  os.path.join(_ARTIFACTS_DIR, "models",  "kex_model.joblib"),
        "scaler": os.path.join(_ARTIFACTS_DIR, "scalers", "kex_scaler.pkl"),
    },
    "sig": {
        "model":  os.path.join(_ARTIFACTS_DIR, "models",  "model_sig.joblib"),
        "scaler": os.path.join(_ARTIFACTS_DIR, "scalers", "scaler_sig.pkl"),
    },
}

_CONFIG: dict[str, dict[str, str]] = {
    kind: dict(paths) for kind, paths in DEFAULT_CONFIG.items()
}


def _validate(cfg: dict[str, Any]) -> None:
    if not isinstance(cfg, dict):
        raise TypeError("config must be a dict")
    for kind in ("kex", "sig"):
        if kind not in cfg:
            continue
        section = cfg[kind]
        if not isinstance(section, dict):
            raise TypeError(f"config['{kind}'] must be a dict")
        for key in ("model", "scaler"):
            if key in section and not isinstance(section[key], str):
                raise TypeError(f"config['{kind}']['{key}'] must be a string path")


def _resolve(base_dir: str, cfg: dict[str, Any]) -> dict[str, dict[str, str]]:
    resolved: dict[str, dict[str, str]] = {}
    for kind in ("kex", "sig"):
        if kind not in cfg:
            continue
        section = cfg[kind]
        merged = dict(_CONFIG.get(kind, {}))
        for key in ("model", "scaler"):
            if key in section:
                path = section[key]
                if not os.path.isabs(path):
                    path = os.path.normpath(os.path.join(base_dir, path))
                merged[key] = path
        resolved[kind] = merged
    return resolved


def add_config(path: str) -> dict[str, dict[str, str]]:
    """Load a JSON config file and apply it to the package.

    Returns the active configuration after applying the file. Sections that
    are missing from the file fall back to the previously active values
    (initially the bundled defaults), so callers can override just one
    classifier if they want.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a string")
    if not os.path.isfile(path):
        raise FileNotFoundError(f"config file not found: {path}")

    with open(path, "r") as fh:
        cfg = json.load(fh)
    _validate(cfg)

    base_dir = os.path.dirname(os.path.abspath(path))
    for kind, paths in _resolve(base_dir, cfg).items():
        _CONFIG[kind] = paths
    return get_config()


def set_config(cfg: dict[str, Any]) -> dict[str, dict[str, str]]:
    """Apply a config supplied as a Python dict (same schema as the JSON)."""
    _validate(cfg)
    base_dir = os.getcwd()
    for kind, paths in _resolve(base_dir, cfg).items():
        _CONFIG[kind] = paths
    return get_config()


def reset_config() -> dict[str, dict[str, str]]:
    """Restore the bundled defaults."""
    for kind, paths in DEFAULT_CONFIG.items():
        _CONFIG[kind] = dict(paths)
    return get_config()


def get_config() -> dict[str, dict[str, str]]:
    """Return a copy of the currently active configuration."""
    return {kind: dict(paths) for kind, paths in _CONFIG.items()}


def get_paths(kind: str) -> dict[str, str]:
    """Return ``{"model": ..., "scaler": ...}`` for ``kind`` ("kex" or "sig")."""
    if kind not in _CONFIG:
        raise ValueError(f"unknown classifier kind '{kind}' (expected 'kex' or 'sig')")
    paths = _CONFIG[kind]
    for key in ("model", "scaler"):
        if key not in paths:
            raise KeyError(f"config['{kind}'] is missing '{key}'")
        if not os.path.isfile(paths[key]):
            raise FileNotFoundError(
                f"config['{kind}']['{key}'] points to a missing file: {paths[key]}"
            )
    return dict(paths)
