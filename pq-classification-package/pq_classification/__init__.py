"""pq_classification — classify post-quantum KEX and SIG telemetry.

Typical usage::

    import pq_classification as pq_cls

    pq_cls.add_config("config.json")          # optional; defaults bundled
    labels  = pq_cls.classify("kex_data.csv", kind="kex")
    scores  = pq_cls.evaluate("kex_labelled.csv", kind="kex")
"""

from .config import (
    DEFAULT_CONFIG,
    add_config,
    get_config,
    get_paths,
    reset_config,
    set_config,
)
from .classify import classify
from .evaluate import evaluate
from .classifiers import kex, sig
from . import capture
from .capture import classify as classify_capture

__all__ = [
    "DEFAULT_CONFIG",
    "add_config",
    "set_config",
    "reset_config",
    "get_config",
    "get_paths",
    "classify",
    "classify_capture",
    "evaluate",
    "kex",
    "sig",
    "capture",
]

__version__ = "0.1.0"
