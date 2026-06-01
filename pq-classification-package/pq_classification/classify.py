from __future__ import annotations

from .classifiers import kex as _kex
from .classifiers import sig as _sig


_KINDS = {
    "kex": _kex.classify,
    "sig": _sig.classify,
}


def classify(source, kind: str = "kex") -> list[str]:
    """Classify rows from ``source`` using the ``kind`` classifier.

    Parameters
    ----------
    source : str | pathlib.Path | pandas.DataFrame
        Path to a CSV file or a DataFrame already loaded in memory.
    kind : {"kex", "sig"}, default "kex"
        Which classifier to run.

    Returns
    -------
    list[str]
        One predicted label per input row.
    """
    if kind not in _KINDS:
        raise ValueError(f"unknown kind '{kind}' (expected 'kex' or 'sig')")
    return _KINDS[kind](source)
