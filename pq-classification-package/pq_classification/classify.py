from __future__ import annotations

from .classifiers import kex as _kex
from .classifiers import sig as _sig
from . import capture as _capture


_KINDS = {
    "kex": _kex.classify,
    "sig": _sig.classify,
    "capture": _capture.classify,
}


def classify(source, kind: str = "kex"):
    """Classify ``source`` using the ``kind`` classifier.

    Parameters
    ----------
    source : str | pathlib.Path | pandas.DataFrame
        For ``kind="kex"``/``"sig"``: path to a CSV file or a DataFrame.
        For ``kind="capture"``: path to a ``.pcapng`` capture file.
    kind : {"kex", "sig", "capture"}, default "kex"
        Which classifier to run. ``"capture"`` is the library equivalent of the
        web app's ``/classify`` endpoint (TLS key-exchange detection).

    Returns
    -------
    list[str] | list[dict]
        ``"kex"``/``"sig"`` return one predicted label per row. ``"capture"``
        returns ``[{"ip", "algorithms"}, ...]`` per detected connection.
    """
    if kind not in _KINDS:
        raise ValueError(f"unknown kind '{kind}' (expected 'kex', 'sig', or 'capture')")
    return _KINDS[kind](source)
