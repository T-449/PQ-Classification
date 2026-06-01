from __future__ import annotations

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report

from . import config
from .classifiers import kex as _kex
from .classifiers import sig as _sig


def _load_csv(source) -> pd.DataFrame:
    if isinstance(source, pd.DataFrame):
        return source.copy()
    return pd.read_csv(source)


def _evaluate_kex(source) -> dict:
    raw = _load_csv(source)
    if "label" not in raw.columns:
        raise ValueError("KEX evaluation requires a 'label' column with ground truth")

    valid = set(_kex.LABELS.keys())
    df = raw.copy()
    df["label"] = pd.to_numeric(df["label"], errors="coerce")
    df = df[df["label"].isin(valid)].copy()
    skipped = len(raw) - len(df)

    y_true = df["label"].map(_kex.LABELS).tolist()

    df_feat = df.drop(columns=["label"] + [c for c in ("elapsed_time",) if c in df.columns])
    paths = config.get_paths("kex")
    scaler = joblib.load(paths["scaler"])
    df_feat[_kex.FEATURES] = scaler.transform(df_feat[_kex.FEATURES])
    df_feat.fillna(0, inplace=True)

    model = joblib.load(paths["model"])
    y_pred_idx = model.predict(df_feat[_kex.FEATURES])
    y_pred = [_kex.LABELS[int(p)] for p in y_pred_idx]

    accuracy = float(accuracy_score(y_true, y_pred))
    report_text = classification_report(
        y_true, y_pred, labels=list(_kex.LABELS.values()), zero_division=0
    )
    report_dict = classification_report(
        y_true, y_pred,
        labels=list(_kex.LABELS.values()),
        zero_division=0,
        output_dict=True,
    )
    return {
        "kind": "kex",
        "rows_evaluated": len(df),
        "rows_skipped": int(skipped),
        "accuracy": accuracy,
        "report": report_dict,
        "report_text": report_text,
        "y_true": y_true,
        "y_pred": y_pred,
    }


def _evaluate_sig(source) -> dict:
    raw = _load_csv(source)
    if "label" not in raw.columns:
        raise ValueError("SIG evaluation requires a 'label' column with ground truth")

    df = raw.copy()
    df["label_mapped"] = df["label"].apply(_sig.map_label)
    skipped = int(df["label_mapped"].isna().sum())
    df = df.dropna(subset=["label_mapped"]).copy()

    y_true = df["label_mapped"].tolist()

    df_feat = df.drop(
        columns=["label", "label_mapped"]
        + [c for c in ("elapsed_time",) if c in df.columns]
    )
    for col in _sig.FEATURES:
        if col not in df_feat.columns:
            df_feat[col] = 0
    df_feat = df_feat[_sig.FEATURES]

    paths = config.get_paths("sig")
    scaler = joblib.load(paths["scaler"])
    df_feat[_sig.FEATURES] = scaler.transform(df_feat[_sig.FEATURES])
    df_feat.fillna(0, inplace=True)

    model = joblib.load(paths["model"])
    y_pred_idx = model.predict(df_feat)
    y_pred = [_sig.LABELS[int(p)] for p in y_pred_idx]

    accuracy = float(accuracy_score(y_true, y_pred))
    report_text = classification_report(
        y_true, y_pred, labels=list(_sig.LABELS.values()), zero_division=0
    )
    report_dict = classification_report(
        y_true, y_pred,
        labels=list(_sig.LABELS.values()),
        zero_division=0,
        output_dict=True,
    )
    return {
        "kind": "sig",
        "rows_evaluated": len(df),
        "rows_skipped": skipped,
        "accuracy": accuracy,
        "report": report_dict,
        "report_text": report_text,
        "y_true": y_true,
        "y_pred": y_pred,
    }


_KINDS = {
    "kex": _evaluate_kex,
    "sig": _evaluate_sig,
}


def evaluate(source, kind: str = "kex") -> dict:
    """Evaluate ``source`` against ground-truth labels for the ``kind`` classifier.

    The CSV (or DataFrame) must have a ``label`` column:

    * For ``kind="kex"``, ``label`` is a numeric class id 0-8.
    * For ``kind="sig"``, ``label`` is a string containing one of
      ``dilithium``, ``falcon``, ``sphincs``, or ``dsa`` (case-insensitive).

    Returns
    -------
    dict
        ``{"kind", "rows_evaluated", "rows_skipped", "accuracy", "report",
        "report_text", "y_true", "y_pred"}``. ``report`` is the sklearn
        per-class dict; ``report_text`` is the human-readable string.
    """
    if kind not in _KINDS:
        raise ValueError(f"unknown kind '{kind}' (expected 'kex' or 'sig')")
    return _KINDS[kind](source)
