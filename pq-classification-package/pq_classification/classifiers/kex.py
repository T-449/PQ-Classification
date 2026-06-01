"""KEX (key-exchange) classifier."""

from __future__ import annotations

from typing import Iterable

import joblib
import pandas as pd

from .. import config


LABELS: dict[int, str] = {
    0: "kyber",
    1: "classic",
    2: "frodokem",
    3: "bike",
    4: "ntruprime",
    5: "hqc",
    6: "sike",
    7: "rsa",
    8: "ecdh",
}

FEATURES: list[str] = ["VmSize", "VmData", "VmRSS", "VmExe"]


def _load_csv(source) -> pd.DataFrame:
    if isinstance(source, pd.DataFrame):
        return source.copy()
    return pd.read_csv(source)


def _prepare_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.drop(columns=[c for c in ("elapsed_time", "label") if c in df.columns])
    missing = [c for c in FEATURES if c not in df.columns]
    if missing:
        raise ValueError(f"KEX input is missing required columns: {missing}")

    paths = config.get_paths("kex")
    scaler = joblib.load(paths["scaler"])
    df[FEATURES] = scaler.transform(df[FEATURES])
    df.fillna(0, inplace=True)
    return df


def classify(source) -> list[str]:
    """Classify each row of a KEX CSV (or DataFrame) into a label name."""
    df = _prepare_features(_load_csv(source))
    paths = config.get_paths("kex")
    model = joblib.load(paths["model"])
    predictions: Iterable[int] = model.predict(df[FEATURES])
    return [LABELS[int(p)] for p in predictions]
