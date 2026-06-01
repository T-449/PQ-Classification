"""SIG (digital-signature) classifier."""

from __future__ import annotations

from typing import Iterable

import joblib
import pandas as pd

from .. import config


LABELS: dict[int, str] = {
    0: "Dilithium",
    1: "Falcon",
    2: "SPHINCS",
    3: "DSA",
}

FEATURES: list[str] = [
    "CPU0_cycles", "CPU1_cycles", "CPU2_cycles", "CPU3_cycles",
    "CPU4_cycles", "CPU5_cycles", "CPU6_cycles", "CPU7_cycles",
    "CPU8_cycles", "CPU9_cycles", "CPU10_cycles", "CPU11_cycles",
    "VmSize", "VmRSS", "VmData", "VmStk", "VmExe", "VmLib", "VmPTE",
]

# Map raw "label" column substrings to canonical names (used for evaluation).
NAME_MAP: dict[str, str] = {
    "dilithium": "Dilithium",
    "falcon":    "Falcon",
    "sphincs":   "SPHINCS",
    "dsa":       "DSA",
}


def map_label(raw: str) -> str | None:
    """Map a noisy SIG label (e.g. ``"Dilithium5.out"``) to a canonical name."""
    if not isinstance(raw, str):
        return None
    lowered = raw.lower()
    for key, name in NAME_MAP.items():
        if key in lowered:
            return name
    return None


def _load_csv(source) -> pd.DataFrame:
    if isinstance(source, pd.DataFrame):
        return source.copy()
    return pd.read_csv(source)


def _prepare_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.drop(columns=[c for c in ("elapsed_time", "label") if c in df.columns])
    for col in FEATURES:
        if col not in df.columns:
            df[col] = 0
    df = df[FEATURES]

    paths = config.get_paths("sig")
    scaler = joblib.load(paths["scaler"])
    df[FEATURES] = scaler.transform(df[FEATURES])
    df.fillna(0, inplace=True)
    return df


def classify(source) -> list[str]:
    """Classify each row of a SIG CSV (or DataFrame) into a label name."""
    df = _prepare_features(_load_csv(source))
    paths = config.get_paths("sig")
    model = joblib.load(paths["model"])
    predictions: Iterable[int] = model.predict(df)
    return [LABELS[int(p)] for p in predictions]
