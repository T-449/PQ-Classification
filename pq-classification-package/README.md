# pq_classification

A Python package for classifying post-quantum cryptographic algorithms from
runtime telemetry (memory and CPU-cycle features).

Two classifiers ship with the package:

| Kind  | What it predicts                          | Classes |
|-------|-------------------------------------------|---------|
| `kex` | Key-exchange mechanism                    | `kyber`, `classic`, `frodokem`, `bike`, `ntruprime`, `hqc`, `sike`, `rsa`, `ecdh` |
| `sig` | Digital-signature algorithm               | `Dilithium`, `Falcon`, `SPHINCS`, `DSA` |

The trained model + scaler artifacts are bundled with the package, so the
defaults work out of the box. You can also point the package at your own
artifacts via a JSON config file.

---

## Install

From the package directory:

```bash
pip install -e .
```

Or just install the dependencies and add the package directory to your
`PYTHONPATH`:

```bash
pip install -r requirements.txt
```

---

## Quick start

```python
import pq_classification as pq_cls

# (optional) load a JSON config — defaults to bundled artifacts otherwise
pq_cls.add_config("config.json")

# Classify a CSV
labels = pq_cls.classify("kex_data.csv", kind="kex")
print(labels)
# ['kyber', 'ecdh', 'frodokem', ...]

# Evaluate against ground truth
scores = pq_cls.evaluate("kex_labelled.csv", kind="kex")
print(scores["accuracy"])
print(scores["report_text"])
```

---

## API

### `pq_cls.add_config(path: str) -> dict`

Load a JSON config from `path` and apply it. Returns the active configuration.
Sections missing from the file fall back to the previously active values
(initially the bundled defaults), so you can override just `kex` or just
`sig` if you want.

Schema:

```json
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
```

Relative paths are resolved against the directory containing the JSON file.

### `pq_cls.set_config(cfg: dict) -> dict`

Same as `add_config`, but accepts a dict directly. Relative paths are resolved
against the current working directory.

### `pq_cls.reset_config() -> dict`

Restore the bundled defaults.

### `pq_cls.get_config() -> dict`

Return a copy of the currently active configuration.

### `pq_cls.classify(source, kind="kex") -> list[str]`

Classify each row of a CSV file (or pandas `DataFrame`) using the `kind`
classifier and return one label string per row.

* `source` — path to a CSV, or an in-memory `pandas.DataFrame`.
* `kind` — `"kex"` or `"sig"`.

**Required input columns**

* `kex` — `VmSize`, `VmData`, `VmRSS`, `VmExe`. Optional `elapsed_time` and
  `label` columns are ignored.
* `sig` — `CPU0_cycles` … `CPU11_cycles`, `VmSize`, `VmRSS`, `VmData`,
  `VmStk`, `VmExe`, `VmLib`, `VmPTE`. Any missing column is filled with `0`.

### `pq_cls.evaluate(source, kind="kex") -> dict`

Score the classifier against ground truth. The input CSV must contain a
`label` column (see [Label column format](#label-column-format) for the full
spec):

* `kex` — numeric class id `0`–`8`. Rows with out-of-range labels are skipped.
* `sig` — string label containing one of `dilithium`, `falcon`, `sphincs`,
  or `dsa` (case-insensitive, substring match). Rows that don't map are
  skipped.

Returns a dict:

```python
{
  "kind":          "kex",            # or "sig"
  "rows_evaluated": 1234,
  "rows_skipped":   5,
  "accuracy":       0.97,
  "report":         { ... },          # sklearn classification_report dict
  "report_text":    "precision ...",  # the human-readable string
  "y_true":         [...],
  "y_pred":         [...],
}
```

### `pq_cls.kex` / `pq_cls.sig`

Direct access to each classifier module — useful if you want the raw label
maps:

```python
pq_cls.kex.LABELS    # {0: 'kyber', 1: 'classic', ...}
pq_cls.kex.FEATURES  # ['VmSize', 'VmData', 'VmRSS', 'VmExe']
pq_cls.sig.LABELS
pq_cls.sig.FEATURES
```

---

## Label column format

The `label` column is **only used by `evaluate`** (as ground truth). `classify`
ignores it entirely — you can include it or leave it out. The two classifiers
expect the column in different formats.

### `kex` — numeric class id

For `kind="kex"`, `label` must be an **integer class id** in the range `0`–`8`.
Values are parsed numerically; any row whose label is non-numeric or outside
`0`–`8` is **skipped** (counted in `rows_skipped`).

| id | label name  | algorithm                              | type      |
|----|-------------|----------------------------------------|-----------|
| 0  | `kyber`     | Kyber / ML-KEM                         | post-quantum |
| 1  | `classic`   | Classic McEliece (PQ, *not* classical) | post-quantum |
| 2  | `frodokem`  | FrodoKEM                               | post-quantum |
| 3  | `bike`      | BIKE                                   | post-quantum |
| 4  | `ntruprime` | NTRU Prime                             | post-quantum |
| 5  | `hqc`       | HQC                                    | post-quantum |
| 6  | `sike`      | SIKE                                   | post-quantum |
| 7  | `rsa`       | RSA                                    | classical |
| 8  | `ecdh`      | ECDH                                   | classical |

Example `label` column: `0`, `3`, `8`, …

### `sig` — algorithm name (substring match)

For `kind="sig"`, `label` is a **string**. It is matched **case-insensitively
by substring** against four keywords, so noisy values like `Dilithium5.out`,
`falcon-512`, or `SPHINCS+-SHA2-128f` all map cleanly. Any row that matches none
of the keywords is **skipped**.

| substring in `label` (case-insensitive) | maps to     | algorithm          | type         |
|------------------------------------------|-------------|--------------------|--------------|
| `dilithium`                              | `Dilithium` | Dilithium / ML-DSA | post-quantum |
| `falcon`                                 | `Falcon`    | Falcon             | post-quantum |
| `sphincs`                                | `SPHINCS`   | SPHINCS+ / SLH-DSA | post-quantum |
| `dsa`                                    | `DSA`       | DSA                | classical    |

Example `label` column: `Dilithium2`, `falcon-1024.out`, `Sphincs-sha256`, …

> The label names in the tables above are exactly the strings `classify` and
> `evaluate` return in their predictions.

---

## Using a custom config

Suppose you have retrained models at `/data/my_models/`:

```bash
cat > my_config.json <<'EOF'
{
  "kex": {
    "model":  "/data/my_models/kex_model.joblib",
    "scaler": "/data/my_models/kex_scaler.pkl"
  },
  "sig": {
    "model":  "/data/my_models/model_sig.joblib",
    "scaler": "/data/my_models/scaler_sig.pkl"
  }
}
EOF
```

```python
import pq_classification as pq_cls
pq_cls.add_config("my_config.json")
labels = pq_cls.classify("sig_data.csv", kind="sig")
```

A minimal config that overrides only `sig` is fine — the `kex` paths will
keep using whatever was active before (the bundled defaults if you haven't
called `add_config`/`set_config` yet).

---

## Project layout

```
pq-classification-package/
├── pq_classification/
│   ├── __init__.py            # public API
│   ├── config.py              # add_config / set_config / get_config
│   ├── classify.py            # classify(source, kind=...)
│   ├── evaluate.py            # evaluate(source, kind=...)
│   ├── classifiers/
│   │   ├── kex.py             # KEX feature list + classifier
│   │   └── sig.py             # SIG feature list + classifier
│   └── artifacts/
│       ├── models/            # bundled .joblib models
│       └── scalers/           # bundled .pkl scalers
├── config.example.json
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## Dependencies

* `pandas`
* `joblib`
* `scikit-learn==1.4.2`
* `xgboost==2.0.3`

The exact `scikit-learn` and `xgboost` versions matter — the bundled
artifacts were trained against them and `joblib` will warn (or fail) if
they're loaded with a mismatched version. If you are using different models please update the accurate version.
