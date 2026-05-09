# PQ Classifier

Two endpoints:
- `POST /classifykex` — classifies key exchange mechanisms
- `POST /classifysig` — classifies digital signature algorithms


## Setup

```bash
cd pq-classifier

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

## Run

```bash
python app.py
```

The server starts on `http://0.0.0.0:5001` by default.

---

## Usage

### `/classifykex`

Input CSV must contain the columns: `VmSize`, `VmData`, `VmRSS`, `VmExe`.
Optional columns `elapsed_time` and `label` are ignored automatically.

```bash
curl -X POST http://localhost:5001/classifykex \
     -F "file=@your_kex_data.csv"
```

**Response**
```json
{
  "labels": ["kyber", "ecdh", "frodokem"]
}
```

Possible labels: `kyber`, `classic`, `frodokem`, `bike`, `ntruprime`, `hqc`, `sike`, `rsa`, `ecdh`

---

### `/classifysig`

Input CSV must contain the columns:
`CPU0_cycles` through `CPU11_cycles`, `VmSize`, `VmRSS`, `VmData`, `VmStk`, `VmExe`, `VmLib`, `VmPTE`.
Any missing CPU/memory columns are automatically filled with `0`.

```bash
curl -X POST http://localhost:5001/classifysig \
     -F "file=@your_sig_data.csv"
```

**Response**
```json
{
  "labels": ["Dilithium", "Falcon", "DSA"]
}
```

Possible labels: `Dilithium`, `Falcon`, `SPHINCS`, `DSA`

---

## Configuration

All settings in `config.py`. Edit that file to change defaults.

---

## Evaluation

Run `evaluate.py` to get accuracy, precision, recall, and F1 against labelled CSVs:

```bash
source .venv/bin/activate
python evaluate.py path/to/kex.csv path/to/sig.csv
```

Both CSVs must have a `label` column with ground-truth values. The script prints a
`sklearn` classification report per classifier.
