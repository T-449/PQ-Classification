import sys
import os
import joblib
import pandas as pd
from sklearn.metrics import classification_report, accuracy_score

sys.path.insert(0, os.path.dirname(__file__))
import config

KEX_LABELS = {0: 'kyber', 1: 'classic', 2: 'frodokem', 3: 'bike',
              4: 'ntruprime', 5: 'hqc', 6: 'sike', 7: 'rsa', 8: 'ecdh'}

SIG_LABELS = {0: 'Dilithium', 1: 'Falcon', 2: 'SPHINCS', 3: 'DSA'}

KEX_FEATURES = ['VmSize', 'VmData', 'VmRSS', 'VmExe']

SIG_FEATURES = [
    'CPU0_cycles', 'CPU1_cycles', 'CPU2_cycles', 'CPU3_cycles',
    'CPU4_cycles', 'CPU5_cycles', 'CPU6_cycles', 'CPU7_cycles',
    'CPU8_cycles', 'CPU9_cycles', 'CPU10_cycles', 'CPU11_cycles',
    'VmSize', 'VmRSS', 'VmData', 'VmStk', 'VmExe', 'VmLib', 'VmPTE',
]

# Map sig label strings (e.g. "Dilithium5.out") to canonical names
SIG_NAME_MAP = {
    'dilithium': 'Dilithium',
    'falcon':    'Falcon',
    'sphincs':   'SPHINCS',
    'dsa':       'DSA',
}

def _map_sig_label(raw):
    for key, name in SIG_NAME_MAP.items():
        if key in raw.lower():
            return name
    return None


def evaluate_kex(csv_path):
    print(f"\n{'='*55}")
    print("KEX CLASSIFIER EVALUATION")
    print(f"CSV: {csv_path}")
    print('='*55)

    df = pd.read_csv(csv_path)
    valid_labels = set(KEX_LABELS.keys())

    # Keep only rows whose ground-truth label is a known class
    df['label'] = pd.to_numeric(df['label'], errors='coerce')
    df = df[df['label'].isin(valid_labels)].copy()
    print(f"Rows with known labels (0–8): {len(df)}  "
          f"(skipped {pd.read_csv(csv_path).shape[0] - len(df)} unlabelled/out-of-range rows)")

    y_true_names = df['label'].map(KEX_LABELS).tolist()

    df_feat = df.drop(columns=['label'] + [c for c in ['elapsed_time'] if c in df.columns])
    scaler = joblib.load(config.SCALER_KEX)
    df_feat[KEX_FEATURES] = scaler.transform(df_feat[KEX_FEATURES])
    df_feat.fillna(0, inplace=True)

    model = joblib.load(config.MODEL_KEX)
    y_pred = model.predict(df_feat[KEX_FEATURES])
    y_pred_names = [KEX_LABELS[p] for p in y_pred]

    acc = accuracy_score(y_true_names, y_pred_names)
    print(f"\nOverall Accuracy: {acc:.4f} ({acc*100:.2f}%)\n")
    print(classification_report(y_true_names, y_pred_names,
                                labels=list(KEX_LABELS.values()),
                                zero_division=0))


def evaluate_sig(csv_path):
    print(f"\n{'='*55}")
    print("SIG CLASSIFIER EVALUATION")
    print(f"CSV: {csv_path}")
    print('='*55)

    df = pd.read_csv(csv_path)

    # Map string labels to canonical names
    df['label_mapped'] = df['label'].apply(_map_sig_label)
    n_unmapped = df['label_mapped'].isna().sum()
    df = df.dropna(subset=['label_mapped'])
    print(f"Rows evaluated: {len(df)}  (skipped {n_unmapped} unmapped labels)")
    print(f"Ground-truth classes present: {sorted(df['label_mapped'].unique())}")

    y_true = df['label_mapped'].tolist()

    df_feat = df.drop(columns=['label', 'label_mapped'] +
                      [c for c in ['elapsed_time'] if c in df.columns])
    for col in SIG_FEATURES:
        if col not in df_feat.columns:
            df_feat[col] = 0
    df_feat = df_feat[SIG_FEATURES]

    scaler = joblib.load(config.SCALER_SIG)
    df_feat[SIG_FEATURES] = scaler.transform(df_feat[SIG_FEATURES])
    df_feat.fillna(0, inplace=True)

    model = joblib.load(config.MODEL_SIG)
    y_pred = model.predict(df_feat)
    y_pred_names = [SIG_LABELS[p] for p in y_pred]

    acc = accuracy_score(y_true, y_pred_names)
    print(f"\nOverall Accuracy: {acc:.4f} ({acc*100:.2f}%)\n")
    print(classification_report(y_true, y_pred_names,
                                labels=list(SIG_LABELS.values()),
                                zero_division=0))


if __name__ == '__main__':
    kex_csv = sys.argv[1] if len(sys.argv) > 1 else \
        '/uploads/kex/input.csv'
    sig_csv = sys.argv[2] if len(sys.argv) > 2 else \
        '/uploads/sig/inputSig.csv'

    evaluate_kex(kex_csv)
    evaluate_sig(sig_csv)
