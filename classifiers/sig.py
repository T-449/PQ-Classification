import joblib
import pandas as pd
import config

LABELS = {
    0: 'Dilithium',
    1: 'Falcon',
    2: 'SPHINCS',
    3: 'DSA',
}

FEATURES = [
    'CPU0_cycles', 'CPU1_cycles', 'CPU2_cycles', 'CPU3_cycles',
    'CPU4_cycles', 'CPU5_cycles', 'CPU6_cycles', 'CPU7_cycles',
    'CPU8_cycles', 'CPU9_cycles', 'CPU10_cycles', 'CPU11_cycles',
    'VmSize', 'VmRSS', 'VmData', 'VmStk', 'VmExe', 'VmLib', 'VmPTE',
]


def classify(filepath):
    df = pd.read_csv(filepath)
    df = df.drop(columns=[c for c in ['elapsed_time', 'label'] if c in df.columns])

    for col in FEATURES:
        if col not in df.columns:
            df[col] = 0
    df = df[FEATURES]

    scaler = joblib.load(config.SCALER_SIG)
    df[FEATURES] = scaler.transform(df[FEATURES])
    df.fillna(0, inplace=True)

    model = joblib.load(config.MODEL_SIG)
    predictions = model.predict(df)
    return [LABELS[p] for p in predictions]
