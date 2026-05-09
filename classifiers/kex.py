import joblib
import pandas as pd
import config

LABELS = {
    0: 'kyber',
    1: 'classic',
    2: 'frodokem',
    3: 'bike',
    4: 'ntruprime',
    5: 'hqc',
    6: 'sike',
    7: 'rsa',
    8: 'ecdh',
}

FEATURES = ['VmSize', 'VmData', 'VmRSS', 'VmExe']


def classify(filepath):
    df = pd.read_csv(filepath)
    df = df.drop(columns=[c for c in ['elapsed_time', 'label'] if c in df.columns])

    scaler = joblib.load(config.SCALER_KEX)
    df[FEATURES] = scaler.transform(df[FEATURES])
    df.fillna(0, inplace=True)

    model = joblib.load(config.MODEL_KEX)
    predictions = model.predict(df[FEATURES])
    return [LABELS[p] for p in predictions]
