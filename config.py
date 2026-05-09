import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Model and scaler paths — swap these to point at different weights
MODEL_KEX  = os.path.join(BASE_DIR, "models", "kex_model.joblib")
SCALER_KEX = os.path.join(BASE_DIR, "scalers", "kex_scaler.pkl")

MODEL_SIG  = os.path.join(BASE_DIR, "models", "model_sig.joblib")
SCALER_SIG = os.path.join(BASE_DIR, "scalers", "scaler_sig.pkl")

# Temporary upload directories (created automatically at runtime)
UPLOAD_KEX = os.path.join(BASE_DIR, "uploads", "kex")
UPLOAD_SIG = os.path.join(BASE_DIR, "uploads", "sig")

PORT = 5001
