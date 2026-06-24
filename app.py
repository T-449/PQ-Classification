import os
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import config
from classifiers import kex, sig

app = Flask(__name__)
CORS(app)


@app.route('/')
def index():
    # Serve the web UI (index.html lives next to this file)
    return send_from_directory(config.BASE_DIR, 'index.html')


@app.route('/health')
def health():
    # Lightweight check the UI uses to show backend status
    return jsonify({"status": "ok"})


@app.route('/classifykex', methods=['POST'])
def classify_kex():
    file = request.files.get('file')
    if not file:
        return jsonify({"error": "No file provided"}), 400
    os.makedirs(config.UPLOAD_KEX, exist_ok=True)
    path = os.path.join(config.UPLOAD_KEX, file.filename)
    file.save(path)
    labels = kex.classify(path)
    return jsonify({"labels": labels})


@app.route('/classifysig', methods=['POST'])
def classify_sig():
    file = request.files.get('file')
    if not file:
        return jsonify({"error": "No file provided"}), 400
    os.makedirs(config.UPLOAD_SIG, exist_ok=True)
    path = os.path.join(config.UPLOAD_SIG, file.filename)
    file.save(path)
    labels = sig.classify(path)
    return jsonify({"labels": labels})


@app.route('/classify', methods=['POST'])
def classify_capture():
    # Detects PQ key exchange in an uploaded TLS .pcapng (pyshark + tshark).
    file = request.files.get('file')
    if not file:
        return jsonify({"error": "No file provided"}), 400
    os.makedirs(config.UPLOAD_CAP, exist_ok=True)
    path = os.path.join(config.UPLOAD_CAP, file.filename)
    file.save(path)
    try:
        import tls_capture
    except ImportError:
        return jsonify({"error": "pyshark not installed — run: pip install -r requirements.txt"}), 500
    try:
        results = tls_capture.classify(path)
    except Exception as e:
        # Most commonly tshark is missing; install via ./install_wireshark.sh
        return jsonify({"error": "Capture parsing failed — is tshark installed? "
                                 "Run ./install_wireshark.sh", "detail": str(e)[:300]}), 500
    return jsonify(results)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=config.PORT, debug=False)
