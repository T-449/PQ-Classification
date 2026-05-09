import os
from flask import Flask, request, jsonify
from flask_cors import CORS

import config
from classifiers import kex, sig

app = Flask(__name__)
CORS(app)


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


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=config.PORT, debug=False)
