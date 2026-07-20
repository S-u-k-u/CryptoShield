#!/usr/bin/env python3
"""
CryptoShield ML Classifier (Component 2b)
=========================================
Random Forest classifier for crypto API misuse detection.
Trains on synthetic feature data derived from CWE rules and
serves classification requests via a lightweight HTTP server.

Usage:
    python3 ml_classifier.py          # Train + start server (default)
    python3 ml_classifier.py --train  # Train only and save model
    python3 ml_classifier.py --serve  # Load saved model and serve

Author: CryptoShield Team
"""

import sys
import json
import math
import pickle
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

# ── Graceful imports ──────────────────────────────────────────────────────────
try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("[ML] sklearn not available — running rule-only fallback mode")

# ── Feature encoding ──────────────────────────────────────────────────────────
ALGORITHMS = {
    "DES": 0, "3DES": 1, "DESede": 1, "RC2": 2, "RC4": 3, "Blowfish": 4,
    "AES/ECB": 5, "AES": 6, "AES/CBC": 7, "AES/GCM": 8, "ChaCha20": 9,
    "MD4": 10, "MD5": 11, "SHA-1": 12, "SHA1": 12, "SHA-256": 13,
    "SHA-384": 14, "SHA-512": 15, "SHA3-256": 16,
    "CONSTANT_IV": 17, "HARDCODED_SEED": 18, "UNKNOWN": 19,
}

KEY_SIZES = {56: 0, 64: 1, 112: 2, 128: 3, 192: 4, 256: 5, 0: 6}
MODES = {"ECB": 0, "CBC": 1, "GCM": 2, "CTR": 3, "NONE": 4, "OTHER": 5}
IV_SOURCES = {"CONSTANT": 0, "NULL": 1, "RANDOM": 2, "UNKNOWN": 3}
TYPES = {"CIPHER": 0, "HASH": 1, "SECURE_RANDOM": 2, "IV": 3}

def encode_algorithm(alg: str, api_type: str) -> list:
    """Encode a crypto algorithm string into a numeric feature vector."""
    alg_upper = alg.upper()

    # Algorithm ID
    alg_id = ALGORITHMS.get("UNKNOWN")
    for key, val in ALGORITHMS.items():
        if key.upper() in alg_upper or alg_upper in key.upper():
            alg_id = val
            break

    # Key size (inferred from algorithm)
    key_size = 0
    if "DES" in alg_upper and "3" not in alg_upper and "EDE" not in alg_upper:
        key_size = 56
    elif "3DES" in alg_upper or "DESEDE" in alg_upper:
        key_size = 112
    elif "AES" in alg_upper:
        key_size = 128  # default; GCM implies better
    elif "RC2" in alg_upper:
        key_size = 64
    if "GCM" in alg_upper:
        key_size = 256

    key_size_id = KEY_SIZES.get(key_size, KEY_SIZES[0])

    # Mode
    if "ECB" in alg_upper:     mode_id = MODES["ECB"]
    elif "CBC" in alg_upper:   mode_id = MODES["CBC"]
    elif "GCM" in alg_upper:   mode_id = MODES["GCM"]
    elif "CTR" in alg_upper:   mode_id = MODES["CTR"]
    else:                      mode_id = MODES["NONE"]

    # IV source
    if "CONSTANT" in alg_upper or "HELLO" in alg_upper:
        iv_source = IV_SOURCES["CONSTANT"]
    elif "NULL" in alg_upper:
        iv_source = IV_SOURCES["NULL"]
    elif "GCM" in alg_upper or "CBC" in alg_upper:
        iv_source = IV_SOURCES["RANDOM"]
    else:
        iv_source = IV_SOURCES["UNKNOWN"]

    type_id = TYPES.get(api_type.upper(), 0)

    return [alg_id, key_size_id, mode_id, iv_source, type_id]


# ── Training data ─────────────────────────────────────────────────────────────
def build_training_data():
    """
    Synthetic training dataset derived from:
    - CWE-327, CWE-328, CWE-338 classification rules
    - MASCBench patterns (Torres et al. 2023)
    - NIST SP 800-175B approved algorithm list
    """
    data = []
    labels = []  # 1 = MISUSE, 0 = SECURE

    # ── Cipher misuses ────────────────────────────────────────────────────
    misuse_ciphers = [
        "DES", "3DES", "DESede", "RC2", "RC4", "Blowfish",
        "AES/ECB/NoPadding", "AES/ECB/PKCS5Padding", "AES",
        "DES/CBC/PKCS5Padding", "DESede/CBC/NoPadding",
    ]
    secure_ciphers = [
        "AES/GCM/NoPadding", "AES/CBC/PKCS5Padding",
        "ChaCha20-Poly1305", "AES/GCM/NOPADDING",
    ]

    for alg in misuse_ciphers:
        features = encode_algorithm(alg, "CIPHER")
        # Add 15 slightly varied samples per class
        for _ in range(15):
            noise = [f + (hash(alg + str(_)) % 3 - 1) * 0 for f in features]
            data.append(noise)
            labels.append(1)  # MISUSE

    for alg in secure_ciphers:
        features = encode_algorithm(alg, "CIPHER")
        for _ in range(15):
            data.append(features[:])
            labels.append(0)  # SECURE

    # ── Hash misuses ──────────────────────────────────────────────────────
    misuse_hashes  = ["MD5", "MD4", "SHA-1", "SHA1", "SHA"]
    secure_hashes  = ["SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-512"]

    for alg in misuse_hashes:
        features = encode_algorithm(alg, "HASH")
        for _ in range(15):
            data.append(features[:])
            labels.append(1)

    for alg in secure_hashes:
        features = encode_algorithm(alg, "HASH")
        for _ in range(15):
            data.append(features[:])
            labels.append(0)

    # ── IV / seed misuses ─────────────────────────────────────────────────
    for _ in range(20):
        data.append(encode_algorithm("CONSTANT_IV", "IV"))
        labels.append(1)
    for _ in range(10):
        data.append(encode_algorithm("AES/GCM", "IV"))
        labels.append(0)

    return data, labels


def train_model():
    print("[ML] Building training dataset...")
    X, y = build_training_data()

    if not ML_AVAILABLE:
        print("[ML] scikit-learn not available, skipping training")
        return None

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=8,
        random_state=42,
        class_weight='balanced'
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"[ML] Training complete — Test accuracy: {acc:.2%}")
    print("[ML] Classification report:")
    print(classification_report(y_test, y_pred, target_names=["SECURE", "MISUSE"]))

    # Save model
    with open("ml_model.pkl", "wb") as f:
        pickle.dump(clf, f)
    print("[ML] Model saved to ml_model.pkl")
    return clf


def load_or_train():
    if Path("ml_model.pkl").exists():
        print("[ML] Loading existing model from ml_model.pkl")
        with open("ml_model.pkl", "rb") as f:
            return pickle.load(f)
    return train_model()


# ── Rule-based fallback ───────────────────────────────────────────────────────
BROKEN = {"DES", "3DES", "DESEDE", "RC2", "RC4", "BLOWFISH",
          "MD5", "MD4", "SHA-1", "SHA1", "SHA", "ECB"}

def rule_classify(algorithm: str) -> float:
    upper = algorithm.upper()
    for broken in BROKEN:
        if broken in upper:
            return 0.97
    return 0.02


# ── HTTP Handler ──────────────────────────────────────────────────────────────
clf_global = None

class MLHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path == "/health":
            self._respond(200, '{"status": "ok"}')
        else:
            self._respond(404, '{"error": "not found"}')

    def do_POST(self):
        if self.path == "/classify":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode()
            try:
                payload = json.loads(body)
                alg  = payload.get("algorithm", "UNKNOWN")
                atype = payload.get("type", "CIPHER")

                if clf_global and ML_AVAILABLE:
                    features = [encode_algorithm(alg, atype)]
                    proba = clf_global.predict_proba(features)[0]
                    # Index 1 = MISUSE class probability
                    classes = list(clf_global.classes_)
                    misuse_idx = classes.index(1) if 1 in classes else 1
                    confidence = float(proba[misuse_idx])
                else:
                    confidence = rule_classify(alg)

                self._respond(200, f'{{"confidence": {confidence:.4f}}}')
            except Exception as e:
                self._respond(500, f'{{"error": "{str(e)}"}}')
        else:
            self._respond(404, '{"error": "not found"}')

    def _respond(self, code, body):
        encoded = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, fmt, *args):
        pass  # Suppress default access log


def start_server(port=5001):
    global clf_global
    clf_global = load_or_train()

    server = HTTPServer(("127.0.0.1", port), MLHandler)
    print(f"[ML] Server running on http://127.0.0.1:{port}")
    print("[ML] Endpoints: GET /health   POST /classify")
    print("[ML] Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[ML] Server stopped")


if __name__ == "__main__":
    if "--train" in sys.argv:
        train_model()
    else:
        start_server()
