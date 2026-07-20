"""
CryptoShield ML Service — Model Training Script
Trains a Random Forest classifier on synthetic + benchmark-style crypto misuse data.
Run once: python3 train_model.py
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import LabelEncoder
import joblib, json, os

# ── Feature encoding maps ────────────────────────────────────────────────────
ALGO_MAP = {
    # Broken ciphers → high risk score
    "DES":0,"DESEDE":1,"3DES":1,"RC4":2,"RC2":3,"BLOWFISH":4,
    "AES/ECB/PKCS5PADDING":5,"AES/ECB/NOPADDING":6,"AES":7,
    # Secure ciphers → low risk
    "AES/GCM/NOPADDING":10,"AES/CBC/PKCS5PADDING":11,"CHACHA20":12,
    # Broken digests
    "MD5":20,"MD4":21,"SHA-1":22,"SHA1":22,"SHA":23,"MD2":24,
    # Secure digests
    "SHA-256":30,"SHA-384":31,"SHA-512":32,"SHA3-256":33,"SHA3-512":34,
    # Unknown
    "UNKNOWN":99
}

APITYPE_MAP = {"CIPHER":0,"DIGEST":1,"SECURERANDOM":2,"KEYGEN":3,"IV":4}

# ── Synthetic training dataset ────────────────────────────────────────────────
def make_dataset():
    rows = []
    def add(algo, api, rule, iv_entropy, key_size, label):
        algo_code = ALGO_MAP.get(algo.upper().replace("/","").replace("-",""), 99)
        api_code  = APITYPE_MAP.get(api.upper(), 0)
        rows.append([algo_code, api_code, int(rule), iv_entropy, key_size, label])

    # ── Definite misuses (label=1) ──────────────────────────────────────────
    for _ in range(80):
        add("DES",              "CIPHER",  True,  1.2, 56,  1)
        add("DESEDE",           "CIPHER",  True,  1.8, 112, 1)
        add("RC4",              "CIPHER",  True,  0.5, 128, 1)
        add("MD5",              "DIGEST",  True,  8.0, 0,   1)
        add("SHA-1",            "DIGEST",  True,  8.0, 0,   1)
        add("AES/ECB/PKCS5PADDING","CIPHER",True, 0.0, 128, 1)
        add("MD4",              "DIGEST",  True,  8.0, 0,   1)
        add("RC2",              "CIPHER",  True,  2.1, 64,  1)
    # Rule missed, ML should catch
    for _ in range(30):
        add("DES",              "CIPHER",  False, 0.9, 56,  1)  # rule glitch
        add("MD5",              "DIGEST",  False, 8.0, 0,   1)
        add("BLOWFISH",         "CIPHER",  False, 3.5, 64,  1)

    # ── Secure uses (label=0) ──────────────────────────────────────────────
    for _ in range(80):
        add("AES/GCM/NOPADDING","CIPHER",  False, 7.9, 256, 0)
        add("AES/CBC/PKCS5PADDING","CIPHER",False, 7.8, 256, 0)
        add("SHA-256",          "DIGEST",  False, 8.0, 0,   0)
        add("SHA-512",          "DIGEST",  False, 8.0, 0,   0)
        add("CHACHA20",         "CIPHER",  False, 7.95,256, 0)
        add("SHA3-256",         "DIGEST",  False, 8.0, 0,   0)
    # Edge cases — secure
    for _ in range(20):
        add("AES/GCM/NOPADDING","CIPHER",  True,  7.5, 128, 0)  # false positive rule
        add("SHA-256",          "DIGEST",  True,  8.0, 0,   0)

    return pd.DataFrame(rows, columns=["algo","api_type","rule_flagged","iv_entropy","key_size","label"])

# ── Train ────────────────────────────────────────────────────────────────────
print("Training CryptoShield Random Forest classifier...")
df = make_dataset()

X = df[["algo","api_type","rule_flagged","iv_entropy","key_size"]]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

clf = RandomForestClassifier(
    n_estimators=120,
    max_depth=10,
    min_samples_leaf=2,
    random_state=42,
    class_weight="balanced"
)
clf.fit(X_train, y_train)

y_pred = clf.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"\n{'='*48}")
print(f"  Accuracy : {acc*100:.1f}%")
print(f"{'='*48}")
print(classification_report(y_test, y_pred, target_names=["SAFE","MISUSE"]))

# Save model + metadata
BASE = os.path.dirname(os.path.abspath(__file__))
joblib.dump(clf, os.path.join(BASE, "model.pkl"))

meta = {
    "accuracy": round(float(acc), 4),
    "features": ["algo","api_type","rule_flagged","iv_entropy","key_size"],
    "algo_map": ALGO_MAP,
    "api_map":  APITYPE_MAP
}
with open(os.path.join(BASE, "model_meta.json"), "w") as f:
    json.dump(meta, f, indent=2)

print("\nModel saved → ml_service/model.pkl")
print("Meta  saved → ml_service/model_meta.json")
