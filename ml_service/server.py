"""
CryptoShield ML Service — Flask REST API
Endpoint: POST /classify
Body:      {"algorithm":"DES","api_type":"CIPHER","rule_flagged":true}
Response:  {"verdict":"MISUSE","confidence":0.97,"features":{...}}

Start: python3 ml_service/server.py
"""
from flask import Flask, request, jsonify
import joblib, json, os, sys

app = Flask(__name__)

# ── Load model ────────────────────────────────────────────────────────────────
BASE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE, "model.pkl")
META_PATH  = os.path.join(BASE, "model_meta.json")

if not os.path.exists(MODEL_PATH):
    print("ERROR: model.pkl not found. Run: python3 ml_service/train_model.py first")
    sys.exit(1)

clf  = joblib.load(MODEL_PATH)
meta = json.load(open(META_PATH))
ALGO_MAP = meta["algo_map"]
API_MAP  = meta["api_map"]

def encode_algo(a: str) -> int:
    key = a.upper().replace(" ","")
    return ALGO_MAP.get(key, ALGO_MAP.get(key.replace("-",""), 99))

def encode_api(a: str) -> int:
    return API_MAP.get(a.upper(), 0)

def estimate_entropy(algo: str) -> float:
    a = algo.upper()
    if any(b in a for b in ["MD5","MD4","SHA1","SHA-1","DES","RC4","BLOWFISH","ECB","RC2"]):
        return 1.5   # low entropy (constant / predictable)
    return 7.9       # high entropy (secure)

def estimate_keysize(algo: str) -> int:
    a = algo.upper()
    if "DES" in a and "3DES" not in a and "DESEDE" not in a: return 56
    if "3DES" in a or "DESEDE" in a: return 112
    if "RC4" in a: return 128
    if "256" in a or "GCM" in a: return 256
    if "128" in a or "CBC" in a: return 128
    return 0

@app.route("/classify", methods=["POST"])
def classify():
    data = request.get_json(force=True)
    algo      = data.get("algorithm","UNKNOWN")
    api_type  = data.get("api_type","CIPHER")
    rule_flag = bool(data.get("rule_flagged", False))

    features = [[
        encode_algo(algo),
        encode_api(api_type),
        int(rule_flag),
        estimate_entropy(algo),
        estimate_keysize(algo)
    ]]

    proba    = clf.predict_proba(features)[0]
    pred     = clf.predict(features)[0]
    # index 1 = MISUSE, index 0 = SAFE
    misuse_conf = float(proba[1]) if len(proba) > 1 else float(pred)
    safe_conf   = float(proba[0]) if len(proba) > 1 else 1 - float(pred)

    verdict    = "MISUSE" if pred == 1 else "SAFE"
    confidence = misuse_conf if verdict == "MISUSE" else safe_conf

    return jsonify({
        "verdict":    verdict,
        "confidence": round(confidence, 4),
        "algorithm":  algo,
        "features":   {
            "algo_code":    features[0][0],
            "api_type_code":features[0][1],
            "rule_flagged": rule_flag,
            "iv_entropy":   features[0][3],
            "key_size":     features[0][4]
        }
    })

@app.route("/health")
def health():
    return jsonify({"status":"ok","model_accuracy": meta["accuracy"]})

if __name__ == "__main__":
    print("="*52)
    print("  CryptoShield ML Service starting on port 5001")
    print(f"  Model accuracy: {meta['accuracy']*100:.1f}%")
    print("="*52)
    app.run(host="127.0.0.1", port=5001, debug=False)
