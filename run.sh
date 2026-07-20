#!/bin/bash
# CryptoShield — Linux/Mac Build & Run Script
set -e
SRCDIR="src"; OUTDIR="out"; MAIN="cryptoshield.demo.CryptoShieldMain"; ML_PID=""
cleanup() { [ -n "$ML_PID" ] && kill "$ML_PID" 2>/dev/null || true; }
trap cleanup EXIT INT TERM
echo ""; echo " === CryptoShield Build & Run ==="; echo ""
command -v java &>/dev/null || { echo "[ERROR] Java not found"; exit 1; }
echo "[1/4] Cleaning..."; rm -rf "$OUTDIR"; mkdir -p "$OUTDIR"
echo "[2/4] Compiling..."; find "$SRCDIR" -name "*.java" | xargs javac -d "$OUTDIR"; echo "      OK"
echo "[3/4] Starting ML classifier..."
if command -v python3 &>/dev/null && python3 -c "import sklearn" 2>/dev/null; then
    cd ml && python3 ml_classifier.py &> /tmp/cs_ml.log & ML_PID=$! && cd ..
    sleep 2; echo "      ML on port 5001 (PID $ML_PID)"
else
    echo "      No sklearn — rule-only mode"
fi
echo "[4/4] Running demo..."; echo ""
java -cp "$OUTDIR" "$MAIN"
echo ""; echo "Done! Open certificates/report.html or dashboard/dashboard.html"
