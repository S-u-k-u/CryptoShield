# 🛡 CryptoShield
### Self-Verifying Runtime Enforcement Framework for Crypto API Security

**Authors:** Sanjay Venkat (23BCE1928) & Sukumaran Sakthevelan (23BCE1876)  
**Course:** Cryptography — Semester End Project  
**Based on:** Torres et al. (2023) — *Runtime Verification of Crypto APIs*, IEEE TSE

---

## What This Project Does

CryptoShield is a **runtime enforcement system** that:

1. **Intercepts** insecure crypto API calls (DES, MD5, ECB, constant IVs) before they execute
2. **Corrects** them automatically using a correction map (DES → AES/GCM/NoPadding)
3. **Verifies** the correction using a **fixed-point convergence loop** with 3 deterministic checks
4. **Certifies** each enforcement action with a JSON audit certificate
5. **Visualises** all events on a live HTML dashboard

Unlike RVSec (base paper, F1=95%), CryptoShield does not just **detect** — it **enforces**.

---

## Quick Start

### Prerequisites
| Requirement | Check | Install |
|---|---|---|
| **Java 11+** | `java -version` | https://adoptium.net |
| **Python 3.8+** *(optional, for ML)* | `python3 --version` | https://python.org |
| **scikit-learn** *(optional)* | `pip show scikit-learn` | `pip3 install scikit-learn numpy` |

### Run on Linux / Mac
```bash
chmod +x run.sh
./run.sh
```

### Run on Windows
```
run_windows.bat
```

### Run in VS Code
1. Open this folder in VS Code
2. Install **Extension Pack for Java** (Microsoft)
3. Wait for Java project to be detected
4. Press **F5** or click `Run > Start Debugging`  
   *(VS Code will auto-compile and launch CryptoShieldMain)*

### Manual (any OS)
```bash
# 1. Compile
mkdir out
find src -name "*.java" | xargs javac -d out        # Linux/Mac
# or on Windows:
# dir /s /b src\*.java > sources.txt && javac -d out @sources.txt

# 2. (Optional) Start ML classifier in a separate terminal
cd ml
python3 ml_classifier.py

# 3. Run
java -cp out cryptoshield.demo.CryptoShieldMain
```

---

## Project Structure

```
CryptoShield/
├── src/cryptoshield/
│   ├── agent/
│   │   ├── CryptoInterceptor.java      ← Main intercept API (C1)
│   │   ├── EntropyCalculator.java      ← Shannon entropy for IV analysis
│   │   └── CryptoShieldDashboard.java  ← Event bus
│   ├── policy/
│   │   ├── SecurityPolicy.java         ← Approved algorithms + correction map
│   │   └── ViolationRecord.java        ← Data class for enforcement events
│   ├── corrector/
│   │   └── CryptoCorrector.java        ← Auto-corrects insecure configs (C3)
│   ├── verifier/
│   │   └── ConvergenceVerifier.java    ← Fixed-point loop + 3 checks (C3)
│   ├── certificate/
│   │   └── CertificateGenerator.java   ← JSON + HTML certificates (C4)
│   ├── ml/
│   │   └── MLBridge.java               ← Calls Python ML service (C2b)
│   └── demo/
│       ├── PaymentService.java         ← Intentionally vulnerable target app
│       └── CryptoShieldMain.java       ← Entry point — runs all scenarios
│
├── ml/
│   └── ml_classifier.py               ← Random Forest classifier + Flask (C2b)
│
├── dashboard/
│   └── dashboard.html                 ← Live dashboard (C5)
│
├── certificates/                       ← Generated at runtime
│   ├── CS-XXXX-XXXX.json             ← Per-event certificates
│   └── report.html                    ← Cumulative HTML report (C4+C5)
│
├── .vscode/
│   ├── launch.json                    ← F5 debug config
│   ├── tasks.json                     ← Build task
│   └── settings.json                  ← Java source paths
│
├── run.sh                             ← Linux/Mac one-click build+run
├── run_windows.bat                    ← Windows one-click build+run
└── README.md
```

---

## Demo Scenarios

The demo runs 6 scenarios through `PaymentService.java`:

| # | Call | CWE | CryptoShield Action |
|---|---|---|---|
| 1 | `Cipher.getInstance("DES")` | CWE-327 | → AES/GCM/NoPadding |
| 2 | `MessageDigest.getInstance("MD5")` | CWE-328 | → SHA-256 |
| 3 | `MessageDigest.getInstance("SHA-1")` | CWE-328 | → SHA-256 |
| 4 | `Cipher.getInstance("AES/ECB/PKCS5Padding")` | CWE-327 | → AES/GCM/NoPadding |
| 5 | `IvParameterSpec("Hello World!!!!!")` | CWE-329 | → SecureRandom IV |
| 6 | `Cipher.getInstance("AES/GCM/NoPadding")` | SAFE | Pass through ✓ |

---

## Fixed-Point Convergence (Key Novelty)

After correction, the system runs up to **5 verification iterations**, each checking:

1. **Algorithm Whitelist** — corrected algorithm must be in the approved set
2. **ECB Pattern Test** — encrypts two identical blocks; ECB produces identical output (FAIL)
3. **Config Stability** — configuration vector `{algo, mode, keysize}` must not change between iterations

> **Why not compare ciphertexts?**  
> AES/GCM produces different ciphertext every run (random IV by design).  
> CryptoShield's fixed point is defined on the **configuration state**, not the output.

---

## ML Classifier (Optional Enhancement)

Start the Python ML service before running the Java demo for confidence scores:

```bash
cd ml
python3 ml_classifier.py
```

The Random Forest classifier is trained on synthetic data derived from CWE rules and MASCBench patterns. It assigns a **0.0–1.0 misuse confidence** to each intercepted call. If the service is not running, the system falls back to rule-only enforcement automatically.

---

## Dashboard

After running the demo:
1. Open `dashboard/dashboard.html` in your browser
2. It auto-reads from `certificates/*.json` (no server needed)
3. Shows: Enforcement Feed, ML Confidence meters, CWE pie chart, Certificate viewer

Or open `certificates/report.html` for a static summary report.

---

## Architecture vs. RVSec

| Capability | RVSec (Base Paper) | CryptoShield |
|---|---|---|
| Detects misuse | ✓ (F1 = 95%) | ✓ |
| Blocks insecure call | ✗ | ✓ |
| Auto-corrects | ✗ | ✓ |
| ML confidence scoring | ✗ | ✓ |
| Fixed-point verification | ✗ | ✓ |
| IV entropy analysis | ✗ | ✓ |
| ECB pattern test | ✗ | ✓ |
| Audit certificate (JSON) | ✗ | ✓ |
| Live dashboard | ✗ | ✓ |

---

## Integrating Into Your Own Code

Replace standard JCA calls with CryptoInterceptor equivalents:

```java
import cryptoshield.agent.CryptoInterceptor;

// Instead of: Cipher.getInstance("DES")
Cipher c = CryptoInterceptor.getCipher("DES", MyClass.class);

// Instead of: MessageDigest.getInstance("MD5")
MessageDigest md = CryptoInterceptor.getMessageDigest("MD5", MyClass.class);

// Instead of: new IvParameterSpec(someBytes)
IvParameterSpec iv = CryptoInterceptor.getIvParameterSpec(someBytes, MyClass.class);

// SecureRandom (safe as-is, but use interceptor to block seeded versions)
SecureRandom sr = CryptoInterceptor.getSecureRandom();
```

---

*CryptoShield — transforms runtime verification from a passive observer into an active security enforcer.*
