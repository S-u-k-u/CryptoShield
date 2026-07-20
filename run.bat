@echo off
REM ╔══════════════════════════════════════════════════╗
REM ║      CryptoShield — One-Click Launcher           ║
REM ║      Windows                                     ║
REM ╚══════════════════════════════════════════════════╝

cd /d "%~dp0"
echo.
echo ============================================================
echo   CryptoShield v1.0  --  Setup and Run
echo ============================================================
echo.

REM Step 1: Check Java
java -version >nul 2>&1
if errorlevel 1 (echo ERROR: Java not found. Install JDK 11+ & goto :end)
echo [OK] Java found

REM Step 2: Check Python
python --version >nul 2>&1
if errorlevel 1 (echo ERROR: Python not found. Install Python 3.8+ & goto :end)
echo [OK] Python found

REM Step 3: Install deps
echo [..] Installing Python packages...
python -m pip install flask scikit-learn numpy joblib --quiet

REM Step 4: Train model
if not exist ml_service\model.pkl (
    echo [..] Training ML model...
    python ml_service\train_model.py
    echo [OK] ML model trained
) else (
    echo [OK] ML model already exists
)

REM Step 5: Compile Java
echo [..] Compiling Java...
if exist out rmdir /s /q out
mkdir out

dir /b /s src\*.java > sources.txt
javac -d out @sources.txt
javac -d out -cp out demo\VulnerableApp.java
copy src\dashboard.html out\ >nul
del sources.txt

echo [OK] Java compiled

REM Step 6: Start ML service in background
echo [..] Starting ML service...
start /b python ml_service\server.py
timeout /t 3 /nobreak >nul
echo [OK] ML service started

REM Step 7: Run demo
echo.
echo ============================================================
echo   Dashboard: http://localhost:8888
echo   Open in browser THEN press any key to continue
echo ============================================================
echo.
pause

java -cp out demo.VulnerableApp

:end
pause
