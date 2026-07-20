@echo off
:: CryptoShield — Windows Build & Run Script
:: Requires Java 11+ (check with: java -version)

setlocal EnableDelayedExpansion
set SRCDIR=src
set OUTDIR=out
set MAIN=cryptoshield.demo.CryptoShieldMain

echo.
echo  ========================================================
echo   CryptoShield — Build ^& Run
echo  ========================================================
echo.

:: Check Java
java -version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Java not found. Install Java 11+ and add to PATH.
    echo         Download: https://adoptium.net
    pause
    exit /b 1
)

echo [1/4] Cleaning output directory...
if exist %OUTDIR% rmdir /s /q %OUTDIR%
mkdir %OUTDIR%

echo [2/4] Compiling Java sources...
:: Collect all .java files
set SOURCES=
for /r %SRCDIR% %%f in (*.java) do set SOURCES=!SOURCES! "%%f"

javac -d %OUTDIR% %SOURCES%
if errorlevel 1 (
    echo [ERROR] Compilation failed. Check errors above.
    pause
    exit /b 1
)
echo     Compilation successful.

echo [3/4] (Optional) Starting ML classifier in background...
where python >nul 2>&1
if not errorlevel 1 (
    start /b "ML Classifier" python ml\ml_classifier.py
    echo     ML classifier starting on port 5001...
    timeout /t 3 /nobreak >nul
) else (
    echo     Python not found — running in rule-only mode.
)

echo [4/4] Running CryptoShield demo...
echo.
java -cp %OUTDIR% %MAIN%

echo.
echo  ========================================================
echo   Demo complete! Open certificates\report.html for report
echo   Open dashboard\dashboard.html for live dashboard
echo  ========================================================
echo.
pause
