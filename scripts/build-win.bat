@echo off
echo.
echo ============================================
echo   AppSleuth Windows Build Script
echo ============================================
echo.

set ROOT=%~dp0..
cd /d "%ROOT%"

REM ── 依存関係チェック ──────────────────────────────────
python --version >nul 2>&1 || (echo [ERROR] Python not found && pause && exit /b 1)
node --version >nul 2>&1   || (echo [ERROR] Node.js not found && pause && exit /b 1)
echo [OK] Python and Node.js found

REM ── Python 仮想環境 & パッケージ ─────────────────────
echo.
echo [1/4] Installing Python packages...
cd "%ROOT%\backend"
if not exist ".venv" python -m venv .venv
call .venv\Scripts\activate.bat
pip install --upgrade pip -q
pip install -r requirements.txt -q
pip install pyinstaller -q

REM ── PyInstaller ───────────────────────────────────────
echo [2/4] Building backend binary...
pyinstaller backend.spec --clean --noconfirm --distpath "%ROOT%\resources\bin"
if errorlevel 1 (echo [ERROR] Backend build failed && pause && exit /b 1)
echo [OK] Backend binary built

REM ── npm ──────────────────────────────────────────────
echo [3/4] Installing npm packages...
cd /d "%ROOT%"
call npm install --silent

REM ── Electron build ────────────────────────────────────
echo [4/4] Building Electron app...
call npm run build:win
if errorlevel 1 (echo [ERROR] Electron build failed && pause && exit /b 1)

echo.
echo ============================================
echo   Build complete!
echo   Check dist\win\ for AppSleuth-Setup.exe
echo ============================================
start "" "%ROOT%\dist\win"
pause
