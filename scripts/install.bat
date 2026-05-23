@echo off
echo ======================================
echo   AppSleuth セキュリティ解析ツール
echo   インストールスクリプト (Windows)
echo ======================================
echo.

REM Python チェック
python --version >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Python が見つかりません。python.org からインストールしてください。
  pause
  exit /b 1
)
echo [OK] Python が見つかりました

REM Node.js チェック
node --version >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Node.js が見つかりません。nodejs.org からインストールしてください。
  pause
  exit /b 1
)
echo [OK] Node.js が見つかりました

echo.
echo [*] npm パッケージをインストール中...
call npm install
if errorlevel 1 (
  echo [ERROR] npm install に失敗しました
  pause
  exit /b 1
)

echo.
echo [*] Python 仮想環境をセットアップ中...
cd backend
python -m venv .venv
call .venv\Scripts\activate.bat

echo [*] Python 依存関係をインストール中...
python -m pip install --upgrade pip -q
pip install -r requirements.txt
if errorlevel 1 (
  echo [ERROR] Python パッケージのインストールに失敗しました
  pause
  exit /b 1
)

echo.
echo [*] オプションツールのチェック:
apktool --version >nul 2>&1
if errorlevel 1 (
  echo [!] apktool が見つかりません: https://apktool.org/
) else (
  echo [OK] apktool が見つかりました
)

jadx --version >nul 2>&1
if errorlevel 1 (
  echo [!] jadx が見つかりません: https://github.com/skylot/jadx/releases
) else (
  echo [OK] jadx が見つかりました
)

echo.
echo ======================================
echo [OK] インストール完了!
echo.
echo 起動方法:
echo   npm run dev           # 開発モード
echo   npm run build:win     # Windows インストーラをビルド
echo.
echo バックエンドのみ起動:
echo   cd backend ^&^& .venv\Scripts\activate ^&^& python main.py
echo ======================================
pause
