#!/usr/bin/env bash
# =====================================================
#  AppSleuth - Mac ビルドスクリプト
#  実行後: dist/mac/AppSleuth.dmg が生成されます
# =====================================================
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo ""
echo "╔══════════════════════════════════════╗"
echo "║   AppSleuth Mac ビルド               ║"
echo "╚══════════════════════════════════════╝"
echo ""

# ── 1. 依存関係チェック ────────────────────────────────

check() {
  command -v "$1" &>/dev/null || { echo "[ERROR] $1 が見つかりません"; exit 1; }
}
check python3
check node
check npm

PYTHON_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "[✓] Python $PYTHON_VER"
echo "[✓] Node $(node -v)"

# ── 2. Python 仮想環境 & 依存パッケージ ───────────────

echo ""
echo "[1/4] Python パッケージをインストール中..."

cd "$ROOT/backend"
if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi
source .venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q
pip install pyinstaller -q

# ── 3. PyInstaller でバックエンドをバイナリ化 ─────────

echo "[2/4] バックエンドを単体バイナリにビルド中..."
echo "      (初回は数分かかります)"

pyinstaller backend.spec \
  --clean \
  --noconfirm \
  --distpath "$ROOT/resources/bin"

deactivate

BACKEND_BIN="$ROOT/resources/bin/appsleuth-backend"
if [ ! -f "$BACKEND_BIN" ]; then
  echo "[ERROR] バックエンドのビルドに失敗しました"
  exit 1
fi
echo "[✓] バックエンドバイナリ: resources/bin/appsleuth-backend"

# ── 4. npm パッケージ ─────────────────────────────────

echo "[3/4] npm パッケージをインストール中..."
cd "$ROOT"
npm install --silent

# ── 5. Electron アプリをビルド ────────────────────────

echo "[4/4] Electron アプリをビルド中..."
npm run build:mac

echo ""
echo "╔══════════════════════════════════════╗"
echo "║   ✅ ビルド完了!                     ║"
echo "║   dist/mac/ に AppSleuth.dmg があります ║"
echo "╚══════════════════════════════════════╝"
echo ""
open "$ROOT/dist/mac" 2>/dev/null || true
