#!/usr/bin/env bash
# AppSleuth インストールスクリプト (macOS / Linux)
set -e

echo "======================================"
echo "  AppSleuth セキュリティ解析ツール"
echo "  インストールスクリプト"
echo "======================================"
echo ""

# Python チェック
if ! command -v python3 &>/dev/null; then
  echo "[ERROR] Python 3 が見つかりません。python.org からインストールしてください。"
  exit 1
fi
PYTHON_VER=$(python3 --version | awk '{print $2}')
echo "[✓] Python $PYTHON_VER"

# Node.js チェック
if ! command -v node &>/dev/null; then
  echo "[ERROR] Node.js が見つかりません。nodejs.org からインストールしてください。"
  exit 1
fi
NODE_VER=$(node --version)
echo "[✓] Node.js $NODE_VER"

# npm インストール
echo ""
echo "[*] npm パッケージをインストール中..."
npm install

# Python 仮想環境
echo ""
echo "[*] Python 仮想環境をセットアップ中..."
cd backend
python3 -m venv .venv
source .venv/bin/activate

echo "[*] Python 依存関係をインストール中..."
pip install --upgrade pip -q
pip install -r requirements.txt

echo ""
echo "[*] オプションツールのチェック:"

# apktool
if command -v apktool &>/dev/null; then
  echo "[✓] apktool: $(apktool --version 2>&1 | head -1)"
else
  echo "[!] apktool が見つかりません (APK 解析に必要)"
  echo "    インストール: https://apktool.org/"
fi

# jadx
if command -v jadx &>/dev/null; then
  echo "[✓] jadx: 利用可能"
else
  echo "[!] jadx が見つかりません (APK 逆コンパイルに必要)"
  echo "    インストール: https://github.com/skylot/jadx/releases"
fi

echo ""
echo "======================================"
echo "[✓] インストール完了!"
echo ""
echo "起動方法:"
echo "  npm run dev          # 開発モード"
echo "  npm run build:mac    # macOS アプリをビルド"
echo ""
echo "バックエンドのみ起動:"
echo "  cd backend && source .venv/bin/activate && python main.py"
echo "======================================"
