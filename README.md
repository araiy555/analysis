# AppSleuth - 総合アプリセキュリティ解析ツール

Android APK・Windows EXE/DLL・macOS バイナリ・Webアプリの解析を一つのデスクトップアプリで行えます。

## 機能

| 機能 | 説明 |
|------|------|
| 静的解析 | APK/EXE/DLL/Mach-O の権限・証明書・文字列・脆弱性を自動解析 |
| ネットワーク解析 | HTTP/S プロキシによるリアルタイムトラフィック傍受 |
| メモリ解析 | Frida 動的インストゥルメンテーション (SSL バイパス・フック・ダンプ) |
| AI 解析 | Claude AI による脆弱性分析・コードレビュー・改善提案 |
| レポート | HTML/JSON 形式のセキュリティレポート生成 |

## 動作環境

- **Windows** 10/11 (x64)
- **macOS** 12+ (Intel / Apple Silicon)
- **Node.js** 18+ 
- **Python** 3.10+

## インストール

### macOS / Linux
```bash
bash scripts/install.sh
```

### Windows
```batch
scripts\install.bat
```

### 手動インストール
```bash
# npm パッケージ
npm install

# Python バックエンド
cd backend
pip install -r requirements.txt
```

## 起動方法

### 開発モード
```bash
# ターミナル1: バックエンド
cd backend && python main.py

# ターミナル2: フロントエンド
npm run dev
```

### 本番ビルド
```bash
npm run build:win    # Windows .exe インストーラ
npm run build:mac    # macOS .dmg
```

## ディレクトリ構成

```
appsleuth/
├── electron/              # Electron メインプロセス
├── src/                   # React フロントエンド
│   └── components/        # UI コンポーネント
├── backend/               # Python FastAPI バックエンド
│   ├── analyzers/         # 静的解析エンジン
│   ├── network/           # ネットワークプロキシ
│   ├── memory/            # Frida クライアント
│   └── ai/                # Claude AI クライアント
└── scripts/               # インストールスクリプト
```

## オプションツール

| ツール | 用途 | インストール |
|--------|------|-------------|
| apktool | APK 逆コンパイル | https://apktool.org/ |
| jadx | DEX→Java 変換 | https://github.com/skylot/jadx |
| frida | 動的解析 | `pip install frida frida-tools` |
| mitmproxy | SSL 傍受 | `pip install mitmproxy` |

## Claude API キーの設定

1. https://console.anthropic.com でアカウント作成
2. API キーを取得 (`sk-ant-...`)
3. アプリの「設定」または「AI 解析」タブでキーを入力

## 注意事項

このツールはセキュリティ研究・ペネトレーションテスト・脆弱性調査を目的として設計されています。
自分が権限を持つシステムや、適切な許可を得たシステムにのみ使用してください。

## ライセンス

MIT License
