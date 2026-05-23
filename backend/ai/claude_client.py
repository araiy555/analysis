"""
Claude AI client for security analysis.
Uses claude-sonnet-4-6 (or falls back to claude-3-5-sonnet-20241022).
"""

from typing import Any

SYSTEM_PROMPTS: dict[str, str] = {
    "vulnerability": """あなたはモバイル・デスクトップアプリのセキュリティ専門家です。
提供されたコード、設定ファイル、またはバイナリ解析結果を分析し、以下を特定してください：
1. セキュリティ脆弱性（深刻度: HIGH/MEDIUM/LOW で分類）
2. 安全でないコーディングパターン
3. 認証・認可の問題
4. データの漏洩リスク
5. 暗号化の問題

各脆弱性について：
- **タイトル**: 脆弱性名
- **深刻度**: HIGH / MEDIUM / LOW
- **説明**: 脆弱性の詳細と悪用可能性
- **コード箇所**: 問題のある箇所
- **推奨対策**: 具体的な修正方法

日本語で回答してください。Markdownで整形してください。""",

    "code_review": """あなたはセキュリティに精通したシニアエンジニアです。
提供されたコードを包括的にレビューし、以下を評価してください：
1. セキュリティ上の問題点
2. コード品質と設計の問題
3. パフォーマンス上の懸念
4. ベストプラクティスへの準拠
5. 具体的な改善提案（コード例付き）

日本語で回答し、Markdownで整形してください。""",

    "reverse_engineering": """あなたはリバースエンジニアリングの専門家です。
提供された逆コンパイルコード、バイナリ解析結果、またはアセンブリを分析し：
1. コードの機能と目的を説明
2. 難読化・パッキング技術の特定
3. 通信プロトコルや暗号化方式の特定
4. 悪意あるコードパターンの特定
5. アンチ解析技術の特定

日本語で、技術的に詳細な説明を Markdown で提供してください。""",

    "privacy": """あなたはプライバシー・コンプライアンスの専門家です。
提供されたコードや設定を分析し：
1. 個人情報・センシティブデータの収集
2. 不要または過剰なデータ収集
3. データの保存・転送・共有の問題
4. GDPR・個人情報保護法への準拠
5. トラッキング・フィンガープリンティングの技術
6. 第三者 SDK によるデータ収集

日本語で回答し、Markdown で整形してください。""",

    "improvement": """あなたはセキュリティアーキテクトです。
提供されたコード・設定・解析結果を基に、セキュリティ改善提案を行ってください：
1. 優先度の高いセキュリティ改善（実装コード付き）
2. セキュリティ設計の改善
3. 使用すべきセキュリティフレームワークとライブラリ
4. テスト方法と検証手順
5. セキュリティチェックリスト

実装可能な具体的なコード例と共に、日本語で Markdown 形式で回答してください。""",
}


def analyze(
    api_key: str,
    analysis_type: str,
    content: str,
    history: list[dict] | None = None,
) -> str:
    """
    Send content to Claude for security analysis.
    Returns markdown-formatted analysis result.
    """
    try:
        import anthropic
    except ImportError:
        return "**エラー**: `anthropic` ライブラリがインストールされていません。\n\n```\npip install anthropic\n```"

    if not api_key.strip():
        return "**エラー**: Claude API キーが設定されていません。設定画面からキーを入力してください。"

    system_prompt = SYSTEM_PROMPTS.get(analysis_type, SYSTEM_PROMPTS["vulnerability"])

    messages: list[dict] = []

    # Add conversation history
    if history:
        for msg in history[-10:]:  # Keep last 10 messages for context
            if msg.get("role") in ("user", "assistant") and msg.get("content"):
                messages.append({"role": msg["role"], "content": msg["content"]})

    # Add current user message
    messages.append({"role": "user", "content": content})

    client = anthropic.Anthropic(api_key=api_key)

    try:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=8192,
            system=system_prompt,
            messages=messages,
        )
        return response.content[0].text if response.content else "応答が空でした。"
    except anthropic.AuthenticationError:
        return "**認証エラー**: API キーが無効です。正しい Claude API キーを設定してください。"
    except anthropic.RateLimitError:
        return "**レート制限エラー**: API のレート制限に達しました。しばらく待ってから再試行してください。"
    except anthropic.APIError as e:
        return f"**API エラー**: {str(e)}"
    except Exception as e:
        return f"**予期しないエラー**: {str(e)}"
