"""
S3 data fetcher for stock chat.
Selects relevant folders based on question keywords and fetches recent data.
"""

import json
import re
from datetime import datetime
from typing import Any


FOLDER_MAP = {
    "screnn-production/": ["おすすめ", "スクリーニング", "銘柄", "推奨", "候補", "screen", "pick"],
    "analysis-production/": ["分析", "解析", "analysis", "レポート"],
    "Financial/": ["財務", "業績", "PER", "PBR", "売上", "利益", "financial"],
    "japan-stocks-5years-chart/": ["チャート", "株価", "推移", "chart", "price", "値動き"],
    "economics/": ["経済", "GDP", "インフレ", "金利", "マクロ", "economics"],
    "correlation-production/": ["相関", "correlation", "関係"],
    "backtest-production/": ["バックテスト", "backtest", "戦略", "パフォーマンス"],
    "fx-strategies/": ["FX", "為替", "ドル", "円"],
    "fx-data/": ["FX", "為替", "ドル", "円"],
    "pairs-production/": ["ペア", "pairs"],
    "quantlab-production/": ["クオント", "定量", "quant"],
    "margin/": ["信用", "マージン", "margin"],
    "disclosure/": ["開示", "IR", "発表", "disclosure"],
    "industry-outlook/": ["業界", "セクター", "industry"],
}

DEFAULT_FOLDERS = ["screnn-production/", "analysis-production/", "Financial/"]
MAX_DATA_BYTES = 80_000  # ~80KB total context limit


def _select_folders(question: str) -> list[str]:
    q = question.lower()
    matched = []
    for folder, keywords in FOLDER_MAP.items():
        if any(kw.lower() in q for kw in keywords):
            matched.append(folder)
    return matched if matched else DEFAULT_FOLDERS


def _list_recent_keys(s3_client, bucket: str, prefix: str, max_keys: int = 5) -> list[dict]:
    try:
        result = s3_client.list_objects_v2(Bucket=bucket, Prefix=prefix, MaxKeys=200)
        objs = result.get("Contents", [])
        objs = [o for o in objs if not o["Key"].endswith("/")]
        objs.sort(key=lambda o: o["LastModified"], reverse=True)
        return objs[:max_keys]
    except Exception:
        return []


def _read_object(s3_client, bucket: str, key: str, max_bytes: int = 20_000) -> str:
    try:
        resp = s3_client.get_object(Bucket=bucket, Key=key)
        raw = resp["Body"].read(max_bytes)
        text = raw.decode("utf-8", errors="replace")
        # Try to pretty-format JSON
        try:
            parsed = json.loads(text)
            return json.dumps(parsed, ensure_ascii=False, indent=2)[:max_bytes]
        except Exception:
            return text
    except Exception as e:
        return f"[読み込みエラー: {e}]"


def fetch_relevant_data(
    question: str,
    aws_access_key: str,
    aws_secret_key: str,
    aws_region: str,
    bucket: str = "m-s3storage",
) -> str:
    import boto3

    s3 = boto3.client(
        "s3",
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        region_name=aws_region or "ap-northeast-1",
    )

    folders = _select_folders(question)
    sections = []
    total_bytes = 0

    for folder in folders:
        if total_bytes >= MAX_DATA_BYTES:
            break
        keys = _list_recent_keys(s3, bucket, folder, max_keys=3)
        if not keys:
            continue
        folder_parts = []
        for obj in keys:
            if total_bytes >= MAX_DATA_BYTES:
                break
            content = _read_object(s3, bucket, obj["Key"], max_bytes=15_000)
            folder_parts.append(f"### {obj['Key']}\n{content}")
            total_bytes += len(content)
        if folder_parts:
            sections.append(f"## フォルダ: {folder}\n" + "\n\n".join(folder_parts))

    if not sections:
        return "（S3から関連データを取得できませんでした）"

    return "\n\n".join(sections)
