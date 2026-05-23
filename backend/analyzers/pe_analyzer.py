"""
Windows PE (EXE/DLL) static analysis using pefile + fallback.
"""

import re
import os
import math
import hashlib
from typing import Any


def parse_pe(file_path: str) -> dict[str, Any]:
    try:
        import pefile
        return _parse_with_pefile(file_path)
    except ImportError:
        return _parse_generic(file_path)


def _parse_with_pefile(file_path: str) -> dict[str, Any]:
    import pefile

    pe = pefile.PE(file_path)

    file_type = "DLL" if pe.is_dll() else "EXE"
    arch = "x64" if pe.FILE_HEADER.Machine == 0x8664 else "x86"

    # Imports
    imports = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("utf-8", errors="ignore")
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    funcs.append(imp.name.decode("utf-8", errors="ignore"))
                else:
                    funcs.append(f"Ordinal_{imp.ordinal}")
            imports.append({"dll": dll, "functions": funcs})

    # Exports
    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append(exp.name.decode("utf-8", errors="ignore"))

    # Sections with entropy
    sections = []
    for section in pe.sections:
        name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")
        data = section.get_data()
        entropy = _calculate_entropy(data)
        sections.append({
            "name": name,
            "size": len(data),
            "entropy": entropy,
            "virtual_address": hex(section.VirtualAddress),
        })

    # Strings
    with open(file_path, "rb") as f:
        raw = f.read()
    strings = _extract_strings(raw)
    urls = [s for s in strings if re.match(r"https?://[^\s\"'<>]{6,}", s)]
    secrets = _find_secrets(strings)

    # Security features
    characteristics = pe.FILE_HEADER.Characteristics
    dll_characteristics = pe.OPTIONAL_HEADER.DllCharacteristics
    has_aslr = bool(dll_characteristics & 0x0040)
    has_dep = bool(dll_characteristics & 0x0100)
    has_seh = not bool(dll_characteristics & 0x0400)  # IMAGE_DLLCHARACTERISTICS_NO_SEH
    has_cfg = bool(dll_characteristics & 0x4000)

    vulns = _check_pe_vulnerabilities(
        has_aslr=has_aslr,
        has_dep=has_dep,
        has_seh=has_seh,
        has_cfg=has_cfg,
        sections=sections,
        imports=imports,
        strings=strings,
    )

    # Timestamp
    import datetime
    try:
        ts = datetime.datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat()
    except Exception:
        ts = "不明"

    return {
        "file_type": f"Windows {file_type} ({arch})",
        "arch": arch,
        "compile_timestamp": ts,
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "imports": imports,
        "exports": exports,
        "sections": sections,
        "strings_found": strings[:500],
        "urls_found": urls[:100],
        "secrets_found": secrets,
        "vulnerabilities": vulns,
        "security_features": {
            "ASLR": has_aslr,
            "DEP/NX": has_dep,
            "SafeSEH": has_seh,
            "CFG": has_cfg,
        },
    }


def _parse_generic(file_path: str) -> dict[str, Any]:
    with open(file_path, "rb") as f:
        raw = f.read()

    strings = _extract_strings(raw)
    urls = [s for s in strings if re.match(r"https?://[^\s\"'<>]{6,}", s)]
    secrets = _find_secrets(strings)

    # Try to detect PE
    is_pe = raw[:2] == b"MZ"
    file_type = "Windows PE" if is_pe else "Binary"

    return {
        "file_type": file_type,
        "strings_found": strings[:500],
        "urls_found": urls[:100],
        "secrets_found": secrets,
        "vulnerabilities": [],
    }


def _calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            prob = count / length
            entropy -= prob * math.log2(prob)
    return round(entropy, 4)


def _extract_strings(data: bytes, min_len: int = 6) -> list[str]:
    results = []
    current: list[str] = []
    for byte in data:
        if 0x20 <= byte <= 0x7E:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                results.append("".join(current))
            current = []
    if len(current) >= min_len:
        results.append("".join(current))
    return results


def _find_secrets(strings: list[str]) -> list[dict]:
    patterns = [
        ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
        ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}"),
        ("Private Key", r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
        ("JWT Token", r"eyJ[A-Za-z0-9\-_=]{20,}\.[A-Za-z0-9\-_=]{20,}\."),
        ("Generic Password", r"(?i)(?:password|passwd)\s*[=:]\s*[\"']([^\"']{6,})[\"']"),
        ("Connection String", r"(?i)(?:Server|Data Source)\s*=\s*[^;]+;"),
        ("Generic API Key", r"(?i)(?:api.?key|apikey)\s*[=:]\s*[\"']?([a-zA-Z0-9\-_]{20,})"),
    ]
    found = []
    seen = set()
    for s in strings:
        for secret_type, pattern in patterns:
            if re.search(pattern, s):
                key = f"{secret_type}:{s[:40]}"
                if key not in seen:
                    seen.add(key)
                    found.append({"type": secret_type, "value": s[:120], "location": "PE バイナリ"})
                break
    return found


SUSPICIOUS_IMPORTS = {
    "VirtualAlloc": ("メモリ割り当て (シェルコード実行に使用されることがある)", "MEDIUM"),
    "VirtualProtect": ("メモリ保護変更 (コード注入の可能性)", "MEDIUM"),
    "CreateRemoteThread": ("リモートスレッド作成 (プロセス注入)", "HIGH"),
    "WriteProcessMemory": ("他プロセスへのメモリ書き込み (注入)", "HIGH"),
    "ReadProcessMemory": ("他プロセスのメモリ読み取り", "HIGH"),
    "OpenProcess": ("プロセスオープン", "MEDIUM"),
    "RegOpenKey": ("レジストリキー読み取り", "LOW"),
    "RegSetValue": ("レジストリ値の設定 (永続化の可能性)", "MEDIUM"),
    "CreateService": ("サービス作成 (永続化の可能性)", "HIGH"),
    "InternetOpen": ("インターネット接続初期化", "LOW"),
    "HttpSendRequest": ("HTTP リクエスト送信", "LOW"),
    "URLDownloadToFile": ("URL からのファイルダウンロード", "MEDIUM"),
    "ShellExecute": ("シェル実行 (コマンド実行)", "MEDIUM"),
    "WinExec": ("コマンド実行", "MEDIUM"),
    "CreateProcess": ("プロセス作成", "LOW"),
    "GetProcAddress": ("動的 API 解決 (難読化の可能性)", "MEDIUM"),
    "LoadLibrary": ("DLL の動的読み込み", "LOW"),
    "SetWindowsHookEx": ("キーボード/マウスフック (キーロガーの可能性)", "HIGH"),
    "FindWindow": ("ウィンドウ検索", "LOW"),
    "GetAsyncKeyState": ("非同期キー状態取得 (キーロガーの可能性)", "HIGH"),
    "CryptEncrypt": ("暗号化 API 使用", "LOW"),
    "IsDebuggerPresent": ("デバッガ検出 (アンチデバッグ)", "MEDIUM"),
    "CheckRemoteDebuggerPresent": ("リモートデバッガ検出 (アンチデバッグ)", "MEDIUM"),
    "NtQueryInformationProcess": ("プロセス情報クエリ (アンチデバッグに使用)", "MEDIUM"),
}


def _check_pe_vulnerabilities(
    has_aslr: bool,
    has_dep: bool,
    has_seh: bool,
    has_cfg: bool,
    sections: list[dict],
    imports: list[dict],
    strings: list[str],
) -> list[dict]:
    vulns = []
    vid = 0

    def add(title: str, description: str, severity: str, recommendation: str, location: str = ""):
        nonlocal vid
        vid += 1
        vulns.append({
            "id": f"PE-{vid:03d}",
            "title": title,
            "description": description,
            "severity": severity,
            "location": location,
            "recommendation": recommendation,
        })

    if not has_aslr:
        add(
            "ASLR が無効",
            "アドレス空間配置のランダム化 (ASLR) が無効です。メモリ攻撃を容易にします。",
            "HIGH",
            "/DYNAMICBASE リンカーオプションを使用してコンパイルしてください。"
        )

    if not has_dep:
        add(
            "DEP/NX が無効",
            "データ実行防止 (DEP/NX) が無効です。シェルコード実行攻撃に脆弱です。",
            "HIGH",
            "/NXCOMPAT リンカーオプションを使用してコンパイルしてください。"
        )

    if not has_cfg:
        add(
            "CFG (制御フロー保護) が無効",
            "制御フロー整合性 (CFG) が有効になっていません。",
            "MEDIUM",
            "/guard:cf コンパイラオプションを使用してください。"
        )

    # Check for high-entropy sections (possible packed/encrypted code)
    for sec in sections:
        if sec["entropy"] > 7.5 and sec["name"] not in (".rsrc",):
            add(
                f"高エントロピーセクション: {sec['name']}",
                f"セクション '{sec['name']}' のエントロピーが {sec['entropy']:.2f} と非常に高く、パック・暗号化・難読化の可能性があります。",
                "MEDIUM",
                "マルウェア解析ツールで詳細に検査することを推奨します。",
                sec["name"]
            )

    # Check for suspicious imports
    all_imports = {}
    for imp in imports:
        for fn in imp["functions"]:
            all_imports[fn] = imp["dll"]

    found_suspicious = []
    for fn, (desc, severity) in SUSPICIOUS_IMPORTS.items():
        if fn in all_imports:
            found_suspicious.append((fn, desc, severity, all_imports[fn]))

    high_risk = [(f, d, s, dll) for f, d, s, dll in found_suspicious if s == "HIGH"]
    med_risk = [(f, d, s, dll) for f, d, s, dll in found_suspicious if s == "MEDIUM"]

    if high_risk:
        names = ", ".join(f[0] for f in high_risk[:5])
        add(
            f"危険な API の使用 ({len(high_risk)} 件)",
            f"高リスク API が検出されました: {names}。プロセス注入・永続化・スパイウェア動作の可能性があります。",
            "HIGH",
            "各 API の使用目的を確認し、不要であれば削除してください。",
        )

    if med_risk:
        names = ", ".join(f[0] for f in med_risk[:5])
        add(
            f"要注意な API の使用 ({len(med_risk)} 件)",
            f"注意が必要な API が検出されました: {names}。",
            "MEDIUM",
            "各 API の使用目的を確認してください。",
        )

    return vulns
