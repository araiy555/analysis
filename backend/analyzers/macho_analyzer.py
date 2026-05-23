"""
macOS Mach-O binary analysis using LIEF.
"""

import re
import os
from typing import Any


def parse_macho(file_path: str) -> dict[str, Any]:
    try:
        import lief
        return _parse_with_lief(file_path)
    except ImportError:
        return _parse_generic(file_path)


def _parse_with_lief(file_path: str) -> dict[str, Any]:
    import lief

    binary = lief.parse(file_path)
    if not binary:
        raise ValueError("LIEF による解析に失敗しました")

    file_type = "macOS Mach-O"

    if isinstance(binary, lief.MachO.FatBinary):
        # Fat binary - analyze first slice
        slices = list(binary)
        macho = slices[0]
        arch_info = f"Fat Binary ({len(slices)} スライス)"
    else:
        macho = binary
        arch_info = _get_arch(macho)

    # Libraries
    libs = [lib.name for lib in macho.libraries]

    # Symbols (exported)
    symbols = []
    for sym in macho.symbols:
        if sym.name and not sym.name.startswith("_OBJC"):
            symbols.append(sym.name)

    symbols = symbols[:200]

    # Entitlements
    entitlements = {}
    try:
        cs = macho.code_signature
        if cs and hasattr(cs, "entitlements"):
            entitlements = {"raw": str(cs.entitlements)[:2000]}
    except Exception:
        pass

    # Strings
    strings_found, urls_found, secrets_found = _analyze_binary(file_path)

    # Security checks
    has_pie = bool(macho.header.flags & lief.MachO.Header.FLAGS.PIE)
    has_stack_canary = any(s.name in ("___stack_chk_fail", "_stack_chk_fail") for s in macho.symbols)
    has_arc = any("_objc_release" in s.name for s in macho.symbols)

    vulns = _check_macho_vulnerabilities(
        has_pie=has_pie,
        has_stack_canary=has_stack_canary,
        entitlements=entitlements,
        libs=libs,
        strings=strings_found,
    )

    return {
        "file_type": file_type,
        "arch": arch_info,
        "libraries": libs,
        "symbols": symbols,
        "entitlements": entitlements,
        "has_pie": has_pie,
        "has_stack_canary": has_stack_canary,
        "has_arc": has_arc,
        "strings_found": strings_found[:500],
        "urls_found": urls_found[:100],
        "secrets_found": secrets_found,
        "vulnerabilities": vulns,
    }


def _get_arch(macho) -> str:
    try:
        import lief
        cpu = macho.header.cpu_type
        if cpu == lief.MachO.Header.CPU_TYPE.ARM64:
            return "ARM64 (Apple Silicon)"
        elif cpu == lief.MachO.Header.CPU_TYPE.X86_64:
            return "x86_64 (Intel)"
        elif cpu == lief.MachO.Header.CPU_TYPE.X86:
            return "x86 (32-bit)"
        return str(cpu)
    except Exception:
        return "不明"


def _analyze_binary(file_path: str) -> tuple[list[str], list[str], list[dict]]:
    strings: list[str] = []
    try:
        with open(file_path, "rb") as f:
            data = f.read(20 * 1024 * 1024)
        current: list[str] = []
        for byte in data:
            if 0x20 <= byte <= 0x7E:
                current.append(chr(byte))
            else:
                if len(current) >= 6:
                    strings.append("".join(current))
                current = []
        if len(current) >= 6:
            strings.append("".join(current))
    except Exception:
        pass

    urls = [s for s in strings if re.match(r"https?://[^\s\"'<>]{6,}", s)]
    secrets = _find_secrets(strings)
    return strings, urls, secrets


def _find_secrets(strings: list[str]) -> list[dict]:
    patterns = [
        ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
        ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}"),
        ("Private Key", r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
        ("JWT Token", r"eyJ[A-Za-z0-9\-_=]{20,}\.[A-Za-z0-9\-_=]{20,}\."),
        ("Generic API Key", r"(?i)api.?key\s*[=:]\s*[\"']?([a-zA-Z0-9\-_]{20,})"),
        ("Generic Password", r"(?i)password\s*[=:]\s*[\"']([^\"']{6,})[\"']"),
    ]
    found = []
    seen = set()
    for s in strings:
        for secret_type, pattern in patterns:
            if re.search(pattern, s):
                key = f"{secret_type}:{s[:40]}"
                if key not in seen:
                    seen.add(key)
                    found.append({"type": secret_type, "value": s[:120], "location": "Mach-O バイナリ"})
                break
    return found


def _parse_generic(file_path: str) -> dict[str, Any]:
    strings: list[str] = []
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        current: list[str] = []
        for byte in data:
            if 0x20 <= byte <= 0x7E:
                current.append(chr(byte))
            else:
                if len(current) >= 6:
                    strings.append("".join(current))
                current = []
    except Exception:
        pass

    urls = [s for s in strings if re.match(r"https?://[^\s\"'<>]{6,}", s)]

    return {
        "file_type": "macOS Binary",
        "arch": "不明 (LIEF 未インストール)",
        "libraries": [],
        "symbols": [],
        "strings_found": strings[:500],
        "urls_found": urls[:100],
        "secrets_found": _find_secrets(strings),
        "vulnerabilities": [],
    }


def _check_macho_vulnerabilities(
    has_pie: bool,
    has_stack_canary: bool,
    entitlements: dict,
    libs: list[str],
    strings: list[str],
) -> list[dict]:
    vulns = []
    vid = 0

    def add(title: str, description: str, severity: str, recommendation: str, location: str = ""):
        nonlocal vid
        vid += 1
        vulns.append({
            "id": f"MACHO-{vid:03d}",
            "title": title,
            "description": description,
            "severity": severity,
            "location": location,
            "recommendation": recommendation,
        })

    if not has_pie:
        add(
            "PIE (位置独立実行形式) が無効",
            "Position Independent Executable (PIE) が無効で、ASLR の恩恵を受けられません。",
            "HIGH",
            "-pie フラグでコンパイルしてください。"
        )

    if not has_stack_canary:
        add(
            "スタックカナリアなし",
            "スタックバッファオーバーフロー対策のスタックカナリアが検出されませんでした。",
            "MEDIUM",
            "-fstack-protector-all でコンパイルしてください。"
        )

    ent_raw = entitlements.get("raw", "")
    if "com.apple.security.get-task-allow" in ent_raw:
        add(
            "デバッグ権限が有効 (get-task-allow)",
            "com.apple.security.get-task-allow エンタイトルメントが有効で、他プロセスからのデバッグを許可しています。",
            "HIGH",
            "本番ビルドからこのエンタイトルメントを削除してください。",
            "Entitlements"
        )

    if "com.apple.security.cs.disable-library-validation" in ent_raw:
        add(
            "ライブラリバリデーション無効",
            "署名されていない外部ライブラリのロードが許可されており、DLL インジェクション攻撃に脆弱です。",
            "HIGH",
            "このエンタイトルメントを削除し、署名済みライブラリのみ使用してください。",
            "Entitlements"
        )

    return vulns
