"""
APK static analysis - works with or without androguard.
Falls back to ZIP+binary parsing when androguard is not installed.
"""

import re
import os
import zipfile
import hashlib
from pathlib import Path
from typing import Any

ANDROID_PERMISSIONS: dict[str, dict] = {
    "android.permission.READ_CONTACTS": {"desc": "連絡先の読み取り", "risk": "HIGH"},
    "android.permission.WRITE_CONTACTS": {"desc": "連絡先の書き込み", "risk": "HIGH"},
    "android.permission.READ_CALL_LOG": {"desc": "通話履歴の読み取り", "risk": "HIGH"},
    "android.permission.WRITE_CALL_LOG": {"desc": "通話履歴の書き込み", "risk": "HIGH"},
    "android.permission.READ_SMS": {"desc": "SMS メッセージの読み取り", "risk": "HIGH"},
    "android.permission.SEND_SMS": {"desc": "SMS の送信", "risk": "HIGH"},
    "android.permission.RECEIVE_SMS": {"desc": "SMS の受信", "risk": "HIGH"},
    "android.permission.ACCESS_FINE_LOCATION": {"desc": "精密な位置情報へのアクセス", "risk": "HIGH"},
    "android.permission.ACCESS_COARSE_LOCATION": {"desc": "大まかな位置情報へのアクセス", "risk": "MEDIUM"},
    "android.permission.RECORD_AUDIO": {"desc": "音声録音", "risk": "HIGH"},
    "android.permission.CAMERA": {"desc": "カメラへのアクセス", "risk": "HIGH"},
    "android.permission.READ_EXTERNAL_STORAGE": {"desc": "外部ストレージの読み取り", "risk": "MEDIUM"},
    "android.permission.WRITE_EXTERNAL_STORAGE": {"desc": "外部ストレージへの書き込み", "risk": "MEDIUM"},
    "android.permission.INTERNET": {"desc": "インターネット接続", "risk": "LOW"},
    "android.permission.RECEIVE_BOOT_COMPLETED": {"desc": "起動時の自動実行", "risk": "MEDIUM"},
    "android.permission.READ_PHONE_STATE": {"desc": "電話状態の読み取り (IMEI 等)", "risk": "HIGH"},
    "android.permission.PROCESS_OUTGOING_CALLS": {"desc": "発信通話の処理", "risk": "HIGH"},
    "android.permission.USE_BIOMETRIC": {"desc": "生体認証の使用", "risk": "MEDIUM"},
    "android.permission.USE_FINGERPRINT": {"desc": "指紋認証の使用", "risk": "MEDIUM"},
    "android.permission.BLUETOOTH": {"desc": "Bluetooth 接続", "risk": "LOW"},
    "android.permission.BLUETOOTH_ADMIN": {"desc": "Bluetooth 管理", "risk": "MEDIUM"},
    "android.permission.NFC": {"desc": "NFC の使用", "risk": "MEDIUM"},
    "android.permission.FLASHLIGHT": {"desc": "フラッシュライトの制御", "risk": "LOW"},
    "android.permission.VIBRATE": {"desc": "バイブレーション", "risk": "LOW"},
    "android.permission.CHANGE_NETWORK_STATE": {"desc": "ネットワーク状態の変更", "risk": "MEDIUM"},
    "android.permission.ACCESS_WIFI_STATE": {"desc": "Wi-Fi 状態の読み取り", "risk": "LOW"},
    "android.permission.CHANGE_WIFI_STATE": {"desc": "Wi-Fi 設定の変更", "risk": "MEDIUM"},
    "android.permission.GET_ACCOUNTS": {"desc": "アカウント情報の取得", "risk": "HIGH"},
    "android.permission.USE_CREDENTIALS": {"desc": "アカウント認証情報の使用", "risk": "HIGH"},
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {"desc": "アクセシビリティサービスへのバインド", "risk": "HIGH"},
    "android.permission.SYSTEM_ALERT_WINDOW": {"desc": "他アプリ上のウィンドウ表示", "risk": "HIGH"},
    "android.permission.REQUEST_INSTALL_PACKAGES": {"desc": "パッケージインストールの要求", "risk": "HIGH"},
    "android.permission.FOREGROUND_SERVICE": {"desc": "フォアグラウンドサービスの実行", "risk": "LOW"},
    "android.permission.WAKE_LOCK": {"desc": "スリープ防止", "risk": "LOW"},
    "android.permission.READ_MEDIA_IMAGES": {"desc": "画像ファイルの読み取り", "risk": "MEDIUM"},
    "android.permission.READ_MEDIA_VIDEO": {"desc": "動画ファイルの読み取り", "risk": "MEDIUM"},
    "android.permission.READ_MEDIA_AUDIO": {"desc": "音声ファイルの読み取り", "risk": "MEDIUM"},
    "android.permission.POST_NOTIFICATIONS": {"desc": "通知の送信", "risk": "LOW"},
    "android.permission.SCHEDULE_EXACT_ALARM": {"desc": "正確なアラームのスケジュール", "risk": "LOW"},
    "android.permission.MANAGE_EXTERNAL_STORAGE": {"desc": "外部ストレージの完全管理", "risk": "HIGH"},
    "android.permission.QUERY_ALL_PACKAGES": {"desc": "インストール済みアプリ一覧の取得", "risk": "MEDIUM"},
}


def parse_apk(file_path: str) -> dict[str, Any]:
    try:
        import androguard.misc as amisc
        return _parse_with_androguard(file_path)
    except ImportError:
        pass

    return _parse_without_androguard(file_path)


def _parse_with_androguard(file_path: str) -> dict[str, Any]:
    from androguard.misc import AnalyzeAPK
    a, d, dx = AnalyzeAPK(file_path)

    app_name = a.get_app_name() or ""
    package = a.get_package() or ""
    version = a.get_androidversion_name() or ""
    min_sdk = int(a.get_min_sdk_version() or 0)
    target_sdk = int(a.get_target_sdk_version() or 0)

    perms_raw = a.get_permissions()
    permissions = []
    for p in perms_raw:
        info = ANDROID_PERMISSIONS.get(p, {"desc": p.split(".")[-1].replace("_", " "), "risk": "LOW"})
        permissions.append({"name": p, "description": info["desc"], "risk": info["risk"]})

    # Certificates
    certs = []
    for cert in a.get_certificates():
        certs.append({
            "issuer": str(cert.issuer.human_friendly),
            "subject": str(cert.subject.human_friendly),
            "valid_from": str(cert.not_valid_before),
            "valid_to": str(cert.not_valid_after),
            "fingerprint": cert.sha256_fingerprint.replace(":", "").upper()[:40],
        })

    strings_found, urls_found, secrets_found = _analyze_binary_content(file_path)

    vulns = _check_apk_vulnerabilities(
        debuggable=a.get_declared_permissions_details().get("debuggable", False),
        allow_backup=True,
        permissions=perms_raw,
        min_sdk=min_sdk,
    )

    return {
        "file_type": "Android APK",
        "app_name": app_name,
        "package_name": package,
        "version": version,
        "min_sdk": min_sdk,
        "target_sdk": target_sdk,
        "permissions": permissions,
        "activities": [a.__str__() for a in a.get_activities()][:20],
        "services": [s.__str__() for s in a.get_services()][:20],
        "certificates": certs,
        "strings_found": strings_found[:500],
        "urls_found": urls_found[:100],
        "secrets_found": secrets_found,
        "vulnerabilities": vulns,
    }


def _parse_without_androguard(file_path: str) -> dict[str, Any]:
    if not zipfile.is_zipfile(file_path):
        raise ValueError("有効な APK ファイルではありません")

    manifest_xml = b""
    dex_files = []

    with zipfile.ZipFile(file_path, "r") as zf:
        names = zf.namelist()
        if "AndroidManifest.xml" in names:
            manifest_xml = zf.read("AndroidManifest.xml")
        dex_files = [n for n in names if n.endswith(".dex")]

    # Parse binary XML manifest
    manifest_info = _parse_binary_xml(manifest_xml)
    strings_found, urls_found, secrets_found = _analyze_binary_content(file_path)

    perms = manifest_info.get("permissions", [])
    permission_list = []
    for p in perms:
        info = ANDROID_PERMISSIONS.get(p, {"desc": p.split(".")[-1].replace("_", " "), "risk": "LOW"})
        permission_list.append({"name": p, "description": info["desc"], "risk": info["risk"]})

    debuggable = manifest_info.get("debuggable", False)
    allow_backup = manifest_info.get("allowBackup", True)
    min_sdk = manifest_info.get("minSdkVersion", 0)

    vulns = _check_apk_vulnerabilities(
        debuggable=debuggable,
        allow_backup=allow_backup,
        permissions=perms,
        min_sdk=min_sdk,
    )

    return {
        "file_type": "Android APK",
        "app_name": manifest_info.get("appName", ""),
        "package_name": manifest_info.get("package", ""),
        "version": manifest_info.get("versionName", ""),
        "min_sdk": min_sdk,
        "target_sdk": manifest_info.get("targetSdkVersion", 0),
        "permissions": permission_list,
        "activities": manifest_info.get("activities", []),
        "services": manifest_info.get("services", []),
        "certificates": _extract_certificates(file_path),
        "strings_found": strings_found[:500],
        "urls_found": urls_found[:100],
        "secrets_found": secrets_found,
        "vulnerabilities": vulns,
    }


def _parse_binary_xml(data: bytes) -> dict[str, Any]:
    """Extract key fields from Android binary XML via regex on decoded strings."""
    result: dict[str, Any] = {
        "permissions": [],
        "activities": [],
        "services": [],
        "debuggable": False,
        "allowBackup": True,
    }

    if not data:
        return result

    # Extract readable strings from binary XML
    texts = re.findall(rb"[\x20-\x7e]{4,}", data)
    decoded = [t.decode("ascii", errors="ignore") for t in texts]

    for s in decoded:
        if s.startswith("android.permission."):
            result["permissions"].append(s)
        elif "Activity" in s and "." in s and len(s) > 10:
            result["activities"].append(s)
        elif "Service" in s and "." in s and len(s) > 10:
            result["services"].append(s)

    # Also try to find package name patterns
    for s in decoded:
        if re.match(r"^[a-z][a-z0-9]*(\.[a-z][a-z0-9_]*){2,}$", s):
            if "package" not in result:
                result["package"] = s

    # Check flags in binary data
    if b"debuggable" in data:
        result["debuggable"] = True

    return result


def _extract_certificates(file_path: str) -> list[dict]:
    certs = []
    try:
        from OpenSSL import crypto
        with zipfile.ZipFile(file_path, "r") as zf:
            for name in zf.namelist():
                if name.startswith("META-INF/") and name.endswith((".RSA", ".DSA", ".EC")):
                    cert_data = zf.read(name)
                    try:
                        pkcs7 = crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, cert_data)
                        # pyOpenSSL pkcs7 cert extraction
                        certs_in = pkcs7.get_certificates() or []
                        for cert in certs_in:
                            certs.append({
                                "issuer": str(cert.get_issuer()),
                                "subject": str(cert.get_subject()),
                                "valid_from": cert.get_notBefore().decode() if cert.get_notBefore() else "",
                                "valid_to": cert.get_notAfter().decode() if cert.get_notAfter() else "",
                                "fingerprint": cert.digest("sha256").decode(),
                            })
                    except Exception:
                        certs.append({
                            "issuer": "解析不可",
                            "subject": name,
                            "valid_from": "",
                            "valid_to": "",
                            "fingerprint": hashlib.sha256(cert_data).hexdigest(),
                        })
    except Exception:
        pass
    return certs


def _analyze_binary_content(file_path: str) -> tuple[list[str], list[str], list[dict]]:
    strings: list[str] = []
    urls: list[str] = []
    secrets: list[dict] = []

    try:
        with zipfile.ZipFile(file_path, "r") as zf:
            for name in zf.namelist():
                if name.endswith(".dex") or name == "classes.dex":
                    try:
                        data = zf.read(name)
                        extracted = _extract_strings_from_bytes(data)
                        strings.extend(extracted)
                    except Exception:
                        pass
    except Exception:
        # If not a zip, read directly
        try:
            with open(file_path, "rb") as f:
                data = f.read(10 * 1024 * 1024)  # max 10MB
            strings = _extract_strings_from_bytes(data)
        except Exception:
            pass

    urls = [s for s in strings if re.match(r"https?://[^\s\"'<>]{6,}", s)]
    secrets = _find_secrets_in_strings(strings)

    return strings, urls, secrets


def _extract_strings_from_bytes(data: bytes, min_len: int = 6) -> list[str]:
    results = []
    current: list[str] = []
    for byte in data:
        if 0x20 <= byte <= 0x7E:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                s = "".join(current)
                results.append(s)
            current = []
    if len(current) >= min_len:
        results.append("".join(current))
    return results


def _find_secrets_in_strings(strings: list[str]) -> list[dict]:
    patterns = [
        ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
        ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}"),
        ("Firebase URL", r"https://[a-z0-9-]+\.firebaseio\.com"),
        ("Private Key", r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
        ("JWT Token", r"eyJ[A-Za-z0-9\-_=]{20,}\.[A-Za-z0-9\-_=]{20,}\."),
        ("Generic Password", r"(?i)(?:password|passwd|pwd)\s*[=:]\s*[\"']?([^\"'\s]{6,})"),
        ("Generic API Key", r"(?i)(?:api.?key|apikey|api_secret)\s*[=:]\s*[\"']?([a-zA-Z0-9\-_]{16,})"),
        ("Auth Token", r"(?i)(?:auth.?token|bearer)\s*[=:]\s*[\"']?([a-zA-Z0-9\-_\.]{20,})"),
    ]
    found = []
    seen = set()
    for s in strings:
        for secret_type, pattern in patterns:
            m = re.search(pattern, s)
            if m:
                value = s[:120]
                key = f"{secret_type}:{value[:40]}"
                if key not in seen:
                    seen.add(key)
                    found.append({"type": secret_type, "value": value, "location": "DEX バイナリ"})
                break
    return found


def _check_apk_vulnerabilities(
    debuggable: bool,
    allow_backup: bool,
    permissions: list[str],
    min_sdk: int,
) -> list[dict]:
    vulns = []
    vid = 0

    def add(title: str, description: str, severity: str, recommendation: str, location: str = ""):
        nonlocal vid
        vid += 1
        vulns.append({
            "id": f"APK-{vid:03d}",
            "title": title,
            "description": description,
            "severity": severity,
            "location": location,
            "recommendation": recommendation,
        })

    if debuggable:
        add(
            "デバッグモードが有効",
            "AndroidManifest.xml で android:debuggable=\"true\" が設定されています。本番環境では無効化が必要です。",
            "HIGH",
            "AndroidManifest.xml の android:debuggable 属性を削除するか false に設定してください。",
            "AndroidManifest.xml"
        )

    if allow_backup:
        add(
            "バックアップが許可されています",
            "android:allowBackup=\"true\" が設定されているため、ADB バックアップでアプリデータを取得可能です。",
            "MEDIUM",
            "android:allowBackup=\"false\" に設定してください。",
            "AndroidManifest.xml"
        )

    if min_sdk and min_sdk < 21:
        add(
            "古い Android SDK バージョンをサポート",
            f"minSdkVersion={min_sdk} は Android 5.0 (Lollipop) 未満をサポートしており、多くの既知の脆弱性が存在します。",
            "MEDIUM",
            "minSdkVersion を 21 (Android 5.0) 以上に設定することを推奨します。",
            "AndroidManifest.xml"
        )

    dangerous_perms = [p for p in permissions if ANDROID_PERMISSIONS.get(p, {}).get("risk") == "HIGH"]
    if len(dangerous_perms) > 5:
        add(
            "過剰な危険権限の要求",
            f"{len(dangerous_perms)} 個の高リスク権限が要求されています: {', '.join(dangerous_perms[:3])} 等",
            "MEDIUM",
            "必要最小限の権限のみ要求するように設計を見直してください。",
        )

    if "android.permission.BIND_ACCESSIBILITY_SERVICE" in permissions:
        add(
            "アクセシビリティサービス権限",
            "アクセシビリティサービス権限はスパイウェアやキーロガーに悪用されることがあります。",
            "HIGH",
            "この権限が本当に必要か確認し、不要であれば削除してください。",
        )

    if "android.permission.SYSTEM_ALERT_WINDOW" in permissions:
        add(
            "オーバーレイウィンドウ権限",
            "他のアプリの上にウィンドウを表示できるため、フィッシング攻撃に悪用される可能性があります。",
            "HIGH",
            "この権限が必要か再検討してください。",
        )

    if "android.permission.REQUEST_INSTALL_PACKAGES" in permissions:
        add(
            "パッケージインストール権限",
            "任意の APK ファイルをインストールできるため、マルウェア配布経路になる可能性があります。",
            "HIGH",
            "この権限の使用が正当な目的かどうか確認してください。",
        )

    return vulns
