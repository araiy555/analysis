import os
import sys
import tempfile
import traceback
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="AppSleuth Backend", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Lazy imports so missing optional deps don't crash startup ──────────────────

def _import(module: str):
    try:
        return __import__(module)
    except ImportError:
        return None


# ── Models ────────────────────────────────────────────────────────────────────

class ProxyStartRequest(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8080
    ssl_intercept: bool = True


class AttachRequest(BaseModel):
    pid: int


class RunScriptRequest(BaseModel):
    pid: int
    script: str


class AIAnalyzeRequest(BaseModel):
    api_key: str
    analysis_type: str
    content: str
    history: list[dict] = []


class ReportRequest(BaseModel):
    history: list[dict]


# ── Health ─────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}


# ── Static Analysis ────────────────────────────────────────────────────────────

@app.post("/analyze/static")
async def analyze_static(file: UploadFile = File(...)):
    suffix = Path(file.filename or "upload").suffix.lower()
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        if suffix == ".apk":
            from analyzers.apk_analyzer import parse_apk
            result = parse_apk(tmp_path)
        elif suffix in (".exe", ".dll", ".sys"):
            from analyzers.pe_analyzer import parse_pe
            result = parse_pe(tmp_path)
        elif suffix in (".dylib", ".macho") or _is_macho(tmp_path):
            from analyzers.macho_analyzer import parse_macho
            result = parse_macho(tmp_path)
        else:
            # Generic binary analysis
            from analyzers.pe_analyzer import parse_pe
            try:
                result = parse_pe(tmp_path)
            except Exception:
                result = _generic_analyze(tmp_path, file.filename or "unknown")

        result["file_name"] = file.filename
        result["file_size"] = len(content)
        return result
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        os.unlink(tmp_path)


def _is_macho(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
        return magic in (b"\xca\xfe\xba\xbe", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")
    except Exception:
        return False


def _generic_analyze(path: str, name: str) -> dict:
    strings = _extract_strings(path)
    urls = [s for s in strings if s.startswith(("http://", "https://", "ftp://"))]
    return {
        "file_type": "Binary",
        "file_size": os.path.getsize(path),
        "strings_found": strings[:500],
        "urls_found": urls,
        "vulnerabilities": [],
        "secrets_found": _find_secrets(strings),
    }


def _extract_strings(path: str, min_len: int = 6) -> list[str]:
    results = []
    try:
        with open(path, "rb") as f:
            data = f.read()
        current = []
        for byte in data:
            if 0x20 <= byte <= 0x7E:
                current.append(chr(byte))
            else:
                if len(current) >= min_len:
                    results.append("".join(current))
                current = []
        if len(current) >= min_len:
            results.append("".join(current))
    except Exception:
        pass
    return results


def _find_secrets(strings: list[str]) -> list[dict]:
    import re
    patterns = [
        ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
        ("AWS Secret Key", r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
        ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}"),
        ("Private Key", r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
        ("JWT Token", r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*"),
        ("Generic Password", r"(?i)password['\"]?\s*[:=]\s*['\"][^'\"]{6,}['\"]"),
        ("Generic API Key", r"(?i)api[_-]?key['\"]?\s*[:=]\s*['\"][^'\"]{10,}['\"]"),
    ]
    found = []
    for s in strings:
        for secret_type, pattern in patterns:
            if re.search(pattern, s):
                found.append({"type": secret_type, "value": s[:100], "location": "binary"})
                break
    return found


# ── Ghidra Decompiler ─────────────────────────────────────────────────────────

class GhidraAnalyzeRequest(BaseModel):
    file_path: str
    timeout: int = 300


@app.get("/ghidra/status")
async def ghidra_status():
    from analyzers.ghidra_analyzer import get_ghidra_status
    return get_ghidra_status()


@app.post("/ghidra/analyze")
async def ghidra_analyze(req: GhidraAnalyzeRequest):
    if not os.path.isfile(req.file_path):
        raise HTTPException(status_code=400, detail="ファイルが見つかりません")
    from analyzers.ghidra_analyzer import run_ghidra_analysis
    return run_ghidra_analysis(req.file_path, timeout=req.timeout)


@app.post("/ghidra/analyze-upload")
async def ghidra_analyze_upload(file: UploadFile = File(...)):
    suffix = Path(file.filename or "upload").suffix.lower()
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name
    try:
        from analyzers.ghidra_analyzer import run_ghidra_analysis
        result = run_ghidra_analysis(tmp_path, timeout=300)
        result["file_name"] = file.filename
        result["file_size"] = len(content)
        return result
    finally:
        os.unlink(tmp_path)


# ── Network Proxy ──────────────────────────────────────────────────────────────

@app.post("/proxy/internal/traffic")
async def proxy_internal_traffic(entry: dict):
    """Internal endpoint: mitmproxy addon calls this to record traffic."""
    from network.proxy_manager import add_traffic_entry
    add_traffic_entry(entry)
    return {"ok": True}


@app.post("/proxy/start")
async def proxy_start(req: ProxyStartRequest):
    try:
        from network.proxy_manager import start_proxy
        start_proxy(req.host, req.port, req.ssl_intercept)
        return {"status": "started", "host": req.host, "port": req.port}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/proxy/stop")
async def proxy_stop():
    try:
        from network.proxy_manager import stop_proxy
        stop_proxy()
        return {"status": "stopped"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/proxy/traffic")
async def proxy_traffic():
    try:
        from network.proxy_manager import get_traffic
        return get_traffic()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Memory / Frida ─────────────────────────────────────────────────────────────

@app.get("/memory/processes")
async def memory_processes():
    try:
        from memory.frida_client import get_processes
        return get_processes()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Frida エラー: {e}")


@app.post("/memory/attach")
async def memory_attach(req: AttachRequest):
    try:
        from memory.frida_client import attach_process
        attach_process(req.pid)
        return {"status": "attached", "pid": req.pid}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/memory/run-script")
async def memory_run_script(req: RunScriptRequest):
    try:
        from memory.frida_client import run_script
        output = run_script(req.pid, req.script)
        return {"status": "ok", "output": output}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── AI Analysis ────────────────────────────────────────────────────────────────

@app.post("/ai/analyze")
async def ai_analyze(req: AIAnalyzeRequest):
    try:
        from ai.claude_client import analyze
        result = analyze(
            api_key=req.api_key,
            analysis_type=req.analysis_type,
            content=req.content,
            history=req.history,
        )
        return {"result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Report Generation ──────────────────────────────────────────────────────────

@app.post("/report/generate")
async def report_generate(req: ReportRequest):
    from jinja2 import Template
    from datetime import datetime

    total_vulns = sum(h.get("vulnCount", 0) for h in req.history)
    html = Template(REPORT_TEMPLATE).render(
        history=req.history,
        total_vulns=total_vulns,
        clean_count=sum(1 for h in req.history if h.get("vulnCount", 0) == 0),
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
    return {"html": html}


REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<title>AppSleuth セキュリティレポート</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #0f1117; color: #e6edf3; padding: 48px; line-height: 1.6; }
  h1 { color: #39d353; font-size: 28px; margin-bottom: 8px; }
  h2 { color: #58a6ff; font-size: 18px; margin: 32px 0 16px; border-bottom: 1px solid #30363d; padding-bottom: 8px; }
  .meta { color: #8b949e; font-size: 14px; margin-bottom: 32px; }
  .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 32px; }
  .stat { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }
  .stat-value { font-size: 32px; font-weight: bold; }
  .stat-label { color: #8b949e; font-size: 13px; margin-top: 4px; }
  table { width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; border: 1px solid #30363d; }
  th { background: #1c2230; padding: 10px 16px; text-align: left; font-size: 12px; color: #8b949e; text-transform: uppercase; }
  td { padding: 12px 16px; border-top: 1px solid #30363d; font-size: 14px; }
  .vuln { color: #f85149; font-weight: 600; }
  .clean { color: #39d353; }
  .footer { margin-top: 48px; color: #484f58; font-size: 12px; text-align: center; }
</style>
</head>
<body>
  <h1>🛡️ AppSleuth セキュリティレポート</h1>
  <div class="meta">生成日時: {{ generated_at }} · AppSleuth v1.0.0</div>
  <div class="stats">
    <div class="stat"><div class="stat-value">{{ history|length }}</div><div class="stat-label">解析済みファイル</div></div>
    <div class="stat"><div class="stat-value" style="color:{% if total_vulns > 0 %}#f85149{% else %}#39d353{% endif %}">{{ total_vulns }}</div><div class="stat-label">検出された脆弱性</div></div>
    <div class="stat"><div class="stat-value">{{ clean_count }}</div><div class="stat-label">クリーンなファイル</div></div>
  </div>
  <h2>解析履歴</h2>
  <table>
    <thead><tr><th>ファイル名</th><th>種別</th><th>解析日時</th><th>脆弱性</th></tr></thead>
    <tbody>
      {% for h in history %}
      <tr>
        <td>{{ h.name }}</td>
        <td style="color:#8b949e">{{ h.type }}</td>
        <td style="color:#8b949e">{{ h.date }}</td>
        <td class="{% if h.vulnCount > 0 %}vuln{% else %}clean{% endif %}">
          {% if h.vulnCount > 0 %}⚠ {{ h.vulnCount }} 件{% else %}✓ クリーン{% endif %}
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  <div class="footer">AppSleuth Security Analysis Tool · Powered by Claude AI</div>
</body>
</html>"""


if __name__ == "__main__":
    port = int(os.environ.get("BACKEND_PORT", 8765))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")
