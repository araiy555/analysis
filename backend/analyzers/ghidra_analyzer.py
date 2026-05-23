"""
Ghidra headless decompiler integration.

Finds Ghidra installation, runs analyzeHeadless, parses decompiled output.
Requires Ghidra 10.x+ installed and GHIDRA_HOME set (or found automatically).
"""

import os
import sys
import json
import shutil
import tempfile
import subprocess
import platform
from pathlib import Path
from typing import Any

SCRIPT_NAME = "GhidraDecompile.py"


# ── Ghidra discovery ──────────────────────────────────────────────────────────

def find_ghidra() -> str | None:
    """Return path to analyzeHeadless script, or None if not found."""
    # 1. Environment variable
    home = os.environ.get("GHIDRA_HOME")
    if home:
        candidate = _headless_path(home)
        if candidate:
            return candidate

    # 2. Common installation paths
    system = platform.system()
    search_roots: list[str] = []

    if system == "Windows":
        search_roots = [
            r"C:\ghidra",
            r"C:\Program Files\ghidra",
            r"C:\Tools\ghidra",
            os.path.expanduser(r"~\ghidra"),
        ]
    elif system == "Darwin":
        search_roots = [
            "/Applications/ghidra",
            os.path.expanduser("~/ghidra"),
            "/opt/ghidra",
            "/usr/local/ghidra",
        ]
    else:
        search_roots = [
            os.path.expanduser("~/ghidra"),
            "/opt/ghidra",
            "/usr/local/ghidra",
            "/tools/ghidra",
        ]

    for root in search_roots:
        if os.path.isdir(root):
            # May be versioned subdirectory: ghidra_10.4_PUBLIC
            for entry in sorted(os.listdir(root), reverse=True):
                full = os.path.join(root, entry)
                if os.path.isdir(full):
                    candidate = _headless_path(full)
                    if candidate:
                        return candidate
            # Root itself might be the install dir
            candidate = _headless_path(root)
            if candidate:
                return candidate

    # 3. PATH search
    for name in ("analyzeHeadless", "analyzeHeadless.bat"):
        found = shutil.which(name)
        if found:
            return found

    return None


def _headless_path(ghidra_dir: str) -> str | None:
    system = platform.system()
    candidates = [
        os.path.join(ghidra_dir, "support", "analyzeHeadless"),
        os.path.join(ghidra_dir, "support", "analyzeHeadless.bat"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


# ── Main analysis function ─────────────────────────────────────────────────────

def run_ghidra_analysis(file_path: str, timeout: int = 300) -> dict[str, Any]:
    """
    Run Ghidra headless analysis on a binary and return decompiled functions.

    Returns dict with keys:
      - program, language, compiler, image_base
      - function_count, decompiled_count
      - functions: list of {name, address, signature, decompiled, size}
      - errors: list of {function, error}
      - ghidra_path: path used
      - status: "ok" | "error"
      - message: error message if status == "error"
    """
    headless = find_ghidra()
    if not headless:
        return {
            "status": "error",
            "message": (
                "Ghidra が見つかりません。\n\n"
                "インストール手順:\n"
                "1. https://ghidra-sre.org/ から Ghidra をダウンロード\n"
                "2. 解凍して GHIDRA_HOME 環境変数に設定\n"
                "   例: export GHIDRA_HOME=/opt/ghidra_11.0_PUBLIC\n"
                "3. または標準パス (/opt/ghidra, ~/ghidra) に配置"
            ),
        }

    # Write the decompile script to a temp dir so Ghidra can find it
    script_dir = tempfile.mkdtemp(prefix="appsleuth_scripts_")
    script_path = os.path.join(script_dir, SCRIPT_NAME)
    _write_decompile_script(script_path)

    project_dir = tempfile.mkdtemp(prefix="appsleuth_proj_")
    project_name = "AppSleuthAnalysis"

    try:
        cmd = [
            headless,
            project_dir,
            project_name,
            "-import", file_path,
            "-scriptPath", script_dir,
            "-postScript", SCRIPT_NAME,
            "-deleteProject",
            "-analysisTimeoutPerFile", str(min(timeout - 30, 240)),
            "-max-cpu", "2",
        ]

        # On Windows analyzeHeadless.bat needs cmd /c
        if headless.endswith(".bat"):
            cmd = ["cmd", "/c"] + cmd

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=project_dir,
        )

        stdout = result.stdout + result.stderr  # Ghidra mixes output/err

        # Extract JSON from output
        parsed = _extract_json(stdout)
        if parsed:
            parsed["status"] = "ok"
            parsed["ghidra_path"] = headless
            parsed["raw_log"] = stdout[-3000:]  # last 3KB of log
            return parsed

        # No JSON found - Ghidra ran but script failed
        return {
            "status": "error",
            "message": f"Ghidra は実行されましたが出力が解析できませんでした。\n\nログ:\n{stdout[-2000:]}",
            "ghidra_path": headless,
        }

    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "message": f"Ghidra 解析がタイムアウトしました ({timeout}秒)。大きなバイナリは時間がかかります。",
            "ghidra_path": headless,
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Ghidra 実行エラー: {e}",
            "ghidra_path": headless,
        }
    finally:
        import shutil as sh
        sh.rmtree(project_dir, ignore_errors=True)
        sh.rmtree(script_dir, ignore_errors=True)


def _extract_json(text: str) -> dict | None:
    start = text.find("GHIDRA_JSON_START")
    end = text.find("GHIDRA_JSON_END")
    if start == -1 or end == -1:
        return None
    json_str = text[start + len("GHIDRA_JSON_START"):end].strip()
    try:
        return json.loads(json_str)
    except json.JSONDecodeError:
        return None


def _write_decompile_script(path: str) -> None:
    """Write the Ghidra Jython script to disk."""
    script_source = Path(__file__).parent / "GhidraDecompile.py"
    if script_source.exists():
        import shutil
        shutil.copy(str(script_source), path)
    else:
        # Fallback: write inline
        with open(path, "w") as f:
            f.write(_INLINE_SCRIPT)


_INLINE_SCRIPT = '''
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import json

MAX_FUNCTIONS = 100
decompiler = DecompInterface()
decompiler.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()
functions = list(currentProgram.getFunctionManager().getFunctions(True))
results = []
for func in functions[:MAX_FUNCTIONS]:
    try:
        r = decompiler.decompileFunction(func, 60, monitor)
        if r and r.decompiledFunction:
            c = r.decompiledFunction.getC()
            if c:
                results.append({"name": func.getName(), "address": str(func.getEntryPoint()),
                                 "signature": str(func.getSignature()), "decompiled": c,
                                 "size": func.getBody().getNumAddresses()})
    except Exception as e:
        pass
output = {"program": currentProgram.getName(),
          "language": str(currentProgram.getLanguage().getLanguageID()),
          "compiler": str(currentProgram.getCompilerSpec().getCompilerSpecID()),
          "image_base": str(currentProgram.getImageBase()),
          "function_count": currentProgram.getFunctionManager().getFunctionCount(),
          "decompiled_count": len(results), "functions": results, "errors": []}
print("GHIDRA_JSON_START")
print(json.dumps(output, ensure_ascii=False))
print("GHIDRA_JSON_END")
'''


def get_ghidra_status() -> dict[str, Any]:
    """Return Ghidra installation status."""
    path = find_ghidra()
    return {
        "installed": path is not None,
        "path": path,
        "env_var": os.environ.get("GHIDRA_HOME"),
    }
