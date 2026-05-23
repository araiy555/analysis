"""
Frida dynamic instrumentation client.
Requires: pip install frida frida-tools
Also requires frida-server running on the target device/system.
"""

from typing import Any
import threading
import time

_sessions: dict[int, Any] = {}
_script_outputs: dict[int, list[str]] = {}


def get_processes() -> list[dict]:
    """List running processes via Frida."""
    try:
        import frida
        device = frida.get_local_device()
        processes = device.enumerate_processes()
        return [
            {
                "pid": proc.pid,
                "name": proc.name,
                "path": getattr(proc, "path", None) or "",
            }
            for proc in sorted(processes, key=lambda p: p.name.lower())
        ]
    except Exception as e:
        # Fallback: list processes using psutil or os
        return _get_processes_fallback()


def _get_processes_fallback() -> list[dict]:
    """List processes without Frida using psutil or /proc."""
    try:
        import psutil
        procs = []
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                procs.append({
                    "pid": proc.info["pid"],
                    "name": proc.info["name"] or "",
                    "path": proc.info["exe"] or "",
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return sorted(procs, key=lambda p: p["name"].lower())
    except ImportError:
        pass

    # Last resort: read /proc on Linux
    import os
    procs = []
    if os.path.exists("/proc"):
        for entry in os.scandir("/proc"):
            if entry.name.isdigit():
                try:
                    pid = int(entry.name)
                    with open(f"/proc/{pid}/comm") as f:
                        name = f.read().strip()
                    procs.append({"pid": pid, "name": name, "path": ""})
                except Exception:
                    pass
    return sorted(procs, key=lambda p: p["name"].lower())


def attach_process(pid: int) -> None:
    """Attach Frida to a process."""
    try:
        import frida
        device = frida.get_local_device()
        session = device.attach(pid)
        _sessions[pid] = session
        _script_outputs[pid] = []
    except Exception as e:
        raise RuntimeError(f"PID {pid} へのアタッチに失敗しました: {e}")


def run_script(pid: int, script_code: str, timeout: int = 15) -> list[str]:
    """Execute a Frida script on the attached process."""
    output: list[str] = []

    try:
        import frida

        session = _sessions.get(pid)
        if not session:
            # Try to attach automatically
            device = frida.get_local_device()
            session = device.attach(pid)
            _sessions[pid] = session

        done = threading.Event()

        def on_message(message: dict, data: Any) -> None:
            if message.get("type") == "send":
                payload = message.get("payload")
                if payload is not None:
                    output.append(str(payload))
            elif message.get("type") == "error":
                desc = message.get("description", "Unknown error")
                output.append(f"[ERROR] {desc}")
                stack = message.get("stack", "")
                if stack:
                    for line in stack.split("\n")[:5]:
                        output.append(f"  {line}")

        script = session.create_script(script_code)
        script.on("message", on_message)
        script.load()

        # Wait for script to produce output (with timeout)
        time.sleep(min(timeout, 10))

        try:
            script.unload()
        except Exception:
            pass

    except ImportError:
        output.append("[ERROR] Frida がインストールされていません")
        output.append("       pip install frida frida-tools を実行してください")
        output.append("       また、解析対象のデバイスで frida-server が起動している必要があります")
        output.append("")
        output.append("[INFO] Frida インストール手順:")
        output.append("       pip install frida frida-tools")
        output.append("       Android の場合: frida-server を /data/local/tmp/ に配置して起動")
    except Exception as e:
        output.append(f"[ERROR] スクリプト実行エラー: {e}")

    return output


def detach_process(pid: int) -> None:
    """Detach from a process."""
    session = _sessions.pop(pid, None)
    if session:
        try:
            session.detach()
        except Exception:
            pass
    _script_outputs.pop(pid, None)
