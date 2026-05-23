"""
Frida dynamic instrumentation client with real-time WebSocket streaming.
"""

from __future__ import annotations

import asyncio
import json
import time
import threading
from typing import Any

# WebSocket clients subscribed to frida output: pid → set of ws
_frida_ws: dict[int, set[Any]] = {}
_sessions: dict[int, Any] = {}


def get_processes() -> list[dict]:
    try:
        import frida
        device = frida.get_local_device()
        procs = device.enumerate_processes()
        return sorted(
            [{"pid": p.pid, "name": p.name, "path": getattr(p, "path", "") or ""} for p in procs],
            key=lambda p: p["name"].lower(),
        )
    except ImportError:
        return _get_processes_fallback()
    except Exception as e:
        return _get_processes_fallback()


def _get_processes_fallback() -> list[dict]:
    try:
        import psutil
        result = []
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                result.append({"pid": proc.info["pid"], "name": proc.info["name"] or "", "path": proc.info["exe"] or ""})
            except Exception:
                pass
        return sorted(result, key=lambda p: p["name"].lower())
    except ImportError:
        pass
    import os
    result = []
    if os.path.exists("/proc"):
        for entry in os.scandir("/proc"):
            if entry.name.isdigit():
                try:
                    with open(f"/proc/{entry.name}/comm") as f:
                        name = f.read().strip()
                    result.append({"pid": int(entry.name), "name": name, "path": ""})
                except Exception:
                    pass
    return sorted(result, key=lambda p: p["name"].lower())


def attach_process(pid: int) -> None:
    try:
        import frida
        device = frida.get_local_device()
        session = device.attach(pid)
        _sessions[pid] = session
    except ImportError:
        raise RuntimeError("frida がインストールされていません: pip install frida frida-tools")
    except Exception as e:
        raise RuntimeError(f"PID {pid} へのアタッチ失敗: {e}")


def run_script(pid: int, script_code: str, timeout: int = 15) -> list[str]:
    """Synchronous run - returns all output at once (backward compat)."""
    output: list[str] = []

    try:
        import frida
        session = _sessions.get(pid)
        if not session:
            device = frida.get_local_device()
            session = device.attach(pid)
            _sessions[pid] = session

        done_event = threading.Event()

        def on_message(message: dict, data: Any) -> None:
            if message.get("type") == "send":
                payload = message.get("payload")
                if payload is not None:
                    output.append(str(payload))
            elif message.get("type") == "error":
                output.append(f"[ERROR] {message.get('description', '')}")
                for line in message.get("stack", "").split("\n")[:3]:
                    if line.strip():
                        output.append(f"  {line}")

        script = session.create_script(script_code)
        script.on("message", on_message)
        script.load()
        time.sleep(min(timeout, 10))
        try:
            script.unload()
        except Exception:
            pass

    except ImportError:
        output.extend(_frida_not_installed_msg())
    except Exception as e:
        output.append(f"[ERROR] {e}")

    return output


async def run_script_streaming(
    pid: int,
    script_code: str,
    ws: Any,
    timeout: int = 60,
) -> None:
    """
    Run Frida script and stream output in real-time via WebSocket.
    `ws` must have an async send_text(str) method.
    """

    async def send(line: str) -> None:
        try:
            ts = time.strftime("%H:%M:%S")
            await ws.send_text(json.dumps({"type": "output", "line": f"{ts} {line}"}))
        except Exception:
            pass

    try:
        import frida
    except ImportError:
        for line in _frida_not_installed_msg():
            await send(line)
        return

    session = _sessions.get(pid)
    if not session:
        try:
            device = frida.get_local_device()
            session = device.attach(pid)
            _sessions[pid] = session
        except Exception as e:
            await send(f"[ERROR] アタッチ失敗: {e}")
            return

    loop = asyncio.get_event_loop()
    queue: asyncio.Queue[str | None] = asyncio.Queue()

    def on_message(message: dict, data: Any) -> None:
        if message.get("type") == "send":
            payload = message.get("payload")
            if payload is not None:
                asyncio.run_coroutine_threadsafe(queue.put(str(payload)), loop)
        elif message.get("type") == "error":
            desc = message.get("description", "Unknown error")
            asyncio.run_coroutine_threadsafe(queue.put(f"[ERROR] {desc}"), loop)
            for line in message.get("stack", "").split("\n")[:3]:
                if line.strip():
                    asyncio.run_coroutine_threadsafe(queue.put(f"  {line}"), loop)

    script = None
    try:
        script = session.create_script(script_code)
        script.on("message", on_message)
        script.load()
        await send("[+] スクリプトを実行中... (出力が表示されます)")

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                line = await asyncio.wait_for(queue.get(), timeout=1.0)
                if line is None:
                    break
                await send(line)
            except asyncio.TimeoutError:
                continue
            except Exception:
                break

    except Exception as e:
        await send(f"[ERROR] スクリプトエラー: {e}")
    finally:
        if script:
            try:
                script.unload()
            except Exception:
                pass
        await send("[*] スクリプト実行完了")
        try:
            await ws.send_text(json.dumps({"type": "done"}))
        except Exception:
            pass


def detach_process(pid: int) -> None:
    session = _sessions.pop(pid, None)
    if session:
        try:
            session.detach()
        except Exception:
            pass


def _frida_not_installed_msg() -> list[str]:
    return [
        "[ERROR] Frida がインストールされていません",
        "       pip install frida frida-tools を実行してください",
        "",
        "[INFO] Android デバイスの場合:",
        "       1. frida-server を /data/local/tmp/ に配置",
        "       2. adb shell chmod +x /data/local/tmp/frida-server",
        "       3. adb shell /data/local/tmp/frida-server &",
        "       4. adb forward tcp:27042 tcp:27042",
    ]
