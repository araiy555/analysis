"""
Network proxy manager using mitmproxy or a simple Python HTTP proxy fallback.
"""

import os
import re
import sys
import uuid
import threading
import time
from typing import Any

_proxy_process = None
_traffic: list[dict] = []
_lock = threading.Lock()
_server_thread = None
_running = False


def start_proxy(host: str = "127.0.0.1", port: int = 8080, ssl_intercept: bool = True) -> None:
    global _proxy_process, _traffic, _running, _server_thread

    _traffic = []

    try:
        _start_mitmproxy(host, port, ssl_intercept)
    except Exception as e:
        print(f"mitmproxy not available ({e}), using built-in proxy")
        _start_builtin_proxy(host, port)


def _start_mitmproxy(host: str, port: int, ssl_intercept: bool) -> None:
    global _proxy_process
    import subprocess

    script_path = os.path.join(os.path.dirname(__file__), "_mitm_addon.py")
    _write_addon_script(script_path)

    args = [
        sys.executable, "-m", "mitmproxy",
        "--listen-host", host,
        "--listen-port", str(port),
        "--mode", "regular",
        "--scripts", script_path,
        "--set", "stream_large_bodies=1m",
        "--quiet",
    ]

    if not ssl_intercept:
        args.append("--no-ssl-insecure")

    _proxy_process = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _write_addon_script(path: str) -> None:
    """Write a mitmproxy addon script that POSTs captured traffic to our backend."""
    script = '''
import json
import uuid
import time
import threading
import requests
from mitmproxy import http

BACKEND = "http://127.0.0.1:8765"

class TrafficCapture:
    def response(self, flow: http.HTTPFlow):
        try:
            entry = {
                "id": str(uuid.uuid4()),
                "method": flow.request.method,
                "host": flow.request.host,
                "path": flow.request.path,
                "status": flow.response.status_code if flow.response else 0,
                "size": len(flow.response.content) if flow.response and flow.response.content else 0,
                "duration": int((flow.response.timestamp_end - flow.request.timestamp_start) * 1000) if flow.response else 0,
                "timestamp": flow.request.timestamp_start,
                "is_https": flow.request.scheme == "https",
                "request_headers": dict(flow.request.headers),
                "response_headers": dict(flow.response.headers) if flow.response else {},
                "request_body": flow.request.get_text(strict=False)[:4096] if flow.request.content else "",
                "response_body": flow.response.get_text(strict=False)[:4096] if flow.response and flow.response.content else "",
            }
            threading.Thread(
                target=requests.post,
                args=(f"{BACKEND}/proxy/internal/traffic",),
                kwargs={"json": entry, "timeout": 2},
                daemon=True
            ).start()
        except Exception:
            pass

addons = [TrafficCapture()]
'''
    with open(path, "w") as f:
        f.write(script)


def _start_builtin_proxy(host: str, port: int) -> None:
    """Start a simple HTTP proxy that captures traffic."""
    global _running, _server_thread

    _running = True

    import socket
    import select

    def handle_client(client_sock: socket.socket) -> None:
        try:
            data = b""
            while True:
                chunk = client_sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\r\n\r\n" in data:
                    break

            if not data:
                return

            request_text = data.decode("latin-1", errors="ignore")
            lines = request_text.split("\r\n")
            if not lines:
                return

            first_line = lines[0]
            parts = first_line.split(" ")
            if len(parts) < 2:
                return

            method, url = parts[0], parts[1]

            # Parse host
            host_match = re.search(r"Host: ([^\r\n]+)", request_text)
            req_host = host_match.group(1).strip() if host_match else url

            # Extract path
            path = url
            if url.startswith("http://") or url.startswith("https://"):
                from urllib.parse import urlparse
                parsed = urlparse(url)
                req_host = parsed.netloc
                path = parsed.path or "/"
                if parsed.query:
                    path += "?" + parsed.query

            # Extract headers
            req_headers: dict[str, str] = {}
            for line in lines[1:]:
                if ": " in line:
                    k, v = line.split(": ", 1)
                    req_headers[k] = v

            # Try to forward request
            target_host = req_host.split(":")[0]
            target_port = int(req_host.split(":")[1]) if ":" in req_host else 80

            start_time = time.time()
            status = 0
            resp_headers: dict[str, str] = {}
            resp_body = ""

            try:
                remote_sock = socket.create_connection((target_host, target_port), timeout=10)
                remote_sock.sendall(data)
                resp_data = b""
                remote_sock.settimeout(5)
                try:
                    while True:
                        chunk = remote_sock.recv(4096)
                        if not chunk:
                            break
                        resp_data += chunk
                        client_sock.sendall(chunk)
                        if len(resp_data) > 1024 * 1024:
                            break
                except socket.timeout:
                    pass
                remote_sock.close()

                resp_text = resp_data.decode("latin-1", errors="ignore")
                resp_lines = resp_text.split("\r\n")
                if resp_lines:
                    status_line = resp_lines[0].split(" ")
                    status = int(status_line[1]) if len(status_line) > 1 else 0
                    for rline in resp_lines[1:]:
                        if ": " in rline:
                            k, v = rline.split(": ", 1)
                            resp_headers[k] = v
                    body_start = resp_text.find("\r\n\r\n")
                    resp_body = resp_text[body_start + 4:body_start + 4 + 4096] if body_start >= 0 else ""

            except Exception:
                client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")

            duration = int((time.time() - start_time) * 1000)

            entry = {
                "id": str(uuid.uuid4()),
                "method": method,
                "host": req_host,
                "path": path,
                "status": status,
                "size": len(resp_data) if "resp_data" in dir() else 0,
                "duration": duration,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "is_https": False,
                "request_headers": req_headers,
                "response_headers": resp_headers,
                "request_body": data.decode("latin-1", errors="ignore")[len(first_line) + 2:4096],
                "response_body": resp_body[:4096],
            }

            with _lock:
                _traffic.append(entry)
                if len(_traffic) > 1000:
                    _traffic.pop(0)

        except Exception:
            pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def proxy_server() -> None:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((host, port))
        server_sock.listen(50)
        server_sock.settimeout(1)
        print(f"Built-in proxy started on {host}:{port}")

        while _running:
            try:
                client, _ = server_sock.accept()
                t = threading.Thread(target=handle_client, args=(client,), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except Exception:
                break

        server_sock.close()

    _server_thread = threading.Thread(target=proxy_server, daemon=True)
    _server_thread.start()


def stop_proxy() -> None:
    global _proxy_process, _running, _server_thread

    _running = False

    if _proxy_process:
        try:
            _proxy_process.terminate()
            _proxy_process.wait(timeout=5)
        except Exception:
            try:
                _proxy_process.kill()
            except Exception:
                pass
        _proxy_process = None


def get_traffic() -> list[dict]:
    with _lock:
        return list(_traffic)


def add_traffic_entry(entry: dict) -> None:
    """Called by mitmproxy addon to add a captured entry."""
    with _lock:
        _traffic.append(entry)
        if len(_traffic) > 1000:
            _traffic.pop(0)
