"""
Full-featured HTTP(S) intercepting proxy.

Architecture:
  - asyncio TCP server running inside the same event loop as FastAPI/uvicorn
  - Intercept mode: suspends a flow via asyncio.Event until user action
  - Repeater: replay requests via httpx
  - Auto-rules: find-replace in request/response headers/body
  - WebSocket broadcast for real-time traffic events
  - SSL/HTTPS: CONNECT tunnel (passthrough) OR full MitM with generated CA

Start the proxy by calling start_proxy_background() once on app startup.
"""

from __future__ import annotations

import asyncio
import base64
import gzip
import hashlib
import json
import re
import ssl
import time
import traceback
import uuid
import zlib
from datetime import datetime, timezone
from typing import Any

import httpx

# ── Shared state (all accesses are within one asyncio event loop) ──────────────

_server: asyncio.Server | None = None
_running = False

# Traffic log
_traffic: list[dict] = []

# Intercept queue: flow_id → {data, event, result}
_intercept_queue: dict[str, dict] = {}
_intercept_enabled = False
_intercept_filter = ""  # simple substring match on host/path

# Auto-modify rules
_rules: list[dict] = []

# WebSocket clients to broadcast traffic events
_ws_clients: set[Any] = set()

# CA for SSL MitM (generated lazily)
_ca_cert_pem: bytes | None = None
_ca_key_pem: bytes | None = None

# ── Public control API ─────────────────────────────────────────────────────────

async def start_proxy(host: str = "127.0.0.1", port: int = 8080, ssl_intercept: bool = True) -> None:
    global _server, _running, _traffic

    if _running:
        await stop_proxy()

    _traffic = []
    _running = True

    if ssl_intercept:
        _ensure_ca()

    _server = await asyncio.start_server(
        lambda r, w: _handle_connection(r, w, ssl_intercept),
        host=host,
        port=port,
    )
    asyncio.create_task(_server.serve_forever())


async def stop_proxy() -> None:
    global _server, _running
    _running = False
    if _server:
        _server.close()
        await _server.wait_closed()
        _server = None
    # Resolve all pending intercepts as drop
    for entry in list(_intercept_queue.values()):
        entry["result"] = {"action": "drop"}
        entry["event"].set()
    _intercept_queue.clear()


def get_traffic() -> list[dict]:
    return list(_traffic)


def set_intercept(enabled: bool, filter_str: str = "") -> None:
    global _intercept_enabled, _intercept_filter
    _intercept_enabled = enabled
    _intercept_filter = filter_str


def get_intercept_queue() -> list[dict]:
    return [v["data"] for v in _intercept_queue.values()]


def resolve_intercept(flow_id: str, action: str, modified: dict | None = None) -> bool:
    entry = _intercept_queue.get(flow_id)
    if not entry:
        return False
    entry["result"] = {"action": action, "modified": modified}
    entry["event"].set()
    return True


def get_rules() -> list[dict]:
    return list(_rules)


def add_rule(rule: dict) -> dict:
    rule = {**rule, "id": str(uuid.uuid4())}
    _rules.append(rule)
    return rule


def delete_rule(rule_id: str) -> bool:
    before = len(_rules)
    _rules[:] = [r for r in _rules if r.get("id") != rule_id]
    return len(_rules) < before


def toggle_rule(rule_id: str) -> bool:
    for r in _rules:
        if r.get("id") == rule_id:
            r["enabled"] = not r.get("enabled", True)
            return True
    return False


async def repeat_request(request_data: dict) -> dict:
    """Replay a captured (or user-modified) request via httpx."""
    method = request_data.get("method", "GET")
    scheme = "https" if request_data.get("is_https") else "http"
    host = request_data.get("host", "")
    path = request_data.get("path", "/")
    url = f"{scheme}://{host}{path}"
    headers = {k: v for k, v in request_data.get("request_headers", {}).items()
               if k.lower() not in ("host", "content-length", "transfer-encoding")}
    body = request_data.get("request_body", "")

    start = time.time()
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=30) as client:
            resp = await client.request(
                method=method,
                url=url,
                headers=headers,
                content=body.encode("latin-1", errors="replace") if body else None,
            )
        duration = int((time.time() - start) * 1000)
        resp_body = _decode_body(resp.content, dict(resp.headers))
        return {
            "status": resp.status_code,
            "duration": duration,
            "response_headers": dict(resp.headers),
            "response_body": resp_body[:50000],
            "size": len(resp.content),
        }
    except Exception as e:
        return {"error": str(e), "status": 0, "duration": int((time.time() - start) * 1000)}


def register_ws(ws: Any) -> None:
    _ws_clients.add(ws)


def unregister_ws(ws: Any) -> None:
    _ws_clients.discard(ws)


# ── SSL CA generation ──────────────────────────────────────────────────────────

def _ensure_ca() -> None:
    global _ca_cert_pem, _ca_key_pem
    if _ca_cert_pem:
        return
    try:
        from cryptography import x509 as cx509
        from cryptography.hazmat.primitives import hashes as ch, serialization as cs
        from cryptography.hazmat.primitives.asymmetric import rsa as cr
        from cryptography.x509.oid import NameOID
        import ipaddress
        from datetime import timedelta

        key = cr.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = cx509.Name([
            cx509.NameAttribute(NameOID.COUNTRY_NAME, "JP"),
            cx509.NameAttribute(NameOID.ORGANIZATION_NAME, "AppSleuth CA"),
            cx509.NameAttribute(NameOID.COMMON_NAME, "AppSleuth Root CA"),
        ])
        cert = (
            cx509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(cx509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
            .add_extension(cx509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, ch.SHA256())
        )
        _ca_cert_pem = cert.public_bytes(cs.Encoding.PEM)
        _ca_key_pem = key.private_bytes(
            cs.Encoding.PEM, cs.PrivateFormat.TraditionalOpenSSL, cs.NoEncryption()
        )
    except ImportError:
        pass  # cryptography not installed, SSL MitM won't work


def get_ca_cert() -> bytes | None:
    _ensure_ca()
    return _ca_cert_pem


def _make_server_cert(hostname: str) -> tuple[bytes, bytes] | None:
    """Generate a per-host cert signed by our CA."""
    if not _ca_cert_pem or not _ca_key_pem:
        return None
    try:
        from cryptography import x509 as cx509
        from cryptography.hazmat.primitives import hashes as ch, serialization as cs
        from cryptography.hazmat.primitives.asymmetric import rsa as cr
        from cryptography.x509.oid import NameOID
        from datetime import timedelta

        ca_cert = cx509.load_pem_x509_certificate(_ca_cert_pem)
        ca_key_obj = cs.load_pem_private_key(_ca_key_pem, password=None)

        srv_key = cr.generate_private_key(public_exponent=65537, key_size=2048)
        subject = cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, hostname)])
        alt_names = [cx509.DNSName(hostname)]

        cert = (
            cx509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(srv_key.public_key())
            .serial_number(cx509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(cx509.SubjectAlternativeName(alt_names), critical=False)
            .sign(ca_key_obj, ch.SHA256())
        )
        return (
            cert.public_bytes(cs.Encoding.PEM),
            srv_key.private_bytes(cs.Encoding.PEM, cs.PrivateFormat.TraditionalOpenSSL, cs.NoEncryption()),
        )
    except Exception:
        return None


# ── Connection handler ─────────────────────────────────────────────────────────

async def _handle_connection(
    client_r: asyncio.StreamReader,
    client_w: asyncio.StreamWriter,
    ssl_intercept: bool,
) -> None:
    try:
        raw_line = await asyncio.wait_for(client_r.readline(), timeout=10)
        if not raw_line:
            return
        first_line = raw_line.decode("latin-1", errors="replace").strip()
        if not first_line:
            return

        parts = first_line.split(" ")
        if len(parts) < 2:
            return
        method = parts[0].upper()

        if method == "CONNECT":
            await _handle_connect(client_r, client_w, parts[1], ssl_intercept)
        else:
            rest = await asyncio.wait_for(client_r.read(65536), timeout=10)
            full = raw_line + rest
            await _handle_http(client_w, full, is_https=False)
    except Exception:
        pass
    finally:
        try:
            client_w.close()
        except Exception:
            pass


async def _handle_connect(
    client_r: asyncio.StreamReader,
    client_w: asyncio.StreamWriter,
    target: str,
    ssl_intercept: bool,
) -> None:
    """Handle HTTPS CONNECT tunnel."""
    # Drain CONNECT headers
    while True:
        line = await asyncio.wait_for(client_r.readline(), timeout=5)
        if line in (b"\r\n", b"\n", b""):
            break

    host = target.split(":")[0]
    port = int(target.split(":")[1]) if ":" in target else 443

    if ssl_intercept and _ca_cert_pem:
        pair = _make_server_cert(host)
        if pair:
            await _handle_https_mitm(client_r, client_w, host, port, pair)
            return

    # Passthrough tunnel
    try:
        remote_r, remote_w = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=10
        )
    except Exception:
        client_w.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        await client_w.drain()
        return

    client_w.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    await client_w.drain()

    async def pipe(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        try:
            while True:
                data = await r.read(65536)
                if not data:
                    break
                w.write(data)
                await w.drain()
        except Exception:
            pass
        finally:
            try:
                w.close()
            except Exception:
                pass

    await asyncio.gather(pipe(client_r, remote_w), pipe(remote_r, client_w))
    try:
        remote_w.close()
    except Exception:
        pass


async def _handle_https_mitm(
    client_r: asyncio.StreamReader,
    client_w: asyncio.StreamWriter,
    host: str,
    port: int,
    cert_pair: tuple[bytes, bytes],
) -> None:
    """Full SSL MitM: present fake cert to client, connect upstream with real SSL."""
    import tempfile, os

    cert_pem, key_pem = cert_pair

    # Write cert/key to temp files (ssl.SSLContext needs file paths)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cf:
        cf.write(cert_pem)
        cert_file = cf.name
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as kf:
        kf.write(key_pem)
        key_file = kf.name

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_file, key_file)

        client_w.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await client_w.drain()

        # Wrap client connection with our fake cert
        loop = asyncio.get_event_loop()
        transport = client_w.transport
        sock = transport.get_extra_info("socket")
        if not sock:
            return

        ssl_sock = ctx.wrap_socket(sock, server_side=True)
        tls_r, tls_w = await asyncio.open_connection(sock=ssl_sock)

        # Now read the actual HTTP request over TLS
        raw = await asyncio.wait_for(tls_r.read(65536), timeout=10)
        if raw:
            await _handle_http(tls_w, raw, is_https=True, hostname=host, port=port)

    except Exception:
        pass
    finally:
        try:
            os.unlink(cert_file)
            os.unlink(key_file)
        except Exception:
            pass


async def _handle_http(
    writer: asyncio.StreamWriter,
    raw: bytes,
    is_https: bool,
    hostname: str = "",
    port: int = 80,
) -> None:
    """Parse HTTP request, apply rules, optionally intercept, forward, log."""
    flow_id = str(uuid.uuid4())

    # Parse raw HTTP
    try:
        req = _parse_http_request(raw, is_https, hostname, port)
    except Exception:
        writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        await writer.drain()
        return

    # Apply request rules
    for rule in _rules:
        if rule.get("enabled") and rule.get("phase") in ("request", "both"):
            req = _apply_rule(req, rule, "request")

    # Intercept?
    if _intercept_enabled and _matches_filter(req):
        req = await _intercept_flow(flow_id, req, writer)
        if req is None:
            return  # dropped

    # Forward to real server
    start = time.time()
    resp = await _forward_request(req)
    duration = int((time.time() - start) * 1000)

    # Apply response rules
    for rule in _rules:
        if rule.get("enabled") and rule.get("phase") in ("response", "both"):
            resp = _apply_rule_to_response(resp, rule)

    # Send response back to client
    try:
        writer.write(_build_http_response(resp))
        await writer.drain()
    except Exception:
        pass

    # Log traffic
    entry = {
        "id": flow_id,
        "method": req["method"],
        "host": req["host"],
        "path": req["path"],
        "status": resp.get("status", 0),
        "size": len(resp.get("body", b"")),
        "duration": duration,
        "timestamp": datetime.now().isoformat(),
        "is_https": is_https,
        "request_headers": req.get("headers", {}),
        "response_headers": resp.get("headers", {}),
        "request_body": req.get("body", ""),
        "response_body": _decode_body(resp.get("body", b""), resp.get("headers", {}))[:8192],
    }
    _traffic.append(entry)
    if len(_traffic) > 2000:
        _traffic.pop(0)

    # Broadcast to WebSocket clients
    await _broadcast(entry)


async def _intercept_flow(flow_id: str, req: dict, writer: asyncio.StreamWriter) -> dict | None:
    """Add flow to intercept queue and wait for user action."""
    event = asyncio.Event()
    data = {
        "id": flow_id,
        "method": req["method"],
        "host": req["host"],
        "path": req["path"],
        "is_https": req.get("is_https", False),
        "request_headers": req.get("headers", {}),
        "request_body": req.get("body", ""),
        "timestamp": datetime.now().isoformat(),
    }
    _intercept_queue[flow_id] = {"data": data, "event": event, "result": None}

    try:
        await asyncio.wait_for(event.wait(), timeout=300)
    except asyncio.TimeoutError:
        _intercept_queue.pop(flow_id, None)
        writer.write(b"HTTP/1.1 504 Gateway Timeout\r\n\r\n")
        await writer.drain()
        return None

    result = _intercept_queue.pop(flow_id, {}).get("result", {})
    if result.get("action") == "drop":
        writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()
        return None

    # Apply user modifications
    if result.get("modified"):
        m = result["modified"]
        req = {**req, **{k: v for k, v in m.items() if v is not None}}

    return req


# ── HTTP parser / builder / forwarder ─────────────────────────────────────────

def _parse_http_request(raw: bytes, is_https: bool, hostname: str, port: int) -> dict:
    idx = raw.find(b"\r\n\r\n")
    if idx == -1:
        idx = raw.find(b"\n\n")
        sep = b"\n\n"
    else:
        sep = b"\r\n\r\n"

    header_part = raw[:idx].decode("latin-1", errors="replace")
    body_bytes = raw[idx + len(sep):]

    lines = header_part.split("\r\n") if "\r\n" in header_part else header_part.split("\n")
    first = lines[0]
    parts = first.split(" ")
    method = parts[0].upper()
    url = parts[1] if len(parts) > 1 else "/"

    # Parse host from headers or URL
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ": " in line:
            k, v = line.split(": ", 1)
            headers[k.strip()] = v.strip()

    host = headers.get("Host", hostname or "unknown")
    if ":" in host and not host.startswith("["):
        host_only = host.split(":")[0]
    else:
        host_only = host

    # Extract path
    if url.startswith("http://") or url.startswith("https://"):
        from urllib.parse import urlparse
        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        host = parsed.netloc or host
    else:
        path = url

    body_text = body_bytes.decode("latin-1", errors="replace") if body_bytes else ""

    return {
        "method": method,
        "host": host,
        "host_only": host_only,
        "port": port,
        "path": path,
        "headers": headers,
        "body": body_text,
        "is_https": is_https,
    }


async def _forward_request(req: dict) -> dict:
    scheme = "https" if req.get("is_https") else "http"
    host = req["host"]
    path = req["path"]
    url = f"{scheme}://{host}{path}"
    headers = {k: v for k, v in req.get("headers", {}).items()
               if k.lower() not in ("content-length", "transfer-encoding", "connection")}
    body = req.get("body", "")

    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=20) as client:
            resp = await client.request(
                method=req["method"],
                url=url,
                headers=headers,
                content=body.encode("latin-1", errors="replace") if body else None,
            )
        return {
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.content,
            "reason": resp.reason_phrase,
        }
    except Exception as e:
        return {
            "status": 502,
            "headers": {"Content-Type": "text/plain"},
            "body": f"AppSleuth proxy error: {e}".encode(),
            "reason": "Bad Gateway",
        }


def _build_http_response(resp: dict) -> bytes:
    status = resp.get("status", 502)
    reason = resp.get("reason", "")
    headers = resp.get("headers", {})
    body = resp.get("body", b"")

    lines = [f"HTTP/1.1 {status} {reason}"]
    for k, v in headers.items():
        if k.lower() not in ("transfer-encoding",):
            lines.append(f"{k}: {v}")
    lines.append(f"Content-Length: {len(body)}")
    lines.append("")
    lines.append("")

    return "\r\n".join(lines).encode("latin-1") + body


# ── Rules engine ───────────────────────────────────────────────────────────────

def _matches_filter(req: dict) -> bool:
    if not _intercept_filter:
        return True
    target = req.get("host", "") + req.get("path", "")
    return _intercept_filter.lower() in target.lower()


def _apply_rule(req: dict, rule: dict, phase: str) -> dict:
    req = dict(req)
    target = rule.get("target", "body")  # body | header | url
    match = rule.get("match", "")
    replace = rule.get("replace", "")

    if not match:
        return req

    if target == "url":
        req["path"] = req.get("path", "").replace(match, replace)
    elif target == "body":
        req["body"] = req.get("body", "").replace(match, replace)
    elif target == "header":
        header_name = rule.get("header_name", "")
        if header_name and header_name in req.get("headers", {}):
            req["headers"] = dict(req.get("headers", {}))
            req["headers"][header_name] = req["headers"][header_name].replace(match, replace)
    return req


def _apply_rule_to_response(resp: dict, rule: dict) -> dict:
    resp = dict(resp)
    target = rule.get("target", "body")
    match_str = rule.get("match", "")
    replace = rule.get("replace", "")

    if not match_str:
        return resp

    if target == "body":
        body = _decode_body(resp.get("body", b""), resp.get("headers", {}))
        body = body.replace(match_str, replace)
        resp["body"] = body.encode("utf-8", errors="replace")
        resp["headers"] = dict(resp.get("headers", {}))
        resp["headers"].pop("content-encoding", None)
        resp["headers"]["content-length"] = str(len(resp["body"]))
    elif target == "header":
        header_name = rule.get("header_name", "")
        if header_name:
            hdrs = dict(resp.get("headers", {}))
            for k in list(hdrs.keys()):
                if k.lower() == header_name.lower():
                    hdrs[k] = hdrs[k].replace(match_str, replace)
            resp["headers"] = hdrs
    return resp


def _decode_body(body: bytes, headers: dict) -> str:
    encoding = headers.get("content-encoding", headers.get("Content-Encoding", ""))
    try:
        if "gzip" in encoding:
            body = gzip.decompress(body)
        elif "deflate" in encoding:
            body = zlib.decompress(body)
        elif "br" in encoding:
            try:
                import brotli
                body = brotli.decompress(body)
            except Exception:
                pass
    except Exception:
        pass
    try:
        return body.decode("utf-8")
    except Exception:
        return body.decode("latin-1", errors="replace")


# ── WebSocket broadcast ────────────────────────────────────────────────────────

async def _broadcast(entry: dict) -> None:
    if not _ws_clients:
        return
    # Send only summary (full detail fetched on demand)
    msg = json.dumps({
        "type": "traffic",
        "id": entry["id"],
        "method": entry["method"],
        "host": entry["host"],
        "path": entry["path"],
        "status": entry["status"],
        "size": entry["size"],
        "duration": entry["duration"],
        "timestamp": entry["timestamp"],
        "is_https": entry["is_https"],
    })
    dead = set()
    for ws in list(_ws_clients):
        try:
            await ws.send_text(msg)
        except Exception:
            dead.add(ws)
    _ws_clients -= dead
