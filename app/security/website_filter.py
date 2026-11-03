"""Website allowlist: only approved websites open.

How it works (honest summary):
* A small HTTP/HTTPS filtering proxy runs on 127.0.0.1 inside SecureWork AI. It looks at the
  destination host name only (HTTPS is tunnelled, never decrypted) and refuses every host that is
  not on the allowed list, so blocked sites do not load.
* On Windows, SecureWork AI points the user's Internet (WinINET) proxy setting at it, which is what
  Edge, Chrome and Firefox (default settings) use. The original settings are saved and restored when
  the filter is turned off or the app closes, and are recovered on the next start after a crash.
* Limits: it is an application-level control, not a firewall. Programs that ignore the Windows proxy
  setting, or a user who changes the proxy setting themselves, can bypass it (SecureWork AI notices and
  restores its setting, and raises an alert). It needs no administrator rights.
"""
from __future__ import annotations

import html
import ipaddress
import json
import logging
import os
import re
import select
import socket
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)
CONFIG_PATH = Path("config/allowed_websites.json")
BACKUP_PATH = Path("data/proxy_backup.json")
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


# ------------------------------------------------------------------ domains
def normalize_domain(text: str) -> str | None:
    """'https://WWW.Example.com:443/a?b' -> 'www.example.com'. None if it is not a valid domain name."""
    value = (text or "").strip().lower()
    if not value or len(value) > 300 or any(c.isspace() for c in value):
        return None
    if "://" in value:
        value = urlsplit(value).hostname or ""
    else:
        value = re.split(r"[/?#]", value, maxsplit=1)[0]
        value = value.rsplit("@", 1)[-1]
        value = re.sub(r":\d+$", "", value)
    value = value.removeprefix("*.").strip(".")
    if not value or len(value) > 253 or "." not in value:
        return None
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    try:
        ipaddress.ip_address(value)
        return None  # IP addresses are not accepted: allow websites by name
    except ValueError:
        pass
    return value if all(_LABEL.match(part) for part in value.split(".")) else None


def host_allowed(host: str, allowed: frozenset[str]) -> bool:
    """True for an allowed domain and any subdomain of it."""
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return False
    parts = host.split(".")
    return any(".".join(parts[i:]) in allowed for i in range(len(parts)))


# -------------------------------------------------------------------- proxy
_BLOCK_PAGE = """<!doctype html><meta charset="utf-8"><title>Blocked</title>
<body style="font-family:Segoe UI,Arial,sans-serif;max-width:560px;margin:12vh auto;color:#1f2937">
<h2>This website is blocked</h2>
<p><b>{host}</b> is not on your allowed websites list.</p>
<p style="color:#6b7280">Blocked by SecureWork AI. Ask your administrator to add it if you need it for work.</p></body>"""


class FilterProxy:
    """Loopback-only HTTP/HTTPS (CONNECT) proxy that only forwards to allowed hosts."""

    def __init__(self, is_allowed: Callable[[str], bool], allow_loopback: bool = False,
                 allowed_ports: tuple[int, ...] = (80, 443, 8080, 8443), max_connections: int = 200,
                 idle_timeout: float = 120.0) -> None:
        self._is_allowed = is_allowed
        self._allow_loopback = allow_loopback
        self._ports = frozenset(allowed_ports)
        self._slots = threading.Semaphore(max_connections)
        self._idle = idle_timeout
        self._server: socket.socket | None = None
        self._stop = threading.Event()
        self.port = 0
        self.blocked: deque[tuple[float, str]] = deque(maxlen=200)
        self.blocked_count = 0
        self.allowed_count = 0
        self._lock = threading.Lock()

    def start(self) -> int:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))  # loopback only: never reachable from the network
        server.listen(128)
        server.settimeout(0.5)
        self._server, self.port = server, server.getsockname()[1]
        self._stop.clear()
        threading.Thread(target=self._accept_loop, name="website-filter", daemon=True).start()
        return self.port

    def stop(self) -> None:
        self._stop.set()
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass
            self._server = None

    @property
    def running(self) -> bool:
        return self._server is not None and not self._stop.is_set()

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            if not self._slots.acquire(blocking=False):  # too many open connections: refuse, never pile up
                conn.close()
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    # ---- one client connection
    def _handle(self, client: socket.socket) -> None:
        upstream = None
        try:
            client.settimeout(15)
            head, rest = self._read_head(client)
            if head is None:
                return
            lines = head.split(b"\r\n")
            parts = lines[0].decode("latin-1").split(" ")
            if len(parts) != 3:
                return self._reply(client, 400, "Bad request")
            method, target, version = parts
            if method.upper() == "CONNECT":
                host, port = self._hostport(target, 443)
                if host is None:
                    return self._reply(client, 400, "Bad request")
                if not self._permit(host, port):
                    return self._reply(client, 403, "Blocked by SecureWork AI")
                upstream = self._open(host, port)
                if upstream is None:
                    return self._reply(client, 502, "Cannot reach site")
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                if rest:
                    upstream.sendall(rest)
            else:
                url = urlsplit(target)
                if url.scheme != "http" or not url.hostname:
                    return self._reply(client, 400, "This is a filtering proxy; use it as a browser proxy")
                host, port = url.hostname.lower(), url.port or 80
                if not self._permit(host, port):
                    return self._reply(client, 403, "", page=_BLOCK_PAGE.format(host=html.escape(host)))
                upstream = self._open(host, port)
                if upstream is None:
                    return self._reply(client, 502, "Cannot reach site")
                path = (url.path or "/") + (f"?{url.query}" if url.query else "")
                out = [f"{method} {path} {version}".encode("latin-1")]
                has_host = False
                for line in lines[1:]:
                    name = line.split(b":", 1)[0].strip().lower()
                    if name in (b"proxy-connection", b"proxy-authorization", b"connection", b"keep-alive"):
                        continue
                    has_host = has_host or name == b"host"
                    out.append(line)
                if not has_host:
                    out.append(f"Host: {url.netloc}".encode("latin-1"))
                out.append(b"Connection: close")
                upstream.sendall(b"\r\n".join(out) + b"\r\n\r\n" + rest)
            self._relay(client, upstream)
        except (OSError, ValueError):
            pass
        finally:
            for s in (upstream, client):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass
            self._slots.release()

    def _permit(self, host: str, port: int) -> bool:
        ok = port in self._ports and self._is_allowed(host)
        with self._lock:
            if ok:
                self.allowed_count += 1
            else:
                self.blocked_count += 1
                self.blocked.append((time.time(), host))
        return ok

    def _open(self, host: str, port: int) -> socket.socket | None:
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError:
            return None
        for family, stype, proto, _canon, addr in infos:
            ip = ipaddress.ip_address(addr[0].split("%")[0])
            # Stops a DNS trick from steering an allowed name to this PC or the local network gateway.
            if not self._allow_loopback and (ip.is_loopback or ip.is_link_local or ip.is_multicast
                                             or ip.is_unspecified or ip.is_reserved):
                continue
            s = socket.socket(family, stype, proto)
            s.settimeout(10)
            try:
                s.connect(addr)
                return s
            except OSError:
                s.close()
        return None

    @staticmethod
    def _read_head(sock: socket.socket) -> tuple[bytes | None, bytes]:
        buf = b""
        while b"\r\n\r\n" not in buf:
            if len(buf) > 65536:
                return None, b""
            chunk = sock.recv(8192)
            if not chunk:
                return None, b""
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        return head, rest

    @staticmethod
    def _hostport(target: str, default: int) -> tuple[str | None, int]:
        target = target.strip()
        if target.startswith("["):  # [IPv6]:port
            host, _, rest = target[1:].partition("]")
            port = rest.lstrip(":")
        elif target.count(":") == 1:
            host, _, port = target.partition(":")
        else:
            host, port = target, ""
        host = host.lower()
        try:
            number = int(port) if port else default
        except ValueError:
            return None, 0
        return (host, number) if host and 0 < number < 65536 else (None, 0)

    @staticmethod
    def _reply(sock: socket.socket, code: int, text: str, page: str | None = None) -> None:
        reason = {400: "Bad Request", 403: "Forbidden", 502: "Bad Gateway"}.get(code, "Error")
        body = (page or text).encode("utf-8")
        ctype = "text/html; charset=utf-8" if page else "text/plain; charset=utf-8"
        try:
            sock.sendall(f"HTTP/1.1 {code} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\n"
                         "Connection: close\r\n\r\n".encode("latin-1") + body)
        except OSError:
            pass

    def _relay(self, a: socket.socket, b: socket.socket) -> None:
        a.settimeout(30)
        b.settimeout(30)
        last = time.monotonic()
        while not self._stop.is_set():
            ready, _, _ = select.select([a, b], [], [], 1.0)
            if not ready:
                if time.monotonic() - last > self._idle:
                    return
                continue
            for s in ready:
                data = s.recv(65536)
                if not data:
                    return
                (b if s is a else a).sendall(data)
                last = time.monotonic()


# ------------------------------------------------------------ system proxy
REG_SZ, REG_DWORD = 1, 4
_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
_NAMES = ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL", "AutoDetect")


class _WinRegistry:
    """Current-user Internet Settings (no administrator rights needed)."""

    def get(self, name: str):
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _KEY) as key:
                value, vtype = winreg.QueryValueEx(key, name)
                return [vtype, value]
        except OSError:
            return None

    def set(self, name: str, vtype: int, value) -> None:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, name, 0, vtype, value)

    def delete(self, name: str) -> None:
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, name)
        except OSError:
            pass

    def notify(self) -> None:
        import ctypes
        wininet = ctypes.windll.wininet
        wininet.InternetSetOptionW(0, 39, 0, 0)  # settings changed
        wininet.InternetSetOptionW(0, 37, 0, 0)  # refresh


class SystemProxy:
    """Points Windows' proxy setting at the filter and puts the user's original settings back."""

    def __init__(self, registry=None, backup_path: Path | str = BACKUP_PATH) -> None:
        self.supported = registry is not None or sys.platform == "win32"
        self._reg = registry if registry is not None else (_WinRegistry() if sys.platform == "win32" else None)
        self.backup_path = Path(backup_path)

    def has_backup(self) -> bool:
        return self.backup_path.exists()

    def enable(self, port: int) -> None:
        if not self.supported:
            raise OSError("Setting the system proxy is only supported on Windows.")
        if not self.has_backup():  # never overwrite the ORIGINAL settings with our own
            backup = {name: self._reg.get(name) for name in _NAMES}
            self.backup_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.backup_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(backup), encoding="utf-8")
            os.replace(tmp, self.backup_path)
        self._apply(port)

    def _apply(self, port: int) -> None:
        self._reg.set("ProxyServer", REG_SZ, f"127.0.0.1:{port}")
        self._reg.set("ProxyOverride", REG_SZ, "localhost;127.0.0.1;::1")
        self._reg.set("AutoDetect", REG_DWORD, 0)
        self._reg.delete("AutoConfigURL")  # a PAC script would bypass our proxy
        self._reg.set("ProxyEnable", REG_DWORD, 1)
        self._reg.notify()

    def is_applied(self, port: int) -> bool:
        if not self.supported:
            return True
        enable, server = self._reg.get("ProxyEnable"), self._reg.get("ProxyServer")
        return bool(enable and enable[1] == 1 and server and server[1] == f"127.0.0.1:{port}"
                    and not self._reg.get("AutoConfigURL"))

    def reapply(self, port: int) -> None:
        if self.supported:
            self._apply(port)

    def restore(self) -> bool:
        """Put back the saved original settings. Returns True if something was restored."""
        if not self.supported or not self.has_backup():
            return False
        backup = json.loads(self.backup_path.read_text(encoding="utf-8"))
        for name in _NAMES:
            saved = backup.get(name)
            if saved is None:
                self._reg.delete(name)
            else:
                self._reg.set(name, int(saved[0]), saved[1])
        self._reg.notify()
        self.backup_path.unlink(missing_ok=True)
        return True


# --------------------------------------------------------------- controller
class WebsiteFilterController:
    def __init__(self, config_path: Path | str = CONFIG_PATH, system_proxy: SystemProxy | None = None,
                 proxy_factory=FilterProxy) -> None:
        self.config_path = Path(config_path)
        self.system_proxy = system_proxy or SystemProxy()
        self._proxy_factory = proxy_factory
        self.proxy: FilterProxy | None = None
        self.sites: list[str] = []
        self.want_enabled = False
        self._allowed: frozenset[str] = frozenset()
        self.load()

    # persistence
    def load(self) -> None:
        try:
            data = json.loads(self.config_path.read_text(encoding="utf-8-sig"))
            sites = [d for d in (normalize_domain(str(x)) for x in data.get("allowed_sites", [])) if d]
            self.sites, self.want_enabled = sorted(set(sites)), data.get("enabled") is True
        except (OSError, ValueError, AttributeError):
            self.sites, self.want_enabled = [], False
        self._allowed = frozenset(self.sites)

    def save(self) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.config_path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"enabled": self.want_enabled, "allowed_sites": self.sites}, indent=2),
                       encoding="utf-8")
        os.replace(tmp, self.config_path)

    # list management
    def add_site(self, text: str) -> tuple[bool, str]:
        domain = normalize_domain(text)
        if domain is None:
            return False, "That doesn't look like a website name. Try something like example.com."
        if domain in self.sites:
            return False, f"{domain} is already on the list."
        self.sites = sorted([*self.sites, domain])
        self._allowed = frozenset(self.sites)
        self.save()
        return True, f"Added {domain} (and its subdomains)."

    def remove_site(self, domain: str) -> None:
        self.sites = [s for s in self.sites if s != domain]
        self._allowed = frozenset(self.sites)
        self.save()

    def is_allowed(self, host: str) -> bool:
        return host_allowed(host, self._allowed)

    # enforcement
    @property
    def running(self) -> bool:
        return self.proxy is not None and self.proxy.running

    def enable(self) -> str:
        if not self.sites:
            raise ValueError("Add at least one allowed website first, otherwise every website would be blocked.")
        if not self.running:
            self.proxy = self._proxy_factory(self.is_allowed)
            self.proxy.start()
        if self.system_proxy.supported:
            try:
                self.system_proxy.enable(self.proxy.port)
            except Exception:
                self.disable(persist=False)
                raise
            note = "Websites not on the list are now blocked in browsers that use the Windows proxy settings."
        else:
            note = (f"Filter running on 127.0.0.1:{self.proxy.port}. Automatic setup is Windows-only; "
                    "set your browser's proxy to that address to test it.")
        self.want_enabled = True
        self.save()
        return note

    def disable(self, persist: bool = True) -> None:
        try:
            self.system_proxy.restore()
        finally:
            if self.proxy is not None:
                self.proxy.stop()
                self.proxy = None
            if persist:
                self.want_enabled = False
                self.save()

    def shutdown(self) -> None:
        """App is closing: put the user's internet settings back (the saved choice is kept)."""
        want = self.want_enabled
        self.disable(persist=False)
        self.want_enabled = want

    def recover(self) -> bool:
        """After a crash the proxy setting could still point at a dead port: restore it."""
        if not self.running and self.system_proxy.has_backup():
            try:
                return self.system_proxy.restore()
            except Exception:
                logger.exception("Could not restore the original internet proxy settings")
        return False

    def tamper_check(self) -> bool:
        """If something changed our proxy setting, put it back. Returns True when it had been changed."""
        if self.running and self.system_proxy.supported and not self.system_proxy.is_applied(self.proxy.port):
            self.system_proxy.reapply(self.proxy.port)
            return True
        return False
