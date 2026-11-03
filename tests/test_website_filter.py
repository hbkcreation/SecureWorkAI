import json
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from app.security import website_filter as wf


class DomainTests(unittest.TestCase):
    def test_normalize(self):
        n = wf.normalize_domain
        self.assertEqual(n("https://WWW.Example.com:443/a/b?c=1"), "www.example.com")
        self.assertEqual(n("example.com/path"), "example.com")
        self.assertEqual(n("*.example.co.uk"), "example.co.uk")
        self.assertEqual(n("user:pw@example.com"), "example.com")
        self.assertEqual(n("bücher.de"), "xn--bcher-kva.de")
        for bad in ("", "localhost", "no spaces.com", "1.2.3.4", "a..com", "-bad-.com", "x" * 70 + ".com",
                    "javascript:alert(1)", "exa\nmple.com", "http://", "[::1]"):
            self.assertIsNone(n(bad), bad)

    def test_subdomain_matching_is_exact_on_label_boundaries(self):
        allowed = frozenset({"example.com"})
        for host in ("example.com", "www.example.com", "a.b.example.com", "EXAMPLE.com.", ):
            self.assertTrue(wf.host_allowed(host, allowed), host)
        for host in ("notexample.com", "example.com.evil.net", "evilexample.com", "com", "", "example.org"):
            self.assertFalse(wf.host_allowed(host, allowed), host)


class _Origin(BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"origin-ok host={self.headers.get('Host')} path={self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class ProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.origin = HTTPServer(("127.0.0.1", 0), _Origin)
        cls.origin_port = cls.origin.server_address[1]
        threading.Thread(target=cls.origin.serve_forever, daemon=True).start()
        cls.echo = socket.socket()
        cls.echo.bind(("127.0.0.1", 0))
        cls.echo.listen(5)
        cls.echo_port = cls.echo.getsockname()[1]

        def echo_loop():
            while True:
                try:
                    c, _ = cls.echo.accept()
                except OSError:
                    return
                data = c.recv(1024)
                c.sendall(b"ECHO:" + data)
                c.close()
        threading.Thread(target=echo_loop, daemon=True).start()
        allowed = frozenset({"localhost", "allowed.test"})
        # loopback + test ports enabled ONLY for this test proxy
        cls.proxy = wf.FilterProxy(lambda h: wf.host_allowed(h, allowed), allow_loopback=True,
                                   allowed_ports=(cls.origin_port, cls.echo_port))
        cls.port = cls.proxy.start()
        # a second proxy with the secure defaults, to prove SSRF protection
        cls.strict = wf.FilterProxy(lambda h: True)
        cls.strict_port = cls.strict.start()

    @classmethod
    def tearDownClass(cls):
        cls.proxy.stop()
        cls.strict.stop()
        cls.origin.shutdown()
        cls.echo.close()

    def raw(self, port, payload: bytes) -> bytes:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(payload)
        out = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                out += chunk
        except socket.timeout:
            pass
        s.close()
        return out

    def test_allowed_http_is_forwarded_with_clean_request(self):
        req = (f"GET http://localhost:{self.origin_port}/hello?x=1 HTTP/1.1\r\nHost: localhost:{self.origin_port}\r\n"
               "Proxy-Connection: keep-alive\r\n\r\n").encode()
        out = self.raw(self.port, req)
        self.assertIn(b"200 OK", out)
        self.assertIn(b"origin-ok", out)
        self.assertIn(b"path=/hello?x=1", out)  # absolute URL rewritten to a normal path

    def test_blocked_http_gets_block_page_and_never_reaches_origin(self):
        out = self.raw(self.port, b"GET http://evil.example/ HTTP/1.1\r\nHost: evil.example\r\n\r\n")
        self.assertIn(b"403 Forbidden", out)
        self.assertIn(b"This website is blocked", out)
        self.assertIn(b"evil.example", out)
        self.assertTrue(any(h == "evil.example" for _t, h in self.proxy.blocked))

    def test_block_page_escapes_the_host(self):
        out = self.raw(self.port, b"GET http://x<script>.test/ HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertNotIn(b"<script>", out)

    def test_connect_blocked_vs_allowed_tunnel(self):
        out = self.raw(self.port, b"CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n")
        self.assertIn(b"403 Forbidden", out)
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        s.sendall(f"CONNECT localhost:{self.echo_port} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
        first = s.recv(4096)
        self.assertIn(b"200 Connection Established", first)
        s.sendall(b"ping")
        data = b""
        while b"ECHO:ping" not in data:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        s.close()
        self.assertIn(b"ECHO:ping", data)

    def test_disallowed_port_blocked_even_for_allowed_host(self):
        out = self.raw(self.port, b"CONNECT localhost:22 HTTP/1.1\r\n\r\n")
        self.assertIn(b"403", out)

    def test_loopback_targets_refused_by_default(self):
        out = self.raw(self.strict_port, b"CONNECT localhost:443 HTTP/1.1\r\n\r\n")
        self.assertIn(b"502", out)  # allowed by name, but resolves to loopback: refused
        out = self.raw(self.strict_port, b"CONNECT 169.254.169.254:80 HTTP/1.1\r\n\r\n")
        self.assertIn(b"502", out)

    def test_garbage_and_oversized_requests_do_not_crash(self):
        self.assertIn(b"400", self.raw(self.port, b"NONSENSE\r\n\r\n"))
        self.raw(self.port, b"A" * 70000)
        self.raw(self.port, b"GET / HTTP/1.1\r\n\r\n")  # origin-form, not a proxy request
        out = self.raw(self.port, b"GET http://evil.example/ HTTP/1.1\r\n\r\n")  # still alive afterwards
        self.assertIn(b"403", out)


class FakeRegistry:
    def __init__(self, initial):
        self.values = dict(initial)
        self.notified = 0

    def get(self, name):
        v = self.values.get(name)
        return list(v) if v is not None else None

    def set(self, name, vtype, value):
        self.values[name] = [vtype, value]

    def delete(self, name):
        self.values.pop(name, None)

    def notify(self):
        self.notified += 1


class SystemProxyTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.original = {"ProxyEnable": [4, 0], "ProxyServer": [1, "corp-proxy:8080"], "AutoConfigURL": [1, "http://pac/x.pac"]}
        self.reg = FakeRegistry(self.original)
        self.sp = wf.SystemProxy(registry=self.reg, backup_path=self.dir / "b.json")

    def test_enable_then_restore_returns_exact_originals(self):
        self.sp.enable(9999)
        self.assertEqual(self.reg.values["ProxyServer"], [1, "127.0.0.1:9999"])
        self.assertEqual(self.reg.values["ProxyEnable"], [4, 1])
        self.assertNotIn("AutoConfigURL", self.reg.values)  # PAC would bypass us
        self.assertTrue(self.sp.is_applied(9999))
        self.assertTrue(self.sp.restore())
        self.assertEqual(self.reg.values["ProxyEnable"], [4, 0])
        self.assertEqual(self.reg.values["ProxyServer"], [1, "corp-proxy:8080"])
        self.assertEqual(self.reg.values["AutoConfigURL"], [1, "http://pac/x.pac"])
        for name in ("ProxyOverride", "AutoDetect"):  # did not exist originally: removed again
            self.assertNotIn(name, self.reg.values)
        self.assertFalse(self.sp.has_backup())

    def test_second_enable_never_overwrites_the_original_backup(self):
        self.sp.enable(1111)
        self.sp.enable(2222)
        self.sp.restore()
        self.assertEqual(self.reg.values["ProxyServer"], [1, "corp-proxy:8080"])

    def test_tamper_is_detected(self):
        self.sp.enable(3333)
        self.reg.set("ProxyEnable", 4, 0)
        self.assertFalse(self.sp.is_applied(3333))

    def test_restore_without_backup_is_a_noop(self):
        self.assertFalse(self.sp.restore())


class ControllerTests(unittest.TestCase):
    def make(self):
        d = Path(tempfile.mkdtemp())
        reg = FakeRegistry({"ProxyEnable": [4, 0]})
        sp = wf.SystemProxy(registry=reg, backup_path=d / "b.json")
        return wf.WebsiteFilterController(d / "w.json", sp), reg, d

    def test_add_remove_persist(self):
        c, _reg, d = self.make()
        ok, msg = c.add_site("https://Docs.Example.com/page")
        self.assertTrue(ok, msg)
        self.assertFalse(c.add_site("docs.example.com")[0])
        self.assertFalse(c.add_site("not a site")[0])
        self.assertTrue(c.is_allowed("x.docs.example.com"))
        self.assertFalse(c.is_allowed("example.com"))
        c2 = wf.WebsiteFilterController(d / "w.json", c.system_proxy)
        self.assertEqual(c2.sites, ["docs.example.com"])
        c2.remove_site("docs.example.com")
        self.assertEqual(c2.sites, [])

    def test_cannot_enable_with_empty_list(self):
        c, _reg, _d = self.make()
        with self.assertRaises(ValueError):
            c.enable()

    def test_enable_disable_and_shutdown_restore_settings(self):
        c, reg, _d = self.make()
        c.add_site("example.com")
        c.enable()
        self.assertTrue(c.running)
        self.assertEqual(reg.values["ProxyEnable"], [4, 1])
        self.assertTrue(c.want_enabled)
        c.shutdown()
        self.assertFalse(c.running)
        self.assertEqual(reg.values["ProxyEnable"], [4, 0])
        self.assertTrue(c.want_enabled)  # choice remembered for next start
        c.enable()
        c.disable()
        self.assertFalse(c.want_enabled)

    def test_crash_recovery_restores_dead_proxy_setting(self):
        c, reg, d = self.make()
        c.add_site("example.com")
        c.enable()
        c.proxy.stop()
        c.proxy = None  # simulate a crash: setting still points at a dead port
        self.assertEqual(reg.values["ProxyEnable"], [4, 1])
        fresh = wf.WebsiteFilterController(d / "w.json", c.system_proxy)
        self.assertTrue(fresh.recover())
        self.assertEqual(reg.values["ProxyEnable"], [4, 0])

    def test_tamper_check_reapplies(self):
        c, reg, _d = self.make()
        c.add_site("example.com")
        c.enable()
        reg.set("ProxyEnable", 4, 0)
        self.assertTrue(c.tamper_check())
        self.assertEqual(reg.values["ProxyEnable"], [4, 1])
        self.assertFalse(c.tamper_check())
        c.disable()

    def test_corrupt_config_fails_safe(self):
        c, _reg, d = self.make()
        (d / "w.json").write_text("{not json")
        c.load()
        self.assertEqual((c.sites, c.want_enabled), ([], False))


if __name__ == "__main__":
    unittest.main()
