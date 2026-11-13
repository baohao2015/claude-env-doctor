import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import claude_env as doctor


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.project = self.root / "project"
        self.home.mkdir()
        self.project.mkdir()
        self.policy = self.root / "managed-settings.json"

    def write(self, path, env):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"env": env}), encoding="utf-8")

    def load(self, env=None):
        checks = []
        result = doctor.read_config(self.project, env or {}, self.home, checks, self.policy)
        return (*result, checks)

    def test_project_proxy_is_a_candidate(self):
        self.write(self.project / ".claude/settings.local.json", {"HTTPS_PROXY": "http://localhost:8181"})
        env, conflicts, _, checks = self.load()
        self.assertFalse(conflicts)
        proxy, known = doctor.choose_proxy(env, conflicts, checks)
        self.assertTrue(known)
        self.assertEqual(proxy, "http://localhost:8181")
        self.assertFalse(any(check["status"] == "fail" for check in checks))

    def test_different_shell_and_file_values_never_silently_fall_back(self):
        self.write(self.home / ".claude/settings.json", {"HTTPS_PROXY": "http://localhost:8181"})
        env, conflicts, _, checks = self.load({"HTTPS_PROXY": "http://localhost:8282"})
        proxy, known = doctor.choose_proxy(env, conflicts, checks)
        self.assertFalse(known)
        self.assertIsNone(proxy)
        with patch.object(doctor, "probe") as probe:
            doctor.inspect_network(env, conflicts, proxy, known, 1, checks)
        probe.assert_not_called()

    def test_identical_candidates_are_not_conflicts(self):
        self.write(self.policy, {"HTTPS_PROXY": "http://localhost:8181"})
        env, conflicts, _, _ = self.load({"HTTPS_PROXY": "http://localhost:8181"})
        self.assertEqual(env["HTTPS_PROXY"], "http://localhost:8181")
        self.assertFalse(conflicts)

    def test_respects_claude_config_dir(self):
        custom = self.root / "custom"
        self.write(custom / "settings.json", {"ANTHROPIC_BASE_URL": "https://example.com"})
        env, _, _, _ = self.load({"CLAUDE_CONFIG_DIR": str(custom)})
        self.assertEqual(env["ANTHROPIC_BASE_URL"], "https://example.com")

    def test_invalid_json_does_not_echo_secrets(self):
        path = self.project / ".claude/settings.json"
        path.parent.mkdir()
        path.write_text('{"secret":"never-print-me", invalid')
        _, _, _, checks = self.load()
        self.assertEqual(checks[0]["status"], "fail")
        self.assertNotIn("never-print-me", json.dumps(checks))

    def test_null_env_is_invalid(self):
        path = self.project / ".claude/settings.json"
        path.parent.mkdir()
        path.write_text('{"env": null}')
        self.assertEqual(self.load()[-1][0]["status"], "fail")

    def test_invalid_env_is_not_partially_merged(self):
        self.write(self.home / ".claude/settings.json", {"HTTPS_PROXY": "http://localhost:8080", "TZ": 123})
        env, _, _, checks = self.load()
        self.assertNotIn("HTTPS_PROXY", env)
        self.assertEqual(checks[0]["status"], "fail")

    def test_offline_never_calls_probe_or_executes_claude(self):
        self.write(self.home / ".claude/settings.json", {"ANTHROPIC_API_KEY": "private-key-example"})
        with patch.object(doctor, "probe") as probe, patch.object(doctor, "run", return_value=None) as run:
            result = doctor.audit(self.project, offline=True, env={}, home=self.home, policy=self.policy)
        probe.assert_not_called()
        self.assertFalse(any("claude" in call.args[0][0] for call in run.call_args_list))
        self.assertNotIn("private-key-example", json.dumps(result))
        self.assertIn("auth.ANTHROPIC_API_KEY", {c["id"] for c in result["checks"]})

    def test_invalid_config_blocks_all_network_requests(self):
        checks = [dict(id="config.user", status="fail")]
        with patch.object(doctor, "probe") as probe, patch.object(shutil, "which", return_value="curl"):
            doctor.inspect_network({}, set(), "", True, 1, checks)
        probe.assert_not_called()
        self.assertEqual(checks[-1]["status"], "unknown")


class InterpretationTests(unittest.TestCase):
    def test_403_is_not_a_ban_verdict(self):
        status, evidence = doctor.classify(dict(code=0, http=403))
        self.assertEqual(status, "warn")
        self.assertIn("无法据此确定", evidence)

    def test_401_is_transport_evidence_not_account_failure(self):
        status, evidence = doctor.classify(dict(code=0, http=401))
        self.assertEqual(status, "info")
        self.assertIn("未发送", evidence)

    def test_transport_failure_wins_over_partial_http_response(self):
        self.assertEqual(doctor.classify(dict(code=60, http=200))[0], "fail")

    def test_all_proxy_alone_is_not_assumed_to_work(self):
        checks = []
        proxy, known = doctor.choose_proxy({"ALL_PROXY": "socks5://localhost:1080"}, set(), checks)
        self.assertIsNone(proxy)
        self.assertFalse(known)

    def test_ambiguous_bypass_and_empty_proxy_do_not_trigger_network(self):
        cases = [
            {"NO_PROXY": "localhost", "no_proxy": "*"},
            {"NO_PROXY": "*.example.com"},
            {"NO_PROXY": "localhost:8181"},
            {"https_proxy": "", "HTTPS_PROXY": "http://localhost:8181"},
        ]
        for env in cases:
            with self.subTest(env=env):
                checks = []
                proxy, known = doctor.choose_proxy(env, set(), checks)
                self.assertIsNone(proxy)
                self.assertFalse(known)

    def test_ipv6_loopback_bypass_is_supported(self):
        self.assertTrue(doctor.no_proxy_matches("::1", "[::1]"))
        self.assertTrue(doctor.no_proxy_matches("::1", "::1"))

    def test_lowercase_proxy_has_documented_priority(self):
        checks = []
        value, known = doctor.choose_proxy({"HTTPS_PROXY": "http://a:80", "https_proxy": "http://b:81"}, set(), checks)
        self.assertEqual(value, "http://b:81")
        self.assertTrue(known)
        self.assertTrue(any(c["id"] == "proxy.priority" for c in checks))

    def test_socks_and_missing_scheme_are_rejected(self):
        for value in ("socks5://localhost:1080", "localhost:7890", "http://localhost:0"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    doctor.parse_url(value, proxy=True)

    def test_proxy_credentials_and_url_paths_are_hidden(self):
        self.assertEqual(doctor.public_url("https://user:password@proxy.example:8181"), "https://proxy.example:8181")
        self.assertEqual(doctor.public_url("https://example.com/private-token/path"), "https://example.com")
        self.assertEqual(doctor.public_url("https://example.com?key=secret"), "[无效 URL，原值隐藏]")

    def test_no_proxy_has_hostname_boundary_and_supports_spaces(self):
        for host, expected in (("api.anthropic.com", True), ("sub.anthropic.com", True), ("notanthropic.com", False)):
            self.assertEqual(doctor.no_proxy_matches(host, "localhost .anthropic.com"), expected)
        self.assertTrue(doctor.no_proxy_matches("127.0.0.1", "127.0.0.0/8"))
        self.assertTrue(doctor.no_proxy_matches("api.example.com", "*"))

    def test_remote_plain_http_api_is_not_probed(self):
        checks = []
        with patch.object(doctor, "probe") as probe, patch.object(shutil, "which", return_value="curl"):
            doctor.inspect_network({"ANTHROPIC_BASE_URL": "http://example.com"}, set(), "", True, 1, checks)
        probe.assert_not_called()
        self.assertEqual(checks[-1]["status"], "fail")

    def test_ipv6_failure_is_unknown_not_no_leak(self):
        def fake_probe(url, proxy, no_proxy, timeout, **kwargs):
            return dict(code=7 if kwargs.get("ipv6") else 0, http=0 if kwargs.get("ipv6") else 401,
                        trace={}, route="system")
        checks = []
        with patch.object(doctor, "probe", side_effect=fake_probe), patch.object(shutil, "which", return_value="curl"):
            doctor.inspect_network({}, set(), "", True, 1, checks)
        self.assertEqual(next(c for c in checks if c["id"] == "ipv6")["status"], "unknown")

    def test_explicit_proxy_does_not_trigger_a_direct_ipv6_probe(self):
        checks = []
        with patch.object(doctor, "probe", return_value=dict(code=0, http=401, trace={}, route="proxy")) as probe:
            doctor.inspect_network({}, set(), "http://localhost:8181", True, 1, checks)
        self.assertFalse(any(call.kwargs.get("ipv6") for call in probe.call_args_list))

    def test_ipv6_ipv4_echo_is_unknown_and_not_used_for_ipv6_region_comparison(self):
        def fake_probe(url, proxy, no_proxy, timeout, **kwargs):
            country = "SG" if kwargs.get("ipv6") else "US"
            return dict(code=0, http=200, trace={"ip": "203.0.113.7", "country": country}, route="system")
        checks = []
        with patch.object(doctor, "probe", side_effect=fake_probe), patch.object(shutil, "which", return_value="curl"):
            doctor.inspect_network({}, set(), "", True, 1, checks)
        self.assertEqual(next(c for c in checks if c["id"] == "ipv6")["status"], "unknown")
        self.assertNotIn("ipv6.consistency", {c["id"] for c in checks})

    def test_api_uses_get_instead_of_head(self):
        checks = []
        with patch.object(doctor, "probe", return_value=dict(code=0, http=401, trace={}, route="system")) as probe:
            doctor.inspect_network({}, set(), "http://localhost:8181", True, 1, checks)
        api_call = next(call for call in probe.call_args_list if call.args[0].endswith("/v1/models"))
        self.assertEqual(api_call.kwargs["method"], "GET")

    def test_html_escapes_external_text_and_has_no_scripts(self):
        report = dict(generated_at="now", checks=[dict(status="warn", title="<script>alert(1)</script>",
                      evidence='<img src="https://example.com">', action="x & y")], limitations=[])
        page = doctor.render_html(report)
        self.assertNotIn("<script>", page)
        self.assertNotIn("<img ", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("default-src 'none'", page)

    def test_control_characters_do_not_enter_terminal_reports(self):
        checks = []
        doctor.add(checks, "test", "info", "test", "bad\x1b[31m\nvalue")
        self.assertNotIn("\x1b", checks[0]["evidence"])
        self.assertNotIn("\n", checks[0]["evidence"])


@unittest.skipUnless(shutil.which("curl"), "curl is required for transport integration tests")
class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.received = []

        class Handler(BaseHTTPRequestHandler):
            def do_HEAD(self):
                if self.path == "/get-only/v1/models":
                    self.send_response(405)
                    self.end_headers()
                else:
                    self.respond(False)

            def do_GET(self):
                self.respond(True)

            def respond(self, body):
                cls.received.append((self.path, dict(self.headers)))
                status = 401 if self.path.endswith("/models") else 403 if self.path == "/forbidden" else 302 if self.path == "/redirect" else 200
                self.send_response(status)
                self.send_header("Location", "/redirect-target")
                self.end_headers()
                if body:
                    self.wfile.write(b"ip=203.0.113.7\nloc=US\n")

            def log_message(self, *args):
                pass

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_trace_is_validated_and_decoded(self):
        result = doctor.probe(self.url, "", "", 2, trace=True)
        self.assertEqual(result["code"], 0)
        self.assertEqual(result["trace"], {"ip": "203.0.113.7", "country": "US"})

    def test_api_401_and_web_403_are_distinct(self):
        self.assertEqual(doctor.classify(doctor.probe(self.url + "/v1/models", "", "", 2))[0], "info")
        self.assertEqual(doctor.classify(doctor.probe(self.url + "/forbidden", "", "", 2))[0], "warn")

    def test_get_only_api_endpoint_can_be_diagnosed_without_credentials(self):
        target = self.url + "/get-only/v1/models"
        self.assertEqual(doctor.probe(target, "", "", 2)["http"], 405)
        result = doctor.probe(target, "", "", 2, method="GET")
        self.assertEqual(result["http"], 401)
        self.assertEqual(doctor.classify(result)[0], "info")

    def test_redirect_is_not_followed(self):
        self.received.clear()
        result = doctor.probe(self.url + "/redirect", "", "", 2)
        self.assertEqual(result["http"], 302)
        self.assertEqual([path for path, _ in self.received], ["/redirect"])

    def test_invalid_proxy_never_falls_back_to_reachable_target(self):
        self.received.clear()
        result = doctor.probe(self.url, "http://127.0.0.1:1", "", 1)
        self.assertNotEqual(result["code"], 0)
        self.assertEqual(self.received, [])

    def test_no_proxy_is_an_explicit_bypass(self):
        result = doctor.probe(self.url, "http://127.0.0.1:1", "127.0.0.1", 2)
        self.assertEqual(result["http"], 200)
        self.assertEqual(result["route"], "system")

    def test_inherited_auth_and_proxy_do_not_reach_the_request(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "never-send-this", "HTTPS_PROXY": "http://127.0.0.1:1",
                                     "ALL_PROXY": "socks5://127.0.0.1:1", "NO_PROXY": "*"}):
            result = doctor.probe(self.url + "/v1/models", "", "", 2)
        self.assertEqual(result["http"], 401)
        headers = {key.lower(): value for key, value in self.received[-1][1].items()}
        self.assertNotIn("authorization", headers)
        self.assertNotIn("x-api-key", headers)
        self.assertNotIn("cookie", headers)
        self.assertNotIn("never-send-this", json.dumps(headers))

    def test_credentials_are_in_stdin_not_process_arguments_or_report(self):
        original_run = doctor.run
        calls = []

        def inspect(command, **kwargs):
            calls.append((command, kwargs))
            return original_run(command, **kwargs)

        # This local HTTP server also acts as an HTTP proxy for the test.
        proxy = self.url.replace("http://", "http://tester:proxy-secret@")
        with patch.object(doctor, "run", side_effect=inspect):
            result = doctor.probe("http://example.invalid/", proxy, "", 2)
        self.assertEqual(result["http"], 200)
        self.assertNotIn("proxy-secret", json.dumps(calls[0][0]))
        self.assertIn("proxy-secret", calls[0][1]["data"])
        self.assertNotIn("proxy-secret", json.dumps(result))

    @unittest.skipUnless(shutil.which("openssl"), "openssl needed to generate temporary test certificate")
    def test_untrusted_tls_certificate_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            cert, key = Path(temp) / "cert.pem", Path(temp) / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost"],
                           check=True, capture_output=True, timeout=20)
            server = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                result = doctor.probe(f"https://127.0.0.1:{server.server_port}", "", "", 2)
                self.assertEqual(result["code"], 60)
                self.assertEqual(doctor.classify(result)[0], "fail")
            finally:
                server.shutdown()
                server.server_close()
                thread.join()


class CliTests(unittest.TestCase):
    def report(self):
        return dict(version="test", generated_at="now", checks=[], limitations=[],
                    summary={"pass": 0, "fail": 1, "warn": 0, "unknown": 0, "info": 0})

    def test_json_is_parseable_and_failure_has_nonzero_exit(self):
        with patch.object(doctor, "audit", return_value=self.report()), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(doctor.main(["--offline", "--json"]), 1)
        self.assertEqual(json.loads(output.getvalue())["summary"]["fail"], 1)

    def test_html_export_does_not_overwrite_files(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "report.html"
            target.write_text("keep-me")
            with patch.object(doctor, "audit", return_value=self.report()), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    doctor.main(["--offline", "--html", str(target)])
            self.assertEqual(target.read_text(), "keep-me")


if __name__ == "__main__":
    unittest.main()
