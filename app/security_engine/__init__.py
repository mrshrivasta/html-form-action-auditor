"""
Security Engine — HTML Form Action Auditor
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Performs a REAL, live HTTP GET request to a target URL you provide,
parses the ACTUAL returned HTML with BeautifulSoup, and extracts every
real <form> element's action, method, and input fields. Nothing is
simulated: if the target is unreachable, that is reported as a real
error, not silently faked.

SAFETY: This engine only ever issues a single, standard, non-destructive
GET request per scan. It never submits any form, never sends form data,
and never follows form actions — it only reads and parses the HTML that
was already returned by the single GET request.
"""
import re
import time
from urllib.parse import urlsplit, urljoin

import requests
from bs4 import BeautifulSoup

DEFAULT_TIMEOUT = 10
DEFAULT_USER_AGENT = "HtmlFormActionAuditor/1.0 (+https://github.com/mrshrivasta; educational security tool)"

_CSRF_NAME_RE = re.compile(r"csrf|xsrf|authenticity_token|__requestverificationtoken", re.IGNORECASE)


def _extract_forms(html, page_url):
    forms = []
    soup = BeautifulSoup(html or "", "html.parser")
    page_origin = "{0.scheme}://{0.netloc}".format(urlsplit(page_url))

    for form in soup.find_all("form"):
        raw_action = form.get("action", "") or ""
        method = (form.get("method") or "GET").strip().upper()
        resolved_action = urljoin(page_url, raw_action) if raw_action else page_url
        action_parts = urlsplit(resolved_action)
        action_origin = f"{action_parts.scheme}://{action_parts.netloc}" if action_parts.netloc else page_origin

        inputs = form.find_all("input")
        has_password = any((inp.get("type") or "").strip().lower() == "password" for inp in inputs)
        has_csrf_hint = any(
            (inp.get("type") or "").strip().lower() == "hidden" and _CSRF_NAME_RE.search(inp.get("name") or "")
            for inp in inputs
        )

        forms.append({
            "raw_action": raw_action,
            "resolved_action": resolved_action,
            "scheme": action_parts.scheme,
            "method": method,
            "same_origin": (action_origin == page_origin),
            "has_password": has_password,
            "has_csrf_hint": has_csrf_hint,
        })
    return forms


class ScanEngine:
    def __init__(self, target_url, timeout=DEFAULT_TIMEOUT, verify_tls=True):
        self.target_url = target_url
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.errors_count = 0

    def _fetch(self):
        headers = {"User-Agent": DEFAULT_USER_AGENT}
        resp = requests.get(
            self.target_url, headers=headers, timeout=self.timeout,
            verify=self.verify_tls, allow_redirects=True,
        )
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        html = resp.text if "html" in headers_lower.get("content-type", "").lower() or not headers_lower.get("content-type") else resp.text
        forms = _extract_forms(html, resp.url)
        return {
            "url": resp.url,
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "headers_lower": headers_lower,
            "forms": forms,
            "elapsed_ms": round(resp.elapsed.total_seconds() * 1000, 1),
        }

    def run(self):
        from app.detection_rules import ALL_RULES
        start = time.time()
        findings = []
        response = None
        try:
            response = self._fetch()
            for rule in ALL_RULES:
                try:
                    result = rule(response)
                except Exception:
                    self.errors_count += 1
                    continue
                if not result:
                    continue
                result_list = result if isinstance(result, list) else [result]
                for item in result_list:
                    item["file_path"] = response["url"]
                    item["permissions_octal"] = str(response["status_code"])
                    item["owner_uid"] = None
                    item["owner_gid"] = None
                    findings.append(item)
        except requests.exceptions.RequestException as exc:
            self.errors_count += 1
            findings.append({
                "rule_id": "FAA-000",
                "rule_name": "Target Unreachable",
                "severity": "low",
                "description": f"Could not reach {self.target_url}: {exc}",
                "file_path": self.target_url,
                "permissions_octal": "-",
                "owner_uid": None,
                "owner_gid": None,
            })

        elapsed = time.time() - start
        return {
            "files_scanned": 1 if response else 0,
            "dirs_scanned": len(response["forms"]) if response else 0,
            "errors_count": self.errors_count,
            "response": response,
            "findings": findings,
            "elapsed_seconds": round(elapsed, 3),
        }
