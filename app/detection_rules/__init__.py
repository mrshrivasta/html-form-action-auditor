"""
Detection Rules — HTML Form Action Auditor
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Each rule inspects the REAL <form> elements parsed from the actual HTML
returned by a single, real HTTP GET request to a target URL you provide
(see app/security_engine). No forms are ever submitted and no sample HTML
is ever generated — every finding is derived from the real page markup.

Each rule below may return None, a single finding dict, or a LIST of
finding dicts (since a single page can legitimately contain more than one
form with the same issue).
"""

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"


def _forms(response):
    return response.get("forms") or []


def _describe(form):
    return form.get("resolved_action") or "(same page)"


def rule_cross_origin_form_action(response):
    """FAA-001: A form's action attribute points to a different origin
    (scheme+host) than the page it's on. Data entered into this form is
    sent somewhere other than the site the user believes they're
    interacting with — a real phishing/data-exfiltration risk pattern,
    especially if unexpected."""
    findings = []
    for form in _forms(response):
        if not form["same_origin"] and form["scheme"] in ("http", "https"):
            findings.append({
                "rule_id": "FAA-001",
                "rule_name": "Form Action Points to a Different Origin",
                "severity": SEVERITY_MEDIUM,
                "description": (
                    f"A form on {response['url']} submits to a different "
                    f"origin: {_describe(form)}. Verify this cross-origin "
                    f"submission is intentional and not a sign of injected/"
                    f"tampered markup."
                ),
            })
    return findings


def rule_password_form_over_http(response):
    """FAA-002: A form containing a password input submits (action
    resolves) to a plain http:// URL. Credentials submitted this way
    travel in cleartext over the network and can be intercepted."""
    findings = []
    for form in _forms(response):
        if form["has_password"] and form["scheme"] == "http":
            findings.append({
                "rule_id": "FAA-002",
                "rule_name": "Password Form Submits Over Plain HTTP",
                "severity": SEVERITY_CRITICAL,
                "description": (
                    f"A form on {response['url']} contains a password "
                    f"field and submits to {_describe(form)} over plain "
                    f"HTTP. Credentials sent this way travel in cleartext "
                    f"and can be intercepted."
                ),
            })
    return findings


def rule_password_form_uses_get(response):
    """FAA-003: A form containing a password input uses method="GET".
    GET-submitted values are appended to the URL, and therefore end up in
    browser history, server access logs, and the Referer header sent to
    any third-party resources on the destination page."""
    findings = []
    for form in _forms(response):
        if form["has_password"] and form["method"] == "GET":
            findings.append({
                "rule_id": "FAA-003",
                "rule_name": "Password Form Uses GET Method",
                "severity": SEVERITY_HIGH,
                "description": (
                    f"A form on {response['url']} contains a password "
                    f"field but uses method=\"GET\". Submitted credentials "
                    f"would appear in the URL, browser history, and server "
                    f"access logs."
                ),
            })
    return findings


def rule_post_form_missing_csrf_hint(response):
    """FAA-004: A state-changing (POST) form has no hidden input field
    whose name resembles a CSRF/anti-forgery token (csrf, xsrf,
    authenticity_token, __RequestVerificationToken, etc.). This is a
    heuristic, not proof of a missing protection (some frameworks protect
    via cookies/headers instead), but it is worth confirming."""
    findings = []
    for form in _forms(response):
        if form["method"] == "POST" and not form["has_csrf_hint"]:
            findings.append({
                "rule_id": "FAA-004",
                "rule_name": "POST Form Missing Apparent CSRF Token Field",
                "severity": SEVERITY_MEDIUM,
                "description": (
                    f"A POST form on {response['url']} (action: "
                    f"{_describe(form)}) has no hidden field whose name "
                    f"resembles a CSRF/anti-forgery token. Confirm CSRF "
                    f"protection is applied via another mechanism "
                    f"(same-site cookies, custom header, etc.) if this is "
                    f"intentional."
                ),
            })
    return findings


def rule_form_action_dangerous_scheme(response):
    """FAA-005: A form's action attribute uses a javascript: or data:
    URI scheme instead of a normal http(s) URL. This is unusual and can
    indicate injected/tampered markup or a form designed to bypass normal
    navigation-based security controls."""
    findings = []
    for form in _forms(response):
        if form["scheme"] in ("javascript", "data"):
            findings.append({
                "rule_id": "FAA-005",
                "rule_name": "Form Action Uses javascript:/data: URI Scheme",
                "severity": SEVERITY_HIGH,
                "description": (
                    f"A form on {response['url']} has action=\"{form['raw_action']}\", "
                    f"using the '{form['scheme']}:' URI scheme instead of a "
                    f"normal URL. This is unusual and can indicate "
                    f"injected/tampered markup."
                ),
            })
    return findings


def rule_form_action_missing(response):
    """FAA-006 (informational): A form has no action attribute at all, so
    it implicitly submits to the current page URL. Not a vulnerability by
    itself, but worth confirming this is intentional, since some
    frameworks generate this by omission rather than by design."""
    findings = []
    for form in _forms(response):
        if not form["raw_action"]:
            findings.append({
                "rule_id": "FAA-006",
                "rule_name": "Form Missing action Attribute (Implicit Self-Submit)",
                "severity": SEVERITY_LOW,
                "description": (
                    f"A form on {response['url']} has no action attribute "
                    f"and will implicitly submit to the current page URL. "
                    f"Confirm this is intentional."
                ),
            })
    return findings


ALL_RULES = [
    rule_cross_origin_form_action,
    rule_password_form_over_http,
    rule_password_form_uses_get,
    rule_post_form_missing_csrf_hint,
    rule_form_action_dangerous_scheme,
    rule_form_action_missing,
]
