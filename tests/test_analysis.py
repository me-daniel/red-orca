from vsw.analysis import analyze_browser, analyze_http
from vsw.domain import FindingState, Severity
from vsw.evidence import EvidenceRecord

SECURE_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=()",
    "Server": "lab",
    "Content-Type": "text/html; charset=utf-8",
}


def record(**overrides) -> EvidenceRecord:
    data = {
        "id": "E-001",
        "kind": "http",
        "url": "http://127.0.0.1:8787/clean/",
        "method": "GET",
        "status": 200,
        "response_headers": dict(SECURE_HEADERS),
        "body": '<html><body><a href="/clean/about">about</a></body></html>',
        "notes": {
            "content_type": "text/html; charset=utf-8",
            "set_cookie": ["sid=<redacted>; Path=/clean; HttpOnly; Secure; SameSite=Lax"],
        },
    }
    data.update(overrides)
    return EvidenceRecord(**data)


def test_clean_control_produces_no_findings():
    assert analyze_http(record()) == []


def test_missing_csp_is_observed_not_validated():
    headers = dict(SECURE_HEADERS)
    headers.pop("Content-Security-Policy")
    findings = analyze_http(record(response_headers=headers))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.check_id == "headers.content-security-policy"
    assert finding.state is FindingState.OBSERVED
    assert finding.severity is Severity.MEDIUM
    assert finding.evidence_ids == ["E-001"]


def test_frame_ancestors_satisfies_frame_options():
    headers = dict(SECURE_HEADERS)
    headers.pop("X-Frame-Options")
    headers["Content-Security-Policy"] = "frame-ancestors 'none'"
    assert analyze_http(record(response_headers=headers)) == []


def test_insecure_cookie_flags_are_reported():
    findings = analyze_http(
        record(
            notes={"content_type": "text/html", "set_cookie": ["session=<redacted>; Path=/vuln"]}
        )
    )
    cookie = [item for item in findings if item.check_id.startswith("cookies.flags")]
    assert len(cookie) == 1
    assert "HttpOnly" in cookie[0].title
    assert cookie[0].severity is Severity.MEDIUM


def test_server_version_is_informational():
    headers = dict(SECURE_HEADERS)
    headers["Server"] = "lab/1.0"
    findings = analyze_http(record(response_headers=headers))
    assert [item.check_id for item in findings] == ["headers.server_version"]
    assert findings[0].severity is Severity.INFO


def test_unescaped_markup_reflection_is_validated():
    url = "http://127.0.0.1:8787/vuln/echo?q=%3Cb%3Evsw%3C%2Fb%3E"
    body = '<html><body><div id="out"><b>vsw</b></div></body></html>'
    findings = analyze_http(
        record(url=url, body=body, response_headers={**SECURE_HEADERS, "Content-Type": "text/html"})
    )
    reflection = [item for item in findings if item.check_id == "reflection.q"]
    assert len(reflection) == 1
    assert reflection[0].state is FindingState.VALIDATED
    assert "not attempted" in reflection[0].impact


def test_plain_text_reflection_is_only_observed():
    """An alphanumeric marker looks identical encoded or not, so it cannot validate."""
    url = "http://127.0.0.1:8787/vuln/echo?q=vsw-probe-1"
    body = '<html><body><div id="out">vsw-probe-1</div></body></html>'
    findings = analyze_http(
        record(url=url, body=body, response_headers={**SECURE_HEADERS, "Content-Type": "text/html"})
    )
    reflection = [item for item in findings if item.check_id == "reflection.q"]
    assert len(reflection) == 1
    assert reflection[0].state is FindingState.OBSERVED
    assert reflection[0].severity is Severity.INFO


def test_escaped_reflection_is_not_a_finding():
    url = "http://127.0.0.1:8787/vuln/echo?q=%3Cscript%3E"
    body = '<html><body><div id="out">&lt;script&gt;</div></body></html>'
    findings = analyze_http(
        record(url=url, body=body, response_headers={**SECURE_HEADERS, "Content-Type": "text/html"})
    )
    assert [item for item in findings if item.check_id.startswith("reflection")] == []


def test_redirect_responses_are_not_scored():
    findings = analyze_http(record(status=302, response_headers={"Server": "lab/1.0"}))
    assert findings == []


def test_external_subresource_is_recorded_as_a_data_flow():
    body = '<html><head><script src="https://cdn.example.invalid/x.js"></script></head></html>'
    findings = analyze_http(record(body=body))
    external = [item for item in findings if item.check_id == "browser.external_subresource"]
    assert len(external) == 1
    assert external[0].severity is Severity.INFO
    assert external[0].state is FindingState.OBSERVED


def test_browser_blocked_third_party_request_is_reported():
    browser_record = EvidenceRecord(
        id="E-002",
        kind="browser",
        url="http://127.0.0.1:8787/vuln/third-party",
        method="GET",
        body="<html></html>",
        notes={
            "requests": [
                {
                    "method": "GET",
                    "url": "https://cdn.example.invalid/x.js",
                    "origin": "https://cdn.example.invalid",
                    "blocked": True,
                    "reason": "origin not approved",
                }
            ],
            "cookies": [
                {
                    "name": "session",
                    "value": "<redacted>",
                    "httpOnly": False,
                    "secure": False,
                    "sameSite": "None",
                }
            ],
            "forms": [],
        },
    )
    findings = analyze_browser(browser_record)
    check_ids = {item.check_id for item in findings}
    assert "browser.third_party_request" in check_ids
    assert "cookies.flags.session" in check_ids
    third_party = next(item for item in findings if item.check_id == "browser.third_party_request")
    assert "blocked" in third_party.summary


def test_browser_clean_context_produces_no_findings():
    clean = EvidenceRecord(
        id="E-003",
        kind="browser",
        url="http://127.0.0.1:8787/clean/",
        method="GET",
        body="<html></html>",
        notes={
            "requests": [
                {
                    "method": "GET",
                    "url": "http://127.0.0.1:8787/clean/",
                    "origin": "http://127.0.0.1:8787",
                    "blocked": False,
                }
            ],
            "cookies": [
                {
                    "name": "sid",
                    "value": "<redacted>",
                    "httpOnly": True,
                    "secure": True,
                    "sameSite": "Lax",
                }
            ],
            "forms": [],
        },
    )
    assert analyze_browser(clean) == []
