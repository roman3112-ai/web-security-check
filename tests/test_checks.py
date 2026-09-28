"""Тесты отдельных проверок и агрегированного прогона."""

from __future__ import annotations

from websec.checks import (
    check_cookie_flags,
    check_security_headers,
    check_server_banner,
    run_checks,
)
from websec.report import has_high_failures, summarize


def test_insecure_target_fails_and_has_high_findings(insecure_response):
    findings = run_checks(insecure_response)
    assert has_high_failures(findings)
    passed, total = summarize(findings)
    assert passed < total


def test_secure_target_passes_all_header_checks(secure_response):
    findings = run_checks(secure_response)
    header_findings = [f for f in findings if f.check.startswith("header:")]
    assert header_findings
    assert all(f.passed for f in header_findings)
    assert not has_high_failures(findings)


def test_insecure_cookie_is_flagged(insecure_response):
    findings = run_checks(insecure_response)
    cookies = [f for f in findings if f.check.startswith("cookie:")]
    assert cookies
    assert all(not f.passed for f in cookies)


def test_secure_cookie_passes(secure_response):
    findings = run_checks(secure_response)
    cookies = [f for f in findings if f.check.startswith("cookie:")]
    assert cookies
    assert all(f.passed for f in cookies)


def test_missing_headers_reported_missing():
    findings = check_security_headers({})
    assert all(not f.passed for f in findings)
    assert {f.check for f in findings} == {
        "header:content-security-policy",
        "header:strict-transport-security",
        "header:x-content-type-options",
        "header:x-frame-options",
        "header:referrer-policy",
        "header:permissions-policy",
    }


def test_server_banner_version_leak_detected():
    leak = check_server_banner({"Server": "nginx/1.25.3"})[0]
    assert leak.passed is False

    clean = check_server_banner({"Server": "nginx"})[0]
    assert clean.passed is True


def test_cookie_flag_parsing():
    good = check_cookie_flags(["sid=1; Secure; HttpOnly; SameSite=Strict"])[0]
    assert good.passed is True

    bad = check_cookie_flags(["sid=1; HttpOnly"])[0]
    assert bad.passed is False
