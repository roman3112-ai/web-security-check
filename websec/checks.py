"""Пассивные проверки одного HTTP-ответа.

Каждая проверка только читает: смотрит заголовки и куки обычного GET-запроса.
Ничего здесь не шлёт атакующий трафик, не перебирает пароли и не сканирует
уязвимости. Вопрос один — "настроен ли сайт защищённо?", и именно это можно
безопасно гонять в CI против своего же сайта.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from .models import Finding, Severity

# Заголовки ответа, которые должны присутствовать, и severity их отсутствия.
SECURITY_HEADERS: dict[str, Severity] = {
    "content-security-policy": Severity.HIGH,
    "strict-transport-security": Severity.HIGH,
    "x-content-type-options": Severity.MEDIUM,
    "x-frame-options": Severity.MEDIUM,
    "referrer-policy": Severity.LOW,
    "permissions-policy": Severity.LOW,
}


def _lower_keys(headers: Mapping[str, str]) -> dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


def check_security_headers(headers: Mapping[str, str]) -> list[Finding]:
    present = _lower_keys(headers)
    findings: list[Finding] = []
    for name, severity in SECURITY_HEADERS.items():
        ok = name in present
        findings.append(
            Finding(
                check=f"header:{name}",
                passed=ok,
                severity=severity,
                detail="есть" if ok else "отсутствует",
            )
        )
    return findings


def check_server_banner(headers: Mapping[str, str]) -> list[Finding]:
    """Отметить Server-заголовок, который светит номер версии."""
    server = _lower_keys(headers).get("server", "")
    leaks_version = any(ch.isdigit() for ch in server)
    return [
        Finding(
            check="server-banner",
            passed=not leaks_version,
            severity=Severity.LOW,
            detail=f"Server: {server or '(нет)'}",
        )
    ]


def check_cookie_flags(set_cookie_headers: Iterable[str]) -> list[Finding]:
    """Проверить, что у каждого Set-Cookie есть Secure, HttpOnly и SameSite."""
    findings: list[Finding] = []
    for raw in set_cookie_headers:
        low = raw.lower()
        name = raw.split("=", 1)[0].strip()
        secure = "secure" in low
        httponly = "httponly" in low
        samesite = "samesite" in low
        findings.append(
            Finding(
                check=f"cookie:{name}",
                passed=secure and httponly and samesite,
                severity=Severity.MEDIUM,
                detail=(
                    f"secure={secure} httponly={httponly} samesite={samesite}"
                ),
            )
        )
    return findings


def run_checks(response) -> list[Finding]:
    """Прогнать все проверки над объектом вида ``httpx.Response``."""
    findings: list[Finding] = []
    findings += check_security_headers(response.headers)
    findings += check_server_banner(response.headers)

    get_list = getattr(response.headers, "get_list", None)
    set_cookies = list(get_list("set-cookie")) if get_list else []
    findings += check_cookie_flags(set_cookies)
    return findings
