"""Два крошечных FastAPI-приложения, служащих целью для тестов.

``insecure_app`` не шлёт security-заголовки и ставит куку без флагов.
``secure_app`` добавляет рекомендованные заголовки и полностью защищённую куку.

Тесты прогоняют чекер против обоих, в процессе, через ASGI-транспорт httpx —
без сети, без внешнего сайта.
"""

from __future__ import annotations

from fastapi import FastAPI, Response


def insecure_app() -> FastAPI:
    app = FastAPI()

    @app.get("/")
    def root(response: Response) -> dict:
        response.set_cookie("session", "abc123")  # без флагов
        return {"ok": True}

    return app


def secure_app() -> FastAPI:
    app = FastAPI()

    @app.middleware("http")
    async def add_security_headers(request, call_next):
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = "default-src 'self'"
        resp.headers["Strict-Transport-Security"] = (
            "max-age=63072000; includeSubDomains"
        )
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "geolocation=()"
        return resp

    @app.get("/")
    def root(response: Response) -> dict:
        response.set_cookie(
            "session", "abc123", secure=True, httponly=True, samesite="strict"
        )
        return {"ok": True}

    return app
