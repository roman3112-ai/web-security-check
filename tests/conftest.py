"""Фикстуры, поднимающие демо-приложения через тестовый клиент Starlette."""

from __future__ import annotations

from collections.abc import Iterator

import httpx
import pytest
from starlette.testclient import TestClient

from tests.demo_target import insecure_app, secure_app


@pytest.fixture()
def insecure_response() -> Iterator[httpx.Response]:
    with TestClient(insecure_app()) as client:
        yield client.get("/")


@pytest.fixture()
def secure_response() -> Iterator[httpx.Response]:
    with TestClient(secure_app()) as client:
        yield client.get("/")
