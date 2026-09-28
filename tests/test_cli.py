"""Сквозной (end-to-end) тест CLI против локально поднятого демо-таргета."""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager

import uvicorn

from tests.demo_target import insecure_app, secure_app
from websec.cli import main


@contextmanager
def serve(app, port):
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        # Ждём, пока сервер поднимется.
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.05)
        yield f"http://127.0.0.1:{port}/"
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def test_cli_fails_on_high_for_insecure_target(capsys):
    with serve(insecure_app(), 8111) as url:
        code = main([url, "--fail-on-high"])
    out = capsys.readouterr().out
    assert code == 1
    assert "ОШИБКА" in out


def test_cli_passes_for_secure_target(capsys):
    with serve(secure_app(), 8112) as url:
        code = main([url, "--fail-on-high"])
    out = capsys.readouterr().out
    assert code == 0
    assert "Итог:" in out
