"""Точка входа CLI: проверить security-настройки URL, которым вы владеете."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

import httpx

from .checks import run_checks
from .report import has_high_failures, render


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="websec",
        description=(
            "Безопасная проверка security-заголовков и флагов кук. "
            "Запускать только против сайтов, которыми вы владеете или на "
            "проверку которых у вас есть разрешение."
        ),
    )
    parser.add_argument("url", help="целевой URL, например https://example.com")
    parser.add_argument(
        "--fail-on-high",
        action="store_true",
        help="завершиться с кодом 1, если провалена хоть одна HIGH-проверка (для CI)",
    )
    parser.add_argument(
        "--timeout", type=float, default=10.0, help="таймаут запроса в секундах"
    )
    args = parser.parse_args(argv)

    try:
        with httpx.Client(follow_redirects=True, timeout=args.timeout) as client:
            response = client.get(args.url)
    except httpx.HTTPError as exc:
        print(f"запрос не выполнен: {exc}", file=sys.stderr)
        return 2

    findings = run_checks(response)
    print(render(findings))

    if args.fail_on_high and has_high_failures(findings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
