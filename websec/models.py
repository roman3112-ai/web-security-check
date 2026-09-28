"""Типы данных, общие для чекера."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    HIGH = "высокий"
    MEDIUM = "средний"
    LOW = "низкий"


@dataclass(frozen=True)
class Finding:
    """Результат одной проверки."""

    check: str
    passed: bool
    severity: Severity
    detail: str
