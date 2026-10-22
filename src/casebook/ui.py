"""Small dependency-free terminal theme for CASEBOOK."""
from __future__ import annotations

import os
import sys
import textwrap
from typing import Iterable


class Theme:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"

    @classmethod
    def enabled(cls) -> bool:
        return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None and os.environ.get("TERM", "") != "dumb"

    @classmethod
    def paint(cls, value: str, *codes: str) -> str:
        if not cls.enabled():
            return value
        return "".join(codes) + value + cls.RESET


def banner() -> None:
    logo = r"""
       ╭────────────────────╮
       │  ╭────────────╮    │
       │  │  ╭──────╮  │    │
       │  │  │      │  │    │
       │  │  ╰──┬───╯  │    │
       │  │  ┌──▣───┐  │    │
       │  │  │ LOCK │  │    │
       │  │  └──────┘  │    │
       │  │  CASE FILE │    │
       │  ╰────────────╯    │
       ╰────────────────────╯"""
    for line in logo.splitlines():
        print(Theme.paint(line, Theme.CYAN, Theme.BOLD))
    print(Theme.paint("  C A S E B O O K", Theme.WHITE, Theme.BOLD))
    print(Theme.paint("  OFFLINE-FIRST  /  DIGITAL FORENSICS WORKSPACE", Theme.BLUE))
    print(Theme.paint("  Evidence integrity  •  Case timeline  •  Reproducible reports", Theme.GRAY))
    print()


def success(message: str) -> None:
    print(f"{Theme.paint('✔', Theme.GREEN, Theme.BOLD)} {message}")


def info(message: str) -> None:
    print(f"{Theme.paint('›', Theme.CYAN, Theme.BOLD)} {message}")


def warning(message: str) -> None:
    print(f"{Theme.paint('!', Theme.YELLOW, Theme.BOLD)} {message}", file=sys.stderr)


def error(message: str) -> None:
    print(f"{Theme.paint('✖', Theme.RED, Theme.BOLD)} {message}", file=sys.stderr)


def panel(title: str, lines: Iterable[str], width: int = 72) -> None:
    inner = max(20, width - 4)
    print(Theme.paint("╭─ " + title + " " + "─" * max(0, width - len(title) - 5) + "╮", Theme.BLUE, Theme.BOLD))
    for line in lines:
        wrapped = textwrap.wrap(str(line), width=inner) or [""]
        for item in wrapped:
            print(Theme.paint("│ ", Theme.BLUE) + item.ljust(inner) + Theme.paint(" │", Theme.BLUE))
    print(Theme.paint("╰" + "─" * (width - 2) + "╯", Theme.BLUE))


def kv(label: str, value: object) -> None:
    print(f"  {Theme.paint(label.ljust(16), Theme.GRAY)} {value}")


def severity(value: str) -> str:
    colors = {
        "critical": Theme.RED + Theme.BOLD,
        "high": Theme.RED,
        "medium": Theme.YELLOW,
        "low": Theme.CYAN,
        "info": Theme.GRAY,
    }
    return Theme.paint(value.upper(), *colors.get(value.lower(), (Theme.WHITE,)))
