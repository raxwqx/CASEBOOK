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
    def unicode_ok(cls, stream: object | None = None) -> bool:
        """Return True when the output stream can encode the theme glyphs."""
        target = stream if stream is not None else sys.stdout
        encoding = getattr(target, "encoding", None) or "ascii"
        try:
            "╭─▣✔›✖•".encode(encoding)
        except (UnicodeEncodeError, LookupError):
            return False
        return True

    @classmethod
    def paint(cls, value: str, *codes: str) -> str:
        if not cls.enabled():
            return value
        return "".join(codes) + value + cls.RESET


def configure_output() -> None:
    """Prevent a legacy console encoding from crashing the terminal UI.

    Windows consoles and redirected pipes may expose cp1252 or another
    non-UTF-8 encoding. Replacing unsupported glyphs keeps diagnostics usable;
    the banner and panels separately fall back to ASCII art when needed.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(errors="replace")
        except (OSError, ValueError):
            pass


def banner() -> None:
    if Theme.unicode_ok():
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
        separator = "  •  "
    else:
        logo = r"""
       +--------------------+
       |  +------------+    |
       |  |  +------+  |    |
       |  |  |      |  |    |
       |  |  +--+---+  |    |
       |  |  +--+---+  |    |
       |  |  | LOCK |  |    |
       |  |  +------+  |    |
       |  | CASE FILE |   |
       |  +------------+    |
       +--------------------+"""
        separator = "  |  "
    for line in logo.splitlines():
        print(Theme.paint(line, Theme.CYAN, Theme.BOLD))
    print(Theme.paint("  C A S E B O O K", Theme.WHITE, Theme.BOLD))
    print(Theme.paint("  OFFLINE-FIRST  /  DIGITAL FORENSICS WORKSPACE", Theme.BLUE))
    print(Theme.paint(f"  Evidence integrity{separator}Case timeline{separator}Portable reports{separator}External digest", Theme.GRAY))
    print()


def success(message: str) -> None:
    print(f"{Theme.paint('✔' if Theme.unicode_ok() else '[+]', Theme.GREEN, Theme.BOLD)} {message}")


def info(message: str) -> None:
    print(f"{Theme.paint('›' if Theme.unicode_ok() else '[i]', Theme.CYAN, Theme.BOLD)} {message}")


def warning(message: str) -> None:
    print(f"{Theme.paint('!' if Theme.unicode_ok() else '[!]', Theme.YELLOW, Theme.BOLD)} {message}", file=sys.stderr)


def error(message: str) -> None:
    print(f"{Theme.paint('✖' if Theme.unicode_ok() else '[x]', Theme.RED, Theme.BOLD)} {message}", file=sys.stderr)


def panel(title: str, lines: Iterable[str], width: int = 72) -> None:
    inner = max(20, width - 4)
    if Theme.unicode_ok():
        print(Theme.paint("╭─ " + title + " " + "─" * max(0, width - len(title) - 5) + "╮", Theme.BLUE, Theme.BOLD))
        for line in lines:
            wrapped = textwrap.wrap(str(line), width=inner) or [""]
            for item in wrapped:
                print(Theme.paint("│ ", Theme.BLUE) + item.ljust(inner) + Theme.paint(" │", Theme.BLUE))
        print(Theme.paint("╰" + "─" * (width - 2) + "╯", Theme.BLUE))
        return
    print(Theme.paint("+- " + title + " " + "-" * max(0, width - len(title) - 5) + "+", Theme.BLUE, Theme.BOLD))
    for line in lines:
        wrapped = textwrap.wrap(str(line), width=inner) or [""]
        for item in wrapped:
            print(Theme.paint("| ", Theme.BLUE) + item.ljust(inner) + Theme.paint(" |", Theme.BLUE))
    print(Theme.paint("+" + "-" * (width - 2) + "+", Theme.BLUE))


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
