"""Safety hook: code that runs BEFORE the guest sees a command, and can block it.

A sentence in a system prompt cannot stop a command; this can. It is also
deliberately *not* the security boundary. A pattern list is trivially bypassed
by obfuscation, so the real boundary is the sandbox itself (own kernel, no
network, read-only system mounts, no secrets). The hook gives three things the
sandbox does not: cheap early refusal, a precise audit reason, and a signal
that the agent has been steered (every block is evidence of an attempted
injection). The containment test measures what the hook alone stops and what
only the network policy stops, so both claims are backed by numbers.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from agent.errors import CommandBlocked

# Packages the grader may install. Anything else is a "suspicious package".
PIP_ALLOWLIST = frozenset({"pytest", "pytest-timeout", "hypothesis"})

_NET_TOOLS = r"(curl|wget|nc|ncat|netcat|socat|telnet|ftp|tftp|scp|sftp|ssh|rsync)"

# (rule name, compiled pattern, reason). Order matters only for the reported rule.
_RULES: list[tuple[str, re.Pattern[str], str]] = [
    (
        "destructive_root_wipe",
        re.compile(
            r"(\brm\s+(-[a-zA-Z]*\s+)*(/|/\*|~|~/\*|\$HOME)(\s|$))"
            r"|(--no-preserve-root)"
            r"|(\bmkfs(\.\w+)?\b)"
            r"|(\bdd\b[^|;&]*\bof=/dev/)"
            r"|(>\s*/dev/(sd|vd|nvme)\w*)"
            r"|(:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:)",
            re.IGNORECASE,
        ),
        "recursive delete of the root/home directory, raw device write or fork bomb",
    ),
    (
        "system_path_destruction",
        re.compile(
            r"(\brm\s+(-[a-zA-Z]+\s+)+[^|;&]*\s?/(usr|bin|sbin|lib|lib64|etc|boot|var|opt|home|root|dev|proc|sys)\b)"
            r"|(\bdd\b[^|;&]*\bof=/(usr|bin|sbin|lib|lib64|etc|boot|var|opt)\b)"
            r"|(>>?\s*/(etc|usr|bin|sbin|lib|lib64|boot)/)",
            re.IGNORECASE,
        ),
        "deleting or overwriting system directories and files",
    ),
    (
        "network_tool",
        re.compile(rf"(^|[\s;&|(`$]){_NET_TOOLS}(\s|$)"),
        "network client binaries are denied: grading needs no network",
    ),
    (
        "raw_socket_redirect",
        re.compile(r"/dev/(tcp|udp)/"),
        "bash /dev/tcp and /dev/udp redirections open raw sockets",
    ),
    (
        "python_network_import",
        re.compile(
            r"(urllib(\.request)?|http\.client|requests|socket|aiohttp|httpx|ftplib|smtplib)"
            r".*(open|connect|get|post|request|send)",
            re.IGNORECASE | re.DOTALL,
        ),
        "inline code that opens network connections",
    ),
    (
        "decode_and_execute",
        re.compile(
            r"(base64\s+(-d|--decode)|xxd\s+-r|openssl\s+enc\s+-d)[^;&]*\|\s*(ba|z|da)?sh\b"
            r"|\beval\b[^;&]*\$\(\s*(echo|printf|base64)"
            r"|\|\s*(ba|z|da)?sh\s*$",
            re.IGNORECASE,
        ),
        "decoding a payload and piping it to a shell hides what will run",
    ),
    (
        "secret_read",
        re.compile(
            r"(cat|less|more|head|tail|strings|cp|scp|base64)\s+[^|;&]*"
            r"(\.env\b|id_rsa|id_ed25519|\.aws/credentials|\.netrc|/etc/shadow)"
            r"|(^|[\s;&|])(printenv|env)\s*(\||$|;|>)"
            r"|\$\{?(CELESTO_API_KEY|LLM_API_KEY|AWS_SECRET_ACCESS_KEY)\}?",
            re.IGNORECASE,
        ),
        "reading credential files or dumping the environment",
    ),
    (
        "privilege_escalation",
        re.compile(r"(^|[\s;&|])(sudo|su|doas|chroot|nsenter|unshare|mount|umount|insmod|modprobe)(\s|$)"),
        "privilege and namespace manipulation is not part of the task",
    ),
]

_PIP_RE = re.compile(r"(^|[\s;&|])(pip3?|python3?\s+-m\s+pip|uv\s+pip|npm|yarn|pnpm)\s+(install|add|i)\b")


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    rule: str = ""
    reason: str = ""


def _pip_packages(command: str) -> list[str]:
    """Best-effort extraction of package names from an install command."""
    packages: list[str] = []
    for segment in re.split(r"[;&|]+", command):
        if not _PIP_RE.search(" " + segment):
            continue
        try:
            tokens = shlex.split(segment)
        except ValueError:
            tokens = segment.split()
        seen_install = False
        for tok in tokens:
            if tok in ("install", "add", "i"):
                seen_install = True
                continue
            if seen_install and not tok.startswith("-"):
                packages.append(re.split(r"[=<>!~\[]", tok, maxsplit=1)[0].lower())
    return packages


class SafetyGuard:
    """Evaluate a command against the deny rules and the package allow-list."""

    def __init__(self, pip_allowlist: frozenset[str] = PIP_ALLOWLIST) -> None:
        self.pip_allowlist = pip_allowlist

    def check(self, command: str) -> Verdict:
        normalized = " ".join(command.split()) if "\n" not in command else command
        for name, pattern, reason in _RULES:
            if pattern.search(normalized):
                return Verdict(False, name, reason)
        for package in _pip_packages(normalized):
            if package not in self.pip_allowlist:
                return Verdict(
                    False,
                    "package_not_allowlisted",
                    f"package '{package}' is not on the allow-list {sorted(self.pip_allowlist)}",
                )
        return Verdict(True)

    def enforce(self, command: str) -> None:
        verdict = self.check(command)
        if not verdict.allowed:
            raise CommandBlocked(command, verdict.rule, verdict.reason)


class AllowAllGuard(SafetyGuard):
    """Used by the containment test to measure the sandbox with the hook switched off."""

    def check(self, command: str) -> Verdict:  # noqa: D401 - trivial override
        return Verdict(True)
