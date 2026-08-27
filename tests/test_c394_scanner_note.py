"""C-394: the README section that answers a third-party scanner's red verdict.

The section makes four claims a reader is invited to check in the source. Prose
cannot keep itself true, so each claim is pinned here. The point is not that the
section exists -- it is that the repository still looks the way the section says
it looks.
"""

from __future__ import annotations

import ast
import io
import re
import tokenize
from pathlib import Path

from clawseccheck import iocdb

_ROOT = Path(__file__).resolve().parent.parent
_README = (_ROOT / "README.md").read_text(encoding="utf-8")
_HEADING = "## 🚩 Why security scanners flag this repo"


def _section() -> str:
    assert _HEADING in _README, "the C-394 scanner-verdict section is gone from README.md"
    body = _README.split(_HEADING, 1)[1]
    # Up to the next top-level heading, if any.
    nxt = re.search(r"^## ", body, re.MULTILINE)
    return body[: nxt.start()] if nxt else body


def _package_files() -> list[Path]:
    return sorted((_ROOT / "clawseccheck").rglob("*.py"))


def test_section_present() -> None:
    assert len(_section().strip()) > 500


def test_named_ioc_hosts_are_exactly_the_shipped_host_indicators() -> None:
    """The section names the host indicators. If the dataset moves, so must the prose.

    Named, not counted, on purpose: a count says nothing about *which* three, and
    "three" would still read as true after all three were replaced.
    """
    section = _section()
    shipped = {r["value"] for r in iocdb.HOSTS}
    named = {v for v in shipped if v in section}
    assert named == shipped, (
        "README's scanner section must name every shipped iocdb.HOSTS indicator; "
        f"missing from the prose: {sorted(shipped - named)}"
    )


def test_zero_dependencies_claim_holds() -> None:
    pyproject = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "dependencies = []" in pyproject


def test_no_network_client_is_imported_anywhere_in_the_package() -> None:
    """The load-bearing claim: the engine imports no network client.

    `urllib.parse` is exempt (pure string parsing) and `socket` is exempt because
    it is used for inet_aton/inet_ntoa conversion only -- which the next test
    pins, so this exemption cannot quietly widen.
    """
    banned = re.compile(
        r"^\s*(?:import\s+(?:requests|httpx|http\.client|urllib\.request|ftplib|smtplib|telnetlib|aiohttp)"
        r"|from\s+(?:requests|httpx|http|urllib\.request|ftplib|smtplib|telnetlib|aiohttp)\b)"
    )
    offenders = []
    for path in _package_files():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if banned.match(line):
                offenders.append(f"{path.relative_to(_ROOT)}:{lineno}: {line.strip()}")
    assert not offenders, "network client imported in the package:\n" + "\n".join(offenders)


def test_socket_is_imported_once_and_used_only_for_ip_string_conversion() -> None:
    """`socket` names appear all over `skillast.py` -- in prose about what it looks
    for in YOUR skills. Only one module actually imports it, and the claim is about
    that one, so the guard is scoped to importers rather than to every mention.
    """
    importers = [
        path
        for path in _package_files()
        if re.search(r"^\s*(?:import socket\b|from socket import)", path.read_text(encoding="utf-8"), re.MULTILINE)
    ]
    assert [p.name for p in importers] == ["_egress.py"], (
        "the README claims a single `import socket` in the package; importers found: "
        f"{[str(p.relative_to(_ROOT)) for p in importers]}"
    )
    used = set()
    for path in importers:
        used.update(re.findall(r"\bsocket\.([A-Za-z_][A-Za-z0-9_]*)", path.read_text(encoding="utf-8")))
    assert used <= {"inet_aton", "inet_ntoa"}, f"socket used beyond IP-string conversion: {sorted(used)}"


def test_flagged_example_urls_appear_only_in_comments_and_docstrings() -> None:
    """`evil.example` must stay documentation in the package, never a live value.

    "comment or string" would be VACUOUS -- a URL cannot be an identifier, so every
    occurrence trivially satisfies it (proved by a negative control that passed when
    it should have failed). The distinction that bites is comment-or-DOCSTRING vs
    any other string literal: a docstring is inert by construction, an ordinary
    string literal is a value something can use.
    """
    offenders = []
    for path in _package_files():
        src = path.read_text(encoding="utf-8")
        if "evil.example" not in src:
            continue
        inert = set()
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type == tokenize.COMMENT and "evil.example" in tok.string:
                inert.update(range(tok.start[0], tok.end[0] + 1))
        tree = ast.parse(src)
        blocks = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        for node in ast.walk(tree):
            if not isinstance(node, blocks):
                continue
            for child in node.body:
                if (
                    isinstance(child, ast.Expr)
                    and isinstance(child.value, ast.Constant)
                    and isinstance(child.value.value, str)
                    and "evil.example" in child.value.value
                ):
                    inert.update(range(child.lineno, (child.end_lineno or child.lineno) + 1))
        # str.splitlines() also splits on \x0c and friends, which neither tokenize
        # nor ast counts as a line -- it silently shifts every later line number.
        for lineno, line in enumerate(src.split("\n"), 1):
            if "evil.example" in line and lineno not in inert:
                offenders.append(f"{path.relative_to(_ROOT)}:{lineno}: {line.strip()}")
    assert not offenders, "evil.example outside a comment/docstring:\n" + "\n".join(offenders)
