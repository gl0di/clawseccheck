#!/usr/bin/env python3
"""Generate docs/CHECKS.md from the source-of-truth catalog and risk rules."""
from __future__ import annotations

import argparse
import ast
import json
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from clawseccheck.catalog import CATALOG, OWASP_LLM_2025, owasp_for, remediation_for  # noqa: E402

SOURCE_RISK = ROOT / "clawseccheck" / "risk.py"
OUTPUT = ROOT / "docs" / "CHECKS.md"


@dataclass(frozen=True)
class RiskDoc:
    id: str
    severity: str
    title: str
    docstring: str
    chain: str
    why: str
    fix: str


def _literal_text(node: ast.AST | None) -> str:
    if node is None:
        return ""
    try:
        value = ast.literal_eval(node)
    except Exception:
        return ast.unparse(node).strip()
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False)


def _callee_name(node: ast.Call) -> str:
    """The bare function name of a call, however it was imported."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _expr_text(node: ast.AST | None) -> str:
    if node is None:
        return ""
    if isinstance(node, ast.Constant):
        return str(node.value)
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for part in node.values:
            if isinstance(part, ast.Constant):
                parts.append(str(part.value))
            elif isinstance(part, ast.FormattedValue):
                # Same rule as the fallback below, and it has to be repeated here because an
                # f-string is rendered by its own branch: a CALL inside a placeholder elides,
                # a bare name is kept as a slot label. Without this,
                # "{', '.join(providers)}" and "{', '.join(transport)}" reached the page —
                # two more leaks of the class the fallback fix alone did not close.
                if any(isinstance(sub, ast.Call) for sub in ast.walk(part.value)):
                    parts.append("...")
                else:
                    parts.append(f"{{{ast.unparse(part.value).strip()}}}")
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _expr_text(node.left) + _expr_text(node.right)
    if isinstance(node, ast.Call) and _callee_name(node) == "_key_advice":
        # B-738: a fix string may resolve its config key against the READER's OpenClaw
        # generation via `checks/_shared.py::_key_advice(ctx, legacy, modern)`. The fallback
        # below would `ast.unparse` that call and put Python source into a user-facing
        # remediation — which it did: RISK-15 shipped
        # "...with an explicit _key_advice(ctx, 'browser.ssrfPolicy.hostnameAllowlist', ...)"
        # into docs/CHECKS.md, caught only because markdownlint read the underscore as
        # emphasis. A document has no reader's build, so it gets the same text the helper
        # itself produces when the generation is undeterminable: both keys, each qualified.
        # Rendered by CALLING the helper, not by restating its format, so the doc cannot
        # drift from the advice the tool actually prints.
        args = [_expr_text(a) for a in node.args[1:]]
        if len(args) == 2:
            from clawseccheck.checks import _key_advice  # local: keeps import cost off startup

            return _key_advice(None, args[0], args[1])
    if isinstance(node, (ast.List, ast.Tuple)):
        return ", ".join(_expr_text(elt) for elt in node.elts)
    try:
        value = ast.literal_eval(node)
    except Exception:
            # An expression this function cannot render as prose must not reach the page as
            # Python SOURCE. `ast.unparse` here is how RISK-15 shipped `_key_advice(ctx, ...)`
            # and how RISK-23 shipped `str(len(fired))`, `'; '.join(fired)` and
            # `'; '.join(signal_bearing)` into user-facing advice. The first was caught only
            # because markdownlint read the underscore as emphasis; the rest carry no
            # underscore and were caught by nobody. Special-casing each callee is what let
            # them through, so the FALLBACK changes instead.
            #
            # Only a CALL elides. A bare name reads as a slot label and carries real
            # information in the schematic `Chain:` lines — "channel_label -> tool_label ->
            # host / filesystem" tells a reader what fills each position, and replacing it
            # with "... -> ..." would trade a cosmetic problem for a worse one. A call is
            # different: it is machinery, and a document has no run to evaluate it against.
            if any(isinstance(sub, ast.Call) for sub in ast.walk(node)):
                return "..."
            return ast.unparse(node).strip()
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False)


def _chain_text(node: ast.AST | None) -> str:
    if node is None:
        return ""
    if isinstance(node, (ast.List, ast.Tuple)):
        return " -> ".join(_expr_text(elt) for elt in node.elts)
    return _expr_text(node)


def _risk_docs() -> list[RiskDoc]:
    tree = ast.parse(SOURCE_RISK.read_text(encoding="utf-8"), filename=str(SOURCE_RISK))
    docs: list[RiskDoc] = []

    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) or not node.name.startswith("_rule_"):
            continue
        call: ast.Call | None = None
        for child in ast.walk(node):
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Name) and child.func.id == "RiskPath":
                call = child
                break
        if call is None:
            continue
        kwargs = {kw.arg: kw.value for kw in call.keywords if kw.arg}
        rid = _literal_text(kwargs.get("id"))
        if not rid.startswith("RISK-"):
            continue
        docs.append(
            RiskDoc(
                id=rid,
                severity=_literal_text(kwargs.get("severity")),
                title=_literal_text(kwargs.get("title")),
                docstring=textwrap.dedent(ast.get_docstring(node, clean=True) or "").strip(),
                chain=_chain_text(kwargs.get("chain")),
                why=_expr_text(kwargs.get("why")),
                fix=_expr_text(kwargs.get("fix")),
            )
        )

    docs.sort(key=lambda item: int(item.id.split("-", 1)[1]))
    return docs


def _fmt_owasp(check_id: str) -> str:
    codes = owasp_for(check_id)
    if not codes:
        return "none"
    return ", ".join(f"{code} {OWASP_LLM_2025.get(code, code)}" for code in codes)


def _fmt_remediation(check_id: str) -> list[str]:
    rem = remediation_for(check_id)
    lines: list[str] = []
    for cmd in rem["commands"]:
        lines.append(f"- command: `{cmd}`")
    for item in rem["config"]:
        path = item["path"]
        value = item.get("set")
        note = item.get("note")
        if value is None:
            line = f"- config: `{path}`"
            if note:
                line += f" - {note}"
        else:
            line = f"- config: `{path}` = `{json.dumps(value, ensure_ascii=False)}`"
            if note:
                line += f" - {note}"
        lines.append(line)
    return lines


def _check_section(meta) -> list[str]:
    lines = [f"### {meta.id} - {meta.title}", ""]
    lines.append(f"- Severity: {meta.severity}")
    lines.append(f"- Block: {meta.block}")
    lines.append(f"- Framework: {meta.framework}")
    lines.append(f"- Scored: {'yes' if meta.scored else 'no'}")
    lines.append(f"- Confidence: {meta.confidence}")
    lines.append(f"- OWASP: {_fmt_owasp(meta.id)}")
    lines.append(f"- What it checks: {meta.title}")
    rem = _fmt_remediation(meta.id)
    lines.append("- Remediation:")
    if rem:
        lines.extend(f"  {line}" for line in rem)
    else:
        lines.append("  - none")
    lines.append("")
    return lines


def _risk_section(doc: RiskDoc) -> list[str]:
    lines = [f"### {doc.id} - {doc.title}", ""]
    lines.append(f"- Severity: {doc.severity}")
    lines.append(f"- Pattern: {doc.docstring.splitlines()[0] if doc.docstring else doc.title}")
    if doc.chain:
        lines.append(f"- Chain: {doc.chain}")
    if doc.why:
        lines.append("- Why:")
        lines.extend(f"  {line}" for line in textwrap.wrap(doc.why, width=88))
    if doc.fix:
        lines.append("- Fix:")
        lines.extend(f"  {line}" for line in textwrap.wrap(doc.fix, width=88))
    lines.append("")
    return lines


def build_checks_docs() -> str:
    lines: list[str] = [
        "# Check Catalog Reference",
        "",
        "Generated from [clawseccheck/catalog.py](../clawseccheck/catalog.py) and [clawseccheck/risk.py](../clawseccheck/risk.py).",
        "",
        "Regenerate with `python3 scripts/gen_checks_docs.py --write`.",
        "",
        "## Verdict semantics",
        "",
        "- PASS: no positive evidence for the issue",
        "- FAIL: positive evidence for the issue",
        "- WARN: partial or likely-insecure default; counts half-weight in the score",
        "- UNKNOWN: cannot be determined from the available evidence; excluded from the score",
        "",
        "Advisory checks are recorded for coverage but are not scored.",
        "",
    ]

    current_block = None
    for meta in CATALOG:
        if meta.block != current_block:
            current_block = meta.block
            title = {
                "trifecta": "Trifecta",
                "hardening": "Hardening checks",
                "advisory": "Advisory checks",
            }.get(current_block, current_block.title())
            lines.extend([f"## {title}", ""])
        lines.extend(_check_section(meta))

    risk_docs = _risk_docs()
    if risk_docs:
        lines.extend(["## Compound risk chains", ""])
        lines.append(
            "These paths are computed from multiple checks. They fire only when every leg"
            " is positively evidenced."
        )
        lines.append("")
        for doc in risk_docs:
            lines.extend(_risk_section(doc))

    return "\n".join(lines).rstrip() + "\n"




def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate docs/CHECKS.md from source metadata.")
    parser.add_argument("--write", action="store_true", help="write docs/CHECKS.md instead of printing")
    args = parser.parse_args(argv)

    body = build_checks_docs()
    if args.write:
        OUTPUT.write_text(body, encoding="utf-8")
        return 0
    sys.stdout.write(body)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
