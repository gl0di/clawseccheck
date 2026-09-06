"""B-747 — an archive member's safety is a property of its NAME, not of this machine.

``safeio.is_safe_tar_member`` used to do ``Path(base_dir / member_name).resolve()``, which
follows symlinks that happen to exist on disk. So it answered "where would this land given
the current state of this machine" rather than "does this declared name escape the root" —
and nothing is being extracted at scan time, so only the second question is being asked.

Measured end to end through ``--vet-skill``, on a skill holding an ordinary editable
checkout beside its own built wheel::

    sk_whl/
      SKILL.md
      mypkg -> ../src/mypkg           # benign symlink
      mypkg-1.0-py3-none-any.whl      # members: mypkg/__init__.py, ...dist-info/...

    -> DO-NOT-INSTALL
       "Archive path traversal detected: mypkg-1.0-py3-none-any.whl::mypkg/__init__.py"

``mypkg/__init__.py`` is the most ordinary path in Python packaging, and the collision is
not bad luck: for a Python package the source directory and the wheel's top-level package
have the SAME NAME by construction. Removing only the symlink restored ``CAUTION``, which
is how the cause was isolated. A false-positive FAIL on a benign skill is Golden Rule #5.

The defect PRE-DATES B-746 — verified on a pre-B-746 tree — but B-746 removed the
accidental WARN-masking that hid it whenever the same skill also tripped a WARN, so it
became visible in a wider population. That is why the two land together.

HOW THIS FILE IS BUILT, AND WHY
-------------------------------
A false NEGATIVE here is far worse than the false positive being fixed, so the replacement
was not reasoned about — it was checked against the predicate it replaces. ``_CASES`` below
is the real content of this file; the end-to-end tests merely confirm the wiring. The two
halves were validated differently and the difference matters:

  * the 32 POSIX shapes were run against the OLD predicate on a clean base directory,
    where it is correct — zero disagreements, before the new one was written;
  * the 12 Windows shapes were added afterwards, when this change's own C-135 pass found
    that a first draft had silently dropped them. They are validated against
    ``ntpath.normpath(ntpath.join(...))``, which is what ``Path.resolve()`` degrades to on
    Windows — a faithful model, not a run, since no Windows host was available. That is
    the one claim in this file resting on simulation, and it is said here rather than
    left for a reader to discover.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

from clawseccheck.checks import check_installed_skills
from clawseccheck.collector import collect
from clawseccheck.safeio import is_safe_tar_member

#: (member name, must be judged safe). Verified to reproduce the pre-B-747 predicate's own
#: answers on a clean base directory, member for member.
_CASES = [
    # --- ordinary names, including every packaging convention that looked risky ---
    ("file.txt", True),
    ("a/b/c.txt", True),
    ("./a.txt", True),
    (".", True),
    ("./", True),
    ("a/../b.txt", True),
    ("dir/sub/../f", True),
    ("foo..bar", True),          # ".." inside a name is not a traversal
    ("..foo", True),
    ("package/lib/x.js", True),  # npm tarball layout
    ("__MACOSX/._foo", True),    # macOS zip resource forks
    ("pax_global_header", True),
    ("././@LongLink", True),     # GNU tar long-name marker
    ("mypkg/__init__.py", True),  # the B-747 repro's own member
    ("mypkg-1.0.dist-info/METADATA", True),
    ("a" * 300, True),
    ("nested/" * 40 + "f.txt", True),
    # A backslash folds to a separator before the check (see the module docstring): an
    # ordinary two-component name stays safe...
    ("dir\\file.txt", True),
    ("package\\lib\\x.js", True),
    # --- genuine escapes ---
    ("../evil", False),
    ("../../evil", False),
    ("../../../tmp/escape_via_zip.txt", False),  # the B-746 fixture's member
    ("a/../../evil", False),
    ("a/b/../../../c", False),
    ("./../evil", False),
    ("/etc/passwd", False),
    ("//etc/passwd", False),     # POSIX treats a leading "//" as absolute too
    ("/", False),
    ("..", False),
    ("../", False),
    ("foo/..", True),            # collapses to the root itself, which is inside it
    ("\x00", False),
    ("a\x00b", False),
    # ...and one that escapes on Windows is unsafe everywhere. SKILL.md declares
    # os: [darwin, linux, win32], and the predicate this replaced joined through ntpath
    # there, so these were FLAGGED before. A first draft used posixpath unconditionally
    # and disclosed the loss as "a pre-existing false negative", which was true on POSIX
    # and false on Windows — caught by this change's own C-135 pass.
    ("..\\..\\evil", False),
    ("..\\evil", False),
    ("..\\", False),
    ("sub\\..\\..\\evil", False),
    ("..\\../evil", False),
    ("a\\..\\..\\..\\evil", False),
    ("..\\.\\..\\evil", False),
    ("C:/evil", False),      # no backslash at all — the sharpest of the twelve
    ("C:\\evil", False),
    ("\\evil", False),
    ("\\\\srv\\share\\evil", False),   # UNC
    ("\\\\?\\C:\\evil", False),        # extended-length prefix
]


def test_the_battery(tmp_path):
    """Every shape, against a real (clean, symlink-free) base directory."""
    wrong = [
        (name, expected, is_safe_tar_member(tmp_path, name))
        for name, expected in _CASES
        if is_safe_tar_member(tmp_path, name) != expected
    ]
    assert not wrong, wrong


def test_the_answer_does_not_depend_on_what_is_on_disk(tmp_path):
    """The structural guard, and the whole point of the change.

    A predicate that consults the filesystem cannot give the same answers for a root that
    does not exist, for an empty root, and for a root full of adversarially-named
    symlinks. This asserts all three agree — which no ``.resolve()``-based implementation
    can satisfy, so it fails on the code this replaced rather than only on its symptom.
    """
    missing = tmp_path / "does-not-exist"

    empty = tmp_path / "empty"
    empty.mkdir()

    trapped = tmp_path / "trapped"
    trapped.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    # symlinks named after the first path component of several battery members
    for link_name in ("a", "dir", "mypkg", "package", "nested", "foo", "__MACOSX"):
        (trapped / link_name).symlink_to(outside, target_is_directory=True)

    for name, expected in _CASES:
        answers = {root: is_safe_tar_member(root, name) for root in (missing, empty, trapped)}
        assert len(set(answers.values())) == 1, (
            f"{name!r} is judged differently depending on the base directory's contents: "
            f"{ {str(k.name): v for k, v in answers.items()} } — the verdict must be a "
            "property of the member name alone"
        )
        assert answers[empty] == expected, (name, answers[empty], expected)


def _skill(tmp_path: Path, name: str, *, members, symlink: bool) -> Path:
    home = tmp_path / name
    d = home / "workspace" / "skills" / "sk"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(
        "---\nname: sk\ndescription: A skill.\n---\nsee wheel\n", encoding="utf-8"
    )
    with zipfile.ZipFile(d / "mypkg-1.0-py3-none-any.whl", "w") as z:
        for m in members:
            z.writestr(m, "x")
    if symlink:
        target = home / "src" / "mypkg"
        target.mkdir(parents=True)
        (target / "__init__.py").write_text("print(1)\n", encoding="utf-8")
        (d / "mypkg").symlink_to(target, target_is_directory=True)
    return home


def test_a_benign_editable_checkout_beside_its_wheel_is_not_a_traversal(tmp_path):
    """The reported case, end to end through the engine."""
    members = ["mypkg/__init__.py", "mypkg-1.0.dist-info/METADATA"]
    f = check_installed_skills(collect(_skill(tmp_path, "a", members=members, symlink=True)))

    assert f.status != "SKILL_ARCHIVE_PATH_TRAVERSAL", (f.status, f.detail[:200])
    assert "traversal" not in (f.detail or "").lower(), f.detail


def test_the_symlink_changes_nothing(tmp_path):
    """The direct pin: identical archive, identical members, only the symlink varies."""
    members = ["mypkg/__init__.py", "mypkg-1.0.dist-info/METADATA"]
    with_link = check_installed_skills(collect(_skill(tmp_path, "w", members=members, symlink=True)))
    without = check_installed_skills(collect(_skill(tmp_path, "n", members=members, symlink=False)))

    assert with_link.status == without.status, (
        f"an on-disk symlink moved the verdict: {without.status} -> {with_link.status}"
    )


def test_a_real_escape_is_still_caught_with_the_same_symlink_present(tmp_path):
    """The other direction, and the one that matters more.

    The fix must not have bought its false-positive relief by loosening the predicate: the
    same skill, same symlink, but one member that genuinely escapes, must still convict.
    """
    members = ["mypkg/__init__.py", "../../../tmp/escape_via_zip.txt"]
    f = check_installed_skills(collect(_skill(tmp_path, "e", members=members, symlink=True)))

    assert f.status == "SKILL_ARCHIVE_PATH_TRAVERSAL", (f.status, f.detail[:200])
    assert "escape_via_zip.txt" in (f.detail or ""), f.detail


def test_the_predicate_reads_no_filesystem_at_all():
    """Positive control for the disk-independence property above.

    ``test_the_answer_does_not_depend_on_what_is_on_disk`` compares three roots and would
    also pass on an implementation that consults the disk but happens to agree on those
    three. This closes it structurally: the function's source must contain no filesystem
    call. Named explicitly rather than "no Path usage", so the failure message tells the
    next author which call reintroduced the coupling.
    """
    import inspect

    src = inspect.getsource(is_safe_tar_member)
    body = src.split('"""')[-1]  # skip the docstring, which discusses .resolve() by name
    for call in (".resolve(", ".exists(", ".stat(", ".is_dir(", ".is_symlink(", "os.path.realpath"):
        assert call not in body, (
            f"is_safe_tar_member calls {call} — the answer must be a property of the "
            "member name, not of this machine's filesystem (B-747)"
        )


def test_the_accepted_residual_is_pinned_where_it_is_silent(tmp_path):
    """The cost of the trade, measured and pinned so it is not mistaken for an oversight.

    A skill can ship both halves of an escape: a real symlink beside an archive member
    that lands through it. The old predicate caught that; this one cannot, because it is
    statically indistinguishable from the benign editable-checkout case above.

    What covers it depends on how far the symlink reaches, and an earlier draft of the
    docstring got this wrong by claiming a WARN always fires:

      * escaping the HOME -> B87 WARNs, so the dangerous half is disclosed.
      * escaping only the SKILL DIRECTORY -> silent on both B13 and B87.

    This pins both, so the day either changes the reader is told. If the second ever
    starts being disclosed, that is progress — update this test, do not delete it.
    """
    from clawseccheck.checks import run_all

    def _build(root: Path, link_target: Path) -> Path:
        home = root / "home"
        d = home / "workspace" / "skills" / "demo"
        d.mkdir(parents=True)
        (d / "SKILL.md").write_text(
            "---\nname: demo\ndescription: A skill.\n---\nsee bundle\n", encoding="utf-8"
        )
        with zipfile.ZipFile(d / "bundle.zip", "w") as z:
            z.writestr("data/payload.txt", "x")
        link_target.mkdir(parents=True, exist_ok=True)
        (d / "data").symlink_to(link_target, target_is_directory=True)
        return home

    # (a) escapes only the skill directory, stays inside the home -> silent
    inner_root = tmp_path / "inner"
    inner_home = _build(inner_root, inner_root / "home" / "elsewhere")
    inner = check_installed_skills(collect(inner_home))
    assert inner.status == "PASS", (inner.status, inner.detail[:160])

    # (b) escapes the home -> B87 discloses the escaping link
    outer_root = tmp_path / "outer"
    outer_home = _build(outer_root, outer_root / "really_outside")
    b87 = next(f for f in run_all(collect(outer_home)) if f.id == "B87")
    assert b87.status == "WARN", (b87.status, b87.detail[:160])
    assert "escapes the tree" in (b87.detail or ""), b87.detail
