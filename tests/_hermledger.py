"""Hermeticity ledger — the child-side instrument template + path classification.

Opt-in (``CSC_HERMETICITY_LEDGER``), two halves, one ``sys.addaudithook`` (PEP 578) per
process. See ``conftest.py`` (parent half: writes this template out, sets the env,
installs the identical hook in-process) and ``tests/test_hermeticity_gate.py`` (the
comparison). Nothing here runs unless that env var is set — zero cost otherwise.

WHY THIS LOOKS LIKE A SUPPLY-CHAIN PERSISTENCE TECHNIQUE, AND WHY THAT IS FINE HERE.
A ``sitecustomize.py`` dropped into a directory that gets prepended to ``PYTHONPATH`` is
exactly the shape this project's own product flags as a red flag (B99/B335/B375 —
catalog.py/risk.py/skillast.py/hostpersist.py/adjudication.py). The difference is scope
and lifetime: the directory is created fresh per pytest session with
``tempfile.mkdtemp()``, lives only for that session (``pytest_unconfigure`` removes it),
is never committed, and never sits anywhere this tool's own audit/vet/dogfooding runs
would walk. Do not copy this pattern into shipped code, and do not mistake a real
finding for "the test suite doing this on purpose" — if a check ever flags this file
itself, that is this file leaking into a scanned path, not a false positive to suppress.

WHAT THIS DOES NOT COVER (carry these forward — do not silently narrow the claim):
  - A subprocess launched with a fully replaced ``env={...}`` that does not inherit
    ``PYTHONPATH`` is invisible to the child half by construction (e.g.
    ``tests/test_b679_invocation_prefix.py`` deliberately runs a foreign-cwd/minimal-env
    scenario this way). Not fixable without changing that test's intent.
  - A grandchild reached via a further re-exec or an ``sh -c`` chain that itself execs a
    program with a stripped environment is likewise invisible past that point.
  - A C extension touching files through its own C-level I/O rather than through
    CPython's ``os``/``io`` C-API entry points bypasses Python audit events entirely —
    the hook only sees what CPython itself instruments.
  - Network calls are out of scope for this instrument (it watches the read/write
    filesystem surface only); enforcing the "no network calls" half of hermeticity would
    need `socket.connect`/`socket.connect_ex`/`socket.bind` audit events added
    separately, via the identical mechanism.
  - ``open`` is treated as read-shaped even when the mode requests a write (e.g.
    ``open(path, "w")``) — the write-shaped event set below is the explicit os-level
    calls only (rename/remove/mkdir/rmdir/chmod). A hermetic test that writes a NEW file
    outside repo/tmp purely via ``open(..., "w")`` without ever renaming/removing/
    chmod-ing it is not flagged as a WRITE by this ledger. Narrowing this is future work,
    not attempted here.
  - Only the first positional audit-event argument is read as "the path" for every
    subscribed event; a few audit events encode paths differently (fd-relative calls,
    bytes vs str vs os.PathLike) and are handled defensively (isinstance check +
    ``os.fspath``) but this was not exhaustively fuzzed against every CPython
    audit-event argument shape.
  - The buffered atexit flush is one ``os.write()`` call per child process, which is not
    formally guaranteed atomic against a sibling process's concurrent flush (only
    practically so, and only because this repo's CI runs pytest single-process).
"""
from __future__ import annotations

import os

# The exact source written to <tmpdir>/sitecustomize.py for the CHILD half, and exec'd
# directly (not imported) for the PARENT half's in-process hook — see conftest.py for
# why exec rather than `import sitecustomize` (avoids colliding with a real
# sitecustomize module already cached in sys.modules).
#
# Deliberately no f-string / .format() — nothing here is templated per-run; every
# per-run value (the ledger path, the test id, the child's HOME) is read from the
# environment INSIDE the child at hook-install / flush time, not baked in here.
SITECUSTOMIZE_SOURCE = '''\
# Written by clawseccheck's test suite (tests/_hermledger.py) into an ephemeral,
# session-scoped temp directory — never committed, never shipped, removed by
# pytest_unconfigure. See tests/_hermledger.py's module docstring for why this is safe
# despite looking like the sitecustomize+PYTHONPATH persistence shape B99/B335/B375
# flag as a red flag in a REAL agent's config.
import atexit
import os
import sys

_LEDGER = os.environ.get("CSC_HERM_LEDGER_PATH")
if _LEDGER:
    _READ = frozenset(("open", "os.stat", "os.listdir", "os.scandir"))
    _WRITE = frozenset(("os.rename", "os.remove", "os.mkdir", "os.rmdir", "os.chmod"))
    _seen = set()

    def _csc_herm_hook(event, args):
        cat = "R" if event in _READ else "W" if event in _WRITE else None
        if cat is None:
            return
        try:
            path = args[0]
        except Exception:
            return
        if not isinstance(path, (str, bytes, os.PathLike)):
            return
        try:
            _seen.add((cat, os.fspath(path)))
        except Exception:
            pass

    def _csc_herm_flush():
        if not _seen:
            return
        test_id = os.environ.get("PYTEST_CURRENT_TEST", "?")
        home = os.environ.get("HOME", "")
        lines = "".join(
            "%s\\t%s\\t%s\\t%s\\n" % (
                cat,
                path.decode("utf-8", "surrogateescape") if isinstance(path, bytes) else path,
                test_id,
                home,
            )
            for cat, path in _seen
        )
        try:
            fd = os.open(_LEDGER, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, lines.encode("utf-8", "surrogateescape"))
            finally:
                os.close(fd)
        except OSError:
            return
        # Cleared only after a SUCCESSFUL write, not in a `finally` -- a failed write
        # keeps the events buffered so the next flush gets another chance instead of
        # silently losing them. The CHILD half only ever calls this once (atexit, at
        # process exit) so clearing here never mattered there; the PARENT half now
        # calls it once per pytest test (conftest.py's `pytest_runtest_teardown`,
        # CLAWSECCHECK-hermeticity's parent-gating fix) and MUST start each test with
        # an empty buffer, or every later flush re-appends every earlier test's events
        # too -- turning one real violation into a duplicate line per subsequent test.
        _seen.clear()

    sys.addaudithook(_csc_herm_hook)
    atexit.register(_csc_herm_flush)
'''


def _safe_roots() -> set:
    """The runtime-computed "this interpreter's own stdlib/site-packages" roots.

    Computed LIVE in whichever interpreter is actually running, so 3.9-vs-3.12 and
    Linux-vs-macOS drift in stdlib/site-packages layout is a non-issue by construction
    instead of needing a hand-maintained, ever-stale list of literal paths.
    """
    import site
    import sysconfig

    roots = set(sysconfig.get_paths().values())
    try:
        roots.update(site.getsitepackages())
    except (AttributeError, OSError):
        # getsitepackages() is absent in some venv/embeddable builds (no stdlib
        # guarantee) — degrade to the sysconfig paths alone rather than raise.
        pass
    try:
        roots.add(site.getusersitepackages())
    except (AttributeError, OSError):
        pass
    return {os.path.normpath(r) for r in roots if r}


def classify(path: str, repo_root: str) -> str:
    """Bucket ``path`` into ``'<repo>'``, ``'<tmp>'``, ``'<site-packages>'``, or return
    it unchanged (the caller then checks the unchanged path against the allowlist).

    Order matters: repo and tmp are checked before the computed interpreter roots
    because a repo checkout or a tmp dir can (rarely) sit under a path that also
    resolves as a site root on some layouts — repo/tmp are the more specific claim.
    """
    import tempfile

    p = os.path.normpath(path)
    repo = os.path.normpath(repo_root)
    if p == repo or p.startswith(repo + os.sep):
        return "<repo>"
    tmp = os.path.normpath(tempfile.gettempdir())
    if p == tmp or p.startswith(tmp + os.sep):
        return "<tmp>"
    for root in _safe_roots():
        if p == root or p.startswith(root + os.sep):
            return "<site-packages>"
    return p
