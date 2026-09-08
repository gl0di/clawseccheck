"""B-519 — the maintainer's ACTUAL home, for the few tests that are about this machine.

``conftest._isolate_local_store`` redirects ``$HOME`` to a throwaway directory for the
whole session, so the suite cannot append to the user's real ``~/.clawseccheck/`` store.
A handful of tests are deliberately about the real box, though — the real-fleet SKILL.md
sweeps, the recorded fleet-FP baseline, the installed OpenClaw dist, the real
``~/.openclaw``, and two "no machine-specific path may leak" assertions. Under the
redirect they would find nothing and pass vacuously, which would trade a write bug for
four dead guards.

They import from here instead.

WHY A SEPARATE MODULE AND NOT ``conftest``. There are two conftest files in this tree
(``./conftest.py`` and ``./fixtures/conftest.py``). On a full-suite run the bare name
``conftest`` resolves to whichever pytest imported first — measured: the ``fixtures`` one,
so ``from conftest import REAL_HOME`` raised ImportError on five modules while passing
when only ``tests/`` was collected. A dedicated name has no such ambiguity.
"""
from __future__ import annotations

import os
from pathlib import Path

#: Captured at import — this module is imported by ``conftest`` before the redirect.
REAL_HOME = Path(os.path.expanduser("~"))


def real_path(tilde_path) -> Path:
    """Expand a ``~/...`` string against :data:`REAL_HOME`, not the redirected ``$HOME``.

    Taking the shipped constant (``gate.DEFAULT_BASELINE``, ``history.DEFAULT_HISTORY``,
    ...) and passing it through here keeps the test tracking the real path instead of
    restating it.
    """
    text = str(tilde_path)
    if text == "~":
        return REAL_HOME
    if text.startswith("~/"):
        return REAL_HOME / text[2:]
    return Path(text)
