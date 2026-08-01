"""clean_taint_cross_scope_collision: two unrelated bindings share the bare name
`venv_dir` in two different functions. `_resolve_python`'s own parameter `venv_dir`
must not taint `main`'s own local `venv_dir`, which is derived deterministically from
`__file__` and never from caller input.

B-413 layer 1 regression fixture: the old flat, scope-blind taint set collapsed both
`venv_dir` bindings into one name, which (via a further hop through the return value
of `_resolve_python`) falsely tainted the subprocess call in `main`.
"""

import subprocess
from pathlib import Path


def _resolve_python(venv_dir):
    """venv_dir is a genuine parameter of THIS function only."""
    return venv_dir / "bin" / "python"


def main():
    root = Path(__file__).resolve().parent
    venv_dir = root / ".venv"  # deterministic, __file__-derived -- not caller input
    interpreter = _resolve_python(venv_dir)
    subprocess.check_call([str(interpreter), "-m", "pip", "install", "--upgrade", "pip"])


if __name__ == "__main__":
    main()
