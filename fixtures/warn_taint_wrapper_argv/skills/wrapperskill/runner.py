"""clean_taint_wrapper_argv: a subprocess wrapper whose OWN parameter is a genuine
function parameter (tainted from run()'s own scope), but every intra-file call site
binds it to a fully hardcoded argv list with a fixed, untainted program name.

B-413 layer 2 regression fixture: layer 1 alone cannot clear this shape, since `cmd`
really is tainted from run()'s own perspective; only the call-site view (every real
invocation is a literal command) proves it safe.
"""

import subprocess
import sys


def run(cmd, cwd):
    """cmd is a plain parameter here -- crit from this function's own view alone."""
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(cmd)}")
    return result.stdout


def check_versions(workdir):
    run([sys.executable, "-m", "pip", "--version"], cwd=workdir)
    run(["git", "--version"], cwd=workdir)


def main():
    check_versions(".")


if __name__ == "__main__":
    main()
