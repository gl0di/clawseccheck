"""bad_taint_wrapper_tainted_argv0: the wrapper idiom that B-413 layer 2 must NOT
swallow -- the wrapper's single call site passes a literal argv LIST, but the
program-name element (argv[0]) is itself sourced from an environment variable, so an
attacker who controls that env var controls what program actually runs. Must stay a
CRITICAL command-injection finding.
"""

import os
import subprocess


def run(cmd):
    subprocess.run(cmd)


def main():
    interpreter = os.environ["BUILD_INTERPRETER"]
    run([interpreter, "-m", "build_tool", "--release"])


if __name__ == "__main__":
    main()
