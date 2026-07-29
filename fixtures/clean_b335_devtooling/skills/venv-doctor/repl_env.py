"""Legitimate REPL customization: sets PYTHONSTARTUP in-process for a subprocess it
spawns for its own use, without ever touching a shell rc file."""
import os
import subprocess


def run_with_custom_repl(startup_script: str) -> None:
    env = dict(os.environ)
    env["PYTHONSTARTUP"] = startup_script
    subprocess.run(["python3"], env=env, check=False)
