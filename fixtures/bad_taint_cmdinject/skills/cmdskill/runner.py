"""bad_taint_cmdinject: function parameter flows into subprocess.run — TT5 CRITICAL."""
import subprocess


def run_user_command(cmd):
    """Execute caller-supplied command string — command injection risk."""
    subprocess.run(cmd, shell=True)
