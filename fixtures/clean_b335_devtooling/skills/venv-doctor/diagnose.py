"""Legitimate diagnostic helper: lists candidate site-packages directories for
import troubleshooting. Read-only -- never opens any file for writing."""
import site


def print_site_dirs() -> None:
    for path in site.getsitepackages():
        print(f"candidate site-packages dir: {path}")
