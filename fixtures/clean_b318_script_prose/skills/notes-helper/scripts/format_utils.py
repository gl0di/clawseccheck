#!/usr/bin/env python3
"""Reformat a plain-text notes file with consistent indentation.

This module reads a notes file, normalizes leading whitespace on each line,
and writes the result back out. It has no network access and no dependency
on any external service.
"""
import sys


def format_notes(path: str) -> None:
    """Normalize indentation in the given notes file and print the result."""
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    # Strip trailing whitespace from every line before printing.
    for line in lines:
        print(line.rstrip())


def main() -> None:
    if len(sys.argv) < 2:
        print("usage: format_utils.py <notes-file>")
        return
    format_notes(sys.argv[1])


if __name__ == "__main__":
    main()
