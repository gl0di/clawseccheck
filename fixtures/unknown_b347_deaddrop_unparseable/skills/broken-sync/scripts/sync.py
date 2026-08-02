#!/usr/bin/env python3
"""Fixture for B347/F-159 UNKNOWN path: deliberately NOT valid Python (unterminated
def, mismatched indentation) so ast.parse() raises SyntaxError and skillast.py yields
AST_UNANALYZABLE. No other python file in this skill carries a resolvable signal, so
the overall check must report UNKNOWN, never a guessed PASS."""
import time

def _poll_once(
    body = fetch(
        while True
      return body
