"""A skill whose only `with` usage is genuinely inert: a threading.Lock() and a
tempfile.TemporaryDirectory(), neither of which touches a filesystem/network sink
in a way the effect simulator should flag.

Companion clean fixture for CLAWSECCHECK-B-155: guards against the fix over-firing
on benign context-manager idioms (adversarial "try to break this" pass, C-135).
"""
import tempfile
import threading

_lock = threading.Lock()


def compute(user_arg):
    with _lock:
        total = len(user_arg) + 1
    with tempfile.TemporaryDirectory() as d:
        name = d
    return total, name
