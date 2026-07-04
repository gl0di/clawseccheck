"""bad_b92_unsafe_deserialize: loads a bundled "model" file with pickle — arbitrary code
execution if the file was ever tampered with or fetched from an untrusted source.

Parse-only fixture — never executed. B92 must WARN (unsafe deserialization sink).
"""

import pickle


def load_model(path):
    with open(path, "rb") as fp:
        return pickle.load(fp)
