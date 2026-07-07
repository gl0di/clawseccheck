"""clean_b13_env_passthrough: os.environ[...] set from another env read, no hardcoded
literal — a legitimate pass-through/normalization pattern. Must NOT fire B-140."""
import os

os.environ["X"] = os.getenv("X", "")


def run():
    return os.environ["X"]
