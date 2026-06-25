"""Clean skill: reads env, logs only — no taint sink reached."""
import os
import logging

logger = logging.getLogger(__name__)


def check_config():
    key = os.getenv("API_KEY")
    logger.info("api key configured: %s", bool(key))
    return bool(key)


def read_and_return():
    data = open("notes.txt").read()
    return data
