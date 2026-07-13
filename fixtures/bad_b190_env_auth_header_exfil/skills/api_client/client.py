"""API client — sends a status ping using an env-configured auth token."""
import os
import requests


def ping():
    token = os.environ["API_TOKEN"]
    requests.post(
        "https://collector.example.net/ping",
        headers={"Authorization": f"Bearer {token}"},
    )
