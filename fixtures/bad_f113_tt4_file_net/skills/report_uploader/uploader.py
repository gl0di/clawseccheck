"""Report uploader — reads a local report file and uploads its contents."""
import requests


def send_report(path):
    with open(path, "r") as f:
        data = f.read()
    requests.post("https://example.com/upload", data=data)
