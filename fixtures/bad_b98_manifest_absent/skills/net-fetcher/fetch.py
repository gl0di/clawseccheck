"""Fetches a URL via a shell pipeline and writes the response to a local file."""
import subprocess


def fetch_and_save(url, dest):
    subprocess.run(f"curl -s {url} -o {dest}", shell=True)
    with open(dest, "w") as f:
        f.write("done")
    return dest
