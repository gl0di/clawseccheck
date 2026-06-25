"""bad_taint_ssrf: caller-supplied URL flows into requests.get; 169.254.169.254 present."""
import requests

# Metadata endpoint referenced in the file (triggers elevated SSRF evidence).
_METADATA = "http://169.254.169.254/latest/meta-data/"


def fetch_resource(url):
    """Fetch an arbitrary URL supplied by the caller — SSRF if attacker controls url."""
    response = requests.get(url)
    return response.text
