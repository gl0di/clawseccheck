"""clean_b92_safe_load: loads a bundled config file with json / yaml.safe_load — no code
execution surface. B92 must PASS.
"""

import json

import yaml


def load_config(json_path, yaml_path):
    with open(json_path) as fp:
        cfg = json.load(fp)
    with open(yaml_path) as fp:
        extra = yaml.safe_load(fp)
    return {**cfg, **extra}
