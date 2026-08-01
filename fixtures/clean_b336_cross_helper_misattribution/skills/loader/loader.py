"""clean_b336_cross_helper_misattribution: TWO composing helpers live in this file --
`load_schema_index` genuinely reads two CHUNKED/part data files (leg 2 + leg 3 both
hold for it on its own), and `build_model_source` reads two ordinary, non-chunked
template fragments (leg 2 holds, leg 3 does not). Only `build_model_source` feeds the
exec() call in `materialize_models`; `load_schema_index` is called from a completely
different function (`schema_names`) and never reaches any exec()/eval() sink.

B-417 (C-135 follow-up): the leg-3 corroborator used to be evaluated against the
UNION of every composing helper's paths in the file once more than one existed, so
`load_schema_index`'s genuinely chunked paths wrongly "donated" chunk evidence to the
unrelated, non-chunked exec() call actually fed by `build_model_source`. B336 must
attribute leg-3 evidence to the helper that ACTUALLY feeds a given sink and PASS /
emit no CHUNKED_FILE_EXEC finding here.
"""

import json
import os

_HERE = os.path.dirname(__file__)

# Shipped sharded to stay under a hosting blob-size limit -- an ordinary, benign
# reason to split a DATA asset that has nothing to do with the exec() below.
INDEX_CHUNKS = ["data/schema_index.part1.jsonl", "data/schema_index.part2.jsonl"]


def load_schema_index():
    """Read the sharded schema index back into one JSONL blob."""
    rows = []
    for path in INDEX_CHUNKS:
        with open(os.path.join(_HERE, path), encoding="utf-8") as fh:
            rows.append(fh.read())
    return "".join(rows)


def build_model_source():
    """Assemble the generated module source from its two template fragments."""
    with open(os.path.join(_HERE, "templates/model_header.tmpl"), encoding="utf-8") as header:
        with open(os.path.join(_HERE, "templates/model_body.tmpl"), encoding="utf-8") as body:
            return header.read() + body.read()


def materialize_models():
    """Compile the generated module into a fresh namespace (the dataclasses trick).
    Fed ONLY by build_model_source() -- never by load_schema_index()."""
    namespace = {}
    exec(build_model_source(), namespace)
    return namespace


def schema_names():
    """Every model name declared in the shipped schema index. Never reaches exec()/
    eval() -- load_schema_index()'s return value flows only here."""
    return [
        json.loads(line)["name"]
        for line in load_schema_index().splitlines()
        if line.strip()
    ]
