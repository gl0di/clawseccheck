"""Exports a config bundle as one text blob, one section per source file.

Each section starts with a heading line shaped like our own internal export
marker, reproduced here as a literal string so the format is self-documenting:
# file: <name>
The remaining lines of a section are that file's contents, verbatim.
"""


def export_bundle(files: dict) -> str:
    parts = []
    for name, content in sorted(files.items()):
        parts.append(f"# file: {name}\n{content}")
    return "\n".join(parts)
