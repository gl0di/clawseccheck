"""C-341 — B343: ML model artifact provenance (huggingface from_pretrained/
snapshot_download/hf_hub_download, ollama pull, or a direct .gguf/.safetensors/.onnx
URL fetch).

Distinct from B92 (unsafe deserialization FORMAT — pickle/marshal/torch.load): this is
about WHERE the model artifact came from, not whether the file format is dangerous to
load. FAIL only for the same unverifiable-provenance shape B103/B157 already FAIL on
(plaintext http/ftp, raw public IP, .onion, exact IOC-dataset match) — an unpinned bare
repo-id/tag stays WARN, matching B103's own "unpinned is the norm" stance.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_model_artifact_provenance
from clawseccheck.collector import Context


def _ctx(skills):
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.bootstrap = {}
    c.installed_skills = skills
    return c


def test_b343_unknown_no_skills():
    assert check_model_artifact_provenance(_ctx({})).status == UNKNOWN


def test_b343_unknown_no_model_reference():
    """Installed skills exist, but none reference a model loader at all."""
    c = _ctx({"skill": "# file: main.py\nimport requests\nrequests.get('https://example.com')\n"})
    assert check_model_artifact_provenance(c).status == UNKNOWN


def test_b343_pass_pinned_from_pretrained():
    c = _ctx({"skill": (
        "# file: main.py\n"
        "model = AutoModel.from_pretrained('org/model', revision='a1b2c3d4e5f6')\n"
    )})
    assert check_model_artifact_provenance(c).status == PASS


def test_b343_pass_pinned_ollama_digest():
    c = _ctx({"skill": (
        "# file: setup.sh\nollama pull llama3:8b@sha256:"
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\n"
    )})
    assert check_model_artifact_provenance(c).status == PASS


def test_b343_pass_https_file_url_to_named_host():
    """A direct HTTPS fetch of a model file to a named host — already a fully-specified
    target, not the 'unpinned reference' shape, so no WARN either."""
    c = _ctx({"skill": (
        "# file: main.py\n"
        "requests.get('https://huggingface.co/org/model/resolve/main/model.safetensors')\n"
    )})
    assert check_model_artifact_provenance(c).status == PASS


def test_b343_warn_unpinned_from_pretrained():
    c = _ctx({"skill": "# file: main.py\nmodel = AutoModel.from_pretrained('org/model')\n"})
    f = check_model_artifact_provenance(c)
    assert f.status == WARN
    assert "org/model" in " ".join(f.evidence)


def test_b343_warn_unpinned_snapshot_download():
    c = _ctx({"skill": "# file: main.py\nsnapshot_download(repo_id='org/model')\n"})
    assert check_model_artifact_provenance(c).status == WARN


def test_b343_warn_unpinned_ollama_shell_text():
    c = _ctx({"skill": "# file: setup.sh\nollama pull llama3:8b\n"})
    f = check_model_artifact_provenance(c)
    assert f.status == WARN
    assert "llama3:8b" in " ".join(f.evidence)


def test_b343_warn_unpinned_ollama_argv_list():
    # The argv-list call form -- subprocess.run(["ollama", "pull", "llama3:8b"]) -- a
    # different shape from the shell-text form above; must be caught too (a sibling
    # check, B338, was previously found to miss exactly this shape).
    c = _ctx({"skill": (
        "# file: main.py\n"
        'subprocess.run(["ollama", "pull", "llama3:8b"])\n'
    )})
    f = check_model_artifact_provenance(c)
    assert f.status == WARN
    assert "llama3:8b" in " ".join(f.evidence)


def test_b343_fail_plaintext_http():
    c = _ctx({"skill": (
        "# file: main.py\n"
        "urllib.request.urlretrieve('http://sketchy.example.com/weights.safetensors', 'w.safetensors')\n"
    )})
    f = check_model_artifact_provenance(c)
    assert f.status == FAIL
    assert "sketchy.example.com" in " ".join(f.evidence)


def test_b343_fail_raw_public_ip():
    c = _ctx({"skill": "# file: main.py\nrequests.get('http://8.8.8.8/model.gguf')\n"})
    assert check_model_artifact_provenance(c).status == FAIL


def test_b343_fail_onion():
    c = _ctx({"skill": (
        "# file: main.py\n"
        "requests.get('http://abcdefghijklmnop1234567890abcdefghijklmnop123456"
        ".onion/model.onnx')\n"
    )})
    assert check_model_artifact_provenance(c).status == FAIL


def test_b343_fail_loader_with_literal_bad_url():
    """A literal (not bare repo-id) URL passed straight to from_pretrained with bad
    provenance -- same FAIL discriminator as a direct artifact-file fetch."""
    c = _ctx({"skill": (
        "# file: main.py\n"
        "model = AutoModel.from_pretrained('http://1.2.3.4/org/model')\n"
    )})
    assert check_model_artifact_provenance(c).status == FAIL


def test_b343_ignores_variable_argument():
    """A variable/f-string argument has no literal to check -- must not be flagged at
    all (silent skip, never guess)."""
    c = _ctx({"skill": "# file: main.py\nmodel = AutoModel.from_pretrained(args.model_id)\n"})
    assert check_model_artifact_provenance(c).status == UNKNOWN


def test_b343_ignores_fstring_argument():
    c = _ctx({"skill": "# file: main.py\nmodel = AutoModel.from_pretrained(f'{org}/{name}')\n"})
    assert check_model_artifact_provenance(c).status == UNKNOWN


def test_b343_clean_documentation_mentioning_huggingface():
    """Prose mentioning huggingface/ollama with no actual loader call site must stay
    UNKNOWN, not WARN -- a documentation skill describing model options is not itself
    a provenance signal."""
    c = _ctx({"skill": (
        "# file: README.md\nThis skill can work with models from huggingface.co or "
        "ollama, depending on configuration.\n"
    )})
    assert check_model_artifact_provenance(c).status == UNKNOWN


# --------------------------------------------------------------------------- #
# C-135 (independent adversarial pass, 2 agents): a documented example and a
# local vendored model path both produced false WARNs. Fixed by reusing
# _is_code_example (the same fence/negation dampener every other content-ring
# check already uses) and a local-filesystem-path guard.
# --------------------------------------------------------------------------- #
def test_b343_does_not_flag_docstring_example():
    c = _ctx({"skill": (
        "# file: main.py\n"
        "def helpful_docs():\n"
        '    """\n'
        "    Example usage:\n"
        '        # e.g. model = AutoModel.from_pretrained("bert-base-uncased")\n'
        "    This skill does not load any model itself; it just explains the pattern.\n"
        '    """\n'
    )})
    assert check_model_artifact_provenance(c).status == UNKNOWN


def test_b343_does_not_flag_fenced_documentation_example():
    c = _ctx({"skill": (
        "# file: README.md\n"
        "Our skill does not actually download any models itself; it calls a remote API.\n\n"
        "```python\n"
        "model = AutoModel.from_pretrained('bert-base-uncased')\n"
        "```\n"
    )})
    assert check_model_artifact_provenance(c).status == UNKNOWN


def test_b343_does_not_flag_local_relative_path():
    c = _ctx({"skill": (
        "# file: main.py\nmodel = AutoModel.from_pretrained('./local_model_dir')\n"
    )})
    assert check_model_artifact_provenance(c).status == UNKNOWN


def test_b343_does_not_flag_local_absolute_path():
    c = _ctx({"skill": (
        "# file: main.py\nmodel = AutoModel.from_pretrained('/opt/models/llama')\n"
    )})
    assert check_model_artifact_provenance(c).status == UNKNOWN


def test_b343_does_not_flag_local_home_path():
    c = _ctx({"skill": (
        "# file: main.py\nmodel = AutoModel.from_pretrained('~/models/llama')\n"
    )})
    assert check_model_artifact_provenance(c).status == UNKNOWN


def test_b343_still_warns_on_real_unpinned_reference_after_c135_fixes():
    """Regression guard: the C-135 fixes above must not have swallowed the real
    unpinned-reference WARN they were verified against during the fix."""
    c = _ctx({"skill": "# file: main.py\nmodel = AutoModel.from_pretrained('org/model')\n"})
    f = check_model_artifact_provenance(c)
    assert f.status == WARN
    assert "org/model" in " ".join(f.evidence)
