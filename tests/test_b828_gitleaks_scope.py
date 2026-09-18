"""Guards for .gitleaks.toml / .gitleaksignore: exemptions are exact values, never places.

The old config exempted `fixtures/` and `tests/` wholesale (about 93% of tracked files)
plus a global stopword list, so a real-shaped secret pasted into a test was invisible to
the only mechanical enforcement of the no-secrets-in-source rule. These tests read the
config as TEXT (tomllib is 3.11+, the CI floor is 3.9) and pin the narrow shape.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG = (ROOT / ".gitleaks.toml").read_text(encoding="utf-8")
IGNORE = (ROOT / ".gitleaksignore").read_text(encoding="utf-8")
CI = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

_PINNED_FINGERPRINTS = {
    "8f274c2879548fc42fa0f0293238c8be71c11e10:fixtures/clean_b13_hardcoded_plain_assignment_comment/skills/s/runner.py:stripe-access-token:7",
    "8f274c2879548fc42fa0f0293238c8be71c11e10:fixtures/clean_b13_hardcoded_plain_assignment_comment/skills/s/runner.py:stripe-access-token:12",
    "8f274c2879548fc42fa0f0293238c8be71c11e10:tests/test_b740_plain_assignment_secret.py:stripe-access-token:128",
    "8f274c2879548fc42fa0f0293238c8be71c11e10:tests/test_b740_plain_assignment_secret.py:stripe-access-token:141",
    "24995977c5e45bf0221ad56348cc28b79da12fd2:tests/test_logsafe.py:gcp-api-key:58",
    "24995977c5e45bf0221ad56348cc28b79da12fd2:tests/test_logsafe.py:gcp-api-key:60",
}


def _strip_comments(text):
    return "\n".join(re.sub(r"^\s*#.*$", "", ln) for ln in text.splitlines())


CODE = _strip_comments(CONFIG)


def _allow_regexes():
    return re.findall(r"regexes\s*=\s*\[\s*'''(.*?)'''\s*\]", CODE, re.S)


def _tok(prefix, n, alphabet="abcdefghijklmnopqrstuvwxyz0123456789"):
    return prefix + (alphabet * 3)[:n]


def test_no_path_or_global_stopword_exemption():
    assert not re.search(r"^\s*paths\s*=", CODE, re.M)
    assert not re.search(r"^\s*stopwords\s*=", CODE, re.M)
    assert not re.search(r"^\s*\[allowlist\]", CODE, re.M)
    assert not re.search(r"^\s*\[\[allowlists\]\]", CODE, re.M)


def test_default_rules_still_extended():
    assert re.search(r"^useDefault\s*=\s*true\s*$", CODE, re.M)


def test_exemptions_are_anchored_exact_values():
    regexes = _allow_regexes()
    assert len(regexes) == 7
    for rx in regexes:
        assert rx.startswith("^") and rx.endswith("$"), rx
        assert ".*" not in rx and ".+" not in rx and "|" not in rx, rx


def test_exemptions_do_not_match_real_shaped_tokens():
    probes = [
        _tok("gh" + "p_", 36),
        _tok("AK" + "IA", 16, "ABCDEFGHIJKLMNOP"),
        _tok("cl" + "h_", 40),
        _tok("s" + "k-", 48),
        _tok("sk_" + "live_", 24),
        _tok("AI" + "za", 35),
    ]
    for rx in _allow_regexes():
        for p in probes:
            assert not re.search(rx, p), (rx, p[:6])


def test_clawhub_rule_matches_token_not_placeholder():
    m = re.search(r"id = \"clawhub-cli-token\".*?regex = '''(.*?)'''", CODE, re.S)
    assert m
    rx = m.group(1)
    assert re.search(rx, "token " + _tok("cl" + "h_", 40))
    assert not re.search(rx, "clh_... placeholder")
    assert 'keywords = ["clh_"]' in CODE


def test_ignore_file_is_exactly_the_pinned_history_fingerprints():
    lines = [ln for ln in IGNORE.splitlines() if ln.strip() and not ln.startswith("#")]
    for ln in lines:
        assert re.fullmatch(r"[0-9a-f]{40}:[^:\s]+:[a-z0-9-]+:\d+", ln), ln
    assert set(lines) == _PINNED_FINGERPRINTS
    assert len(lines) == len(set(lines))


def test_ci_secret_scan_uses_this_config():
    assert "--config=.gitleaks.toml" in CI
